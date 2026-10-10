"""Read-state reconciliation around existing, independently guarded mutations."""
from __future__ import annotations

from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
import inspect
import logging

from .runtime import MAX_RUNTIME_CONTAINERS, public_runtime_container

_PUBLIC_SERVICE_FIELDS = ("key", "name", "container_id", "image", "image_id", "digest", "version", "created", "architecture", "state", "health", "restart_policy", "started_at", "stack", "compose_service", "working_dir", "compose_files", "local_build", "ignored", "mutable")
_active = ContextVar("upt_mutation_reconciliation", default=None)


def public_service(service) -> dict:
    data = service.as_dict() if hasattr(service, "as_dict") else dict(service)
    public = {key: data.get(key) for key in _PUBLIC_SERVICE_FIELDS if key in data}
    if public.get("container_id"):
        public["key"] = "container/" + public["container_id"]
    return public


def mark_changed(service=None, *, current_name=None, after_change=False):
    """Called immediately before a guarded workload/configuration change."""
    context = _active.get()
    if context and getattr(context["state"], "supports_service_verification", False) and not context["changed"]:
        if service is not None:
            context["service"] = service
        context["current_name"] = current_name
        # A failed invalidation must precede any workload change. Once the
        # mutation runs, a later delivery failure cannot revive old facts.
        try:
            context["state"].invalidate_verification("container/" + context["service"].container_id)
        except Exception:
            if not after_change:
                raise
            logging.getLogger(__name__).warning("Post-mutation verification invalidation needs retry")
        context["changed"] = True


def mark_project_inputs_changed():
    """Called where a guarded operation writes or accepts shared Compose inputs.

    Only a later clean success may trigger the passive sibling trust refresh.
    """
    context = _active.get()
    if context is not None:
        context["project_inputs"] = True


def _clean_success(result):
    # Recovered or manual-recovery outcomes never re-trust siblings.
    status = getattr(result, "status", None)
    if status is None:
        return True
    return (status == "succeeded" and not getattr(result, "recovered", False)
            and not getattr(result, "manual_recovery_required", False))


def reconcile_operation(function):
    """Preserve the core outcome; reconcile actual runtime even after recovery.

    Adapters may supply a server-owned ``post_mutation(service)`` callback to
    queue exact-container verification. Core callers without a delivery adapter
    still persist invalidation and current runtime, falling back to Check required.
    ``post_project_change(service)`` is called only after a clean success that
    changed shared Compose inputs; it must publish nothing it cannot prove.
    """
    signature = inspect.signature(function)

    @wraps(function)
    def wrapped(*args, post_mutation=None, reconcile_discover=None, post_project_change=None, **kwargs):
        arguments = signature.bind(*args, **kwargs).arguments
        service = arguments.get("s") or arguments.get("service")
        if service is None and "plan" in arguments:
            service = arguments["plan"].service
        state = arguments.get("state")
        if state is None or _active.get() is not None:
            return function(*args, **kwargs)
        context = {"service": service, "state": state, "changed": False, "current_name": None,
                   "project_inputs": False}
        token = _active.set(context)
        succeeded = False
        try:
            result = function(*args, **kwargs)
            succeeded = _clean_success(result)
            return result
        finally:
            _active.reset(token)
            if context["changed"]:
                service = context["service"]
                try:
                    attempted_at = datetime.now(timezone.utc).isoformat()
                    discover = reconcile_discover or arguments.get("discover_current") or (lambda: function.__globals__["discover"](all_containers=True))
                    found = discover()
                    if len(found) > MAX_RUNTIME_CONTAINERS:
                        raise ValueError("runtime inventory limit")
                    if context["current_name"]:
                        selected = [item for item in found if item.name == context["current_name"]]
                    elif service.stack and service.compose_service:
                        selected = [item for item in found if item.stack == service.stack
                                    and item.compose_service == service.compose_service]
                    else:
                        selected = [item for item in found if item.container_id == service.container_id]
                    # Service discovery supplies identity/startup facts. Retain
                    # safe diagnostic counters for the same container from the
                    # runtime sampler; never transfer them to a replacement.
                    cached = {item["container_id"]: item for item in
                              state.runtime_snapshot().get("containers", [])}
                    containers = [public_runtime_container({**cached.get(item.container_id, {}),
                                  **public_service(item), "healthcheck": item.health}) for item in found]
                    current = selected[0] if len(selected) == 1 else None
                    state.reconcile_runtime("container/" + service.container_id, containers,
                                            current_service=public_service(current) if current else None,
                                            candidate_services=[public_service(item) for item in selected] if current is None else (),
                                            attempted_at=attempted_at)
                except Exception:
                    # Delivery/collection must never reclassify an already factual
                    # workload outcome. Invalidation remains durable on failure.
                    logging.getLogger(__name__).warning("Post-mutation state refresh needs retry")
                    try:
                        state.record_runtime_failure(attempted_at=attempted_at, failure_category="inventory_changed")
                    except Exception:
                        logging.getLogger(__name__).warning("Post-mutation runtime failure could not be recorded")
                else:
                    if current is not None and post_mutation:
                        try:
                            post_mutation(current)
                        except Exception:
                            logging.getLogger(__name__).warning("Post-mutation targeted verification needs retry")
                    if current is not None and post_project_change and succeeded and context["project_inputs"]:
                        try:
                            post_project_change(current)
                        except Exception:
                            logging.getLogger(__name__).warning("Same-project baseline reconciliation needs retry")
    return wrapped


def queue_agent_verification(service, *, state):
    """CLI adapter: bounded read-only RPC, never invoke the interactive CLI."""
    from .agent import AgentClient
    from .config import Config, WebConfig
    # A CLI using a separate state root must not refresh the default agent's
    # inventory. This also keeps isolated fixture invocations off a live socket.
    if state.root.resolve() != Config().state_dir.resolve():
        return
    AgentClient(str(WebConfig().socket_path), timeout=5).call(
        "refresh_start", {"service_key": "container/" + service.container_id, "after_reconcile": True})


def queue_agent_project_refresh(service, *, state):
    """CLI adapter: ask the agent to passively re-prove already-trusted siblings."""
    from .agent import AgentClient
    from .config import Config, WebConfig
    if state.root.resolve() != Config().state_dir.resolve():
        return
    AgentClient(str(WebConfig().socket_path), timeout=5).call(
        "refresh_start", {"service_key": "container/" + service.container_id, "after_reconcile": True,
                          "project_inputs": True})
