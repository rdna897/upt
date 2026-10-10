from __future__ import annotations

import re
import logging
import json
import copy
import errno
import hashlib
import os
import secrets
import shutil
import tempfile
import threading
from contextvars import ContextVar
from functools import partial, wraps
import uuid
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

from ._version import __version__
from .component_version import TRANSPORT_VERSION_FIELD, ComponentVersionMismatch, reported_version
from .config import Config
from .compose import ComposeSourceNotWritable, pin_plan, verify_atomic_replace_access
from .compose_baseline import BaselineIntegrityError, BaselineStore, logical_key
from .compose_discard import (DISCARD_REASONS, DiscardRefused, SourceMutationPlan, discard_gate_reasons,
                              do_compose_discard, prove_source_isolation, unchanged_runtime)
from .compose_bootstrap import (BootstrapRefused, BootstrapExecutionFailed, REASONS as BOOTSTRAP_REASONS,
                                make_plan as make_bootstrap_plan, do_compose_bootstrap)
from .compose_reconcile import (ReconcileOutcome, do_compose_reconcile, input_layout,
                                peer_identity, verify_image_unchanged)
from .compose_drift import (DRIFTED, IN_SYNC, REASONS as COMPOSE_REASONS, UNSUPPORTED, UNVERIFIABLE,
                            ComposePreflightRefused, InputFile, InputReadError,
                            build_inventory, compute_diff, hash_excluded_fields_present,
                            observed_service_model, read_input)
from .compose_drift import fingerprint as compose_fingerprint
from .compose_namespace import (NamespaceRefused, _relationship, _start, namespace_candidate, namespace_owner, prove_owner,
                                resolve_namespace, resolved_hash, mutation_refusal, require_mutation_safe)
from .docker import compose_args, discover
from .lock import Lock
from .operations import (BLOCKING_REFUSALS, PreMutationRefusal, RecoveryFailed, RecoveryRefused, RecoveryRequired,
                         ReviewedTargetChanged, WebRollbackFailure, do_update,
                         do_web_rollback)
from .namespace_update import NamespaceUpdateReview, review_namespace_update
from .namespace_apply import (NamespaceApplyDeps, NamespaceApplyGuard, NamespaceApplyReview,
                              refuse_consumer_env_file, review_namespace_apply)
from .operation_presentation import REFRESH_NOTICE
from .progress import DISCARD_STAGE_TOTAL, RECONCILE_STAGE_TOTAL, Reporter
from .registry import LOCAL_DIGEST_UNVERIFIED, scan_service_with_tracking, tracking_image
from .models import parse_image_ref
from .reconciliation import public_service as _public_service
from .runtime import RUNTIME_INTERVAL_SECONDS, RuntimeProbeError, collect_runtime_containers, utc_now
from .state import State, verification_identity
from .scan_worker import run_full_scan
from .system import run


COMPOSE_HISTORY_ATTEMPTS = 3  # bounded retry of the core History write before finalization
READ_ONLY_OPERATIONS = frozenset({"health", "snapshot", "runtime_snapshot", "service", "scan_start", "scan_status", "audit_recent", "verification_snapshot", "refresh_start", "refresh_status", "compose_status"})
MUTATION_OPERATIONS = frozenset({"update_review", "update_start", "rollback_review", "rollback_start", "operation_status",
                                 "compose_reconcile_review", "compose_reconcile_start", "compose_bootstrap_review", "compose_bootstrap_start"})
AGENT_OPERATIONS = READ_ONLY_OPERATIONS | MUTATION_OPERATIONS
# Mutation admission requires exact web/agent product-version agreement.
# operation_status only reports an already-admitted operation, so it stays
# available during a mismatch for diagnosis.
VERSION_GATED_OPERATIONS = MUTATION_OPERATIONS - {"operation_status"}
UPDATE_STATUSES = frozenset({"UPDATE", "DIGEST CHANGED", "PINNED UPDATE"})
COMPOSE_HASH_LABEL = "com.docker.compose.config-hash"
COMPOSE_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
UPDATE_REVIEW_TTL_SECONDS = 600
UPDATE_REVIEW_LIMIT = 256
ROLLBACK_REVIEW_TTL_SECONDS = 600
ROLLBACK_REVIEW_LIMIT = 256
UPDATE_REVIEW_IDENTITY_FIELDS = (
    "container_id", "image", "image_id", "digest", "version", "architecture",
    "state", "stack", "compose_service", "working_dir", "compose_files",
)
ROLLBACK_REVIEW_IDENTITY_FIELDS = UPDATE_REVIEW_IDENTITY_FIELDS + (
    "restart_policy", "local_build", "ignored",
)
MAX_BACKUP_CANDIDATES = 3
ADOPTION_RETRY_SECONDS = 600
# Same-project baseline reconciliation is a one-shot best-effort follow-up:
# one worker, at most this many distinct pending projects, never persisted.
PROJECT_REFRESH_QUEUE_LIMIT = 16
_deferred_project_refresh = ContextVar("upt_deferred_project_refresh", default=None)
COMPOSE_STATUS_CACHE_SECONDS = 30
# Fixed copy for update operations refused before the mutation boundary.
BLOCKED_UPDATE_MESSAGES = {
    "compose_drift": "Compose configuration changed after review. Review the pending configuration changes on the service page before trying again.",
    "compose_unverifiable": "UPT could not verify this service's Compose configuration before updating. Check the service's Configuration status before trying again.",
    "hash_excluded": "This service uses Compose build, pull-policy, profile or scale settings that UPT cannot verify. Review the configuration and use the CLI.",
    "service_changed": "The service changed after review. Refresh the service page and review its current state before trying again.",
    "service_ineligible": "The service is no longer an eligible running Compose service.",
    "target_unavailable": "The reviewed image update is no longer available. Refresh this service and review again.",
    "target_changed": "The reviewed image target changed or could not be verified. Refresh the service page and review the current target before trying again.",
}

BLOCKED_UPDATE_MESSAGES.update({key: COMPOSE_REASONS[key] for key in (
    "namespace_owner_has_dependents", "namespace_owner_unproven", "namespace_unsupported_compose",
    "namespace_owner_changed", "namespace_owner_replaced", "namespace_owner_unhealthy", "namespace_stale")})


class _ComposeCheckRaced(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class _ExecutionContextRefused(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _unmodified_compose_hash(service):
    try:
        output = run(compose_args(service) + ["config", "--hash", service.compose_service],
                     cwd=service.working_dir, timeout=30)
    except Exception:
        raise PreMutationRefusal(
            "Compose configuration identity could not be verified; reconcile pending changes and refresh this service before updating",
            "compose_unverifiable") from None
    result = ReadOnlyService._compose_hash_from_output(service.compose_service, output)
    if result is None:
        raise PreMutationRefusal(
            "Compose configuration identity is missing or ambiguous; reconcile pending changes and refresh this service before updating",
            "compose_unverifiable")
    return result


def _assert_project_identity(service, model):
    if not isinstance(model, dict):
        raise _ExecutionContextRefused("project_identity_unavailable")
    name = model.get("name")
    if not isinstance(name, str) or not name or not isinstance(service.stack, str):
        raise _ExecutionContextRefused("project_identity_unavailable")
    if (os.environ.get("COMPOSE_PROJECT_NAME") is not None
            or (service.labels or {}).get("com.docker.compose.project") != service.stack
            or name != service.stack):
        raise _ExecutionContextRefused("project_identity")
    return name


def _selected_project_network(project, selected, model):
    """Return the selected service's one supported project network.

    Supported: the implicit ``default`` network, or one network declared by
    the same project whose only setting is the bridge driver. Any per-service
    attachment value (aliases, static addresses, priority, ...) and any other
    network setting (external, custom name, IPAM, driver options, internal,
    attachable, IPv6, labels) is a user semantic choice and stays unproven.
    """
    networks = selected.get("networks")
    if networks in (None, {}):
        logical = "default"
    elif isinstance(networks, dict) and len(networks) == 1:
        (logical, attachment), = networks.items()
        if attachment is not None or not isinstance(logical, str) or not logical:
            raise _ExecutionContextRefused("network_unproven")
    else:
        raise _ExecutionContextRefused("network_unproven")
    project_networks = model.get("networks") or {}
    if not isinstance(project_networks, dict):
        raise _ExecutionContextRefused("network_unproven")
    expected_network = f"{project}_{logical}"
    desired = project_networks.get(logical)
    if logical == "default":
        if desired not in (None, {}, {"name": expected_network, "ipam": {}}):
            raise _ExecutionContextRefused("network_unproven")
    elif (not isinstance(desired, dict) or set(desired) - {"name", "driver", "ipam"}
            or desired.get("name") != expected_network
            or desired.get("driver", "bridge") != "bridge" or desired.get("ipam", {}) != {}):
        raise _ExecutionContextRefused("network_unproven")
    return logical, expected_network, desired


def _selected_logical_network(service, model):
    """Project-network allowance for Phase 2A: only the selected service's own
    proven network. Refusal is reported by the execution-context proof."""
    try:
        services = model.get("services") or {}
        return _selected_project_network(service.stack, services[service.compose_service], model)[0]
    except (_ExecutionContextRefused, AttributeError, KeyError, TypeError):
        return "default"


def _runtime_project_network_id(service, expected_network, logical_network, *, absent_container=False):
    """Read only the selected container attachment and its Compose network."""
    if absent_container:
        # Recovery can have no selected container after a failed invocation.
        # Independently inspect the server-proven named default network; its
        # exact ID still has to reproduce the reviewed context fingerprint.
        network_id = None
        target = expected_network
    else:
        raw = run(["docker", "inspect", "--type", "container", "--format",
                   "{{json .NetworkSettings.Networks}}", service.container_id], timeout=30)
        if len(raw) > 65536:
            raise ValueError("oversized network observation")
        attached = json.loads(raw)
        if not isinstance(attached, dict) or set(attached) != {expected_network}:
            raise ValueError("network attachment differs")
        network_id = attached[expected_network].get("NetworkID")
        if not isinstance(network_id, str) or not re.fullmatch(r"[0-9a-f]{64}", network_id):
            raise ValueError("network identity unavailable")
        target = network_id
    raw = run(["docker", "network", "inspect", "--format", "{{json .}}", target], timeout=30)
    if len(raw) > 65536:
        raise ValueError("oversized network observation")
    observed = json.loads(raw)
    if absent_container:
        network_id = observed.get("Id")
        if not isinstance(network_id, str) or not re.fullmatch(r"[0-9a-f]{64}", network_id):
            raise ValueError("network identity unavailable")
    labels = observed.get("Labels") or {}
    if (observed.get("Id") != network_id or observed.get("Name") != expected_network
            or observed.get("Driver") != "bridge" or observed.get("Internal") is not False
            or observed.get("Attachable") is not False or observed.get("Ingress") is not False
            or observed.get("Scope") != "local" or observed.get("EnableIPv6") is not False
            or (observed.get("IPAM") or {}).get("Driver") not in ("default", None)
            or observed.get("Options") not in ({}, None)
            or labels.get("com.docker.compose.project") != service.stack
            or labels.get("com.docker.compose.network") != logical_network):
        raise ValueError("network definition differs")
    return network_id


def _execution_context_fingerprint(service, model, *, identity_container_id=None, absent_container=False, namespace_evidence=None, namespace_hash_reader=None, namespace_consumer_started_at=None):
    """Prove only the resources Compose may apply to this selected service.

    Phase 1 supports bind mounts and one project-owned local bridge network:
    the ordinary implicit default or a single plain declared bridge network.
    The runtime network is verified independently; no project observation or
    selected-service hash is used as evidence for a named project resource.
    """
    name = _assert_project_identity(service, model)
    services = model.get("services")
    selected = services.get(service.compose_service) if isinstance(services, dict) else None
    if not isinstance(selected, dict):
        raise _ExecutionContextRefused("service_resource_unproven")
    if isinstance(selected.get("network_mode"), str) and selected["network_mode"].startswith("service:"):
        if absent_container:
            raise _ExecutionContextRefused("namespace_owner_unproven")
        try:
            owner, evidence = resolve_namespace(
                service, model, context_reader=_execution_context_fingerprint,
                hash_reader=namespace_hash_reader or _unmodified_compose_hash, image_verifier=verify_image_unchanged,
                mounts_reader=_assert_reconcile_runtime_mounts)
        except NamespaceRefused as exc:
            raise _ExecutionContextRefused(exc.reason) from None
        except Exception:
            raise _ExecutionContextRefused("namespace_owner_unproven") from None
        if namespace_evidence is not None:
            namespace_evidence.append(evidence)
        values = evidence.fingerprint_values()
        if namespace_consumer_started_at is not None:
            # The live resolver above still proves replacement freshness/PIDs.
            # An image update compares context under its original review identity;
            # only the necessarily replaced consumer's start identity is normalised.
            values['consumer_started_at'] = namespace_consumer_started_at
        return compose_fingerprint({"project": name, "service": identity_container_id or service.container_id,
                                    "namespace": {"owner": owner.compose_service,
                                                  "owner_evidence": compose_fingerprint(values),
                                                  "definition": {"network_mode": selected["network_mode"],
                                                                 "depends_on": selected.get("depends_on")}}})
    if namespace_candidate(service, selected):
        raise _ExecutionContextRefused("network_unproven")
    if any(selected.get(field) for field in ("configs", "secrets", "models", "volumes_from",
                                               "links", "external_links", "depends_on")):
        raise _ExecutionContextRefused("service_resource_unproven")
    if any(selected.get(field) for field in ("network_mode", "pid", "ipc", "uts")):
        raise _ExecutionContextRefused("network_unproven")
    mounts = selected.get("volumes") or []
    if not isinstance(mounts, list):
        raise _ExecutionContextRefused("named_volume_unproven")
    for mount in mounts:
        if not isinstance(mount, dict) or mount.get("type") != "bind":
            raise _ExecutionContextRefused("named_volume_unproven")
    logical_network, expected_network, desired = _selected_project_network(name, selected, model)
    try:
        network_id = _runtime_project_network_id(service, expected_network, logical_network,
                                                 absent_container=absent_container)
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError, KeyError):
        raise _ExecutionContextRefused("network_unproven") from None
    # Ephemeral fingerprint only: no raw IDs, source or model values persist.
    return compose_fingerprint({"project": name, "service": identity_container_id or service.container_id,
                                "network": network_id, "definition": desired})


def _assert_reconcile_runtime_mounts(service, service_model):
    """Phase 2A excludes image-declared/anonymous volumes as well as named ones.

    Runtime bind identities must match the selected proven model. Application
    data is inspected only as mount metadata; it is never read or copied.
    """
    expected = []
    for mount in service_model.get("volumes") or []:
        if (not isinstance(mount, dict) or mount.get("type") != "bind"
                or not isinstance(mount.get("source"), str) or not isinstance(mount.get("target"), str)):
            raise _ExecutionContextRefused("named_volume_unproven")
        expected.append((mount["source"], mount["target"], not bool(mount.get("read_only")),
                         (mount.get("bind") or {}).get("propagation") or "rprivate"))
    try:
        raw = run(["docker", "inspect", "--type", "container", "--format", "{{json .Mounts}}",
                   service.container_id], timeout=30)
        if len(raw) > 65536:
            raise ValueError("oversized mount observation")
        mounts = json.loads(raw)
        if not isinstance(mounts, list) or len(mounts) > 64:
            raise ValueError("mount inventory is unavailable")
        actual = []
        for mount in mounts:
            if (not isinstance(mount, dict) or mount.get("Type") != "bind"
                    or type(mount.get("RW")) is not bool):
                raise ValueError("unsupported runtime mount")
            actual.append((mount.get("Source"), mount.get("Destination"), mount["RW"], mount.get("Propagation")))
        if sorted(actual) != sorted(expected):
            raise ValueError("runtime bind mounts differ")
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        raise _ExecutionContextRefused("runtime_mounts_unproven") from None


@dataclass(frozen=True)
class ComposePlan:
    """Trusted server-side Compose status; only a projection reaches browsers."""
    status: str
    reasons: tuple = ()
    inventory_reasons: tuple = ()
    checked_at: str = ""
    runtime_hash: str | None = None
    desired_hash: str | None = None
    desired_model: dict | None = None
    inventory: object | None = None
    baseline: object | None = None
    diff: object | None = None
    image_change: bool = False
    apply_eligible: bool = False
    discard_eligible: bool = False
    discard_reasons: tuple = ()
    discard_plan: SourceMutationPlan | None = None
    eligibility_reasons: tuple = ()
    update_eligible: bool = False
    update_reasons: tuple = ()
    execution_context_fingerprint: str | None = None
    namespace_update_review: NamespaceUpdateReview | None = None
    namespace_apply_review: NamespaceApplyReview | None = None


def _safe_mutation_log_identifier(value):
    if not isinstance(value, str) or not value:
        return "unknown"
    return re.sub(r"[^A-Za-z0-9_.:-]", "_", value)[:100] or "unknown"


def _safe_runtime_failure_class(exc):
    name = re.sub(r"[^A-Za-z0-9_]", "", type(exc).__name__)[:64]
    return name or "UnknownError"


def _safe_runtime_exit_code(exc):
    for attribute in ("code", "returncode", "exit_code"):
        try:
            value = getattr(exc, attribute, None)
        except Exception:
            continue
        if type(value) is int and -255 <= value <= 255:
            return value
    return "none"


def _project_identity(service):
    identity = (service.stack, service.working_dir, tuple(service.compose_files or ()))
    return identity if all(identity) else None


def _after_terminal_project_refresh(worker):
    """Hold same-project refresh requests until the worker has persisted its outcome.

    Only an operation durably recorded as succeeded dispatches them, and only
    to the bounded background queue; this never delays or alters the result.
    """
    @wraps(worker)
    def wrapped(self, operation_id, *args, **kwargs):
        if _deferred_project_refresh.get() is not None:
            return worker(self, operation_id, *args, **kwargs)
        requests = []
        token = _deferred_project_refresh.set(requests)
        try:
            return worker(self, operation_id, *args, **kwargs)
        finally:
            _deferred_project_refresh.reset(token)
            if requests:
                self._dispatch_project_refresh(operation_id, requests)
    return wrapped


def _log_web_mutation_failure(logger, operation, operation_id, intent, exc):
    """Log bounded mutation diagnostics without exception text or source data."""
    identity = dict(zip(UPDATE_REVIEW_IDENTITY_FIELDS, getattr(intent, "service_identity", ())))
    service = identity.get("compose_service") or str(getattr(intent, "service_key", "unknown")).rsplit("/", 1)[-1]
    stack = identity.get("stack")
    error_number = getattr(exc, "errno", None) if isinstance(exc, OSError) else None
    if isinstance(exc, ComposeSourceNotWritable):
        category = "compose_source_not_writable"
    elif isinstance(exc, OSError):
        category = {
            errno.EROFS: "filesystem_read_only",
            errno.EACCES: "filesystem_permission_denied",
            errno.EPERM: "filesystem_permission_denied",
            errno.ENOSPC: "filesystem_no_space",
        }.get(error_number, "filesystem_error")
    elif isinstance(exc, ReviewedTargetChanged):
        category = "reviewed_target_changed"
    elif isinstance(exc, RecoveryFailed):
        category = "recovery_attempt_failed"
    elif isinstance(exc, WebRollbackFailure):
        if exc.manual_recovery_required:
            category = "manual_recovery_required"
        elif exc.recovered:
            category = "rollback_failed_recovered"
        else:
            category = "rollback_failed"
    elif isinstance(exc, RecoveryRefused):
        category = "recovery_safety_refused"
    elif isinstance(exc, RecoveryRequired):
        category = "manual_recovery_required"
    elif isinstance(exc, ValueError):
        category = "validation_refused"
    else:
        category = "mutation_failure"
    failure_class = type(exc).__name__[:60]
    symbolic_errno = errno.errorcode.get(error_number, "unknown") if error_number is not None else "none"
    logger.error(
        "Web mutation failed operation=%s operation_id=%s stack=%s service=%s category=%s failure_class=%s errno=%s",
        _safe_mutation_log_identifier(operation),
        _safe_mutation_log_identifier(operation_id),
        _safe_mutation_log_identifier(stack),
        _safe_mutation_log_identifier(service),
        category,
        _safe_mutation_log_identifier(failure_class),
        symbolic_errno,
    )


@dataclass(frozen=True)
class UpdateReviewIntent:
    verification_id: str
    service_key: str
    requested_by: str
    target: tuple
    service_identity: tuple
    expires_at: float
    execution_context_fingerprint: str = ""
    namespace_review: NamespaceUpdateReview | None = None


@dataclass(frozen=True)
class RollbackReviewIntent:
    service_key: str
    requested_by: str
    service_identity: tuple
    rollback_identity: tuple
    backup_fingerprint: str
    source_identity: tuple
    current_model_identity: str
    restored_model_identity: str
    expires_at: float


@dataclass(frozen=True)
class ComposeReviewIntent:
    action: str
    service_key: str
    requested_by: str
    service_identity: tuple
    baseline_id: str
    evidence_fingerprint: str
    expires_at: float
    # Server-held Stage 2 authority; never supplied or replaced by a request.
    namespace_review: NamespaceApplyReview | None = None


@dataclass(frozen=True)
class BootstrapReviewIntent:
    service_key: str
    requested_by: str
    evidence_fingerprint: str
    expires_at: float


class AgentAuthorizationError(PermissionError):
    """The agent refused the caller or operation (fixed, non-sensitive text).

    Distinct from OS-level PermissionError so that it can be reported as an
    authorisation rejection rather than falling through to the registry
    diagnostic category. The wire type stays "PermissionError".
    """


def _safe_error(exc: Exception | str) -> str:
    """Return a deliberately curated browser-safe diagnostic category."""
    if str(exc) == LOCAL_DIGEST_UNVERIFIED:
        return LOCAL_DIGEST_UNVERIFIED
    text = str(exc).strip().lower()
    if any(value in text for value in ("429", "rate limit", "too many requests")):
        return "registry rate limit reached"
    if any(value in text for value in ("unauthorized", "authentication", "forbidden", "401", "403", "credential", "token", "password", "secret", "authorization")):
        return "registry authentication failed"
    if any(value in text for value in ("timed out", "timeout", "deadline")):
        return "registry request timed out"
    if any(value in text for value in ("not found", "404", "manifest unknown")):
        return "image or manifest was not found"
    if "architecture" in text or "platform" in text:
        return "image platform is not supported"
    return "registry query failed"


def _public_result(result, state=None) -> dict:
    if hasattr(result, "as_dict"):
        data = result.as_dict()
    elif isinstance(result, dict):
        data = result
    else:
        data = {"service": getattr(result, "service", {}), "status": getattr(result, "status", "UNKNOWN"), "remote_digest": getattr(result, "remote_digest", None), "remote_version": getattr(result, "remote_version", None), "remote_created": getattr(result, "remote_created", None), "error": getattr(result, "error", None)}
    status = data.get("status", "UNKNOWN")
    error = data.get("error")
    tracking_issue = getattr(result, "tracking_issue", None) if not isinstance(result, dict) else result.get("tracking_issue")
    if status == "PINNED" and tracking_issue == "missing_channel":
        # Do not present an untracked digest as a healthy/fully monitored pin.
        # This static message is safe for the browser; never pass through
        # registry text or invent a tracking tag/channel.
        status = "UNTRACKED DIGEST"
        error = "No trusted tracking tag is recorded for this digest pin. UPT did not guess a release channel, so update tracking is unavailable."
    service_value = result.service if hasattr(result, "service") else data.get("service", {})
    public_service = _public_service(service_value)
    target_image = None
    tracking_tag = None
    channel = None
    if state is not None and status in {"PINNED", "PINNED UPDATE"} and parse_image_ref(public_service.get("image", "")).digest:
        tracked = (service_value if hasattr(result, "service") else SimpleNamespace(
            image=public_service.get("image"), stack=public_service.get("stack"),
            key=public_service.get("compose_service") or public_service.get("key"),
        ))
        channel = tracking_image(tracked, state)
        if channel and status == "PINNED UPDATE" and data.get("remote_digest"):
            target_image = f"{channel.rsplit('@', 1)[0]}@{data['remote_digest']}"
    if channel:
        try:
            tag = parse_image_ref(channel).tag
            if len(tag) <= 128 and not any(char in tag for char in "\0\r\n/@"):
                tracking_tag = tag
        except Exception:
            # Presentation parsing cannot suppress a previously resolved
            # update target or alter scan status.
            tracking_tag = None
    public = {"service": public_service,
              "status": status, "remote_digest": data.get("remote_digest"),
              "remote_version": data.get("remote_version"), "remote_created": data.get("remote_created"),
              "error": error if status == "UNTRACKED DIGEST" else (_safe_error(error) if error else None),
              "tracking_issue": tracking_issue}
    if tracking_tag:
        public["tracking_tag"] = tracking_tag
    if target_image:
        public["target_image"] = target_image
    return public


class ReadOnlyService:
    """Bounded agent service; historical class name retained for compatibility.

    Read RPCs and the fixed single-service update operations share this service;
    arbitrary Docker/command execution is intentionally not part of its API.
    """
    def __init__(self, config: Config, state: State, web_settings: dict | None = None):
        self.config, self.state = config, state
        self.web_settings = web_settings or {"audit_retention_days": 365, "scan_retention_days": 30}
        self._threads: dict[str, threading.Thread] = {}
        self._refresh_threads: dict[str, threading.Thread] = {}
        self._refresh_started_at: dict[str, str] = {}
        self._refresh_again: set[str] = set()
        self._operation_threads: dict[str, threading.Thread] = {}
        # Opaque, short-lived references point to trusted target material held
        # only by the privileged agent. A page field can select an intent but
        # cannot supply or alter the image used for execution.
        self._update_intents: dict[str, UpdateReviewIntent] = {}
        self._rollback_intents: dict[str, RollbackReviewIntent] = {}
        self._compose_intents: dict[str, ComposeReviewIntent] = {}
        self._lock = threading.Lock()
        # Serialises baseline capture/adoption so concurrent status reads
        # cannot write duplicate or interleaved baseline material.
        self._baseline_lock = threading.Lock()
        self._adoption_failures: dict[tuple, float] = {}
        self._project_refresh_pending: dict[tuple, object] = {}
        self._project_refresh_thread = None
        # Display-only read-through cache for Service Detail. Update review
        # and execution never read it.
        self._bootstrap_intents: dict[str, BootstrapReviewIntent] = {}
        self._compose_status_cache: dict[tuple, tuple[float, dict]] = {}
        self._health_lock = threading.Lock()
        self._health_stop = threading.Event()
        self._health_thread = None
        self._docker_health_cache = {"ok": None, "status": "not checked"}
        hours = self.web_settings.get("verification_freshness_hours", 6)
        if type(hours) not in (int, float) or not 1 <= hours <= 168:
            raise ValueError("verification freshness must be between 1 and 168 hours")
        self.verification_freshness_seconds = hours * 3600

    @staticmethod
    def _validate_service_key(service_key):
        if (not isinstance(service_key, str) or not re.fullmatch(r"container/[0-9a-f]{64}", service_key)):
            raise ValueError("invalid service identifier")

    def verification_snapshot(self):
        now = datetime.now(timezone.utc)
        records = self.state.verification_snapshot()
        for record in records:
            checked_at = record.get("checked_at")
            try:
                age = (now - datetime.fromisoformat(checked_at)).total_seconds() if checked_at else float("inf")
            except (TypeError, ValueError):
                age = float("inf")
            record["fresh"] = bool(record.get("result") and not record.get("failed_at")
                                   and 0 <= age <= self.verification_freshness_seconds)
            record.pop("identity", None)
        return {"records": records}

    def start_refresh(self, service_key, *, after_reconcile=False):
        self._validate_service_key(service_key)
        with self._lock:
            thread = self._refresh_threads.get(service_key)
            if thread and thread.is_alive():
                started = self._refresh_started_at.get(service_key)
                if after_reconcile and started:
                    record = next((item for item in self.verification_snapshot()["records"]
                                   if item["service_key"] == service_key), None)
                    if record and record.get("failed_at") and record["failed_at"] > started:
                        self._refresh_again.add(service_key)
                return {"status": "checking", "existing": True}
            if self.state.active_scan() and not after_reconcile:
                return {"status": "scan_active", "existing": True}
            record = next((item for item in self.verification_snapshot()["records"]
                           if item["service_key"] == service_key), None)
            if record and record.get("failed_at") and not record.get("invalidated") and not after_reconcile:
                try:
                    elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(record["failed_at"])).total_seconds()
                except (TypeError, ValueError):
                    elapsed = 60
                if elapsed < 60:
                    return {"status": "retry_later", "existing": True}
            thread = threading.Thread(target=self._refresh_worker,
                                      args=(service_key, True) if after_reconcile else (service_key,),
                                      name=f"upt-refresh-{service_key[10:18]}", daemon=True)
            self._refresh_threads[service_key] = thread
            self._refresh_again.discard(service_key)
            try:
                thread.start()
            except Exception:
                self._refresh_threads.pop(service_key, None)
                raise
            return {"status": "checking", "existing": False}

    def _queue_post_mutation(self, service):
        self._compose_status_cache.clear()
        return self.start_refresh("container/" + service.container_id, after_reconcile=True)

    def _discover_post_mutation(self):
        return discover(self.config, all_containers=True)

    def refresh_status(self, service_key):
        self._validate_service_key(service_key)
        with self._lock:
            thread = self._refresh_threads.get(service_key)
            checking = bool((thread and thread.is_alive()) or service_key in self._refresh_again)
        record = next((item for item in self.verification_snapshot()["records"]
                       if item["service_key"] == service_key), None)
        return {"status": "checking" if checking else ("failed" if record and record.get("failed_at") and not record.get("invalidated") else "idle"),
                "record": record}

    def _refresh_worker(self, service_key, wait_for_scan=False):
        try:
            while True:
                with self.state.scan_worker_guard():
                    if not self.state.active_scan():
                        started_at = datetime.now(timezone.utc).isoformat()
                        with self._lock:
                            self._refresh_started_at[service_key] = started_at
                        found = [service for service in discover(self.config)
                                 if f"container/{service.container_id}" == service_key]
                        if len(found) != 1:
                            return
                        service = found[0]
                        public = _public_service(service)
                        identity = verification_identity(public)
                        try:
                            result = _public_result(scan_service_with_tracking(service, self.state), self.state)
                        except Exception as exc:
                            result = {"service": public, "status": "REGISTRY ERROR", "error": _safe_error(exc)}
                        # Replacement during a registry query cannot produce
                        # current evidence for this exact container key.
                        current = [item for item in discover(self.config) if item.container_id == service.container_id]
                        if len(current) != 1 or verification_identity(_public_service(current[0])) != identity:
                            return
                        self.state.save_verification(result, started_at=started_at)
                        return
                if not wait_for_scan:
                    return
                # One targeted refresh queued by this Apply, never a scheduler.
                time.sleep(.2)
        except Exception:
            logging.getLogger(__name__).warning("Service verification failed for %s", _safe_mutation_log_identifier(service_key))
        finally:
            with self._lock:
                again = service_key in self._refresh_again
                if self._refresh_threads.get(service_key) is threading.current_thread():
                    self._refresh_threads.pop(service_key, None)
                    self._refresh_started_at.pop(service_key, None)
            if again:
                try:
                    self.start_refresh(service_key, after_reconcile=True)
                except Exception:
                    with self._lock:
                        self._refresh_again.discard(service_key)
                    logging.getLogger(__name__).warning("Post-mutation targeted verification needs retry")

    def health(self):
        # RPC health is a cheap liveness check. Docker probing runs on a single
        # background monitor so unauthenticated health traffic and cached UI
        # reads cannot trigger or wait behind a Docker CLI subprocess.
        with self._health_lock:
            docker = dict(self._docker_health_cache)
        return {"ok": True, "service": "upt-agent", "version": __version__, "docker": docker}

    def start_health_monitor(self, interval_seconds: int = RUNTIME_INTERVAL_SECONDS):
        """Start one agent-owned liveness and runtime snapshot monitor."""
        with self._health_lock:
            if self._health_thread and self._health_thread.is_alive():
                return
            self._health_stop.clear()

            def monitor():
                while not self._health_stop.is_set():
                    result = self._docker_health()
                    with self._health_lock:
                        self._docker_health_cache = result
                    self._refresh_runtime_snapshot()
                    self._health_stop.wait(max(5, int(interval_seconds)))

            self._health_thread = threading.Thread(target=monitor, name="upt-runtime-health", daemon=True)
            self._health_thread.start()

    def _refresh_runtime_snapshot(self):
        attempted_at = datetime.now(timezone.utc).isoformat()
        logger = logging.getLogger(__name__)
        try:
            containers = collect_runtime_containers(self.config)
        except RuntimeProbeError as exc:
            logger.warning(
                "Runtime probe failed stage=%s category=%s failure_class=%s exit_code=%s",
                exc.stage, exc.category, exc.failure_class,
                exc.exit_code if exc.exit_code is not None else "none",
            )
            try:
                self.state.record_runtime_failure(attempted_at=attempted_at, failure_category=exc.category)
            except Exception as persist_exc:
                logger.warning(
                    "Runtime failure persistence failed stage=persist category=%s failure_class=%s",
                    exc.category, _safe_runtime_failure_class(persist_exc),
                )
                pass
            return
        except Exception as exc:
            # Never persist exception text from Docker, the process runner, or
            # SQLite as a browser-visible runtime diagnostic.
            logger.warning(
                "Runtime probe failed stage=collect category=probe_failed failure_class=%s exit_code=%s",
                _safe_runtime_failure_class(exc), _safe_runtime_exit_code(exc),
            )
            try:
                self.state.record_runtime_failure(attempted_at=attempted_at, failure_category="probe_failed")
            except Exception as persist_exc:
                logger.warning(
                    "Runtime failure persistence failed stage=persist category=probe_failed failure_class=%s",
                    _safe_runtime_failure_class(persist_exc),
                )
                pass
            return
        captured_at = datetime.now(timezone.utc).isoformat()
        try:
            self.state.save_runtime_snapshot(containers, captured_at=captured_at, attempted_at=attempted_at)
        except Exception as exc:
            # A failed persistence write leaves the previous snapshot untouched.
            logger.warning(
                "Runtime snapshot persistence failed stage=persist failure_class=%s",
                _safe_runtime_failure_class(exc),
            )
            return

    def stop_health_monitor(self):
        self._health_stop.set()
        thread = self._health_thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=6)

    def _docker_health(self):
        try:
            from .system import run
            version = run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=10).strip()
            return {"ok": True, "version": version or "unknown"}
        except Exception:
            return {"ok": False, "error": "Docker daemon unavailable"}

    def snapshot(self):
        item = self.state.latest_scan()
        return item or {"status": "never", "payload": {"services": [], "count": 0}}

    def runtime_snapshot(self):
        return self.state.runtime_snapshot()

    def service(self, service_key: str):
        if (not isinstance(service_key, str) or not service_key or len(service_key) > 200
                or any(c in service_key for c in "\0\r\n") or service_key.strip() != service_key):
            raise ValueError("invalid service identifier")
        item = self.snapshot()
        services = item.get("payload", {}).get("services", [])
        for result in services:
            service = result.get("service") or {}
            if service.get("key") == service_key:
                return {**result, "_review_scan_id": item.get("scan_id")}
        name_matches = [result for result in services if (result.get("service") or {}).get("name") == service_key]
        if len(name_matches) == 1:
            return {**name_matches[0], "_review_scan_id": item.get("scan_id")}
        if len(name_matches) > 1:
            raise ValueError("service name is ambiguous in cached scan; use its full service link")
        raise ValueError("service not found in cached scan")

    def start_scan(self):
        with self._lock:
            for active_id, active_thread in self._threads.items():
                if active_thread.is_alive():
                    run = self.state.scan_run_summary(active_id)
                    if run and run.get("status") in {"running", "finalizing"}:
                        return {"run_id": active_id, "status": run["status"], "existing": True}
            run_id = uuid.uuid4().hex
            result = self.state.claim_scan(run_id)
            if result.get("existing"): return result
            self.state.scan_event(run_id, "operation_started", message="Read-only scan started")
            thread = threading.Thread(target=self._guarded_scan_worker, args=(run_id,), name=f"upt-scan-{run_id[:8]}", daemon=True)
            self._threads[run_id] = thread
            thread.start()
            return {"run_id": run_id, "status": "running", "existing": False}

    def _guarded_scan_worker(self, run_id: str):
        try:
            with self.state.scan_worker_guard():
                self._scan_worker(run_id)
        except Exception:
            logging.getLogger(__name__).exception("Scan worker lease or worker failed")
            message = "scan worker lease unavailable"
            try:
                self.state.stage_scan_result(run_id, "failed", error=message, services=[])
                try:
                    self.state.mark_scan_terminal(run_id, "failed", message=message)
                except Exception:
                    self.state.mark_scan_terminal(run_id, "failed", emit_event=False)
            except Exception:
                logging.getLogger(__name__).warning("Could not persist scan worker failure state")
        finally:
            with self._lock:
                self._threads.pop(run_id, None)

    def scan_status(self, run_id: str | None = None, after_event_id: int = 0):
        if run_id is None:
            run = self.state.active_scan()
            if run:
                return self.state.scan_run_summary(run["id"])
            else:
                recent = self.state.latest_scan_run()
                if recent:
                    return recent
                latest = self.state.latest_scan()
                if not latest:
                    return {"status": "never", "events": []}
                run_id = latest.get("scan_id")
        run = self.state.scan_run(run_id, after_event_id=after_event_id)
        if not run:
            raise ValueError("scan operation not found")
        return run

    def audit_recent(self, limit=100):
        try: limit = max(1, min(200, int(limit)))
        except (TypeError, ValueError): limit = 100
        return {"events": self.state.audit_events(limit)}

    @staticmethod
    def _exact_payload(payload, names):
        if set(payload) != set(names):
            raise ValueError("invalid operation request")

    def _completed_update_candidate(self, service_key, include_live=False):
        self._validate_service_key(service_key)
        record = next((item for item in self.verification_snapshot()["records"]
                       if item["service_key"] == service_key), None)
        if not record or not record.get("fresh") or not record.get("verification_id"):
            raise ValueError("current service update verification is required; refresh this service")
        result = record.get("result") or {}
        service = result.get("service") or {}
        if result.get("status") not in UPDATE_STATUSES:
            raise ValueError("service does not currently have a verified update")
        if (not service.get("container_id") or not service.get("stack")
                or not service.get("compose_service") or not service.get("working_dir")
                or not service.get("compose_files") or service.get("state") != "running"
                or not service.get("digest")
                or service.get("local_build") or service.get("ignored")):
            raise ValueError("service is not an eligible running Compose service")
        found = discover(self.config)
        live = [item for item in found if item.container_id == service["container_id"]]
        if len(live) != 1 or verification_identity(_public_service(live[0])) != verification_identity(service):
            raise ReviewedTargetChanged("The service identity changed. Refresh this service and review again.")
        if include_live:
            return record, result, service, live[0], found
        return record, result, service

    def _cached_update_candidate(self, service_key):
        return self._completed_update_candidate(service_key)[2]

    @staticmethod
    def _model_fingerprint(model):
        encoded=json.dumps(model,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _bytes_fingerprint(value):
        return hashlib.sha256(value).hexdigest()

    @staticmethod
    def _rollback_details(row):
        try: details=json.loads(row.get("details") or "{}")
        except (TypeError,json.JSONDecodeError): details={}
        return details if isinstance(details,dict) else {}

    def _compose_model_from_backups(self,service,files,compose_paths,env_path=None):
        args=["docker","compose","--project-directory",service.working_dir]
        if env_path and env_path in files: args += ["--env-file",str(files[env_path])]
        for source in compose_paths:
            if source not in files: raise ValueError("the retained Compose backup is incomplete")
            args += ["-f",str(files[source])]
        try:
            model=json.loads(run(args+["config","--format","json"],cwd=service.working_dir,timeout=30))
        except Exception:
            raise ValueError("the retained Compose project model could not be verified") from None
        if not isinstance(model,dict) or not isinstance(model.get("services"),dict):
            raise ValueError("the retained Compose project model could not be verified")
        return model

    def _latest_rollback_point(self,service):
        rows=[row for row in self.state.history_for_service(service.stack,service.key)
              if row.get("action")=="update" and row.get("result")=="SUCCESS"]
        if not rows: raise ValueError("no successful rollback point is available for this service")
        row=rows[0]
        if not row.get("old_image_id") or not row.get("old_image") or not row.get("new_image_id"):
            raise ValueError("the latest rollback point does not have a verifiable image identity")
        if service.image_id!=row.get("new_image_id"):
            raise ValueError("the service no longer matches the latest successful update; review its current state first")
        with self.state.connect() as connection:
            found=connection.execute(
                "SELECT history_id,image_id,created,expired,purge_status FROM rollback_refs WHERE history_id=?",
                (row["id"],),
            ).fetchone()
        if not found: raise ValueError("the protected rollback image reference is missing")
        point=dict(zip(("history_id","image_id","created","expired","purge_status"),found))
        if point["image_id"]!=row["old_image_id"]:
            raise ValueError("the protected rollback image identity does not match its history record")
        retention=self.config.data.get("retention",{})
        days=int(retention.get("rollback_images_days",retention.get("recovery_days",7)))
        try:
            from .retention import expires
            expiry=expires(point["created"],days)
        except (TypeError,ValueError,OverflowError):
            raise ValueError("rollback point expiry could not be verified") from None
        if point["expired"] or point["purge_status"] in {"PURGED","ALREADY ABSENT"} or expiry<=datetime.now(timezone.utc):
            raise ValueError("the latest rollback point has expired")
        return row,point,expiry

    def _rollback_manifest(self,service,row):
        value=row.get("backup")
        if not isinstance(value,str) or not value: raise ValueError("the retained Compose backup is missing")
        root=(self.state.root/"backups").resolve(strict=False)
        directory=Path(value)
        if directory.is_symlink(): raise ValueError("the retained Compose backup cannot be verified")
        try: directory=directory.resolve(strict=True)
        except OSError: raise ValueError("the retained Compose backup is missing") from None
        if not directory.is_relative_to(root) or not directory.is_dir():
            raise ValueError("the retained Compose backup is outside UPT recovery storage")
        metadata=directory/"metadata.json"
        if metadata.is_symlink() or not metadata.is_file() or metadata.stat().st_size>65536:
            raise ValueError("the retained Compose backup metadata cannot be verified")
        try:
            raw=metadata.read_bytes(); data=json.loads(raw)
        except (OSError,ValueError,json.JSONDecodeError):
            raise ValueError("the retained Compose backup metadata cannot be verified") from None
        if data.get("stack")!=service.stack or data.get("service")!=service.key:
            raise ValueError("the retained Compose backup belongs to a different service")
        entries=data.get("files")
        if not isinstance(entries,list) or not entries or len(entries)>32:
            raise ValueError("the retained Compose backup file inventory is invalid")
        source_paths=[str(Path(item).resolve(strict=True)) for item in service.compose_files]
        if len(set(source_paths))!=len(source_paths): raise ValueError("Compose source identity is ambiguous")
        env_path=Path(service.working_dir)/".env"
        expected_paths=list(source_paths)
        if env_path.exists() or env_path.is_symlink(): expected_paths.append(str(env_path.resolve(strict=True)))
        mapping={}; destinations=set(); seen_sources=[]; total=0; fingerprint=hashlib.sha256(raw)
        for item in entries:
            if not isinstance(item,dict) or set(item)!={"source","backup"}:
                raise ValueError("the retained Compose backup file inventory is invalid")
            source=Path(item["source"])
            if source.is_symlink(): raise ValueError("a Compose backup source is a symbolic link")
            try: source=source.resolve(strict=True)
            except OSError: raise ValueError("a Compose backup source is unavailable") from None
            source_name=str(source)
            if source_name in seen_sources: raise ValueError("the retained Compose backup source list is ambiguous")
            seen_sources.append(source_name)
            backup=Path(item["backup"])
            if backup.is_symlink(): raise ValueError("a retained Compose backup file is a symbolic link")
            try: backup=backup.resolve(strict=True)
            except OSError: raise ValueError("a retained Compose backup file is missing") from None
            if not backup.is_relative_to(directory) or not backup.is_file() or backup in destinations:
                raise ValueError("the retained Compose backup file inventory is invalid")
            destinations.add(backup)
            content=backup.read_bytes(); total+=len(content)
            if total>16*1024*1024: raise ValueError("the retained Compose backup exceeds the verification limit")
            mapping[source_name]={"backup":backup,"restore":content}
            fingerprint.update(source_name.encode()); fingerprint.update(str(backup.relative_to(directory)).encode())
            fingerprint.update(self._bytes_fingerprint(content).encode())
        if seen_sources[:len(source_paths)]!=source_paths or seen_sources not in (expected_paths,source_paths):
            raise ValueError("the retained Compose backup does not cover the current project sources")
        if len({path.name for path in destinations})!=len(destinations):
            raise ValueError("the retained Compose backup contains ambiguous file names")
        return {"directory":directory,"metadata":data,"files":mapping,"fingerprint":fingerprint.hexdigest(),
                "compose_paths":source_paths,"env_path":str(env_path.resolve(strict=False))}

    def _verify_local_image_identity(self,image_id,reference,digest,architecture):
        if not isinstance(image_id,str) or not re.fullmatch(r"sha256:[0-9a-f]{64}",image_id):
            raise ValueError("the exact image ID is unavailable")
        try:
            raw=run(["docker","image","inspect","--format","{{json .}}",image_id],timeout=30)
            image=json.loads(raw)
        except (OSError,RuntimeError,ValueError,TypeError):
            raise ValueError("the exact image is unavailable locally") from None
        if isinstance(image,list): image=image[0] if len(image)==1 else None
        if not isinstance(image,dict) or image.get("Id")!=image_id:
            raise ValueError("the exact image could not be proven locally")
        if architecture and image.get("Architecture")!=architecture:
            raise ValueError("the image architecture does not match the running service")
        if digest:
            try: ref=parse_image_ref(reference)
            except (TypeError,ValueError): raise ValueError("the recorded image digest identity is invalid") from None
            matches=[]
            for item in image.get("RepoDigests") or []:
                if not isinstance(item,str) or "@" not in item: continue
                candidate=parse_image_ref(item)
                if candidate.digest==digest and (candidate.registry,candidate.repository)==(ref.registry,ref.repository):
                    matches.append(item)
            if not matches:
                raise ValueError("the image does not match its recorded digest")
        return image

    def _rollback_image_identity(self,row,architecture):
        image=self._verify_local_image_identity(row.get("old_image_id"),row.get("old_image"),
                                                row.get("old_digest"),architecture)
        return image

    def _rollback_evidence(self,service,row,point):
        manifest=self._rollback_manifest(service,row)
        details=self._rollback_details(row); pin_advanced=details.get("pin_advanced") is True
        files=manifest["files"]
        backup_paths={source:str(item["backup"]) for source,item in files.items()}
        backup_compose=[backup_paths[source] for source in manifest["compose_paths"]]
        restored_model=self._compose_model_from_backups(
            service,backup_paths,manifest["compose_paths"],manifest["env_path"] if manifest["env_path"] in backup_paths else None)
        current_model=self._compose_config_model(service)
        try:
            _assert_project_identity(service, current_model)
            _assert_project_identity(service, restored_model)
        except _ExecutionContextRefused:
            raise ValueError("the Compose project identity changed") from None
        current_target=(current_model.get("services") or {}).get(service.compose_service)
        restored_target=(restored_model.get("services") or {}).get(service.compose_service)
        if not isinstance(current_target,dict) or not isinstance(restored_target,dict):
            raise ValueError("the selected service is missing from its Compose project model")
        if restored_target.get("image")!=row.get("old_image"):
            raise ValueError("the retained Compose model does not match the recorded rollback image")
        expected_model=copy.deepcopy(restored_model)
        expected_target=(expected_model.get("services") or {}).get(service.compose_service)
        expected_target["image"]=(row.get("new_image") if pin_advanced else row.get("old_image"))
        if current_model!=expected_model:
            raise ValueError("Compose configuration changed outside the reviewed update; rollback was refused")
        if pin_advanced and (not isinstance(row.get("new_image"),str) or "@sha256:" not in row["new_image"]):
            raise ValueError("the recorded digest pin change cannot be verified")
        found=discover(self.config)
        self._verify_compose_runtime_identity(service,found,compose_model=current_target)

        expected_current={path:dict(item) for path,item in files.items()}
        if pin_advanced:
            backup_service=SimpleNamespace(
                key=service.key,compose_service=service.compose_service,
                compose_files=backup_compose,working_dir=str(manifest["directory"]),
                image=row.get("new_image"),digest=row.get("new_digest"),version=row.get("new_version"),
            )
            try: changed_path,old_text,new_text,_kind=pin_plan(
                backup_service,digest=True,target_image=row["new_image"])
            except Exception:
                raise ValueError("the recorded digest pin backup could not be reproduced") from None
            changed_backup=Path(changed_path).resolve(strict=True)
            matches=[path for path,item in expected_current.items() if item["backup"]==changed_backup]
            if len(matches)!=1 or old_text.encode("utf-8")!=expected_current[matches[0]]["restore"]:
                raise ValueError("the recorded digest pin source could not be verified")
            expected_current[matches[0]]["current_expected"]=new_text.encode("utf-8")
        sources=[]; source_identity=[]
        for source,item in expected_current.items():
            path=Path(source)
            if path.is_symlink() or not path.is_file(): raise ValueError("a Compose source is missing or unsafe")
            before=path.read_bytes(); restore=item["restore"]
            if before!=item.get("current_expected",restore):
                raise ValueError("Compose source changed outside the reviewed update; rollback was refused")
            sources.append({"path":source,"before":before,"restore":restore})
            source_identity.append((source,self._bytes_fingerprint(before),self._bytes_fingerprint(restore)))
        image_identity=self._rollback_image_identity(row,service.architecture)
        return {"manifest":manifest,"sources":sources,"source_identity":tuple(source_identity),
                "current_model":current_model,"restored_model":restored_model,
                "current_model_identity":self._model_fingerprint(current_model),
                "restored_model_identity":self._model_fingerprint(restored_model),
                "image_identity":image_identity,
                "point_identity":self._rollback_point_identity(row,point,manifest)}

    @staticmethod
    def _rollback_point_identity(row,point,manifest):
        return (int(row["id"]),point["history_id"],point["image_id"],point["created"],
                point["expired"],point["purge_status"],row.get("old_image"),row.get("old_image_id"),
                row.get("old_digest"),row.get("old_version"),row.get("new_image"),
                row.get("new_image_id"),row.get("backup"),manifest["fingerprint"])

    def _completed_rollback_candidate(self,service_key):
        self._validate_service_key(service_key)
        found=[item for item in discover(self.config) if f"container/{item.container_id}"==service_key]
        if len(found)!=1: raise ReviewedTargetChanged("the selected service identity changed; refresh and review again")
        service=found[0]; public=_public_service(service)
        if (not public.get("stack") or not public.get("compose_service") or not public.get("working_dir")
                or not public.get("compose_files") or public.get("state")!="running"
                or public.get("local_build") or public.get("ignored")):
            raise ValueError("service is not an eligible running Compose service")
        require_mutation_safe(service)
        row,point,_expiry=self._latest_rollback_point(service)
        evidence=self._rollback_evidence(service,row,point)
        return service,row,point,evidence

    def rollback_review(self,payload):
        self._exact_payload(payload,{"service_key","requested_by"})
        service_key,requested_by=payload["service_key"],payload["requested_by"]
        if not isinstance(requested_by,str) or not requested_by or len(requested_by)>80 or any(c in requested_by for c in "\0\r\n"):
            raise ValueError("invalid requester")
        service,row,point,evidence=self._completed_rollback_candidate(service_key)
        self.state.assert_service_unfenced(service)
        now=time.monotonic()
        with self._lock:
            self._rollback_intents={key:item for key,item in self._rollback_intents.items() if item.expires_at>now}
            while len(self._rollback_intents)>=ROLLBACK_REVIEW_LIMIT:
                self._rollback_intents.pop(next(iter(self._rollback_intents)))
            confirmation_id=secrets.token_urlsafe(32)
            intent=RollbackReviewIntent(
                service_key=service_key,requested_by=requested_by,
                service_identity=self._rollback_service_review_identity(_public_service(service)),
                rollback_identity=evidence["point_identity"],backup_fingerprint=evidence["manifest"]["fingerprint"],
                source_identity=evidence["source_identity"],
                current_model_identity=evidence["current_model_identity"],
                restored_model_identity=evidence["restored_model_identity"],
                expires_at=now+ROLLBACK_REVIEW_TTL_SECONDS,
            )
            self._rollback_intents[confirmation_id]=intent
        rollback={
            "service":service.name,"stack":service.stack,"current_image":service.image,
            "current_version":service.version,"current_digest":service.digest,
            "target_image":row.get("old_image"),"target_version":row.get("old_version"),
            "target_digest":row.get("old_digest"),"history_timestamp":row.get("timestamp"),
            "digest_pin":bool(parse_image_ref(service.image).digest or parse_image_ref(str(row.get("old_image"))).digest),
        }
        # This is presentation metadata only. Keep the server-selected rollback
        # point and its confirmation intent bound to the protected evidence above.
        try:
            tracked_image=tracking_image(service,self.state)
            tracking_tag=parse_image_ref(tracked_image).tag if tracked_image else None
            if (not isinstance(tracking_tag,str) or not tracking_tag or len(tracking_tag)>128
                    or any(char in tracking_tag for char in "\0\r\n/@")):
                tracking_tag=None
        except Exception:
            tracking_tag=None
        if tracking_tag:
            rollback["tracking_tag"]=tracking_tag
        return {"confirmation_id":confirmation_id,"rollback":rollback}

    def _rollback_intent_candidate(self,intent):
        try:
            service,row,point,evidence=self._completed_rollback_candidate(intent.service_key)
        except ValueError as exc:
            if isinstance(exc, (ReviewedTargetChanged, PreMutationRefusal)): raise
            raise ReviewedTargetChanged("the reviewed rollback point or service changed; refresh and review rollback again") from None
        if (self._rollback_service_review_identity(_public_service(service))!=intent.service_identity
                or evidence["point_identity"]!=intent.rollback_identity
                or evidence["manifest"]["fingerprint"]!=intent.backup_fingerprint
                or evidence["source_identity"]!=intent.source_identity
                or evidence["current_model_identity"]!=intent.current_model_identity
                or evidence["restored_model_identity"]!=intent.restored_model_identity):
            raise ReviewedTargetChanged("the reviewed rollback point or configuration changed; refresh and review rollback again")
        return service,row,point,evidence

    @staticmethod
    def _rollback_service_review_identity(service):
        return tuple(tuple(service.get(field) or []) if field=="compose_files" else service.get(field)
                     for field in ROLLBACK_REVIEW_IDENTITY_FIELDS)

    def _verify_rollback_reference(self,intent,service,row,point):
        rows=[item for item in self.state.history_for_service(service.stack,service.key)
              if item.get("action")=="update" and item.get("result")=="SUCCESS"]
        if not rows or int(rows[0]["id"])!=int(row["id"]):
            raise ReviewedTargetChanged("a newer service operation changed the rollback point")
        with self.state.connect() as connection:
            found=connection.execute(
                "SELECT history_id,image_id,created,expired,purge_status FROM rollback_refs WHERE history_id=?",
                (row["id"],),
            ).fetchone()
        if not found: raise ReviewedTargetChanged("the protected rollback point disappeared")
        reference=dict(zip(("history_id","image_id","created","expired","purge_status"),found))
        manifest=self._rollback_manifest(service,row)
        if (self._rollback_point_identity(row,reference,manifest)!=intent.rollback_identity
                or manifest["fingerprint"]!=intent.backup_fingerprint):
            raise ReviewedTargetChanged("the protected rollback point or backup changed")
        return manifest

    def _verify_service_before_rollback_recreate(self,expected):
        matches=[item for item in discover(self.config) if item.container_id==expected.container_id]
        if len(matches)!=1:
            raise ReviewedTargetChanged("the selected service changed during rollback")
        current=matches[0]
        if self._rollback_service_review_identity(_public_service(current))!=self._rollback_service_review_identity(_public_service(expected)):
            raise ReviewedTargetChanged("the selected service changed during rollback")
        require_mutation_safe(current)
        return current

    def _verify_rollback_image(self,row,architecture):
        return self._rollback_image_identity(row,architecture)

    def _recovery_backup_matches(self,path,service,sources):
        if path is None: raise ValueError("the pre-rollback recovery backup is unavailable")
        root=(self.state.root/"backups").resolve(strict=False); directory=Path(path)
        if directory.is_symlink(): raise ValueError("the pre-rollback recovery backup cannot be verified")
        directory=directory.resolve(strict=True)
        if not directory.is_relative_to(root) or not directory.is_dir():
            raise ValueError("the pre-rollback recovery backup cannot be verified")
        meta_path=directory/"metadata.json"
        if meta_path.is_symlink() or not meta_path.is_file():
            raise ValueError("the pre-rollback recovery backup cannot be verified")
        metadata=json.loads(meta_path.read_text())
        if metadata.get("stack")!=service.stack or metadata.get("service")!=service.key:
            raise ValueError("the pre-rollback recovery backup identity changed")
        recorded_paths={}; recorded_bytes={}
        for item in metadata.get("files",[]):
            source_path=Path(item["source"])
            if source_path.is_symlink(): raise ValueError("the pre-rollback recovery backup cannot be verified")
            source=str(source_path.resolve(strict=True)); backup=Path(item["backup"])
            if backup.is_symlink(): raise ValueError("the pre-rollback recovery backup cannot be verified")
            backup=backup.resolve(strict=True)
            if not backup.is_relative_to(directory) or not backup.is_file() or source in recorded_paths:
                raise ValueError("the pre-rollback recovery backup cannot be verified")
            recorded_paths[source]=backup
            recorded_bytes[source]=backup.read_bytes()
        if set(recorded_paths)!={item["path"] for item in sources}:
            raise ValueError("the pre-rollback recovery backup inventory changed")
        if any(recorded_bytes[item["path"]]!=item["before"] for item in sources):
            raise ValueError("the pre-rollback recovery backup contents changed")
        compose_paths=[str(Path(item).resolve(strict=True)) for item in service.compose_files]
        env_path=str((Path(service.working_dir)/".env").resolve(strict=False))
        verified_files={source:str(backup) for source,backup in recorded_paths.items()}
        model=self._compose_model_from_backups(service,verified_files,
                                               compose_paths,env_path if env_path in verified_files else None)
        return {"directory":directory,"files":recorded_bytes,"file_paths":verified_files,"model":model}

    def _rollback_progress_reporter(self,operation_id):
        return self._operation_progress_reporter(operation_id,"rollback","Preparing rollback")

    def _operation_progress_reporter(self,operation_id,operation,initial_stage):
        """The single core-event -> persisted-event bridge for every web operation.

        Only bounded labels are persisted (never command output, arguments or
        exception text). Numbered stages carry their real ``n/N`` label from the
        core; ``task_info`` is an unnumbered explanatory marker.
        """
        current_stage=[initial_stage]
        def stage_label(event):
            step,steps,label=(event.data or {}).get("step"),(event.data or {}).get("steps"),(event.data or {}).get("label")
            if isinstance(step,int) and isinstance(steps,int) and isinstance(label,str): return f"{step}/{steps} {label}"[:160]
            return None
        def persist(event):
            if event.kind in {"task_started","task_running"}:
                numbered=stage_label(event)
                if numbered: current_stage[0]=numbered
                elif event.kind=="task_started": current_stage[0]=str(event.message)[:160]
                kind,status,message="task_started","running","In progress"
            elif event.kind=="task_completed":
                numbered=stage_label(event)
                if numbered: current_stage[0]=numbered
                kind,status,message="task_completed","completed","Completed"
            elif event.kind=="task_progress": kind,status,message="task_progress","running","Working"
            elif event.kind=="task_warning": kind,status,message="task_warning","warning","Warning"
            elif event.kind=="task_failed":
                numbered=stage_label(event)
                if numbered: current_stage[0]=numbered
                kind,status,message="task_failed","failed","Step failed"
            elif event.kind=="task_info":
                # Bounded core-authored marker; not a step and never "running".
                kind,status,message="task_info","info",""
            else: return
            try: self.state.operation_event(operation_id,kind,stage=(str(event.message)[:160] if kind=="task_info" else current_stage[0]),message=message,status=status)
            except Exception: logging.getLogger(__name__).warning("Could not persist operation progress event")
        reporter=Reporter(enabled=False,on_event=persist); reporter.operation=operation; reporter.started=time.monotonic()
        return reporter

    def _safe_rollback_error(self,exc):
        if isinstance(exc,ComposeSourceNotWritable):
            return ("UPT cannot modify this service's Compose source from the agent sandbox. "
                    "Authorise the Compose project directory for UPT writes and try again.")
        if isinstance(exc,WebRollbackFailure):
            if exc.manual_recovery_required:
                return ("Rollback did not complete. Automatic recovery was refused or failed; recovery backups and "
                        "protected images were retained. Manual recovery is required.")
            if exc.recovered:
                return ("Rollback did not complete, but UPT restored the previous configuration and service. "
                        "The rollback point and recovery backup remain available.")
            return "Rollback did not complete; the running service was not recreated and the rollback point remains available."
        if isinstance(exc,ReviewedTargetChanged):
            return "The rollback review is stale. No further changes were made; refresh the service page and review rollback again."
        text=str(exc).lower()
        if "another web operation" in text or "another modifying" in text:
            return "Another UPT operation is active; no rollback was started."
        if "image" in text and ("missing" in text or "unavailable" in text or "proven" in text):
            return "The protected rollback image is unavailable or could not be verified locally. No rollback was started."
        if "backup" in text or "rollback point" in text:
            return "The retained rollback point or configuration backup is unavailable or changed. No rollback was started."
        if "configuration" in text or "compose" in text or "source" in text:
            return "Compose configuration changed or could not be verified. No unrelated changes were overwritten; review the service and rollback backup."
        return "The rollback failed. Check UPT History for the recorded outcome and recovery status."

    def start_rollback(self,payload):
        self._exact_payload(payload,{"confirmation_id","requested_by","client_ip","user_agent"})
        confirmation_id=payload["confirmation_id"]
        username,client_ip,user_agent=(payload["requested_by"],payload["client_ip"],payload["user_agent"])
        if not isinstance(confirmation_id,str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}",confirmation_id):
            raise ValueError("invalid or expired rollback review; refresh and review rollback again")
        for value,label,limit in ((username,"requester",80),(client_ip,"client address",64),(user_agent,"user agent",300)):
            if not isinstance(value,str) or (label=="requester" and not value) or len(value)>limit or any(c in value for c in "\0\r\n"):
                raise ValueError(f"invalid {label}")
        operation_id=uuid.uuid4().hex
        with self._lock:
            intent=self._rollback_intents.get(confirmation_id)
            if not intent or intent.expires_at<=time.monotonic() or intent.requested_by!=username:
                self._rollback_intents.pop(confirmation_id,None)
                raise ValueError("invalid or expired rollback review; refresh and review rollback again")
            with Lock(self.state.root/"update.lock"):
                self.state.ensure_compatible()
                self.state.recover_abandoned_operations()
                service,row,_point,evidence=self._rollback_intent_candidate(intent)
                self.state.assert_service_unfenced(service)
                summary={"service":service.name,"stack":service.stack,
                         "current_image":service.image,"current_version":service.version,
                         "target_image":row.get("old_image"),"target_version":row.get("old_version"),
                         "target_digest":row.get("old_digest")}
                self.state.create_operation(operation_id,kind="rollback",service_key=intent.service_key,
                                            service=service.name,stack=service.stack,
                                            requested_by=username,summary=summary)
                try:
                    self.state.audit("web_rollback","requested",username=username,client_ip=client_ip,
                                     user_agent=user_agent,details={"origin":"web","operation_id":operation_id,
                                                                    "service_key":intent.service_key})
                except Exception:
                    self.state.finish_operation(operation_id,"failed",message="Rollback could not be audited; no changes were made.",error="audit unavailable")
                    raise RuntimeError("rollback could not be safely recorded") from None
            self._rollback_intents.pop(confirmation_id,None)
            thread=threading.Thread(target=self._rollback_worker,args=(operation_id,payload,intent),
                                    name=f"upt-rollback-{operation_id[:8]}",daemon=True)
            self._operation_threads[operation_id]=thread
            try: thread.start()
            except RuntimeError:
                self._operation_threads.pop(operation_id,None)
                self.state.finish_operation(operation_id,"failed",message="Rollback worker could not start; no changes were made.",error="worker unavailable")
                self.state.audit("web_rollback","failed",username=username,client_ip=client_ip,
                                 user_agent=user_agent,details={"origin":"web","operation_id":operation_id,
                                                               "error":"worker unavailable"})
                raise RuntimeError("rollback worker could not start; no changes were made") from None
        return {"operation_id":operation_id,"status":"queued","service":summary["service"]}

    def _review_target(self, result, service):
        status = result.get("status") if isinstance(result, dict) else getattr(result, "status", None)
        digest = result.get("remote_digest") if isinstance(result, dict) else getattr(result, "remote_digest", None)
        version = result.get("remote_version") if isinstance(result, dict) else getattr(result, "remote_version", None)
        created = result.get("remote_created") if isinstance(result, dict) else getattr(result, "remote_created", None)
        target_image = None
        if status == "PINNED UPDATE":
            channel = None
            if isinstance(service, dict):
                channel = tracking_image(SimpleNamespace(image=service.get("image"), stack=service.get("stack"),
                                                         key=service.get("compose_service") or service.get("key")), self.state)
            else:
                channel = tracking_image(service, self.state)
            if not channel or not digest:
                raise ValueError("the exact digest target could not be resolved; refresh and review the service again")
            target_image = f"{channel.rsplit('@', 1)[0]}@{digest}"
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("the exact available image digest could not be verified; refresh and review the service again")
        return (status, digest, version, created, target_image)

    @staticmethod
    def _service_review_identity(service):
        return tuple(tuple(service.get(field) or []) if field == "compose_files" else service.get(field)
                     for field in UPDATE_REVIEW_IDENTITY_FIELDS)

    def update_review(self, payload):
        self._exact_payload(payload, {"service_key", "requested_by", "verification_id"})
        service_key, requested_by, rendered_verification_id = (
            payload["service_key"], payload["requested_by"], payload["verification_id"]
        )
        if (not isinstance(requested_by, str) or not requested_by or len(requested_by) > 80
                or any(char in requested_by for char in "\0\r\n")):
            raise ValueError("invalid requester")
        record, result, service, live, found = self._completed_update_candidate(service_key, include_live=True)
        if not isinstance(rendered_verification_id, str) or rendered_verification_id != record.get("verification_id"):
            raise ReviewedTargetChanged(
                "The service changed while its review page was being prepared. Refresh the service page and review the current target before updating."
            )
        # Independent agent-side preflight: a stale or tampered page cannot
        # obtain an update review while Compose drift exists. Execution keeps
        # its own mutation-time revalidation; this is an additional layer.
        plan = self._compose_plan(live, found, persist=False)
        if not plan.update_eligible:
            reasons = plan.update_reasons if plan.status == IN_SYNC else plan.reasons
            raise ComposePreflightRefused(plan.status, reasons[0] if reasons else "")
        target = self._review_target(result, service)
        if result.get("status") == "PINNED UPDATE" and result.get("target_image") != target[4]:
            raise ReviewedTargetChanged("The tracked image target changed. Refresh this service and review again.")
        now = time.monotonic()
        with self._lock:
            self._update_intents = {key: item for key, item in self._update_intents.items()
                                    if item.expires_at > now}
            while len(self._update_intents) >= UPDATE_REVIEW_LIMIT:
                self._update_intents.pop(next(iter(self._update_intents)))
            confirmation_id = secrets.token_urlsafe(32)
            self._update_intents[confirmation_id] = UpdateReviewIntent(
                verification_id=record["verification_id"], service_key=service_key, requested_by=requested_by,
                target=target, service_identity=self._service_review_identity(service),
                expires_at=now + UPDATE_REVIEW_TTL_SECONDS,
                execution_context_fingerprint=plan.execution_context_fingerprint or "",
                namespace_review=plan.namespace_update_review,
            )
        return {"confirmation_id": confirmation_id}

    def _intent_candidate(self, intent):
        try:
            record, result, service = self._completed_update_candidate(intent.service_key)
        except ValueError:
            raise ReviewedTargetChanged(
                "The reviewed service or image target changed. Refresh the service page and review the current target before updating."
            ) from None
        if (record.get("verification_id") != intent.verification_id
                or self._service_review_identity(service) != intent.service_identity
                or self._review_target(result, service) != intent.target):
            raise ReviewedTargetChanged(
                "The reviewed image target is stale or changed. Refresh the service page and review the current target before updating."
            )
        return service

    @staticmethod
    def _target_identity(result):
        return (getattr(result, "status", None), getattr(result, "remote_digest", None),
                getattr(result, "remote_version", None), getattr(result, "remote_created", None))

    def _verify_local_target(self, intent, image):
        try:
            raw = run(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image], timeout=30)
            digests = json.loads(raw)
            if not isinstance(digests, list):
                raise ValueError("image digest metadata is missing")
            target_ref = intent.target[4] or self._digest_reference(image, intent.target[1])
            target = parse_image_ref(target_ref)
            expected_repository = f"{target.registry}/{target.repository}"
            matches = []
            for entry in digests:
                if not isinstance(entry, str) or "@" not in entry:
                    continue
                parsed = parse_image_ref(entry)
                repository = f"{parsed.registry}/{parsed.repository}"
                if parsed.digest == intent.target[1] and repository == expected_repository:
                    matches.append(entry)
            if not matches:
                raise ValueError("pulled image does not match the reviewed digest")
        except Exception:
            raise ReviewedTargetChanged(
                "The pulled image could not be proven to match the reviewed digest. The service was not recreated; refresh and review the target again."
            ) from None

    @staticmethod
    def _digest_reference(image, digest):
        image_base = str(image).split("@", 1)[0]
        last = image_base.rsplit("/", 1)[-1]
        if ":" in last:
            image_base = image_base.rsplit(":", 1)[0]
        return f"{image_base}@{digest}"

    def start_update(self, payload):
        # The browser may submit only an opaque review reference. The exact
        # service and image target remain in agent-owned trusted state.
        self._exact_payload(payload, {"confirmation_id", "requested_by", "client_ip", "user_agent"})
        confirmation_id = payload["confirmation_id"]
        username, client_ip, user_agent = payload["requested_by"], payload["client_ip"], payload["user_agent"]
        if not isinstance(confirmation_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", confirmation_id):
            raise ValueError("invalid or expired update review; refresh the service page and review again")
        for value, label, limit in ((username, "requester", 80), (client_ip, "client address", 64),
                                    (user_agent, "user agent", 300)):
            if not isinstance(value, str) or (label == "requester" and not value) or len(value) > limit or any(char in value for char in "\0\r\n"):
                raise ValueError(f"invalid {label}")

        operation_id = uuid.uuid4().hex
        summary = None
        with self._lock:
            intent = self._update_intents.get(confirmation_id)
            if not intent or intent.expires_at <= time.monotonic() or intent.requested_by != username:
                self._update_intents.pop(confirmation_id, None)
                raise ValueError("invalid or expired update review; refresh the service page and review again")
            # Claim and stale-record reconciliation are serialized against the
            # same lock held by every live UPT mutation. A long-running worker
            # cannot be mistaken for a crash because it retains this lock even
            # while a Docker subprocess is blocked.
            with Lock(self.state.root / "update.lock"):
                self.state.ensure_compatible()
                self.state.recover_abandoned_operations()
                cached = self._intent_candidate(intent)
                service_key = intent.service_key
                summary = {"service": cached.get("name"), "stack": cached.get("stack"),
                           "old_image": cached.get("image"), "old_version": cached.get("version"),
                           "old_digest": cached.get("digest")}
                self.state.create_operation(operation_id, kind="update", service_key=service_key,
                                            service=cached.get("name") or cached.get("compose_service"),
                                            stack=cached.get("stack"), requested_by=username, summary=summary)
                audit_details = {"origin": "web", "operation_id": operation_id, "service_key": service_key}
                try:
                    self.state.audit("web_update", "requested", username=username, client_ip=client_ip,
                                     user_agent=user_agent, details=audit_details)
                except Exception:
                    self.state.finish_operation(operation_id, "failed", message="Update could not be audited; no changes were made.",
                                                error="audit unavailable")
                    raise RuntimeError("update could not be safely recorded") from None
            self._update_intents.pop(confirmation_id, None)
            thread = threading.Thread(target=self._update_worker, args=(operation_id, payload, intent),
                                      name=f"upt-update-{operation_id[:8]}", daemon=True)
            self._operation_threads[operation_id] = thread
            try:
                thread.start()
            except RuntimeError:
                self._operation_threads.pop(operation_id, None)
                self.state.finish_operation(operation_id, "failed", message="Update worker could not start; no changes were made.",
                                            error="worker unavailable")
                self.state.audit("web_update", "failed", username=username, client_ip=client_ip,
                                 user_agent=user_agent, details={"origin": "web", "operation_id": operation_id,
                                                                "service_key": service_key, "error": "worker unavailable"})
                raise RuntimeError("update worker could not start; no changes were made") from None
        return {"operation_id": operation_id, "status": "queued", "service": summary["service"]}

    @staticmethod
    def _compose_hash_from_output(service, output):
        lines = [line.strip() for line in str(output).splitlines() if line.strip()]
        prefix = f"{service} "
        if len(lines) != 1 or not lines[0].startswith(prefix):
            return None
        value = lines[0][len(prefix):]
        return value if COMPOSE_HASH_PATTERN.fullmatch(value) else None

    def _compose_service_hash(self, service, *, model=None, namespace_evidence=None):
        # Existing callers/peer proof receive the same resolved identity. Consumer
        # evaluations always calibrate against Compose, never cache calibration.
        if model is None and (getattr(service, "network_mode", None) or "").startswith("container:"):
            model = self._compose_config_model(service)
        selected = (model or {}).get("services", {}).get(service.compose_service, {})
        if isinstance(selected.get("network_mode"), str) and selected["network_mode"].startswith("service:"):
            evidence = namespace_evidence
            if evidence is None:
                values = []
                _execution_context_fingerprint(service, model, namespace_evidence=values)
                evidence = values[0]
            return resolved_hash(selected, evidence.container_id, _unmodified_compose_hash(service))
        return _unmodified_compose_hash(service)

    def _compose_config_model(self, service):
        try:
            raw = run(compose_args(service) + ["config", "--format", "json"],
                      cwd=service.working_dir, timeout=30)
            model = json.loads(raw)
        except Exception:
            model = None
        if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
            raise PreMutationRefusal(
                "Compose service configuration could not be verified; reconcile pending changes and refresh this service before updating", "compose_unverifiable"
            ) from None
        return model

    def _compose_service_model(self, service):
        model = self._compose_config_model(service)
        compose_service = model["services"].get(service.compose_service)
        if not isinstance(compose_service, dict):
            raise PreMutationRefusal(
                "Compose service configuration could not be verified; reconcile pending changes and refresh this service before updating", "compose_unverifiable"
            )
        return compose_service

    def _verify_compose_runtime_identity(self, service, found, expected_hash=None, compose_model=None):
        compose_model = compose_model or self._compose_service_model(service)
        if compose_model.get("image") != service.image:
            raise PreMutationRefusal("Compose image differs from the running image; update the Compose source and scan again", "compose_drift")
        deploy = compose_model.get("deploy") or {}
        if (compose_model.get("build") or compose_model.get("scale") is not None
                or compose_model.get("pull_policy") is not None or compose_model.get("profiles")
                or (isinstance(deploy, dict) and deploy.get("replicas") is not None)):
            # Docker Compose intentionally excludes these fields from its
            # service config hash; they can influence builds, pulls, service
            # count, or whether this service is enabled for the project.
            # Refuse rather than treating the hash as proof for them.
            raise PreMutationRefusal(
                "Hash-excluded Compose build, pull-policy, profile, or scale configuration cannot be verified; reconcile and use the CLI", "hash_excluded"
            )
        current_hash = self._compose_service_hash(service)
        if expected_hash and current_hash != expected_hash:
            raise PreMutationRefusal(
                "Pending or unverified Compose changes were detected; reconcile and deploy the service, then refresh this service before updating", "compose_drift"
            )
        self.state.assert_service_unfenced(service)
        replicas = [item for item in found
                    if item.stack == service.stack and item.compose_service == service.compose_service]
        if not replicas or not any(item.container_id == service.container_id for item in replicas):
            raise PreMutationRefusal("service identity changed; refresh this service before updating", "service_changed")
        for replica in replicas:
            runtime_hash = (replica.labels or {}).get(COMPOSE_HASH_LABEL)
            if not isinstance(runtime_hash, str) or not COMPOSE_HASH_PATTERN.fullmatch(runtime_hash):
                raise PreMutationRefusal(
                    "Compose/runtime configuration identity is missing or ambiguous; reconcile pending changes and refresh this service before updating", "compose_unverifiable"
                )
            if runtime_hash != current_hash:
                raise PreMutationRefusal(
                    "Pending or unverified Compose changes were detected; reconcile and deploy the service, then refresh this service before updating", "compose_drift"
                )
        return current_hash

    def _revalidate_compose_runtime_identity(self, service_key, expected_service, expected_hash, expected_model=None,
                                             expected_context=None):
        found = discover(self.config)
        matches = [service for service in found if service.container_id == expected_service.container_id]
        if len(matches) != 1:
            raise PreMutationRefusal("service identity changed; refresh this service before updating", "service_changed")
        service = matches[0]
        for field in ("image", "image_id", "digest", "version", "architecture", "state",
                      "stack", "compose_service", "working_dir", "compose_files", "restart_policy",
                      "local_build", "ignored"):
            if getattr(service, field) != getattr(expected_service, field):
                raise PreMutationRefusal("service configuration or running image changed; refresh this service before updating", "service_changed")
        if f"container/{service.container_id}" != service_key or service.state != "running":
            raise PreMutationRefusal("service identity changed; refresh this service before updating", "service_changed")
        if sum(item.stack == service.stack and item.compose_service == service.compose_service for item in found) != 1:
            raise PreMutationRefusal("Compose service replicas changed after review", "compose_unverifiable")
        before = build_inventory(service.compose_files, service.working_dir)
        current_model = self._compose_config_model(service)
        if (expected_model is not None
                and (current_model.get("services") or {}).get(service.compose_service) !=
                    (expected_model.get("services") or {}).get(service.compose_service)):
            raise PreMutationRefusal(
                "Pending or unverified Compose changes were detected; reconcile and refresh this service before updating", "compose_drift"
            )
        compose_service = (current_model.get("services") or {}).get(service.compose_service)
        if not isinstance(compose_service, dict):
            raise PreMutationRefusal("Compose service configuration could not be verified; refresh this service before updating", "compose_unverifiable")
        self._verify_compose_runtime_identity(service, found, expected_hash, compose_service)
        after = build_inventory(service.compose_files, service.working_dir, model=current_model)
        if (not before.supported or not after.supported or before.fingerprint != after.fingerprint
                or before.unsupported != after.unsupported):
            raise PreMutationRefusal(
                "Compose configuration inputs could not be fully verified; refresh this service before updating",
                "compose_unverifiable")
        try:
            context = _execution_context_fingerprint(service, current_model)
        except _ExecutionContextRefused as exc:
            raise PreMutationRefusal(COMPOSE_REASONS[exc.reason], "compose_unverifiable") from None
        if expected_context is not None and context != expected_context:
            raise PreMutationRefusal("Compose execution context changed after review", "compose_drift")

    def _revalidate_compose_pin_model(self, service_key, expected_service, baseline_model, target_image,
                                      expected_context=None):
        """Require a digest-pin edit to be the sole effective Compose change.

        The old runtime label cannot match the intentionally changed target
        image's Compose hash. Compare the selected service's resolved model
        with only its image replaced, then separately reprove project identity
        and execution resources. Unrelated service edits are outside scope.
        """
        found = discover(self.config)
        matches = [service for service in found if service.container_id == expected_service.container_id]
        if len(matches) != 1:
            raise PreMutationRefusal("service identity changed; refresh this service before updating", "service_changed")
        service = matches[0]
        for field in ("image", "image_id", "digest", "version", "architecture", "state",
                      "stack", "compose_service", "working_dir", "compose_files", "restart_policy",
                      "local_build", "ignored"):
            if getattr(service, field) != getattr(expected_service, field):
                raise PreMutationRefusal("service configuration or running image changed; refresh this service before updating", "service_changed")
        if f"container/{service.container_id}" != service_key or service.state != "running":
            raise PreMutationRefusal("service identity changed; refresh this service before updating", "service_changed")
        if sum(item.stack == service.stack and item.compose_service == service.compose_service for item in found) != 1:
            raise PreMutationRefusal("Compose service replicas changed after review", "compose_unverifiable")
        if not isinstance(target_image, str) or "@sha256:" not in target_image:
            raise PreMutationRefusal("target digest pin could not be verified; no service recreation was performed", "target_changed")
        expected_model = copy.deepcopy(baseline_model)
        services = expected_model.get("services") or {}
        target_service = services.get(service.compose_service)
        if not isinstance(target_service, dict):
            raise PreMutationRefusal("Compose service configuration could not be verified; no service recreation was performed", "compose_unverifiable")
        target_service["image"] = target_image
        current_model = self._compose_config_model(service)
        if (current_model.get("services") or {}).get(service.compose_service) != target_service:
            raise PreMutationRefusal(
                "Pending or unverified Compose changes were detected after pinning; no service recreation was performed", "compose_drift"
            )
        try:
            context = _execution_context_fingerprint(service, current_model)
        except _ExecutionContextRefused as exc:
            raise PreMutationRefusal(COMPOSE_REASONS[exc.reason], "compose_unverifiable") from None
        if expected_context is not None and context != expected_context:
            raise PreMutationRefusal("Compose execution context changed after review", "compose_drift")

    def _verify_compose_recovery_model(self, service, expected_hash, baseline_model):
        """Permit automatic recovery only for the original server-trusted model."""
        try:
            current_model = self._compose_config_model(service)
            current_hash = self._compose_service_hash(service)
        except Exception:
            raise RecoveryRefused("Compose recovery identity is unavailable") from None
        if current_model != baseline_model or current_hash != expected_hash:
            raise RecoveryRefused("Compose recovery identity changed")
        try:
            _execution_context_fingerprint(service, current_model)
        except _ExecutionContextRefused:
            raise RecoveryRefused("Compose recovery execution context changed") from None

    def _fresh_update_service(self, service_key, cached):
        # Resolve by the container ID captured in the trusted snapshot, then
        # compare all execution-relevant runtime/Compose identity fields.
        found = discover(self.config)
        matches = [service for service in found if service.container_id == cached.get("container_id")]
        if len(matches) != 1:
            raise PreMutationRefusal("service identity changed; refresh this service before updating", "service_changed")
        service = matches[0]
        current = _public_service(service)
        for field in ("image", "image_id", "digest", "version", "architecture", "state",
                      "restart_policy", "stack", "compose_service", "working_dir", "compose_files", "local_build", "ignored"):
            if current.get(field) != cached.get(field):
                raise PreMutationRefusal("service configuration or running image changed; refresh this service before updating", "service_changed")
        if service.state != "running" or not service.stack or not service.compose_service or not service.working_dir or not service.compose_files:
            raise PreMutationRefusal("service is not an eligible running Compose service", "service_ineligible")
        if service.local_build or service.ignored or f"container/{service.container_id}" != service_key:
            raise PreMutationRefusal("service is not an eligible running Compose service", "service_ineligible")
        if sum(item.stack == service.stack and item.compose_service == service.compose_service for item in found) != 1:
            raise PreMutationRefusal("Compose service replicas cannot be verified for update", "compose_unverifiable")

        # Compose may have changed since the last container snapshot. Resolve
        # the current source without logging its output and fail closed unless
        # it still targets the image that was actually scanned and confirmed.
        compose_model = self._compose_config_model(service)
        compose_service = (compose_model.get("services") or {}).get(service.compose_service)
        if not isinstance(compose_service, dict):
            raise PreMutationRefusal(
                "Compose service configuration could not be verified; reconcile pending changes and refresh this service before updating", "compose_unverifiable"
            )

        # The config hash is Compose's own identity for the effective service
        # configuration used to create a container. It covers merged files,
        # interpolation and normalized options without exposing Compose/env
        # contents. Require every currently running replica to agree; absent,
        # malformed or unsupported output is a refusal, never a fallback.
        runtime_config_hash = self._verify_compose_runtime_identity(service, found, compose_model=compose_service)

        before = build_inventory(service.compose_files, service.working_dir)
        after = build_inventory(service.compose_files, service.working_dir, model=compose_model)
        if not before.supported or not after.supported or before.fingerprint != after.fingerprint:
            raise PreMutationRefusal("Compose configuration inputs could not be fully verified", "compose_unverifiable")
        try:
            context = _execution_context_fingerprint(service, compose_model)
        except _ExecutionContextRefused as exc:
            raise PreMutationRefusal(COMPOSE_REASONS[exc.reason], "compose_unverifiable") from None

        # Registry and architecture eligibility are checked again while the
        # shared update lock is held. A stale page can never authorize an old
        # result, and digest-pinned services retain their known channel rules.
        result = scan_service_with_tracking(service, self.state)
        if result.status not in UPDATE_STATUSES:
            raise PreMutationRefusal("a verified update is no longer available", "target_unavailable")
        return service, result, runtime_config_hash, compose_model, context

    @staticmethod
    def _safe_operation_error(exc):
        if isinstance(exc, RecoveryRequired) and "namespace image update" in str(exc).lower():
            return ("The namespace image update could not be fully verified after Compose started. "
                    "No automatic recovery was attempted; manual recovery is required.")
        if isinstance(exc, ComposeSourceNotWritable):
            return (
                "UPT cannot modify this service's Compose source from the agent sandbox. "
                "Authorise the Compose project directory for UPT writes and try again."
            )
        if isinstance(exc, RecoveryFailed):
            return (
                "Automatic recovery was attempted but did not complete successfully. "
                "The backup and previous image were retained; manual recovery is required."
            )
        if isinstance(exc, (RecoveryRefused, RecoveryRequired)):
            return (
                "Automatic recovery was refused because Compose configuration changed or could not be verified. "
                "The backup and previous image were retained; manual recovery is required."
            )
        if isinstance(exc, ReviewedTargetChanged):
            return (
                "The reviewed image target changed or could not be verified. No service was recreated. "
                "Refresh the service page and review the current target before trying again."
            )
        text = str(exc).lower()
        if "registry" in text or "manifest" in text or "rate limit" in text or "timed out" in text:
            return _safe_error(exc)
        if "architecture" in text or "platform" in text:
            return "The replacement image does not support this service architecture."
        if "health" in text or "unhealthy" in text or "restart" in text:
            return "The replacement service failed startup or health verification; recovery information was retained."
        if "compose validation" in text:
            return "Compose validation failed; the original configuration was restored."
        if "compose pin restoration could not be verified" in text:
            return (
                "The update failed and its Compose source changed during recovery. UPT preserved the changed file "
                "and did not attempt another recreation. Review the current source and UPT backup before retrying."
            )
        if "another modifying" in text:
            return "Another UPT operation is active; no update was performed."
        if "another web operation" in text:
            return "Another UPT operation is active; no update was performed."
        if any(marker in text for marker in ("service identity", "service configuration", "compose configuration identity",
                                              "compose/runtime configuration identity",
                                              "hash-excluded compose",
                                              "pending or unverified compose", "verified update",
                                              "complete service scan", "eligible running", "compose image differs")):
            return str(exc)[:240]
        return "The update failed. Check UPT History and agent logs for the recovery outcome."

    @_after_terminal_project_refresh
    def _update_worker(self, operation_id, payload, intent):
        username, client_ip, user_agent = payload["requested_by"], payload["client_ip"], payload["user_agent"]
        service_key = intent.service_key
        # Explicit mutation boundary. It is crossed immediately before the
        # first image pull or source write; only refusals raised before it
        # may be reported as "blocked".
        boundary = {"crossed": False}

        def mutation_started(_kind):
            boundary["crossed"] = True
        try:
            with Lock(self.state.root / "update.lock"):
                self.state.ensure_compatible()
                self.state.set_operation_running(operation_id, "Revalidating service eligibility")
                self.state.operation_event(operation_id, "task_started", stage="Revalidating service eligibility",
                                            message="Checking current service identity and registry status", status="running")
                cached = self._intent_candidate(intent)
                service, checked, runtime_config_hash, compose_model, context = self._fresh_update_service(service_key, cached)
                if context != intent.execution_context_fingerprint:
                    raise PreMutationRefusal("Compose execution context changed after review", "compose_drift")
                # A consumer update is bound to the owner evidence of its own review;
                # never substitute a fresh proof at execution time.
                if ((service.network_mode or "").startswith("container:")
                        and (intent.namespace_review is None
                             or intent.namespace_review.container_id != service.container_id)):
                    raise PreMutationRefusal(COMPOSE_REASONS["namespace_owner_unproven"], "namespace_owner_unproven")
                if self._target_identity(checked) != intent.target[:4]:
                    raise ReviewedTargetChanged(
                        "The reviewed image target changed or could not be verified. Refresh the service page and review again."
                    )
                # Close the same row that was opened, so it never lingers as a running step.
                self.state.operation_event(operation_id, "task_completed", stage="Revalidating service eligibility",
                                            message=f"Verified {checked.status} for {service.name}", status="completed")

                reporter = self._operation_progress_reporter(operation_id, "update", "Preparing update")
                context = {"origin": "web", "operation_id": operation_id, "requested_by": username}
                def revalidate_compose_identity():
                    self._revalidate_compose_runtime_identity(service_key, service, runtime_config_hash, compose_model,
                                                              intent.execution_context_fingerprint)

                def verify_compose_source_writeability(path):
                    verify_atomic_replace_access([path])

                def revalidate_compose_pin(target_image):
                    self._revalidate_compose_pin_model(service_key, service, compose_model, target_image,
                                                       intent.execution_context_fingerprint)

                def revalidate_compose_recovery():
                    self._verify_compose_recovery_model(service, runtime_config_hash, compose_model)

                def verify_target(stage, observed):
                    if stage == "registry":
                        if self._target_identity(SimpleNamespace(
                                status=checked.status,
                                remote_digest=(observed or {}).get("digest"),
                                remote_version=(observed or {}).get("version"),
                                remote_created=(observed or {}).get("created"))) != intent.target[:4]:
                            raise ReviewedTargetChanged(
                                "The reviewed image target changed before it could be pulled. Refresh and review the current target again."
                            )
                    elif stage in {"pulled", "resolved"}:
                        self._verify_local_target(intent, observed)

                result = do_update(service, self.state, yes=True,
                                   health_timeout=int(self.config.data.get("health_timeout", 90)),
                                   reporter=reporter, output=lambda *_: None, audit_context=context,
                                   pre_source_write_check=verify_compose_source_writeability,
                                   pre_pull_check=revalidate_compose_identity,
                                   pre_recreate_check=revalidate_compose_identity,
                                   post_pin_check=revalidate_compose_pin,
                                   pre_recovery_check=revalidate_compose_recovery,
                                   target_guard=verify_target,
                                   mutation_started=mutation_started, project_name=service.stack,
                                   namespace_review=intent.namespace_review, post_mutation=self._queue_post_mutation, reconcile_discover=self._discover_post_mutation,
                                   post_project_change=self._defer_project_refresh)
                safe_result = {key: result[key] for key in ("updated", "history_id", "image", "version", "digest", "health")
                               if isinstance(result, dict) and key in result}
                unchanged = isinstance(result, dict) and result.get("updated") is False
                outcome = "unchanged" if unchanged else "success"
                completion = (f"{service.name} already matches its tracked digest; no update was needed."
                              if unchanged else f"{service.name} updated successfully.")
                warnings = []
                try:
                    self.state.audit("web_update", outcome, username=username, client_ip=client_ip,
                                     user_agent=user_agent, details={"origin": "web", "operation_id": operation_id,
                                                                    "service_key": service_key, **safe_result})
                except Exception:
                    warnings.append("Outcome audit could not be written; core update history is preserved.")
                self.state.finish_operation(operation_id, "succeeded", message=completion,
                                            result={**safe_result, **({"warnings": warnings} if warnings else {})})
        except Exception as exc:
            if not boundary["crossed"] and isinstance(exc, BLOCKING_REFUSALS):
                self._finish_blocked_update(operation_id, intent, exc, username, client_ip, user_agent)
                return
            _log_web_mutation_failure(logging.getLogger(__name__), "update", operation_id, intent, exc)
            safe_error = self._safe_operation_error(exc)
            audit_result = ("manual recovery required"
                            if isinstance(exc, (RecoveryRefused, RecoveryRequired)) else "failed")
            try:
                self.state.audit("web_update", audit_result, username=username, client_ip=client_ip,
                                 user_agent=user_agent, details={"origin": "web", "operation_id": operation_id,
                                                                "service_key": service_key, "error": safe_error,
                                                                "recovery_required": audit_result == "manual recovery required"})
            except Exception:
                logging.getLogger(__name__).warning("Could not persist update failure audit")
            # A terminal operation is externally visible to polling/SSE. Make
            # the audit attempt first so observers cannot race ahead of its
            # outcome record (the audit failure remains a bounded warning).
            try:
                self.state.finish_operation(operation_id, "failed", message=safe_error, error=safe_error)
            except Exception:
                logging.getLogger(__name__).exception("Could not persist update terminal state")
        finally:
            with self._lock:
                self._operation_threads.pop(operation_id, None)

    @staticmethod
    def _blocked_reason(exc):
        if isinstance(exc, PreMutationRefusal) and exc.reason in BLOCKED_UPDATE_MESSAGES:
            return exc.reason
        return "target_changed"

    def _finish_blocked_update(self, operation_id, intent, exc, username, client_ip, user_agent):
        """Record a factual pre-mutation refusal: terminal, audited, no side effect."""
        reason = self._blocked_reason(exc)
        message = BLOCKED_UPDATE_MESSAGES[reason]
        identity = dict(zip(UPDATE_REVIEW_IDENTITY_FIELDS, getattr(intent, "service_identity", ())))
        logging.getLogger(__name__).warning(
            "Web mutation blocked before any side effect operation=update operation_id=%s stack=%s service=%s reason=%s",
            _safe_mutation_log_identifier(operation_id), _safe_mutation_log_identifier(identity.get("stack")),
            _safe_mutation_log_identifier(identity.get("compose_service")), reason,
        )
        try:
            self.state.audit("web_update", "blocked", username=username, client_ip=client_ip,
                             user_agent=user_agent, details={"origin": "web", "operation_id": operation_id,
                                                            "service_key": intent.service_key, "reason": reason,
                                                            "mutation_performed": False, "error": message})
        except Exception:
            logging.getLogger(__name__).warning("Could not persist update blocked audit")
        try:
            self.state.finish_operation(operation_id, "blocked", message=message, error=message,
                                        result={"blocked_reason": reason, "mutation_performed": False})
        except Exception:
            logging.getLogger(__name__).exception("Could not persist update terminal state")

    @_after_terminal_project_refresh
    def _rollback_worker(self,operation_id,payload,intent):
        username,client_ip,user_agent=(payload["requested_by"],payload["client_ip"],payload["user_agent"])
        service=row=point=evidence=None
        try:
            with Lock(self.state.root/"update.lock"):
                self.state.ensure_compatible()
                self.state.set_operation_running(operation_id,"Revalidating rollback point")
                self.state.operation_event(operation_id,"task_started",stage="Revalidating rollback point",
                                            message="Checking protected rollback point and service identity",status="running")
                service,row,point,evidence=self._rollback_intent_candidate(intent)
                self.state.assert_service_unfenced(service)
                original_service=service
                sources=evidence["sources"]
                verify_atomic_replace_access([item["path"] for item in sources])
                self.state.operation_event(operation_id,"task_completed",stage="Revalidating rollback point",
                                            message="Verified protected rollback point and service identity",status="completed")
                original_source={item["path"]:item["before"] for item in sources}
                restored_source={item["path"]:item["restore"] for item in sources}

                def point_guard():
                    self._verify_rollback_reference(intent,original_service,row,point)
                    manifest=self._rollback_manifest(original_service,row)
                    if manifest["fingerprint"]!=intent.backup_fingerprint:
                        raise ReviewedTargetChanged("the retained rollback backup changed")

                def verify_before_restore(phase):
                    point_guard()
                    self._verify_service_before_rollback_recreate(original_service)
                    self._verify_rollback_image(row,original_service.architecture)
                    if phase=="initial":
                        current=self._rollback_evidence(original_service,row,point)
                        if (current["source_identity"]!=intent.source_identity
                                or current["current_model_identity"]!=intent.current_model_identity
                                or current["restored_model_identity"]!=intent.restored_model_identity):
                            raise ReviewedTargetChanged("the reviewed Compose model changed")
                    else:
                        for source in sources:
                            value=Path(source["path"]).read_bytes()
                            if value not in {source["before"],source["restore"]}:
                                raise ReviewedTargetChanged("a Compose source changed while rollback was in progress")

                def verify_before_recreate():
                    point_guard()
                    self._verify_service_before_rollback_recreate(original_service)
                    if any(Path(item["path"]).read_bytes()!=item["restore"] for item in sources):
                        raise ReviewedTargetChanged("the restored Compose source changed before recreation")
                    model=self._compose_config_model(original_service)
                    try: _assert_project_identity(original_service,model)
                    except _ExecutionContextRefused: raise ReviewedTargetChanged("the Compose project identity changed") from None
                    if self._model_fingerprint(model)!=intent.restored_model_identity:
                        raise ReviewedTargetChanged("the restored Compose model changed before recreation")
                    self._verify_rollback_image(row,original_service.architecture)

                def verify_recovery_sources(recovery_backup):
                    point_guard()
                    self._recovery_backup_matches(recovery_backup,original_service,sources)
                    for item in sources:
                        value=Path(item["path"]).read_bytes()
                        if value not in {item["before"],item["restore"]}:
                            raise ReviewedTargetChanged("a Compose source changed during rollback recovery")

                def verify_pre_rollback_recovery(phase,recovery_backup):
                    # Before a recovery source write, prove the exact source and
                    # model snapshot captured before rollback plus both local
                    # image identities. After restore, prove that the live
                    # Compose model and source bytes equal that captured state.
                    point_guard()
                    recovery=self._recovery_backup_matches(recovery_backup,original_service,sources)
                    if self._model_fingerprint(recovery["model"])!=intent.current_model_identity:
                        raise ReviewedTargetChanged("the captured pre-rollback Compose model changed")
                    identity=dict(zip(ROLLBACK_REVIEW_IDENTITY_FIELDS,intent.service_identity))
                    self._verify_local_image_identity(identity["image_id"],identity["image"],
                                                      identity["digest"],identity["architecture"])
                    self._verify_rollback_image(row,original_service.architecture)
                    if phase=="before-source-restore":
                        if any(Path(item["path"]).read_bytes()!=item["restore"] for item in sources):
                            raise ReviewedTargetChanged("UPT rollback sources changed before recovery")
                        live=self._compose_config_model(original_service)
                        try: _assert_project_identity(original_service,live)
                        except _ExecutionContextRefused: raise ReviewedTargetChanged("the Compose project identity changed") from None
                        if self._model_fingerprint(live)!=intent.restored_model_identity:
                            raise ReviewedTargetChanged("the rollback Compose model changed before recovery")
                    elif phase=="before-recovery-recreate":
                        if any(Path(item["path"]).read_bytes()!=item["before"] for item in sources):
                            raise ReviewedTargetChanged("the previous Compose sources were not fully restored")
                        live=self._compose_config_model(original_service)
                        try: _assert_project_identity(original_service,live)
                        except _ExecutionContextRefused: raise ReviewedTargetChanged("the Compose project identity changed") from None
                        if self._model_fingerprint(live)!=intent.current_model_identity:
                            raise ReviewedTargetChanged("the previous Compose model could not be restored exactly")
                        services=discover(self.config,all_containers=True)
                        selected=[item for item in services if item.stack==original_service.stack
                                  and item.compose_service==original_service.compose_service]
                        if len(selected)>1 or (selected and selected[0].image_id not in
                                {identity["image_id"],row.get("old_image_id")}):
                            raise ReviewedTargetChanged("the running service changed during rollback recovery")
                    else:
                        raise ValueError("invalid recovery verification phase")

                reporter=self._rollback_progress_reporter(operation_id)
                command=compose_args(service,project_name=service.stack)+["up","-d","--no-deps","--pull","never",service.compose_service]
                result=do_web_rollback(
                    service,row,self.state,sources=sources,operation_id=operation_id,
                    rollback_command=command,recovery_command=list(command),
                    verify_before_restore=verify_before_restore,
                    verify_before_recreate=verify_before_recreate,
                    verify_recovery_sources=verify_recovery_sources,
                    verify_pre_rollback_recovery=verify_pre_rollback_recovery,
                    health_timeout=int(self.config.data.get("health_timeout",90)),reporter=reporter,
                    post_mutation=self._queue_post_mutation, reconcile_discover=self._discover_post_mutation,
                    post_project_change=self._defer_project_refresh)
                audit_details={"origin":"web","operation_id":operation_id,
                               "service_key":intent.service_key,"rollback_history_id":int(row["id"]),
                               "history_id":int(result["history_id"]),"image":result["image"],
                               "version":result["version"],"digest":result["digest"]}
                warnings=[]
                try: self.state.audit("web_rollback","success",username=username,client_ip=client_ip,
                                      user_agent=user_agent,details=audit_details)
                except Exception: warnings.append("Outcome audit could not be written; core History is preserved.")
                public_result={key:value for key,value in result.items() if key!="recovery_backup"}
                self.state.finish_operation(operation_id,"succeeded",message=f"{service.name} rolled back successfully.",
                                            result={**public_result,**({"warnings":warnings} if warnings else {})})
        except Exception as exc:
            _log_web_mutation_failure(logging.getLogger(__name__), "rollback", operation_id, intent, exc)
            safe_error=self._safe_rollback_error(exc)
            manual=isinstance(exc,WebRollbackFailure) and exc.manual_recovery_required
            recovered=isinstance(exc,WebRollbackFailure) and exc.recovered
            outcome="manual recovery required" if manual else "recovered" if recovered else "failed"
            if row is None:
                try:
                    with self.state.read() as connection:
                        item=connection.execute("SELECT * FROM history WHERE id=?",(intent.rollback_identity[0],)).fetchone()
                    row=dict(item) if item else None
                except Exception: row=None
            if row is not None:
                try:
                    existing=False
                    for item in self.state.history_for_service(row.get("stack"),row.get("service")):
                        try: details=json.loads(item.get("details") or "{}")
                        except (TypeError,json.JSONDecodeError): details={}
                        if item.get("action")=="rollback" and isinstance(details,dict) and details.get("operation_id")==operation_id:
                            existing=True; break
                    if not existing:
                        identity=dict(zip(ROLLBACK_REVIEW_IDENTITY_FIELDS,intent.service_identity))
                        self.state.record(stack=row.get("stack"),service=row.get("service"),action="rollback",
                                          old_image=identity.get("image"),old_image_id=identity.get("image_id"),
                                          old_digest=identity.get("digest"),old_version=identity.get("version"),
                                          new_image=row.get("old_image"),new_image_id=row.get("old_image_id"),
                                          result="FAILED",rollback_result="NO CHANGES MADE",
                                          details={"origin":"web","operation_id":operation_id,
                                                   "rollback_history_id":int(row["id"]),
                                                   "error":"review became stale before mutation"})
                except Exception: logging.getLogger(__name__).warning("Could not persist rollback History failure")
            try:
                self.state.audit("web_rollback",outcome,username=username,client_ip=client_ip,user_agent=user_agent,
                                 details={"origin":"web","operation_id":operation_id,
                                          "service_key":intent.service_key,"error":safe_error,
                                          "recovery_required":manual,"recovered":recovered})
            except Exception: logging.getLogger(__name__).warning("Could not persist rollback outcome audit")
            try:
                self.state.finish_operation(operation_id,"failed",message=safe_error,error=safe_error,
                                            result={"manual_recovery_required":manual,"recovered":recovered})
            except Exception: logging.getLogger(__name__).exception("Could not persist rollback terminal operation state")
        finally:
            with self._lock: self._operation_threads.pop(operation_id,None)

    def _bootstrap_baseline_available(self, service, runtime_hash):
        store = BaselineStore(self.state)
        with self._baseline_lock:
            for record in store.records(self._baseline_key(service)):
                loaded = store.load(record)  # Integrity failures are not absence.
                if record.runtime_hash != runtime_hash:
                    continue
                if record.container_id == service.container_id:
                    return True
                inputs = {item.path: item for item in loaded.inputs if item.role in {'compose','project_env'}}
                if self._reproduce_candidate(service, runtime_hash, inputs):
                    return True
            for _name, inputs in self._backup_candidates(service):
                if self._reproduce_candidate(service, runtime_hash, inputs):
                    return True
        return False

    def _bootstrap_candidate(self, service_key, own_operation=None):
        self._validate_service_key(service_key)
        found = discover(self.config, all_containers=True)
        selected = [item for item in found if 'container/' + item.container_id == service_key]
        if len(selected) != 1:
            raise BootstrapRefused('service_ineligible')
        plan = make_bootstrap_plan(selected[0], found, self.state,
                                   model_reader=self._compose_config_model, hash_reader=self._compose_service_hash,
                                   context_reader=_execution_context_fingerprint,
                                   mounts_reader=_assert_reconcile_runtime_mounts,
                                   baseline_available=self._bootstrap_baseline_available,
                                   own_operation=own_operation)
        return plan

    def compose_bootstrap_review(self, payload):
        self._exact_payload(payload, {'service_key', 'requested_by'})
        username = payload['requested_by']
        if not isinstance(username, str) or not 1 <= len(username) <= 80 or any(c in username for c in '\0\r\n'):
            raise ValueError('invalid requester')
        plan = self._bootstrap_candidate(payload['service_key'])
        now = time.monotonic()
        with self._lock:
            self._bootstrap_intents = {key: item for key, item in self._bootstrap_intents.items() if item.expires_at > now}
            while len(self._bootstrap_intents) >= UPDATE_REVIEW_LIMIT:
                self._bootstrap_intents.pop(next(iter(self._bootstrap_intents)))
            token = secrets.token_urlsafe(32)
            self._bootstrap_intents[token] = BootstrapReviewIntent(payload['service_key'], username,
                                                                  plan.fingerprint, now + UPDATE_REVIEW_TTL_SECONDS)
        return {'confirmation_id': token, 'review': {'service': plan.service.key, 'stack': plan.service.stack,
                'action': 'bootstrap', 'image_unchanged': True, 'service_recreated': True,
                'automatic_recovery': False, 'previous_source_known': False, 'proposal': plan.proposal,
                'observations': plan.observations}}

    def _bootstrap_intent_candidate(self, intent, own_operation=None):
        if intent.expires_at <= time.monotonic():
            raise BootstrapRefused('review_changed')
        plan = self._bootstrap_candidate(intent.service_key, own_operation)
        if plan.fingerprint != intent.evidence_fingerprint:
            raise BootstrapRefused('review_changed')
        return plan

    def start_compose_bootstrap(self, payload):
        self._exact_payload(payload, {'confirmation_id','acknowledge_no_rollback','requested_by','client_ip','user_agent'})
        if payload['acknowledge_no_rollback'] is not True:
            raise ValueError('explicit no-automatic-rollback acknowledgement is required')
        token = payload['confirmation_id']
        if not isinstance(token, str) or not re.fullmatch('[A-Za-z0-9_-]{43}', token):
            raise ValueError('invalid or expired bootstrap review')
        for field, limit in (('requested_by',80),('client_ip',64),('user_agent',300)):
            value = payload[field]
            if not isinstance(value,str) or len(value)>limit or field=='requested_by' and not value or any(c in value for c in '\0\r\n'):
                raise ValueError('invalid request context')
        operation_id = uuid.uuid4().hex
        with self._lock:
            intent = self._bootstrap_intents.get(token)
            if not intent or intent.expires_at <= time.monotonic() or intent.requested_by != payload['requested_by']:
                self._bootstrap_intents.pop(token, None)
                raise ValueError('invalid or expired bootstrap review')
            with Lock(self.state.root / 'update.lock'):
                self.state.ensure_compatible()
                self.state.recover_abandoned_operations()
                plan = self._bootstrap_intent_candidate(intent)
                self.state.create_operation(operation_id, kind='compose_bootstrap', service_key=intent.service_key,
                    service=plan.service.key, stack=plan.service.stack, requested_by=intent.requested_by,
                    summary={'action':'bootstrap', 'logical_key':plan.logical_key,
                             'review_evidence':plan.fingerprint, 'old_trusted_source_available':False,
                             'automatic_recovery':False})
                try:
                    self.state.audit('web_compose_bootstrap','requested',username=intent.requested_by,
                        client_ip=payload['client_ip'],user_agent=payload['user_agent'],
                        details={'operation_id':operation_id,'acknowledge_no_rollback':True})
                except Exception:
                    self.state.finish_bootstrap_failure(operation_id, reason='evidence_unavailable')
                    raise BootstrapRefused('evidence_unavailable') from None
                self._bootstrap_intents.pop(token, None)
            thread = threading.Thread(target=self._bootstrap_worker,args=(operation_id,payload,intent),
                                      name='upt-bootstrap-' + operation_id[:8],daemon=True)
            self._operation_threads[operation_id] = thread
            try:
                thread.start()
            except RuntimeError:
                self._operation_threads.pop(operation_id,None)
                self.state.finish_bootstrap_failure(operation_id, reason='evidence_unavailable')
                raise BootstrapRefused('evidence_unavailable') from None
        return {'operation_id':operation_id,'status':'queued'}

    @_after_terminal_project_refresh
    def _bootstrap_worker(self, operation_id, payload, intent):
        try:
            with Lock(self.state.root / 'update.lock'):
                self.state.ensure_compatible()
                self.state.set_operation_running(operation_id,'Revalidate trust bootstrap')
                plan = self._bootstrap_intent_candidate(intent, operation_id)

                def verify_context(current, model, original_id, expected):
                    value = _execution_context_fingerprint(current, model, identity_container_id=original_id)
                    _assert_reconcile_runtime_mounts(current, model['services'][current.compose_service])
                    if expected is not None and value != expected:
                        raise BootstrapRefused('project_unproven')
                    return value

                fresh = do_compose_bootstrap(plan, self.state, operation_id=operation_id,
                    requester=intent.requested_by,client_ip=payload['client_ip'],user_agent=payload['user_agent'],
                    revalidate=lambda:self._bootstrap_intent_candidate(intent,operation_id),
                    discover_current=lambda:discover(self.config,all_containers=True),
                    verify_configuration=self._verify_reconcile_configuration, verify_context=verify_context,
                    health_timeout=int(self.config.data.get('health_timeout',90)), post_mutation=self._queue_post_mutation, reconcile_discover=self._discover_post_mutation,
                    post_project_change=self._defer_project_refresh)
                # Trust already committed. Delivery failure cannot reclassify it.
                self._compose_status_cache.clear()
        except Exception as exc:
            reason = exc.reason if isinstance(exc,(BootstrapRefused,BootstrapExecutionFailed)) else 'evidence_unavailable'
            try:
                self.state.finish_bootstrap_failure(operation_id, reason=reason)
            except Exception:
                logging.getLogger(__name__).warning('Bootstrap outcome persistence unavailable; durable fence retained')
            self._compose_status_cache.clear()
        finally:
            with self._lock:
                self._operation_threads.pop(operation_id,None)

    def _add_bootstrap_status(self, public, service):
        public.update(bootstrap_eligible=False,bootstrap_reasons=[])
        if public['status'] != DRIFTED or public.get('baseline'):
            return public
        try:
            plan = self._bootstrap_candidate('container/' + service.container_id)
            public.update(bootstrap_eligible=True, bootstrap_proposal=plan.proposal)
        except BootstrapRefused as exc:
            public['bootstrap_reasons'] = [{'code':exc.reason,'message':BOOTSTRAP_REASONS[exc.reason]}]
        except Exception:
            public['bootstrap_reasons'] = [{'code':'trust_store_unavailable','message':BOOTSTRAP_REASONS['trust_store_unavailable']}]
        return public

    # Trusted-baseline configuration Apply and source-only Discard -----------------------
    def _compose_candidate(self, service_key, action="apply", own_operation=None):
        self._validate_service_key(service_key)
        found = discover(self.config, all_containers=True)
        matches = [item for item in found if f"container/{item.container_id}" == service_key]
        if len(matches) != 1:
            if action == "discard":
                raise DiscardRefused("service_ineligible")
            raise ValueError("Configuration Apply is unavailable. The selected container changed.")
        service = matches[0]
        plan = self._compose_plan(service, found, persist=False, own_operation=own_operation)
        if not (plan.discard_eligible if action == "discard" else plan.apply_eligible):
            if action == "discard":
                raise DiscardRefused(next(iter(plan.discard_reasons), "source_layout_unsupported"))
            reason = next(iter(plan.eligibility_reasons or plan.reasons), "service_ineligible")
            raise ValueError("Configuration " + action.title() + " is unavailable. " + COMPOSE_REASONS.get(
                reason, "UPT could not verify the required configuration and recovery evidence."))
        identity = self._service_review_identity(_public_service(service))
        evidence = compose_fingerprint({
            "action": action, "identity": identity, "runtime_hash": plan.runtime_hash,
            "baseline_id": plan.baseline.record.id, "baseline": plan.baseline.record.fingerprint,
            "manifest": plan.baseline.record.manifest,
            "inventory": plan.inventory.fingerprint, "desired_model": plan.desired_model,
            "desired_hash": plan.desired_hash, "diff": plan.diff.fingerprint,
            "project": service.stack, "execution": plan.execution_context_fingerprint,
            "peers": unchanged_runtime(found, service) if action == "discard" else peer_identity(found, service),
            "source_isolation": plan.discard_plan.fingerprint if action == "discard" else None,
            **({"namespace": plan.namespace_apply_review.fingerprint}
               if action == "apply" and plan.namespace_apply_review else {}),
        })
        return service, plan, evidence

    def compose_reconcile_review(self, payload):
        self._exact_payload(payload, {"service_key", "action", "requested_by"})
        if payload["action"] not in ("apply", "discard"):
            raise ValueError("unsupported configuration action")
        username = payload["requested_by"]
        if (not isinstance(username, str) or not username or len(username) > 80
                or any(char in username for char in "\0\r\n")):
            raise ValueError("invalid requester")
        service, plan, evidence = self._compose_candidate(payload["service_key"], payload["action"])
        now = time.monotonic()
        with self._lock:
            self._compose_intents = {key: item for key, item in self._compose_intents.items() if item.expires_at > now}
            while len(self._compose_intents) >= UPDATE_REVIEW_LIMIT:
                self._compose_intents.pop(next(iter(self._compose_intents)))
            confirmation_id = secrets.token_urlsafe(32)
            namespace = plan.namespace_apply_review if payload["action"] == "apply" else None
            self._compose_intents[confirmation_id] = ComposeReviewIntent(
                action=payload["action"], service_key=payload["service_key"], requested_by=username,
                service_identity=self._service_review_identity(_public_service(service)),
                baseline_id=plan.baseline.record.id, evidence_fingerprint=evidence,
                expires_at=now + UPDATE_REVIEW_TTL_SECONDS, namespace_review=namespace)
        review = {"service": service.name, "stack": service.stack,
                  "action": payload["action"], "image_unchanged": True,
                  "service_recreated": payload["action"] == "apply", "automatic_recovery": True,
                  "service_changes": list(plan.diff.service)}
        if namespace:
            # One bounded display fact; the owner name is a validated service name.
            review["namespace"] = {"owner": namespace.owner.service, "owner_unchanged": True,
                                   "configuration_only_recovery": True}
        return {"confirmation_id": confirmation_id, "review": review}

    def _compose_intent_candidate(self, intent, own_operation=None):
        if intent.expires_at <= time.monotonic():
            raise ValueError("configuration review expired")
        service, plan, evidence = self._compose_candidate(intent.service_key, intent.action, own_operation)
        reviewed = intent.namespace_review
        current = plan.namespace_apply_review if intent.action == "apply" else None
        if (self._service_review_identity(_public_service(service)) != intent.service_identity
                or plan.baseline.record.id != intent.baseline_id or evidence != intent.evidence_fingerprint
                # A consumer intent needs its own server-held review; fresh
                # evidence never replaces missing or different review authority.
                or (reviewed is None) != (current is None)
                or (reviewed is not None and reviewed.fingerprint != current.fingerprint)):
            raise ValueError("reviewed configuration evidence changed")
        return service, plan

    def start_compose_reconcile(self, payload):
        self._exact_payload(payload, {"confirmation_id", "requested_by", "client_ip", "user_agent"})
        confirmation_id = payload["confirmation_id"]
        if not isinstance(confirmation_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", confirmation_id):
            raise ValueError("invalid or expired configuration review")
        for field, limit in (("requested_by", 80), ("client_ip", 64), ("user_agent", 300)):
            value = payload[field]
            if (not isinstance(value, str) or (field == "requested_by" and not value)
                    or len(value) > limit or any(char in value for char in "\0\r\n")):
                raise ValueError("invalid configuration request context")
        operation_id = uuid.uuid4().hex
        with self._lock:
            intent = self._compose_intents.get(confirmation_id)
            if not intent or intent.expires_at <= time.monotonic() or intent.requested_by != payload["requested_by"]:
                self._compose_intents.pop(confirmation_id, None)
                raise ValueError("invalid or expired configuration review")
            identity = dict(zip(UPDATE_REVIEW_IDENTITY_FIELDS, intent.service_identity))
            with Lock(self.state.root / "update.lock"):
                self.state.ensure_compatible()
                self.state.recover_abandoned_operations()
                namespace = intent.namespace_review if intent.action == "apply" else None
                summary = {"action": intent.action, "baseline_id": intent.baseline_id,
                           **({"discard_evidence": intent.evidence_fingerprint} if intent.action == "discard" else {})}
                if namespace:
                    # Bound before evidence exists so orphan material stays attributable.
                    summary.update(namespace_apply=3, namespace_apply_logical_key=namespace.logical_key,
                                   namespace_apply_review=namespace.fingerprint,
                                   namespace_apply_owner=namespace.owner_fingerprint, namespace_apply_marked=False)
                self.state.create_operation(operation_id, kind="compose_reconcile", service_key=intent.service_key,
                                            service=identity["compose_service"], stack=identity["stack"],
                                            requested_by=intent.requested_by, summary=summary)
                self._compose_intents.pop(confirmation_id, None)
                try:
                    self.state.audit("web_compose_reconcile", "requested", username=intent.requested_by,
                                     client_ip=payload["client_ip"], user_agent=payload["user_agent"],
                                     details={"operation_id": operation_id, "action": intent.action, "service_key": intent.service_key})
                except Exception:
                    self._block_compose_start(operation_id, intent, "audit", payload)
                    raise RuntimeError("configuration action could not be audited") from None
            thread = threading.Thread(target=self._compose_worker, args=(operation_id, payload, intent),
                                      name=f"upt-compose-{operation_id[:8]}", daemon=True)
            self._operation_threads[operation_id] = thread
            try:
                thread.start()
            except RuntimeError:
                self._operation_threads.pop(operation_id, None)
                self._block_compose_start(operation_id, intent, "worker", payload)
                raise RuntimeError("configuration action worker could not start") from None
        return {"operation_id": operation_id, "status": "queued"}

    def _block_compose_start(self, operation_id, intent, cause, payload):
        if intent.namespace_review is not None and intent.action == "apply":
            self.state.finish_namespace_apply(operation_id, reason=cause + "_unavailable",
                                              client_ip=payload["client_ip"], user_agent=payload["user_agent"])
            return
        label = "audit is unavailable" if cause == "audit" else "worker is unavailable"
        self.state.finish_operation(operation_id, "blocked", message=("No source changes were made; " if intent.action == "discard"
                                                     else "No application changes were made; ") + label + ".",
                                    error=label.capitalize() + ".", result={"action": intent.action, "mutation_performed": False})

    def _verify_reconcile_configuration(self, service, inventory, model, expected_hash, *, observed=False):
        before = build_inventory(service.compose_files, service.working_dir)
        current = self._compose_config_model(service)  # Detect project mismatch before pinning.
        _assert_project_identity(service, current)
        current_hash = self._compose_service_hash(service)
        after = build_inventory(service.compose_files, service.working_dir, model=current)
        current_model = observed_service_model(current, service.compose_service) if observed else current
        if (not after.supported or before.fingerprint != after.fingerprint
                or after.fingerprint != inventory.fingerprint or current_hash != expected_hash
                or compose_fingerprint(current_model) != compose_fingerprint(model)):
            raise ValueError("configuration inputs or model changed")
        return current, after

    @_after_terminal_project_refresh
    def _compose_worker(self, operation_id, payload, intent):
        if intent.action == "apply" and intent.namespace_review is not None:
            return self._namespace_apply_worker(operation_id, payload, intent)
        outcome = ReconcileOutcome("blocked")
        reporter = self._rollback_progress_reporter(operation_id)
        reporter.operation = "compose_reconcile"
        try:
            with Lock(self.state.root / "update.lock"):
                self.state.ensure_compatible()
                self.state.set_operation_running(operation_id, "Discarding configuration changes" if intent.action == "discard" else "Applying configuration")
                service, plan = self._compose_intent_candidate(intent)

                def revalidate():
                    self._compose_intent_candidate(intent)

                def verify_configuration(current_service, inventory, model, expected_hash):
                    return self._verify_reconcile_configuration(
                        current_service, inventory, model, expected_hash,
                        observed=model is plan.baseline.model)

                def verify_context(current_service, model, *, absent=False):
                    # Baseline project entries are observational digests. Use
                    # only its selected service with the independently proved
                    # current default project context; never promote digests.
                    if model is plan.baseline.model:
                        model = {**plan.desired_model, "services": {
                            service.compose_service: plan.baseline.model["services"][service.compose_service]}}
                    current = _execution_context_fingerprint(current_service, model,
                                                               identity_container_id=service.container_id,
                                                               absent_container=absent)
                    if current != plan.execution_context_fingerprint:
                        raise ValueError("execution context changed")
                    if not absent:
                        _assert_reconcile_runtime_mounts(current_service, model["services"][service.compose_service])

                def capture(current_service, runtime_hash, model, inventory):
                    current, checked = verify_configuration(current_service, inventory, model, runtime_hash)
                    verify_context(current_service, model)
                    return self._capture_baseline(current_service, runtime_hash, current, checked)

                if intent.action == "discard":
                    outcome = do_compose_discard(
                        service, self.state, plan, operation_id=operation_id,
                        binding={"baseline_id": intent.baseline_id, "evidence": intent.evidence_fingerprint},
                        revalidate=revalidate, discover_current=lambda: discover(self.config, all_containers=True),
                        verify_configuration=verify_configuration, verify_context=verify_context,
                        mutation_started=lambda: self.state.mark_compose_mutation_started(operation_id),
                        reporter=reporter, post_mutation=self._queue_post_mutation, reconcile_discover=self._discover_post_mutation,
                        post_project_change=self._defer_project_refresh)
                    if outcome.mutation_performed:
                        self._compose_status_cache.clear()
                else:
                    outcome = do_compose_reconcile(
                        service, self.state, plan, operation_id=operation_id,
                        binding={"baseline_id": intent.baseline_id, "evidence": intent.evidence_fingerprint},
                        revalidate=revalidate, discover_current=lambda: discover(self.config, all_containers=True),
                        verify_configuration=verify_configuration, verify_context=verify_context,
                        capture_baseline=capture,
                        mutation_started=lambda: self.state.mark_compose_mutation_started(operation_id),
                        health_timeout=int(self.config.data.get("health_timeout", 90)),
                        reporter=reporter, post_mutation=self._queue_post_mutation, reconcile_discover=self._discover_post_mutation,
                        post_project_change=self._defer_project_refresh)
                    if outcome.service:
                        self._compose_status_cache.clear()
                    if outcome.baseline_id:
                        self.state.retain_compose_operation_baseline(operation_id, outcome.baseline_id)
                self._finish_compose_reconcile(operation_id, payload, intent, outcome, reporter)
        except Exception as exc:
            _log_web_mutation_failure(logging.getLogger(__name__), "compose_reconcile", operation_id, intent, exc)
            # Core returns post-boundary outcomes rather than throwing. Keep
            # that factual outcome if later persistence/refresh work fails.
            self._finish_compose_reconcile(operation_id, payload, intent, outcome, reporter)
        finally:
            with self._lock:
                self._operation_threads.pop(operation_id, None)

    def _namespace_apply_worker(self, operation_id, payload, intent):
        """Stage 2 adapter: lock, intent and projection only.

        do_compose_reconcile remains the state machine; the guard owns proof,
        durable markers and atomic publication. Terminal state is derived from
        durable state, never from in-memory dispatch flags.
        """
        reporter = self._rollback_progress_reporter(operation_id)
        reporter.operation = "compose_reconcile"
        outcome = None
        try:
            with Lock(self.state.root / "update.lock"):
                self.state.ensure_compatible()
                self.state.set_operation_running(operation_id, "Applying configuration")
                service, plan = self._compose_intent_candidate(intent, own_operation=operation_id)
                guard = NamespaceApplyGuard(intent.namespace_review, service=service, plan=plan, state=self.state,
                                            operation_id=operation_id, requester=intent.requested_by,
                                            client_ip=payload["client_ip"], user_agent=payload["user_agent"],
                                            deps=self._namespace_apply_deps())
                outcome = do_compose_reconcile(
                    service, self.state, plan, operation_id=operation_id, binding=None,
                    revalidate=lambda: self._compose_intent_candidate(intent, own_operation=operation_id),
                    discover_current=lambda: discover(self.config, all_containers=True),
                    verify_configuration=guard.verify_configuration, verify_context=None,
                    capture_baseline=guard.prepare_baseline, mutation_started=guard.mark,
                    health_timeout=int(self.config.data.get("health_timeout", 90)), reporter=reporter, guard=guard,
                    post_mutation=self._queue_post_mutation, reconcile_discover=self._discover_post_mutation,
                    post_project_change=self._defer_project_refresh)
                if guard.published is None:
                    self.state.finish_namespace_apply(operation_id, reason="review_changed",
                                                      client_ip=payload["client_ip"], user_agent=payload["user_agent"],
                                                      observation=guard.diagnostic_observation() if guard.marked else None)
                self._compose_status_cache.clear()
        except Exception as exc:
            _log_web_mutation_failure(logging.getLogger(__name__), "compose_reconcile", operation_id, intent, exc)
            try:
                self.state.finish_namespace_apply(operation_id, reason="review_changed",
                                                  client_ip=payload["client_ip"], user_agent=payload["user_agent"])
            except Exception:
                logging.getLogger(__name__).warning("Namespace Apply outcome persistence unavailable; fence retained")
            self._compose_status_cache.clear()
        finally:
            with self._lock:
                self._operation_threads.pop(operation_id, None)

    def _finish_compose_reconcile(self, operation_id, payload, intent, outcome, reporter):
        messages = {"succeeded": "Configuration applied successfully. The service image is unchanged.",
                    "blocked": "The reviewed configuration or recovery evidence changed or could not be verified. Review changes again.",
                    "recovered": "Apply failed; the previous configuration was recovered. Desired changes remain pending.",
                    "manual": "Apply failed. Automatic recovery could not be completed safely. Manual recovery is required."}
        if intent.action == "discard":
            messages = {"succeeded": "Pending configuration changes discarded. UPT did not recreate or restart the running service.",
                        "blocked": "Blocked — no source changes made. Refresh and review the pending changes again.",
                        "recovered": "Discard failed — pending source restored. UPT did not recreate the running service.",
                        "manual": "Manual source recovery required. Pending source evidence was retained. UPT did not recreate the running service."}
        label = "manual" if outcome.manual_recovery_required else "recovered" if outcome.recovered else outcome.status
        result = {"action": intent.action, "mutation_performed": outcome.mutation_performed,
                  "recovered": outcome.recovered, "manual_recovery_required": outcome.manual_recovery_required}
        if intent.action == "discard":
            result["source_recovered"] = outcome.recovered
            result["manual_source_recovery_required"] = outcome.manual_recovery_required
        if outcome.service:
            result["current_service_key"] = f"container/{outcome.service.container_id}"
        identity = dict(zip(UPDATE_REVIEW_IDENTITY_FIELDS, intent.service_identity))
        def write_history():
            # Preserve exact image identity as private History evidence, but
            # configuration-only actions never create image rollback refs.
            for row in self.state.history_for_service(identity["stack"], identity["compose_service"]):
                if row.get("action") == "compose_reconcile" and json.loads(row.get("details") or "{}").get("operation_id") == operation_id:
                    return row["id"]
            return self.state.record(
                stack=identity["stack"], service=identity["compose_service"], action="compose_reconcile",
                old_image=identity["image"], old_image_id=identity["image_id"],
                new_image=identity["image"], new_image_id=identity["image_id"] if outcome.service else None,
                result={"succeeded": "SUCCESS", "blocked": "BLOCKED", "failed": "FAILED"}[outcome.status],
                backup=outcome.recovery_path,
                rollback_result="SOURCE RECOVERY SUCCEEDED" if outcome.recovered and intent.action == "discard" else
                                "MANUAL SOURCE RECOVERY REQUIRED" if outcome.manual_recovery_required and intent.action == "discard" else
                                "AUTOMATIC RECOVERY SUCCEEDED" if outcome.recovered else
                                "MANUAL RECOVERY REQUIRED" if outcome.manual_recovery_required else None,
                details={"origin": "web", "operation_id": operation_id, "baseline_id": intent.baseline_id,
                         "new_baseline_id": outcome.baseline_id, **result})

        history_id = None
        for attempt in range(COMPOSE_HISTORY_ATTEMPTS):
            try:
                history_id = write_history()
                break
            except Exception:
                if attempt + 1 < COMPOSE_HISTORY_ATTEMPTS:
                    time.sleep(0.2 * (attempt + 1))
        final_stage = None
        if history_id is None:
            # The workload outcome is already committed (trusted baseline, source bytes) and cannot
            # be revoked, so it stays factual; the missing record is surfaced, never hidden.
            result["warnings"] = ["Core History could not be written; recovery evidence is retained."]
        else:
            result["history_id"] = history_id
            if outcome.status == "succeeded":
                # Real final stage: the durable History record exists. It is committed with the
                # terminal state (never duplicated by a retry). Blocked, recovered and manual
                # outcomes are conveyed by their terminal state alone.
                total = DISCARD_STAGE_TOTAL if intent.action == "discard" else RECONCILE_STAGE_TOTAL
                final_stage = f"{total}/{total} Record result"
        try:
            self.state.audit("web_compose_reconcile", label, username=intent.requested_by,
                             client_ip=payload["client_ip"], user_agent=payload["user_agent"],
                             details={"operation_id": operation_id, "service_key": intent.service_key, **result})
        except Exception:
            result.setdefault("warnings", []).append("Outcome audit could not be written.")
        self.state.finish_operation(operation_id, outcome.status, message=messages[label],
                                    error=messages[label] if outcome.status != "succeeded" else None, result=result,
                                    final_stage=final_stage)

    # Compose drift status and trusted baselines ----------------------------
    def compose_status(self, payload):
        """Bounded read-only status for one exact current container.

        Docker and Compose are only read. UPT state may gain a trusted
        baseline, and only after the evidence has been proved.
        """
        self._exact_payload(payload, {"service_key"})
        service_key = payload["service_key"]
        self._validate_service_key(service_key)
        found = discover(self.config)
        matches = [item for item in found if f"container/{item.container_id}" == service_key]
        if len(matches) != 1:
            return self._public_compose_status(ComposePlan(UNVERIFIABLE, ("service_not_found",), checked_at=utc_now()))
        service = matches[0]
        cache_key = None
        if service.stack and service.compose_service and service.working_dir and service.compose_files:
            # Any runtime or configuration-input change produces a new key.
            replicas = tuple(sorted((item.container_id, (item.labels or {}).get(COMPOSE_HASH_LABEL))
                                    for item in found if item.stack == service.stack
                                    and item.compose_service == service.compose_service))
            cache_inventory = build_inventory(service.compose_files, service.working_dir)
            cache_key = (service.container_id, service.image_id, service.image, service.state, replicas,
                         cache_inventory.fingerprint, cache_inventory.unsupported)
            cached = self._compose_status_cache.get(cache_key)
            if (cached and cached[0] > time.monotonic() and cached[1]["status"] != IN_SYNC
                    and not cached[1].get("baseline")):
                return self._add_bootstrap_status(copy.deepcopy(cached[1]), service)
        public = self._add_bootstrap_status(self._public_compose_status(self._compose_plan(service, found, persist=True)), service)
        if cache_key and public["status"] in {DRIFTED, UNSUPPORTED}:
            now = time.monotonic()
            self._compose_status_cache = {key: value for key, value in self._compose_status_cache.items()
                                          if value[0] > now}
            if len(self._compose_status_cache) >= 512:
                self._compose_status_cache.clear()
            self._compose_status_cache[cache_key] = (now + COMPOSE_STATUS_CACHE_SECONDS, copy.deepcopy(public))
        return public

    @staticmethod
    def _public_compose_status(plan):
        """Allowlisted browser projection. No hashes, paths, sources or values."""
        def reasons(codes):
            return [{"code": code, "message": COMPOSE_REASONS[code]} for code in codes if code in COMPOSE_REASONS]
        data = {"status": plan.status, "reasons": reasons(plan.reasons),
                "inventory_reasons": reasons(plan.inventory_reasons), "checked_at": plan.checked_at,
                "baseline": ({"captured_at": plan.baseline.record.captured_at, "origin": plan.baseline.record.origin}
                             if plan.baseline else None),
                "update_blocked": not plan.update_eligible,
                "update_reasons": reasons(plan.update_reasons),
                "apply_eligible": bool(plan.apply_eligible),
                "discard_eligible": bool(plan.discard_eligible),
                "discard_reasons": [{"code": code, "message": DISCARD_REASONS[code]}
                                    for code in plan.discard_reasons if code in DISCARD_REASONS],
                "apply_reasons": reasons(plan.eligibility_reasons),
                "image_change": bool(plan.image_change)}
        if plan.status == DRIFTED:
            data.update(service_changes=list(plan.diff.service) if plan.diff else [],
                        project_changes=list(plan.diff.project) if plan.diff else [],
                        scope=plan.diff.scope if plan.diff else "unknown",
                        changes_itemised=bool(plan.diff))
        return data

    def _compose_plan(self, service, found, *, persist, own_operation=None, refresh_guard=None):
        """Classify one running container against its desired Compose configuration.

        persist=False is used by update-review preflight: classification only,
        with no baseline capture or adoption. refresh_guard (same-project
        reconciliation only) is re-proved under the capture lock and disables
        retained-evidence adoption.
        """
        checked_at = utc_now()

        def result(status, *reasons, **values):
            if "discard_reasons" not in values:
                values["discard_reasons"] = ("no_pending_changes",) if status == IN_SYNC else ("source_layout_unsupported",)
            return ComposePlan(status, tuple(reasons), checked_at=checked_at, **values)

        if not (service.stack and service.compose_service and service.working_dir and service.compose_files):
            return result(UNVERIFIABLE, "not_compose_service")
        if service.state != "running":
            return result(UNVERIFIABLE, "service_not_running")
        if self.state.namespace_update_fence(self._baseline_key(service)):
            return result(UNVERIFIABLE, 'namespace_update_unresolved')
        fence = self.state.bootstrap_fence(self._baseline_key(service), own_operation=own_operation)
        if fence:
            return result(UNVERIFIABLE, 'namespace_apply_unresolved' if self.state.namespace_apply_operation(
                fence.get('operation_id')) else 'bootstrap_unresolved')
        replicas = [item for item in found
                    if item.stack == service.stack and item.compose_service == service.compose_service]
        runtime_hash = (service.labels or {}).get(COMPOSE_HASH_LABEL)
        replica_hashes = [(item.labels or {}).get(COMPOSE_HASH_LABEL) for item in replicas]
        if (not any(item.container_id == service.container_id for item in replicas)
                or not all(isinstance(value, str) and COMPOSE_HASH_PATTERN.fullmatch(value)
                           for value in [runtime_hash, *replica_hashes])):
            return result(UNVERIFIABLE, "runtime_hash_missing")
        # Fingerprint every input before and after Compose resolves them so a
        # concurrent edit cannot be mistaken for the evaluated configuration.
        before = build_inventory(service.compose_files, service.working_dir)
        try:
            model = self._compose_config_model(service)
        except Exception:
            return result(UNVERIFIABLE, "compose_model_unavailable", runtime_hash=runtime_hash)
        service_model = model["services"].get(service.compose_service)
        if not isinstance(service_model, dict):
            return result(UNVERIFIABLE, "service_missing_from_model", runtime_hash=runtime_hash)
        namespace_context = None
        namespace_evidence = []
        consumer = namespace_candidate(service, service_model)
        try:
            if consumer:
                try:
                    namespace_context = _execution_context_fingerprint(service, model, namespace_evidence=namespace_evidence)
                    desired_hash = self._compose_service_hash(service, model=model, namespace_evidence=namespace_evidence[0])
                except _ExecutionContextRefused as exc:
                    # The shared resolver reports a consumer mount mismatch as an
                    # unproven owner/context; owner-only proof below stays strict.
                    if exc.reason not in {"runtime_mounts_unproven", "namespace_owner_unproven"}:
                        raise
                    # A pending bind edit cannot match running mounts. Derive the
                    # desired identity from owner-only proof; Stage 2 review then
                    # proves the running consumer against its trusted baseline.
                    desired_hash = self._namespace_desired_hash(service, model)
            else:
                desired_hash = self._compose_service_hash(service)
        except _ExecutionContextRefused as exc:
            return result(UNVERIFIABLE, exc.reason, runtime_hash=runtime_hash)
        except NamespaceRefused as exc:
            return result(UNVERIFIABLE, exc.reason, runtime_hash=runtime_hash)
        except Exception:
            return result(UNVERIFIABLE, "compose_hash_unavailable", runtime_hash=runtime_hash)
        inventory = build_inventory(service.compose_files, service.working_dir, model=model)
        if inventory.fingerprint != before.fingerprint or inventory.unsupported != before.unsupported:
            return result(UNVERIFIABLE, "sources_changed_during_check", runtime_hash=runtime_hash)
        common = dict(runtime_hash=runtime_hash, desired_hash=desired_hash, desired_model=model,
                      inventory=inventory, inventory_reasons=inventory.unsupported)
        if hash_excluded_fields_present(service_model):
            return result(UNVERIFIABLE, "hash_excluded_fields", **common)
        try:
            mutation_reason = mutation_refusal(service, model=model)
        except NamespaceRefused as exc:
            mutation_reason = exc.reason
        drift = []
        if service_model.get("image") != service.image:
            drift.append("image_differs")
        if desired_hash != runtime_hash:
            drift.append("config_hash_differs")
        elif any(value != desired_hash for value in replica_hashes):
            drift.append("replica_hash_differs")
        if not drift:
            baseline = None
            try:
                _assert_project_identity(service, model)
                project_matches = True
            except _ExecutionContextRefused:
                project_matches = False
            if persist and inventory.supported and project_matches:
                try:
                    baseline = self._capture_baseline(service, runtime_hash, model, inventory, guard=refresh_guard)
                except _ComposeCheckRaced as exc:
                    return result(UNVERIFIABLE, exc.reason, **common)
                except Exception:
                    logging.getLogger(__name__).warning("Could not persist a trusted Compose baseline")
            if inventory.supported:
                if len(replicas) != 1:
                    return result(IN_SYNC, baseline=baseline, update_reasons=("multiple_replicas",), **common)
                try:
                    context = _execution_context_fingerprint(service, model)
                except _ExecutionContextRefused as exc:
                    if consumer:
                        return result(UNVERIFIABLE, exc.reason, **common)
                    return result(IN_SYNC, baseline=baseline, update_reasons=(exc.reason,), **common)
                if consumer and context != namespace_context:
                    return result(UNVERIFIABLE, "namespace_owner_changed", **common)
                update_review = None
                if consumer and mutation_reason == 'namespace_unsupported_compose':
                    try:
                        update_review = review_namespace_update(service)
                        if (update_review.context != context
                                or update_review.model_fingerprint != compose_fingerprint(model)
                                or update_review.inputs != tuple(tuple(item.identity()) for item in inventory.files)):
                            raise PreMutationRefusal(COMPOSE_REASONS['namespace_owner_changed'], 'namespace_owner_changed')
                        mutation_reason = None
                    except PreMutationRefusal as exc:
                        mutation_reason = exc.reason
                return result(IN_SYNC, baseline=baseline, update_eligible=not mutation_reason,
                              update_reasons=(mutation_reason,) if mutation_reason else (),
                              execution_context_fingerprint=context, namespace_update_review=update_review, **common)
            return result(UNSUPPORTED, *inventory.unsupported, **common)

        baseline = diff = None
        trust_store_failed = False
        try:
            if persist and refresh_guard is None:
                baseline = self._trusted_baseline(service, runtime_hash)
            else:
                # Review authority: exact current trust only. For a namespace
                # consumer an integrity failure is a trust-store error.
                baseline = self._exact_baseline(service, runtime_hash, strict=consumer)
        except Exception:
            trust_store_failed = True
            logging.getLogger(__name__).warning("Could not evaluate trusted Compose baselines")
        image_change = "image_differs" in drift
        if baseline:
            diff = compute_diff(baseline.model, model, service.compose_service, baseline.record.fingerprint,
                                project_observed=baseline.project_observed)
            image_change = image_change or diff.image_change
        ineligible = []
        if trust_store_failed and consumer:
            ineligible.append("trust_store_unavailable")
        if consumer:
            # Reported independently of other gates: initial Stage 2 never
            # supports a selected-consumer env_file, wherever it is declared.
            try:
                refuse_consumer_env_file(inventory, service.compose_service, [service_model])
                if baseline:
                    refuse_consumer_env_file(baseline.inventory, service.compose_service,
                                             [baseline.model["services"][service.compose_service]])
            except NamespaceRefused as exc:
                ineligible.append(exc.reason)
        if not baseline:
            ineligible.append("no_trusted_baseline")
        # Observations remain observations. Require an independent live proof
        # for the supported execution context; never promote project_trusted.
        if (not baseline or not baseline.project_observed
                or set(model) - {"name", "services", "networks"}
                or set(model.get("networks") or {}) - {"default", _selected_logical_network(service, model)}):
            ineligible.append("project_unproven")
        if not inventory.supported:
            ineligible.append("inventory_unsupported")
        if image_change:
            ineligible.append("image_change")
        if diff and diff.scope != "service":
            ineligible.append("project_changes")
        if len(replicas) != 1:
            ineligible.append("multiple_replicas")
        if service.local_build or service.ignored:
            ineligible.append("service_ineligible")
        if service.health in {"unhealthy", "starting"}:
            ineligible.append("service_ineligible")
        context = None
        namespace_review = None
        # Namespace consumers use the Stage 2 owner/consumer review below instead.
        if not consumer:
            try:
                context = _execution_context_fingerprint(service, model)
                if baseline:
                    baseline_service = baseline.model["services"][service.compose_service]
                    if hash_excluded_fields_present(baseline_service):
                        ineligible.append("hash_excluded_fields")
                    for selected in (service_model, baseline_service):
                        if any(selected.get(field) for field in ("develop", "provider", "tmpfs", "deploy")):
                            ineligible.append("service_resource_unproven")
                        if "build" in selected:
                            ineligible.append("hash_excluded_fields")
                    if baseline_service.get("image") != service.image:
                        ineligible.append("image_change")
                    recovery_model = {**model, "services": {service.compose_service: baseline_service}}
                    if _execution_context_fingerprint(service, recovery_model) != context:
                        ineligible.append("service_resource_unproven")
                    _assert_reconcile_runtime_mounts(service, baseline_service)
            except _ExecutionContextRefused as exc:
                ineligible.append(exc.reason)
        if baseline and input_layout(inventory) != input_layout(baseline.inventory):
            ineligible.append("input_inventory_changed")
        if diff and (not diff.service or desired_hash == runtime_hash):
            ineligible.append("service_change_unproven")
        if not ineligible:
            try:
                verify_atomic_replace_access([item.path for item in inventory.files if item.present])
            except Exception:
                ineligible.append("recovery_source_not_writable")
            try:
                verify_image_unchanged(service)
            except Exception:
                ineligible.append("local_image_changed")
        if consumer and not ineligible and mutation_reason == "namespace_unsupported_compose":
            # Stage 2 replaces the ordinary single-service context gates with the
            # reviewed owner/consumer proof. Discard remains unavailable.
            try:
                namespace_review = review_namespace_apply(
                    service, found, model=model, inventory=inventory, baseline=baseline, diff=diff,
                    desired_hash=desired_hash, deps=self._namespace_apply_deps())
                mutation_reason = None
            except NamespaceRefused as exc:
                ineligible.append(exc.reason if exc.reason in COMPOSE_REASONS else "namespace_owner_unproven")
            except Exception:
                ineligible.append("namespace_owner_unproven")
        isolation = None
        discard_reasons = list(discard_gate_reasons(ineligible + (["namespace_unsupported_compose"] if consumer else [])))
        if not baseline or baseline.record.container_id != service.container_id:
            discard_reasons.insert(0, "no_trusted_baseline")
        # Diagnose the source class independently of the common safety gates.
        # A proved source plan alone never authorises Discard.
        if baseline:
            try:
                isolation = prove_source_isolation(inventory, baseline.inventory, service.compose_service,
                                                   reviewed_fields={entry["field"] for entry in diff.service})
            except DiscardRefused as exc:
                discard_reasons.insert(0, exc.reason)
            except Exception:
                discard_reasons.insert(0, "source_layout_unsupported")
        elif len(service.compose_files) > 1:
            discard_reasons.append("multiple_compose_files")
        if discard_reasons:
            isolation = None
        return result(DRIFTED, *drift, baseline=baseline, diff=diff, image_change=image_change,
                      apply_eligible=not ineligible and not mutation_reason and (not consumer or namespace_review is not None),
                      discard_eligible=isolation is not None, discard_plan=isolation,
                      discard_reasons=tuple(dict.fromkeys(discard_reasons)),
                      execution_context_fingerprint=context, namespace_apply_review=namespace_review,
                      eligibility_reasons=tuple(dict.fromkeys(ineligible + ([mutation_reason] if mutation_reason else []))), **common)

    def _exact_baseline(self, service, runtime_hash, *, strict=False):
        """Load existing current-container evidence; never adopt during review.

        strict: an integrity failure is a trust-store error, never absence.
        """
        store = BaselineStore(self.state)
        with self._baseline_lock:
            return self._find_exact_baseline(store, service, runtime_hash, strict=strict)

    def _find_exact_baseline(self, store, service, runtime_hash, *, strict):
        # Caller holds _baseline_lock.
        for record in store.records(self._baseline_key(service)):
            if record.container_id == service.container_id and record.runtime_hash == runtime_hash:
                try:
                    return store.load(record)
                except BaselineIntegrityError:
                    if strict:
                        raise
                    continue
        return None

    def _refresh_project_baselines(self, changed):
        """Passively re-prove already-trusted members of one exact Compose project.

        Called only after a clean mutation success changed shared project
        inputs. It reuses the compose_status() proof/capture path, but never
        creates first-time trust, adopts retained evidence or follows a
        restarted/replaced namespace owner. Docker and Compose are only read.
        """
        identity = _project_identity(changed)
        if identity is None:
            return 0
        self._compose_status_cache.clear()
        members = discover(self.config, all_containers=True)
        found = discover(self.config)
        refreshed = 0
        for sibling in found:
            if _project_identity(sibling) != identity:
                continue
            runtime_hash = (sibling.labels or {}).get(COMPOSE_HASH_LABEL)
            try:
                # Trust is refreshed only for an unambiguous logical service.
                if not self._sole_member(sibling, members):
                    continue
                trusted = (self._exact_baseline(sibling, runtime_hash, strict=True)
                           if isinstance(runtime_hash, str) else None)
                if trusted is None:
                    continue
                plan = self._compose_plan(sibling, found, persist=True, refresh_guard=partial(
                    self._refresh_guard, sibling, runtime_hash, trusted.record))
                if plan.status == IN_SYNC and plan.baseline and plan.baseline.record.id != trusted.record.id:
                    refreshed += 1
            except Exception:
                logging.getLogger(__name__).warning("Same-project baseline reconciliation needs retry")
        self._compose_status_cache.clear()
        return refreshed

    @staticmethod
    def _sole_member(service, members):
        logical = [item for item in members
                   if item.stack == service.stack and item.compose_service == service.compose_service]
        return len(logical) == 1 and logical[0].container_id == service.container_id

    def _refresh_guard(self, service, runtime_hash, trusted, store, consumer):
        """Re-prove, under the capture lock, the trust a refresh may replace."""
        current = self._find_exact_baseline(store, service, runtime_hash, strict=True)
        if current is None or current.record.id != trusted.id:
            raise _ComposeCheckRaced("no_trusted_baseline")
        members = discover(self.config, all_containers=True)
        if not self._sole_member(service, members):
            raise _ComposeCheckRaced("multiple_replicas")
        if not consumer:
            return
        # A baseline does not retain owner context. Any owner restart or
        # replacement after trust was captured must be reviewed, not refreshed.
        mode = service.network_mode or ""
        owners = [item for item in members
                  if mode.startswith("container:") and item.container_id == mode[len("container:"):]]
        try:
            if (len(owners) != 1 or owners[0].state != "running"
                    or _start(owners[0].started_at) > _start(trusted.captured_at)):
                raise _ComposeCheckRaced("namespace_owner_changed")
        except NamespaceRefused:
            raise _ComposeCheckRaced("namespace_owner_changed") from None

    def start_project_refresh(self, service_key):
        """Agent RPC adapter for CLI mutations; enqueue only, never prove inline."""
        self._validate_service_key(service_key)
        found = [item for item in discover(self.config) if f"container/{item.container_id}" == service_key]
        if len(found) != 1:
            return {"status": "ignored"}
        return {"status": self._queue_project_refresh(found[0])}

    def _defer_project_refresh(self, service):
        """post_project_change for web workers: dispatched after terminal persistence."""
        requests = _deferred_project_refresh.get()
        if requests is None:
            self._queue_project_refresh(service)
        elif len(requests) < 4:
            requests.append(service)

    def _dispatch_project_refresh(self, operation_id, requests):
        try:
            operation = self.state.operation_status(operation_id, after_event_id=2**63 - 1)
            if not operation or operation.get("status") != "succeeded":
                return
            for service in requests:
                self._queue_project_refresh(service)
        except Exception:
            logging.getLogger(__name__).warning("Same-project baseline reconciliation needs retry")

    def _queue_project_refresh(self, service):
        """Coalesce by exact project identity onto one bounded background worker."""
        identity = _project_identity(service)
        if identity is None:
            return "ignored"
        with self._lock:
            if identity in self._project_refresh_pending:
                self._project_refresh_pending[identity] = service
                return "coalesced"
            if len(self._project_refresh_pending) >= PROJECT_REFRESH_QUEUE_LIMIT:
                logging.getLogger(__name__).warning("Same-project baseline reconciliation queue is full")
                return "saturated"
            self._project_refresh_pending[identity] = service
            if self._project_refresh_thread is not None:
                return "queued"
            thread = threading.Thread(target=self._project_refresh_worker, name="upt-project-refresh", daemon=True)
            self._project_refresh_thread = thread
        try:
            thread.start()
        except Exception:
            with self._lock:
                if self._project_refresh_thread is thread:
                    self._project_refresh_thread = None
                    self._project_refresh_pending.clear()
            logging.getLogger(__name__).warning("Same-project baseline reconciliation worker unavailable")
            return "unavailable"
        return "queued"

    def _project_refresh_worker(self):
        try:
            while True:
                with self._lock:
                    if not self._project_refresh_pending:
                        self._project_refresh_thread = None
                        return
                    service = self._project_refresh_pending.pop(next(iter(self._project_refresh_pending)))
                try:
                    self._refresh_project_baselines(service)
                except Exception:
                    logging.getLogger(__name__).warning("Same-project baseline reconciliation needs retry")
        finally:
            with self._lock:
                if self._project_refresh_thread is threading.current_thread():
                    self._project_refresh_thread = None

    def _confirm_runtime_unchanged(self, service, runtime_hash):
        try:
            current = [item for item in discover(self.config) if item.container_id == service.container_id]
        except Exception:
            raise _ComposeCheckRaced("runtime_changed_during_check") from None
        if (len(current) != 1 or current[0].state != "running" or current[0].image_id != service.image_id
                or (current[0].labels or {}).get(COMPOSE_HASH_LABEL) != runtime_hash):
            raise _ComposeCheckRaced("runtime_changed_during_check")

    @staticmethod
    def _baseline_key(service):
        return logical_key(service.stack, service.compose_service, service.working_dir, service.compose_files)

    def _capture_baseline(self, service, runtime_hash, model, inventory, *, guard=None):
        """Persist live inputs proven (hash, model and bracketing fingerprints) to be running."""
        selected = model["services"][service.compose_service]
        consumer = namespace_candidate(service, selected)
        if consumer and self.state.namespace_update_fence(self._baseline_key(service)):
            raise _ComposeCheckRaced('namespace_update_unresolved')

        def consumer_proof():
            evidence = []
            try:
                before = build_inventory(service.compose_files, service.working_dir, model=model)
                context = _execution_context_fingerprint(service, model, namespace_evidence=evidence)
                if self._compose_service_hash(service, model=model, namespace_evidence=evidence[0]) != runtime_hash:
                    raise _ComposeCheckRaced("compose_hash_unavailable")
                after = build_inventory(service.compose_files, service.working_dir, model=model)
                if (not before.supported or not after.supported
                        or before.fingerprint != inventory.fingerprint or after.fingerprint != inventory.fingerprint):
                    raise _ComposeCheckRaced("sources_changed_during_check")
                return context
            except (_ExecutionContextRefused, NamespaceRefused) as exc:
                raise _ComposeCheckRaced(exc.reason) from None
            except PreMutationRefusal:
                raise _ComposeCheckRaced("compose_hash_unavailable") from None

        context = consumer_proof() if consumer else None
        # Passive capture writes baseline material before its database row.
        self.state.ensure_compatible()
        self.state.assert_service_unfenced(service)
        store = BaselineStore(self.state)
        key = self._baseline_key(service)
        with self._baseline_lock:
            for record in store.records(key)[:1]:
                if (record.container_id == service.container_id and record.runtime_hash == runtime_hash
                        and record.inventory_fingerprint == inventory.fingerprint
                        and record.manifest.get("version") == 2
                        and record.project_fingerprint == compose_fingerprint(
                            observed_service_model(model, service.compose_service))):
                    try:
                        return store.load(record)
                    except BaselineIntegrityError:
                        break
            self._confirm_runtime_unchanged(service, runtime_hash)
            if guard:
                guard(store, consumer)
            if consumer and consumer_proof() != context:
                raise _ComposeCheckRaced("namespace_owner_changed")
            record = store.save(key=key, stack=service.stack, compose_service=service.compose_service,
                                container_id=service.container_id, runtime_hash=runtime_hash, model=model,
                                inventory=inventory, origin="captured", captured_at=utc_now(),
                                protected=self._active_compose_baselines())
            return store.load(record)

    def _active_compose_baselines(self):
        with self._lock:
            return {item.baseline_id for item in self._compose_intents.values()
                    if item.expires_at > time.monotonic()}

    def _trusted_baseline(self, service, runtime_hash):
        """Return a baseline proven to reproduce this exact running container, else None.

        A stored baseline is trusted directly only for the container it was
        captured for. A replacement container, or a retained UPT backup, must
        independently reproduce the running Compose hash from its own bytes.
        """
        self.state.assert_service_unfenced(service)
        store = BaselineStore(self.state)
        key = self._baseline_key(service)
        with self._baseline_lock:
            for record in store.records(key):
                if record.runtime_hash != runtime_hash:
                    continue
                try:
                    loaded = store.load(record)
                except BaselineIntegrityError:
                    continue
                if record.container_id == service.container_id:
                    return loaded
                proved = self._reproduce_candidate(
                    service, runtime_hash,
                    {item.path: item for item in loaded.inputs if item.role in {"compose", "project_env"}})
                if proved:
                    return self._save_proved(store, key, service, runtime_hash, proved, "reproduced")
            candidates = self._backup_candidates(service)
            signature = (service.container_id, runtime_hash, tuple(name for name, _inputs in candidates))
            now = time.monotonic()
            if self._adoption_failures.get(signature, 0) > now:
                return None
            for _name, inputs in candidates:
                proved = self._reproduce_candidate(service, runtime_hash, inputs)
                if proved:
                    return self._save_proved(store, key, service, runtime_hash, proved, "adopted_backup")
            self._adoption_failures = {item: expiry for item, expiry in self._adoption_failures.items()
                                       if expiry > now}
            if len(self._adoption_failures) < 256:
                self._adoption_failures[signature] = now + ADOPTION_RETRY_SECONDS
            return None

    def _save_proved(self, store, key, service, runtime_hash, proved, origin):
        self.state.assert_service_unfenced(service)
        model, inventory = proved
        try:
            self._confirm_runtime_unchanged(service, runtime_hash)
        except _ComposeCheckRaced:
            return None
        record = store.save(key=key, stack=service.stack, compose_service=service.compose_service,
                            container_id=service.container_id, runtime_hash=runtime_hash, model=model,
                            inventory=inventory, origin=origin, captured_at=utc_now(),
                            protected=self._active_compose_baselines())
        return store.load(record)

    def _reproduce_candidate(self, service, runtime_hash, inputs):
        """Prove candidate Compose/.env bytes reproduce the running hash.

        Compose files and the project .env come from the candidate; env_file
        inputs are read live and fingerprinted before and after the Compose
        run. The resulting baseline is exactly the byte set Compose evaluated.
        """
        owner = []

        def names(model):
            selected = (model.get("services") or {}).get(service.compose_service)
            if isinstance(selected, dict) and namespace_candidate(service, selected):
                # The owner oracle must resolve the same private source as
                # the consumer, not independently read the live Compose file.
                owner.append(namespace_owner(selected))
            return (service.compose_service, *owner)

        try:
            model, hashes, after = self._evaluate_private_inputs(service, inputs, names)
        except Exception:
            return None
        service_model = model["services"].get(service.compose_service)
        candidate_hash = hashes.get(service.compose_service)
        if isinstance(service_model, dict) and isinstance(service_model.get("network_mode"), str) and service_model["network_mode"].startswith("service:"):
            try:
                values = []
                _execution_context_fingerprint(
                    service, model, namespace_evidence=values,
                    namespace_hash_reader=lambda item: hashes.get(owner[0]) if owner and item.compose_service == owner[0] else None)
                candidate_hash = resolved_hash(service_model, values[0].container_id, candidate_hash)
            except Exception:
                return None
        if (candidate_hash != runtime_hash
                or not isinstance(service_model, dict) or service_model.get("image") != service.image
                or hash_excluded_fields_present(service_model)):
            return None
        return model, after

    def _evaluate_private_inputs(self, service, inputs, names):
        """Bounded read-only Compose evaluation of retained compose/.env bytes.

        Uses the original project directory; env_file inputs are read live and
        bracketed. Returns (model, {service: unmodified hash}, inventory) or
        raises. No source restoration or workload command is involved.
        """
        working_dir = os.path.abspath(service.working_dir)
        compose_paths = [os.path.abspath(path) for path in service.compose_files]
        env_path = os.path.join(working_dir, ".env")
        if any(path not in inputs or not inputs[path].present for path in compose_paths):
            raise ValueError("retained inputs are incomplete")

        def reader(role, path, optional):
            if role in {"compose", "project_env"}:
                item = inputs.get(path)
                if item is None or not item.present:
                    if role == "compose":
                        raise InputReadError("source_unreadable")
                    return InputFile(role, path, False, None, 0)
                return InputFile(role, path, True, item.sha256, item.size, item.content)
            return read_input(role, path, optional=optional)

        before = build_inventory(compose_paths, working_dir, reader)
        if not before.supported:
            raise ValueError("retained inputs are unsupported")
        env_item = before.by_path().get(env_path)
        temporary_root = Path(self.state.root) / "tmp"
        temporary_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory = tempfile.mkdtemp(prefix="compose-proof-", dir=str(temporary_root))
        try:
            def private_copy(name, content):
                path = os.path.join(directory, name)
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(content)
                return path
            args = ["docker", "compose", "--project-directory", working_dir, "--env-file",
                    private_copy("project.env", env_item.content if env_item and env_item.present else b"")]
            for index, path in enumerate(compose_paths):
                args += ["-f", private_copy(f"{index:02d}-compose.yml", inputs[path].content)]
            model = json.loads(run(args + ["config", "--format", "json"], cwd=working_dir, timeout=30))
            if not isinstance(model, dict) or not isinstance(model.get("services"), dict):
                raise ValueError("retained model is invalid")
            hashes = {}
            for name in names(model):
                output = run(args + ["config", "--hash", name], cwd=working_dir, timeout=30)
                hashes[name] = self._compose_hash_from_output(name, output)
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        after = build_inventory(compose_paths, working_dir, reader, model=model)
        if not after.supported or after.fingerprint != before.fingerprint:
            raise ValueError("retained inputs changed during evaluation")
        return model, hashes, after

    def _namespace_apply_deps(self):
        return NamespaceApplyDeps(
            discover=lambda: discover(self.config, all_containers=True), model_reader=self._compose_config_model,
            unmodified_hash=_unmodified_compose_hash,
            evaluate_retained=lambda service, inputs, names: self._evaluate_private_inputs(
                service, inputs, lambda _model: names),
            context_reader=_execution_context_fingerprint, mounts_reader=_assert_reconcile_runtime_mounts,
            image_verifier=verify_image_unchanged)

    def _namespace_desired_hash(self, service, model):
        """Desired consumer identity from owner-only proof (no consumer mount proof)."""
        selected = model["services"][service.compose_service]
        owner_name = namespace_owner(selected)
        owner_model = model["services"].get(owner_name)
        try:
            owner = prove_owner(service, owner_name, owner_model,
                                condition=_relationship(service, selected, owner_name, owner_model),
                                found=discover(self.config, all_containers=True),
                                context_reader=_execution_context_fingerprint, context_model=model,
                                hash_reader=_unmodified_compose_hash, image_verifier=verify_image_unchanged,
                                mounts_reader=_assert_reconcile_runtime_mounts)
        except NamespaceRefused as exc:
            raise _ExecutionContextRefused(exc.reason) from None
        return resolved_hash(selected, owner.container_id, _unmodified_compose_hash(service))

    def _backup_candidates(self, service):
        """Newest retained UPT backups whose inventory covers the current sources.

        Matching stack/service names only selects a candidate; trust requires
        _reproduce_candidate to reproduce the running hash from its bytes.
        """
        root = Path(self.state.root) / "backups"
        if root.is_symlink() or not root.is_dir():
            return []
        working_dir = os.path.abspath(service.working_dir)
        compose_paths = [os.path.abspath(path) for path in service.compose_files]
        env_path = os.path.join(working_dir, ".env")
        allowed = set(compose_paths) | {env_path}
        try:
            directories = sorted((item for item in root.iterdir() if not item.is_symlink() and item.is_dir()),
                                 key=lambda item: item.name, reverse=True)[:64]
        except OSError:
            return []
        candidates = []
        for directory in directories:
            try:
                metadata = json.loads(read_input("metadata", str(directory / "metadata.json")).content)
            except (InputReadError, ValueError):
                continue
            if (not isinstance(metadata, dict) or metadata.get("stack") != service.stack
                    or metadata.get("service") != service.key):
                continue
            entries = metadata.get("files")
            if not isinstance(entries, list) or not entries or len(entries) > 32:
                continue
            inputs, valid = {}, True
            for entry in entries:
                if (not isinstance(entry, dict) or not isinstance(entry.get("source"), str)
                        or not isinstance(entry.get("backup"), str)):
                    valid = False
                    break
                source = os.path.abspath(entry["source"])
                backup = os.path.abspath(entry["backup"])
                if source not in allowed or source in inputs or os.path.dirname(backup) != os.path.abspath(directory):
                    valid = False
                    break
                try:
                    item = read_input("backup", backup)
                except InputReadError:
                    valid = False
                    break
                role = "compose" if source in compose_paths else "project_env"
                inputs[source] = InputFile(role, source, True, item.sha256, item.size, item.content)
            if not valid or any(path not in inputs for path in compose_paths):
                continue
            inputs.setdefault(env_path, InputFile("project_env", env_path, False, None, 0))
            candidates.append((directory.name, inputs))
            if len(candidates) >= MAX_BACKUP_CANDIDATES:
                break
        return candidates

    def operation_status(self, payload):
        self._exact_payload(payload, {"operation_id", "after_event_id"})
        operation_id, after = payload["operation_id"], payload["after_event_id"]
        if not isinstance(operation_id, str) or not re.fullmatch(r"[a-f0-9]{32}", operation_id):
            raise ValueError("invalid operation identifier")
        if type(after) is not int or after < 0 or after > 2**63 - 1:
            raise ValueError("invalid operation cursor")
        result = self.state.operation_status(operation_id, after)
        namespace = bool(result and result.get("kind") == "compose_reconcile"
                         and result["summary"].get("namespace_apply") is not None)
        if result and (result.get('kind') == 'compose_bootstrap' or namespace) and result.get('status') in {'queued','running','finalizing'}:
            try:
                with Lock(self.state.root/'update.lock'):
                    self.state.ensure_compatible()
                    self.state.recover_abandoned_operations()
                result = self.state.operation_status(operation_id, after)
            except RuntimeError:
                # A live worker retains the lock throughout. Polling cannot
                # classify it as interrupted merely because it takes time.
                pass
        if result is None:
            raise ValueError("operation not found")
        if result.get('kind') == 'compose_bootstrap':
            result['summary'] = {key:value for key,value in result['summary'].items()
                                 if key in {'action','automatic_recovery','old_trusted_source_available'}}
            if result.get('status') == 'succeeded' and result['result'].get('refresh_required'):
                result['result'].setdefault('warnings',[]).append(REFRESH_NOTICE)
        if namespace:
            return self._public_namespace_operation(result)
        if result.get("kind") == "compose_reconcile":
            result["summary"].pop("baseline_id", None)
            result["summary"].pop("new_baseline_id", None)
            result["summary"].pop("discard_evidence", None)
        return result

    _NAMESPACE_RESULT_FIELDS = frozenset({
        "action", "mutation_performed", "possible_mutation", "recovered", "manual_recovery_required",
        "namespace", "image_unchanged", "owner_unchanged", "current_service_key", "refresh_required",
        "history_id", "blocked_reason"})

    @classmethod
    def _public_namespace_operation(cls, operation):
        """Explicit allowlist (HTTP, SSE and reload): no fingerprints, IDs or paths."""
        def facts(value):
            value = value if isinstance(value, dict) else {}
            public = {key: value[key] for key in cls._NAMESPACE_RESULT_FIELDS if key in value}
            key = public.get("current_service_key")
            if key is not None and not (isinstance(key, str) and re.fullmatch(r"container/[0-9a-f]{64}", key)):
                public.pop("current_service_key")
            if public.get("refresh_required"):
                public["warnings"] = [REFRESH_NOTICE]
            return public
        public = {key: operation.get(key) for key in (
            "id", "kind", "service_key", "service", "stack", "requested_by", "status", "created_at", "started_at",
            "finished_at", "current_stage", "error", "last_event_id")}
        public["summary"] = {"action": "apply", "namespace": True}
        public["result"] = facts(operation.get("result"))
        public["events"] = [{**{key: event.get(key) for key in ("id", "operation_id", "timestamp", "kind", "stage",
                                                              "message", "status")},
                             "payload": facts(event.get("payload"))} for event in operation.get("events") or []]
        return public

    def handle(self, operation: str, payload: dict | None = None):
        if operation not in AGENT_OPERATIONS:
            raise AgentAuthorizationError("operation is not available through the bounded agent")
        payload = payload or {}
        if operation == "health": return self.health()
        if operation == "snapshot": return self.snapshot()
        if operation == "runtime_snapshot": return self.runtime_snapshot()
        if operation == "verification_snapshot": return self.verification_snapshot()
        if operation == "refresh_start":
            after = payload.get("after_reconcile", False)
            project = payload.get("project_inputs", False)
            if type(after) is not bool or type(project) is not bool:
                raise ValueError("invalid refresh mode")
            if project:
                return self.start_project_refresh(payload.get("service_key"))
            return self.start_refresh(payload.get("service_key"), after_reconcile=after)
        if operation == "refresh_status": return self.refresh_status(payload.get("service_key"))
        if operation == "service": return self.service(payload.get("service_key", ""))
        if operation == "scan_start": return self.start_scan()
        if operation == "scan_status": return self.scan_status(payload.get("run_id"), payload.get("after_event_id", 0))
        if operation == "audit_recent": return self.audit_recent(payload.get("limit", 100))
        if operation == "update_review": return self.update_review(payload)
        if operation == "update_start": return self.start_update(payload)
        if operation == "rollback_review": return self.rollback_review(payload)
        if operation == "rollback_start": return self.start_rollback(payload)
        if operation == "operation_status": return self.operation_status(payload)
        if operation == "compose_status": return self.compose_status(payload)
        if operation == "compose_bootstrap_review": return self.compose_bootstrap_review(payload)
        if operation == "compose_bootstrap_start": return self.start_compose_bootstrap(payload)
        if operation == "compose_reconcile_review": return self.compose_reconcile_review(payload)
        if operation == "compose_reconcile_start": return self.start_compose_reconcile(payload)
        raise AgentAuthorizationError("unsupported operation")

    def _scan_worker(self, run_id: str):
        # Resolve helpers at call time so existing test patches of webservice
        # discovery/registry functions also govern the background scan worker.
        return run_full_scan(
            run_id, config=self.config, state=self.state, web_settings=self.web_settings,
            discover_services=discover, check_service=scan_service_with_tracking,
            public_result=_public_result, public_service=_public_service,
            safe_error=_safe_error, safe_identifier=_safe_mutation_log_identifier,
            logger=logging.getLogger(__name__),
        )


@dataclass
class AgentServer:
    service: ReadOnlyService
    socket_path: str
    mode: int = 0o660
    allow_test_paths: bool = False
    allowed_mutation_uid: int | None = None

    def handle_line(self, line: bytes, *, peer_uid: int | None = None) -> bytes:
        import json
        operation = None
        try:
            if not line or len(line) > 65536 or not line.endswith(b"\n"):
                raise ValueError("invalid request framing")
            request = json.loads(line.decode("utf-8"))
            if not isinstance(request, dict): raise ValueError("invalid request")
            operation, payload = request.get("operation"), request.get("payload", {})
            if not isinstance(operation, str) or not isinstance(payload, dict): raise ValueError("invalid request")
            if operation in MUTATION_OPERATIONS and (self.allowed_mutation_uid is None or peer_uid != self.allowed_mutation_uid):
                raise AgentAuthorizationError("mutation requests are restricted to the configured web service identity")
            if operation in VERSION_GATED_OPERATIONS:
                # Agent-side half of the version gate: refuses an old/unknown web
                # client that cannot perform the web-side comparison itself. The
                # transport owns the in-payload assertion and strips it, so the
                # handlers' exact payload schemas stay unchanged.
                claim = payload.get(TRANSPORT_VERSION_FIELD)
                if request.get("client_version") != __version__ or reported_version(claim) != __version__:
                    raise ComponentVersionMismatch()
                payload = {key: value for key, value in payload.items() if key != TRANSPORT_VERSION_FIELD}
            response = {"ok": True, "data": self.service.handle(operation, payload)}
        except Exception as exc:
            if isinstance(exc, AgentAuthorizationError):
                response = {"ok": False, "error": str(exc), "type": "PermissionError"}
            elif isinstance(exc, ComponentVersionMismatch):
                response = {"ok": False, "error": exc.public_message, "type": "ComponentVersionMismatch", "reason": exc.reason}
            elif operation == "service" and isinstance(exc, ValueError) and str(exc) == "service not found in cached scan":
                response = {"ok": False, "error": "service not present in cached scan", "type": "AgentNotFound"}
            elif operation == "scan_status" and isinstance(exc, ValueError) and str(exc) == "scan operation not found":
                response = {"ok": False, "error": "scan operation not found", "type": "AgentNotFound"}
            elif operation == "operation_status" and isinstance(exc, ValueError) and str(exc) == "operation not found":
                response = {"ok": False, "error": "operation not found", "type": "AgentNotFound"}
            elif operation == "update_review" and isinstance(exc, ComposePreflightRefused):
                response = {"ok": False, "error": exc.public_message, "type": "ComposePreflightRefused",
                            "status": exc.status, "reason": exc.reason}
            elif operation == "update_start" and isinstance(exc, (ValueError, RuntimeError)):
                response = {"ok": False, "error": self.service._safe_operation_error(exc),
                            "type": "ValueError" if isinstance(exc, PreMutationRefusal) else exc.__class__.__name__}
            elif operation == "rollback_start" and isinstance(exc, (ValueError, RuntimeError)):
                response = {"ok": False, "error": self.service._safe_rollback_error(exc),
                            "type": "ValueError" if isinstance(exc, PreMutationRefusal) else exc.__class__.__name__}
            elif operation == "compose_reconcile_review" and isinstance(exc, DiscardRefused):
                response = {"ok": False, "error": exc.public_message, "type": "DiscardRefused", "reason": exc.reason}
            elif (operation in {"compose_reconcile_review", "compose_reconcile_start"}
                  and isinstance(exc, (ValueError, RuntimeError))):
                response = {"ok": False, "error": "Configuration action could not be reviewed or started safely. Refresh and review again.",
                            "type": "ValueError"}
            else:
                response = {"ok": False, "error": _safe_error(exc), "type": exc.__class__.__name__}
        return (json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8")

    def serve_forever(self):
        import json
        import os
        import socket
        import struct
        from pathlib import Path
        # Refuse an unsupported core state database before binding the socket,
        # so the agent never becomes able to accept or start mutation work.
        self.service.state.ensure_compatible()
        path = Path(self.socket_path)
        runtime_root = Path("/run/docker-update-manager")
        resolved_parent = path.parent.resolve()
        if resolved_parent != runtime_root and not (self.allow_test_paths and str(resolved_parent).startswith("/tmp/")):
            raise ValueError("agent socket must be under /run/docker-update-manager")
        if not path.parent.exists():
            if resolved_parent == runtime_root: path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            else: raise ValueError("agent socket parent directory does not exist")
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_socket(): raise ValueError("refusing to replace non-socket agent path")
            path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(path))
        os.chmod(path, self.mode)
        sock.listen(16)
        try:
            self.service.start_health_monitor()
            while True:
                conn, _ = sock.accept()
                with conn:
                    conn.settimeout(10)
                    raw = conn.makefile("rwb")
                    try:
                        credentials = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                        _pid, peer_uid, _gid = struct.unpack("3i", credentials)
                    except Exception:
                        peer_uid = None
                    try:
                        response_data = self.handle_line(raw.readline(65537), peer_uid=peer_uid)
                    except Exception:
                        response_data = self.handle_line(b"{}", peer_uid=peer_uid)
                    raw.write(response_data); raw.flush()
        finally:
            self.service.stop_health_monitor()
            sock.close()
            try: path.unlink()
            except FileNotFoundError: pass
