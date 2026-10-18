"""Service-only, image-preserving Compose Apply and one guarded recovery.

The caller owns review authority and the shared mutation lock. All inputs and
callbacks are server-owned; this core has no HTTP, prompts or CLI dependency.
"""
from __future__ import annotations

import json
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .compose_namespace import require_mutation_safe
from .compose import atomic_write_bytes, validate, verify_atomic_replace_access
from .compose_baseline import _read_private, _write_private
from .compose_drift import fingerprint, read_input
from .docker import compose_args
from .reconciliation import mark_changed, mark_project_inputs_changed, reconcile_operation
from .progress import DISCARD_STAGE_TOTAL, NULL_REPORTER, RECONCILE_STAGE_TOTAL  # noqa: F401 (re-exported)
from .models import Service
from .system import run

HASH_LABEL = "com.docker.compose.config-hash"


def verify_image_unchanged(service):
    """Local inspection only. Never pull or retag to repair a moved tag."""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(service.image_id)):
        raise ValueError("running image identity is unavailable")
    resolved = run(["docker", "image", "inspect", "--format", "{{.Id}}", service.image], timeout=30).strip()
    if resolved != service.image_id:
        raise ValueError("local image reference changed")


def runtime_identity(service):
    return (service.container_id, service.stack, service.compose_service, service.image,
            service.image_id, service.digest, service.working_dir, tuple(service.compose_files),
            (service.labels or {}).get(HASH_LABEL),
            (service.labels or {}).get("com.docker.compose.project"))


def peer_identity(found, service):
    """Observe all other project containers, including dependencies."""
    return tuple(sorted((runtime_identity(item) + (item.state,)
                         for item in found if item.stack == service.stack
                         and item.compose_service != service.compose_service), key=lambda item: item[0]))


def input_layout(inventory):
    return tuple((item.role, item.path, item.present) for item in inventory.files)


class RecoveryBundle:
    """Restricted durable copies of both configurations, managed by retention.

    Active and manual-recovery evidence is protected from automatic cleanup. No material or path
    from this bundle is returned through the browser-facing operation result.
    """
    def __init__(self, root, operation_id, desired, baseline, binding):
        if not re.fullmatch(r"[0-9a-f]{32}", operation_id):
            raise ValueError("invalid recovery identifier")
        parent = Path(root) / "compose-recoveries"
        if parent.is_symlink():
            raise ValueError("unsafe recovery storage")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        self.path = parent / operation_id
        self.path.mkdir(mode=0o700)
        self.manifest = {"version": 1, "binding": binding, "files": []}
        for kind, inventory in (("desired", desired), ("baseline", baseline.inventory)):
            for index, item in enumerate(inventory.files):
                stored = f"{kind}-{index:02d}" if item.present else None
                self.manifest["files"].append({"kind": kind, "role": item.role, "path": item.path,
                                              "present": item.present, "sha256": item.sha256,
                                              "size": item.size, "stored": stored})
                if stored:
                    _write_private(self.path / stored, item.content)
        _write_private(self.path / "manifest.json", json.dumps(self.manifest, sort_keys=True).encode())
        self.manifest_fingerprint = fingerprint(self.manifest)
        for directory in (self.path, parent):
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def verify(self):
        import hashlib
        for directory in (self.path.parent, self.path):
            info = os.lstat(directory)
            if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
                raise ValueError("unsafe recovery storage")
        manifest = json.loads(_read_private(self.path / "manifest.json", 256 * 1024))
        if fingerprint(manifest) != self.manifest_fingerprint:
            raise ValueError("recovery evidence changed")
        for entry in manifest["files"]:
            if entry["stored"]:
                content = _read_private(self.path / entry["stored"], 1024 * 1024)
                if len(content) != entry["size"] or hashlib.sha256(content).hexdigest() != entry["sha256"]:
                    raise ValueError("recovery evidence changed")


@dataclass(frozen=True)
class ReconcileOutcome:
    status: str
    mutation_performed: bool = False
    recovered: bool = False
    manual_recovery_required: bool = False
    service: Service | None = None
    baseline_id: str | None = None
    recovery_path: str | None = None
    command: tuple | None = None  # Bounded proposed argv, dry-run only.


@reconcile_operation
def do_compose_reconcile(service, state, plan, *, operation_id, binding,
                         revalidate, discover_current, verify_configuration,
                         verify_context, capture_baseline, mutation_started=lambda: None, health_timeout=90,
                         reporter=NULL_REPORTER, dry_run=False, guard=None):
    """Execute an already reviewed Apply under the caller's shared lock.

    The first `up` invocation is the only application mutation boundary.
    Refusals before it are BLOCKED, including failed configuration validation.
    After it, attempt at most one recovery, with exact-byte and runtime guards.

    `guard` is an optional reviewed Stage 2 NamespaceApplyGuard. It supplies
    typed consumer admission, v3 evidence, the atomic marker/fence, typed
    invocation outcomes, exact owner checkpoints and atomic publication. With
    a guard the only recovery is the qualified completed-zero desired
    startup/health failure; every other post-marker failure is manual.
    """
    state.assert_completion_unfenced(service)  # before any bundle, source or runtime effect
    command = compose_args(service, project_name=service.stack) + [
        "up", "-d", "--no-deps", "--pull", "never"] + (["--no-build"] if guard else []) + [service.compose_service]
    boundary = False
    bundle = None
    selected_after = None
    observed_after = False
    total = RECONCILE_STAGE_TOTAL
    expected_sources = {item.path: item for item in plan.inventory.files}
    baseline_sources = {item.path: item for item in plan.baseline.inputs}
    peers = peer_identity(discover_current(), service)

    def stage(number, label, running=False):
        reporter.stage(number, total, label, state="running" if running else "completed", service=service.key)

    def mutation_safe(target, model, **options):
        if guard:
            guard.require_mutation_safe(target, model)
        else:
            require_mutation_safe(target, model=model, **options)

    def check_sources():
        for item in expected_sources.values():
            current = read_input(item.role, item.path, optional=not item.present)
            if (current.present, current.sha256, current.size) != (item.present, item.sha256, item.size):
                raise ValueError("configuration source changed")

    def current_selected():
        found = discover_current()
        if peer_identity(found, service) != peers:
            raise ValueError("another project container changed")
        selected = [item for item in found if item.stack == service.stack
                    and item.compose_service == service.compose_service]
        if len(selected) > 1:
            raise ValueError("selected service became ambiguous")
        return selected[0] if selected else None

    def check_recovery_runtime():
        if guard:
            # Exactly the admitted failed desired container before recovery
            # dispatch, then exactly the proved recovered container.
            guard.prove_runtime("recovered" if guard.recovered_proved else "failed_desired")
            return
        current = current_selected()
        if not observed_after or ((runtime_identity(current) if current else None) != selected_after):
            raise ValueError("runtime changed during reconciliation")
        if current and (current.image_id != service.image_id or current.image != service.image
                        or current.working_dir != service.working_dir
                        or current.compose_files != service.compose_files
                        or (current.labels or {}).get("com.docker.compose.project") != service.stack
                        or (current.labels or {}).get(HASH_LABEL) not in {plan.runtime_hash, plan.desired_hash}):
            raise ValueError("runtime cannot be recovered safely")
        if current:
            model = plan.baseline.model if (current.labels or {}).get(HASH_LABEL) == plan.runtime_hash else plan.desired_model
            verify_context(current, model)
        else:
            verify_context(service, plan.baseline.model, absent=True)

    def verify_namespace_runtime(phase):
        # Every poll is a full owner/consumer/kernel/peer checkpoint.
        fresh, proof = guard.prove_runtime(phase)
        deadline = time.monotonic() + max(0, int(health_timeout))
        while proof.health == "starting" and time.monotonic() < deadline:
            reporter.progress("Health is starting", service=service.key)
            time.sleep(min(2, max(.05, deadline - time.monotonic())))
            fresh, proof = guard.prove_runtime(phase)
        if proof.health in {"unhealthy", "starting"}:
            if phase == "apply":
                # The only qualified admission: running, fully proved desired
                # replacement, unhealthy or still starting at UPT's poll deadline.
                guard.admit("desired_unhealthy" if proof.health == "unhealthy" else "desired_start_deadline")
            raise ValueError("replacement startup or health verification failed")
        if proof.health not in {"healthy", "none"}:
            raise ValueError("replacement health is unproved")
        check_sources()
        return fresh

    def verify_runtime(expected_hash, model, *, replacement):
        if guard:
            return verify_namespace_runtime("apply" if replacement else "recovery")
        fresh = current_selected()
        if fresh is None:
            raise ValueError("selected service is missing")
        identity = runtime_identity(fresh)
        if (fresh.image != service.image or fresh.image_id != service.image_id
                or fresh.working_dir != service.working_dir or fresh.compose_files != service.compose_files
                or (fresh.labels or {}).get("com.docker.compose.project") != service.stack
                or (fresh.labels or {}).get(HASH_LABEL) != expected_hash
                or (replacement and fresh.container_id == service.container_id)):
            raise ValueError("replacement identity differs")
        verify_context(fresh, model)
        deadline = time.monotonic() + max(0, int(health_timeout))
        while fresh.health == "starting" and time.monotonic() < deadline:
            reporter.progress("Health is starting", service=service.key)
            time.sleep(min(2, max(.05, deadline - time.monotonic())))
            fresh = current_selected()
            if fresh is None or runtime_identity(fresh) != identity:
                raise ValueError("replacement changed during health verification")
        if fresh.state != "running" or fresh.health in {"unhealthy", "starting"}:
            raise ValueError("replacement startup or health verification failed")
        verify_context(fresh, model)
        check_sources()
        return fresh

    def replace_sources(target):
        # Refuse the entire restore on an observed edit; repeat before every
        # atomic replacement so a later edit is never knowingly overwritten.
        check_sources()
        for path, item in target.items():
            before = expected_sources[path]
            if item.content == before.content:
                continue
            check_sources()
            check_recovery_runtime()
            verify_atomic_replace_access([path])
            atomic_write_bytes(path, item.content, expected=before.content)
            expected_sources[path] = item

    def launch(phase):
        if guard:
            guard.invoke(command, phase=phase, cwd=service.working_dir)
        else:
            run(command, cwd=service.working_dir, timeout=600)

    def manual_outcome():
        # Post-marker uncertainty: no source switch, no recovery invocation.
        guard.discard_unpublished()
        return ReconcileOutcome("failed", None, manual_recovery_required=True,
                                recovery_path=str(bundle.path) if bundle else None)

    try:
        mutation_safe(service, plan.desired_model)
        revalidate()
        stage(1, "Revalidate reviewed configuration")
        if not plan.apply_eligible or input_layout(plan.inventory) != input_layout(plan.baseline.inventory):
            raise ValueError("reconciliation evidence is incomplete")
        check_sources()
        verify_atomic_replace_access([item.path for item in plan.inventory.files if item.present])
        if dry_run:
            return ReconcileOutcome("dry_run", command=tuple(command))  # no workload or source writes
        bundle = guard.write_evidence() if guard else RecoveryBundle(state.root, operation_id, plan.inventory, plan.baseline, binding)
        bundle.verify()
        stage(2, "Protect desired and trusted recovery evidence")
        validate(service, project_name=service.stack)
        verify_configuration(service, plan.inventory, plan.desired_model, plan.desired_hash)
        stage(3, "Validate desired Compose configuration")
        revalidate()
        check_sources()
        if peer_identity(discover_current(), service) != peers:
            raise ValueError("another project container changed")
        verify_image_unchanged(service)
        bundle.verify()
        stage(4, "Recreate selected service without pulling", True)
        mutation_safe(service, plan.desired_model)
        if guard:
            guard.prove_runtime("pre_marker")  # Immediate pre-marker checkpoint.
            verify_configuration(service, plan.inventory, plan.desired_model, plan.desired_hash)
        try:
            mutation_started()
        except BaseException:
            if guard and (guard.marked or state.namespace_apply_marker(operation_id) != "absent"):
                mark_changed(after_change=True)
            raise
        mark_changed()
        mark_project_inputs_changed()  # Apply accepts the current shared project inputs.
        boundary = True
        try:
            launch("apply")
        finally:
            if not guard:
                current = current_selected()
                selected_after = runtime_identity(current) if current else None
                observed_after = True
        stage(4, "Recreate selected service without pulling")
        stage(5, "Verify replacement configuration and image", True)
        fresh = verify_runtime(plan.desired_hash, plan.desired_model, replacement=True)
        stage(5, "Verify replacement configuration and image")
        stage(6, "Verify startup and health")
        verify_configuration(fresh, plan.inventory, plan.desired_model, plan.desired_hash)
        baseline = capture_baseline(fresh, plan.desired_hash, plan.desired_model, plan.inventory)
        verify_runtime(plan.desired_hash, plan.desired_model, replacement=True)
        verify_configuration(fresh, plan.inventory, plan.desired_model, plan.desired_hash)
        stage(7, "Capture new trusted running baseline")
        if guard:
            guard.publish(baseline, recovered=False)
        return ReconcileOutcome("succeeded", True, service=fresh, baseline_id=baseline.record.id,
                                recovery_path=str(bundle.path))
    except Exception:
        if not boundary:
            if guard and guard.marked:
                return manual_outcome()  # Marker committed or unprovable.
            return ReconcileOutcome("blocked", recovery_path=str(bundle.path) if bundle else None)
        if guard and not guard.recovery_admitted():
            return manual_outcome()
        recovered = False
        fresh = None
        recovery_baseline = None
        try:
            if guard:
                guard.begin_recovery()
            bundle.verify()
            check_sources()
            check_recovery_runtime()
            replace_sources(baseline_sources)
            validate(service, project_name=service.stack)
            verify_configuration(service, plan.baseline.inventory, plan.baseline.model, plan.runtime_hash)
            verify_image_unchanged(service)
            bundle.verify()
            check_sources()
            check_recovery_runtime()
            if guard:
                current, _proof = guard.prove_runtime("failed_desired")
                mutation_safe(current, plan.baseline.model)
                guard.mark_recovery_dispatch()
            else:
                current = current_selected()
                require_mutation_safe(current or service, model=plan.baseline.model, allow_absent=True)
            reporter.note("Recovering trusted previous configuration once", service=service.key)
            launch("recovery")
            if not guard:
                current = current_selected()
                selected_after = runtime_identity(current) if current else None
            fresh = verify_runtime(plan.runtime_hash, plan.baseline.model, replacement=False)
            verify_configuration(fresh, plan.baseline.inventory, plan.baseline.model, plan.runtime_hash)
            recovery_baseline = capture_baseline(fresh, plan.runtime_hash, plan.baseline.model, plan.baseline.inventory)
            recovered = True
            if guard:
                guard.recovered_proved = True
        except Exception:
            recovered = False
        if guard and not guard.pending_restore_allowed():
            # Latched uncertainty: no further source writes, retain evidence.
            return manual_outcome()
        # Restore only bytes written by this operation, even if recovery failed.
        # On a concurrent edit, keep every remaining evidence file and stop.
        try:
            bundle.verify()
            replace_sources({item.path: item for item in plan.inventory.files})
            validate(service, project_name=service.stack)
            verify_configuration(service, plan.inventory, plan.desired_model, plan.desired_hash)
            if guard and recovered:
                # Recovered baseline runtime with the reviewed desired bytes pending.
                fresh = verify_runtime(plan.runtime_hash, plan.baseline.model, replacement=False)
                guard.publish(recovery_baseline, recovered=True)
        except Exception:
            recovered = False
        if guard and not recovered:
            return manual_outcome()
        if guard:
            guard.discard_unpublished()
        return ReconcileOutcome("failed", True, recovered=recovered, manual_recovery_required=not recovered,
                                service=fresh if recovered else None,
                                baseline_id=recovery_baseline.record.id if recovery_baseline else None,
                                recovery_path=str(bundle.path) if bundle else None)
