"""Byte-proven scalar restoration, with no Docker workload mutation path."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken, DirectiveToken, TagToken

from .compose import atomic_write_bytes, validate, verify_atomic_replace_access
from .compose_drift import InputFile, InputReadError, Inventory, fingerprint, read_input
from .compose_reconcile import (RecoveryBundle, ReconcileOutcome, input_layout,
                                runtime_identity, verify_image_unchanged)
from .reconciliation import mark_changed, mark_project_inputs_changed, reconcile_operation
from .progress import DISCARD_STAGE_TOTAL, NULL_REPORTER


# Fixed server-owned diagnostics, never source-derived exception text.
DISCARD_REASONS = {
    "no_trusted_baseline": "Discard requires a valid trusted baseline for this exact running container.",
    "source_layout_unsupported": "UPT cannot prove the source input layout required for Discard.",
    "source_layout_changed": "The source input layout or structure differs from the trusted baseline.",
    "multiple_compose_files": "Discard does not support multiple Compose files or overlays.",
    "shared_input_changed": "A shared configuration input changed or cannot be isolated for Discard.",
    "unsupported_source_construct": "The source uses YAML or interpolation constructs unsupported by Discard.",
    "source_not_isolated": "Source bytes outside the reviewed scalar value changes cannot be proved unchanged.",
    "project_changes": "Project or unrelated-service changes prevent isolated Discard.",
    "image_identity_changed": "The desired or local image identity differs from the unchanged running image.",
    "execution_context_unproven": "UPT cannot prove the trusted project and execution context required for Discard.",
    "source_not_writable": "UPT cannot safely replace the source required for Discard.",
    "service_ineligible": "The current service identity or state is not eligible for Discard.",
    "no_pending_changes": "UPT could not prove a pending selected-service change to discard.",
}


class DiscardRefused(ValueError):
    def __init__(self, reason):
        self.reason = reason if isinstance(reason, str) and reason in DISCARD_REASONS else "source_layout_unsupported"
        self.public_message = DISCARD_REASONS[self.reason]
        super().__init__(self.public_message)


def discard_gate_reasons(reasons):
    """Translate the unchanged common safety gates; do not inherit Apply state."""
    mapping = {
        "no_trusted_baseline": "no_trusted_baseline",
        "inventory_unsupported": "source_layout_unsupported",
        "input_inventory_changed": "source_layout_changed",
        "project_changes": "project_changes",
        "image_change": "image_identity_changed",
        "local_image_changed": "image_identity_changed",
        "recovery_source_not_writable": "source_not_writable",
        "service_change_unproven": "no_pending_changes",
        "project_unproven": "execution_context_unproven",
        "project_identity": "execution_context_unproven",
        "project_identity_unavailable": "execution_context_unproven",
        "network_unproven": "execution_context_unproven",
        "named_volume_unproven": "execution_context_unproven",
        "service_resource_unproven": "execution_context_unproven",
        "runtime_mounts_unproven": "execution_context_unproven",
    }
    return tuple(dict.fromkeys(mapping.get(reason, "service_ineligible") for reason in reasons))


@dataclass(frozen=True)
class SourceMutationPlan:
    pending: InputFile
    restored: InputFile
    ranges: tuple  # current byte start/end, baseline byte start/end
    fingerprint: str


def _tree(content):
    text = content.decode("utf-8")
    if "$" in text:
        raise DiscardRefused("unsupported_source_construct")
    for token in yaml.scan(text):
        if isinstance(token, (AliasToken, AnchorToken, DirectiveToken, TagToken)):
            raise DiscardRefused("unsupported_source_construct")
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    # PyYAML marks count Unicode characters, not bytes.
    offsets = [0]
    for char in text:
        offsets.append(offsets[-1] + len(char.encode("utf-8")))
    return node, offsets


def prove_source_isolation(inventory, baseline_inventory, service_name, *, reviewed_fields):
    """Restore changed scalar lexemes only; every other byte must already match.

    This is intentionally stricter than semantic equality. No serializer, line
    matching, comment ownership or effective-model inference authorises a write.
    Structural changes, changed keys, flow collections and block/multiline
    scalars are refused. Unchanged project .env is unused (no interpolation);
    service env_file inputs and multiple Compose sources are refused outright.
    """
    compose = [item for item in inventory.files if item.role == "compose"]
    if len(compose) > 1:
        raise DiscardRefused("multiple_compose_files")
    if not inventory.supported or not baseline_inventory.supported:
        raise DiscardRefused("unsupported_source_construct")
    if input_layout(inventory) != input_layout(baseline_inventory):
        raise DiscardRefused("source_layout_changed")
    if len(compose) != 1:
        raise DiscardRefused("source_layout_unsupported")
    if any(item.role not in {"compose", "project_env"} for item in inventory.files):
        raise DiscardRefused("shared_input_changed")
    old_inputs = baseline_inventory.by_path()
    for item in inventory.files:
        if item.role != "compose" and item.identity() != old_inputs[item.path].identity():
            raise DiscardRefused("shared_input_changed")
    pending = compose[0]
    original = old_inputs[pending.path]
    try:
        current, current_offsets = _tree(pending.content)
        trusted, trusted_offsets = _tree(original.content)
    except (yaml.YAMLError, UnicodeDecodeError, RecursionError):
        raise DiscardRefused("unsupported_source_construct") from None
    ranges = []

    def span(node, offsets):
        return offsets[node.start_mark.index], offsets[node.end_mark.index]

    def walk(before, after, path=()):
        if type(before) is not type(after) or before.tag != after.tag:
            raise DiscardRefused("source_layout_changed")
        if isinstance(before, ScalarNode):
            if (before.style in {"|", ">"} or after.style in {"|", ">"}
                    or before.start_mark.line != before.end_mark.line
                    or after.start_mark.line != after.end_mark.line):
                raise DiscardRefused("unsupported_source_construct")
            a, b = span(before, trusted_offsets)
            c, d = span(after, current_offsets)
            if original.content[a:b] != pending.content[c:d]:
                if len(path) < 3 or path[:2] != ("services", service_name) or path[2] not in reviewed_fields or before.value == after.value:
                    raise DiscardRefused("source_not_isolated")
                ranges.append((c, d, a, b))
        elif isinstance(before, MappingNode):
            if before.flow_style or after.flow_style:
                raise DiscardRefused("unsupported_source_construct")
            if len(before.value) != len(after.value):
                raise DiscardRefused("source_layout_changed")
            keys = set()
            for (old_key, old_value), (new_key, new_value) in zip(before.value, after.value):
                if (not isinstance(old_key, ScalarNode) or not isinstance(new_key, ScalarNode)
                        or old_key.tag != "tag:yaml.org,2002:str" or new_key.tag != old_key.tag
                        or old_key.value != new_key.value or old_key.value in keys
                        or old_key.value in {"<<", "include", "extends", "env_file"}):
                    raise DiscardRefused("unsupported_source_construct")
                keys.add(old_key.value)
                a, b = span(old_key, trusted_offsets)
                c, d = span(new_key, current_offsets)
                if original.content[a:b] != pending.content[c:d]:
                    raise DiscardRefused("source_layout_changed")
                walk(old_value, new_value, path + (old_key.value,))
        elif isinstance(before, SequenceNode):
            if before.flow_style or after.flow_style:
                raise DiscardRefused("unsupported_source_construct")
            if len(before.value) != len(after.value):
                raise DiscardRefused("source_layout_changed")
            for index, (old, new) in enumerate(zip(before.value, after.value)):
                walk(old, new, path + (index,))
        else:
            raise DiscardRefused("unsupported_source_construct")

    if not isinstance(current, MappingNode) or not isinstance(trusted, MappingNode):
        raise DiscardRefused("unsupported_source_construct")
    for root in (current, trusted):
        services = [v for k, v in root.value if isinstance(k, ScalarNode) and k.value == "services"]
        if len(services) != 1 or not isinstance(services[0], MappingNode):
            raise DiscardRefused("unsupported_source_construct")
        selected = [v for k, v in services[0].value if isinstance(k, ScalarNode) and k.value == service_name]
        if len(selected) != 1 or not isinstance(selected[0], MappingNode):
            raise DiscardRefused("unsupported_source_construct")
    walk(trusted, current)
    if not ranges:
        raise DiscardRefused("source_not_isolated")
    cursor = trusted_cursor = 0
    result = []
    for start, end, old_start, old_end in ranges:
        # Includes all comments, whitespace, keys and project/peer material.
        if pending.content[cursor:start] != original.content[trusted_cursor:old_start]:
            raise DiscardRefused("source_not_isolated")
        result.extend((pending.content[cursor:start], original.content[old_start:old_end]))
        cursor, trusted_cursor = end, old_end
    if pending.content[cursor:] != original.content[trusted_cursor:]:
        raise DiscardRefused("source_not_isolated")
    result.append(pending.content[cursor:])
    output = b"".join(result)
    if output != original.content:
        raise DiscardRefused("source_not_isolated")
    restored = InputFile(pending.role, pending.path, True, hashlib.sha256(output).hexdigest(), len(output), output)
    proof = fingerprint({"pending": pending.identity(), "restored": restored.identity(), "ranges": ranges})
    return SourceMutationPlan(pending, restored, tuple(ranges), proof)


def classify_interrupted_discard(state_root, operation_id, summary, *, queued=False):
    """Read-only crash classification; markers never override exact bytes.

    Only the validated, operation-bound private bundle supplies source paths or
    bytes. No restart-time restoration is attempted. Missing/unreadable/malformed
    evidence for a running operation, or any third state, remains protected.
    The baseline Compose copy is the exact scalar-plan output: the proof required
    every byte outside the reviewed ranges to match it before any write.
    """
    from pathlib import Path
    from .compose_recovery_retention import checked_bundle

    path = Path(state_root) / "compose-recoveries" / operation_id
    try:
        with checked_bundle(state_root, path) as bundle:
            if (bundle["binding"]["baseline_id"] != summary.get("baseline_id")
                    or bundle["binding"]["evidence"] != summary.get("discard_evidence")):
                return "unknown"
            pending, output = bundle["inputs"]["desired"], bundle["inputs"]["baseline"]
            changed = [before for before, after in zip(pending, output)
                       if before.identity() != after.identity() or before.content != after.content]
            if (len(changed) != 1 or changed[0].role != "compose"
                    or sum(item.role == "compose" for item in pending) != 1
                    or any(item.role not in {"compose", "project_env"} for item in pending)):
                return "unknown"

            def live_inputs():
                items = []
                for item in pending:
                    source = Path(item.path)
                    if source.parent.resolve(strict=True) != source.parent:
                        raise ValueError("source layout changed")
                    items.append(read_input(item.role, item.path, optional=not item.present))
                return items

            def equal(left, right):
                return all(a.identity() == b.identity() and a.content == b.content for a, b in zip(left, right))

            first = live_inputs()
            if not equal(first, live_inputs()):
                return "unknown"
            if equal(first, pending):
                return "pending"
            if equal(first, output):
                return "discarded"
    except FileNotFoundError:
        # A queued worker never began its core path. A running operation without
        # evidence cannot establish a source outcome, regardless of its marker.
        if queued and not summary.get("mutation_started") and not path.exists() and not path.is_symlink():
            return "not_started"
    except (InputReadError, OSError, ValueError, TypeError, KeyError, RecursionError):
        pass
    return "unknown"


def unchanged_runtime(found, selected):
    """Bind selected and peers, including state and health, to this review."""
    return tuple(sorted((runtime_identity(item) + (item.state, item.health)
                         for item in found if item.stack == selected.stack), key=lambda row: row[0]))


@reconcile_operation
def do_compose_discard(service, state, plan, *, operation_id, binding, revalidate,
                       discover_current, verify_configuration, verify_context,
                       mutation_started=lambda: None, reporter=NULL_REPORTER, dry_run=False):
    """Caller holds the shared mutation lock; one source write and one recovery."""
    boundary = False
    bundle = None
    mutation = plan.discard_plan
    pending_inventory = plan.inventory
    restored_inventory = Inventory(tuple(mutation.restored if item.path == mutation.pending.path else item
                                         for item in pending_inventory.files), ())
    runtime = unchanged_runtime(discover_current(), service)

    def sources(expected):
        for item in expected.files:
            if read_input(item.role, item.path, optional=not item.present).identity() != item.identity():
                raise ValueError("source changed")

    def containers():
        found = discover_current()
        if unchanged_runtime(found, service) != runtime:
            raise ValueError("running workload changed")
        exact = [item for item in found if item.container_id == service.container_id]
        if len(exact) != 1 or runtime_identity(exact[0]) != runtime_identity(service):
            raise ValueError("selected runtime changed")
        verify_image_unchanged(service)
        verify_context(exact[0], plan.baseline.model)

    def crossed_boundary():
        nonlocal boundary
        boundary = True
        mark_changed(after_change=True)
        mark_project_inputs_changed()

    def stage(number, message, state="completed"):
        reporter.stage(number, DISCARD_STAGE_TOTAL, message, service=service.key, state=state)

    try:
        revalidate()
        if not plan.discard_eligible or prove_source_isolation(
                plan.inventory, plan.baseline.inventory, service.compose_service,
                reviewed_fields={entry["field"] for entry in plan.diff.service}) != mutation:
            raise ValueError("source isolation changed")
        sources(pending_inventory)
        containers()
        verify_atomic_replace_access([mutation.pending.path])
        if dry_run:
            return ReconcileOutcome("dry_run")
        stage(1, "Revalidate reviewed source isolation")
        bundle = RecoveryBundle(state.root, operation_id, pending_inventory, plan.baseline, binding)
        bundle.verify()
        stage(2, "Protect pending source recovery copy")
        validate(service, project_name=service.stack)
        verify_configuration(service, pending_inventory, plan.desired_model, plan.desired_hash)
        revalidate()
        sources(pending_inventory)
        containers()
        bundle.verify()
        verify_atomic_replace_access([mutation.pending.path])
        stage(3, "Discarding configuration changes", "running")
        mutation_started()
        atomic_write_bytes(mutation.pending.path, mutation.restored.content, expected=mutation.pending.content,
                           on_replaced=crossed_boundary)
        stage(3, "Discarding configuration changes")
        sources(restored_inventory)
        validate(service, project_name=service.stack)
        verify_configuration(service, restored_inventory, plan.baseline.model, plan.runtime_hash)
        containers()
        sources(restored_inventory)
        stage(4, "Verify trusted source and unchanged running workload")
        return ReconcileOutcome("succeeded", True, service=service, recovery_path=str(bundle.path))
    except Exception:
        if not boundary:
            return ReconcileOutcome("blocked", recovery_path=str(bundle.path) if bundle else None)
        recovered = False
        try:
            bundle.verify()
            containers()
            # Every input must be exactly this operation's output. Third states
            # are never overwritten, even when their effective model matches.
            sources(restored_inventory)
            verify_atomic_replace_access([mutation.pending.path])
            atomic_write_bytes(mutation.pending.path, mutation.pending.content, expected=mutation.restored.content)
            sources(pending_inventory)
            validate(service, project_name=service.stack)
            verify_configuration(service, pending_inventory, plan.desired_model, plan.desired_hash)
            containers()
            sources(pending_inventory)
            recovered = True
        except Exception:
            pass
        return ReconcileOutcome("failed", True, recovered=recovered, manual_recovery_required=not recovered,
                                service=service if recovered else None, recovery_path=str(bundle.path))
