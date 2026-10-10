"""Review-bound namespace checks for the existing normal image-update engine.

No Docker mutation or recovery is implemented here. The server-owned shared
execution-context proof remains the authority for every live observation.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import uuid
from dataclasses import dataclass

from .compose_baseline import logical_key
from .compose_drift import REASONS, build_inventory, fingerprint
from .compose_namespace import (NamespaceOwnerEvidence, NamespaceRefused, mutation_refusal,
                                qualified_image_update_runtime, resolved_hash)
from .compose_reconcile import peer_identity, runtime_identity, verify_image_unchanged
from .docker import compose_args, discover, local_image_provenance
from .operations import PreMutationRefusal, RecoveryRequired, ReviewedTargetChanged
from .system import run


@dataclass(frozen=True)
class NamespaceUpdateReview:
    container_id: str
    consumer_identity: tuple
    owner: NamespaceOwnerEvidence
    context: str
    model_fingerprint: str
    inputs: tuple
    source_hash: str
    peers: tuple
    runtime: tuple


def _inputs(inventory):
    if not inventory.supported:
        raise NamespaceRefused('namespace_owner_unproven')
    return tuple(tuple(item.identity()) for item in inventory.files)


def _snapshot(service, *, review=None):
    # These are the existing shared Stage-1 proof, not an alternative resolver.
    from .webservice import _execution_context_fingerprint, _unmodified_compose_hash
    runtime = qualified_image_update_runtime()
    before = build_inventory(service.compose_files, service.working_dir)
    raw = run(compose_args(service, project_name=service.stack) + ['config', '--format', 'json'],
              cwd=service.working_dir, timeout=30)
    if len(raw) > 16 * 1024 * 1024:
        raise NamespaceRefused('namespace_owner_unproven')
    model = json.loads(raw)
    reason = mutation_refusal(service, model=model, _image_update=True)
    if reason:
        raise NamespaceRefused(reason)
    values = []
    context = _execution_context_fingerprint(
        service, model, namespace_evidence=values,
        identity_container_id=review.container_id if review else None,
        namespace_consumer_started_at=review.owner.consumer_started_at if review else None)
    if len(values) != 1 or values[0].netns_equal is not True:
        raise NamespaceRefused('namespace_stale')
    oracle = _unmodified_compose_hash(service)
    resolved = resolved_hash(model['services'][service.compose_service], values[0].container_id, oracle)
    after = build_inventory(service.compose_files, service.working_dir, model=model)
    if _inputs(before) != _inputs(after):
        raise NamespaceRefused('namespace_owner_changed')
    found = discover(all_containers=True)
    matches = [s for s in found if s.container_id == service.container_id]
    if len(matches) != 1:
        raise NamespaceRefused('namespace_owner_changed')
    live = matches[0]
    # Owner health is bound by the owner evidence; unrelated peer health is not.
    peers = peer_identity(found, service) + tuple(sorted(
        (s.container_id, s.started_at, s.network_mode)
        for s in found if s.stack == service.stack and s.compose_service != service.compose_service))
    return model, NamespaceUpdateReview(service.container_id, runtime_identity(live) +
        (live.state, live.health, live.started_at, live.network_mode), values[0], context,
        fingerprint(model), _inputs(after), oracle, peers, runtime), resolved


def review_namespace_update(service):
    try:
        model, review, desired = _snapshot(service)
        if (model['services'][service.compose_service].get('image') != service.image
                or (service.labels or {}).get('com.docker.compose.config-hash') != desired):
            raise NamespaceRefused('namespace_owner_unproven')
        verify_image_unchanged(service)
        return review
    except NamespaceRefused as exc:
        raise PreMutationRefusal(REASONS[exc.reason], exc.reason) from None
    except PreMutationRefusal:
        raise
    except Exception:
        raise PreMutationRefusal(REASONS['namespace_owner_unproven'], 'namespace_owner_unproven') from None


class NamespaceImageUpdate:
    def __init__(self, service, state, *, review=None, audit_context=None):
        self.service, self.state = service, state
        self.review = review or review_namespace_update(service)
        self.model = None
        self.inputs = self.review.inputs
        self.source_hash = self.review.source_hash
        self.target_image = service.image
        self.target_digest = self.target_image_id = None
        self.replacement_id = None
        self.replacement_start = None
        self.replacement_restarts = None
        self.marked = False
        self.operation_id = (audit_context or {}).get('operation_id')
        self.owns_operation = not self.operation_id
        self.check()

    def check(self, fresh=None):
        from .compose_namespace import observe
        try:
            selected = fresh or self.service
            model, current, desired = _snapshot(selected, review=self.review)
            owner = current.owner.fingerprint_values()
            # Start time of the *consumer* necessarily changes on replacement.
            # Every owner field and the actual live namespace proof remain exact.
            owner['consumer_started_at'] = self.review.owner.consumer_started_at
            if (owner != self.review.owner.fingerprint_values() or current.context != self.review.context
                    or current.peers != self.review.peers or current.runtime != self.review.runtime
                    or current.inputs != self.inputs):
                raise NamespaceRefused('namespace_owner_changed')
            expected = self.model or model
            if self.model is None and fingerprint(model) != self.review.model_fingerprint:
                raise NamespaceRefused('namespace_owner_changed')
            if model != expected or current.source_hash != self.source_hash:
                raise NamespaceRefused('namespace_owner_changed')
            if fresh is None:
                if current.consumer_identity != self.review.consumer_identity:
                    raise NamespaceRefused('namespace_owner_changed')
            else:
                if (fresh.container_id == self.review.container_id or fresh.state != 'running'
                        or fresh.image != self.target_image or fresh.image_id != self.target_image_id
                        or fresh.digest != self.target_digest
                        or (fresh.labels or {}).get('com.docker.compose.config-hash') != desired):
                    raise NamespaceRefused('namespace_owner_changed')
                observed = observe(fresh)
                identity = (fresh.container_id, fresh.started_at, observed['restart_count'])
                if self.replacement_id is not None and identity != (
                        self.replacement_id, self.replacement_start, self.replacement_restarts):
                    raise NamespaceRefused('namespace_owner_changed')
                self.replacement_id, self.replacement_start, self.replacement_restarts = identity
                self.target('resolved', fresh.image)
            if self.model is None:
                self.model = copy.deepcopy(model)
            return desired
        except Exception as exc:
            if self.marked:
                raise RecoveryRequired('Namespace image update cannot be proved; manual recovery is required') from None
            reason = getattr(exc, 'reason', 'namespace_owner_unproven')
            raise PreMutationRefusal(REASONS.get(reason, REASONS['namespace_owner_unproven']), reason) from None

    def target(self, stage, observed):
        if stage == 'registry':
            digest = (observed or {}).get('digest')
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', str(digest)):
                raise ReviewedTargetChanged('The exact namespace consumer image target is unproved')
            if self.target_digest is not None and digest != self.target_digest:
                raise ReviewedTargetChanged('The namespace consumer image target changed')
            self.target_digest = digest
            return
        raw = run(['docker', 'image', 'inspect', '--format',
                   '{"Id":{{json .Id}},"RepoDigests":{{json .RepoDigests}},'
                   '"Descriptor":{{json .Descriptor}},"Identity":{{json .Identity}}}', observed], timeout=30)
        if len(raw) > 65536:
            raise ReviewedTargetChanged('The exact image target is unproved')
        image = json.loads(raw)
        provenance = local_image_provenance(image, image.get('Id'), observed)
        if (provenance.digest != self.target_digest or not provenance.digest
                or (self.target_image_id is not None and image.get('Id') != self.target_image_id)):
            raise ReviewedTargetChanged('The exact image target changed or is unproved')
        self.target_image_id = image['Id']

    def accept_pin(self, path, old, new, target):
        """Admit exactly UPT's own digest-pin edit as the new expected source/model."""
        from .webservice import _unmodified_compose_hash
        inventory = build_inventory(self.service.compose_files, self.service.working_dir)
        identities = list(self.inputs)
        matches = [i for i, item in enumerate(identities) if item[1] == str(path)]
        if len(matches) != 1 or identities[matches[0]][3] != hashlib.sha256(old.encode()).hexdigest():
            raise PreMutationRefusal(REASONS['namespace_owner_changed'], 'namespace_owner_changed')
        item = list(identities[matches[0]])
        item[3], item[4] = hashlib.sha256(new.encode()).hexdigest(), len(new.encode())
        identities[matches[0]] = tuple(item)
        if tuple(identities) != _inputs(inventory):
            raise PreMutationRefusal(REASONS['namespace_owner_changed'], 'namespace_owner_changed')
        # Only the selected service's image may differ from the reviewed model;
        # check() then requires the live model to equal this exactly.
        self.model['services'][self.service.compose_service]['image'] = target
        self.inputs = tuple(identities)
        self.target_image = target
        self.source_hash = _unmodified_compose_hash(self.service)
        self.check()

    def before_exec(self):
        """Final pre-exec proof, then the durable write-ahead mutation marker.

        The proof deliberately precedes the marker so a changed owner observed
        here is still a factual pre-mutation block (I2). The caller launches
        Compose immediately after this returns; anything later is post-marker.
        """
        self.check()
        self.target('resolved', self.target_image)
        if self.owns_operation:
            self.operation_id = uuid.uuid4().hex
            self.state.create_operation(self.operation_id, kind='update',
                service_key='container/' + self.service.container_id, service=self.service.name,
                stack=self.service.stack, requested_by='cli', summary={'namespace_update': True})
        try:
            if self.owns_operation:
                self.state.set_operation_running(self.operation_id, 'Namespace image update')
            key = logical_key(self.service.stack, self.service.compose_service,
                              self.service.working_dir, self.service.compose_files)
            self.state.mark_namespace_update(self.operation_id, key,
                                             fingerprint(self.review.owner.fingerprint_values()),
                                             self.service.image_id)
        except Exception:
            # The marker transaction did not commit, so Compose was never launched.
            if self.owns_operation:
                self.state.finish_operation(self.operation_id, 'blocked', message='Namespace image update not started.')
            raise PreMutationRefusal(REASONS['namespace_owner_unproven'], 'namespace_owner_unproven') from None
        self.marked = True

    def failure(self):
        if self.marked:
            self.state.finish_operation(self.operation_id, 'failed',
                message='Namespace image update failed; manual recovery is required.',
                result={'manual_recovery_required': True, 'mutation_performed': True,
                        'recovery_attempted': False})
