"""Namespace Stage 2: reviewed configuration Apply for a trusted namespace consumer.

Core types only: the immutable review, the checkpoint guard and the private v3
recovery evidence. compose_reconcile.do_compose_reconcile remains the single
Apply/recovery state machine; adapters own update.lock, intents and projections.

Authority comes only from the server-held review. After the durable mutation
marker every uncertainty latches manual recovery: the guard never refreshes the
reviewed owner, never admits a state outside the qualified recovery path and
never retries a workload command.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import asdict, dataclass
from typing import Callable

import yaml

from .compose_baseline import BaselineStore, _write_private, logical_key
from .compose_drift import (build_inventory, fingerprint, hash_excluded_fields_present,
                            observed_service_model, project_outside_service)
from .compose_namespace import (FORBIDDEN, HASH_LABEL, NamespaceApplyAuthority, NamespaceConsumerProof,
                                NamespaceOwnerProof, NamespaceRefused, _inspect, _relationship,
                                canonical_relationship, mutation_refusal, namespace_owner, prove_consumer,
                                prove_owner, qualified_apply_runtime, resolved_hash)
from .namespace_change_catalog import refuse_unqualified_changes
from .system import invoke

PROOF_LIMIT = 256 * 1024
MANIFEST_LIMIT = 256 * 1024
EVIDENCE_VERSION = 3
EVIDENCE_ACTION = 'namespace_apply'
BINDING_KEYS = frozenset({'operation_id', 'logical_key', 'requester', 'baseline_id', 'baseline_fingerprint',
                          'review', 'owner'})
PROOF_KEYS = frozenset({'version', 'logical_key', 'owner', 'consumer', 'condition', 'relationship', 'baseline',
                        'desired', 'fingerprints', 'hashes', 'peers', 'runtime', 'review'})
# Initial automatic recovery admission: completed-zero Apply whose uniquely
# proved, running desired replacement fails bounded startup/health verification.
QUALIFIED_FAILURE_CLASSES = frozenset({'desired_unhealthy', 'desired_start_deadline'})
# Completed non-zero invocation classes that may recover automatically. EMPTY:
# every normally completed non-zero outcome is manual-only (Layer A, 2026-10-05).
COMPLETED_NONZERO_RECOVERY_ALLOWLIST = frozenset()


_HEX64 = re.compile(r'[0-9a-f]{64}')
_HEX32 = re.compile(r'[0-9a-f]{32}')
_IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
_STARTED = re.compile(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,9})?(Z|[+-]\d\d:\d\d)')
_NETNS = re.compile(r'net:\[\d{1,20}\]')
_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
_STATES = frozenset({'created', 'running', 'restarting', 'exited', 'paused', 'dead', 'removing'})
_HEALTH = frozenset({'none', 'starting', 'healthy', 'unhealthy'})
_MAX_PEERS = 64
_INT_LIMIT = 2**31


# Frozen schema of retained evidence version=3 / action=namespace_apply. These
# constants define what v3 means; runtime proof dataclasses do not. A runtime
# field change must be mapped compatibly or ship a new, reviewed evidence version.
V3_OWNER_KEYS = ('service', 'container_id', 'image', 'image_id', 'runtime_hash', 'project', 'working_dir',
                 'compose_files', 'network_mode', 'state', 'health', 'has_healthcheck', 'started_at',
                 'restart_count', 'context', 'pid', 'netns')
V3_CONSUMER_KEYS = ('container_id', 'image', 'image_id', 'runtime_hash', 'state', 'health', 'started_at',
                    'restart_count', 'pid', 'network_mode')
V3_BASELINE_KEYS = ('id', 'fingerprint', 'manifest', 'inventory', 'service')
V3_DESIRED_KEYS = ('inventory', 'model', 'service')
V3_FINGERPRINT_KEYS = ('baseline_selected', 'owner_model', 'project_observed', 'diff')
V3_HASH_KEYS = ('baseline_oracle', 'desired_oracle', 'baseline_resolved', 'desired_resolved')


class ProofSchemaError(ValueError):
    """The v3 proof is not exactly the typed structure the producer writes."""


def _need(condition):
    if not condition:
        raise ProofSchemaError('malformed namespace Apply proof')


def _fields(value, names):
    _need(isinstance(value, dict) and set(value) == set(names))
    return value


def _string(value, limit=4096, pattern=None, optional=False):
    if value is None and optional:
        return
    _need(isinstance(value, str) and 0 < len(value) <= limit and '\x00' not in value)
    _need(pattern is None or pattern.fullmatch(value) is not None)


def _in(value, domain):
    _need(isinstance(value, str) and value in domain)


def _natural(value, minimum=0):
    _need(type(value) is int and minimum <= value < _INT_LIMIT)


def _paths(value):
    _need(isinstance(value, list) and 1 <= len(value) <= 32)
    for item in value:
        _string(item)


def validate_proof(proof):
    """Closed recursive schema for NamespaceApplyReview.facts(), by explicit field.

    The frozen V3_* constants are the schema authority; runtime dataclasses
    neither define nor are populated from untrusted evidence. Unknown, missing,
    extra or mistyped structure at any depth raises ProofSchemaError without
    interpreting it.
    """
    _fields(proof, PROOF_KEYS)
    _need(type(proof['version']) is int and proof['version'] == EVIDENCE_VERSION)
    for name in ('logical_key', 'review'):
        _string(proof[name], 64, _HEX64)
    owner = _fields(proof['owner'], V3_OWNER_KEYS)
    _string(owner['service'], 64, _NAME)
    _string(owner['container_id'], 64, _HEX64)
    _string(owner['image'], 512)
    _string(owner['image_id'], 71, _IMAGE_ID)
    _string(owner['runtime_hash'], 64, _HEX64)
    _string(owner['project'], 128)
    _string(owner['working_dir'])
    _paths(owner['compose_files'])
    _string(owner['network_mode'], 512)
    _in(owner['state'], _STATES)
    _in(owner['health'], _HEALTH)
    _need(type(owner['has_healthcheck']) is bool)
    _string(owner['started_at'], 40, _STARTED)
    _natural(owner['restart_count'])
    _string(owner['context'], 64, _HEX64)
    _natural(owner['pid'], 1)
    _string(owner['netns'], 32, _NETNS)
    consumer = _fields(proof['consumer'], V3_CONSUMER_KEYS)
    _string(consumer['container_id'], 64, _HEX64)
    _string(consumer['image'], 512)
    _string(consumer['image_id'], 71, _IMAGE_ID)
    _string(consumer['runtime_hash'], 64, _HEX64)
    _in(consumer['state'], _STATES)
    _in(consumer['health'], _HEALTH)
    _string(consumer['started_at'], 40, _STARTED)
    _natural(consumer['restart_count'])
    _natural(consumer['pid'], 1)
    _string(consumer['network_mode'], 512)
    _in(proof['condition'], {'service_started', 'service_healthy'})
    relationship = proof['relationship']
    _need(isinstance(relationship, list) and len(relationship) == 2)
    _need(relationship[0] == 'service:' + owner['service'])
    _string(relationship[1], 512)
    baseline = _fields(proof['baseline'], V3_BASELINE_KEYS)
    _string(baseline['id'], 32, _HEX32)
    for name in ('fingerprint', 'manifest', 'inventory', 'service'):
        _string(baseline[name], 64, _HEX64)
    desired = _fields(proof['desired'], V3_DESIRED_KEYS)
    for name in desired:
        _string(desired[name], 64, _HEX64)
    for group, names in (('fingerprints', V3_FINGERPRINT_KEYS), ('hashes', V3_HASH_KEYS)):
        entries = _fields(proof[group], names)
        for name in names:
            _string(entries[name], 64, _HEX64)
    peers = proof['peers']
    _need(isinstance(peers, list) and len(peers) <= _MAX_PEERS)
    for peer in peers:
        # runtime_identity (10 fields) + item.state, raw state, health, StartedAt, RestartCount.
        _need(isinstance(peer, list) and len(peer) == 15)
        _string(peer[0], 64, _HEX64)
        _string(peer[1], 128)
        _string(peer[2], 64, _NAME)
        _string(peer[3], 512)
        _string(peer[4], 71, _IMAGE_ID)
        _string(peer[5], 128, optional=True)
        _string(peer[6])
        _paths(peer[7])
        _string(peer[8], 64, _HEX64, optional=True)
        _string(peer[9], 128, optional=True)
        _in(peer[10], _STATES)
        _in(peer[11], _STATES)
        _in(peer[12], _HEALTH)
        _string(peer[13], 40, _STARTED)
        _natural(peer[14])
    runtime = proof['runtime']
    _need(isinstance(runtime, list) and len(runtime) == 8)
    for item in runtime:
        _string(item, 128)
    _string(runtime[7], 64, _HEX64)


class NamespaceApplyManual(RuntimeError):
    """Post-marker uncertainty. Latched: no source switch, recovery or trust."""

    def __init__(self, reason='namespace_owner_changed'):
        self.reason = reason
        super().__init__('Namespace Apply cannot be proved; manual recovery is required.')


@dataclass(frozen=True)
class NamespaceApplyDeps:
    """Server-owned observers supplied by the adapter; no web import here."""
    discover: Callable
    model_reader: Callable
    unmodified_hash: Callable
    evaluate_retained: Callable
    context_reader: Callable
    mounts_reader: Callable
    image_verifier: Callable


@dataclass(frozen=True)
class NamespaceApplyReview:
    logical_key: str
    consumer: NamespaceConsumerProof
    owner: NamespaceOwnerProof
    condition: str
    relationship: tuple
    baseline_id: str
    baseline_fingerprint: str
    baseline_manifest: str
    baseline_inventory: str
    baseline_service: str
    desired_inventory: str
    desired_model: str
    desired_service: str
    baseline_selected: str
    owner_model: str
    project_observed: str
    diff: str
    baseline_oracle: str
    desired_oracle: str
    baseline_resolved: str
    desired_resolved: str
    peers: tuple
    runtime: tuple

    @property
    def fingerprint(self):
        return fingerprint(asdict(self))

    @property
    def owner_fingerprint(self):
        return fingerprint(asdict(self.owner))

    @property
    def authority(self):
        return NamespaceApplyAuthority(self.logical_key, self.owner.container_id, self.relationship)

    def facts(self):
        """Private bounded proof: typed facts and expected identities only."""
        return {'version': EVIDENCE_VERSION, 'logical_key': self.logical_key, 'owner': asdict(self.owner),
                'consumer': asdict(self.consumer), 'condition': self.condition,
                'relationship': list(self.relationship),
                'baseline': {'id': self.baseline_id, 'fingerprint': self.baseline_fingerprint,
                             'manifest': self.baseline_manifest, 'inventory': self.baseline_inventory,
                             'service': self.baseline_service},
                'desired': {'inventory': self.desired_inventory, 'model': self.desired_model,
                            'service': self.desired_service},
                'fingerprints': {'baseline_selected': self.baseline_selected, 'owner_model': self.owner_model,
                                 'project_observed': self.project_observed, 'diff': self.diff},
                'hashes': {'baseline_oracle': self.baseline_oracle, 'desired_oracle': self.desired_oracle,
                           'baseline_resolved': self.baseline_resolved, 'desired_resolved': self.desired_resolved},
                'peers': self.peers, 'runtime': list(self.runtime), 'review': self.fingerprint}


def refuse_consumer_env_file(inventory, compose_service, selected_models=()):
    """Initial Stage 2 refuses any selected-consumer env_file, wherever declared.

    Normal resolved JSON expands env_file into environment, so the raw source
    of every ordered Compose file is inspected too (YAML merge keys resolved by
    the safe loader). In-file `extends` could inherit one invisibly: refused.
    """
    if any(isinstance(selected, dict) and 'env_file' in selected for selected in selected_models):
        raise NamespaceRefused('namespace_env_file_unsupported')
    for item in inventory.files:
        if item.role != 'compose' or not item.present:
            continue
        try:
            document = yaml.safe_load(item.content.decode('utf-8'))
        except (yaml.YAMLError, UnicodeDecodeError):
            raise NamespaceRefused('namespace_env_file_unsupported') from None
        services = document.get('services') if isinstance(document, dict) else None
        if services is None:
            continue
        if not isinstance(services, dict):
            raise NamespaceRefused('namespace_env_file_unsupported')
        node = services.get(compose_service)
        if node is not None and (not isinstance(node, dict) or 'env_file' in node or 'extends' in node):
            raise NamespaceRefused('namespace_env_file_unsupported')


def _validate_desired_binds(selected):
    """Desired bind structure/access; runtime mounts are proved after Apply."""
    for mount in selected.get('volumes') or []:
        if (not isinstance(mount, dict) or mount.get('type') != 'bind'
                or not isinstance(mount.get('source'), str) or not os.path.isabs(mount['source'])
                or not isinstance(mount.get('target'), str) or not mount['target'].startswith('/')):
            raise NamespaceRefused('named_volume_unproven')
        try:
            os.stat(mount['source'])  # Never let Compose create a host path.
        except OSError:
            raise NamespaceRefused('runtime_mounts_unproven') from None


def peer_observations(found, service, owner_name):
    """Other project containers: identity, state/health, StartedAt and RestartCount."""
    from .compose_reconcile import runtime_identity
    peers = []
    for item in found:
        if item.stack == service.stack and item.compose_service not in {service.compose_service, owner_name}:
            raw = _inspect(item.container_id)
            peers.append(runtime_identity(item) + (item.state, raw['state'], raw['health'],
                                                   raw['started_at'], raw['restart_count']))
    return tuple(sorted(peers, key=lambda value: value[0]))


def review_namespace_apply(service, found, *, model, inventory, baseline, diff, desired_hash, deps):
    """Read-only review. No adoption, capture, source restoration or workload command."""
    runtime = qualified_apply_runtime()
    name = service.compose_service
    runtime_hash = (service.labels or {}).get(HASH_LABEL)
    record = baseline.record
    key = logical_key(service.stack, name, service.working_dir, service.compose_files)
    if (service.state != 'running' or service.health not in {'healthy', 'none'}
            or service.local_build or service.ignored):
        raise NamespaceRefused('service_ineligible')
    if (record.container_id != service.container_id or record.runtime_hash != runtime_hash
            or record.logical_key != key or record.manifest.get('version') != 2 or not baseline.project_observed):
        raise NamespaceRefused('no_trusted_baseline')
    if not inventory.supported or diff is None or diff.scope != 'service' or not diff.service:
        raise NamespaceRefused('service_change_unproven')
    desired = model['services'][name]
    trusted = baseline.model['services'][name]
    refuse_consumer_env_file(baseline.inventory, name, [trusted])
    refuse_consumer_env_file(inventory, name, [desired])
    owner_name = namespace_owner(desired)
    if canonical_relationship(trusted) != canonical_relationship(desired):
        raise NamespaceRefused('namespace_relationship_changed')
    # Hash calibration is not mutation authority: only Layer A-qualified changes.
    refuse_unqualified_changes(trusted, desired)
    for selected in (desired, trusted):
        if set(selected) & FORBIDDEN or hash_excluded_fields_present(selected):
            raise NamespaceRefused('service_resource_unproven')
        if selected.get('image') != service.image:
            raise NamespaceRefused('image_change')
    owner_model = model['services'].get(owner_name)
    condition = _relationship(service, desired, owner_name, owner_model)
    retained = {item.path: item for item in baseline.inputs if item.role in {'compose', 'project_env'}}
    try:
        baseline_full, hashes, evaluated = deps.evaluate_retained(service, retained, (name, owner_name))
        services = baseline_full['services']
        if (evaluated.fingerprint != record.inventory_fingerprint
                or fingerprint(observed_service_model(baseline_full, name)) != record.project_fingerprint
                or services.get(name) != trusted or services.get(owner_name) != owner_model
                or project_outside_service(baseline_full, name) != project_outside_service(model, name)):
            raise ValueError()
    except Exception:
        raise NamespaceRefused('namespace_baseline_unproven') from None

    def prove_live_owner():
        return prove_owner(service, owner_name, owner_model, condition=condition, found=deps.discover(),
                           context_reader=deps.context_reader, context_model=model,
                           hash_reader=deps.unmodified_hash, image_verifier=deps.image_verifier,
                           mounts_reader=deps.mounts_reader)

    owner = prove_owner(service, owner_name, owner_model, condition=condition, found=found,
                        context_reader=deps.context_reader, context_model=model, hash_reader=deps.unmodified_hash,
                        image_verifier=deps.image_verifier, mounts_reader=deps.mounts_reader)
    if hashes.get(owner_name) != owner.runtime_hash:
        raise NamespaceRefused('namespace_baseline_unproven')
    consumer = prove_consumer(service, owner, trusted, found=found, mounts_reader=deps.mounts_reader)
    if (consumer.container_id != service.container_id or consumer.image_id != service.image_id
            or consumer.runtime_hash != runtime_hash or consumer.health not in {'healthy', 'none'}):
        raise NamespaceRefused('namespace_owner_changed')
    baseline_resolved = resolved_hash(trusted, owner.container_id, hashes.get(name))
    if baseline_resolved != runtime_hash:
        raise NamespaceRefused('namespace_baseline_unproven')
    desired_oracle = deps.unmodified_hash(service)
    desired_resolved = resolved_hash(desired, owner.container_id, desired_oracle)
    if desired_resolved == runtime_hash or desired_resolved != desired_hash:
        raise NamespaceRefused('service_change_unproven')
    _validate_desired_binds(desired)
    try:
        deps.image_verifier(service)
    except Exception:
        raise NamespaceRefused('local_image_changed') from None
    peers = peer_observations(found, service, owner_name)
    after = build_inventory(service.compose_files, service.working_dir, model=model)
    if not after.supported or after.fingerprint != inventory.fingerprint:
        raise NamespaceRefused('sources_changed_during_check')
    refuse_consumer_env_file(after, name, [desired])
    # Close the bracket: the owner is exactly unchanged after every evaluation.
    if prove_live_owner() != owner:
        raise NamespaceRefused('namespace_owner_changed')
    return NamespaceApplyReview(
        key, consumer, owner, condition, canonical_relationship(desired), record.id, record.fingerprint,
        fingerprint(record.manifest), record.inventory_fingerprint, record.service_fingerprint,
        inventory.fingerprint, fingerprint(model), fingerprint(desired), fingerprint(trusted),
        fingerprint(owner_model), fingerprint(project_outside_service(model, name)), diff.fingerprint,
        hashes[name], desired_oracle, baseline_resolved, desired_resolved, peers, tuple(runtime))


class NamespaceApplyEvidence:
    """Private v3 recovery evidence in the existing compose-recoveries root."""

    def __init__(self, state, operation_id, review, *, desired, baseline, requester):
        if not re.fullmatch('[0-9a-f]{32}', operation_id):
            raise ValueError('invalid operation identifier')
        if not isinstance(requester, str) or not 1 <= len(requester) <= 80:
            raise ValueError('invalid requester')
        parent = state.root / 'compose-recoveries'
        if parent.is_symlink() or state.root.resolve() != state.root.absolute():
            raise ValueError('unsafe evidence storage')
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        self.state = state
        self.path = parent / operation_id
        self.path.mkdir(mode=0o700)
        try:
            files = []
            for kind, inventory in (('desired', desired), ('baseline', baseline.inventory)):
                for index, item in enumerate(inventory.files):
                    stored = f'{kind}-{index:02d}' if item.present else None
                    files.append({'kind': kind, 'role': item.role, 'path': item.path, 'present': item.present,
                                  'sha256': item.sha256, 'size': item.size, 'stored': stored})
                    if stored:
                        _write_private(self.path / stored, item.content)
            proof = json.dumps(review.facts(), sort_keys=True, separators=(',', ':')).encode()
            if len(proof) > PROOF_LIMIT:
                raise ValueError('oversized namespace Apply proof')
            _write_private(self.path / 'proof.json', proof)
            manifest = {'version': EVIDENCE_VERSION, 'action': EVIDENCE_ACTION,
                        'binding': {'operation_id': operation_id, 'logical_key': review.logical_key,
                                    'requester': requester, 'baseline_id': review.baseline_id,
                                    'baseline_fingerprint': review.baseline_fingerprint,
                                    'review': review.fingerprint, 'owner': review.owner_fingerprint},
                        'files': files, 'proof_sha256': hashlib.sha256(proof).hexdigest()}
            encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
            if len(encoded) > MANIFEST_LIMIT:
                raise ValueError('oversized namespace Apply manifest')
            _write_private(self.path / 'manifest.json', encoded)
            self.fingerprint = fingerprint(manifest)
            for directory in (self.path, parent, state.root):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            self.verify()
        except BaseException:
            # Unbound and pre-marker: nothing refers to this partial directory.
            shutil.rmtree(self.path, ignore_errors=True)
            raise

    def verify(self):
        from .compose_recovery_retention import checked_bundle
        with checked_bundle(self.state.root, self.path) as bundle:
            if not bundle.get('namespace_apply') or bundle['fingerprint'] != self.fingerprint:
                raise ValueError('namespace Apply evidence changed')


class NamespaceApplyGuard:
    """Checkpoint authority for one reviewed Stage 2 Apply under update.lock."""

    def __init__(self, review, *, service, plan, state, operation_id, requester, client_ip, user_agent, deps):
        if not isinstance(review, NamespaceApplyReview):
            raise TypeError('a reviewed namespace Apply is required')
        self.review, self.service, self.plan, self.state = review, service, plan, state
        self.operation_id, self.requester = operation_id, requester
        self.client_ip, self.user_agent, self.deps = client_ip, user_agent, deps
        self.owner_name = review.owner.service
        self.evidence = None
        self.marked = False
        self.latched = False
        self.outcomes = {}
        self.admitted = None
        self.desired_identity = None
        self.recovered_identity = None
        self.recovered_proved = False
        self.transcript = []
        self.prepared = []
        self.published = None
        self.published_baseline = None

    # -- failure discipline -------------------------------------------------
    def _fail(self, reason, latch=True):
        if self.marked:
            # Owner/consumer/invocation/persistence uncertainty latches every
            # further source write and workload command off for this operation.
            self.latched = self.latched or latch
            raise NamespaceApplyManual(reason)
        raise NamespaceRefused(reason)

    def _guarded(self, function, reason='namespace_owner_changed', latch=True):
        if self.latched:
            raise NamespaceApplyManual('latched')
        try:
            return function()
        except NamespaceApplyManual:
            self.latched = True
            raise
        except NamespaceRefused as exc:
            self._fail(exc.reason, latch)
        except Exception:
            self._fail(reason, latch)

    # -- typed mutation admission --------------------------------------------
    def require_mutation_safe(self, service, model):
        def check():
            reason = mutation_refusal(service, model=model, namespace_apply=self.review.authority)
            if reason:
                raise NamespaceRefused(reason)
        self._guarded(check, 'namespace_owner_unproven')

    # -- owner/peer/consumer checkpoints ---------------------------------------
    def _owner(self, found):
        # Bound reviewed owner hash/model: the live model can be partially restored.
        owner_model = self.plan.desired_model['services'][self.owner_name]
        return prove_owner(self.service, self.owner_name, owner_model, condition=self.review.condition,
                           found=found, context_reader=self.deps.context_reader,
                           context_model=self.plan.desired_model,
                           hash_reader=lambda _owner: self.review.owner.runtime_hash,
                           image_verifier=self.deps.image_verifier, mounts_reader=self.deps.mounts_reader)

    def check_owner(self):
        def check():
            found = self.deps.discover()
            if self._owner(found) != self.review.owner:
                raise NamespaceRefused('namespace_owner_changed')
            if peer_observations(found, self.service, self.owner_name) != self.review.peers:
                raise NamespaceRefused('namespace_owner_changed')
            return found
        return self._guarded(check)

    def prove_runtime(self, phase):
        """Full checkpoint for one phase; returns (Service, consumer proof)."""
        expected = {'pre_marker': (self.review.consumer.runtime_hash, self.plan.baseline.model),
                    'apply': (self.review.desired_resolved, self.plan.desired_model),
                    'failed_desired': (self.review.desired_resolved, self.plan.desired_model),
                    'recovery': (self.review.baseline_resolved, self.plan.baseline.model),
                    'recovered': (self.review.baseline_resolved, self.plan.baseline.model)}[phase]

        def check():
            found = self.check_owner()
            selected = [item for item in found if item.stack == self.service.stack
                        and item.compose_service == self.service.compose_service]
            if len(selected) != 1:
                raise NamespaceRefused('namespace_owner_changed')
            fresh = selected[0]
            proof = prove_consumer(fresh, self.review.owner, expected[1]['services'][self.service.compose_service],
                                   found=found, mounts_reader=self.deps.mounts_reader)
            if (proof.container_id != fresh.container_id or fresh.image != self.service.image
                    or fresh.image_id != self.service.image_id or proof.image_id != self.service.image_id
                    or proof.runtime_hash != expected[0]):
                raise NamespaceRefused('namespace_owner_changed')
            original = self.review.consumer.container_id
            if phase == 'pre_marker':
                if proof.identity() != self.review.consumer.identity():
                    raise NamespaceRefused('namespace_owner_changed')
            elif phase in {'apply', 'recovery'}:
                avoid = {original} | ({self.desired_identity[0]} if phase == 'recovery' else set())
                if proof.container_id in avoid or proof.restart_count != 0:
                    raise NamespaceRefused('namespace_owner_changed')
                attribute = 'desired_identity' if phase == 'apply' else 'recovered_identity'
                bound = getattr(self, attribute)
                if bound is not None and bound != proof.identity():
                    raise NamespaceRefused('namespace_owner_changed')
                setattr(self, attribute, proof.identity())
            else:
                bound = self.desired_identity if phase == 'failed_desired' else self.recovered_identity
                if bound is None or proof.identity() != bound:
                    raise NamespaceRefused('namespace_owner_changed')
            self.transcript.append(fingerprint([phase, proof.identity(), proof.health]))
            return fresh, proof
        return self._guarded(check)

    def verify_configuration(self, current_service, inventory, model, expected_hash):
        """Bracketed model/inventory/hash evaluation using the reviewed owner ID."""
        def check():
            name = self.service.compose_service
            baseline = expected_hash == self.review.baseline_resolved
            if expected_hash not in {self.review.baseline_resolved, self.review.desired_resolved}:
                raise NamespaceRefused('compose_hash_unavailable')
            before = build_inventory(self.service.compose_files, self.service.working_dir)
            current = self.deps.model_reader(self.service)
            if not isinstance(current, dict) or current.get('name') != self.service.stack:
                raise NamespaceRefused('project_identity')
            oracle = self.deps.unmodified_hash(self.service)
            owner = next(item for item in self.deps.discover() if item.container_id == self.review.owner.container_id)
            owner_oracle = self.deps.unmodified_hash(owner)
            after = build_inventory(self.service.compose_files, self.service.working_dir, model=current)
            refuse_consumer_env_file(after, name, [current['services'].get(name)])
            observed = observed_service_model(current, name) if baseline else current
            if (not after.supported or before.fingerprint != after.fingerprint
                    or after.fingerprint != inventory.fingerprint
                    or fingerprint(observed) != fingerprint(model)
                    or owner_oracle != self.review.owner.runtime_hash
                    or current['services'].get(self.owner_name) != self.plan.desired_model['services'][self.owner_name]
                    or resolved_hash(current['services'][name], self.review.owner.container_id, oracle) != expected_hash
                    or oracle != (self.review.baseline_oracle if baseline else self.review.desired_oracle)):
                raise NamespaceRefused('sources_changed_during_check')
            return current, after
        # A configuration mismatch alone does not prove owner/runtime loss.
        return self._guarded(check, 'sources_changed_during_check', latch=False)

    def diagnostic_observation(self):
        """Bounded read-only consumer facts for a manual outcome; never authority.

        Reports authoritative zero/one/many inventory where inspectable, with
        no invented PID/netns proof. An uninspectable inventory is 'unknown',
        never absence.
        """
        try:
            found = self.deps.discover()
            selected = [item for item in found if item.stack == self.service.stack
                        and item.compose_service == self.service.compose_service]
            facts = {'consumers': len(selected) if len(selected) < 2 else 'many'}
            if len(selected) == 1:
                item = selected[0]
                raw = _inspect(item.container_id)
                runtime_hash = (item.labels or {}).get(HASH_LABEL)
                facts.update(
                    state=raw['state'] if raw['state'] in {'created', 'running', 'restarting', 'exited', 'paused',
                                                           'dead', 'removing'} else 'other',
                    original=item.container_id == self.review.consumer.container_id,
                    network_mode_owner=raw['network_mode'] == 'container:' + self.review.owner.container_id,
                    image_unchanged=raw['image_id'] == self.service.image_id,
                    configuration=('desired' if runtime_hash == self.review.desired_resolved else
                                   'baseline' if runtime_hash == self.review.baseline_resolved else 'other'))
            return facts
        except Exception:
            return {'consumers': 'unknown'}

    # -- evidence, marker and invocation -------------------------------------
    def write_evidence(self):
        def write():
            self.evidence = NamespaceApplyEvidence(self.state, self.operation_id, self.review,
                                                   desired=self.plan.inventory, baseline=self.plan.baseline,
                                                   requester=self.requester)
            self.state.bind_namespace_apply_evidence(
                self.operation_id, self.evidence.fingerprint, logical_key=self.review.logical_key,
                review=self.review.fingerprint, owner=self.review.owner_fingerprint, requester=self.requester,
                expectation={'desired': [self.review.desired_resolved, self.review.desired_service,
                                         self.review.desired_inventory],
                             'baseline': [self.review.baseline_resolved, self.review.baseline_service,
                                          self.review.baseline_inventory]})
            return self.evidence
        return self._guarded(write, 'evidence_unavailable')

    def mark(self):
        """Atomic marker + fence. Ambiguity is resolved only from durable state."""
        try:
            self.state.mark_namespace_apply(self.operation_id, logical_key=self.review.logical_key,
                                            evidence=self.evidence.fingerprint)
        except Exception:
            if self.state.namespace_apply_marker(self.operation_id) == 'absent':
                raise NamespaceRefused('evidence_unavailable') from None
            self.marked = self.latched = True
            raise NamespaceApplyManual('marker_uncertain') from None
        self.marked = True

    def invoke(self, command, *, phase, cwd, timeout=600):
        if self.latched:
            raise NamespaceApplyManual('latched')
        outcome = invoke(command, phase=phase, cwd=cwd, timeout=timeout)
        recorded = False
        try:
            recorded = self.state.record_namespace_invocation(self.operation_id, outcome.record()) is True
        except Exception:
            recorded = False
        self.outcomes[phase] = (outcome, recorded)
        # Non-zero completion is never a recovery class (allowlist EMPTY).
        if not recorded or not outcome.completed_zero:
            self.latched = True
            raise NamespaceApplyManual('invocation_' + outcome.category)
        return outcome

    # -- recovery admission ----------------------------------------------------
    def admit(self, failure_class):
        """Called only immediately after a fully proved checkpoint of the running
        desired replacement that then fails bounded startup/health verification."""
        outcome, recorded = self.outcomes.get('apply', (None, False))
        if (failure_class in QUALIFIED_FAILURE_CLASSES and not self.latched and self.marked and recorded
                and outcome is not None and outcome.completed_zero and self.desired_identity is not None
                and 'recovery' not in self.outcomes):
            self.admitted = failure_class

    def recovery_admitted(self):
        return self.admitted is not None and not self.latched

    def begin_recovery(self):
        """Before any source write: evidence, baseline integrity, local image,
        failed desired identity and the exact owner, then the durable phase."""
        if not self.recovery_admitted():
            self.latched = True
            raise NamespaceApplyManual('recovery_not_admitted')

        def verify():
            self.evidence.verify()
            BaselineStore(self.state).load(self.plan.baseline.record)
            self.deps.image_verifier(self.service)  # Never pull or retag to recover.
        self._guarded(verify, 'evidence_unavailable')
        self.prove_runtime('failed_desired')

        def commit():
            self.state.namespace_apply_phase(self.operation_id, 'recovery_source_transition',
                                             failure_class=self.admitted)
        self._guarded(commit, 'evidence_unavailable')

    def check_capability(self):
        """The reviewed Apply/recovery runtime identity, observed afresh."""
        def check():
            if tuple(qualified_apply_runtime()) != tuple(self.review.runtime):
                raise NamespaceRefused('namespace_apply_unqualified')
        self._guarded(check, 'namespace_apply_unqualified')

    def mark_recovery_dispatch(self):
        self.check_capability()

        def commit():
            self.state.namespace_apply_phase(self.operation_id, 'recovery_recreate_may_have_started')
        self._guarded(commit, 'evidence_unavailable')

    def pending_restore_allowed(self):
        """Restore desired bytes after proved recovery, or best-effort when a
        recovery step failed before its dispatch with nothing latched."""
        if self.latched or self.admitted is None:
            return False
        return self.recovered_proved or 'recovery' not in self.outcomes

    # -- staged trust and atomic publication -------------------------------
    def prepare_baseline(self, fresh, runtime_hash, model, inventory):
        self.check_owner()
        current, checked = self.verify_configuration(fresh, inventory, model, runtime_hash)

        def prepare():
            from .state import _utc_now
            store = BaselineStore(self.state)
            record = store.prepare(key=self.review.logical_key, stack=self.service.stack,
                                   compose_service=self.service.compose_service, container_id=fresh.container_id,
                                   runtime_hash=runtime_hash, model=current, inventory=checked,
                                   origin='captured', captured_at=_utc_now())
            self.prepared.append(record)
            return store.load(record)
        return self._guarded(prepare, 'evidence_unavailable')

    def discard_unpublished(self):
        """Remove prepared material only where the database proves it unpublished."""
        store = BaselineStore(self.state)
        for record in self.prepared:
            if record.id != self.published_baseline:
                store.discard_unpublished(record)

    def publish(self, prepared, *, recovered):
        store = BaselineStore(self.state)
        record = prepared.record
        values = {**record.__dict__, 'manifest': json.dumps(record.manifest, sort_keys=True, separators=(',', ':'))}
        try:
            # Final bracket immediately before the commit: material, evidence,
            # capability, exact owner/peers/consumer and the desired bytes on disk.
            self._guarded(lambda: (store.load(record), self.evidence.verify()), 'evidence_unavailable')
            self.check_capability()
            self.prove_runtime('recovered' if recovered else 'apply')

            def sources():
                current = build_inventory(self.service.compose_files, self.service.working_dir)
                if not current.supported or current.fingerprint != self.review.desired_inventory:
                    raise NamespaceRefused('sources_changed_during_check')
            self._guarded(sources, 'sources_changed_during_check')
            self.state.publish_namespace_apply(
                self.operation_id, values, {'checks': len(self.transcript), 'digest': fingerprint(self.transcript)},
                recovered=recovered, requester=self.requester, client_ip=self.client_ip, user_agent=self.user_agent,
                evidence=self.evidence.fingerprint)
        except Exception:
            # Never recreate again: only a proved durable commit is success.
            if self.state.namespace_apply_published(self.operation_id, record.id, recovered=recovered):
                self.published, self.published_baseline = ('recovered' if recovered else 'succeeded'), record.id
                return
            self.latched = True
            raise NamespaceApplyManual('publication_uncertain') from None
        self.published, self.published_baseline = ('recovered' if recovered else 'succeeded'), record.id
