"""No-baseline trust bootstrap. The caller owns review authority and update.lock.

Live sources and local image aliases are bracketed, not frozen. After the
write-ahead boundary any uncertainty requires manual recovery; this module
never writes Compose sources, pulls images or reconstructs an old model.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from functools import wraps
from pathlib import Path

import yaml
from yaml.events import AliasEvent

from .compose_namespace import require_mutation_safe
from .operations import PreMutationRefusal
from .compose_drift import REASONS as COMPOSE_REASONS
from .compose import validate
from .compose_baseline import BaselineStore, _write_private, logical_key
from .compose_drift import (FIELD_LABELS, Inventory, build_inventory, fingerprint,
                            hash_excluded_fields_present, service_changes, read_input)
from .compose_reconcile import HASH_LABEL, runtime_identity, verify_image_unchanged
from .models import Service
from .reconciliation import mark_changed, mark_project_inputs_changed, reconcile_operation
from .progress import BOOTSTRAP_STAGE_TOTAL
from .docker import compose_args
from .system import run

REASONS = {name: message for name, message in (
    ('service_ineligible', 'The selected service is not eligible for trust bootstrap.'),
    ('not_bootstrap_state', 'Trust bootstrap requires pending configuration changes without a trusted baseline.'),
    ('trusted_baseline_available', 'A trusted configuration is available. Use the normal Apply or Discard review.'),
    ('trust_store_unavailable', 'UPT could not verify whether trusted configuration is available.'),
    ('inventory_unsupported', 'UPT cannot prove the complete configuration input inventory.'),
    ('service_resource_unproven', 'Service resources are outside the supported bootstrap scope.'),
    ('project_unproven', 'The original project execution context could not be proved.'),
    ('peer_unproven', 'Other project services could not be proved unchanged.'),
    ('image_change', 'The desired image reference differs from the running image.'),
    ('local_image_changed', 'The local image reference does not resolve to the reviewed running image.'),
    ('review_changed', 'The reviewed source or runtime evidence changed.'),
    ('operation_active', 'Another UPT operation is active.'),
    ('bootstrap_unresolved', 'An unresolved bootstrap requires manual recovery before any further mutation.'),
    ('completion_unresolved', 'An unresolved update or rollback completion requires manual recovery before any further mutation.'),
    ('evidence_unavailable', 'Private bootstrap evidence could not be safely persisted or verified.'),
)}
REASONS.update({key: COMPOSE_REASONS[key] for key in (
    'namespace_owner_has_dependents', 'namespace_owner_unproven', 'namespace_unsupported_compose')})



class BootstrapRefused(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else 'review_changed'
        super().__init__(REASONS[self.reason])


class BootstrapExecutionFailed(RuntimeError):
    """Safe failure transport; durable state determines mutation uncertainty."""
    def __init__(self, reason='evidence_unavailable'):
        self.reason = reason if reason in REASONS else 'evidence_unavailable'
        super().__init__('Bootstrap did not complete. Consult the durable operation outcome and retained private evidence.')


def _bounded_plan(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except BootstrapRefused:
            raise
        except PreMutationRefusal as exc:
            raise BootstrapRefused(exc.reason) from None
        except Exception:
            raise BootstrapRefused('trust_store_unavailable') from None
    return checked


def _bounded_execution(function):
    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception as exc:
            reason = exc.reason if isinstance(exc, (BootstrapRefused, PreMutationRefusal)) else 'evidence_unavailable'
            raise BootstrapExecutionFailed(reason) from None
    return checked


@dataclass(frozen=True)
class BootstrapPlan:
    logical_key: str
    service: Service
    inventory: Inventory
    desired_model: dict
    desired_hash: str
    runtime_hash: str
    context: str
    peers: tuple
    selected: tuple
    fingerprint: str
    baseline_signature: tuple

    @property
    def proposal(self):
        """Desired-only presentation projection; previous values are never fabricated."""
        desired = self.desired_model['services'][self.service.compose_service]
        desired = {name: value for name, value in desired.items() if value not in (None, [], {})}
        entries = []
        for entry in service_changes({}, desired):
            value = desired.get(entry['field'])
            shown = {'field': entry['field'], 'label': entry['label'], 'summary': 'Configured'}
            if entry.get('new'):
                shown['summary'] = entry['new']
            elif entry['field'] in ('environment', 'labels') and isinstance(value, (dict, list)):
                shown['summary'] = f'{len(value)} set · names only'
            elif isinstance(value, (dict, list)) and entry.get('added'):
                shown['summary'] = f'{len(value)} configured'
            if entry.get('added'):
                shown['items'] = entry['added']
            if entry.get('hidden'):
                shown['hidden'] = entry['hidden']
            entries.append(shown)
        return entries

    @property
    def observations(self):
        """Bounded Docker-observed facts for display; never browser authority."""
        service = self.service

        def safe(value, default, limit=160):
            return value if isinstance(value, str) and 0 < len(value) <= limit and value.isprintable() else default
        return [{'label': 'Image', 'value': safe(service.image, 'unknown', 200)},
                {'label': 'Container state', 'value': safe(service.state, 'unknown', 40)},
                {'label': 'Health', 'value': safe(service.health, 'none', 40)},
                {'label': 'Restart policy (runtime)', 'value': safe(service.restart_policy, 'unknown', 40)}]


def _strict_source(inventory):
    class UniqueLoader(yaml.SafeLoader):
        pass

    def mapping(loader, node):
        result = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=True)
            if key in result:
                raise ValueError('duplicate YAML key')
            result[key] = loader.construct_object(value_node, deep=True)
        return result

    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    for item in inventory.files:
        path = Path(item.path)
        if str(path.absolute()) != str(path.resolve(strict=False)):
            raise BootstrapRefused('inventory_unsupported')
        if item.role != 'compose':
            continue
        try:
            for event in yaml.parse(item.content):
                if isinstance(event, AliasEvent) or getattr(event, 'anchor', None) or getattr(event, 'tag', None):
                    raise ValueError('unsupported YAML syntax')
            source = yaml.load(item.content, Loader=UniqueLoader)
            if not isinstance(source, dict) or 'include' in source:
                raise ValueError('unsupported source')
            if any('extends' in value for value in (source.get('services') or {}).values()):
                raise ValueError('unsupported source')
        except (yaml.YAMLError, ValueError, TypeError):
            raise BootstrapRefused('inventory_unsupported') from None


def observe(service):
    """Bounded runtime observations, including same-ID restarts."""
    raw = run(['docker', 'inspect', '--type', 'container', '--format',
               '{{json .RestartCount}}', service.container_id], timeout=30)
    try:
        count = json.loads(raw)
    except (ValueError, TypeError):
        raise BootstrapRefused('service_ineligible') from None
    if type(count) is not int or count < 0 or count > 2**31:
        raise BootstrapRefused('service_ineligible')
    if not isinstance(service.started_at, str) or not service.started_at or len(service.started_at) > 80:
        raise BootstrapRefused('service_ineligible')
    labels = service.labels or {}
    if (labels.get('com.docker.compose.project') != service.stack
            or labels.get('com.docker.compose.service') != service.compose_service
            or labels.get('com.docker.compose.project.working_dir') != service.working_dir
            or labels.get('com.docker.compose.project.config_files') != ','.join(service.compose_files)
            or str(labels.get('com.docker.compose.oneoff')).lower() != 'false'):
        raise BootstrapRefused('project_unproven')
    return runtime_identity(service) + (service.state, service.health, service.started_at, count,
                                        service.name, service.architecture, service.restart_policy)


@_bounded_plan
def make_plan(service, found, state, *, model_reader, hash_reader, context_reader,
              mounts_reader, baseline_available, own_operation=None):
    """Read-only proposal authority: every predicate is independently proved."""
    if not (service.stack and service.compose_service and service.working_dir and len(service.compose_files) == 1):
        raise BootstrapRefused('inventory_unsupported')
    if str(Path(service.working_dir).absolute()) != str(Path(service.working_dir).resolve(strict=True)):
        raise BootstrapRefused('project_unproven')
    require_mutation_safe(service)
    key = logical_key(service.stack, service.compose_service, service.working_dir, service.compose_files)
    if state.bootstrap_fence(key, own_operation=own_operation):
        raise BootstrapRefused('bootstrap_unresolved')
    try:
        state.assert_completion_unfenced(service)
    except ValueError:
        raise BootstrapRefused('completion_unresolved') from None
    with state.read() as c:
        if c.execute("SELECT 1 FROM operation_runs WHERE status IN ('queued','running','finalizing') AND id!=?", (own_operation or '',)).fetchone():
            raise BootstrapRefused('operation_active')
    selected = [item for item in found if item.stack == service.stack and item.compose_service == service.compose_service]
    if (len(selected) != 1 or selected[0].container_id != service.container_id or service.state != 'running'
            or service.health not in {'none', 'healthy'} or service.local_build or service.ignored):
        raise BootstrapRefused('service_ineligible')
    selected_observation = observe(service)
    runtime_hash = (service.labels or {}).get(HASH_LABEL)
    if not isinstance(runtime_hash, str) or not re.fullmatch('[0-9a-f]{64}', runtime_hash):
        raise BootstrapRefused('service_ineligible')
    try:
        if baseline_available(service, runtime_hash):
            raise BootstrapRefused('trusted_baseline_available')
    except BootstrapRefused:
        raise
    except Exception:
        raise BootstrapRefused('trust_store_unavailable') from None
    baseline_signature = tuple((row['id'], row['fingerprint']) for row in state.compose_baselines(key))
    _strict_source(Inventory((read_input('compose', service.compose_files[0]),), ()))
    before = build_inventory(service.compose_files, service.working_dir)
    try:
        model = model_reader(service)
        desired_hash = hash_reader(service)
    except Exception:
        raise BootstrapRefused('review_changed') from None
    after = build_inventory(service.compose_files, service.working_dir, model=model)
    if not after.supported or before.fingerprint != after.fingerprint or before.unsupported != after.unsupported:
        raise BootstrapRefused('inventory_unsupported')
    _strict_source(after)
    selected_model = (model.get('services') or {}).get(service.compose_service)
    if not isinstance(selected_model, dict):
        raise BootstrapRefused('service_resource_unproven')
    if selected_model.get('image') != service.image:
        raise BootstrapRefused('image_change')
    if desired_hash == runtime_hash:
        raise BootstrapRefused('not_bootstrap_state')
    if not re.fullmatch('[0-9a-f]{64}', str(desired_hash)):
        raise BootstrapRefused('review_changed')
    if (set(selected_model) - (set(FIELD_LABELS) | {'env_file'})
            or hash_excluded_fields_present(selected_model)
            or any(field in selected_model for field in ('build', 'pull_policy', 'profiles', 'scale', 'develop',
                    'provider', 'deploy', 'tmpfs', 'configs', 'secrets', 'models', 'links', 'external_links',
                    'volumes_from', 'depends_on', 'network_mode', 'pid', 'ipc'))):
        raise BootstrapRefused('service_resource_unproven')
    for mount in selected_model.get('volumes') or []:
        if (not isinstance(mount,dict) or set(mount) - {'type','source','target','read_only','bind'}
                or not isinstance(mount.get('bind') or {},dict)
                or set(mount.get('bind') or {}) - {'propagation','create_host_path'}):
            raise BootstrapRefused('service_resource_unproven')
    if set(model) - {'name', 'services', 'networks'}:
        raise BootstrapRefused('project_unproven')
    try:
        context = context_reader(service, model)
        mounts_reader(service, selected_model)
    except Exception:
        raise BootstrapRefused('project_unproven') from None
    project = [item for item in found if item.stack == service.stack and item.compose_service != service.compose_service]
    names = set(model['services']) - {service.compose_service}
    if len(project) != len(names) or {item.compose_service for item in project} != names:
        raise BootstrapRefused('peer_unproven')
    peers = []
    for peer in project:
        try:
            peer_model = model['services'][peer.compose_service]
            if (set(peer_model) - (set(FIELD_LABELS) | {'env_file'})
                    or any(field in peer_model for field in ('build','pull_policy','profiles','scale','develop','provider','deploy','tmpfs'))
                    or peer.state != 'running' or peer.health not in {'none', 'healthy'} or peer_model.get('image') != peer.image
                    or peer.working_dir != service.working_dir or peer.compose_files != service.compose_files
                    or hash_excluded_fields_present(peer_model)):
                raise ValueError('peer changed')
            observed = observe(peer)
            if hash_reader(peer) != (peer.labels or {}).get(HASH_LABEL):
                raise ValueError('peer drift')
            verify_image_unchanged(peer)
            peer_context = context_reader(peer, model)
            mounts_reader(peer, peer_model)
            peers.append((observed, peer_context))
        except Exception:
            raise BootstrapRefused('peer_unproven') from None
    try:
        verify_image_unchanged(service)
    except Exception:
        raise BootstrapRefused('local_image_changed') from None
    # Enclose peer hash evaluation and image/context inspection in the bracket.
    final = build_inventory(service.compose_files, service.working_dir, model=model)
    if final.fingerprint != after.fingerprint or final.unsupported != after.unsupported or observe(service) != selected_observation:
        raise BootstrapRefused('review_changed')
    peers = tuple(sorted(peers, key=lambda item: item[0][0]))
    binding = fingerprint({'version': 1, 'no_baseline': True, 'logical_key': key, 'selected': selected_observation,
                           'peers': peers, 'context': context, 'model': model, 'hash': desired_hash,
                           'inventory': after.fingerprint, 'baseline_signature': baseline_signature})
    return BootstrapPlan(key, service, after, model, desired_hash, runtime_hash, context, peers, selected_observation, binding, baseline_signature)


class BootstrapEvidence:
    def __init__(self, state, operation_id, plan, requester):
        if not re.fullmatch('[0-9a-f]{32}', operation_id):
            raise ValueError('invalid operation identifier')
        parent = state.root / 'compose-recoveries'
        if parent.is_symlink() or state.root.resolve() != state.root.absolute():
            raise ValueError('unsafe evidence storage')
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(parent, 0o700)
        self.path = parent / operation_id
        self.path.mkdir(mode=0o700)
        files = []
        for index, item in enumerate(plan.inventory.files):
            stored = f'desired-{index:02d}' if item.present else None
            files.append(dict(kind='desired', role=item.role, path=item.path, present=item.present,
                              sha256=item.sha256, size=item.size, stored=stored))
            if stored:
                _write_private(self.path / stored, item.content)
        proof = json.dumps({'model': plan.desired_model, 'selected': plan.selected, 'peers': plan.peers,
                            'context': plan.context, 'desired_hash': plan.desired_hash, 'runtime_hash': plan.runtime_hash},
                           sort_keys=True, separators=(',', ':')).encode()
        if len(proof) > 8 * 1024 * 1024:
            raise ValueError('oversized bootstrap proof')
        import hashlib
        _write_private(self.path / 'proof.json', proof)
        manifest = {'version': 2, 'action': 'bootstrap', 'binding': {
                    'operation_id': operation_id, 'logical_key': plan.logical_key, 'evidence': plan.fingerprint,
                    'requester': requester, 'old_trusted_source_available': False},
                    'files': files, 'proof_sha256': hashlib.sha256(proof).hexdigest()}
        encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
        if len(encoded) > 256 * 1024:
            raise ValueError('oversized bootstrap manifest')
        _write_private(self.path / 'manifest.json', encoded)
        self.fingerprint = fingerprint(manifest)
        for directory in (self.path, parent, state.root):
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        self.verify(state)

    def verify(self, state):
        from .compose_recovery_retention import checked_bundle
        with checked_bundle(state.root, self.path) as bundle:
            if bundle['fingerprint'] != self.fingerprint:
                raise ValueError('bootstrap evidence changed')


def require_compose_flags():
    """Capability gate, never downgrade execution arguments."""
    help_text = run(['docker', 'compose', 'up', '--help'], timeout=30)
    if len(help_text) > 65536 or not all(re.search(r'(?<![\w-])' + re.escape(flag) + r'(?![\w-])', help_text)
               for flag in ('--no-deps', '--pull', '--no-build')) or not re.search(r'--pull[^\n]*never', help_text):
        raise BootstrapRefused('service_ineligible')


@_bounded_execution
@reconcile_operation
def do_compose_bootstrap(plan, state, *, operation_id, requester, client_ip, user_agent,
                         revalidate, discover_current, verify_configuration, verify_context,
                         health_timeout=90, dry_run=False):
    """Recreate once and publish the first baseline with terminal success.

    The shared mutation lock is held by the adapter throughout. Callback
    authorities are server-owned and reusable outside HTTP/CLI presentation.
    """
    require_mutation_safe(plan.service, model=plan.desired_model)
    state.ensure_compatible()
    try:
        state.assert_completion_unfenced(plan.service)
    except ValueError:
        raise BootstrapRefused('completion_unresolved') from None
    transcript = []
    require_compose_flags()
    service = plan.service
    replacement_identity = None

    def configuration(current, expected_hash):
        model, inventory = verify_configuration(current, plan.inventory, plan.desired_model, expected_hash)
        _strict_source(inventory)
        return model, inventory

    def verify_after(*, allow_starting=False):
        nonlocal replacement_identity
        found = discover_current()
        selected = [item for item in found if item.stack == service.stack and item.compose_service == service.compose_service]
        if len(selected) != 1:
            raise ValueError('replacement unavailable')
        fresh = selected[0]
        observed = observe(fresh)
        if (fresh.container_id == service.container_id or fresh.state != 'running'
                or fresh.image_id != service.image_id or fresh.image != service.image
                or fresh.working_dir != service.working_dir or fresh.compose_files != service.compose_files
                or (fresh.labels or {}).get(HASH_LABEL) != plan.desired_hash
                or fresh.health not in ({'none', 'healthy', 'starting'} if allow_starting else {'none', 'healthy'})):
            raise ValueError('replacement verification failed')
        # Health may move from starting to healthy; every other observation is stable.
        stable = observed[:11] + observed[12:]
        if observed[13] != 0 or replacement_identity is not None and stable != replacement_identity:
            raise ValueError('replacement restarted or changed')
        replacement_identity = stable
        configuration(fresh, plan.desired_hash)
        verify_image_unchanged(fresh)
        verify_context(fresh, plan.desired_model, service.container_id, plan.context)
        peers = []
        for peer in found:
            if peer.stack == service.stack and peer.compose_service != service.compose_service:
                peer_observation = observe(peer)
                peer_context = verify_context(peer, plan.desired_model, peer.container_id, None)
                peers.append((peer_observation, peer_context))
                verify_image_unchanged(peer)
                configuration(peer, (peer.labels or {}).get(HASH_LABEL))
        if tuple(sorted(peers, key=lambda item: item[0][0])) != plan.peers:
            raise ValueError('peer changed')
        configuration(fresh, plan.desired_hash)
        transcript.append(fingerprint({'selected': observed, 'peers': peers, 'inventory': plan.inventory.fingerprint}))
        return fresh

    revalidate()
    if dry_run:
        return None
    running = []

    def stage(number, label, message=None):
        """Persist one real numbered stage; ``message`` marks it running, otherwise it completed."""
        state.operation_event(operation_id, 'task_started' if message else 'task_completed',
                              stage=f'{number}/{BOOTSTRAP_STAGE_TOTAL} {label}', message=message or 'Completed',
                              status='running' if message else 'completed')
        running[:] = [(number, label)] if message else []

    try:
        stage(1, 'Revalidate reviewed configuration')
        evidence = BootstrapEvidence(state, operation_id, plan, requester)
        state.bind_bootstrap_evidence(operation_id, evidence.fingerprint, logical_key=plan.logical_key,
                                      review=plan.fingerprint, requester=requester, old_container_id=service.container_id,
                                      runtime_hash=plan.desired_hash,
                                      service_fingerprint=fingerprint(plan.desired_model['services'][service.compose_service]),
                                      inventory_fingerprint=plan.inventory.fingerprint)
        stage(2, 'Protect bootstrap evidence')
        validate(service, project_name=service.stack)
        configuration(service, plan.desired_hash)
        evidence.verify(state)
        # This callback repeats ALL review predicates with a fresh complete inventory.
        revalidate()
        stage(3, 'Validate desired Compose configuration')
        command = compose_args(service, project_name=service.stack) + ['up', '-d', '--no-deps', '--pull', 'never', '--no-build', service.compose_service]
        stage(4, 'Recreate service to establish trust', 'Recreating the selected service without pulling')
        require_mutation_safe(service, model=plan.desired_model)
        state.mark_bootstrap_recreate(operation_id, plan.logical_key, evidence.fingerprint, plan.baseline_signature)
        mark_changed()
        mark_project_inputs_changed()  # Recreated from the current shared project inputs.
        run(command, cwd=service.working_dir, timeout=1800)
        stage(4, 'Recreate service to establish trust')
        stage(5, 'Verify recreated service', 'Checking reviewed runtime, source and image evidence')
        fresh = verify_after(allow_starting=True)
        stage(5, 'Verify recreated service')
        stage(6, 'Verify startup and health', 'Checking health and unchanged project peers')
        deadline = time.monotonic() + max(1, min(int(health_timeout), 600))
        while fresh.health == 'starting':
            if time.monotonic() >= deadline:
                raise ValueError('health timeout')
            time.sleep(1)
            fresh = verify_after(allow_starting=True)
        fresh = verify_after()
        stage(6, 'Verify startup and health')
        stage(7, 'Prepare first trusted baseline', 'Preparing verified private baseline material')
        from .state import _utc_now
        store = BaselineStore(state)
        record = store.prepare(key=plan.logical_key, stack=service.stack, compose_service=service.compose_service,
                               container_id=fresh.container_id, runtime_hash=plan.desired_hash, model=plan.desired_model,
                               inventory=plan.inventory, origin='captured', captured_at=_utc_now())
        try:
            store.load(record)
            evidence.verify(state)
            fresh = verify_after()
            stage(7, 'Prepare first trusted baseline')
            values = {**record.__dict__, 'manifest': json.dumps(record.manifest, sort_keys=True, separators=(',', ':'))}
            # Stage 8 is committed inside this publication, immediately before the terminal event.
            state.publish_bootstrap_success(operation_id, values, {'checks':len(transcript), 'digest':fingerprint(transcript), 'final_brackets':transcript[-3:]}, requester=requester,
                                            client_ip=client_ip, user_agent=user_agent)
        except BaseException:
            # Cleanup never changes the failure being classified and is skipped unless the
            # database proves the prepared baseline was not published.
            store.discard_unpublished(record)
            raise
    except Exception:
        # Presentation only: mark the in-flight step failed. Never alters the failure
        # classification, which the adapter derives from durable state.
        if running:
            try:
                number, label = running[0]
                state.operation_event(operation_id, 'task_failed', stage=f'{number}/{BOOTSTRAP_STAGE_TOTAL} {label}',
                                      message='Step failed', status='failed')
            except Exception:
                pass
        raise
    return fresh
