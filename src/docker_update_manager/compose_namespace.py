"""Bounded, read-only Compose namespace evidence and shared mutation guards.

Hash reconstruction is never authority without per-evaluation calibration and
the shared context proof. Only the separate normal-image-update guard and the
typed reviewed Stage 2 NamespaceApplyAuthority may admit a consumer mutation;
every other operation retains the default refusal.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .compose_drift import hash_excluded_fields_present
from .docker import compose_args, discover
from .system import run

HASH_LABEL = 'com.docker.compose.config-hash'
HEX_ID = re.compile(r'[0-9a-f]{64}')
FORBIDDEN = frozenset('networks ports expose hostname domainname dns dns_search dns_opt extra_hosts mac_address links external_links pid ipc uts volumes_from configs secrets models develop provider tmpfs deploy build pull_policy profiles scale post_start pre_stop use_api_socket'.split())
# This is a bounded subset of compose-go ServiceConfig's JSON field order.
# command/entrypoint are emitted even when nil. Unknown shapes fail calibration.
HASH_FIELDS = 'annotations attach cap_add cap_drop command container_name entrypoint environment image init labels logging network_mode privileged read_only restart security_opt shm_size stdin_open stop_grace_period stop_signal sysctls tty user volumes working_dir'.split()


class NamespaceRefused(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class NamespaceOwnerEvidence:
    service: str
    container_id: str
    image_id: str
    image: str
    runtime_hash: str
    state: str
    health: str
    started_at: str
    restart_count: int
    execution_context_fingerprint: str
    consumer_network_mode: str
    consumer_started_at: str
    netns_equal: bool | None = None

    def fingerprint_values(self):
        return asdict(self)


def namespace_candidate(service, selected):
    mode = selected.get('network_mode')
    return ((isinstance(mode, str) and mode.startswith('service:'))
            or (getattr(service, 'network_mode', None) or '').startswith('container:'))


def namespace_owner(selected):
    mode = selected.get('network_mode')
    if not isinstance(mode, str) or not re.fullmatch(r'service:[a-zA-Z0-9][a-zA-Z0-9_.-]*', mode):
        raise NamespaceRefused('network_unproven')
    return mode[len('service:'):]


def service_hash(selected):
    """Go-compatible JSON for the supported subset, never a general hash oracle.

    Compose ServiceHash excludes build/pull_policy/scale/depends_on/profiles and
    deploy.replicas. Other unsupported structs deliberately fail closed rather
    than guessing their marshalling. Calibration detects version/default changes.
    """
    value = copy.deepcopy(selected)
    for key in ('build', 'pull_policy', 'scale', 'depends_on', 'profiles'):
        value.pop(key, None)
    if set(value) - set(HASH_FIELDS):
        raise NamespaceRefused('compose_hash_unavailable')
    ordered = {}
    for field in HASH_FIELDS:
        if field in ('command', 'entrypoint'):
            ordered[field] = value.get(field)
        elif field in value:
            ordered[field] = value[field]
    # Maps marshal in lexical order, struct fields in declared order.
    for field in ('annotations', 'environment', 'labels', 'sysctls'):
        if field in ordered:
            if not isinstance(ordered[field], dict):
                raise NamespaceRefused('compose_hash_unavailable')
            ordered[field] = dict(sorted(ordered[field].items()))
    if 'logging' in ordered:
        node = ordered['logging']
        if not isinstance(node, dict) or set(node) - {'driver', 'options'}:
            raise NamespaceRefused('compose_hash_unavailable')
        ordered['logging'] = {key: (dict(sorted(node[key].items())) if key == 'options' else node[key])
                              for key in ('driver', 'options') if key in node}
    if 'volumes' in ordered:
        mounts = []
        for mount in ordered['volumes']:
            if not isinstance(mount, dict) or set(mount) - {'type', 'source', 'target', 'read_only', 'bind'}:
                raise NamespaceRefused('compose_hash_unavailable')
            item = {key: mount[key] for key in ('type', 'source', 'target', 'read_only') if key in mount}
            if 'bind' in mount:
                bind = mount['bind']
                fields = ('selinux', 'propagation', 'create_host_path', 'recursive')
                if not isinstance(bind, dict) or set(bind) - set(fields):
                    raise NamespaceRefused('compose_hash_unavailable')
                item['bind'] = {key: bind[key] for key in fields if key in bind}
            mounts.append(item)
        ordered['volumes'] = mounts
    try:
        payload = json.dumps(ordered, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
        # encoding/json escapes HTML and these two Unicode separators.
        for char, escaped in (('&', r'\u0026'), ('<', r'\u003c'), ('>', r'\u003e'),
                              ('\u2028', r'\u2028'), ('\u2029', r'\u2029')):
            payload = payload.replace(char, escaped)
        encoded = payload.encode()
        if len(encoded) > 16 * 1024 * 1024:
            raise NamespaceRefused('compose_hash_unavailable')
        return hashlib.sha256(encoded).hexdigest()
    except (TypeError, ValueError, UnicodeError):
        raise NamespaceRefused('compose_hash_unavailable') from None


def resolved_hash(selected, owner_id, unmodified_compose_hash):
    if (not isinstance(owner_id, str) or not HEX_ID.fullmatch(owner_id)
            or not isinstance(unmodified_compose_hash, str)
            or not HEX_ID.fullmatch(unmodified_compose_hash)
            or service_hash(selected) != unmodified_compose_hash):
        raise NamespaceRefused('compose_hash_unavailable')
    namespace_owner(selected)
    return service_hash({**selected, 'network_mode': 'container:' + owner_id})


# Each entry requires its own disposable qualification and independent review.
# A version string is insufficient: Docker's selected plugin bytes are bound too.
QUALIFIED_IMAGE_UPDATE_RUNTIME = (
    '29.7.1', '1.55', 'linux', 'amd64', '29.7.1', '1.55', 'v5.3.1',
    'f9ebc6ebdb19d769b793c245a736caaeb198c62587f13b25c660c13b4987f959',
)


def qualified_image_update_runtime():
    return _qualified_runtime(lambda: QUALIFIED_IMAGE_UPDATE_RUNTIME, 'namespace_unsupported_compose')


# Stage 2 configuration Apply/recovery has its own reviewed Layer A entry
# (2026-10-05). The image-update entry never implies Apply authority.
QUALIFIED_APPLY_RUNTIME = (
    '29.7.1', '1.55', 'linux', 'amd64', '29.7.1', '1.55', 'v5.3.1',
    'f9ebc6ebdb19d769b793c245a736caaeb198c62587f13b25c660c13b4987f959',
)


def qualified_apply_runtime():
    return _qualified_runtime(lambda: QUALIFIED_APPLY_RUNTIME, 'namespace_apply_unqualified')


def _qualified_runtime(allowed, reason):
    """Observe the selected Compose implementation afresh; never cache trust."""
    try:
        def bounded_json(argv):
            raw = run(argv, timeout=30)
            if len(raw) > 65536:
                raise ValueError()
            return json.loads(raw)
        versions = bounded_json(['docker', 'version', '--format', '{{json .}}'])
        plugins = bounded_json(['docker', 'info', '--format', '{{json .ClientInfo.Plugins}}'])
        compose_version = bounded_json(['docker', 'compose', 'version', '--format', 'json'])
        selected = [item for item in plugins if item.get('Name') == 'compose']
        if len(selected) != 1 or selected[0].get('Version') != compose_version.get('version'):
            raise ValueError()
        path = selected[0]['Path']
        if not isinstance(path, str) or not os.path.isabs(path):
            raise ValueError()
        with open(path, 'rb') as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 128 * 1024 * 1024:
                raise ValueError()
            digest = hashlib.sha256()
            total = 0
            while chunk := source.read(65536):
                total += len(chunk)
                if total > 128 * 1024 * 1024:
                    raise ValueError()
                digest.update(chunk)
            after = os.fstat(source.fileno())
        signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if signature(before) != signature(after) or signature(after) != signature(os.stat(path)):
            raise ValueError()
        server, client = versions['Server'], versions['Client']
        identity = (server['Version'], server['ApiVersion'], server['Os'], server['Arch'],
                    client['Version'], client['ApiVersion'], compose_version['version'], digest.hexdigest())
        if identity != allowed():
            raise ValueError()
        return identity
    except Exception:
        raise NamespaceRefused(reason) from None


# No Config/environment, mounts or raw kernel inode leaves this observation.
_OBSERVE = ('{"id":{{json .Id}},"image_id":{{json .Image}},'
            '"network_mode":{{json .HostConfig.NetworkMode}},"state":{{json .State.Status}},'
            '"pid":{{json .State.Pid}},"started_at":{{json .State.StartedAt}},'
            '"restart_count":{{json .RestartCount}},"health":{{with index .State "Health"}}{{json .Status}}{{else}}"none"{{end}},'
            '"has_healthcheck":{{with index .Config "Healthcheck"}}{{with index . "Test"}}{{if eq (index . 0) "NONE"}}false{{else}}true{{end}}{{else}}false{{end}}{{else}}false{{end}},'
            '"networks":{{json .NetworkSettings.Networks}},"ports":{{json .HostConfig.PortBindings}}}')


def observe(service):
    try:
        raw = run(['docker', 'inspect', '--type', 'container', '--format', _OBSERVE, service.container_id], timeout=30)
        if len(raw) > 65536:
            raise ValueError()
        value = json.loads(raw)
        if (value['id'] != service.container_id or value['image_id'] != service.image_id
                or value['state'] != service.state or value['health'] != service.health
                or value['started_at'] != service.started_at
                or type(value['pid']) is not int or value['pid'] <= 0
                or type(value['restart_count']) is not int or value['restart_count'] < 0):
            raise ValueError()
        return value
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        raise NamespaceRefused('namespace_owner_changed') from None


def _start(value):
    # Preserve RFC3339 nanoseconds; datetime alone truncates Docker timestamps.
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)', value or '')
    if not match:
        raise NamespaceRefused('namespace_owner_unproven')
    try:
        date = datetime.fromisoformat(match[1] + match[3].replace('Z', '+00:00'))
        seconds = (date.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()
        return int(seconds) * 10**9 + int((match[2] or '').ljust(9, '0'))
    except ValueError:
        raise NamespaceRefused('namespace_owner_unproven') from None


_OWNER_FORBIDDEN = ('network_mode', 'pid', 'ipc', 'uts', 'depends_on', 'develop', 'provider', 'deploy', 'tmpfs')


def _relationship(service, selected, owner_name, owner_model):
    """Strict supported same-project relationship; returns the readiness condition."""
    if (owner_name == service.compose_service or not isinstance(owner_model, dict)
            or set(selected) & FORBIDDEN
            or hash_excluded_fields_present(owner_model)
            or any(key in owner_model for key in _OWNER_FORBIDDEN)):
        raise NamespaceRefused('namespace_owner_unproven')
    dependency = selected.get('depends_on')
    condition = 'service_started'
    if dependency is not None:
        if not isinstance(dependency, dict) or set(dependency) != {owner_name}:
            raise NamespaceRefused('service_resource_unproven')
        hint = dependency[owner_name]
        if (not isinstance(hint, dict) or set(hint) != {'condition', 'required'}
                or hint['required'] is not True or hint['condition'] not in {'service_started', 'service_healthy'}):
            raise NamespaceRefused('service_resource_unproven')
        condition = hint['condition']
    return condition


def _member(found, service, name):
    """The unique running, non-one-off project member with proved Compose labels."""
    matches = [s for s in found if s.stack == service.stack and s.compose_service == name]
    if len(matches) != 1:
        raise NamespaceRefused('namespace_owner_unproven')
    item = matches[0]
    labels = item.labels or {}
    if (item.state != 'running' or item.working_dir != service.working_dir
            or item.compose_files != service.compose_files
            or labels.get('com.docker.compose.project') != service.stack
            or labels.get('com.docker.compose.service') != name
            or labels.get('com.docker.compose.project.working_dir') != service.working_dir
            or labels.get('com.docker.compose.project.config_files') != ','.join(service.compose_files)
            or labels.get('com.docker.compose.oneoff', '').lower() != 'false'
            or not HEX_ID.fullmatch(item.container_id)):
        raise NamespaceRefused('namespace_owner_unproven')
    return item


def resolve_namespace(service, model, *, context_reader, hash_reader, image_verifier, mounts_reader, found=None):
    """Extend the shared proof using the owner's ordinary shared context branch."""
    selected = model['services'][service.compose_service]
    owner_name = namespace_owner(selected)
    owner_model = model['services'].get(owner_name)
    condition = _relationship(service, selected, owner_name, owner_model)
    found = discover(all_containers=True) if found is None else found
    members = [_member(found, service, name) for name in (service.compose_service, owner_name)]
    consumer, owner = members
    if consumer.container_id != service.container_id:
        raise NamespaceRefused('namespace_owner_changed')
    before_s, before_o = observe(consumer), observe(owner)
    if before_s['network_mode'] != 'container:' + owner.container_id:
        raise NamespaceRefused('namespace_owner_replaced')
    if before_s['networks'] or before_s['ports']:
        raise NamespaceRefused('network_unproven')
    if _start(before_s['started_at']) <= _start(before_o['started_at']):
        raise NamespaceRefused('namespace_stale')
    if (before_o['health'] not in {'none', 'healthy'}
            or (before_o['has_healthcheck'] and before_o['health'] != 'healthy')
            or (condition == 'service_healthy' and not before_o['has_healthcheck'])):
        raise NamespaceRefused('namespace_owner_unhealthy')
    runtime_hash = (owner.labels or {}).get(HASH_LABEL)
    if (not isinstance(runtime_hash, str) or not HEX_ID.fullmatch(runtime_hash)
            or owner_model.get('image') != owner.image or hash_reader(owner) != runtime_hash):
        raise NamespaceRefused('namespace_owner_unproven')
    try:
        image_verifier(owner)
        owner_context = context_reader(owner, model)
        mounts_reader(owner, owner_model)
        mounts_reader(consumer, selected)
    except Exception:
        raise NamespaceRefused('namespace_owner_unproven') from None
    equal = None
    try:
        consumer_ns = os.readlink(f"/proc/{before_s['pid']}/ns/net")
        owner_ns = os.readlink(f"/proc/{before_o['pid']}/ns/net")
    except OSError:
        pass  # Optional for read-only truth. Stage 1 never permits mutation.
    else:
        if not re.fullmatch(r'net:\[\d+\]', consumer_ns) or consumer_ns != owner_ns:
            raise NamespaceRefused('namespace_stale')
        equal = True
    if before_s != observe(consumer) or before_o != observe(owner):
        raise NamespaceRefused('namespace_owner_changed')
    return owner, NamespaceOwnerEvidence(owner_name, owner.container_id, owner.image_id, owner.image,
                                         runtime_hash, owner.state, owner.health, owner.started_at,
                                         before_o['restart_count'], owner_context, before_s['network_mode'],
                                         consumer.started_at, equal)


# --- Stage 2: stable owner-only proof, separate per-consumer proof ----------

def _inspect(container_id):
    """Raw bounded observation; callers decide which fields must be stable."""
    try:
        raw = run(['docker', 'inspect', '--type', 'container', '--format', _OBSERVE, container_id], timeout=30)
        if len(raw) > 65536:
            raise ValueError()
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('id') != container_id
                or not isinstance(value.get('image_id'), str) or not isinstance(value.get('network_mode'), str)
                or not isinstance(value.get('state'), str) or not isinstance(value.get('health'), str)
                or not isinstance(value.get('started_at'), str) or type(value.get('has_healthcheck')) is not bool
                or type(value.get('pid')) is not int or value['pid'] < 0
                or type(value.get('restart_count')) is not int or value['restart_count'] < 0):
            raise ValueError()
        return value
    except (OSError, RuntimeError, ValueError, TypeError, KeyError):
        raise NamespaceRefused('namespace_owner_changed') from None


def _netns(pid):
    """Mandatory kernel identity for Stage 2; unavailable is never equality."""
    try:
        value = os.readlink(f'/proc/{int(pid)}/ns/net')
    except (OSError, ValueError, TypeError):
        raise NamespaceRefused('namespace_stale') from None
    if not isinstance(value, str) or not re.fullmatch(r'net:\[\d+\]', value):
        raise NamespaceRefused('namespace_stale')
    return value


@dataclass(frozen=True)
class NamespaceOwnerProof:
    """Owner-only identity. It contains no consumer-dependent fact, so it is
    compared exactly at every checkpoint, across intended consumer replacement."""
    service: str
    container_id: str
    image: str
    image_id: str
    runtime_hash: str
    project: str
    working_dir: str
    compose_files: tuple
    network_mode: str
    state: str
    health: str
    has_healthcheck: bool
    started_at: str
    restart_count: int
    context: str
    pid: int
    netns: str


@dataclass(frozen=True)
class NamespaceConsumerProof:
    container_id: str
    image: str
    image_id: str
    runtime_hash: str
    state: str
    health: str
    started_at: str
    restart_count: int
    pid: int
    network_mode: str

    def identity(self):
        """Stable identity; an ordinary starting-to-healthy transition is not drift."""
        return (self.container_id, self.image, self.image_id, self.runtime_hash, self.started_at,
                self.restart_count, self.pid, self.network_mode)


def prove_owner(service, owner_name, owner_model, *, condition, found, context_reader, context_model,
                hash_reader, image_verifier, mounts_reader):
    """Owner-only proof. It never requires, inspects or trusts a consumer.

    It cannot refresh authority: callers compare the result with the reviewed
    proof. hash_reader may evaluate live sources or return the bound reviewed
    hash while a multi-file source transition makes the live model inconsistent.
    """
    if (not isinstance(owner_model, dict) or hash_excluded_fields_present(owner_model)
            or any(key in owner_model for key in _OWNER_FORBIDDEN)
            or condition not in {'service_started', 'service_healthy'}):
        raise NamespaceRefused('namespace_owner_unproven')
    owner = _member(found, service, owner_name)
    before = _inspect(owner.container_id)
    if (before['state'] != 'running' or before['pid'] <= 0 or before['image_id'] != owner.image_id
            or before['started_at'] != owner.started_at):
        raise NamespaceRefused('namespace_owner_changed')
    if (before['health'] not in {'none', 'healthy'}
            or (before['has_healthcheck'] and before['health'] != 'healthy')
            or (condition == 'service_healthy' and not before['has_healthcheck'])):
        raise NamespaceRefused('namespace_owner_unhealthy')
    runtime_hash = (owner.labels or {}).get(HASH_LABEL)
    if (not isinstance(runtime_hash, str) or not HEX_ID.fullmatch(runtime_hash)
            or owner_model.get('image') != owner.image):
        raise NamespaceRefused('namespace_owner_unproven')
    try:
        if hash_reader(owner) != runtime_hash:
            raise ValueError()
        image_verifier(owner)
        context = context_reader(owner, context_model)
        mounts_reader(owner, owner_model)
    except Exception:
        raise NamespaceRefused('namespace_owner_unproven') from None
    netns = _netns(before['pid'])
    if _inspect(owner.container_id) != before:
        raise NamespaceRefused('namespace_owner_changed')
    return NamespaceOwnerProof(owner_name, owner.container_id, owner.image, owner.image_id, runtime_hash,
                               service.stack, service.working_dir, tuple(service.compose_files),
                               before['network_mode'], before['state'], before['health'],
                               before['has_healthcheck'], before['started_at'], before['restart_count'],
                               context, before['pid'], netns)


def prove_consumer(service, owner, selected_model, *, found, mounts_reader):
    """Running consumer joined to exactly this proved owner, with kernel equality.

    selected_model is phase specific: trusted baseline before Apply, desired
    after Apply and baseline after recovery. Health is reported, not judged.
    """
    consumer = _member(found, service, service.compose_service)
    before = _inspect(consumer.container_id)
    if before['state'] != 'running' or before['pid'] <= 0 or before['image_id'] != consumer.image_id:
        raise NamespaceRefused('namespace_owner_changed')
    if before['network_mode'] != 'container:' + owner.container_id:
        raise NamespaceRefused('namespace_owner_replaced')
    if before['networks'] or before['ports']:
        raise NamespaceRefused('network_unproven')
    if _start(before['started_at']) <= _start(owner.started_at):
        raise NamespaceRefused('namespace_stale')
    try:
        mounts_reader(consumer, selected_model)
    except Exception:
        raise NamespaceRefused('runtime_mounts_unproven') from None
    if _netns(before['pid']) != owner.netns or _netns(owner.pid) != owner.netns:
        raise NamespaceRefused('namespace_stale')
    current_owner = _inspect(owner.container_id)
    if (current_owner['pid'], current_owner['started_at'], current_owner['state']) != (owner.pid, owner.started_at, owner.state):
        raise NamespaceRefused('namespace_owner_changed')
    after = _inspect(consumer.container_id)
    if {**after, 'health': None} != {**before, 'health': None}:
        raise NamespaceRefused('namespace_owner_changed')
    return NamespaceConsumerProof(consumer.container_id, consumer.image, consumer.image_id,
                                  str((consumer.labels or {}).get(HASH_LABEL)), after['state'], after['health'],
                                  after['started_at'], after['restart_count'], after['pid'], after['network_mode'])


def canonical_relationship(selected):
    """network_mode plus canonical depends_on, including absence."""
    return (selected.get('network_mode'), json.dumps(selected.get('depends_on'), sort_keys=True, separators=(',', ':')))


@dataclass(frozen=True)
class NamespaceApplyAuthority:
    """Typed, server-owned admission for one reviewed consumer and owner.

    Only reviewed Stage 2 configuration Apply constructs this. It is never a
    generic switch: it binds the logical service, exact owner ID and the
    immutable relationship, and every other operation keeps the default refusal.
    """
    logical_key: str
    owner_id: str
    relationship: tuple

    def admits(self, service, current_mode, selected):
        from .compose_baseline import logical_key
        return (service.stack and service.compose_service and service.working_dir and service.compose_files
                and logical_key(service.stack, service.compose_service, service.working_dir,
                                service.compose_files) == self.logical_key
                and HEX_ID.fullmatch(self.owner_id) is not None
                and current_mode == 'container:' + self.owner_id
                and isinstance(selected, dict) and canonical_relationship(selected) == self.relationship)


@dataclass(frozen=True)
class RuntimeNamespaceReference:
    container_id: str
    network_mode: str
    project: str | None
    service: str | None


def runtime_relationships():
    """All projects and stopped containers, without parsing Compose or images."""
    try:
        ids = run(['docker', 'ps', '-aq', '--no-trunc'], timeout=30).split()
        if len(ids) > 4096 or len(set(ids)) != len(ids) or any(not HEX_ID.fullmatch(item) for item in ids):
            raise ValueError()
        if not ids:
            return ()
        raw = run(['docker', 'inspect', '--type', 'container', '--format',
                   '[{{json .Id}},{{json .HostConfig.NetworkMode}},{{with index .Config "Labels"}}{{json (index . "com.docker.compose.project")}}{{else}}null{{end}},{{with index .Config "Labels"}}{{json (index . "com.docker.compose.service")}}{{else}}null{{end}}]', *ids], timeout=30)
        if len(raw) > 1024 * 1024:
            raise ValueError()
        values = [json.loads(line) for line in raw.splitlines()]
        if (len(values) != len(ids)
                or any(not isinstance(item, list) or len(item) != 4 or not isinstance(item[0], str)
                       or not isinstance(item[1], str)
                       or any(value is not None and not isinstance(value, str) for value in item[2:]) for item in values)
                or {item[0] for item in values} != set(ids)):
            raise ValueError()
        return tuple(RuntimeNamespaceReference(*item) for item in values)
    except (OSError, RuntimeError, ValueError, TypeError, IndexError):
        raise NamespaceRefused('namespace_owner_unproven') from None


def mutation_refusal(service, *, model=None, allow_absent=False, _image_update=False, namespace_apply=None):
    """Runtime references independently protect owners even with broken sources.

    namespace_apply must be a reviewed NamespaceApplyAuthority; anything else,
    including a bare boolean, retains the default consumer refusal.
    """
    if namespace_apply is not None and (_image_update or allow_absent
                                        or not isinstance(namespace_apply, NamespaceApplyAuthority)):
        return 'namespace_unsupported_compose'
    relationships = runtime_relationships()
    targets = {service.container_id}
    if service.stack and service.compose_service:
        # Compose service commands can affect replicas of the selected service.
        targets.update(item.container_id for item in relationships
                       if item.project == service.stack and item.service == service.compose_service)
    target_modes = {'container:' + identity for identity in targets}
    if any(item.network_mode in target_modes for item in relationships):
        return 'namespace_owner_has_dependents'
    current = [item.network_mode for item in relationships if item.container_id == service.container_id]
    if len(current) != 1 and not (allow_absent and not current):
        return 'namespace_owner_unproven'
    reviewed = namespace_apply is not None
    if (not _image_update and not reviewed
            and ((current and current[0].startswith('container:')) or (not current and (service.network_mode or '').startswith('container:')))):
        return 'namespace_unsupported_compose'
    if reviewed and not service.stack:
        return 'namespace_unsupported_compose'
    if service.stack:
        if model is None:
            try:
                raw = run(compose_args(service) + ['config', '--format', 'json'], cwd=service.working_dir, timeout=30)
                if len(raw) > 16 * 1024 * 1024:
                    raise ValueError()
                model = json.loads(raw)
            except (OSError, RuntimeError, ValueError):
                return 'namespace_owner_unproven'
        services = model.get('services') if isinstance(model, dict) else None
        if not isinstance(services, dict):
            return 'namespace_owner_unproven'
        if any(isinstance(node, dict) and node.get('network_mode') == 'service:' + service.compose_service
               for node in services.values()):
            return 'namespace_owner_has_dependents'
        selected = services.get(service.compose_service)
        if not isinstance(selected, dict):
            return 'namespace_owner_unproven'
        if reviewed:
            if not namespace_apply.admits(service, current[0], selected):
                return 'namespace_unsupported_compose'
        elif not _image_update and ('network_mode' in selected or 'depends_on' in selected):
            return 'namespace_unsupported_compose'
    return None


def require_mutation_safe(service, *, model=None, allow_absent=False):
    # Import lazily: operations uses this core helper too.
    from .compose_drift import REASONS
    from .operations import PreMutationRefusal
    try:
        reason = mutation_refusal(service, model=model, allow_absent=allow_absent)
    except NamespaceRefused as exc:
        reason = exc.reason
    if reason:
        raise PreMutationRefusal(REASONS[reason], reason)
