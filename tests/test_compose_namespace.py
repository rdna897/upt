"""Stage 1 synthetic safety/truth tests. No real Docker, browser or /proc calls."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import copy
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import yaml

from docker_update_manager import compose_namespace as ns, operations, webservice
from docker_update_manager.compose_baseline import BaselineStore
from docker_update_manager.compose_bootstrap import make_plan, do_compose_bootstrap, BootstrapRefused, BootstrapExecutionFailed
from docker_update_manager.compose_drift import IN_SYNC, UNVERIFIABLE, ComposePreflightRefused, build_inventory
from docker_update_manager.compose_reconcile import do_compose_reconcile
from docker_update_manager.config import Config
from docker_update_manager.conversion import generate_conversion, deploy_conversion, rollback_conversion
from docker_update_manager.models import Service
from docker_update_manager.removal import remove_service
from docker_update_manager.state import State

OWNER_ID = 'a' * 64
CONSUMER_ID = 'b' * 64
IMAGE_ID = 'sha256:' + '1' * 64
OWNER_HASH = 'e' * 64
CONSUMER_MODEL = {'image': 'example/consumer:1', 'network_mode': 'service:owner',
                  'command': None, 'entrypoint': None, 'restart': 'unless-stopped',
                  'depends_on': {'owner': {'condition': 'service_healthy', 'required': True}}}


class HashTests(unittest.TestCase):
    def test_golden_resolved_hash_and_exact_id(self):
        # Literal Go ServiceConfig JSON, including nil command/entrypoint.
        oracle_bytes = b'{"command":null,"entrypoint":null,"image":"example/consumer:1","network_mode":"service:owner","restart":"unless-stopped"}'
        oracle = hashlib.sha256(oracle_bytes).hexdigest()
        resolved_bytes = oracle_bytes.replace(b'service:owner', ('container:' + OWNER_ID).encode())
        self.assertEqual(ns.resolved_hash(CONSUMER_MODEL, OWNER_ID, oracle), hashlib.sha256(resolved_bytes).hexdigest())
        for invalid in ('owner', OWNER_ID[:12], '', 'z' * 64):
            with self.subTest(invalid=invalid), self.assertRaises(ns.NamespaceRefused):
                ns.resolved_hash(CONSUMER_MODEL, invalid, oracle)
        self.assertEqual(CONSUMER_MODEL['network_mode'], 'service:owner')

    def test_calibration_fails_closed_and_is_not_reused(self):
        oracle = ns.service_hash(CONSUMER_MODEL)
        self.assertTrue(ns.resolved_hash(CONSUMER_MODEL, OWNER_ID, oracle))
        for oracle in (None, '0' * 64, 'bad'):
            with self.subTest(oracle=oracle), self.assertRaises(ns.NamespaceRefused) as refused:
                ns.resolved_hash(CONSUMER_MODEL, OWNER_ID, oracle)
            self.assertEqual(refused.exception.reason, 'compose_hash_unavailable')

    def test_go_map_html_and_bind_struct_serialization(self):
        selected = {'image': 'example/consumer:1', 'network_mode': 'service:owner',
                    'environment': {'Z': '<&>\u2028', 'A': 'ok'},
                    'volumes': [{'bind': {'create_host_path': True, 'propagation': 'rprivate'},
                                 'target': '/config', 'source': '/synthetic/config', 'type': 'bind'}]}
        expected = ('{"command":null,"entrypoint":null,"environment":{"A":"ok","Z":"\\u003c\\u0026\\u003e\\u2028"},'
                    '"image":"example/consumer:1","network_mode":"service:owner",'
                    '"volumes":[{"type":"bind","source":"/synthetic/config","target":"/config",'
                    '"bind":{"propagation":"rprivate","create_host_path":true}}]}')
        self.assertEqual(ns.service_hash(selected), hashlib.sha256(expected.encode()).hexdigest())
        with self.assertRaises(ns.NamespaceRefused):
            ns.service_hash({**selected, 'future_field': True})


class NamespaceFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'compose.yml'
        self.model = {'name': 'synthetic', 'services': {'consumer': copy.deepcopy(CONSUMER_MODEL),
                       'owner': {'image': 'example/owner:1'}},
                      'networks': {'default': {'name': 'synthetic_default', 'ipam': {}}}}
        self.write_source()
        self.consumer = self.service('consumer', CONSUMER_ID, ns.resolved_hash(CONSUMER_MODEL, OWNER_ID, ns.service_hash(CONSUMER_MODEL)))
        self.owner = self.service('owner', OWNER_ID, OWNER_HASH)
        self.runtime = [self.consumer, self.owner]
        self.observations = {CONSUMER_ID: self.observation(self.consumer, 'container:' + OWNER_ID, 102, False),
                             OWNER_ID: self.observation(self.owner, 'synthetic_default', 101, True)}
        self.hash_fault = False
        self.network_fault = False
        self.mount_fault = False
        self.calls = []
        self.state = State(self.root / 'state')
        self.agent = webservice.ReadOnlyService(Config(path=str(self.root / 'config.yml')), self.state)
        # Same-project refresh is a background follow-up; tests opt in explicitly.
        self.project_refresh_patch = patch.object(self.agent, "_queue_project_refresh", return_value="queued")
        self.project_refresh = self.project_refresh_patch.start()
        self.addCleanup(self.project_refresh_patch.stop)
        for target in ('compose_namespace.run', 'webservice.run', 'compose_reconcile.run'):
            mocked = patch('docker_update_manager.' + target, side_effect=self.docker_run)
            mocked.start(); self.addCleanup(mocked.stop)
        for target in ('compose_namespace.discover', 'webservice.discover', 'operations.discover'):
            mocked = patch('docker_update_manager.' + target, side_effect=lambda *a, **kw: list(self.runtime))
            mocked.start(); self.addCleanup(mocked.stop)
        mocked = patch('docker_update_manager.compose_namespace.os.readlink', side_effect=PermissionError())
        mocked.start(); self.addCleanup(mocked.stop)

    def write_source(self):
        self.source.write_text(yaml.safe_dump(self.model))

    def service(self, name, identity, runtime_hash):
        labels = {'com.docker.compose.project': 'synthetic', 'com.docker.compose.service': name,
                  'com.docker.compose.project.working_dir': str(self.root),
                  'com.docker.compose.project.config_files': str(self.source),
                  'com.docker.compose.oneoff': 'False', ns.HASH_LABEL: runtime_hash}
        return Service(name, identity, 'example/' + name + ':1', IMAGE_ID, 'sha256:' + '2' * 64,
                       '1', None, 'amd64', 'running', 'healthy' if name == 'owner' else 'none',
                       'unless-stopped', '2026-10-04T12:00:00.000000001Z' if name == 'owner' else '2026-10-04T12:00:00.000000002Z',
                       'synthetic', name, str(self.root), [str(self.source)], labels,
                       network_mode='container:' + OWNER_ID if name == 'consumer' else 'synthetic_default')

    @staticmethod
    def observation(service, mode, pid, healthcheck):
        return {'id': service.container_id, 'image_id': service.image_id, 'network_mode': mode,
                'state': service.state, 'health': service.health, 'started_at': service.started_at,
                'pid': pid, 'restart_count': 0, 'has_healthcheck': healthcheck,
                'networks': {} if mode.startswith('container:') else {'synthetic_default': {'NetworkID': 'c' * 64}},
                'ports': {}}

    def docker_run(self, args, **kw):
        self.calls.append(list(args))
        if args[:3] == ['docker', 'ps', '-aq']:
            return '\n'.join(self.observations)
        if args[:3] == ['docker', 'inspect', '--type']:
            template = args[5]
            if template == ns._OBSERVE:
                return json.dumps(self.observations[args[-1]])
            if template.startswith('[{{json .Id}}'):
                return '\n'.join(json.dumps([key, self.observations[key]['network_mode'],
                    next((s.stack for s in self.runtime if s.container_id == key), None),
                    next((s.compose_service for s in self.runtime if s.container_id == key), None)]) for key in args[6:])
            if template == '{{json .Mounts}}':
                return json.dumps([{'Type': 'volume'}] if self.mount_fault else [])
            if template == '{{json .NetworkSettings.Networks}}':
                return json.dumps(self.observations[args[-1]]['networks'])
        if args[:3] == ['docker', 'network', 'inspect']:
            if self.network_fault:
                raise RuntimeError('synthetic fault')
            return json.dumps({'Id': 'c' * 64, 'Name': 'synthetic_default', 'Driver': 'bridge',
                               'Internal': False, 'Attachable': False, 'Ingress': False, 'Scope': 'local',
                               'EnableIPv6': False, 'IPAM': {'Driver': 'default'}, 'Options': {},
                               'Labels': {'com.docker.compose.project': 'synthetic', 'com.docker.compose.network': 'default'}})
        if args[:3] == ['docker', 'image', 'inspect']:
            return IMAGE_ID
        if args[:2] == ['docker', 'compose'] and 'config' in args:
            if '--hash' in args:
                name = args[-1]
                value = ('0' * 64 if self.hash_fault else ns.service_hash(self.model['services'][name])) if name == 'consumer' else OWNER_HASH
                return name + ' ' + value
            return json.dumps(self.model)
        raise AssertionError(args)

    def plan(self, service=None, persist=False):
        return self.agent._compose_plan(service or self.consumer, self.runtime, persist=persist)

    def context(self):
        return webservice._execution_context_fingerprint(self.consumer, self.model)

    def records(self):
        return BaselineStore(self.state).records(self.agent._baseline_key(self.consumer))


class ClassificationTests(NamespaceFixture):
    def test_in_sync_without_proc_captures_phase1_and_never_enables_mutation(self):
        plan = self.plan(persist=True)
        self.assertEqual(plan.status, IN_SYNC)
        self.assertEqual(plan.desired_hash, self.consumer.labels[ns.HASH_LABEL])
        self.assertFalse(plan.update_eligible)
        self.assertFalse(plan.apply_eligible)
        self.assertIn('namespace_unsupported_compose', plan.update_reasons)
        self.assertEqual(plan.baseline.record.origin, 'captured')
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(self.plan(persist=True).baseline.record.id, plan.baseline.record.id)
        self.assertTrue(all('up' not in command and 'restart' not in command for command in self.calls))

    def test_hash_calibration_failure_never_captures(self):
        self.hash_fault = True
        plan = self.plan(persist=True)
        self.assertEqual(plan.status, UNVERIFIABLE)
        self.assertIn('compose_hash_unavailable', plan.reasons)
        self.assertEqual(self.records(), [])

    def test_exact_owner_replaced_short_id_and_stale_refused(self):
        for mode, start, reason in [('container:' + 'd' * 64, self.owner.started_at, 'namespace_owner_replaced'),
                                    ('container:' + OWNER_ID[:12], self.owner.started_at, 'namespace_owner_replaced'),
                                    ('container:' + OWNER_ID, self.consumer.started_at, 'namespace_stale')]:
            with self.subTest(reason=reason):
                self.owner.started_at = start
                self.observations[OWNER_ID]['started_at'] = start
                self.observations[CONSUMER_ID]['network_mode'] = mode
                plan = self.plan(persist=True)
                self.assertEqual(plan.status, UNVERIFIABLE)
                self.assertIn(reason, plan.reasons)
                self.assertEqual(self.records(), [])

    def test_unhealthy_stopped_replicated_oneoff_and_drifted_owner_refused(self):
        for change in ('unhealthy', 'stopped', 'replica', 'oneoff', 'hash', 'image', 'label'):
            with self.subTest(change=change):
                owner = copy.deepcopy(self.owner)
                old_observation = copy.deepcopy(self.observations[OWNER_ID])
                self.runtime = [self.consumer, owner]
                if change == 'unhealthy':
                    owner.health = self.observations[OWNER_ID]['health'] = 'unhealthy'
                elif change == 'stopped':
                    owner.state = 'exited'
                elif change == 'replica':
                    self.runtime.append(replace(owner, container_id='d' * 64))
                elif change == 'oneoff':
                    owner.labels['com.docker.compose.oneoff'] = 'True'
                elif change == 'hash':
                    owner.labels[ns.HASH_LABEL] = 'd' * 64
                elif change == 'image':
                    owner.image = 'example/owner:2'
                else:
                    owner.labels['com.docker.compose.project.working_dir'] = '/different'
                self.assertEqual(self.plan(persist=True).status, UNVERIFIABLE)
                self.assertEqual(self.records(), [])
                self.observations[OWNER_ID] = old_observation
        self.runtime = [self.consumer, self.owner]

    def test_full_context_and_mounts_required_before_direct_baseline_capture(self):
        inventory = build_inventory(self.consumer.compose_files, self.consumer.working_dir, model=self.model)
        for fault in ('network_fault', 'mount_fault'):
            with self.subTest(fault=fault):
                setattr(self, fault, True)
                self.assertEqual(self.plan(persist=True).status, UNVERIFIABLE)
                with self.assertRaises(webservice._ComposeCheckRaced):
                    self.agent._capture_baseline(self.consumer, self.consumer.labels[ns.HASH_LABEL], self.model, inventory)
                self.assertEqual(self.records(), [])
                setattr(self, fault, False)

    def test_capture_revalidates_owner_before_save(self):
        original = self.agent._confirm_runtime_unchanged
        def race(*args):
            original(*args)
            self.owner.health = self.observations[OWNER_ID]['health'] = 'unhealthy'
        with patch.object(self.agent, '_confirm_runtime_unchanged', side_effect=race):
            plan = self.plan(persist=True)
        self.assertEqual(plan.status, UNVERIFIABLE)
        self.assertEqual(self.records(), [])

    def test_fingerprint_binds_owner_identity_restart_health_and_network(self):
        original = self.context()
        for field, value in [('started_at', '2026-10-04T11:59:59Z'), ('restart_count', 1)]:
            old = self.observations[OWNER_ID][field]
            if field == 'started_at': self.owner.started_at = value
            self.observations[OWNER_ID][field] = value
            self.assertNotEqual(self.context(), original)
            self.observations[OWNER_ID][field] = old
            if field == 'started_at': self.owner.started_at = old
        self.owner.health = self.observations[OWNER_ID]['health'] = 'none'
        self.observations[OWNER_ID]['has_healthcheck'] = False
        self.model['services']['consumer']['depends_on']['owner']['condition'] = 'service_started'
        self.assertNotEqual(self.context(), original)
        old_id = self.owner.container_id
        self.owner.container_id = 'd' * 64
        self.observations[self.owner.container_id] = self.observations.pop(old_id)
        self.observations[self.owner.container_id]['id'] = self.owner.container_id
        self.observations[CONSUMER_ID]['network_mode'] = 'container:' + self.owner.container_id
        self.assertNotEqual(self.context(), original)

    def test_context_binds_declared_ordering_hint_despite_hash_exclusion(self):
        original = self.context()
        unresolved_hash = ns.service_hash(self.model['services']['consumer'])
        self.model['services']['consumer']['depends_on']['owner']['condition'] = 'service_started'
        self.assertEqual(ns.service_hash(self.model['services']['consumer']), unresolved_hash)
        self.assertNotEqual(self.context(), original)
        self.model['services']['consumer'].pop('depends_on')
        self.assertEqual(self.plan().status, IN_SYNC)
        self.assertNotEqual(self.context(), original)

    def test_owner_change_after_initial_hash_is_unverifiable(self):
        real = self.agent._compose_service_hash
        def race(*args, **kwargs):
            result = real(*args, **kwargs)
            self.owner.health = self.observations[OWNER_ID]['health'] = 'unhealthy'
            return result
        with patch.object(self.agent, '_compose_service_hash', side_effect=race):
            plan = self.plan()
        self.assertEqual(plan.status, UNVERIFIABLE)
        self.assertIn('namespace_owner_unhealthy', plan.reasons)

    def test_retained_source_requires_owner_hash_from_same_private_copy(self):
        plan = self.plan(persist=True)
        inputs = {item.path: item for item in plan.baseline.inputs if item.role in {'compose', 'project_env'}}
        self.assertIsNotNone(self.agent._reproduce_candidate(self.consumer, plan.runtime_hash, inputs))
        real = self.docker_run
        def bad_owner(args, **kwargs):
            if '--env-file' in args and '--hash' in args and args[-1] == 'owner':
                return 'owner ' + 'd' * 64
            return real(args, **kwargs)
        with patch.object(webservice, 'run', side_effect=bad_owner):
            self.assertIsNone(self.agent._reproduce_candidate(self.consumer, plan.runtime_hash, inputs))
        self.assertEqual(list((self.state.root / 'tmp').iterdir()), [])

    def test_capture_compose_oracle_failure_is_unverifiable(self):
        real = self.agent._compose_service_hash
        calls = []
        def race(*args, **kwargs):
            calls.append(1)
            if len(calls) > 1:
                raise operations.PreMutationRefusal('synthetic unavailable', 'compose_unverifiable')
            return real(*args, **kwargs)
        with patch.object(self.agent, '_compose_service_hash', side_effect=race):
            plan = self.plan(persist=True)
        self.assertEqual(plan.status, UNVERIFIABLE)
        self.assertIn('compose_hash_unavailable', plan.reasons)
        self.assertEqual(self.records(), [])

    def test_available_proc_must_match_and_pid_revalidation_detects_race(self):
        with patch.object(ns.os, 'readlink', return_value='net:[123]'):
            self.assertTrue(self.context())
        with patch.object(ns.os, 'readlink', side_effect=['net:[123]', 'net:[456]']):
            self.assertIn('namespace_stale', self.plan().reasons)
        def race(path):
            self.observations[OWNER_ID]['pid'] += 1
            return 'net:[123]'
        with patch.object(ns.os, 'readlink', side_effect=race):
            self.assertIn('namespace_owner_changed', self.plan().reasons)

    def test_source_and_runtime_races_fail_closed(self):
        real = self.docker_run
        def source_race(args, **kw):
            value = real(args, **kw)
            if '--hash' in args and args[-1] == 'consumer':
                self.source.write_text(self.source.read_text() + '# concurrent edit\n')
            return value
        with patch.object(webservice, 'run', side_effect=source_race):
            self.assertIn('sources_changed_during_check', self.plan(persist=True).reasons)
        self.assertEqual(self.records(), [])

    def test_external_container_reference_cannot_capture_from_hash_equality(self):
        selected = self.model['services']['consumer']
        selected['network_mode'] = 'container:' + OWNER_ID
        selected.pop('depends_on')
        self.consumer.labels[ns.HASH_LABEL] = ns.service_hash(selected)
        self.write_source()
        plan = self.plan(persist=True)
        self.assertEqual(plan.status, UNVERIFIABLE)
        self.assertIn('network_unproven', plan.reasons)
        self.assertEqual(self.records(), [])
        inventory = build_inventory(self.consumer.compose_files, self.consumer.working_dir, model=self.model)
        with self.assertRaises(webservice._ComposeCheckRaced):
            self.agent._capture_baseline(self.consumer, self.consumer.labels[ns.HASH_LABEL], self.model, inventory)

    def test_explicit_exclusions_and_dependency_shapes(self):
        selected = self.model['services']['consumer']
        for field in ns.FORBIDDEN:
            with self.subTest(field=field):
                selected[field] = {}  # Presence matters even for empty settings.
                self.assertEqual(self.plan(persist=True).status, UNVERIFIABLE)
                selected.pop(field)
        for dependency in ({'other': {'condition': 'service_started', 'required': True}},
                           {'owner': {'condition': 'service_completed_successfully', 'required': True}},
                           {'owner': {'condition': 'service_started', 'required': False}},
                           {'owner': {'condition': 'service_started', 'required': True, 'restart': False}}, []):
            with self.subTest(dependency=dependency):
                selected['depends_on'] = dependency
                self.assertEqual(self.plan().status, UNVERIFIABLE)
        selected['depends_on'] = CONSUMER_MODEL['depends_on']
        for mode in ('container:' + OWNER_ID, 'container:owner', 'host', 'none', 'bridge', 'service:consumer', 'service:absent', 'service:other/owner'):
            with self.subTest(mode=mode):
                selected['network_mode'] = mode
                plan = self.plan()
                self.assertFalse(plan.update_eligible)
                self.assertFalse(plan.apply_eligible)
                with self.assertRaises(webservice._ExecutionContextRefused):
                    self.context()
        selected['network_mode'] = 'service:owner'
        for field in ('network_mode', 'pid', 'ipc', 'uts', 'depends_on'):
            with self.subTest(owner_field=field):
                self.model['services']['owner'][field] = 'service:other'
                self.assertEqual(self.plan().status, UNVERIFIABLE)
                self.model['services']['owner'].pop(field)
        self.assertEqual(self.records(), [])

    def test_health_condition_no_healthcheck_allowed_only_for_started(self):
        self.owner.health = self.observations[OWNER_ID]['health'] = 'none'
        self.observations[OWNER_ID]['has_healthcheck'] = False
        self.assertIn('namespace_owner_unhealthy', self.plan().reasons)
        self.model['services']['consumer']['depends_on']['owner']['condition'] = 'service_started'
        # Hash excludes the declared ordering hint; runtime identity stays equal.
        self.assertEqual(self.plan().status, IN_SYNC)

    def test_consumer_update_review_refused_and_owner_status_protected(self):
        self.assertIn('namespace_owner_has_dependents', self.plan(self.owner).update_reasons)
        record = {'verification_id': 'synthetic-verification'}
        for selected, reason in ((self.consumer, 'namespace_unsupported_compose'), (self.owner, 'namespace_owner_has_dependents')):
            public = webservice._public_service(selected)
            with patch.object(self.agent, '_completed_update_candidate', return_value=(record, {}, public, selected, self.runtime)):
                with self.assertRaises(ComposePreflightRefused) as refused:
                    self.agent.update_review({'service_key': 'container/' + selected.container_id, 'requested_by': 'test',
                                              'verification_id': record['verification_id']})
            self.assertEqual(refused.exception.reason, reason)


class ProtectionTests(NamespaceFixture):
    def test_runtime_reference_is_sufficient_with_broken_source_any_project_stopped(self):
        self.source.write_text('not valid compose')
        self.observations[CONSUMER_ID]['state'] = 'exited'
        self.consumer.stack = 'another-project'
        self.assertEqual(ns.mutation_refusal(self.owner), 'namespace_owner_has_dependents')
        self.assertFalse(any(command[:2] == ['docker', 'compose'] for command in self.calls))

    def test_runtime_owner_replica_is_protected_by_service_scoped_commands(self):
        replica = replace(self.owner, container_id='d' * 64)
        self.runtime.append(replica)
        self.observations[replica.container_id] = self.observation(replica, 'synthetic_default', 103, True)
        self.observations[CONSUMER_ID]['network_mode'] = 'container:' + replica.container_id
        self.model['services'].pop('consumer')
        self.assertEqual(ns.mutation_refusal(self.owner, model=self.model), 'namespace_owner_has_dependents')

    def test_declared_source_relationship_protects_owner_without_runtime_consumer(self):
        self.observations.pop(CONSUMER_ID)
        self.assertEqual(ns.mutation_refusal(self.owner), 'namespace_owner_has_dependents')

    def test_unknown_runtime_inventory_fails_closed(self):
        with patch.object(ns, 'run', side_effect=RuntimeError('no Docker')):
            with self.assertRaises(operations.PreMutationRefusal) as refused:
                ns.require_mutation_safe(self.owner)
        self.assertEqual(refused.exception.reason, 'namespace_owner_unproven')

    def test_direct_cli_web_core_mutations_refused_before_side_effects(self):
        callbacks = {key: Mock() for key in ('verify_before_restore', 'verify_before_recreate', 'verify_recovery_sources', 'verify_pre_rollback_recovery')}
        actions = [lambda: operations.do_update(self.owner, self.state, yes=True),
                   lambda: operations._do_pinned_update(self.owner, self.state, yes=True),
                   lambda: operations.do_rollback(self.owner, self.state, yes=True),
                   lambda: operations.do_restart(self.owner),
                   lambda: operations.do_restart(self.owner, dry_run=True),
                   lambda: remove_service(self.owner, self.state, yes=True),
                   lambda: remove_service(self.owner, self.state, dry_run=True),
                   lambda: generate_conversion(self.owner, self.state, self.root, dry_run=True),
                   lambda: deploy_conversion(self.owner, self.state, self.root, {}, {}, yes=True),
                   lambda: operations.do_web_rollback(self.owner, {}, self.state, sources=[], operation_id='test', rollback_command=[], recovery_command=[], **callbacks),
                   lambda: do_compose_bootstrap(SimpleNamespace(service=self.owner, desired_model=self.model), self.state, operation_id='test', requester='test', client_ip='', user_agent='', revalidate=Mock(), discover_current=Mock(), verify_configuration=Mock(), verify_context=Mock()),
                   lambda: make_plan(self.owner, self.runtime, self.state, model_reader=Mock(), hash_reader=Mock(), context_reader=Mock(), mounts_reader=Mock(), baseline_available=Mock())]
        for action in actions:
            with self.subTest(action=actions.index(action)), self.assertRaises((operations.PreMutationRefusal, BootstrapRefused, BootstrapExecutionFailed)) as refused:
                action()
            self.assertEqual(refused.exception.reason, 'namespace_owner_has_dependents')
        for callback in callbacks.values(): callback.assert_not_called()
        self.assertFalse((self.state.root / 'backups').exists())
        self.assertFalse((self.state.root / 'conversion-snapshots').exists())

    def test_new_runtime_dependent_after_confirmation_blocks_before_backup_or_pull(self):
        self.model['services'].pop('consumer')
        self.observations[CONSUMER_ID]['network_mode'] = 'bridge'
        def confirm(prompt):
            self.observations[CONSUMER_ID]['network_mode'] = 'container:' + OWNER_ID
            return 'yes'
        with patch.object(operations, 'backup_files') as backup, patch.object(operations, 'run') as docker:
            with self.assertRaises(operations.PreMutationRefusal) as refused:
                operations.do_update(self.owner, self.state, input_fn=confirm, output=lambda text: None)
        self.assertEqual(refused.exception.reason, 'namespace_owner_has_dependents')
        backup.assert_not_called()
        docker.assert_not_called()

    def test_runtime_relationship_parser_rejects_incomplete_or_ambiguous_inventory(self):
        for raw in ('', json.dumps([OWNER_ID, 'synthetic_default']),
                    json.dumps([OWNER_ID, 'synthetic_default']) + '\n' + json.dumps([OWNER_ID, 'synthetic_default'])):
            with self.subTest(raw=raw):
                with patch.object(ns, 'run', side_effect=[OWNER_ID + '\n' + CONSUMER_ID, raw]):
                    with self.assertRaises(ns.NamespaceRefused):
                        ns.runtime_relationships()

    def test_generic_dependency_without_namespace_stays_unsupported(self):
        self.observations.pop(CONSUMER_ID)
        self.model['services'].pop('consumer')
        self.model['services']['owner']['depends_on'] = {'other': {'condition': 'service_started', 'required': True}}
        self.assertEqual(ns.mutation_refusal(self.owner, model=self.model), 'namespace_unsupported_compose')
        with self.assertRaises(webservice._ExecutionContextRefused):
            webservice._execution_context_fingerprint(self.owner, self.model)

    def test_absent_ordinary_recovery_still_protects_declared_and_runtime_owners(self):
        self.observations.pop(OWNER_ID)
        self.assertEqual(ns.mutation_refusal(self.owner, model=self.model, allow_absent=True), 'namespace_owner_has_dependents')
        self.observations.pop(CONSUMER_ID)
        self.model['services'].pop('consumer')
        self.assertIsNone(ns.mutation_refusal(self.owner, model=self.model, allow_absent=True))

    def test_web_rollback_refuses_owner_before_evidence_or_worker(self):
        with patch.object(self.agent, '_latest_rollback_point') as evidence:
            with self.assertRaises(operations.PreMutationRefusal) as refused:
                self.agent.rollback_review({'service_key': 'container/' + OWNER_ID, 'requested_by': 'test'})
            self.assertEqual(refused.exception.reason, 'namespace_owner_has_dependents')
            with self.assertRaises(operations.PreMutationRefusal):
                self.agent._rollback_intent_candidate(SimpleNamespace(service_key='container/' + OWNER_ID))
        evidence.assert_not_called()
        self.assertEqual(webservice.ReadOnlyService._blocked_reason(refused.exception), 'namespace_owner_has_dependents')

    def test_consumer_core_mutations_unavailable(self):
        for action in (operations.do_update, operations.do_rollback):
            with self.subTest(action=action), self.assertRaises(operations.PreMutationRefusal) as refused:
                action(self.consumer, self.state, dry_run=True)
            self.assertEqual(refused.exception.reason, 'namespace_unsupported_compose')
        with self.assertRaises(operations.PreMutationRefusal):
            operations.do_restart(self.consumer)

    def test_core_apply_owner_and_consumer_blocked(self):
        inventory = build_inventory(self.consumer.compose_files, self.consumer.working_dir, model=self.model)
        plan = SimpleNamespace(desired_model=self.model, inventory=inventory, baseline=SimpleNamespace(inputs=inventory.files))
        for selected in (self.owner, self.consumer):
            marker = Mock()
            outcome = do_compose_reconcile(selected, self.state, plan, operation_id='test', binding='test',
                                           revalidate=Mock(), discover_current=lambda: self.runtime,
                                           verify_configuration=Mock(), verify_context=Mock(), capture_baseline=Mock(), mutation_started=marker)
            self.assertEqual(outcome.status, 'blocked')
            marker.assert_not_called()

    def test_cli_restart_stack_refuses_all_before_any_restart(self):
        from docker_update_manager.cli import execute, parser
        args = parser().parse_args(['restart', '--stack', 'synthetic', '--yes'])
        with patch('docker_update_manager.cli.services', return_value=self.runtime), patch('docker_update_manager.cli.run') as docker:
            with self.assertRaises(operations.PreMutationRefusal):
                execute(args, parser(), self.agent.config, self.state)
        docker.assert_not_called()

    def test_conversion_rollback_protects_current_and_retained_owner(self):
        state = Mock()
        row = {'id': 1, 'action': 'convert', 'result': 'SUCCESS', 'stack': 'synthetic', 'service': 'owner',
               'details': json.dumps({'backup_container': 'retained'})}
        state.history.return_value = state.history_for_service.return_value = [row]
        retained = replace(self.owner, name='retained', compose_service=None, stack=None, container_id='f' * 64)
        with patch('docker_update_manager.conversion.discover', return_value=[self.owner, retained]), patch('docker_update_manager.conversion.run') as docker:
            with self.assertRaises(operations.PreMutationRefusal):
                rollback_conversion('owner', state, yes=True)
        docker.assert_not_called()
