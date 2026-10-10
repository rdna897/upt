"""Namespace Stage 2 Layer B: deterministic Apply/recovery safety machinery.

No real Docker, Compose, browser or /proc access. The real namespace review,
guard, v3 evidence, marker/fence and publication code runs against synthetic
sources and a fake Docker runtime extended from the Stage 1/1b fixtures.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import copy
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

import yaml

from test_compose_namespace import CONSUMER_ID, OWNER_HASH, OWNER_ID
from test_compose_namespace_update import OTHER_OWNER_ID, Stage1bFixture

from docker_update_manager import compose_namespace as ns, namespace_apply, retention
from docker_update_manager.compose_baseline import BaselineStore
from docker_update_manager.compose_drift import Inventory, InputFile
from docker_update_manager.compose_reconcile import do_compose_reconcile
from docker_update_manager.compose_recovery_retention import checked_bundle, lifecycle
from docker_update_manager.lock import Lock
from docker_update_manager.models import Service
from docker_update_manager.operation_presentation import REFRESH_NOTICE, operation_presentation
from docker_update_manager.webapp import operation_event_role
from progress_assertions import assert_stage_model
from docker_update_manager.system import CommandError, ComposeInvocationOutcome, invoke, run

DESIRED_ID = '5' * 64
RECOVERED_ID = '6' * 64
EXTRA_ID = '7' * 64
STRICT_TAIL = ['up', '-d', '--no-deps', '--pull', 'never', '--no-build', 'consumer']
REAL_ATOMIC_WRITE = __import__('docker_update_manager.compose', fromlist=['atomic_write_bytes']).atomic_write_bytes


class Stage2Fixture(Stage1bFixture):
    def setUp(self):
        super().setUp()
        self.patch('compose_namespace.QUALIFIED_APPLY_RUNTIME', new=self.qualified)
        self.patch('compose.run', side_effect=self.docker_run)
        self.patch('namespace_apply.invoke', side_effect=self.fake_invoke)
        self.patch('compose_reconcile.time.sleep', side_effect=self.fake_sleep)
        self.patch('compose_reconcile.atomic_write_bytes', side_effect=self.fake_write)
        self.refresh = patch.object(self.agent, 'start_refresh', return_value={'status': 'checking'}).start()
        self.addCleanup(patch.stopall)
        self.agent.config.data['health_timeout'] = 30
        self.mounts, self.invocations, self.effects, self.sleeps, self.writes = {}, [], [], [], []
        self.desired_health = self.recovery_health = 'healthy'
        self.next_ids = [DESIRED_ID, RECOVERED_ID, EXTRA_ID]
        self.next_pid, self.next_start = 110, 5
        self.sleep_hook = self.config_hook = self.write_hook = None
        self.prepare_layout()
        # Phase 1 read-only status captures the trusted v2 baseline.
        self.assertEqual(self.plan(persist=True).status, 'in_sync')
        self.baseline = self.records()[0]
        self.original = self.sources()
        self.make_desired_edit()
        self.desired = self.sources()
        self.assertNotEqual(self.original, self.desired)

    def prepare_layout(self):
        pass

    def make_desired_edit(self):
        self.model['services']['consumer']['environment'] = {'TZ': 'UTC'}
        self.write_source()

    def sources(self):
        paths = list(self.consumer.compose_files) + [str(self.root / '.env')]
        return {path: Path(path).read_bytes() for path in paths if Path(path).exists()}

    # -- fake runtime ---------------------------------------------------------
    def env_values(self, args):
        if '--env-file' in args:
            path = Path(args[args.index('--env-file') + 1])
        else:
            path = Path(args[args.index('--project-directory') + 1]) / '.env'
        if not path.exists():
            return {}
        return dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)

    def load_model(self, files, env=None, project=None):
        merged = None
        for path in files:
            text = Path(path).read_text()
            for key, value in (env or {}).items():
                text = text.replace('${' + key + '}', value)
            document = yaml.safe_load(text)
            if merged is None:
                merged = document
            else:
                for name, node in (document.get('services') or {}).items():
                    target = merged['services'].setdefault(name, {})
                    for field, value in node.items():
                        if isinstance(value, dict) and isinstance(target.get(field), dict):
                            target[field] = {**target[field], **value}
                        else:
                            target[field] = value
        # Normal resolved JSON expands env_file into environment (Layer A).
        for node in merged['services'].values():
            reference = node.pop('env_file', None)
            if reference:
                path = Path(project or self.root) / reference
                values = dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)
                node['environment'] = {**(node.get('environment') or {}), **values}
        return merged

    def live_model(self):
        args = ['--project-directory', str(self.root)]
        return self.load_model(self.consumer.compose_files, self.env_values(args))

    def docker_run(self, args, **kw):
        args = list(args)
        if args[:2] == ['docker', 'compose'] and 'config' in args:
            self.calls.append(args)
            if self.config_hook:
                self.config_hook(args)
            if '--quiet' in args:
                return ''
            model = self.load_model(self.files(args), self.env_values(args))
            if '--hash' in args:
                name = args[-1]
                if name == 'consumer':
                    return name + ' ' + ('0' * 64 if self.hash_fault else ns.service_hash(model['services'][name]))
                return name + ' ' + (OWNER_HASH if model['services'][name] == {'image': 'example/owner:1'} else '9' * 64)
            return json.dumps(model)
        if args[:3] == ['docker', 'inspect', '--type'] and args[5] == '{{json .Mounts}}':
            self.calls.append(args)
            return json.dumps(self.mounts.get(args[-1], []))
        return super().docker_run(args, **kw)

    @staticmethod
    def files(args):
        return [args[i + 1] for i, value in enumerate(args) if value == '-f']

    def consumer_now(self):
        return next(item for item in self.runtime if item.compose_service == 'consumer')

    def place_consumer(self, *, container_id=None, health='healthy', state='running', runtime_hash=None,
                       owner_id=None, restart_count=0, keep_old=False, netns=None, started=None):
        selected = self.live_model()['services']['consumer']
        owner_id = owner_id or self.owner.container_id
        runtime_hash = runtime_hash or ns.resolved_hash(selected, owner_id, ns.service_hash(selected))
        container_id = container_id or self.next_ids.pop(0)
        current = self.consumer_now()
        labels = {**current.labels, ns.HASH_LABEL: runtime_hash}
        self.next_start += 1
        fresh = replace(current, container_id=container_id, state=state, health=health, labels=labels,
                        started_at=started or f'2026-10-04T12:{self.next_start:02d}:00.000000001Z',
                        network_mode='container:' + owner_id)
        if not keep_old:
            self.runtime = [item for item in self.runtime if item.container_id != current.container_id]
            self.observations.pop(current.container_id, None)
        self.runtime = self.runtime + [fresh]
        self.next_pid += 1
        pid = self.next_pid if state == 'running' else 0
        observed = self.observation(fresh, 'container:' + owner_id, pid, False)
        observed['restart_count'] = restart_count
        self.observations[container_id] = observed
        self.netns[pid] = netns or self.netns[101]
        self.mounts[container_id] = self.runtime_mounts(selected)
        return fresh

    @staticmethod
    def runtime_mounts(selected):
        return [{'Type': 'bind', 'Source': item['source'], 'Destination': item['target'],
                 'RW': not item.get('read_only', False), 'Propagation': 'rprivate'}
                for item in selected.get('volumes') or []]

    def set_health(self, container_id, health):
        self.runtime = [replace(item, health=health) if item.container_id == container_id else item
                        for item in self.runtime]
        self.observations[container_id]['health'] = health

    def restart_owner(self, *, started='2026-10-04T12:59:00.000000001Z', restart_count=None):
        self.owner = replace(self.owner, started_at=started)
        self.runtime = [self.owner if item.container_id == OWNER_ID else item for item in self.runtime]
        self.observations[OWNER_ID]['started_at'] = started
        if restart_count is not None:
            self.observations[OWNER_ID]['restart_count'] = restart_count

    def remove_consumer(self):
        current = self.consumer_now()
        self.runtime = [item for item in self.runtime if item.container_id != current.container_id]
        self.observations.pop(current.container_id, None)

    def fake_invoke(self, command, *, phase, cwd=None, timeout=600):
        self.invocations.append((list(command), phase))
        assert command[-7:] == STRICT_TAIL, command
        assert 'owner' not in command and command.count('consumer') == 1, command
        assert not {'--force-recreate', '--build', '--remove-orphans', '--always-recreate-deps'} & set(command)
        effect = self.effects.pop(0) if self.effects else None
        if effect is None:
            self.place_consumer(health=self.desired_health if phase == 'apply' else self.recovery_health)
            return ComposeInvocationOutcome('completed', 0, phase)
        result = effect(phase)
        return result if isinstance(result, ComposeInvocationOutcome) else ComposeInvocationOutcome('completed', 0, phase)

    def fake_sleep(self, seconds):
        self.sleeps.append(seconds)
        if self.sleep_hook:
            self.sleep_hook(len(self.sleeps))

    def fake_write(self, path, content, **kwargs):
        self.writes.append(path)
        if self.write_hook:
            self.write_hook(len(self.writes), path)
        return REAL_ATOMIC_WRITE(path, content, **kwargs)

    # -- workflow -------------------------------------------------------------
    def review(self):
        return self.agent.compose_reconcile_review({'service_key': 'container/' + CONSUMER_ID, 'action': 'apply',
                                                    'requested_by': 'admin'})

    def start(self, reviewed=None):
        reviewed = reviewed or self.review()
        payload = {'confirmation_id': reviewed['confirmation_id'], 'requested_by': 'admin',
                   'client_ip': '127.0.0.1', 'user_agent': 'fixture'}
        intent = self.agent._compose_intents.get(payload['confirmation_id'])
        with patch('docker_update_manager.webservice.threading.Thread'):
            result = self.agent.start_compose_reconcile(payload)
        return result['operation_id'], payload, intent

    def execute(self, reviewed=None, before=None):
        operation_id, payload, intent = self.start(reviewed)
        if before:
            before()
        self.agent._compose_worker(operation_id, payload, intent)
        return self.status(operation_id)

    def status(self, operation_id):
        return self.agent.operation_status({'operation_id': operation_id, 'after_event_id': 0})

    def row(self, operation_id):
        with self.state.read() as c:
            row = dict(c.execute('SELECT * FROM operation_runs WHERE id=?', (operation_id,)).fetchone())
        row['summary'], row['result'] = json.loads(row['summary']), json.loads(row['result'])
        return row

    def fence(self, operation_id):
        with self.state.read() as c:
            row = c.execute('SELECT lifecycle FROM compose_bootstrap_fences WHERE operation_id=?', (operation_id,)).fetchone()
        return row[0] if row else None

    def key(self):
        return self.agent._baseline_key(self.consumer)

    def phases(self):
        return [phase for _command, phase in self.invocations]

    def reasons(self):
        return self.plan().eligibility_reasons

    def assert_ineligible(self, reason=None):
        plan = self.plan()
        self.assertFalse(plan.apply_eligible)
        self.assertIsNone(plan.namespace_apply_review)
        if reason:
            self.assertIn(reason, plan.eligibility_reasons)
        with self.assertRaises(ValueError):
            self.review()
        self.assertEqual(self.invocations, [])
        self.assertEqual([record.id for record in self.records()], [self.baseline.id])

    def assert_blocked(self, operation):
        self.assertEqual(operation['status'], 'blocked', operation)
        self.assertIs(operation['result']['mutation_performed'], False)
        self.assertFalse(operation['result']['manual_recovery_required'])
        self.assertEqual(self.invocations, [])
        self.assertIsNone(self.fence(operation['id']))
        self.assertFalse(self.row(operation['id'])['summary'].get('mutation_started'))
        self.assertEqual(self.sources(), self.desired)
        self.assertIsNone(self.state.bootstrap_fence(self.key()))
        self.refresh.assert_not_called()

    def assert_manual(self, operation, phases=('apply',), sources=None):
        self.assertEqual(operation['status'], 'failed', operation)
        result = operation['result']
        self.assertIs(result['manual_recovery_required'], True)
        self.assertIs(result['recovered'], False)
        self.assertIsNone(result['mutation_performed'])
        self.assertIs(result['possible_mutation'], True)
        self.assertEqual(self.phases(), list(phases))
        self.assertEqual(self.fence(operation['id']), 'manual')
        self.assertTrue(self.state.bootstrap_fence(self.key()))
        with self.assertRaises(ValueError):
            self.state.assert_service_unfenced(self.consumer)
        self.assertEqual(self.sources(), self.desired if sources is None else sources)
        self.assertTrue((self.state.root / 'compose-recoveries' / operation['id'] / 'manifest.json').exists())
        selected = [item for item in self.runtime if item.stack == self.consumer.stack
                    and item.compose_service == self.consumer.compose_service]
        if len(selected) == 1:
            self.refresh.assert_called_with('container/' + selected[0].container_id, after_reconcile=True)
        else:
            self.refresh.assert_not_called()
        # Only the original trusted baseline remains published; no trust from uncertainty.
        self.assertEqual([record.id for record in self.records()], [self.baseline.id])
        self.assertEqual(operation_presentation(operation)['outcome'], 'manual')

    def assert_recovered(self, operation):
        self.assertEqual(operation['status'], 'failed', operation)
        result = operation['result']
        self.assertTrue(result['recovered'] and result['mutation_performed'])
        self.assertFalse(result['manual_recovery_required'])
        self.assertEqual(self.phases(), ['apply', 'recovery'])
        self.assertEqual(result['current_service_key'], 'container/' + RECOVERED_ID)
        recovered = self.consumer_now()
        self.assertEqual(recovered.container_id, RECOVERED_ID)
        self.assertEqual(recovered.labels[ns.HASH_LABEL], self.baseline.runtime_hash)
        self.assertEqual(recovered.image_id, self.consumer.image_id)
        # Desired configuration remains pending on disk, unapplied.
        self.assertEqual(self.sources(), self.desired)
        self.assertEqual(self.fence(operation['id']), 'resolved')
        records = self.records()
        self.assertEqual(records[0].container_id, RECOVERED_ID)
        self.assertEqual(records[0].runtime_hash, self.baseline.runtime_hash)
        self.assertIn(self.baseline.id, [record.id for record in records])
        self.refresh.assert_called_once_with('container/' + RECOVERED_ID, after_reconcile=True)
        with self.state.read() as c:
            history = c.execute("SELECT result,rollback_result FROM history WHERE action='compose_reconcile'").fetchall()
        self.assertEqual([tuple(row) for row in history], [('FAILED', 'AUTOMATIC RECOVERY SUCCEEDED')])
        self.assertIsNone(self.state.bootstrap_fence(self.key()))
        self.assertEqual(operation_presentation(operation)['outcome'], 'recovered')
        self.assertIn('Desired changes remain pending', operation_presentation(operation)['alert'])
        self.assertIn('not rolled back', operation_presentation(operation)['alert'])


class MultiInputFixture(Stage2Fixture):
    """Ordered base + override with project .env interpolation (qualified shape)."""

    def prepare_layout(self):
        base = {'name': 'synthetic', 'services': {'consumer': dict(self.model['services']['consumer']),
                                                  'owner': {'image': 'example/owner:1'}},
                'networks': {'default': {'name': 'synthetic_default', 'ipam': {}}}}
        self.source.write_text(yaml.safe_dump(base))
        self.override = self.root / 'override.yml'
        self.override.write_text(yaml.safe_dump({'services': {'consumer': {'environment': {'TZ': '${TZ_VALUE}'}}}}))
        (self.root / '.env').write_text('TZ_VALUE=UTC\n')
        files = [str(self.source), str(self.override)]
        replaced = []
        for item in self.runtime:
            labels = {**item.labels, 'com.docker.compose.project.config_files': ','.join(files)}
            replaced.append(replace(item, compose_files=files, labels=labels))
        self.runtime = replaced
        self.consumer, self.owner = replaced
        selected = self.live_model()['services']['consumer']
        runtime_hash = ns.resolved_hash(selected, OWNER_ID, ns.service_hash(selected))
        self.consumer = replace(self.consumer, labels={**self.consumer.labels, ns.HASH_LABEL: runtime_hash})
        self.runtime = [self.consumer, self.owner]

    def make_desired_edit(self):
        (self.root / '.env').write_text('TZ_VALUE=Europe/London\n')


# ---------------------------------------------------------------------------
class InvocationOutcomeTests(TestCase):
    """Real subprocesses: the typed boundary never infers from text or codes."""

    def test_completed_zero_and_non_zero_carry_actual_return_codes(self):
        self.assertEqual(invoke(['true'], phase='apply'), ComposeInvocationOutcome('completed', 0, 'apply'))
        self.assertTrue(invoke(['true'], phase='apply').completed_zero)
        outcome = invoke([sys.executable, '-c', 'import sys; print("secret"); sys.exit(3)'], phase='apply')
        self.assertEqual((outcome.category, outcome.returncode), ('completed', 3))
        self.assertFalse(outcome.completed_zero)

    def test_timeout_signal_and_launch_error_are_distinct_from_completion(self):
        timed = invoke([sys.executable, '-c', 'import time; time.sleep(5)'], phase='apply', timeout=1)
        self.assertEqual((timed.category, timed.returncode), ('timeout', None))
        signalled = invoke(['sh', '-c', 'kill -TERM $$'], phase='recovery')
        self.assertEqual((signalled.category, signalled.returncode, signalled.phase), ('signal', -15, 'recovery'))
        missing = invoke(['/nonexistent/upt-compose'], phase='apply')
        self.assertEqual((missing.category, missing.returncode), ('launch_error', None))
        self.assertEqual(missing.record(), {'phase': 'apply', 'category': 'launch_error', 'code': None})

    def test_generic_command_error_code_is_ambiguous_but_typed_outcome_is_not(self):
        codes = []
        for argv, kwargs in (([sys.executable, '-c', 'import sys; sys.exit(1)'], {}),
                             ([sys.executable, '-c', 'import time; time.sleep(5)'], {'timeout': 1}),
                             (['/nonexistent/upt-compose'], {})):
            with self.assertRaises(CommandError) as raised:
                run(argv, **kwargs)
            codes.append(raised.exception.code)
        self.assertEqual(codes, [1, 1, 1])  # Why CommandError can never be recovery authority.
        categories = [invoke([sys.executable, '-c', 'import sys; sys.exit(1)'], phase='apply').category,
                      invoke([sys.executable, '-c', 'import time; time.sleep(5)'], phase='apply', timeout=1).category,
                      invoke(['/nonexistent/upt-compose'], phase='apply').category]
        self.assertEqual(categories, ['completed', 'timeout', 'launch_error'])

    def test_completed_non_zero_recovery_allowlist_is_empty(self):
        self.assertEqual(namespace_apply.COMPLETED_NONZERO_RECOVERY_ALLOWLIST, frozenset())
        self.assertEqual(namespace_apply.QUALIFIED_FAILURE_CLASSES, {'desired_unhealthy', 'desired_start_deadline'})


class EnvFileUnitTests(TestCase):
    def inventory(self, *documents):
        files = []
        for index, document in enumerate(documents):
            content = document.encode()
            files.append(InputFile('compose', f'/synthetic/{index}.yml', True, 'x' * 64, len(content), content))
        return Inventory(tuple(files), ())

    def test_any_selected_env_file_declaration_refuses(self):
        refused = [
            'services:\n  consumer:\n    env_file: ./consumer.env\n',
            'services:\n  consumer:\n    env_file: [{path: ./a.env, required: false}]\n',
            'x-base: &base\n  env_file: ./hidden.env\nservices:\n  consumer:\n    <<: *base\n',
            'services:\n  base:\n    env_file: ./a.env\n  consumer:\n    extends: base\n',
        ]
        for document in refused:
            with self.subTest(document=document), self.assertRaises(ns.NamespaceRefused) as raised:
                namespace_apply.refuse_consumer_env_file(self.inventory('services:\n  consumer: {}\n', document), 'consumer')
            self.assertEqual(raised.exception.reason, 'namespace_env_file_unsupported')
        with self.assertRaises(ns.NamespaceRefused):
            namespace_apply.refuse_consumer_env_file(self.inventory('services: {}\n'), 'consumer', [{'env_file': ['a']}])

    def test_owner_env_file_and_project_env_do_not_refuse(self):
        namespace_apply.refuse_consumer_env_file(
            self.inventory('services:\n  owner:\n    env_file: ./owner.env\n  consumer:\n    environment: {A: b}\n'), 'consumer')


# ---------------------------------------------------------------------------
class SuccessTests(Stage2Fixture):
    def test_successful_apply_publishes_atomically_with_one_strict_invocation(self):
        reviewed = self.review()
        self.assertEqual(reviewed['review']['namespace'], {'owner': 'owner', 'owner_unchanged': True,
                                                           'configuration_only_recovery': True})
        operation = self.execute(reviewed)
        self.assertEqual(operation['status'], 'succeeded', operation)
        self.assertEqual(self.phases(), ['apply'])
        command = self.invocations[0][0]
        self.assertEqual(command, ['docker', 'compose', '--project-directory', str(self.root), '--project-name',
                                   'synthetic', '-f', str(self.source)] + STRICT_TAIL)
        result = operation['result']
        self.assertEqual(result['current_service_key'], 'container/' + DESIRED_ID)
        self.assertTrue(result['mutation_performed'] and result['image_unchanged'] and result['owner_unchanged'])
        self.assertFalse(result['manual_recovery_required'])
        self.assertEqual(self.fence(operation['id']), 'resolved')
        records = self.records()
        self.assertEqual(records[0].container_id, DESIRED_ID)
        self.assertEqual(records[0].origin, 'captured')
        self.assertEqual(records[0].runtime_hash, self.consumer_now().labels[ns.HASH_LABEL])
        self.assertEqual(self.sources(), self.desired)
        self.refresh.assert_called_once_with('container/' + DESIRED_ID, after_reconcile=True)
        # Immutable commit-time fact; queueing the refresh never rewrites the result.
        self.assertTrue(self.row(operation['id'])['result']['refresh_required'])
        with self.state.read() as c:
            history = c.execute("SELECT result FROM history WHERE action='compose_reconcile'").fetchall()
            audit = c.execute("SELECT result FROM audit_events WHERE action='web_compose_reconcile'").fetchall()
        self.assertEqual([row[0] for row in history], ['SUCCESS'])
        self.assertEqual([row[0] for row in audit], ['requested', 'succeeded'])
        self.assertIsNone(self.state.bootstrap_fence(self.key()))
        self.assertEqual(operation_presentation(operation)['outcome'], 'success')
        summary = self.row(operation['id'])['summary']
        self.assertEqual(summary['namespace_apply_invocations'], [{'phase': 'apply', 'category': 'completed', 'code': 0}])
        self.assertTrue(summary['mutation_started'] and summary['namespace_apply_marked'])
        self.assertEqual(summary['completion_proof']['checks'] >= 3, True)

    def test_starting_to_healthy_is_not_identity_drift_and_owner_checked_each_poll(self):
        self.desired_health = 'starting'
        owner_checks = []
        self.sleep_hook = lambda count: (owner_checks.append(count), self.set_health(DESIRED_ID, 'healthy'))
        operation = self.execute()
        self.assertEqual(operation['status'], 'succeeded', operation)
        self.assertEqual(len(self.sleeps), 1)

    def test_refresh_failure_preserves_committed_success(self):
        self.refresh.side_effect = RuntimeError('refresh unavailable')
        operation = self.execute()
        self.assertEqual(operation['status'], 'succeeded')
        self.assertTrue(operation['result']['refresh_required'])
        self.assertIn('Check for updates', operation['result']['warnings'][0])
        self.assertEqual(self.records()[0].container_id, DESIRED_ID)

    def test_success_publication_ambiguity_reads_durable_commit_and_never_recreates(self):
        real = self.state.publish_namespace_apply

        def committed_then_lost(*args, **kwargs):
            real(*args, **kwargs)
            raise sqlite3.OperationalError('acknowledgement lost')
        with patch.object(self.state, 'publish_namespace_apply', side_effect=committed_then_lost):
            operation = self.execute()
        self.assertEqual(operation['status'], 'succeeded')
        self.assertEqual(self.phases(), ['apply'])

    def test_success_publication_failure_is_manual_and_discards_only_unpublished_material(self):
        with patch.object(self.state, 'publish_namespace_apply', side_effect=sqlite3.OperationalError('disk I/O')):
            operation = self.execute()
        self.assert_manual(operation)
        staged = [path.name for path in (self.state.root / 'compose-baselines').iterdir()]
        self.assertEqual(staged, [self.baseline.id])

    def test_baseline_prepare_fsync_failure_is_manual_without_recovery(self):
        with patch.object(BaselineStore, 'prepare', side_effect=OSError('fsync')):
            operation = self.execute()
        self.assert_manual(operation)

    def test_dry_run_is_read_only(self):
        reviewed = self.review()
        intent = self.agent._compose_intents[reviewed['confirmation_id']]
        service, plan = self.agent._compose_intent_candidate(intent)
        guard = namespace_apply.NamespaceApplyGuard(intent.namespace_review, service=service, plan=plan,
                                                    state=self.state, operation_id='a' * 32, requester='admin',
                                                    client_ip='', user_agent='', deps=self.agent._namespace_apply_deps())
        outcome = do_compose_reconcile(service, self.state, plan, operation_id='a' * 32, binding=None,
                                       revalidate=lambda: None, discover_current=lambda: list(self.runtime),
                                       verify_configuration=guard.verify_configuration, verify_context=None,
                                       capture_baseline=guard.prepare_baseline, mutation_started=guard.mark,
                                       dry_run=True, guard=guard)
        self.assertEqual(outcome.status, 'dry_run')
        self.assertEqual(list(outcome.command[-7:]), STRICT_TAIL)
        self.assertNotIn('owner', outcome.command)
        self.assertEqual(self.invocations, [])
        self.assertFalse((self.state.root / 'compose-recoveries').exists())
        self.assertEqual(self.sources(), self.desired)


class NamespaceProgressTests(Stage2Fixture):
    """Real stage totals, neutral markers and one canonical refresh fact for namespace Apply."""

    def public(self, operation_id, after=0):
        return self.agent.operation_status({'operation_id': operation_id, 'after_event_id': after})

    def test_success_reports_eight_real_stages_with_publication_as_the_last(self):
        operation = self.execute()
        self.assertEqual(operation['status'], 'succeeded', operation)
        events = operation['events']
        self.assertEqual(assert_stage_model(self, events, 8), list(range(1, 9)))
        self.assertEqual(events[-2]['stage'], '8/8 Publish trusted baseline and result')
        self.assertEqual(events[-1]['kind'], 'operation_completed')
        self.assertFalse([event for event in events if event['stage'] and event['stage'].startswith('9/')])
        # The marker events are neutral facts, never incomplete steps.
        markers = [event for event in events if event['kind'] == 'task_info']
        self.assertTrue(markers)
        self.assertTrue(all(operation_event_role(event) == 'info' and event['status'] == 'info' for event in markers))
        self.assertFalse([event for event in events if event['kind'] == 'task_running'])
        # Reload from any cursor projects the same ordered history as the live stream.
        later = self.public(operation['id'], after=events[2]['id'])
        self.assertEqual([event['id'] for event in later['events']], [event['id'] for event in events[3:]])
        self.assertEqual(later['events'], events[3:])

    def test_refresh_required_is_one_immutable_fact_across_every_projection(self):
        operation = self.execute()
        self.assertEqual(operation['status'], 'succeeded')
        stored = self.row(operation['id'])['result']
        with self.state.read() as c:
            history = json.loads(c.execute("SELECT details FROM history WHERE action='compose_reconcile'").fetchone()[0])
            audit = json.loads(c.execute("SELECT details FROM audit_events WHERE action='web_compose_reconcile' "
                                         "AND result='succeeded'").fetchone()[0])
        terminal = operation['events'][-1]['payload']
        views = {'operation result': operation['result'], 'stored result': stored, 'terminal event': terminal,
                 'history': history, 'audit': audit}
        for name, view in views.items():
            self.assertIs(view['refresh_required'], True, name)
        self.assertIn(REFRESH_NOTICE, operation_presentation(operation)['alert'])
        self.refresh.assert_called_once_with(stored['current_service_key'], after_reconcile=True)
        # Queueing is asynchronous and never rewrites the committed result.
        self.assertEqual(self.row(operation['id'])['result'], stored)

    def test_refresh_queue_failure_does_not_change_the_committed_result(self):
        self.refresh.side_effect = RuntimeError('refresh unavailable')
        operation = self.execute()
        self.assertEqual(operation['status'], 'succeeded')
        self.assertIs(operation['result']['refresh_required'], True)
        self.assertEqual(self.public(operation['id'])['result'], operation['result'])
        # The notice must stay true although the refresh was never queued.
        alert = operation_presentation(operation)['alert']
        self.assertIn(REFRESH_NOTICE, alert)
        self.assertNotIn('is queued', alert)
        self.assertEqual(operation['result']['warnings'], [REFRESH_NOTICE])

    def test_blocked_has_no_publication_stage(self):
        operation = self.execute(self.review(), before=lambda: self.set_health(OWNER_ID, 'unhealthy'))
        self.assert_blocked(operation)
        self.assertNotIn(8, assert_stage_model(self, operation['events'], 8))
        self.assertEqual(operation['events'][-1]['kind'], 'operation_blocked')

    def test_recovered_and_manual_keep_their_terminal_semantics_without_a_publication_stage(self):
        self.desired_health = 'unhealthy'
        recovered = self.execute()
        self.assert_recovered(recovered)
        self.assertNotIn(8, assert_stage_model(self, recovered['events'], 8))
        self.assertEqual(recovered['events'][-1]['kind'], 'operation_failed')
        self.assertNotIn('refresh_required', recovered['result'])
        self.setUp()
        self.effects = [lambda phase: self.remove_consumer()]
        manual = self.execute()
        self.assert_manual(manual)
        self.assertNotIn(8, assert_stage_model(self, manual['events'], 8))
        self.assertEqual(manual['events'][-1]['kind'], 'operation_failed')
        self.assertTrue(manual['result']['manual_recovery_required'])


class MultiInputTests(MultiInputFixture):
    def test_qualified_project_env_change_applies(self):
        operation = self.execute()
        self.assertEqual(operation['status'], 'succeeded', operation)
        self.assertEqual(self.files(self.invocations[0][0]), [str(self.source), str(self.override)])

    def test_project_env_and_override_recovery_restores_baseline_then_pending_bytes(self):
        self.desired_health = 'unhealthy'
        restored = []
        self.write_hook = lambda count, path: restored.append(Path(path).name)
        operation = self.execute()
        self.assert_recovered(operation)
        # Only the changed input was rewritten: baseline, then pending again.
        self.assertEqual(restored, ['.env', '.env'])

    def test_override_env_file_hidden_by_resolved_expansion_is_ineligible(self):
        (self.root / 'consumer.env').write_text('EXTRA=1\n')
        self.override.write_text(yaml.safe_dump({'services': {'consumer': {
            'environment': {'TZ': '${TZ_VALUE}'}, 'env_file': './consumer.env'}}}))
        self.assertNotIn('env_file', self.live_model()['services']['consumer'])
        self.assert_ineligible('namespace_env_file_unsupported')


class EligibilityTests(Stage2Fixture):
    def test_review_is_bounded_and_never_adopts_or_captures(self):
        reviewed = self.review()
        text = json.dumps(reviewed)
        for private in (OWNER_ID, CONSUMER_ID, self.baseline.id, self.baseline.fingerprint, str(self.root),
                        'net:[', OWNER_HASH, self.baseline.runtime_hash):
            self.assertNotIn(private, text)
        self.assertEqual([record.id for record in self.records()], [self.baseline.id])
        self.assertEqual(self.invocations, [])

    def test_missing_stale_and_tampered_baselines_or_trust_failure_refuse(self):
        with self.subTest('trust store query failure'), patch.object(
                BaselineStore, 'records', side_effect=sqlite3.OperationalError('locked')):
            self.assertIn('trust_store_unavailable', self.reasons())
            with self.assertRaises(ValueError):
                self.review()
        manifest = self.state.root / 'compose-baselines' / self.baseline.id / 'manifest.json'
        original = manifest.read_bytes()
        with self.subTest('tampered'):
            manifest.write_bytes(b'{}')
            self.assert_ineligible('trust_store_unavailable')
            manifest.write_bytes(original)
        with self.subTest('stale: different exact container'):
            moved = replace(self.consumer, container_id=EXTRA_ID)
            self.runtime = [moved, self.owner]
            self.observations[EXTRA_ID] = {**self.observations.pop(CONSUMER_ID), 'id': EXTRA_ID}
            try:
                plan = self.agent._compose_plan(moved, self.runtime, persist=False)
                self.assertIn('no_trusted_baseline', plan.eligibility_reasons)
                with self.assertRaises(ValueError):
                    self.agent.compose_reconcile_review({'service_key': 'container/' + EXTRA_ID, 'action': 'apply',
                                                         'requested_by': 'admin'})
                self.assertEqual([record.id for record in self.records()], [self.baseline.id])  # review never adopts
            finally:
                self.runtime = [self.consumer, self.owner]
                self.observations[CONSUMER_ID] = {**self.observations.pop(EXTRA_ID), 'id': CONSUMER_ID}
        with self.subTest('missing'):
            self.state.delete_compose_baseline(self.baseline.id)
            self.assertIn('no_trusted_baseline', self.reasons())
            with self.assertRaises(ValueError):
                self.review()
            self.assertEqual(self.records(), [])

    def test_base_file_env_file_hidden_by_resolved_json_is_ineligible(self):
        (self.root / 'consumer.env').write_text('EXTRA=1\n')
        self.model['services']['consumer']['env_file'] = './consumer.env'
        self.write_source()
        self.assertNotIn('env_file', self.live_model()['services']['consumer'])
        self.assert_ineligible('namespace_env_file_unsupported')


    def test_relationship_edits_are_refused(self):
        for change in ({'depends_on': {'owner': {'condition': 'service_started', 'required': True}}},
                       {'depends_on': None}, {'network_mode': 'service:other'}):
            with self.subTest(change=change):
                consumer = dict(self.model['services']['consumer'])
                for field, value in change.items():
                    if value is None:
                        consumer.pop(field)
                    else:
                        consumer[field] = value
                saved = self.model['services']['consumer']
                self.model['services']['consumer'] = consumer
                self.write_source()
                self.assertFalse(self.plan().apply_eligible)
                with self.assertRaises(ValueError):
                    self.review()
                self.model['services']['consumer'] = saved
                self.write_source()
        self.assertEqual(self.invocations, [])

    def test_owner_peer_project_and_image_edits_are_refused(self):
        for mutate, reason in ((lambda m: m['services']['owner'].update(environment={'A': 'b'}), 'namespace_owner_unproven'),
                               (lambda m: m['networks'].update(extra={'name': 'synthetic_extra'}), 'project_unproven'),
                               (lambda m: m['services']['consumer'].update(image='example/consumer:2'), 'image_change'),
                               (lambda m: m['services']['consumer'].update(ports=['80:80']), 'namespace_owner_unproven')):
            with self.subTest(reason=reason):
                saved = json.loads(json.dumps(self.model))
                try:
                    mutate(self.model)
                    self.write_source()
                    plan = self.plan()
                    self.assertFalse(plan.apply_eligible)
                    self.assertIn(reason, plan.reasons + plan.eligibility_reasons)
                    with self.assertRaises(ValueError):
                        self.review()
                finally:
                    self.model = saved
                    self.write_source()
        self.assertEqual(self.invocations, [])

    def test_mandatory_kernel_proof_and_unqualified_runtime_refuse(self):
        with self.subTest('netns unavailable'):
            netns = dict(self.netns)
            self.netns.clear()
            self.assertFalse(self.plan().apply_eligible)
            self.netns.update(netns)
        with self.subTest('Apply runtime not qualified, image-update entry alone insufficient'), patch(
                'docker_update_manager.compose_namespace.QUALIFIED_APPLY_RUNTIME', new=('other',)):
            self.assertIn('namespace_apply_unqualified', self.reasons())
        self.assertTrue(self.plan().apply_eligible)

    def test_discard_stays_unavailable_and_owner_stays_protected(self):
        plan = self.plan()
        self.assertTrue(plan.apply_eligible)
        self.assertFalse(plan.discard_eligible)
        owner_plan = self.agent._compose_plan(self.owner, self.runtime, persist=False)
        self.assertFalse(owner_plan.apply_eligible)
        self.assertEqual(ns.mutation_refusal(self.owner), 'namespace_owner_has_dependents')

    def test_no_generic_namespace_bypass(self):
        for value in (True, 'yes', {'owner_id': OWNER_ID}):
            self.assertEqual(ns.mutation_refusal(self.consumer, namespace_apply=value), 'namespace_unsupported_compose')
        with self.assertRaises(Exception):
            ns.require_mutation_safe(self.consumer)
        authority = self.plan().namespace_apply_review.authority
        self.assertIsNone(ns.mutation_refusal(self.consumer, namespace_apply=authority))
        wrong = replace(authority, owner_id=OTHER_OWNER_ID)
        self.assertEqual(ns.mutation_refusal(self.consumer, namespace_apply=wrong), 'namespace_unsupported_compose')
        self.assertEqual(ns.mutation_refusal(self.consumer, namespace_apply=authority, _image_update=True),
                         'namespace_unsupported_compose')


class PreMarkerTests(Stage2Fixture):
    def test_owner_replaced_or_restarted_before_marker_blocks(self):
        cases = {'replaced': self.replace_owner,
                 'same-ID restart, RestartCount unchanged': lambda: self.restart_owner(),
                 'restart count changed': lambda: self.observations[OWNER_ID].update(restart_count=1),
                 'owner unhealthy': lambda: self.set_health(OWNER_ID, 'unhealthy')}
        for label, change in cases.items():
            with self.subTest(label):
                reviewed = self.review()
                operation = self.execute(reviewed, before=change)
                self.assert_blocked(operation)
                self.setUp()

    def test_source_model_hash_alias_and_context_races_block(self):
        def edit_source():
            self.source.write_bytes(self.source.read_bytes() + b'\n# external edit\n')

        def image_alias():
            original = self.docker_run

            def aliased(args, **kw):
                if list(args)[:3] == ['docker', 'image', 'inspect'] and '{"Id"' not in ' '.join(args):
                    return 'sha256:' + '9' * 64
                return original(args, **kw)
            self.patch('compose_reconcile.run', side_effect=aliased)
            self.patch('webservice.run', side_effect=aliased)
            self.patch('compose_namespace.run', side_effect=aliased)
        cases = {'source edit': edit_source,
                 'hash oracle': lambda: setattr(self, 'hash_fault', True),
                 'network context': lambda: setattr(self, 'network_fault', True),
                 'pid/netns mismatch': lambda: self.netns.update({102: 'net:[4026539999]'}),
                 'image alias': image_alias}
        for label, change in cases.items():
            with self.subTest(label):
                operation = self.execute(self.review(), before=change)
                self.assertEqual(operation['status'], 'blocked', label)
                self.assertEqual(self.invocations, [])
                self.assertIsNone(self.fence(operation['id']))
                self.setUp()

    def test_evidence_write_failure_blocks_and_leaves_no_orphan(self):
        with patch('docker_update_manager.namespace_apply._write_private', side_effect=OSError('ENOSPC')):
            operation = self.execute()
        self.assert_blocked(operation)
        self.assertEqual(list((self.state.root / 'compose-recoveries').iterdir()), [])

    def test_marker_transaction_failure_definitely_absent_is_blocked(self):
        with patch.object(self.state, 'mark_namespace_apply', side_effect=sqlite3.OperationalError('busy')):
            operation = self.execute()
        self.assert_blocked(operation)

    def test_marker_committed_but_unacknowledged_is_manual_without_dispatch(self):
        real = self.state.mark_namespace_apply

        def committed(*args, **kwargs):
            real(*args, **kwargs)
            raise sqlite3.OperationalError('acknowledgement lost')
        with patch.object(self.state, 'mark_namespace_apply', side_effect=committed):
            operation = self.execute()
        self.assert_manual(operation, phases=())

    def test_marker_readback_unknown_is_manual_without_dispatch(self):
        with patch.object(self.state, 'mark_namespace_apply', side_effect=sqlite3.OperationalError('busy')), \
                patch.object(self.state, 'namespace_apply_marker', return_value='unknown'):
            operation_id, payload, intent = self.start()
            self.agent._compose_worker(operation_id, payload, intent)
        self.assertEqual(self.invocations, [])
        operation = self.status(operation_id)
        self.assertEqual(operation['status'], 'blocked')  # Durable state proves no marker.

    def test_intent_without_server_review_is_refused(self):
        reviewed = self.review()
        intent = self.agent._compose_intents[reviewed['confirmation_id']]
        self.agent._compose_intents[reviewed['confirmation_id']] = replace(intent, namespace_review=None)
        operation = self.execute(reviewed)
        self.assertEqual(operation['status'], 'blocked')
        self.assertEqual(self.invocations, [])
        self.assertEqual(self.sources(), self.desired)


class PostMarkerOwnerTests(Stage2Fixture):
    def apply_then(self, change, **kwargs):
        def effect(phase):
            self.place_consumer(**kwargs)
            change()
        self.effects = [effect]
        return self.execute()

    def test_owner_change_after_marker_latches_manual(self):
        for label, change in {'replaced': self.replace_owner, 'same-ID restart': self.restart_owner,
                              'restart count': lambda: self.observations[OWNER_ID].update(restart_count=1),
                              'unhealthy': lambda: self.set_health(OWNER_ID, 'unhealthy'),
                              'lost': lambda: self.runtime.remove(self.owner)}.items():
            with self.subTest(label):
                self.assert_manual(self.apply_then(change))
                self.setUp()

    def test_owner_unhealthy_during_consumer_starting_poll_is_manual(self):
        self.desired_health = 'starting'

        def poll(count):
            self.set_health(OWNER_ID, 'unhealthy')
            self.set_health(DESIRED_ID, 'unhealthy')
        self.sleep_hook = poll
        self.assert_manual(self.execute())

    def test_wrong_owner_stale_ordering_and_kernel_mismatch_are_manual(self):
        cases = {'wrong owner': dict(owner_id=OTHER_OWNER_ID),
                 'stale ordering': dict(started='2026-10-04T11:00:00.000000001Z'),
                 'netns mismatch': dict(netns='net:[4026539999]'),
                 'restart count': dict(restart_count=1),
                 'unhealthy with kernel mismatch': dict(health='unhealthy', netns='net:[4026539999]')}
        for label, values in cases.items():
            with self.subTest(label):
                self.assert_manual(self.apply_then(lambda: None, **values))
                self.setUp()

    def test_kernel_proof_unavailable_after_marker_is_manual(self):
        def effect(phase):
            fresh = self.place_consumer(health='unhealthy')
            self.netns.pop(self.observations[fresh.container_id]['pid'])
        self.effects = [effect]
        self.assert_manual(self.execute())

    def test_source_or_model_race_after_marker_is_manual_and_preserves_external_edit(self):
        def effect(phase):
            self.place_consumer()
            self.source.write_bytes(self.source.read_bytes() + b'\n# external edit\n')
        self.effects = [effect]
        edited = None
        operation = self.execute()
        edited = self.sources()
        self.assertNotEqual(edited, self.desired)
        self.assert_manual(operation, sources=edited)


class RecoveryAdmissionTests(Stage2Fixture):
    def test_completed_zero_desired_unhealthy_recovers_once(self):
        self.desired_health = 'unhealthy'
        operation = self.execute()
        self.assert_recovered(operation)
        summary = self.row(operation['id'])['summary']
        self.assertEqual(summary['namespace_apply_failure_class'], 'desired_unhealthy')
        self.assertTrue(summary['recovery_recreate_may_have_started'])
        self.assertEqual([item['phase'] for item in summary['namespace_apply_invocations']], ['apply', 'recovery'])
        self.assertEqual(self.invocations[0][0], self.invocations[1][0])  # Same strict argv.

    def test_completed_zero_starting_at_bounded_deadline_recovers_once(self):
        self.agent.config.data['health_timeout'] = 0
        self.desired_health = 'starting'
        operation = self.execute()
        self.assert_recovered(operation)
        self.assertEqual(self.row(operation['id'])['summary']['namespace_apply_failure_class'], 'desired_start_deadline')

    def test_manual_outcome_records_bounded_private_consumer_inventory_without_kernel_proof(self):
        for label, effect, expected in (
                ('missing', lambda phase: self.remove_consumer(), {'consumers': 0}),
                ('created', lambda phase: self.place_consumer(state='created', health='none'),
                 {'consumers': 1, 'state': 'created', 'original': False, 'network_mode_owner': True,
                  'image_unchanged': True, 'configuration': 'desired'}),
                ('replicas', lambda phase: self.place_consumer(keep_old=True, health='unhealthy'),
                 {'consumers': 'many'})):
            with self.subTest(label):
                self.effects = [effect]
                operation = self.execute()
                self.assert_manual(operation)
                self.assertEqual(self.row(operation['id'])['summary']['namespace_apply_observation'], expected)
                self.assertNotIn('namespace_apply_observation', json.dumps(operation))
                self.setUp()

    def test_unqualified_zero_exit_states_are_manual(self):
        def stopped(phase):
            observed = self.observations[CONSUMER_ID]
            observed.update(state='exited', pid=0)
            self.runtime = [replace(item, state='exited') if item.container_id == CONSUMER_ID else item
                            for item in self.runtime]

        def same_id_restart(phase):
            self.place_consumer(container_id=CONSUMER_ID, health='unhealthy')
        cases = {'stopped/exited baseline': stopped,
                 'same-ID baseline restart': same_id_restart,
                 'baseline no-op': lambda phase: None,
                 'created consumer': lambda phase: self.place_consumer(state='created', health='none'),
                 'missing consumer': lambda phase: self.remove_consumer(),
                 'baseline-hash replacement': lambda phase: self.place_consumer(
                     health='unhealthy', runtime_hash=self.baseline.runtime_hash),
                 'replicas': lambda phase: self.place_consumer(health='unhealthy', keep_old=True),
                 'restart count': lambda phase: self.place_consumer(health='unhealthy', restart_count=1)}
        for label, effect in cases.items():
            with self.subTest(label):
                self.effects = [effect]
                self.assert_manual(self.execute())
                self.setUp()

    def test_non_latching_failure_on_healthy_replacement_never_admits_recovery(self):
        # Only the qualified startup/health classes admit recovery; a transient
        # configuration-verification error on a healthy desired replacement is
        # manual even though owner, consumer and invocation remain proved.
        failures = []

        def effect(phase):
            self.place_consumer()

            def once(args):
                if not failures:
                    failures.append(args)
                    raise RuntimeError('transient compose evaluation failure')
            self.config_hook = once
        self.effects = [effect]
        operation = self.execute()
        self.assertTrue(failures)
        self.assert_manual(operation)
        self.assertIsNone(self.row(operation['id'])['summary'].get('namespace_apply_failure_class'))

    def test_desired_replacement_lost_before_recovery_dispatch_is_manual(self):
        self.desired_health = 'unhealthy'
        self.write_hook = lambda count, path: self.remove_consumer()
        operation = self.execute()
        # The baseline bytes were written before loss was observed; no further
        # writes or recreation follow, and partial disk state remains evidence.
        self.assert_manual(operation, sources=self.original)

    def test_every_completed_non_zero_outcome_is_manual(self):
        states = {'replaced unhealthy': lambda: self.place_consumer(health='unhealthy'),
                  'replaced healthy': lambda: self.place_consumer(),
                  'created': lambda: self.place_consumer(state='created', health='none'),
                  'absent': self.remove_consumer, 'unchanged': lambda: None}
        for code in (1, 2, 125, 255):
            for label, change in states.items():
                with self.subTest(code=code, state=label):
                    def effect(phase, change=change, code=code):
                        change()
                        return ComposeInvocationOutcome('completed', code, phase)
                    self.effects = [effect]
                    self.assert_manual(self.execute())
                    self.setUp()

    def test_uncertain_invocation_outcomes_are_manual_even_with_stable_runtime(self):
        for category, code in (('timeout', None), ('signal', -15), ('signal', -2), ('launch_error', None),
                               ('unknown', None)):
            with self.subTest(category=category, code=code):
                def effect(phase, category=category, code=code):
                    self.place_consumer(health='unhealthy')
                    return ComposeInvocationOutcome(category, code, phase)
                self.effects = [effect]
                operation = self.execute()
                self.assert_manual(operation)
                self.assertEqual(self.row(operation['id'])['summary']['namespace_apply_invocations'],
                                 [{'phase': 'apply', 'category': category, 'code': code}])
                self.setUp()

    def test_invocation_outcome_persistence_failure_cannot_admit_recovery(self):
        self.desired_health = 'unhealthy'
        with patch.object(self.state, 'record_namespace_invocation', side_effect=sqlite3.OperationalError('busy')):
            self.assert_manual(self.execute())

    def test_worker_interruption_after_completed_record_never_replays(self):
        self.desired_health = 'starting'

        def interrupt(count):
            raise KeyboardInterrupt()
        self.sleep_hook = interrupt
        operation_id, payload, intent = self.start()
        with self.assertRaises(KeyboardInterrupt):
            self.agent._compose_worker(operation_id, payload, intent)
        self.assertEqual(self.row(operation_id)['status'], 'running')
        self.assertEqual(self.row(operation_id)['summary']['namespace_apply_invocations'][0]['code'], 0)
        with Lock(self.state.root / 'update.lock'):
            self.state.recover_abandoned_operations()
        self.assert_manual(self.status(operation_id))

    def test_operation_status_poll_classifies_interrupted_worker_from_durable_state(self):
        def interrupt(phase):
            raise KeyboardInterrupt()
        self.effects = [interrupt]
        operation_id, payload, intent = self.start()
        with self.assertRaises(KeyboardInterrupt):
            self.agent._compose_worker(operation_id, payload, intent)
        self.assert_manual(self.status(operation_id))


class RecoveryFailureTests(Stage2Fixture):
    def setUp(self):
        super().setUp()
        self.desired_health = 'unhealthy'

    def test_recovery_invocation_uncertainty_or_non_zero_is_manual_without_further_writes(self):
        for category, code in (('timeout', None), ('signal', -9), ('launch_error', None), ('unknown', None),
                               ('completed', 1)):
            with self.subTest(category=category, code=code):
                self.desired_health = 'unhealthy'

                def recovery(phase, category=category, code=code):
                    self.place_consumer()
                    return ComposeInvocationOutcome(category, code, phase)
                self.effects = [None, recovery]
                self.effects[0] = lambda phase: self.place_consumer(health='unhealthy') and None
                operation = self.execute()
                # Temporarily restored baseline inputs remain as evidence.
                self.assert_manual(operation, phases=('apply', 'recovery'), sources=self.original)
                self.setUp()

    def test_recovered_consumer_health_failure_is_manual(self):
        self.recovery_health = 'unhealthy'
        self.assert_manual(self.execute(), phases=('apply', 'recovery'), sources=self.original)

    def test_owner_loss_during_recovery_source_transition_stops_writes(self):
        self.write_hook = lambda count, path: self.replace_owner()
        self.assert_manual(self.execute(), sources=self.original)
        self.assertEqual(len(self.writes), 1)

    def test_owner_change_during_recovery_health_poll_is_manual(self):
        self.recovery_health = 'starting'

        def poll(count):
            self.restart_owner()
        self.sleep_hook = poll
        self.assert_manual(self.execute(), phases=('apply', 'recovery'), sources=self.original)

    def test_partial_source_write_failure_before_dispatch_restores_pending_best_effort(self):
        def fail(count, path):
            if count == 1:
                raise OSError('EIO')
        self.write_hook = fail
        self.assert_manual(self.execute())

    def test_external_third_state_is_preserved(self):
        def external(count, path):
            Path(path).write_bytes(b'name: external-edit\n')
        self.write_hook = external
        operation = self.execute()
        third = self.sources()
        self.assertEqual(Path(self.source).read_bytes(), b'name: external-edit\n')
        self.assert_manual(operation, sources=third)

    def test_desired_restoration_failure_never_publishes_partial_recovery(self):
        def fail(count, path):
            if count == 2:
                raise OSError('EIO')
        self.write_hook = fail
        operation = self.execute()
        self.assert_manual(operation, phases=('apply', 'recovery'), sources=self.original)
        staged = [path.name for path in (self.state.root / 'compose-baselines').iterdir()]
        self.assertEqual(staged, [self.baseline.id])

    def test_evidence_tamper_after_marker_prevents_recovery(self):
        def effect(phase):
            self.place_consumer(health='unhealthy')
            proof = next((self.state.root / 'compose-recoveries').iterdir()) / 'proof.json'
            os.chmod(proof, 0o600)
            proof.write_bytes(b'{}')
        self.effects = [effect]
        self.assert_manual(self.execute())

    def test_recovery_publication_ambiguity_and_failure(self):
        real = self.state.publish_namespace_apply

        def committed(*args, **kwargs):
            real(*args, **kwargs)
            raise sqlite3.OperationalError('acknowledgement lost')
        with patch.object(self.state, 'publish_namespace_apply', side_effect=committed):
            self.assert_recovered(self.execute())
        self.setUp()
        self.desired_health = 'unhealthy'
        with patch.object(self.state, 'publish_namespace_apply', side_effect=sqlite3.OperationalError('I/O')):
            operation = self.execute()
        self.assert_manual(operation, phases=('apply', 'recovery'))

    def test_runtime_capability_change_before_recovery_dispatch_is_manual(self):
        def change(count, path):
            self.plugin.write_bytes(b'different compose plugin bytes')
        self.write_hook = change
        self.assert_manual(self.execute(), sources=self.original)

    def test_baseline_integrity_loss_before_source_switch_is_manual(self):
        def effect(phase):
            self.place_consumer(health='unhealthy')
            manifest = self.state.root / 'compose-baselines' / self.baseline.id / 'manifest.json'
            manifest.write_bytes(b'{}')
        self.effects = [effect]
        self.assert_manual(self.execute())
        self.assertEqual(self.writes, [])

    def test_recovery_phase_commit_failure_latches_before_source_switch(self):
        with patch.object(self.state, 'namespace_apply_phase', side_effect=sqlite3.OperationalError('busy')):
            self.assert_manual(self.execute())
        self.assertEqual(self.writes, [])


class CrashBoundaryTests(Stage2Fixture):
    def crash(self, target, *, after=False):
        real = getattr(self.state, target)

        def interrupted(*args, **kwargs):
            if after:
                real(*args, **kwargs)
            raise KeyboardInterrupt()
        operation_id, payload, intent = self.start()
        with patch.object(self.state, target, side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.agent._compose_worker(operation_id, payload, intent)
        with Lock(self.state.root / 'update.lock'):
            self.state.recover_abandoned_operations()
        return self.status(operation_id)

    def test_crash_after_evidence_before_marker_is_blocked(self):
        operation = self.crash('mark_namespace_apply')
        self.assert_blocked(operation)
        bundle = self.state.root / 'compose-recoveries' / operation['id']
        with self.state.read() as c, checked_bundle(self.state.root, bundle) as checked:
            self.assertEqual(lifecycle(c, operation['id'], checked)[0], 'terminal')

    def test_crash_with_marker_committed_is_manual_without_dispatch(self):
        self.assert_manual(self.crash('mark_namespace_apply', after=True), phases=())

    def test_crash_at_recovery_phase_and_recovery_marker_is_manual(self):
        for target in ('namespace_apply_phase',):
            self.desired_health = 'unhealthy'
            operation = self.crash(target, after=True)
            self.assertEqual(operation['status'], 'failed')
            self.assertTrue(operation['result']['manual_recovery_required'])
            self.assertEqual(self.phases(), ['apply'])

    def test_crash_at_recovery_recreate_marker_never_dispatches_recovery(self):
        self.desired_health = 'unhealthy'
        real = self.state.namespace_apply_phase

        def second_phase(operation_id, phase, **kwargs):
            real(operation_id, phase, **kwargs)
            if phase == 'recovery_recreate_may_have_started':
                raise KeyboardInterrupt()
        operation_id, payload, intent = self.start()
        with patch.object(self.state, 'namespace_apply_phase', side_effect=second_phase), \
                self.assertRaises(KeyboardInterrupt):
            self.agent._compose_worker(operation_id, payload, intent)
        with Lock(self.state.root / 'update.lock'):
            self.state.recover_abandoned_operations()
        self.assertTrue(self.row(operation_id)['summary']['recovery_recreate_may_have_started'])
        self.assert_manual(self.status(operation_id), sources=self.original)

    def test_crash_with_recovered_runtime_and_pending_restored_before_commit_is_manual(self):
        self.desired_health = 'unhealthy'
        operation = self.crash('publish_namespace_apply')
        self.assert_manual(operation, phases=('apply', 'recovery'))
        self.assertEqual(self.consumer_now().container_id, RECOVERED_ID)

    def test_crash_before_and_after_publication_commit(self):
        operation = self.crash('publish_namespace_apply')
        self.assert_manual(operation)
        self.setUp()
        operation = self.crash('publish_namespace_apply', after=True)
        self.assertEqual(operation['status'], 'succeeded')
        self.assertEqual(self.phases(), ['apply'])

    def test_crash_during_source_restore_is_manual_and_never_resumes(self):
        self.desired_health = 'unhealthy'

        def interrupt(count, path):
            raise KeyboardInterrupt()
        self.write_hook = interrupt
        operation_id, payload, intent = self.start()
        with self.assertRaises(KeyboardInterrupt):
            self.agent._compose_worker(operation_id, payload, intent)
        with Lock(self.state.root / 'update.lock'):
            self.state.recover_abandoned_operations()
            self.state.recover_abandoned_operations()
        self.assert_manual(self.status(operation_id))


class AdmissionProjectionTests(Stage2Fixture):
    def test_one_use_expiry_user_binding_and_lock_exclusion(self):
        reviewed = self.review()
        payload = {'confirmation_id': reviewed['confirmation_id'], 'requested_by': 'other',
                   'client_ip': '127.0.0.1', 'user_agent': 'fixture'}
        with self.assertRaises(ValueError):
            self.agent.start_compose_reconcile(payload)
        reviewed = self.review()
        intent = self.agent._compose_intents[reviewed['confirmation_id']]
        self.agent._compose_intents[reviewed['confirmation_id']] = replace(intent, expires_at=0)
        with self.assertRaises(ValueError):
            self.start(reviewed)
        reviewed = self.review()
        with Lock(self.state.root / 'update.lock'), self.assertRaises(RuntimeError):
            self.start(reviewed)
        reviewed = self.review()
        self.execute(reviewed)
        with self.assertRaises(ValueError):
            self.start(reviewed)

    def test_http_sse_and_reload_projections_are_allowlisted(self):
        for health in ('healthy', 'unhealthy'):
            with self.subTest(health=health):
                self.desired_health = health
                operation = self.execute()
                text = json.dumps(operation)
                with self.state.read() as c:
                    row = dict(c.execute('SELECT summary FROM operation_runs').fetchone())
                summary = json.loads(row['summary'])
                for private in (OWNER_ID, self.baseline.id, summary['namespace_apply_review'],
                                summary['namespace_apply_evidence'], summary['namespace_apply_owner'],
                                summary['new_baseline_id'], str(self.root), 'net:[', 'compose-recoveries',
                                self.baseline.runtime_hash, OWNER_HASH):
                    self.assertNotIn(private, text)
                self.assertEqual(operation['summary'], {'action': 'apply', 'namespace': True})
                for event in operation['events']:
                    self.assertLessEqual(set(event['payload']), self.agent._NAMESPACE_RESULT_FIELDS | {'warnings'})
                self.setUp()


class RetentionCompatibilityTests(Stage2Fixture):
    def manual_operation(self):
        self.effects = [lambda phase: self.remove_consumer()]
        return self.execute()

    def test_manual_fence_survives_pruning_restart_and_replacement_ids(self):
        operation = self.manual_operation()
        with self.state.connect() as c:
            c.execute("UPDATE operation_runs SET finished_at='2000-01-01T00:00:00+00:00', created_at='2000-01-01T00:00:00+00:00'")
        self.state.prune_operations(retention_days=1, limit=20)
        self.assertEqual(self.row(operation['id'])['status'], 'failed')
        replacement = replace(self.consumer, container_id=EXTRA_ID)
        with self.assertRaises(ValueError):
            self.state.assert_service_unfenced(replacement)
        self.assertIn(self.baseline.id, self.state.compose_baseline_references())
        path = self.state.root / 'compose-recoveries' / operation['id']
        with self.assertRaises(ValueError):
            retention._cleanup_compose_artifact(self.state, path, 1, datetime.now(timezone.utc) + timedelta(days=999), False)
        self.assertTrue(path.exists())

    def test_lost_replay_row_v3_orphan_remains_fenced_and_protects_baseline(self):
        operation = self.manual_operation()
        with self.state.connect() as c:
            c.execute('DELETE FROM operation_runs')
            c.execute('DELETE FROM compose_bootstrap_fences')
        self.assertTrue(self.state.bootstrap_fence(self.key()))
        self.assertIn(self.baseline.id, self.state.compose_baseline_references())
        self.assertEqual(self.agent._compose_plan(self.consumer, self.runtime, persist=True).reasons,
                         ('namespace_apply_unresolved',))

    def test_unkeyable_or_unknown_v3_material_fails_closed_globally(self):
        other = replace(self.consumer, stack='other', compose_service='web', container_id=EXTRA_ID,
                        working_dir='/srv/other', compose_files=['/srv/other/compose.yml'])
        root = self.state.root / 'compose-recoveries'
        for manifest in ({'version': 3, 'action': 'namespace_apply', 'binding': {'logical_key': self.key()}},
                         {'version': 4, 'action': 'namespace_apply'}):
            with self.subTest(version=manifest['version']):
                path = root / ('e' * 32)
                path.mkdir(parents=True, mode=0o700)
                os.chmod(root, 0o700)
                (path / 'manifest.json').write_text(json.dumps(manifest))
                os.chmod(path / 'manifest.json', 0o600)
                for service in (self.consumer, other):
                    with self.assertRaises(ValueError):
                        self.state.assert_service_unfenced(service)
                self.assertEqual(self.plan(persist=True).status, 'unverifiable')
                (path / 'manifest.json').unlink()
                path.rmdir()

    def test_manual_stage2_fence_blocks_stage1b_image_update_and_passive_trust(self):
        self.manual_operation()
        current = self.consumer_now() if any(i.compose_service == 'consumer' for i in self.runtime) else self.consumer
        plan = self.agent._compose_plan(current, self.runtime, persist=True)
        self.assertEqual((plan.status, plan.reasons), ('unverifiable', ('namespace_apply_unresolved',)))
        self.assertFalse(plan.update_eligible)
        with self.assertRaises(sqlite3.IntegrityError):
            with self.state.connect() as c:
                c.execute("INSERT INTO compose_bootstrap_fences VALUES(?,?,?,'active','x','x')",
                          (self.key(), 'b' * 32, 'x'))

    def test_terminal_success_expires_only_through_bounded_retention(self):
        operation = self.execute()
        path = self.state.root / 'compose-recoveries' / operation['id']
        with self.state.read() as c, checked_bundle(self.state.root, path) as bundle:
            self.assertEqual(lifecycle(c, operation['id'], bundle)[0], 'terminal')
            self.assertTrue(bundle['namespace_apply'])
        retention._cleanup_compose_artifact(self.state, path, 1, datetime.now(timezone.utc) + timedelta(days=30), False)
        self.assertFalse(path.exists())
        self.assertIsNone(self.state.bootstrap_fence(self.key()))

    def test_frozen_older_schema9_reader_refuses_every_v3_bundle(self):
        """Option B: older binaries are unsupported while any v3 evidence exists."""
        def older_bootstrap_fence_refuses(manifest):
            # Frozen from main@44aae82 State.bootstrap_fence orphan scan.
            if isinstance(manifest, dict) and manifest.get('version') == 1:
                return False
            if not isinstance(manifest, dict) or manifest.get('version') != 2 or manifest.get('action') != 'bootstrap':
                return True
            return None

        def older_checked_bundle_accepts(manifest):
            # Frozen from main@44aae82 checked_bundle manifest gate.
            bootstrap = manifest.get('version') == 2
            if bootstrap:
                return manifest.get('action') == 'bootstrap'
            return set(manifest) == {'version', 'binding', 'files'} and manifest['version'] == 1
        for health in ('healthy', 'unhealthy'):
            self.desired_health = health
            operation = self.execute()
            manifest = json.loads((self.state.root / 'compose-recoveries' / operation['id'] / 'manifest.json').read_text())
            self.assertEqual((manifest['version'], manifest['action']), (3, 'namespace_apply'))
            self.assertTrue(older_bootstrap_fence_refuses(manifest))
            self.assertFalse(older_checked_bundle_accepts(manifest))
            self.setUp()

    def test_proof_is_bounded_and_strict(self):
        operation = self.execute()
        path = self.state.root / 'compose-recoveries' / operation['id']
        proof = (path / 'proof.json').read_bytes()
        self.assertLessEqual(len(proof), namespace_apply.PROOF_LIMIT)
        parsed = json.loads(proof)
        self.assertEqual(set(parsed), namespace_apply.PROOF_KEYS)
        self.assertNotIn('UTC', proof.decode())  # No environment values or model payloads.
        self.assertEqual(sorted(os.listdir(path)), ['baseline-00', 'desired-00', 'manifest.json', 'proof.json'])
        for name in os.listdir(path):
            self.assertEqual(os.stat(path / name).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o700)


class EnvFileBaselineTests(Stage2Fixture):
    """env_file in both trusted baseline and desired source: identical layouts,
    so only the Stage 2 refusal stops Apply, despite enumerable Phase 2A inventory."""

    def prepare_layout(self):
        (self.root / 'consumer.env').write_text('EXTRA=1\n')
        self.model['services']['consumer']['env_file'] = './consumer.env'
        self.write_source()
        selected = self.live_model()['services']['consumer']
        self.consumer = replace(self.consumer, labels={**self.consumer.labels, ns.HASH_LABEL: ns.resolved_hash(
            selected, OWNER_ID, ns.service_hash(selected))})
        self.runtime = [self.consumer, self.owner]

    def test_env_file_in_baseline_and_desired_is_ineligible(self):
        self.assertEqual(self.plan().eligibility_reasons, ('namespace_env_file_unsupported', 'namespace_unsupported_compose'))
        self.assert_ineligible('namespace_env_file_unsupported')
        with self.assertRaises(ns.NamespaceRefused) as raised:
            plan = self.plan()
            namespace_apply.review_namespace_apply(
                self.consumer, self.runtime, model=plan.desired_model, inventory=plan.inventory,
                baseline=plan.baseline, diff=plan.diff, desired_hash=plan.desired_hash,
                deps=self.agent._namespace_apply_deps())
        self.assertEqual(raised.exception.reason, 'namespace_env_file_unsupported')


class PeerTests(Stage2Fixture):
    """A third project container: bound by identity, state/health, StartedAt and RestartCount."""
    HELPER_ID = '8' * 64

    def prepare_layout(self):
        self.model['services']['helper'] = {'image': 'example/helper:1'}
        self.write_source()
        helper = replace(self.owner, name='helper', container_id=self.HELPER_ID, image='example/helper:1',
                         compose_service='helper', health='none', started_at='2026-10-04T11:00:00.000000001Z',
                         labels={**self.owner.labels, 'com.docker.compose.service': 'helper'})
        self.runtime = [self.consumer, self.owner, helper]
        self.observations[self.HELPER_ID] = self.observation(helper, 'synthetic_default', 120, False)

    def test_peer_restart_blocks_before_marker_and_is_manual_after(self):
        restart = lambda: self.observations[self.HELPER_ID].update(restart_count=1)
        self.assert_blocked(self.execute(self.review(), before=restart))
        self.setUp()

        def effect(phase):
            self.place_consumer(health='unhealthy')
            restart()
        self.effects = [effect]
        self.assert_manual(self.execute())

    def test_unchanged_peer_allows_success(self):
        self.assertEqual(self.execute()['status'], 'succeeded')


class NamespaceApplyWebTests(TestCase):
    """HTTP review page: one bounded owner fact and configuration-only recovery copy."""
    import test_compose_reconciliation as _phase1
    setUp = _phase1.ServiceDetailAndOperationRouteTests.setUp

    def review_page(self, namespace):
        self.agent.compose_status_data = self._phase1.ServiceDetailAndOperationRouteTests.drifted(apply_eligible=True)
        self.agent.namespace_review = namespace
        return self.client.post('/compose/apply/review', data={'csrf': self.csrf, 'action': 'apply',
                                                              'service_key': 'container/' + 'a' * 64})

    def test_review_shows_owner_fact_and_configuration_only_recovery(self):
        page = self.review_page({'owner': 'gluetun', 'owner_unchanged': True, 'configuration_only_recovery': True})
        self.assertEqual(page.status_code, 200)
        self.assertIn('Shares the network namespace of gluetun; the owner will not be changed.', page.text)
        self.assertIn('Recovery restores the previous Compose configuration only', page.text)
        self.assertIn('desired changes remain pending', page.text)
        self.assertIn('application data and database migrations are not rolled back', page.text)
        self.assertNotIn('VPN', page.text)

    def test_malformed_namespace_fact_is_refused(self):
        for namespace in ({'owner': '<script>', 'owner_unchanged': True, 'configuration_only_recovery': True},
                          {'owner': 'gluetun', 'owner_unchanged': True, 'configuration_only_recovery': True,
                           'owner_id': 'a' * 64},
                          {'owner': 'gluetun', 'owner_unchanged': False, 'configuration_only_recovery': True}):
            with self.subTest(namespace=namespace):
                self.assertEqual(self.review_page(namespace).status_code, 409)

    def test_namespace_outcome_presentation(self):
        base = {'id': 'f' * 32, 'kind': 'compose_reconcile', 'summary': {'action': 'apply', 'namespace': True}}
        manual = operation_presentation({**base, 'status': 'failed', 'result': {
            'namespace': True, 'manual_recovery_required': True, 'mutation_performed': None, 'possible_mutation': True}})
        self.assertIn('Recreation may have occurred', manual['alert'])
        self.assertEqual(manual['outcome'], 'manual')
        blocked = operation_presentation({**base, 'status': 'blocked', 'result': {'namespace': True}})
        self.assertIn('no workload changes', blocked['alert'])
        success = operation_presentation({**base, 'status': 'succeeded', 'result': {'namespace': True}})
        self.assertIn('namespace owner was unchanged', success['alert'])


# ---------------------------------------------------------------------------
# Finding 1: the Layer A-qualified change catalogue is the Apply change surface.
DELETE = object()


class ShapeFixture(Stage2Fixture):
    """Baseline/desired selected-consumer field edits around the real review."""
    BASE = {}
    DESIRED = {}

    def edit(self, changes):
        consumer = self.model['services']['consumer']
        for field, value in changes.items():
            if isinstance(value, list):
                value = [item(self) if callable(item) else item for item in value]
            if value is DELETE:
                consumer.pop(field, None)
            else:
                consumer[field] = value
        self.write_source()

    def bind(self, name, **overrides):
        path = self.root / name
        path.mkdir(exist_ok=True)
        mount = {'type': 'bind', 'source': str(path), 'target': '/data', 'read_only': True,
                 'bind': {'create_host_path': False}, **overrides}
        return {key: value for key, value in mount.items() if value is not DELETE}

    def prepare_layout(self):
        self.edit(self.BASE)
        selected = self.live_model()['services']['consumer']
        self.consumer = replace(self.consumer, labels={**self.consumer.labels, ns.HASH_LABEL: ns.resolved_hash(
            selected, OWNER_ID, ns.service_hash(selected))})
        self.runtime = [self.consumer, self.owner]
        self.mounts[CONSUMER_ID] = self.runtime_mounts(selected)

    def make_desired_edit(self):
        self.edit(self.DESIRED)


def _bind(name, **overrides):
    return lambda fixture: fixture.bind(name, **overrides)


POSITIVE = {
    'environment': ({'environment': {'TZ': 'UTC'}}, {'environment': {'TZ': 'Europe/London', 'A': '<&>'}}),
    'environment-added': ({'environment': DELETE}, {'environment': {'TZ': 'UTC'}}),
    'labels': ({'labels': {'tier': 'one'}}, {'labels': {'tier': 'two'}}),
    'command': ({'command': DELETE}, {'command': ['sh', '-c', 'sleep 3600']}),
    'command-changed': ({'command': ['sh', '-c', 'sleep 3600']}, {'command': ['sh', '-c', 'sleep 7200']}),
    'command-to-pair': ({'command': ['sh', '-c', 'sleep 3600']},
                        {'entrypoint': ['sh', '-c'], 'command': ['sleep 3600']}),
    'pair-script-changed': ({'entrypoint': ['sh', '-c'], 'command': ['sleep 1']}, {'command': ['sleep 2']}),
    'pair-removed': ({'entrypoint': ['sh', '-c'], 'command': ['sleep 1']},
                     {'entrypoint': DELETE, 'command': DELETE}),
    'entrypoint': ({'entrypoint': DELETE, 'command': DELETE},
                   {'entrypoint': ['sh', '-c'], 'command': ['sleep 3600']}),
    'restart': ({'restart': DELETE}, {'restart': 'unless-stopped'}),
    'logging': ({'logging': DELETE},
                {'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}),
    'logging-options': ({'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}},
                        {'logging': {'driver': 'json-file', 'options': {'max-size': '20m', 'max-file': '5'}}}),
    'bind-added': ({'volumes': DELETE}, {'volumes': [_bind('data-a')]}),
    'bind-source-a-to-b': ({'volumes': [_bind('data-a')]}, {'volumes': [_bind('data-b')]}),
}


class PositiveShapeMixin:
    def test_qualified_change_is_eligible_and_applies(self):
        plan = self.plan()
        self.assertTrue(plan.apply_eligible, plan.eligibility_reasons)
        self.assertIsNotNone(plan.namespace_apply_review)
        operation = self.execute()
        self.assertEqual(operation['status'], 'succeeded', operation)
        self.assertEqual(self.phases(), ['apply'])
        self.assertEqual(self.sources(), self.desired)

    def test_qualified_change_failure_recovers_configuration_only(self):
        self.desired_health = 'unhealthy'
        self.assert_recovered(self.execute())


for _name, (_base, _desired) in POSITIVE.items():
    _cls = '_'.join(['QualifiedShape'] + [part.title() for part in _name.split('-')]) + 'Tests'
    globals()[_cls] = type(_cls, (PositiveShapeMixin, ShapeFixture), {'BASE': _base, 'DESIRED': _desired})


class QualifiedShapeOrderedOverrideTests(MultiInputFixture):
    """Ordered override + project .env: the resolved change is a qualified environment edit."""

    def test_resolved_consumer_change_is_environment_only(self):
        plan = self.plan()
        self.assertTrue(plan.apply_eligible, plan.eligibility_reasons)
        before = plan.baseline.model['services']['consumer']
        after = plan.desired_model['services']['consumer']
        self.assertEqual({field for field in set(before) | set(after) if before.get(field) != after.get(field)},
                         {'environment'})


# Fields that Stage 1 proof and hash calibration may understand but Stage 2 may not change.
NEGATIVE = {
    'privileged': ({}, {'privileged': True}),
    'cap_add': ({}, {'cap_add': ['NET_ADMIN']}),
    'cap_drop': ({}, {'cap_drop': ['ALL']}),
    'security_opt': ({}, {'security_opt': ['no-new-privileges:true']}),
    'sysctls': ({}, {'sysctls': {'net.core.somaxconn': '1024'}}),
    'read_only': ({}, {'read_only': True}),
    'user': ({}, {'user': '1000:1000'}),
    'shm_size': ({}, {'shm_size': '64m'}),
    'init': ({}, {'init': True}),
    'stdin_open': ({}, {'stdin_open': True}),
    'tty': ({}, {'tty': True}),
    'stop_signal': ({}, {'stop_signal': 'SIGINT'}),
    'stop_grace_period': ({}, {'stop_grace_period': '30s'}),
    'healthcheck': ({}, {'healthcheck': {'test': ['CMD', 'true']}}),
    'logging-driver': ({}, {'logging': {'driver': 'local', 'options': {'max-size': '10m'}}}),
    'logging-driver-no-options': ({}, {'logging': {'driver': 'json-file', 'options': {}}}),
    'logging-unqualified-option': ({}, {'logging': {'driver': 'json-file', 'options': {'tag': 'x'}}}),
    'logging-bad-size': ({}, {'logging': {'driver': 'json-file', 'options': {'max-size': '-1'}}}),
    'restart-always': ({}, {'restart': 'always'}),
    'command-other-shape': ({}, {'command': ['/bin/app', '--flag']}),
    'entrypoint-other-shape': ({}, {'entrypoint': ['/bin/app']}),
    'environment-non-string': ({}, {'environment': {'N': 1}}),
    'command-standalone-one-element': ({}, {'command': ['some-script']}),
    'entrypoint-standalone': ({}, {'entrypoint': ['sh', '-c']}),
    'entrypoint-with-multi-command': ({}, {'entrypoint': ['sh', '-c'], 'command': ['a', 'b']}),
    'entrypoint-with-three-element-command': ({}, {'entrypoint': ['sh', '-c'], 'command': ['sh', '-c', 'x']}),
    'one-element-command-unqualified-entrypoint': ({}, {'entrypoint': ['/bin/app'], 'command': ['x']}),
    'command-empty': ({}, {'command': []}),
    'entrypoint-empty': ({}, {'entrypoint': []}),
    'entrypoint-empty-with-command': ({}, {'entrypoint': [], 'command': ['sh', '-c', 'x']}),
    'qualified-command-to-empty': ({'command': ['sh', '-c', 'sleep 1']}, {'command': []}),
    'qualified-pair-to-empty-command': ({'entrypoint': ['sh', '-c'], 'command': ['sleep 1']}, {'command': []}),
    'qualified-pair-to-empty-entrypoint': ({'entrypoint': ['sh', '-c'], 'command': ['sleep 1']}, {'entrypoint': []}),
    'qualified-pair-entrypoint-removed': ({'entrypoint': ['sh', '-c'], 'command': ['sleep 1']},
                                          {'entrypoint': DELETE}),
    'qualified-command-gains-unqualified-entrypoint': ({'command': ['sh', '-c', 'sleep 1']},
                                                       {'entrypoint': ['/bin/app']}),
    'bind-writable': ({}, {'volumes': [_bind('data-a', read_only=False)]}),
    'bind-read-only-missing': ({}, {'volumes': [_bind('data-a', read_only=DELETE)]}),
    'bind-create-host-path': ({}, {'volumes': [_bind('data-a', bind={'create_host_path': True})]}),
    'bind-extra-bind-option': ({}, {'volumes': [_bind('data-a', bind={'create_host_path': False,
                                                                       'propagation': 'rshared'})]}),
    'bind-missing-source': ({}, {'volumes': [_bind('data-a', source='/nonexistent/upt-stage2')]}),
    'bind-relative-source': ({}, {'volumes': [_bind('data-a', source='data-a')]}),
    'bind-short-syntax': ({}, {'volumes': ['/srv/a:/data:ro']}),
    'bind-extra-key': ({}, {'volumes': [_bind('data-a', consistency='cached')]}),
    'bind-writable-baseline': ({'volumes': [_bind('data-a', read_only=False)]}, {'volumes': [_bind('data-b')]}),
    'bind-named-volume': ({}, {'volumes': [{'type': 'volume', 'source': 'cache', 'target': '/data'}]}),
}

class NegativeShapeMixin:
    def test_unqualified_change_is_ineligible_and_never_reviewed(self):
        plan = self.plan()
        self.assertFalse(plan.apply_eligible)
        self.assertIsNone(plan.namespace_apply_review)
        with self.assertRaises(ValueError):
            self.review()
        self.assertEqual(self.invocations, [])
        self.assertEqual([record.id for record in self.records()], [self.baseline.id])

    def test_catalogue_validator_refuses_it_directly(self):
        from docker_update_manager.namespace_change_catalog import refuse_unqualified_changes
        trusted = BaselineStore(self.state).load(self.baseline).model['services']['consumer']
        with self.assertRaises(ns.NamespaceRefused) as raised:
            refuse_unqualified_changes(trusted, self.live_model()['services']['consumer'])
        self.assertEqual(raised.exception.reason, 'namespace_change_unqualified')
        self.assertNotIn(str(self.root), str(raised.exception))


for _name, (_base, _desired) in NEGATIVE.items():
    _cls = 'UnqualifiedShape' + ''.join(part.title() for part in re.split('[-_]', _name)) + 'Tests'
    globals()[_cls] = type(_cls, (NegativeShapeMixin, ShapeFixture), {'BASE': _base, 'DESIRED': _desired})
del _name, _base, _desired, _cls


class CatalogueUnitTests(TestCase):
    """Calibration-capable but uncatalogued fields may stay unchanged; only changes are judged."""

    def check(self, baseline, desired):
        from docker_update_manager.namespace_change_catalog import refuse_unqualified_changes
        refuse_unqualified_changes(baseline, desired)

    def test_unchanged_unqualified_fields_are_permitted(self):
        common = {'image': 'x', 'privileged': True, 'user': '1000', 'sysctls': {'a': '1'},
                  'volumes': [{'type': 'bind', 'source': '/x', 'target': '/y', 'read_only': False}]}
        self.check({**common, 'environment': {'A': '1'}}, {**common, 'environment': {'A': '2'}})

    def test_hash_fields_are_not_authority(self):
        with self.assertRaises(ns.NamespaceRefused):
            self.check({}, {'privileged': True})
        self.assertTrue({'privileged', 'user', 'cap_add'} <= set(ns.HASH_FIELDS))
        from docker_update_manager.namespace_change_catalog import CATALOGUE, COUPLED
        self.assertEqual(set(CATALOGUE), {'environment', 'labels', 'restart', 'logging', 'volumes'})
        self.assertEqual(set(COUPLED), {'entrypoint', 'command'})

    def test_command_and_entrypoint_are_validated_only_as_a_coupled_pair(self):
        script = ['sh', '-c', 'sleep 1']
        pair = {'entrypoint': ['sh', '-c'], 'command': ['sleep 1']}
        for baseline, desired in (({}, {'command': script}), ({}, pair), ({'command': script}, pair),
                                  (pair, {}), (pair, {**pair, 'command': ['sleep 2']}),
                                  ({'command': None}, {'command': script})):
            self.check(baseline, desired)  # Qualified Layer A combinations pass.
        for baseline, desired in (
                ({}, {'command': ['some-script']}), ({}, {'entrypoint': ['sh', '-c']}),
                ({}, {'entrypoint': ['sh', '-c'], 'command': ['a', 'b']}),
                ({}, {'entrypoint': ['sh', '-c'], 'command': script}),
                ({}, {'entrypoint': ['/bin/app'], 'command': ['x']}), ({}, {'command': ['sh', '-c']}),
                ({}, {'command': ['sh', '-c', '']}), ({}, {'command': ['sh', '-c', 'x', 'y']}),
                (pair, {'command': ['sleep 1']}), (pair, {'entrypoint': ['sh', '-c']}),
                (pair, {**pair, 'command': ['sleep 1', 'x']}), (pair, {**pair, 'entrypoint': ['sh']}),
                ({'entrypoint': ['/bin/app']}, {'entrypoint': ['/bin/app'], 'command': script})):
            with self.subTest(desired=desired), self.assertRaises(ns.NamespaceRefused) as raised:
                self.check(baseline, desired)
            self.assertEqual(raised.exception.reason, 'namespace_change_unqualified')
            self.assertNotIn('sleep', str(raised.exception))

    def test_empty_command_and_entrypoint_are_never_absence(self):
        script = ['sh', '-c', 'sleep 1']
        pair = {'entrypoint': ['sh', '-c'], 'command': ['sleep 1']}
        for baseline, desired in (({}, {'command': []}), ({'command': None}, {'command': []}), ({}, {'entrypoint': []}),
                                  ({'entrypoint': None}, {'entrypoint': []}), ({'command': []}, {}),
                                  ({'entrypoint': []}, {'command': None}), ({'command': script}, {'command': []}),
                                  (pair, {'command': []}), (pair, {'entrypoint': []}),
                                  ({'command': []}, {'command': script})):
            with self.subTest(baseline=baseline, desired=desired), self.assertRaises(ns.NamespaceRefused):
                self.check(baseline, desired)

    def test_no_generic_empty_value_normalisation(self):
        # Exact resolved-value comparison: an empty map is a visible change that is
        # then judged by its own field validator, never silently equal to absence.
        self.check({'environment': {}}, {'environment': {'A': '1'}})
        self.check({'volumes': None}, {'volumes': None})
        for baseline, desired in (({}, {'volumes': []}), ({'volumes': []}, {}), ({}, {'logging': {}}),
                                  ({}, {'restart': ''}), ({}, {'unknown': []}), ({}, {'unknown': {}})):
            with self.subTest(desired=desired), self.assertRaises(ns.NamespaceRefused):
                self.check(baseline, desired)

    def test_unknown_or_malformed_models_fail_closed(self):
        for baseline, desired in (({}, {'future_field': 1}), (None, {}), ({}, [])):
            with self.assertRaises(ns.NamespaceRefused):
                self.check(baseline, desired)


# ---------------------------------------------------------------------------
# Finding 2: proof.json is a closed nested schema; a valid checksum is not enough.
class ProofSchemaTests(Stage2Fixture):
    def setUp(self):
        super().setUp()
        self.operation = self.execute()
        self.assertEqual(self.operation['status'], 'succeeded')
        self.bundle = self.state.root / 'compose-recoveries' / self.operation['id']
        self.proof = json.loads((self.bundle / 'proof.json').read_bytes())

    def rewrite(self, proof, *, recompute=True):
        data = json.dumps(proof, sort_keys=True, separators=(',', ':')).encode()
        manifest = json.loads((self.bundle / 'manifest.json').read_bytes())
        if recompute:
            manifest['proof_sha256'] = hashlib.sha256(data).hexdigest()
        for name, content in (('proof.json', data), ('manifest.json', json.dumps(
                manifest, sort_keys=True, separators=(',', ':')).encode())):
            (self.bundle / name).write_bytes(content)
            os.chmod(self.bundle / name, 0o600)

    def refuses(self, mutate, label=''):
        proof = copy.deepcopy(self.proof)
        mutate(proof)
        self.rewrite(proof)
        with self.assertRaises(ValueError, msg=label), checked_bundle(self.state.root, self.bundle):
            pass

    def test_unmodified_bundle_validates_and_round_trips_the_producer_schema(self):
        namespace_apply.validate_proof(self.proof)
        with checked_bundle(self.state.root, self.bundle) as bundle:
            self.assertTrue(bundle['namespace_apply'])

    def test_checksum_recomputed_nested_tampering_is_rejected(self):
        peer = ['8' * 64, 'synthetic', 'helper', 'example/helper:1', 'sha256:' + '1' * 64, None, str(self.root),
                [str(self.source)], None, 'synthetic', 'running', 'running', 'none',
                '2026-10-04T11:00:00.000000001Z', 0]
        cases = {
            'extra owner key': lambda p: p['owner'].update(extra=1),
            'missing owner key': lambda p: p['owner'].pop('netns'),
            'missing consumer key': lambda p: p['consumer'].pop('restart_count'),
            'extra consumer key': lambda p: p['consumer'].update(env={'A': 'b'}),
            'owner boolean wrong type': lambda p: p['owner'].update(has_healthcheck='yes'),
            'owner integer as boolean': lambda p: p['owner'].update(restart_count=True),
            'owner integer as string': lambda p: p['owner'].update(pid='101'),
            'negative restart count': lambda p: p['consumer'].update(restart_count=-1),
            'zero pid': lambda p: p['owner'].update(pid=0),
            'oversized integer': lambda p: p['owner'].update(restart_count=2 ** 40),
            'owner string as list': lambda p: p['owner'].update(image=['x']),
            'malformed owner ID': lambda p: p['owner'].update(container_id='abc123'),
            'uppercase owner ID': lambda p: p['owner'].update(container_id='A' * 64),
            'malformed consumer ID': lambda p: p['consumer'].update(container_id='x' * 64),
            'malformed image ID': lambda p: p['owner'].update(image_id='sha256:xyz'),
            'malformed netns': lambda p: p['owner'].update(netns='net:[x]'),
            'malformed started_at': lambda p: p['consumer'].update(started_at='yesterday'),
            'oversized string': lambda p: p['owner'].update(working_dir='/' + 'a' * 5000),
            'NUL in string': lambda p: p['owner'].update(project='a\x00b'),
            'owner state domain': lambda p: p['owner'].update(state='rebooting'),
            'consumer health domain': lambda p: p['consumer'].update(health='great'),
            'condition domain': lambda p: p.update(condition='service_completed'),
            'condition type': lambda p: p.update(condition=['service_started']),
            'relationship as dict': lambda p: p.update(relationship={'network_mode': 'service:owner'}),
            'relationship length': lambda p: p.update(relationship=['service:owner']),
            'relationship wrong owner': lambda p: p.update(relationship=['service:other', 'null']),
            'relationship type': lambda p: p.update(relationship=['service:owner', None]),
            'extra baseline key': lambda p: p['baseline'].update(path='/x'),
            'missing baseline key': lambda p: p['baseline'].pop('manifest'),
            'baseline id format': lambda p: p['baseline'].update(id='z' * 32),
            'extra desired key': lambda p: p['desired'].update(content='x'),
            'missing desired key': lambda p: p['desired'].pop('inventory'),
            'desired hash format': lambda p: p['desired'].update(model='nothex'),
            'extra fingerprint entry': lambda p: p['fingerprints'].update(extra='a' * 64),
            'missing fingerprint entry': lambda p: p['fingerprints'].pop('diff'),
            'fingerprint format': lambda p: p['fingerprints'].update(diff='G' * 64),
            'extra hash entry': lambda p: p['hashes'].update(extra='a' * 64),
            'missing hash entry': lambda p: p['hashes'].pop('baseline_oracle'),
            'hash type': lambda p: p['hashes'].update(desired_resolved=7),
            'hashes as list': lambda p: p.update(hashes=['a' * 64] * 4),
            'runtime short': lambda p: p.update(runtime=p['runtime'][:7]),
            'runtime long': lambda p: p.update(runtime=p['runtime'] + ['x']),
            'runtime member type': lambda p: p['runtime'].__setitem__(0, 29),
            'runtime digest format': lambda p: p['runtime'].__setitem__(7, 'abc'),
            'runtime as dict': lambda p: p.update(runtime={'a': 'b'}),
            'peers oversized': lambda p: p.update(peers=[peer] * 65),
            'peers as dict': lambda p: p.update(peers={'a': peer}),
            'peer length': lambda p: p.update(peers=[peer[:-1]]),
            'peer extra member': lambda p: p.update(peers=[peer + ['x']]),
            'peer ID format': lambda p: p.update(peers=[['bad'] + peer[1:]]),
            'peer state domain': lambda p: p.update(peers=[peer[:10] + ['gone'] + peer[11:]]),
            'peer restart type': lambda p: p.update(peers=[peer[:14] + ['0']]),
            'peer files type': lambda p: p.update(peers=[peer[:7] + ['x'] + peer[8:]]),
            'version type': lambda p: p.update(version='3'),
            'version value': lambda p: p.update(version=4),
            'logical key format': lambda p: p.update(logical_key='k'),
            'review format': lambda p: p.update(review='r' * 64 + 'x'),
            'top-level extra key': lambda p: p.update(extra=True),
            'top-level missing key': lambda p: p.pop('peers'),
        }
        for label, mutate in cases.items():
            with self.subTest(label):
                self.setUp_bundle_again()
                self.refuses(mutate, label)

    def setUp_bundle_again(self):
        # Restore the pristine bundle between mutations.
        self.rewrite(self.proof)

    def test_well_formed_peer_member_is_accepted(self):
        proof = copy.deepcopy(self.proof)
        proof['peers'] = [['8' * 64, 'synthetic', 'helper', 'example/helper:1', 'sha256:' + '1' * 64, None,
                           str(self.root), [str(self.source)], None, 'synthetic', 'running', 'running', 'none',
                           '2026-10-04T11:00:00.000000001Z', 0]]
        namespace_apply.validate_proof(proof)

    def test_unrecomputed_checksum_manifest_and_binding_tampering_still_rejected(self):
        proof = copy.deepcopy(self.proof)
        proof['owner']['restart_count'] = 3
        self.rewrite(proof, recompute=False)
        with self.assertRaises(ValueError), checked_bundle(self.state.root, self.bundle):
            pass
        self.rewrite(self.proof)
        manifest = json.loads((self.bundle / 'manifest.json').read_bytes())
        for mutate in (lambda m: m.update(version=4), lambda m: m['binding'].update(extra='x'),
                       lambda m: m['binding'].update(review='0' * 64), lambda m: m.update(action='bootstrap')):
            changed = copy.deepcopy(manifest)
            mutate(changed)
            (self.bundle / 'manifest.json').write_bytes(json.dumps(changed).encode())
            os.chmod(self.bundle / 'manifest.json', 0o600)
            with self.assertRaises(ValueError), checked_bundle(self.state.root, self.bundle):
                pass

    def test_oversized_proof_is_rejected(self):
        proof = copy.deepcopy(self.proof)
        proof['owner']['working_dir'] = '/' + 'a' * namespace_apply.PROOF_LIMIT
        self.rewrite(proof)
        with self.assertRaises(ValueError), checked_bundle(self.state.root, self.bundle):
            pass

    def test_malformed_nested_proof_keeps_the_service_globally_fenced(self):
        proof = copy.deepcopy(self.proof)
        proof['owner']['extra'] = 1
        self.rewrite(proof)
        # Resolved terminal evidence that no longer validates cannot be waived.
        with self.assertRaises(ValueError):
            self.state.assert_service_unfenced(self.consumer)
        other = replace(self.consumer, stack='other', compose_service='web', container_id=EXTRA_ID,
                        working_dir='/srv/other', compose_files=['/srv/other/compose.yml'])
        with self.assertRaises(ValueError):
            self.state.assert_service_unfenced(other)


# ---------------------------------------------------------------------------
# Finding 2: v3 key sets are frozen schema constants, not derived from runtime types.
class FrozenV3SchemaTests(Stage2Fixture):
    def test_producer_matches_the_frozen_v3_schema(self):
        """Fails when a runtime proof type changes, forcing an explicit compatibility decision."""
        from dataclasses import fields
        self.assertEqual(tuple(f.name for f in fields(ns.NamespaceOwnerProof)), namespace_apply.V3_OWNER_KEYS)
        self.assertEqual(tuple(f.name for f in fields(ns.NamespaceConsumerProof)), namespace_apply.V3_CONSUMER_KEYS)
        review = self.plan().namespace_apply_review
        facts = review.facts()
        self.assertEqual(set(facts), namespace_apply.PROOF_KEYS)
        self.assertEqual(tuple(facts['owner']), namespace_apply.V3_OWNER_KEYS)
        self.assertEqual(tuple(facts['consumer']), namespace_apply.V3_CONSUMER_KEYS)
        self.assertEqual(tuple(facts['baseline']), namespace_apply.V3_BASELINE_KEYS)
        self.assertEqual(tuple(facts['desired']), namespace_apply.V3_DESIRED_KEYS)
        self.assertEqual(tuple(facts['fingerprints']), namespace_apply.V3_FINGERPRINT_KEYS)
        self.assertEqual(tuple(facts['hashes']), namespace_apply.V3_HASH_KEYS)
        # The live producer output serialises and validates against the frozen schema.
        namespace_apply.validate_proof(json.loads(json.dumps(facts)))

    def test_reader_does_not_follow_runtime_dataclasses(self):
        """A future runtime field is not silently accepted by (or breaking for) retained v3."""
        import dataclasses
        import inspect
        source = inspect.getsource(namespace_apply.validate_proof)
        self.assertIsNone(re.search(r'\bfields\(', source))
        for name in ('NamespaceOwnerProof', 'NamespaceConsumerProof'):
            self.assertNotIn(name, source)
        self.assertNotIn('dataclasses.fields', inspect.getsource(namespace_apply))
        facts = json.loads(json.dumps(self.plan().namespace_apply_review.facts()))
        extended = dataclasses.make_dataclass('NamespaceOwnerProof', [('future_runtime_only', int, 0)],
                                              bases=(ns.NamespaceOwnerProof,), frozen=True)
        with patch.object(ns, 'NamespaceOwnerProof', extended), patch.object(ns, 'NamespaceConsumerProof', extended):
            namespace_apply.validate_proof(facts)  # Retained v3 evidence still validates.
            facts['owner']['future_runtime_only'] = 0
            with self.assertRaises(namespace_apply.ProofSchemaError):
                namespace_apply.validate_proof(facts)  # A future key is not automatically v3.

    def test_frozen_constants_are_immutable_tuples(self):
        for name in ('V3_OWNER_KEYS', 'V3_CONSUMER_KEYS', 'V3_BASELINE_KEYS', 'V3_DESIRED_KEYS',
                     'V3_FINGERPRINT_KEYS', 'V3_HASH_KEYS'):
            value = getattr(namespace_apply, name)
            self.assertIsInstance(value, tuple)
            self.assertEqual(len(set(value)), len(value))
