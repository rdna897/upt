"""Stage 1b synthetic tests: bounded namespace-consumer image updates.

No real Docker, Compose, registry or /proc access. The capability gate runs its
real code against a synthetic plugin binary whose digest the test qualifies.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock, patch

import yaml

from progress_assertions import assert_core_stage_model, assert_stage_model
from test_compose_namespace import CONSUMER_ID, IMAGE_ID, OWNER_ID, NamespaceFixture

from docker_update_manager import compose_namespace as ns, namespace_update, operations, webservice
from docker_update_manager.compose_drift import IN_SYNC, UNVERIFIABLE
from docker_update_manager.compose_bootstrap import make_plan, BootstrapRefused
from docker_update_manager.progress import Reporter

NEW_ID = 'd' * 64
OTHER_OWNER_ID = 'f' * 64
NEW_IMAGE_ID = 'sha256:' + '3' * 64
NEW_DIGEST = 'sha256:' + '4' * 64
VERSIONS = {'Server': {'Version': '29.7.1', 'ApiVersion': '1.55', 'Os': 'linux', 'Arch': 'amd64'},
            'Client': {'Version': '29.7.1', 'ApiVersion': '1.55'}}


class Stage1bFixture(NamespaceFixture):
    def setUp(self):
        super().setUp()
        self.plugin = self.root / 'docker-compose'
        self.plugin.write_bytes(b'synthetic qualified compose plugin')
        self.qualified = ('29.7.1', '1.55', 'linux', 'amd64', '29.7.1', '1.55', 'v5.3.1',
                          hashlib.sha256(self.plugin.read_bytes()).hexdigest())
        self.compose_version = 'v5.3.1'
        self.netns = {101: 'net:[4026534203]', 102: 'net:[4026534203]', 103: 'net:[4026534203]'}
        self.ups = []
        self.on_up = self.replace_consumer
        self.after_up = None
        self.before_up = None
        self.up_error = None
        self.patch('compose_namespace.QUALIFIED_IMAGE_UPDATE_RUNTIME', new=self.qualified)
        self.patch('compose_namespace.os.readlink', side_effect=self.readlink)
        self.patch('namespace_update.run', side_effect=self.docker_run)
        self.patch('namespace_update.discover', side_effect=lambda *a, **kw: list(self.runtime))
        self.patch('operations.run', side_effect=self.mutating_run)
        self.patch('operations.remote_manifest', return_value={'digest': NEW_DIGEST, 'platforms': []})

    def patch(self, target, **kwargs):
        mocked = patch('docker_update_manager.' + target, **kwargs)
        mocked.start(); self.addCleanup(mocked.stop)

    def readlink(self, path):
        pid = int(path.split('/')[2])
        if pid not in self.netns:
            raise PermissionError()
        return self.netns[pid]

    def docker_run(self, args, **kw):
        if args[:2] == ['docker', 'version']:
            return json.dumps(VERSIONS)
        if args[:2] == ['docker', 'info']:
            return json.dumps([{'Name': 'compose', 'Version': self.compose_version, 'Path': str(self.plugin)}])
        if args[:3] == ['docker', 'compose', 'version']:
            return json.dumps({'version': self.compose_version})
        if args[:3] == ['docker', 'image', 'inspect'] and args[4].startswith('{"Id"'):
            self.calls.append(list(args))
            tagged = args[-1].endswith(NEW_DIGEST) or any(call[:3] == ['docker', 'image', 'tag'] for call in self.ups_and_tags())
            image_id, digest = (NEW_IMAGE_ID, NEW_DIGEST) if tagged else (IMAGE_ID, 'sha256:' + '2' * 64)
            return json.dumps({'Id': image_id, 'RepoDigests': ['example/consumer@' + digest],
                               'Descriptor': None, 'Identity': None})
        return super().docker_run(args, **kw)

    def ups_and_tags(self):
        return [call for call in self.calls if call[:2] == ['docker', 'image'] and call[2] == 'tag'] + self.ups

    def mutating_run(self, args, **kw):
        self.calls.append(list(args))
        if args[:2] == ['docker', 'pull'] or args[:3] == ['docker', 'image', 'tag']:
            return ''
        if args[:2] == ['docker', 'compose'] and 'up' in args:
            self.ups.append(list(args))
            if self.before_up:
                self.before_up()
            if self.on_up:
                self.on_up()
            if self.up_error:
                raise RuntimeError(self.up_error)
            return ''
        raise AssertionError(args)

    def replace_consumer(self, *, owner_id=OWNER_ID, state='running', started='2026-10-04T12:05:00.000000001Z',
                         runtime_hash=None):
        labels = dict(self.consumer.labels)
        labels[ns.HASH_LABEL] = runtime_hash or self.consumer.labels[ns.HASH_LABEL]
        fresh = replace(self.consumer, container_id=NEW_ID, image_id=NEW_IMAGE_ID, digest=NEW_DIGEST,
                        started_at=started, state=state, network_mode='container:' + owner_id, labels=labels)
        self.runtime = [fresh if item.container_id == CONSUMER_ID else item for item in self.runtime]
        self.observations.pop(CONSUMER_ID, None)
        self.observations[NEW_ID] = self.observation(fresh, 'container:' + owner_id, 103 if state == 'running' else 0, False)
        self.fresh = fresh

    def replace_owner(self):
        owner = replace(self.owner, container_id=OTHER_OWNER_ID, started_at='2026-10-04T12:03:00.000000001Z')
        self.runtime = [owner if item.container_id == OWNER_ID else item for item in self.runtime]
        observed = self.observations.pop(OWNER_ID)
        self.observations[OTHER_OWNER_ID] = {**observed, 'id': OTHER_OWNER_ID, 'pid': 104,
                                             'started_at': owner.started_at}
        self.netns[104] = 'net:[4026534274]'
        self.owner = owner

    def update(self, **kwargs):
        return operations.do_update(self.consumer, self.state, yes=True, output=lambda *a: None, **kwargs)

    def operation(self):
        with self.state.read() as c:
            return c.execute("SELECT status,summary,result FROM operation_runs").fetchall()

    def assert_manual_recovery(self, action):
        with self.assertRaises(operations.RecoveryRequired):
            action()
        rows = self.operation()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'failed')
        self.assertTrue(json.loads(rows[0]['result'])['manual_recovery_required'])
        self.assertTrue(json.loads(rows[0]['summary'])['namespace_recreate_started'])
        key = self.agent._baseline_key(self.consumer)
        self.assertTrue(self.state.namespace_update_fence(key))
        with self.assertRaisesRegex(ValueError, 'namespace_update_unresolved'):
            self.state.assert_service_unfenced(self.consumer)
        with self.state.read() as c:
            history = c.execute("SELECT result,rollback_result FROM history WHERE action='update'").fetchall()
        self.assertEqual([tuple(row) for row in history], [('FAILED', 'MANUAL RECOVERY REQUIRED')])
        # Exactly one Compose launch; no automatic recreation against any owner.
        self.assertEqual(len(self.ups), 1)

    def assert_blocked_without_marker(self, action, reason=None):
        with self.assertRaises(operations.PreMutationRefusal) as refused:
            action()
        if reason:
            self.assertEqual(refused.exception.reason, reason)
        self.assertEqual(self.ups, [])
        self.assertIsNone(self.state.namespace_update_fence(self.agent._baseline_key(self.consumer)))
        for row in self.operation():
            self.assertNotEqual(row['status'], 'running')
            self.assertFalse(json.loads(row['summary']).get('namespace_recreate_started'))


class CapabilityGateTests(Stage1bFixture):
    def test_qualified_runtime_enables_normal_consumer_update_with_exact_strict_argv(self):
        plan = self.plan()
        self.assertEqual(plan.status, IN_SYNC)
        self.assertTrue(plan.update_eligible, plan.update_reasons)
        self.assertEqual(plan.namespace_update_review.owner.container_id, OWNER_ID)
        result = self.update()
        self.assertTrue(result['updated'])
        base = ['docker', 'compose', '--project-directory', str(self.root), '--project-name', 'synthetic',
                '-f', str(self.source)]
        self.assertEqual(self.ups, [base + ['up', '-d', '--no-deps', '--pull', 'never', '--no-build', 'consumer']])
        mutations = [call for call in self.calls if call[:2] == ['docker', 'pull'] or call[:3] == ['docker', 'image', 'tag']
                     or 'up' in call]
        for call in mutations:
            self.assertNotIn('owner', call)
            self.assertFalse(any(OWNER_ID in part for part in call))
        self.assertEqual(mutations[0], ['docker', 'pull', 'example/consumer@' + NEW_DIGEST])
        rows = self.operation()
        self.assertEqual(rows[0]['status'], 'succeeded')
        self.assertIsNone(self.state.namespace_update_fence(self.agent._baseline_key(self.consumer)))
        self.state.assert_service_unfenced(self.fresh)

    def test_unqualified_compose_version_or_build_stays_read_only(self):
        for change in ('version', 'build', 'engine'):
            with self.subTest(change=change):
                if change == 'version':
                    self.compose_version = 'v5.3.2'
                elif change == 'build':
                    self.plugin.write_bytes(b'rebuilt plugin claiming v5.3.1')
                else:
                    VERSIONS['Server']['Version'] = '29.8.0'
                try:
                    plan = self.plan()
                    self.assertEqual(plan.status, IN_SYNC)
                    self.assertFalse(plan.update_eligible)
                    self.assertEqual(plan.update_reasons, ('namespace_unsupported_compose',))
                    self.assert_blocked_without_marker(self.update, 'namespace_unsupported_compose')
                finally:
                    self.compose_version = 'v5.3.1'
                    self.plugin.write_bytes(b'synthetic qualified compose plugin')
                    VERSIONS['Server']['Version'] = '29.7.1'

    def test_mandatory_proc_proof_failure_blocks_but_read_only_stays_in_sync(self):
        self.netns = {}
        plan = self.plan()
        self.assertEqual(plan.status, IN_SYNC)
        self.assertFalse(plan.update_eligible)
        self.assert_blocked_without_marker(self.update)

    def test_no_health_and_pin_flags_refused(self):
        for flag in ('no_health', 'pin'):
            with self.subTest(flag=flag):
                self.assert_blocked_without_marker(lambda: self.update(**{flag: True}), 'namespace_unsupported_compose')
        self.assertFalse((self.state.root / 'backups').exists())


class PreMutationTests(Stage1bFixture):
    def test_owner_identity_change_before_mutation_blocks(self):
        review = namespace_update.review_namespace_update(self.consumer)
        self.observations[OWNER_ID]['restart_count'] = 1
        self.assert_blocked_without_marker(lambda: self.update(namespace_review=review), 'namespace_owner_changed')

    def test_owner_replacement_immediately_pre_exec_blocks(self):
        original = namespace_update.NamespaceImageUpdate.before_exec
        def replace_then_exec(guard):
            self.replace_owner()
            return original(guard)
        with patch.object(namespace_update.NamespaceImageUpdate, 'before_exec', replace_then_exec):
            self.assert_blocked_without_marker(self.update)

    def test_unhealthy_and_stopped_owner_block(self):
        for state, health in (('running', 'unhealthy'), ('exited', 'unhealthy')):
            with self.subTest(state=state):
                review = namespace_update.review_namespace_update(self.consumer)
                saved = (self.owner, dict(self.observations[OWNER_ID]), list(self.runtime))
                owner = replace(self.owner, state=state, health=health)
                self.runtime = [owner if item.container_id == OWNER_ID else item for item in self.runtime]
                self.observations[OWNER_ID].update(state=state, health=health)
                try:
                    self.assert_blocked_without_marker(lambda: self.update(namespace_review=review))
                finally:
                    self.owner, self.observations[OWNER_ID], self.runtime = saved

    def test_source_and_execution_context_change_after_review_block(self):
        review = namespace_update.review_namespace_update(self.consumer)
        self.model['services']['consumer']['labels'] = {'changed': 'yes'}
        self.assert_blocked_without_marker(lambda: self.update(namespace_review=review))
        del self.model['services']['consumer']['labels']
        self.network_fault = True
        self.assert_blocked_without_marker(lambda: self.update(namespace_review=review))

    def test_web_intent_without_review_never_substitutes_fresh_proof(self):
        plan = self.plan()
        self.assertEqual(plan.namespace_update_review.container_id, CONSUMER_ID)
        self.state.create_operation('op1', kind='update', service_key='container/' + CONSUMER_ID,
                                    service='consumer', stack='synthetic', requested_by='test', summary={})
        intent = SimpleNamespace(service_key='container/' + CONSUMER_ID, execution_context_fingerprint='ctx',
                                 namespace_review=None, target=('t',) * 4, service_identity=())
        with patch.object(self.agent, '_intent_candidate', return_value={}), \
                patch.object(self.agent, '_fresh_update_service', return_value=(self.consumer, None, None, self.model, 'ctx')), \
                patch.object(webservice, 'do_update') as update:
            self.agent._update_worker('op1', {'requested_by': 'test', 'client_ip': '', 'user_agent': ''}, intent)
        update.assert_not_called()
        self.assertEqual(self.operation()[0]['status'], 'blocked')


class PostMarkerTests(Stage1bFixture):
    def test_new_consumer_joins_exact_reviewed_owner_and_resolved_hash(self):
        refresh = Mock()
        self.update(post_mutation=refresh)
        refresh.assert_called_once_with(self.fresh)
        current = next(row for row in self.state.verification_snapshot() if row['service_key'] == 'container/' + NEW_ID)
        self.assertTrue(current['invalidated'])
        self.assertIsNone(current['verification_id'])
        self.assertEqual(current['result']['service']['container_id'], NEW_ID)
        self.assertIn(NEW_ID, [item['container_id'] for item in self.state.runtime_snapshot()['containers']])
        self.assertEqual(self.fresh.network_mode, 'container:' + OWNER_ID)
        with self.state.read() as c:
            row = c.execute("SELECT result,new_image_id FROM history WHERE action='update'").fetchone()
        self.assertEqual(tuple(row), ('SUCCESS', NEW_IMAGE_ID))

    def web_operation(self):
        self.state.create_operation('web1', kind='update', service_key='container/' + CONSUMER_ID,
                                    service='consumer', stack='synthetic', requested_by='test', summary={})
        self.state.set_operation_running('web1')
        return {'origin': 'web', 'operation_id': 'web1', 'requested_by': 'test'}

    def test_web_owned_success_persists_all_eight_stages_with_the_final_one_before_terminal(self):
        # The History record terminalizes a namespace update, so the core reporter can no longer
        # persist stage 8; it is committed in the same transaction, immediately before the terminal event.
        context = self.web_operation()
        reporter = self.agent._operation_progress_reporter('web1', 'update', 'Preparing update')
        self.update(audit_context=context, namespace_review=self.plan().namespace_update_review, reporter=reporter)
        events = self.state.operation_status('web1')['events']
        self.assertEqual(assert_stage_model(self, events, 8), list(range(1, 9)))
        self.assertEqual(events[-2]['stage'], '8/8 Record update')
        self.assertEqual(events[-1]['kind'], 'operation_completed')
        self.assertEqual(len([e for e in events if e['stage'] == '8/8 Record update']), 1)

    def test_web_owned_success_is_published_atomically_with_history(self):
        context = self.web_operation()
        review = self.plan().namespace_update_review
        self.update(audit_context=context, namespace_review=review)
        self.assertEqual(self.operation()[0]['status'], 'succeeded')
        # The worker's own later completion cannot overwrite the verified result.
        self.assertFalse(self.state.finish_operation('web1', 'succeeded', message='done'))

    def test_web_owned_post_marker_failure_stays_failed(self):
        context = self.web_operation()
        self.on_up = lambda: self.replace_consumer(runtime_hash='9' * 64)
        self.assert_manual_recovery(lambda: self.update(audit_context=context))
        self.assertFalse(self.state.finish_operation('web1', 'succeeded', message='done'))
        self.assertEqual(self.operation()[0]['status'], 'failed')

    def test_subprocess_failure_after_marker_is_manual_recovery(self):
        self.up_error = 'cannot join network namespace of a non running container'
        self.on_up = lambda: self.replace_consumer(state='created', started='0001-01-01T00:00:00Z')
        self.assert_manual_recovery(self.update)

    def test_created_replacement_with_matching_hash_and_image_is_not_trusted(self):
        self.on_up = lambda: self.replace_consumer(state='created', started='0001-01-01T00:00:00Z')
        self.assert_manual_recovery(self.update)

    def test_matching_hash_and_image_alone_cannot_succeed_without_namespace(self):
        def stale():
            self.replace_consumer()
            self.netns[103] = 'net:[1]'
        self.on_up = stale
        self.assert_manual_recovery(self.update)

    def test_successful_compose_without_replacement_is_not_success(self):
        self.on_up = None
        self.assert_manual_recovery(self.update)

    def test_unavailable_proc_after_replacement_is_manual_recovery(self):
        def replaced():
            self.replace_consumer()
            del self.netns[103]
        self.on_up = replaced
        self.assert_manual_recovery(self.update)

    def test_replacement_owner_after_launch_cannot_be_rebound(self):
        def owner_replaced_during_compose():
            self.replace_owner()
            self.replace_consumer(owner_id=OTHER_OWNER_ID, started='2026-10-04T12:05:00.000000001Z',
                                  runtime_hash=ns.resolved_hash(self.model['services']['consumer'], OTHER_OWNER_ID,
                                                                ns.service_hash(self.model['services']['consumer'])))
            self.netns[103] = self.netns[104]
        self.on_up = owner_replaced_during_compose
        self.assert_manual_recovery(self.update)

    def test_owner_change_after_marker_is_manual_recovery(self):
        def restarted():
            self.replace_consumer()
            self.observations[OWNER_ID]['restart_count'] = 1
        self.on_up = restarted
        self.assert_manual_recovery(self.update)

    def test_resolved_runtime_hash_mismatch_is_manual_recovery(self):
        self.on_up = lambda: self.replace_consumer(runtime_hash='9' * 64)
        self.assert_manual_recovery(self.update)

    def test_source_and_context_change_after_marker_are_manual_recovery(self):
        def source_changed():
            self.replace_consumer()
            self.model['services']['consumer']['labels'] = {'changed': 'yes'}
        self.on_up = source_changed
        self.assert_manual_recovery(self.update)

    def test_execution_context_change_after_marker_is_manual_recovery(self):
        def context_changed():
            self.replace_consumer()
            self.network_fault = True
        self.on_up = context_changed
        self.assert_manual_recovery(self.update)

    def test_owner_unhealthy_during_health_polling_is_manual_recovery(self):
        polls = []
        def starting():
            self.replace_consumer()
            self.fresh = replace(self.fresh, health='starting')
            self.runtime = [self.fresh if item.container_id == NEW_ID else item for item in self.runtime]
            self.observations[NEW_ID]['health'] = 'starting'
        def sleep(_seconds):
            polls.append(1)
            owner = replace(self.owner, health='unhealthy')
            self.runtime = [owner if item.container_id == OWNER_ID else item for item in self.runtime]
            self.observations[OWNER_ID]['health'] = 'unhealthy'
        self.on_up = starting
        with patch('docker_update_manager.operations.time.sleep', side_effect=sleep):
            self.assert_manual_recovery(self.update)
        self.assertEqual(polls, [1])

    def test_interrupted_post_marker_operation_never_infers_success(self):
        def interrupted():
            self.replace_consumer()
            raise KeyboardInterrupt()
        self.on_up = interrupted
        self.assert_manual_recovery(self.update)

    def test_abandoned_marked_operation_recovers_as_manual_and_fences_trust(self):
        guard = namespace_update.NamespaceImageUpdate(self.consumer, self.state)
        guard.target('registry', {'digest': NEW_DIGEST})
        with patch.object(guard, 'check'):
            guard.target_image_id = None
            with patch.object(guard, 'target'):
                guard.before_exec()
        # Simulate the agent dying: the row stays running with the marker.
        with self.state.connect() as c:
            c.execute("UPDATE operation_runs SET started_at='2000-01-01T00:00:00Z',created_at='2000-01-01T00:00:00Z'")
        self.state.recover_abandoned_operations()
        rows = self.operation()
        self.assertEqual(rows[0]['status'], 'failed')
        self.assertTrue(json.loads(rows[0]['result'])['manual_recovery_required'])
        self.replace_consumer()
        plan = self.agent._compose_plan(self.fresh, self.runtime, persist=True)
        self.assertEqual(plan.status, UNVERIFIABLE)
        self.assertIn('namespace_update_unresolved', plan.reasons)
        self.assertEqual(self.records(), [])
        with self.assertRaisesRegex(ValueError, 'not authorised'):
            self.state.record(stack='synthetic', service='consumer', action='update', result='SUCCESS',
                              namespace_operation_id=guard.operation_id)
        self.state.prune_operations(retention_days=0, limit=0)
        self.assertEqual(len(self.operation()), 1)


OLD_PIN = 'example/consumer:1@sha256:' + '2' * 64
NEW_PIN = 'example/consumer:1@' + NEW_DIGEST


class PinnedUpdateTests(Stage1bFixture):
    """Production-shaped consumer: tag@digest pin advanced by UPT's own source edit."""
    def setUp(self):
        super().setUp()
        self.model['services']['consumer']['image'] = OLD_PIN
        self.write_source()
        selected = self.model['services']['consumer']
        self.consumer = replace(self.consumer, image=OLD_PIN, labels={
            **self.consumer.labels, ns.HASH_LABEL: ns.resolved_hash(selected, OWNER_ID, ns.service_hash(selected))})
        self.runtime = [self.consumer, self.owner]
        self.patch('compose.run', side_effect=self.docker_run)

    def docker_run(self, args, **kw):
        if args[:2] == ['docker', 'compose'] and 'config' in args:
            self.model = yaml.safe_load(self.source.read_text())
            if '--quiet' in args:
                return ''
        return super().docker_run(args, **kw)

    def pinned_replacement(self):
        selected = yaml.safe_load(self.source.read_text())['services']['consumer']
        self.replace_consumer(runtime_hash=ns.resolved_hash(selected, OWNER_ID, ns.service_hash(selected)))
        self.fresh = replace(self.fresh, image=NEW_PIN)
        self.runtime = [self.fresh if item.container_id == NEW_ID else item for item in self.runtime]

    def test_pinned_consumer_update_succeeds_with_strict_argv(self):
        self.on_up = self.pinned_replacement
        self.assertTrue(self.plan().update_eligible)
        result = self.update()
        self.assertTrue(result['updated'])
        self.assertEqual(self.ups[0][-7:], ['up', '-d', '--no-deps', '--pull', 'never', '--no-build', 'consumer'])
        self.assertIn(NEW_PIN, self.source.read_text())
        self.assertEqual(self.operation()[0]['status'], 'succeeded')
        for call in self.calls:
            if call[:2] == ['docker', 'pull'] or 'up' in call:
                self.assertNotIn('owner', call)

    def test_pinned_update_reports_eight_real_stages_without_synthetic_ones(self):
        self.on_up = self.pinned_replacement
        reporter = Reporter(enabled=False)
        self.assertTrue(self.update(reporter=reporter)['updated'])
        self.assertEqual(assert_core_stage_model(self, reporter.events, 8), list(range(1, 9)))
        labels = [event.data['label'] for event in reporter.events if event.data.get('step')]
        self.assertEqual(labels[0], 'Resolve tracked channel')
        self.assertEqual(labels[-1], 'Record update')
        for synthetic in ('Preserve volumes and dependencies', 'Digest pin update complete'):
            self.assertNotIn(synthetic, labels)

    def test_pinned_dry_run_previews_the_same_eight_stage_model(self):
        reporter = Reporter(enabled=False)
        self.update(dry_run=True, reporter=reporter)
        stages = [(event.data['step'], event.data['steps'], event.status) for event in reporter.events if event.data.get('step')]
        self.assertEqual([item[0] for item in stages], list(range(1, 9)))
        self.assertEqual({item[1] for item in stages}, {8})
        self.assertEqual([item[2] for item in stages], ['completed', 'completed'] + ['pending'] * 6)

    def test_pinned_post_marker_failure_retains_new_pin_without_recovery(self):
        def failed():
            self.pinned_replacement()
            self.observations[OWNER_ID]['restart_count'] = 1
        self.on_up = failed
        self.assert_manual_recovery(self.update)
        self.assertIn(NEW_PIN, self.source.read_text())

    def test_unrelated_source_edit_after_pin_blocks_before_marker(self):
        def operator_edit(_target):
            self.source.write_text(self.source.read_text() + '# operator edit\n')
        with self.assertRaises(Exception):
            self.update(post_pin_check=operator_edit)
        self.assertEqual(self.ups, [])
        self.assertIsNone(self.state.namespace_update_fence(self.agent._baseline_key(self.consumer)))


class BoundaryTests(Stage1bFixture):
    def test_owner_protection_unchanged_on_qualified_runtime(self):
        self.assertIn('namespace_owner_has_dependents', self.plan(self.owner).update_reasons)
        for action in (lambda: operations.do_update(self.owner, self.state, yes=True),
                       lambda: operations.do_rollback(self.owner, self.state, yes=True),
                       lambda: operations.do_restart(self.owner)):
            with self.subTest(action=action), self.assertRaises(operations.PreMutationRefusal) as refused:
                action()
            self.assertEqual(refused.exception.reason, 'namespace_owner_has_dependents')
        self.assertEqual(self.ups, [])

    def test_runtime_reverse_reference_protects_owner_with_broken_source(self):
        self.source.write_text('not valid compose')
        self.model = None
        with self.assertRaises(operations.PreMutationRefusal) as refused:
            ns.require_mutation_safe(self.owner)
        self.assertEqual(refused.exception.reason, 'namespace_owner_has_dependents')

    def test_other_consumer_mutations_remain_unavailable_on_qualified_runtime(self):
        for action in (lambda: operations.do_rollback(self.consumer, self.state, yes=True),
                       lambda: operations.do_restart(self.consumer)):
            with self.subTest(action=action), self.assertRaises(operations.PreMutationRefusal) as refused:
                action()
            self.assertEqual(refused.exception.reason, 'namespace_unsupported_compose')
        with self.assertRaises(BootstrapRefused):
            make_plan(self.consumer, self.runtime, self.state, model_reader=lambda *a: self.model,
                      hash_reader=lambda *a: None, context_reader=lambda *a: None, mounts_reader=lambda *a: None,
                      baseline_available=lambda *a: True)
        self.assertEqual(self.ups, [])

    def test_ordinary_non_namespace_update_keeps_existing_command(self):
        ordinary = replace(self.owner, network_mode='synthetic_default')
        with patch('docker_update_manager.operations.require_mutation_safe') as safe, \
                patch('docker_update_manager.namespace_update.NamespaceImageUpdate') as guard, \
                patch('docker_update_manager.operations.run_compose_progress') as pull, \
                patch('docker_update_manager.operations.backup_files', return_value=self.root / 'b'):
            def up(args, **kw):
                self.ups.append(list(args))
                return ''
            self.on_up = None
            self.runtime = [replace(ordinary, container_id=NEW_ID, image_id=NEW_IMAGE_ID)]
            operations.do_update(ordinary, self.state, yes=True, output=lambda *a: None)
        safe.assert_called()
        guard.assert_not_called()
        pull.assert_called_once()
        self.assertEqual(self.ups[0][-4:], ['up', '-d', '--no-deps', 'owner'])


if __name__ == '__main__':
    import unittest
    unittest.main()
