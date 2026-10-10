"""Same-project trusted-baseline reconciliation. Synthetic Docker/Compose only."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import threading
import time
import unittest
from dataclasses import replace
from unittest.mock import Mock, patch

from docker_update_manager import compose_namespace as ns, webservice
from docker_update_manager.compose_baseline import BaselineStore
from docker_update_manager.compose_drift import DRIFTED, compute_diff
from docker_update_manager.compose_reconcile import ReconcileOutcome
from docker_update_manager.operations import do_pin, do_update
from docker_update_manager.reconciliation import mark_changed, mark_project_inputs_changed, reconcile_operation

from test_compose_namespace import CONSUMER_ID, OWNER_HASH, NamespaceFixture
import test_post_mutation_reconciliation as post_mutation_fixture

SIBLING_ID = 'f' * 64


class SameProjectRefreshTests(NamespaceFixture):
    """qBittorrent-like consumer behind an owner, with a Radarr-like sibling."""

    def setUp(self):
        super().setUp()
        self.model['services']['sibling'] = {'image': 'example/sibling:1'}
        self.write_source()
        self.sibling = self.service('sibling', SIBLING_ID, OWNER_HASH)
        self.runtime.append(self.sibling)
        self.observations[SIBLING_ID] = self.observation(self.sibling, 'synthetic_default', 103, False)
        self.trusted = self.plan(persist=True).baseline
        self.assertIsNotNone(self.trusted)

    def mutate_sibling_source(self):
        # A sibling-only source change accepted by e.g. pin/Apply on that sibling.
        self.model['services']['sibling']['image'] = 'example/sibling:2'
        self.write_source()
        self.sibling.image = 'example/sibling:2'

    def assert_not_refreshed(self):
        self.assertEqual([record.id for record in self.records()], [self.trusted.record.id])

    def project_scope(self, baseline):
        return compute_diff(baseline.model, self.model, 'consumer', baseline.record.fingerprint,
                            project_observed=baseline.project_observed).scope

    def test_stale_consumer_baseline_refreshed_then_consumer_drift_reviewable(self):
        self.mutate_sibling_source()
        self.assertNotEqual(self.project_scope(self.trusted), 'service')
        self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 1)
        records = self.records()
        self.assertEqual(len(records), 2)
        fresh = BaselineStore(self.state).load(records[0])
        self.assertEqual((fresh.record.container_id, fresh.record.runtime_hash),
                         (CONSUMER_ID, self.consumer.labels[ns.HASH_LABEL]))
        self.assertEqual(self.project_scope(fresh), 'service')
        # Passive only: Docker was read, never mutated.
        self.assertTrue(all(not {'up', 'restart', 'rm', 'stop', 'create'} & set(command) for command in self.calls))
        # Later consumer-only drift is itemised against the refreshed baseline.
        self.model['services']['consumer']['restart'] = 'always'
        self.write_source()
        plan = self.plan()
        self.assertEqual(plan.status, DRIFTED)
        self.assertEqual(plan.baseline.record.id, fresh.record.id)
        self.assertEqual(plan.diff.scope, 'service')
        self.assertNotIn('project_changes', plan.eligibility_reasons)
        self.assertEqual(len(self.records()), 2)  # review never persists

    def test_no_existing_exact_baseline_never_creates_first_trust(self):
        # The in-sync sibling has never been trusted; compose_status() would
        # capture it, but reconciliation must not.
        # A replacement consumer only has evidence for its predecessor.
        self.mutate_sibling_source()
        self.runtime[0] = replace(self.consumer, container_id='9' * 64)
        self.observations['9' * 64] = dict(self.observations.pop(CONSUMER_ID), id='9' * 64)
        self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 0)
        self.assert_not_refreshed()
        self.assertEqual(BaselineStore(self.state).records(self.agent._baseline_key(self.sibling)), [])

    def test_restarted_owner_does_not_refresh_consumer(self):
        self.mutate_sibling_source()
        # Owner restarted after trust, then the consumer rejoined it: the
        # passive proof alone would accept the new owner context.
        self.owner.started_at = self.observations[self.owner.container_id]['started_at'] = '2099-01-01T00:00:00.5Z'
        self.consumer.started_at = self.observations[CONSUMER_ID]['started_at'] = '2099-01-01T00:00:01Z'
        self.assertEqual(self.plan(persist=False).status, 'in_sync')
        self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 0)
        self.assert_not_refreshed()

    def test_replaced_owner_does_not_refresh_consumer(self):
        self.mutate_sibling_source()
        new_id = 'd' * 64
        self.observations[new_id] = dict(self.observations.pop(self.owner.container_id), id=new_id)
        self.runtime[1] = replace(self.owner, container_id=new_id)
        self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 0)
        self.assert_not_refreshed()

    def test_changed_owner_source_does_not_refresh_consumer(self):
        self.mutate_sibling_source()
        self.model['services']['owner']['image'] = 'example/owner:2'
        self.write_source()
        self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 0)
        self.assert_not_refreshed()

    def test_owner_restart_inside_capture_bracket_refused(self):
        self.mutate_sibling_source()
        original = self.agent._confirm_runtime_unchanged

        def race(*args):
            original(*args)
            self.owner.started_at = self.observations[self.owner.container_id]['started_at'] = '2099-01-01T00:00:00Z'
            self.consumer.started_at = self.observations[CONSUMER_ID]['started_at'] = '2099-01-01T00:00:01Z'
        with patch.object(self.agent, '_confirm_runtime_unchanged', side_effect=race):
            self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 0)
        self.assert_not_refreshed()

    def test_same_project_name_different_identity_untouched(self):
        self.mutate_sibling_source()
        for field, value in (('working_dir', str(self.root / 'elsewhere')),
                             ('compose_files', [str(self.source), str(self.root / 'override.yml')])):
            with self.subTest(field=field):
                stranger = replace(self.sibling, **{field: value})
                self.assertEqual(self.agent._refresh_project_baselines(stranger), 0)
                self.assert_not_refreshed()
        with self.subTest(field='reordered files'):
            self.consumer.compose_files = [str(self.root / 'override.yml'), str(self.source)]
            self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 0)

    def test_ambiguity_and_unresolved_state_publish_nothing(self):
        self.mutate_sibling_source()
        real_inventory = webservice.build_inventory
        calls = {'n': 0}

        def racing_inventory(*args, **kwargs):
            calls['n'] += 1
            if calls['n'] == 2:
                self.source.write_text(self.source.read_text() + '# concurrent edit\n')
            return real_inventory(*args, **kwargs)
        faults = {
            'source race': patch('docker_update_manager.webservice.build_inventory', side_effect=racing_inventory),
            'runtime ambiguity': patch.object(self.agent, '_confirm_runtime_unchanged',
                                              side_effect=webservice._ComposeCheckRaced('runtime_changed_during_check')),
            'hash unavailable': patch.object(self, 'hash_fault', True),
            'unsupported network': patch.object(self, 'network_fault', True),
            'unresolved fence': patch.object(self.state, 'namespace_update_fence', return_value={'operation_id': 'x'}),
            'bootstrap fence': patch.object(self.state, 'bootstrap_fence', return_value={'operation_id': 'x'}),
        }
        for name, fault in faults.items():
            with self.subTest(fault=name):
                calls['n'] = 0
                self.write_source()
                with fault:
                    self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 0)
                self.assert_not_refreshed()

    def test_corrupt_trusted_baseline_publishes_nothing(self):
        self.mutate_sibling_source()
        record = self.records()[0]
        stored = sorted(path for path in (BaselineStore(self.state).root / record.id).rglob('*') if path.is_file())
        self.assertTrue(stored)
        for path in stored:
            path.chmod(0o600)
            path.write_bytes(path.read_bytes() + b'tampered')
        self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 0)
        self.assertEqual([item.id for item in self.records()], [record.id])

    def test_drifted_member_never_adopts_or_reproduces_evidence(self):
        self.mutate_sibling_source()
        self.model['services']['consumer']['restart'] = 'always'
        self.write_source()
        with patch.object(self.agent, '_trusted_baseline') as adopting:
            self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 0)
        adopting.assert_not_called()
        self.assert_not_refreshed()

    def test_review_paths_never_persist(self):
        self.mutate_sibling_source()
        for _ in range(2):
            self.plan(persist=False)
        self.assert_not_refreshed()

    def test_rpc_flag_is_strict_and_only_enqueues(self):
        call = {'service_key': 'container/' + SIBLING_ID, 'after_reconcile': True}
        with self.assertRaises(ValueError):
            self.agent.handle('refresh_start', {**call, 'project_inputs': 'yes'})
        with patch.object(self.agent, '_queue_project_refresh', return_value='queued') as queue, \
             patch.object(self.agent, '_refresh_project_baselines') as refresh:
            self.assertEqual(self.agent.handle('refresh_start', {**call, 'project_inputs': True}), {'status': 'queued'})
        queue.assert_called_once_with(self.sibling)
        refresh.assert_not_called()

    def trust_owner(self):
        # A plain (non-namespace) service: only replica gates protect it.
        baseline = self.plan(self.owner, persist=True).baseline
        self.assertIsNotNone(baseline)
        return baseline

    def owner_records(self):
        return [record.id for record in BaselineStore(self.state).records(self.agent._baseline_key(self.owner))]

    def add_owner_replica(self, identity='7' * 64, state='running'):
        replica = replace(self.owner, container_id=identity, name='owner-2', state=state)
        self.runtime.append(replica)
        self.observations[identity] = dict(self.observations[self.owner.container_id], id=identity, pid=104)
        return replica

    def test_plain_service_refreshed_when_sole_member(self):
        trusted = self.trust_owner()
        self.mutate_sibling_source()
        self.assertEqual(self.agent._refresh_project_baselines(self.sibling), 2)
        self.assertEqual(len(self.owner_records()), 2)
        self.assertNotEqual(self.owner_records()[0], trusted.record.id)

    def test_multiple_replicas_never_refreshed_even_with_agreeing_hashes(self):
        trusted = self.trust_owner()
        self.mutate_sibling_source()
        replica = self.add_owner_replica()
        self.assertEqual(replica.labels[ns.HASH_LABEL], self.owner.labels[ns.HASH_LABEL])
        self.agent._refresh_project_baselines(self.sibling)
        self.assertEqual(self.owner_records(), [trusted.record.id])

    def test_stopped_replica_also_makes_service_ambiguous(self):
        trusted = self.trust_owner()
        self.mutate_sibling_source()
        self.add_owner_replica(state='exited')
        with patch('docker_update_manager.webservice.discover',
                   side_effect=lambda *a, all_containers=False, **kw: [item for item in self.runtime
                                                                       if all_containers or item.state == 'running']):
            self.agent._refresh_project_baselines(self.sibling)
        self.assertEqual(self.owner_records(), [trusted.record.id])

    def test_replica_membership_change_during_proof_refused(self):
        trusted = self.trust_owner()
        self.mutate_sibling_source()
        original = self.agent._confirm_runtime_unchanged

        def race(*args):
            original(*args)
            if args[0].container_id == self.owner.container_id and len(self.runtime) == 3:
                self.add_owner_replica()
        with patch.object(self.agent, '_confirm_runtime_unchanged', side_effect=race):
            self.agent._refresh_project_baselines(self.sibling)
        self.assertEqual(self.owner_records(), [trusted.record.id])


class RefreshQueueTests(NamespaceFixture):
    """Bounded, coalesced, best-effort dispatch; never inline proof."""

    def setUp(self):
        super().setUp()
        self.project_refresh_patch.stop()  # exercise the real dispatcher
        self.entered, self.release = threading.Event(), threading.Event()
        self.proved = []

        def slow(service):
            self.proved.append(service.working_dir)
            self.entered.set()
            if not self.release.wait(5):
                raise AssertionError('proof was never released')
        patcher = patch.object(self.agent, '_refresh_project_baselines', side_effect=slow)
        patcher.start(); self.addCleanup(patcher.stop)
        self.addCleanup(self.release.set)

    def project(self, index):
        return replace(self.consumer, working_dir=str(self.root / f'project-{index}'))

    def workers(self):
        return [thread for thread in threading.enumerate() if thread.name == 'upt-project-refresh']

    def drain(self):
        self.release.set()
        deadline = time.monotonic() + 5
        while self.agent._project_refresh_thread is not None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertIsNone(self.agent._project_refresh_thread)

    def test_duplicates_coalesce_queue_is_bounded_and_single_worker(self):
        self.assertEqual(self.agent._queue_project_refresh(self.project(0)), 'queued')
        self.assertTrue(self.entered.wait(5))  # project 0 is now in flight
        self.assertEqual(self.agent._queue_project_refresh(self.project(0)), 'queued')
        self.assertEqual(self.agent._queue_project_refresh(self.project(0)), 'coalesced')
        statuses = [self.agent._queue_project_refresh(self.project(index))
                    for index in range(1, webservice.PROJECT_REFRESH_QUEUE_LIMIT + 3)]
        self.assertEqual(statuses.count('queued'), webservice.PROJECT_REFRESH_QUEUE_LIMIT - 1)
        self.assertEqual(statuses[-3:], ['saturated'] * 3)
        self.assertEqual(len(self.workers()), 1)
        self.drain()
        self.assertEqual(self.proved.count(str(self.root / 'project-0')), 2)  # in flight + one coalesced rerun
        self.assertEqual(len(self.proved), len(set(self.proved)) + 1)
        self.assertEqual(self.agent._project_refresh_pending, {})

    def test_worker_failure_and_start_failure_are_contained(self):
        self.agent._refresh_project_baselines.side_effect = [RuntimeError('proof failed'), None]
        self.agent._queue_project_refresh(self.project(1))
        self.agent._queue_project_refresh(self.project(2))
        self.drain()
        self.assertEqual(self.agent._refresh_project_baselines.call_count, 2)
        with patch('docker_update_manager.webservice.threading.Thread') as thread:
            thread.return_value.start.side_effect = RuntimeError('no threads')
            self.assertEqual(self.agent._queue_project_refresh(self.project(3)), 'unavailable')
        self.assertEqual(self.agent._project_refresh_pending, {})
        self.assertIsNone(self.agent._project_refresh_thread)
        self.agent._refresh_project_baselines.side_effect = None
        self.assertEqual(self.agent._queue_project_refresh(self.project(3)), 'queued')
        self.drain()

    def test_worker_defers_until_terminal_success_and_never_blocks(self):
        terminal = {}

        @webservice._after_terminal_project_refresh
        def worker(agent, operation_id, status):
            agent._defer_project_refresh(self.project(5))
            self.assertEqual(agent._project_refresh_pending, {})  # nothing dispatched yet
            terminal[operation_id] = status
        statuses = {'ok': 'succeeded', 'bad': 'failed', 'stop': 'blocked'}
        with patch.object(self.state, 'operation_status',
                          side_effect=lambda operation_id, **kw: {'status': terminal[operation_id]}):
            for operation_id, status in statuses.items():
                started = time.monotonic()
                worker(self.agent, operation_id, status)
                self.assertLess(time.monotonic() - started, 1)
        self.assertTrue(self.entered.wait(5))
        self.assertEqual(self.proved, [str(self.root / 'project-5')])
        self.drain()
        self.assertEqual(self.proved, [str(self.root / 'project-5')])  # failed/blocked queued nothing

    def test_dispatch_failure_never_escapes_worker(self):
        @webservice._after_terminal_project_refresh
        def worker(agent, operation_id):
            agent._defer_project_refresh(self.project(6))
            return 'terminal'
        with patch.object(self.state, 'operation_status', side_effect=RuntimeError('state unavailable')):
            self.assertEqual(worker(self.agent, 'x'), 'terminal')
        with patch.object(self.state, 'operation_status', return_value={'status': 'succeeded'}), \
             patch.object(self.agent, '_queue_project_refresh', side_effect=RuntimeError('queue failed')):
            self.assertEqual(worker(self.agent, 'x'), 'terminal')
        self.assertEqual(self.proved, [])

    def test_web_workers_defer_refresh(self):
        for name in ('_update_worker', '_rollback_worker', '_bootstrap_worker', '_compose_worker'):
            self.assertTrue(hasattr(getattr(webservice.ReadOnlyService, name), '__wrapped__'), name)


class TriggerTests(unittest.TestCase):
    """Only clean successes that change shared Compose inputs trigger refresh."""

    setUp = post_mutation_fixture.PostMutationTests.setUp
    docker = post_mutation_fixture.PostMutationTests.docker

    def test_pin_triggers_once_with_current_service(self):
        with self.docker():
            refresh = Mock()
            do_pin(self.old, self.state, yes=True, output=lambda *_: None, post_project_change=refresh)
        refresh.assert_called_once_with(self.old)

    def test_mutable_tag_update_and_dry_run_do_not_trigger(self):
        with self.docker():
            refresh = Mock()
            do_update(self.old, self.state, yes=True, output=lambda *_: None, post_project_change=refresh)
            do_pin(self.current, self.state, dry_run=True, output=lambda *_: None, post_project_change=refresh)
        refresh.assert_not_called()

    def test_failed_pin_does_not_trigger(self):
        with self.docker(), patch('docker_update_manager.operations.validate', side_effect=RuntimeError('bad')):
            refresh = Mock()
            with self.assertRaises(RuntimeError):
                do_pin(self.old, self.state, yes=True, output=lambda *_: None, post_project_change=refresh)
        refresh.assert_not_called()

    def test_follow_up_failure_never_changes_triggering_outcome(self):
        with self.docker():
            backup = do_pin(self.old, self.state, yes=True, output=lambda *_: None,
                            post_project_change=Mock(side_effect=RuntimeError('refresh failed')))
        self.assertTrue(backup)
        self.assertEqual(self.state.history(self.old.key)[0]['result'], 'SUCCESS')

    def test_only_clean_reconcile_outcomes_trigger(self):
        @reconcile_operation
        def operation(service, state, outcome):
            mark_changed()
            mark_project_inputs_changed()
            return outcome
        cases = {ReconcileOutcome('succeeded', True): True,
                 ReconcileOutcome('failed', True, recovered=True): False,
                 ReconcileOutcome('failed', True, manual_recovery_required=True): False,
                 ReconcileOutcome('succeeded', True, recovered=True): False,
                 ReconcileOutcome('blocked'): False}
        for outcome, expected in cases.items():
            with self.subTest(outcome=outcome):
                refresh = Mock()
                operation(self.old, self.state, outcome, reconcile_discover=lambda: [self.old],
                          post_project_change=refresh)
                self.assertEqual(refresh.called, expected)

    def test_exception_after_source_change_does_not_trigger(self):
        @reconcile_operation
        def operation(service, state):
            mark_changed()
            mark_project_inputs_changed()
            raise RuntimeError('recreate failed')
        refresh = Mock()
        with self.assertRaises(RuntimeError):
            operation(self.old, self.state, reconcile_discover=lambda: [self.old], post_project_change=refresh)
        refresh.assert_not_called()

