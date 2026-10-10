"""Mutation/read-state integration with synthetic Docker and registry state."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import contextlib
import io
import json
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from docker_update_manager.config import Config
from docker_update_manager.models import ScanResult, Service
from docker_update_manager.operations import do_pin, do_restart, do_rollback, do_update
from docker_update_manager.reconciliation import public_service, queue_agent_verification
from docker_update_manager.state import State
from docker_update_manager.webservice import ReadOnlyService, _public_result
from docker_update_manager.webviews import merge_service_items


class PostMutationTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict('os.environ', {'UPT_TESTING': '1'})
        environment.start(); self.addCleanup(environment.stop)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.compose = self.root / 'compose.yml'
        self.compose.write_text('name: demo\nservices:\n  app:\n    image: example/app:latest\n    environment:\n      DEMO_SECRET: harmless-fake-secret\n')
        self.state = State(self.root / 'state')
        self.agent = ReadOnlyService(Config(str(self.root / 'config.yml')), self.state)
        self.old = Service('app', 'a'*64, 'example/app:latest', 'sha256:'+'1'*64,
                           'sha256:'+'2'*64, '1.0', None, 'amd64', 'running', 'healthy',
                           'always', '2026-01-01T00:00:00Z', stack='demo', compose_service='app',
                           working_dir=str(self.root), compose_files=[str(self.compose)],
                           labels={'secret': 'harmless-fake-secret'})
        self.new = replace(self.old, container_id='b'*64, image_id='sha256:'+'3'*64,
                           digest='sha256:'+'3'*64, version='1.1')
        self.current = self.old
        self.state.start_scan('before')
        self.state.finish_scan('before', 'complete', services=[_public_result(ScanResult(self.old, 'UPDATE', self.new.digest, '1.1'))])
        self.state.save_runtime_snapshot([public_service(self.old)])
        self.snapshot = self.state.latest_scan()

    def rows(self):
        return merge_service_items(self.state.latest_scan(), self.state.runtime_snapshot(), self.agent.verification_snapshot())

    def wait_refresh(self, service):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            key = 'container/' + service.container_id
            if self.agent.refresh_status(key)['status'] != 'checking':
                return
            time.sleep(.01)
        self.fail('targeted verification did not finish')

    @contextlib.contextmanager
    def docker(self, *, recovered=None):
        launches = []
        def run(args, **kwargs):
            if 'up' in args:
                # The old result is already unusable before Docker recreation.
                old = next(row for row in self.state.verification_snapshot() if row['service_key'] == 'container/' + self.old.container_id)
                self.assertTrue(old['invalidated'])
                launches.append(args)
                self.current = recovered if recovered and len(launches) > 1 else self.new
            return ''
        with patch('docker_update_manager.operations.require_mutation_safe'), \
             patch('docker_update_manager.operations.run', side_effect=run), \
             patch('docker_update_manager.operations.run_compose_progress'), \
             patch('docker_update_manager.operations.validate'), \
             patch('docker_update_manager.operations.remote_manifest', return_value={'digest': self.new.digest, 'platforms': []}), \
             patch('docker_update_manager.operations.tracking_image', return_value='example/app:latest'), \
             patch('docker_update_manager.operations.discover', side_effect=lambda **kwargs: [self.current]), \
             patch('docker_update_manager.webservice.discover', side_effect=lambda *args, **kwargs: [self.current]):
            yield launches

    def assert_pending(self, service):
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['service']['container_id'], service.container_id)
        self.assertEqual(rows[0]['status'], 'CHECK REQUIRED')
        self.assertIsNone(rows[0].get('remote_digest'))
        self.assertIsNone(rows[0].get('target_image'))
        self.assertIsNone(rows[0].get('verification_id'))
        self.assertEqual(self.state.latest_scan(), self.snapshot)
        self.assertNotIn('harmless-fake-secret', json.dumps(self.agent.verification_snapshot()))

    def test_real_ordinary_and_pinned_update_immediate_and_eventual_exact_verification(self):
        for pinned in (False, True):
            with self.subTest(pinned=pinned):
                if pinned:
                    self.old = replace(self.current, container_id='c'*64,
                                       image='example/app:latest@' + self.old.digest)
                    self.new = replace(self.old, container_id='d'*64, digest='sha256:'+'4'*64,
                                       image='example/app:latest@sha256:'+'4'*64)
                    self.current = self.old
                    self.compose.write_text('services:\n  app:\n    image: ' + self.old.image + '\n')
                    self.state.save_verification(_public_result(ScanResult(self.old, 'PINNED UPDATE', self.new.digest)))
                    self.state.save_runtime_snapshot([public_service(self.old)])
                entered, release = threading.Event(), threading.Event()
                def registry(service, state):
                    entered.set()
                    release.wait(3)
                    return ScanResult(service, 'CURRENT', service.digest)
                with self.docker(), patch('docker_update_manager.webservice.scan_service_with_tracking', side_effect=registry) as check, \
                     patch.object(self.agent, 'start_scan') as full_scan:
                    result = do_update(self.old, self.state, yes=True, output=lambda *_: None,
                                       post_mutation=self.agent._queue_post_mutation)
                    self.assertTrue(result['updated'])
                    try:
                        self.assertTrue(entered.wait(2))
                        self.assert_pending(self.new)
                    finally:
                        release.set()
                    self.wait_refresh(self.new)
                    self.assertEqual([call.args[0].container_id for call in check.call_args_list], [self.new.container_id])
                    full_scan.assert_not_called()
                self.assertEqual(self.rows()[0]['status'], 'CURRENT')
                self.assertEqual(self.state.latest_scan(), self.snapshot)

    def test_queue_failure_keeps_current_identity_and_check_required(self):
        queue = Mock(side_effect=RuntimeError('token=harmless-fake-secret'))
        with self.docker(), self.assertLogs('docker_update_manager.reconciliation', level='WARNING') as logs:
            result = do_update(self.old, self.state, yes=True, output=lambda *_: None, post_mutation=queue)
        self.assertTrue(result['updated'])
        queue.assert_called_once_with(self.new)
        self.assert_pending(self.new)
        self.assertEqual(self.state.runtime_snapshot()['status'], 'current')
        self.assertNotIn('harmless-fake-secret', str(logs.output))

    def test_runtime_failure_revokes_historical_update_even_without_current_runtime(self):
        queue = Mock()
        with self.docker(), patch('docker_update_manager.operations.discover', side_effect=[[self.new], RuntimeError('secret=private')]), \
             self.assertLogs('docker_update_manager.reconciliation', level='WARNING'):
            result = do_update(self.old, self.state, yes=True, output=lambda *_: None, post_mutation=queue)
        self.assertTrue(result['updated'])
        queue.assert_not_called()
        self.assertEqual(self.rows()[0]['status'], 'CHECK REQUIRED')
        self.assertEqual(self.state.runtime_snapshot()['status'], 'unavailable')
        # The same tombstone also covers no successful runtime snapshot at all.
        rows = merge_service_items(self.snapshot, None, self.agent.verification_snapshot())
        self.assertEqual(rows[0]['status'], 'CHECK REQUIRED')
        self.assertIsNone(rows[0]['remote_digest'])

    def test_registry_failure_on_replacement_never_restores_old_update(self):
        with self.docker(), patch('docker_update_manager.webservice.scan_service_with_tracking', side_effect=RuntimeError('token=private 429')):
            do_update(self.old, self.state, yes=True, output=lambda *_: None, post_mutation=self.agent._queue_post_mutation)
            self.wait_refresh(self.new)
        self.assert_pending(self.new)

    def test_pinned_failed_update_reconciles_only_the_recovered_container(self):
        self.old.image += '@' + self.old.digest
        self.compose.write_text('services:\n  app:\n    image: ' + self.old.image + '\n')
        self.new.image += '@' + self.new.digest
        self.new.health = 'unhealthy'
        recovered = replace(self.old, container_id='c'*64)
        queue = Mock()
        with self.docker(recovered=recovered) as launches:
            with self.assertRaisesRegex(RuntimeError, 'pinned update failed'):
                do_update(self.old, self.state, yes=True, output=lambda *_: None, post_mutation=queue)
        self.assertEqual(len(launches), 2)
        queue.assert_called_once_with(recovered)
        self.assert_pending(recovered)
        self.assertEqual(self.state.history()[0]['result'], 'FAILED')

    def test_cli_rollback_reconciles_result_without_rewriting_scan(self):
        with self.docker():
            do_update(self.old, self.state, yes=True, output=lambda *_: None)
        updated = self.new
        self.new = replace(self.old, container_id='c'*64)
        queue = Mock()
        with self.docker(), contextlib.redirect_stdout(io.StringIO()):
            do_rollback(updated, self.state, yes=True, post_mutation=queue)
        queue.assert_called_once_with(self.new)
        self.assert_pending(self.new)
        self.assertEqual(self.state.history()[0]['result'], 'ROLLED BACK')

    def test_late_runtime_success_and_failure_cannot_overwrite_post_mutation_identity(self):
        before = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        with self.docker():
            do_update(self.old, self.state, yes=True, output=lambda *_: None)
        expected = self.state.runtime_snapshot()
        self.state.save_runtime_snapshot([public_service(self.old)], attempted_at=before)
        self.state.record_runtime_failure(attempted_at=before)
        self.assertEqual(self.state.runtime_snapshot(), expected)
        self.assert_pending(self.new)

    def test_inflight_same_container_check_is_superseded_and_one_retry_is_coalesced(self):
        entered, release = threading.Event(), threading.Event()
        def registry(service, state):
            if not entered.is_set():
                entered.set()
                release.wait(3)
                return ScanResult(service, 'UPDATE', self.new.digest)
            return ScanResult(service, 'CURRENT', service.digest)
        key = 'container/' + self.old.container_id
        with patch('docker_update_manager.webservice.discover', return_value=[self.old]), \
             patch('docker_update_manager.webservice.scan_service_with_tracking', side_effect=registry) as check:
            self.agent.start_refresh(key)
            self.assertTrue(entered.wait(2))
            self.state.reconcile_runtime(key, [public_service(self.old)], current_service=public_service(self.old),
                                         attempted_at=datetime.now(timezone.utc).isoformat())
            self.agent.start_refresh(key, after_reconcile=True)
            self.agent.start_refresh(key, after_reconcile=True)
            self.assert_pending(self.old)
            release.set()
            self.wait_refresh(self.old)
        self.assertEqual(check.call_count, 2)
        self.assertEqual(self.rows()[0]['status'], 'CURRENT')

    def test_late_full_scan_result_remains_historical_and_cannot_revive_invalidated_update(self):
        self.state.start_scan('inflight')
        key = 'container/' + self.old.container_id
        self.state.invalidate_verification(key)
        self.state.finish_scan('inflight', 'complete', services=[_public_result(ScanResult(self.old, 'UPDATE', self.new.digest))])
        self.assertEqual(self.state.latest_scan()['payload']['services'][0]['status'], 'UPDATE')
        self.assertEqual(self.rows()[0]['status'], 'CHECK REQUIRED')
        self.assertTrue(self.state.verification_snapshot()[0]['invalidated'])

    def test_custom_cli_state_never_contacts_default_live_agent(self):
        with patch('docker_update_manager.agent.AgentClient') as client:
            queue_agent_verification(self.old, state=self.state)
        client.assert_not_called()

    def test_dry_run_and_failed_invalidation_never_recreate_or_queue(self):
        queue = Mock()
        verification = self.state.verification_snapshot()
        with self.docker() as launches:
            do_update(self.old, self.state, dry_run=True, output=lambda *_: None, post_mutation=queue)
            with patch.object(self.state, 'invalidate_verification', side_effect=OSError('fixture disk failure')):
                with self.assertRaises(OSError):
                    do_update(self.old, self.state, yes=True, output=lambda *_: None, post_mutation=queue)
        self.assertEqual(launches, [])
        queue.assert_not_called()
        self.assertEqual(self.state.verification_snapshot(), verification)

    def test_missing_or_ambiguous_result_does_not_guess_verification_target(self):
        for observed in ([], [self.new, replace(self.new, container_id='c'*64)]):
            with self.subTest(observed=len(observed)), self.docker():
                queue = Mock()
                do_update(self.old, self.state, yes=True, output=lambda *_: None,
                          post_mutation=queue, reconcile_discover=lambda: observed)
                queue.assert_not_called()
                self.assertTrue(all(row['status'] == 'CHECK REQUIRED' for row in self.rows()))
                self.assertEqual(self.state.latest_scan(), self.snapshot)

    def test_invalidation_survives_retention_and_agent_restart(self):
        key = 'container/' + self.old.container_id
        self.state.invalidate_verification(key)
        with self.state.connect() as connection:
            connection.execute("UPDATE service_verifications SET failed_at='2020-01-01T00:00:00Z' WHERE service_key=?", (key,))
        self.state.save_verification(_public_result(ScanResult(self.new, 'CURRENT', self.new.digest)))
        restarted = ReadOnlyService(self.agent.config, State(self.state.root))
        rows = merge_service_items(self.snapshot, None, restarted.verification_snapshot())
        self.assertEqual(rows[0]['status'], 'CHECK REQUIRED')
        self.assertIsNone(rows[0]['remote_digest'])

    def test_active_scan_finishes_before_one_exact_replacement_check(self):
        self.state.start_scan('active')
        with self.docker(), patch('docker_update_manager.webservice.scan_service_with_tracking',
                                 side_effect=lambda svc, state: ScanResult(svc, 'CURRENT', svc.digest)) as check:
            do_update(self.old, self.state, yes=True, output=lambda *_: None, post_mutation=self.agent._queue_post_mutation)
            self.assert_pending(self.new)
            check.assert_not_called()
            self.state.finish_scan('active', 'partial', services=[])
            self.wait_refresh(self.new)
            self.assertEqual([call.args[0].container_id for call in check.call_args_list], [self.new.container_id])
        self.assertEqual(self.rows()[0]['status'], 'CURRENT')

    def test_pin_and_restart_invalidate_same_container_and_queue_once(self):
        for operation in ('pin', 'restart'):
            with self.subTest(operation=operation), self.docker():
                queue = Mock()
                if operation == 'pin':
                    do_pin(self.old, self.state, yes=True, output=lambda *_: None, post_mutation=queue)
                else:
                    do_restart(self.old, state=self.state, output=lambda *_: None, post_mutation=queue)
                queue.assert_called_once_with(self.old)
                self.assert_pending(self.old)

    def test_runtime_refresh_preserves_peer_counters_without_copying_them_to_replacement(self):
        peer = replace(self.old, container_id='c'*64, name='peer', compose_service='peer')
        self.state.save_runtime_snapshot([{**public_service(self.old), 'restart_count': 7},
                                         {**public_service(peer), 'restart_count': 3}])
        with self.docker():
            do_update(self.old, self.state, yes=True, output=lambda *_: None,
                      reconcile_discover=lambda: [self.new, peer])
        rows = {row['container_id']: row for row in self.state.runtime_snapshot()['containers']}
        self.assertEqual(rows[peer.container_id]['restart_count'], 3)
        self.assertIsNone(rows[self.new.container_id]['restart_count'])

    def test_removal_invalidates_missing_container_without_queueing_a_namesake(self):
        from docker_update_manager.removal import remove_service
        queue = Mock()
        with patch('docker_update_manager.removal.require_mutation_safe'), \
             patch('docker_update_manager.removal.run'), contextlib.redirect_stdout(io.StringIO()):
            result = remove_service(self.old, self.state, yes=True, post_mutation=queue,
                                    reconcile_discover=lambda: [])
        self.assertTrue(result['removed'])
        queue.assert_not_called()
        self.assertEqual(self.state.runtime_snapshot()['containers'], [])
        self.assertEqual(self.rows()[0]['status'], 'CHECK REQUIRED')
        self.assertEqual(self.state.latest_scan(), self.snapshot)

    def test_conversion_and_its_rollback_reconcile_actual_named_container(self):
        from docker_update_manager.conversion import deploy_conversion, rollback_conversion
        original = replace(self.old, stack=None, compose_service=None)
        queue = Mock()
        summary = {'service': 'app', 'image': self.new.image}
        with patch('docker_update_manager.conversion.require_mutation_safe'), \
             patch('docker_update_manager.conversion.run'), \
             patch('docker_update_manager.conversion._inspect', return_value={'State': {'Status': 'running'}}), \
             contextlib.redirect_stdout(io.StringIO()):
            deploy_conversion(original, self.state, self.root, summary, {}, yes=True,
                              post_mutation=queue, reconcile_discover=lambda: [self.new])
            queue.assert_called_once_with(self.new)
            self.assert_pending(self.new)
            name = json.loads(self.state.history()[0]['details'])['backup_container']
            retained = replace(original, name=name)
            queue.reset_mock()
            with patch('docker_update_manager.conversion.discover', return_value=[self.new, retained]):
                rollback_conversion('app', self.state, yes=True, post_mutation=queue,
                                    reconcile_discover=lambda: [original])
        queue.assert_called_once_with(original)
        self.assert_pending(original)

    def test_all_four_pages_converge_immediately_and_after_targeted_verification(self):
        from fastapi.testclient import TestClient
        from docker_update_manager.auth import new_token
        from docker_update_manager.config import WebConfig
        from docker_update_manager.webapp import create_app
        from docker_update_manager.webstate import WebState

        web = WebState(self.root / 'web')
        user = web.create_user('admin', 'unused fixture hash')
        expiry = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        session = web.create_session(user, new_token(), expiry, expiry)
        adapter = Mock()
        adapter.call.side_effect = self.agent.handle
        client = TestClient(create_app(WebConfig(path=str(self.root / 'web.yml')), web, adapter))
        self.addCleanup(client.close)
        client.cookies.set('upt_session', session)
        with self.docker(), patch.object(self.agent, 'compose_status', return_value={}), \
             patch.object(self.agent, 'rollback_review', side_effect=ValueError('no fixture rollback review')):
            do_update(self.old, self.state, yes=True, output=lambda *_: None)
            for expected in ('CHECK REQUIRED', 'CURRENT'):
                contexts = [client.get(path).context for path in ('/', '/services', '/updates',
                            '/services/container/' + self.new.container_id)]
                rows = [contexts[0]['merged_items'][0], contexts[1]['items'][0],
                        contexts[2]['groups']['undetermined' if expected == 'CHECK REQUIRED' else 'current'][0]['item'],
                        contexts[3]['result']]
                self.assertEqual([(row['service']['container_id'], row['status']) for row in rows],
                                 [(self.new.container_id, expected)] * 4)
                self.assertTrue(all(not row.get('target_image') for row in rows))
                if expected == 'CHECK REQUIRED':
                    with patch('docker_update_manager.webservice.scan_service_with_tracking',
                               side_effect=lambda svc, state: ScanResult(svc, 'CURRENT', svc.digest)):
                        self.agent._queue_post_mutation(self.new)
                        self.wait_refresh(self.new)
        self.assertEqual(self.state.latest_scan(), self.snapshot)
