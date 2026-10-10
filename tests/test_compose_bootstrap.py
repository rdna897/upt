"""Deterministic Phase 2B2 tests; no production Docker or source access."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import json
import os
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from docker_update_manager.compose_bootstrap import BootstrapRefused
from docker_update_manager.operation_presentation import REFRESH_NOTICE, operation_presentation
from docker_update_manager.webapp import operation_event_role, operation_timeline
from progress_assertions import assert_stage_model
from docker_update_manager.compose_baseline import BaselineStore
from docker_update_manager.compose_drift import build_inventory
from docker_update_manager.compose_recovery_retention import checked_bundle, lifecycle
from docker_update_manager.state import State
from docker_update_manager.operation_presentation import operation_presentation
from test_compose_reconciliation import ComposeFixture, SECRET, service_hash, use_named_runtime_network, with_named_network
from test_compose_apply import FakeApplyCompose


class FakeBootstrapCompose(FakeApplyCompose):
    def __call__(self, args, **kwargs):
        args = list(args)
        if args[-2:] == ['up','--help']:
            return '--no-deps --pull string (always|missing|never) --no-build'
        if '{{json .RestartCount}}' in args:
            return json.dumps(self.fixture.restart_counts.get(args[-1], 0))
        if 'up' in args:
            self.calls.append(args)
            self.up_calls.append(args)
            assert args[-7:] == ['up','-d','--no-deps','--pull','never','--no-build','sonarr'], args
            model = self.model([str(self.fixture.compose)], str(self.fixture.project), None)
            fresh = self.fixture.make_service(service_hash(model['services']['sonarr']),container_id='c'*64,health=self.health,digest=self.fixture.service.digest)
            self.fixture.runtime = [item for item in self.fixture.runtime if item.compose_service != 'sonarr'] + [fresh]
            if self.up_hook:
                self.up_hook(len(self.up_calls), fresh)
            return ''
        return super().__call__(args, **kwargs)


class BootstrapTests(ComposeFixture):
    def make_service(self, runtime_hash, container_id='a'*64, **changes):
        service = super().make_service(runtime_hash,container_id,**changes)
        service.started_at = '2026-10-03T00:00:00Z'
        service.labels.update({'com.docker.compose.service':service.compose_service,
                               'com.docker.compose.project.working_dir':service.working_dir,
                               'com.docker.compose.project.config_files':','.join(service.compose_files),
                               'com.docker.compose.oneoff':'False'})
        return service

    def setUp(self):
        super().setUp()
        self.restart_counts = {}
        self.fake = FakeBootstrapCompose(self)
        for name in ('webservice','compose_reconcile','compose_bootstrap','compose'):
            mocked = patch('docker_update_manager.' + name + '.run', side_effect=self.fake)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.refresh = patch.object(self.agent,'start_refresh',return_value={'status':'checking'}).start()
        self.addCleanup(patch.stopall)
        self.compose.write_text(self.compose.read_text().split('  redis:')[0])
        self.original = self.compose.read_bytes()
        self.edit('restart: unless-stopped','restart: always')

    def review(self, **changes):
        return self.agent.compose_bootstrap_review({'service_key':'container/'+self.service.container_id,
                                                   'requested_by':'admin', **changes})

    def start(self, reviewed=None, **changes):
        reviewed = reviewed or self.review()
        payload = {'confirmation_id':reviewed['confirmation_id'],'acknowledge_no_rollback':True,
                   'requested_by':'admin','client_ip':'127.0.0.1','user_agent':'fixture',**changes}
        intent = self.agent._bootstrap_intents.get(payload['confirmation_id'])
        with patch('docker_update_manager.webservice.threading.Thread'):
            queued = self.agent.start_compose_bootstrap(payload)
        return queued['operation_id'], payload, intent

    def execute(self, reviewed=None):
        operation_id, payload, intent = self.start(reviewed)
        self.agent._bootstrap_worker(operation_id,payload,intent)
        return self.state.operation_status(operation_id)

    def assert_manual(self, op):
        self.assertEqual(op['status'],'failed')
        self.assertIsNone(op['result']['mutation_performed'])
        self.assertTrue(op['result']['manual_recovery_required'])
        self.assertFalse(op['result']['recovered'])
        self.assertEqual(self.records(), [])
        self.assertTrue(self.state.bootstrap_fence(self.agent._baseline_key(self.service)))
        # Registry verification may run after a failed mutation; it cannot
        # publish trust or resolve the durable manual fence.
        self.assertFalse(any(record["verification_id"] for record in self.state.verification_snapshot()))

    def test_success_recreates_once_and_atomically_publishes_selected_trust(self):
        desired = self.compose.read_bytes()
        op = self.execute()
        self.assertEqual(op['status'],'succeeded')
        self.assertTrue(op['result']['trust_established'])
        self.assertEqual(len(self.fake.up_calls),1)
        self.assertEqual(self.compose.read_bytes(),desired)
        self.assertEqual(len(self.records()),1)
        baseline = BaselineStore(self.state).load(self.records()[0])
        self.assertEqual(baseline.record.container_id,'c'*64)
        self.assertFalse(baseline.project_trusted)
        self.assertIsNone(self.state.bootstrap_fence(self.agent._baseline_key(self.service)))
        with self.state.read() as c:
            self.assertEqual(c.execute('SELECT count(*) FROM rollback_refs').fetchone()[0],0)
            self.assertEqual(c.execute('SELECT count(*) FROM history').fetchone()[0],1)
            self.assertEqual(c.execute("SELECT count(*) FROM audit_events WHERE action='web_compose_bootstrap' AND result='success'").fetchone()[0],1)
        self.refresh.assert_called_once_with('container/'+'c'*64,after_reconcile=True)

    def test_success_reports_eight_real_stages_with_trust_publication_last(self):
        op = self.execute()
        self.assertEqual(op['status'],'succeeded')
        events = op['events']
        self.assertEqual(assert_stage_model(self,events,8),list(range(1,9)))
        self.assertEqual(events[-2]['stage'],'8/8 Publish trusted baseline and result')
        self.assertEqual(events[-1]['kind'],'operation_completed')
        # Every running row was closed under its own key; nothing is left spinning before the terminal event.
        self.assertEqual([row['stage'] for row in operation_timeline(events[:-1]) if row['_timeline_active']],[])
        markers = [event for event in events if event['kind'] == 'task_info']
        self.assertEqual([event['stage'] for event in markers],['Recreating service to establish trust'])
        self.assertEqual(operation_event_role(markers[0]),'info')

    def test_blocked_before_marker_never_reaches_recreation_or_publication_stages(self):
        reviewed = self.review()
        operation_id,payload,intent = self.start(reviewed)
        self.edit('restart: always','restart: on-failure')
        self.agent._bootstrap_worker(operation_id,payload,intent)
        op = self.state.operation_status(operation_id)
        self.assertEqual(op['status'],'blocked')
        completed = assert_stage_model(self,op['events'],8)
        self.assertTrue(set(completed) <= {1,2,3},completed)
        self.assertEqual(op['events'][-1]['kind'],'operation_blocked')

    def test_post_dispatch_failure_marks_the_in_flight_stage_failed_without_publication(self):
        self.fake.health = 'unhealthy'
        op = self.execute()
        self.assert_manual(op)
        events = op['events']
        self.assertEqual(assert_stage_model(self,events,8),[1,2,3,4])
        failed = [event['stage'] for event in events if event['kind'] == 'task_failed']
        self.assertEqual(failed,['5/8 Verify recreated service'])
        self.assertEqual(events[-1]['kind'],'operation_failed')

    def test_refresh_queue_failure_presentation_never_claims_the_refresh_was_queued(self):
        self.refresh.side_effect = OSError('queue fault')
        op = self.execute()
        self.assertEqual(op['status'],'succeeded')
        self.assertIs(op['result']['refresh_required'],True)
        alert = operation_presentation(op)['alert']
        self.assertIn(REFRESH_NOTICE,alert)
        self.assertIn('A targeted refresh is required',alert)
        self.assertNotIn('is queued',alert)

    def test_project_declared_bridge_network_uses_the_shared_context_proof(self):
        use_named_runtime_network(self.fake)
        desired = self.compose.read_text()
        self.compose.write_text(with_named_network("      monitoring:\n        aliases: [metrics]\n", source=desired))
        with self.assertRaises(BootstrapRefused):
            self.review()
        self.compose.write_text(with_named_network(source=desired))
        op = self.execute()
        self.assertEqual(op['status'],'succeeded')
        self.assertEqual(len(self.fake.up_calls),1)

    def test_review_is_private_and_does_not_invent_previous_values(self):
        result = self.review()
        encoded = json.dumps(result)
        for value in (SECRET,str(self.project),self.service.image_id,self.service.digest,self.current_hash()):
            self.assertNotIn(value,encoded)
        self.assertFalse(result['review']['automatic_recovery'])
        self.assertFalse(result['review']['previous_source_known'])
        self.assertFalse(self.records())
        self.assertTrue(all('old' not in entry for entry in result['review']['proposal']))
        self.assertFalse(self.fake.up_calls)

    def test_review_projection_has_desired_summaries_and_bounded_observations(self):
        review = self.review()['review']
        by_field = {entry['field']: entry for entry in review['proposal']}
        self.assertEqual(by_field['restart']['summary'], 'always')
        self.assertTrue(all(set(entry) <= {'field','label','summary','items','hidden'} for entry in review['proposal']))
        self.assertEqual([item['label'] for item in review['observations']],
                         ['Image','Container state','Health','Restart policy (runtime)'])
        self.assertEqual({item['label']: item['value'] for item in review['observations']}['Container state'], 'running')
        self.assertTrue(all(set(item) == {'label','value'} and len(item['value']) <= 200 for item in review['observations']))
        self.assertNotIn(SECRET, json.dumps(review))
        _, payload, _ = self.start()
        self.assertNotIn('observations', payload)

    def test_confirmation_is_exact_acknowledged_bound_one_use_expiring(self):
        for changes in ({'acknowledge_no_rollback':False},{'acknowledge_no_rollback':'yes'}, {'image_id':'tampered'},
                        {'requested_by':'other'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.start(**changes)
        reviewed = self.review()
        intent = self.agent._bootstrap_intents[reviewed['confirmation_id']]
        self.agent._bootstrap_intents[reviewed['confirmation_id']] = replace(intent,expires_at=time.monotonic()-1)
        with self.assertRaises(ValueError):
            self.start(reviewed)
        reviewed = self.review()
        self.execute(reviewed)
        with self.assertRaises(ValueError):
            self.start(reviewed)

    def test_valid_or_adoptable_baseline_routes_to_existing_operations(self):
        self.compose.write_bytes(self.original)
        self.status()
        self.edit('restart: unless-stopped','restart: always')
        with self.assertRaises(BootstrapRefused) as exc:
            self.review()
        self.assertEqual(exc.exception.reason,'trusted_baseline_available')
        self.runtime = [self.make_service(self.service.labels['com.docker.compose.config-hash'],container_id='d'*64)]
        with self.assertRaises(BootstrapRefused) as exc:
            self.review(service_key='container/'+'d'*64)
        self.assertEqual(exc.exception.reason,'trusted_baseline_available')
        self.assertEqual(len(self.records()),1)

    def test_trust_store_query_failure_is_not_absence(self):
        with patch.object(self.state,'compose_baselines',side_effect=OSError('private-error')):
            with self.assertRaises(BootstrapRefused) as exc:
                self.review()
        self.assertEqual(exc.exception.reason,'trust_store_unavailable')
        self.assertNotIn('private-error',str(exc.exception))

    def test_source_and_same_id_restart_after_review_block_before_marker(self):
        for change in ('source','restart'):
            reviewed = self.review()
            operation_id,payload,intent = self.start(reviewed)
            if change == 'source':
                self.edit('restart: always','restart: on-failure')
            else:
                self.restart_counts[self.service.container_id] = 1
            self.agent._bootstrap_worker(operation_id,payload,intent)
            op = self.state.operation_status(operation_id)
            self.assertEqual(op['status'],'blocked')
            self.assertFalse(op['result']['mutation_performed'])
            self.assertFalse(self.fake.up_calls)
            self.assertFalse(self.records())

    def test_observed_source_and_alias_races_after_dispatch_require_manual_recovery(self):
        for race in ('compose','env','alias','image','missing','restart','context','health'):
            # Each case has its own state/logical identity.
            with self.subTest(race=race):
                self.state = State(self.root / ('state-'+race))
                self.agent.state = self.state
                self.runtime = [self.service]
                self.fake.local_image_id = self.service.image_id
                self.fake.health = 'healthy'
                self.restart_counts.clear()
                self.compose.write_bytes(self.original.replace(b'restart: unless-stopped',b'restart: always'))
                (self.project/'.env').write_text('SONARR_API_KEY='+SECRET+'\n')
                def hook(_count,fresh):
                    if race == 'compose': self.edit('restart: always','restart: on-failure')
                    elif race == 'env': (self.project/'.env').write_text('SONARR_API_KEY=changed\n')
                    elif race == 'alias': self.fake.local_image_id = 'sha256:'+'3'*64
                    elif race == 'image': fresh.image_id = 'sha256:'+'3'*64
                    elif race == 'missing': self.runtime = []
                    elif race == 'restart': fresh.state = 'restarting'
                    elif race == 'context': self.fake.network_id = 'd'*64
                    elif race == 'health': fresh.health = 'unhealthy'
                self.fake.up_hook = hook
                self.assert_manual(self.execute())
                self.fake.network_id = 'b'*64

    def test_marker_committed_but_dispatch_unobserved_is_manual_on_restart(self):
        marker = self.state.mark_bootstrap_recreate
        def interrupted(*args):
            marker(*args)
            raise RuntimeError('dispatch not observed')
        with patch.object(self.state,'mark_bootstrap_recreate',side_effect=interrupted):
            op = self.execute()
        self.assert_manual(op)
        self.assertFalse(self.fake.up_calls)
        restarted = State(self.state.root)
        self.assertTrue(restarted.bootstrap_fence(self.agent._baseline_key(self.service)))

    def test_crash_before_trust_commit_never_passively_adopts_desired_runtime(self):
        with patch.object(self.state,'publish_bootstrap_success',side_effect=RuntimeError('crash')):
            op = self.execute()
        self.assert_manual(op)
        current = self.runtime[0]
        status = self.status(current)
        self.assertTrue(status['update_blocked'])
        self.assertFalse(status['apply_eligible'])
        self.assertEqual(status['reasons'][0]['code'],'bootstrap_unresolved')
        with self.assertRaises(ValueError):
            self.agent._capture_baseline(current,self.current_hash(),self.fake.model([str(self.compose)],str(self.project),None),
                                         __import__('docker_update_manager.compose_drift',fromlist=['build_inventory']).build_inventory([str(self.compose)],str(self.project)))
        self.assertFalse(self.records())

    def test_atomic_audit_failure_rolls_back_baseline_and_success(self):
        with self.state.connect() as c:
            c.execute("CREATE TRIGGER fail_success_audit BEFORE INSERT ON audit_events WHEN NEW.result='success' BEGIN SELECT RAISE(ABORT,'fault'); END")
        op = self.execute()
        self.assert_manual(op)
        with self.state.read() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM history WHERE result='SUCCESS'").fetchone()[0],0)
            self.assertEqual(c.execute("SELECT count(*) FROM operation_events WHERE kind='operation_completed'").fetchone()[0],0)

    def test_pre_marker_evidence_failure_does_not_dispatch(self):
        with patch('docker_update_manager.compose_bootstrap._write_private',side_effect=OSError('fsync fault')):
            op = self.execute()
        self.assertEqual(op['status'],'blocked')
        self.assertFalse(self.fake.up_calls)
        self.assertFalse(self.records())

    def test_refused_compose_flags_never_weakens_argv(self):
        with patch('docker_update_manager.compose_bootstrap.require_compose_flags',side_effect=BootstrapRefused('service_ineligible')):
            op = self.execute()
        self.assertEqual(op['status'],'blocked')
        self.assertFalse(self.fake.up_calls)

    def test_fence_survives_operation_prune_and_evidence_retention(self):
        self.fake.up_hook = lambda _count,fresh:setattr(fresh,'health','unhealthy')
        op = self.execute()
        self.assert_manual(op)
        with self.state.connect() as c:
            c.execute("UPDATE operation_runs SET created_at='2000-01-01',finished_at='2000-01-01' WHERE id=?",(op['id'],))
        self.state.prune_operations(retention_days=1)
        self.assertIsNone(self.state.operation_status(op['id']))
        self.assertTrue(self.state.bootstrap_fence(self.agent._baseline_key(self.service)))
        path = self.state.root/'compose-recoveries'/op['id']
        with self.state.read() as c, checked_bundle(self.state.root,path) as bundle:
            self.assertEqual(lifecycle(c,op['id'],bundle)[0],'manual')
            self.assertEqual(c.execute('SELECT lifecycle FROM compose_recovery_receipts').fetchone()[0],'manual')
        self.assertTrue(path.exists())

    def test_refresh_failure_preserves_committed_success_and_trust(self):
        self.refresh.side_effect = OSError('queue fault')
        op = self.execute()
        self.assertEqual(op['status'],'succeeded')
        self.assertEqual(len(self.records()),1)
        public = self.agent.operation_status({'operation_id':op['id'],'after_event_id':0})
        self.assertTrue(public['result']['warnings'])
        for private in ('logical_key','bootstrap_evidence','completion_proof','new_baseline_id'):
            self.assertNotIn(private,json.dumps(public))

    def test_reload_and_live_presentation_use_factual_bootstrap_results(self):
        for status in ('succeeded','blocked','failed'):
            result = {'mutation_performed':None,'manual_recovery_required':status=='failed'}
            view = operation_presentation({'kind':'compose_bootstrap','status':status,'result':result})
            expected = {'succeeded':'trusted baseline established','blocked':'no workload changes','failed':'manual recovery required'}[status]
            self.assertIn(expected,view['status_label'].lower())

    def test_peer_scope_refuses_absent_stopped_replicated_drifted_and_restarted_peers(self):
        self.compose.write_text(self.compose.read_text()+'  redis:\n    image: redis:7\n')
        model = self.fake.model([str(self.compose)],str(self.project),None)
        peer = self.make_service(service_hash(model['services']['redis']),container_id='d'*64,
                                 compose_service='redis',image='redis:7')
        actual = self.fake
        def peer_fake(args, **kwargs):
            if '{{json .Mounts}}' in args and args[-1] == peer.container_id:
                return '[]'
            return actual(args,**kwargs)
        with patch('docker_update_manager.webservice.run',side_effect=peer_fake):
            with self.assertRaises(BootstrapRefused): self.review()
            self.runtime.append(peer)
            reviewed = self.review()
            op,payload,intent = self.start(reviewed)
            self.restart_counts[peer.container_id] = 1
            self.agent._bootstrap_worker(op,payload,intent)
            self.assertEqual(self.state.operation_status(op)['status'],'blocked')
            self.restart_counts.clear()
            for runtime in ([self.service,replace(peer,state='exited')], [self.service,peer,replace(peer,container_id='e'*64)],
                            [self.service,replace(peer,labels={**peer.labels,'com.docker.compose.config-hash':'0'*64})]):
                self.runtime=runtime
                with self.assertRaises(BootstrapRefused): self.review()
            self.runtime = [self.service,peer]
            op = self.execute()
            self.assertEqual(op['status'],'succeeded')
            self.assertEqual(self.runtime[0].container_id,peer.container_id)

    def test_unsupported_yaml_and_service_fields_refuse_read_only(self):
        desired = self.compose.read_text()
        for text in (desired.replace('restart: always','restart: always\n    restart: no'),
                     desired.replace('restart: always','restart: &shared always'),
                     desired.replace('restart: always','restart: always\n    build: .'),
                     desired.replace('restart: always','restart: always\n    unknown_field: true'),
                     desired.replace('restart: always','restart: always\n    depends_on: [redis]')):
            self.compose.write_text(text)
            with self.assertRaises(ValueError): self.review()
        self.assertFalse(self.fake.up_calls)
        self.assertFalse(self.records())

    def test_absent_repodigest_does_not_block_configuration_bootstrap_or_authorise_images(self):
        self.service.digest = None
        op = self.execute()
        self.assertEqual(op['status'],'succeeded')
        from docker_update_manager.operations import do_pin
        with self.assertRaises(ValueError):
            do_pin(self.runtime[0],self.state,yes=True,output=lambda *_:None)

    def test_evidence_corruption_retains_fence_and_no_automatic_retry(self):
        self.fake.up_hook = lambda _count,fresh:setattr(fresh,'health','unhealthy')
        op = self.execute()
        path=self.state.root/'compose-recoveries'/op['id']/'proof.json'
        path.write_bytes(b'corrupt')
        self.state.prune_operations(retention_days=1)
        self.assertTrue(self.state.bootstrap_fence(self.agent._baseline_key(self.service)))
        self.runtime = [self.make_service(self.current_hash(),container_id='c'*64)]
        with self.assertRaises(BootstrapRefused): self.review(service_key='container/'+'c'*64)
        self.assertFalse(self.records())


    def test_abrupt_crashes_at_durable_boundaries_classify_on_reload_without_recreate(self):
        for boundary in ('bind_bootstrap_evidence','mark_bootstrap_recreate','prepare','publish_bootstrap_success'):
            with self.subTest(boundary=boundary):
                self.state = State(self.root / ('crash-'+boundary))
                self.agent.state = self.state
                self.runtime = [self.service]
                self.fake.up_calls.clear()
                self.refresh.reset_mock()
                op,payload,intent = self.start()
                owner = BaselineStore if boundary == 'prepare' else self.state
                original = getattr(owner,boundary)
                def crash(*args,**kwargs):
                    original(*args,**kwargs)
                    raise SystemExit('simulated abrupt exit')
                with patch.object(owner,boundary,**({'new':crash} if boundary == 'prepare' else {'side_effect':crash})), self.assertRaises(SystemExit):
                    self.agent._bootstrap_worker(op,payload,intent)
                self.state = State(self.state.root)
                self.agent.state = self.state
                # No age delay: acquiring update.lock proves the running worker is gone.
                result = self.agent.operation_status({'operation_id':op,'after_event_id':0})
                if boundary == 'publish_bootstrap_success':
                    self.assertEqual(result['status'],'succeeded')
                    self.assertEqual(len(self.records()),1)
                    self.assertIsNone(self.state.bootstrap_fence(self.agent._baseline_key(self.service)))
                elif boundary == 'bind_bootstrap_evidence':
                    self.assertEqual(result['status'],'blocked')
                    self.assertFalse(result['result']['mutation_performed'])
                    self.assertFalse(self.fake.up_calls)
                else:
                    self.assert_manual(result)
                before = len(self.fake.up_calls)
                self.agent.operation_status({'operation_id':op,'after_event_id':0})
                self.assertEqual(len(self.fake.up_calls),before)

    def test_live_worker_lock_prevents_poll_from_classifying_interruption(self):
        from docker_update_manager.lock import Lock
        op,_payload,_intent = self.start()
        self.state.set_operation_running(op,'Revalidate trust bootstrap')
        with Lock(self.state.root/'update.lock'):
            result=self.agent.operation_status({'operation_id':op,'after_event_id':0})
        self.assertEqual(result['status'],'running')
        self.assertFalse(self.records())

    def test_final_publication_bracket_refuses_input_alias_and_unproved_orphan_races(self):
        for race in ('compose','env_file','alias','orphan','fence'):
            with self.subTest(race=race):
                self.state=State(self.root/('late-'+race)); self.agent.state=self.state
                self.runtime=[self.service]; self.fake.local_image_id=self.service.image_id
                self.compose.write_bytes(self.original.replace(b'restart: unless-stopped',b'restart: always'))
                envfile=self.project/'service.env'; envfile.write_text('LATE_SETTING=before\n')
                if race == 'env_file':
                    self.edit('restart: always','restart: always\n    env_file: [service.env]')
                original=BaselineStore.prepare
                def changed(store,*args,**kwargs):
                    record=original(store,*args,**kwargs)
                    if race == 'compose': self.edit('restart: always','restart: on-failure')
                    elif race == 'env_file': envfile.write_text('LATE_SETTING=after\n')
                    elif race == 'alias': self.fake.local_image_id='sha256:'+'3'*64
                    elif race == 'orphan':
                        (self.state.root/'compose-recoveries'/('f'*32)).mkdir(mode=0o700)
                    elif race == 'fence':
                        with self.state.connect() as c:
                            c.execute("INSERT INTO compose_bootstrap_fences VALUES('unproven:external','external','unproven','manual','2000-01-01','2000-01-01')")
                    return record
                with patch.object(BaselineStore,'prepare',new=changed):
                    self.assert_manual(self.execute())

    def test_health_polling_rechecks_source_and_timeout_without_recovery(self):
        for fault in ('race','timeout','healthy'):
            with self.subTest(fault=fault):
                self.state=State(self.root/('health-'+fault)); self.agent.state=self.state
                self.runtime=[self.service]; self.fake.health='starting'; self.fake.local_image_id=self.service.image_id
                self.compose.write_bytes(self.original.replace(b'restart: unless-stopped',b'restart: always'))
                self.refresh.reset_mock()
                self.config.data['health_timeout']=1
                def poll(_seconds):
                    if fault == 'race': (self.project/'.env').write_text('SONARR_API_KEY=changed\n')
                    if fault != 'timeout': self.runtime[0].health='healthy'
                # The timeout path uses real monotonic time, mocked sleep moves the deadline.
                if fault == 'timeout':
                    import docker_update_manager.compose_bootstrap as bootstrap
                    clock=time.monotonic()
                    tick=[0]
                    def advance(_seconds): tick[0]+=2
                    with patch.object(bootstrap.time,'sleep',side_effect=advance), patch.object(bootstrap.time,'monotonic',side_effect=lambda:clock+tick[0]):
                        op=self.execute()
                else:
                    with patch('docker_update_manager.compose_bootstrap.time.sleep',side_effect=poll): op=self.execute()
                if fault == 'healthy':
                    self.assertEqual(op['status'],'succeeded')
                    self.assertEqual(len(self.records()),1)
                else: self.assert_manual(op)
                (self.project/'.env').write_text('SONARR_API_KEY='+SECRET+'\n')

    def test_staged_baseline_and_sqlite_terminal_faults_never_partially_publish(self):
        for fault in ('rename','fsync','history','event','dispatch'):
            with self.subTest(fault=fault):
                self.state=State(self.root/('fault-'+fault)); self.agent.state=self.state
                self.runtime=[self.service]; self.refresh.reset_mock()
                if fault in {'history','event'}:
                    table='history' if fault=='history' else 'operation_events'
                    condition="NEW.result='SUCCESS'" if fault=='history' else "NEW.kind='operation_completed'"
                    with self.state.connect() as c:
                        c.execute(f"CREATE TRIGGER fail_terminal BEFORE INSERT ON {table} WHEN {condition} BEGIN SELECT RAISE(ABORT,'fault'); END")
                    op=self.execute()
                elif fault == 'dispatch':
                    self.fake.up_hook=lambda *_:(_ for _ in ()).throw(RuntimeError('Docker error with private detail'))
                    op=self.execute(); self.fake.up_hook=None
                else:
                    original=BaselineStore.prepare
                    def failed(store,*args,**kwargs):
                        with patch('docker_update_manager.compose_baseline.os.'+('replace' if fault=='rename' else 'fsync'),side_effect=OSError('fault')):
                            return original(store,*args,**kwargs)
                    with patch.object(BaselineStore,'prepare',new=failed): op=self.execute()
                self.assert_manual(op)
                with self.state.read() as c:
                    self.assertEqual(c.execute("SELECT count(*) FROM operation_events WHERE kind='operation_completed'").fetchone()[0],0)
                    self.assertEqual(c.execute("SELECT count(*) FROM history WHERE result='SUCCESS'").fetchone()[0],0)

    def baseline_dirs(self):
        root = self.state.root / 'compose-baselines'
        return sorted(item.name for item in root.iterdir()) if root.exists() else []

    def test_failure_after_prepare_before_publication_removes_prepared_directory(self):
        original = BaselineStore.prepare
        def changed(store, *args, **kwargs):
            record = original(store, *args, **kwargs)
            self.assertEqual(self.baseline_dirs(), [record.id])
            self.edit('restart: always', 'restart: on-failure')
            return record
        with patch.object(BaselineStore, 'prepare', new=changed):
            self.assert_manual(self.execute())
        self.assertEqual(self.baseline_dirs(), [])

    def test_publication_failure_with_no_committed_row_removes_prepared_directory(self):
        with self.state.connect() as c:
            c.execute("CREATE TRIGGER fail_success_audit BEFORE INSERT ON audit_events WHEN NEW.result='success' BEGIN SELECT RAISE(ABORT,'fault'); END")
        self.assert_manual(self.execute())
        self.assertEqual(self.baseline_dirs(), [])

    def test_post_rename_prepare_failures_do_not_strand_final_directory(self):
        real_fsync, prepare = os.fsync, BaselineStore.prepare
        def root_fsync_fails(store, *args, **kwargs):
            root_inode = os.stat(store._ensure_root()).st_ino
            def fsync(descriptor):
                if os.fstat(descriptor).st_ino == root_inode:
                    raise OSError('fault')
                return real_fsync(descriptor)
            with patch('docker_update_manager.compose_baseline.os.fsync', side_effect=fsync):
                return prepare(store, *args, **kwargs)
        faults = {'verification': patch.object(BaselineStore, 'load', side_effect=RuntimeError('verification fault')),
                  'root_fsync': patch.object(BaselineStore, 'prepare', new=root_fsync_fails)}
        for name, fault in faults.items():
            with self.subTest(fault=name):
                self.state = State(self.root / ('post-rename-' + name)); self.agent.state = self.state
                self.runtime = [self.service]
                with fault:
                    self.assert_manual(self.execute())
                self.assertEqual(self.baseline_dirs(), [])

    def test_committed_baseline_row_retains_material(self):
        original = self.state.publish_bootstrap_success
        def publish_then_fail(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError('failure after commit')
        with patch.object(self.state, 'publish_bootstrap_success', side_effect=publish_then_fail):
            self.execute()
        store = BaselineStore(self.state)
        records = store.records(self.agent._baseline_key(self.service))
        self.assertEqual(len(records), 1)
        self.assertEqual(self.baseline_dirs(), [records[0].id])
        self.assertFalse(store.discard_unpublished(records[0]))
        store.load(records[0])

    def test_unprovable_publication_state_retains_material(self):
        original = BaselineStore.prepare
        prepared = []
        unreadable = patch.object(State, 'read', side_effect=RuntimeError('database unavailable'))
        def keep(store, *args, **kwargs):
            record = original(store, *args, **kwargs)
            prepared.append(record)
            self.edit('restart: always', 'restart: on-failure')
            unreadable.start()
            return record
        try:
            with patch.object(BaselineStore, 'prepare', new=keep):
                try:
                    self.execute()
                except Exception:
                    pass  # the database is deliberately unreadable after prepare
            self.assertEqual(self.baseline_dirs(), [prepared[0].id])
            self.assertFalse(BaselineStore(self.state).discard_unpublished(prepared[0]))
        finally:
            unreadable.stop()
        self.assertEqual(self.baseline_dirs(), [prepared[0].id])
        self.assertEqual(self.records(), [])

    def test_failed_promotion_never_removes_preexisting_trusted_material(self):
        self.assertEqual(self.execute()['status'], 'succeeded')
        store = BaselineStore(self.state)
        key = self.agent._baseline_key(self.service)
        trusted = store.records(key)[0]
        self.assertEqual(self.baseline_dirs(), [trusted.id])
        inventory = build_inventory([str(self.compose)], str(self.project))
        with patch('docker_update_manager.compose_baseline.secrets.token_hex', return_value=trusted.id), \
                self.assertRaises(OSError):
            store.prepare(key=key, stack=trusted.stack, compose_service=trusted.compose_service,
                          container_id=trusted.container_id, runtime_hash=trusted.runtime_hash,
                          model=self.fake.model([str(self.compose)], str(self.project), None),
                          inventory=inventory, origin='captured', captured_at='2026-10-03T00:00:00Z')
        self.assertEqual(self.baseline_dirs(), [trusted.id])
        self.assertEqual([item.id for item in store.records(key)], [trusted.id])
        store.load(trusted)

    def test_cleanup_refuses_symlink_unsafe_and_malformed_targets(self):
        store = BaselineStore(self.state)
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'keep').write_text('x')
        root = store._ensure_root()
        record = type('Record', (), {'id': 'e' * 32})()
        (root / record.id).symlink_to(outside, target_is_directory=True)
        store.discard_unpublished(record)
        self.assertTrue((outside / 'keep').exists())
        self.assertFalse(store.discard_unpublished(type('Record', (), {'id': '../outside'})()))


class BootstrapWebTests(unittest.TestCase):
    from test_compose_reconciliation import ServiceDetailAndOperationRouteTests
    setUp = ServiceDetailAndOperationRouteTests.setUp

    def configure(self):
        self.agent.compose_status_data = self.ServiceDetailAndOperationRouteTests.drifted(
            baseline=None,apply_eligible=False,bootstrap_eligible=True,changes_itemised=False,service_changes=[],project_changes=[],
            bootstrap_proposal=[{'field':'environment','label':'Environment','summary':'1 set · names only','items':['API_KEY']},
                                {'field':'command','label':'Command','summary':'Configured'}])

    def test_confirmation_risk_acknowledgement_and_auth_origin_csrf_exact_payload(self):
        self.configure()
        self.assertIn('Apply configuration and establish trust',self.client.get(self.url).text)
        review={'csrf':self.csrf,'service_key':'container/'+'a'*64,'action':'bootstrap'}
        confirm={'csrf':self.csrf,'confirmation_id':'B'*43,'acknowledge_no_rollback':'yes'}
        response=self.client.post('/compose/bootstrap/review',data=review)
        self.assertEqual(response.status_code,200)
        self.assertIn('Apply configuration without automatic rollback?',response.text)
        self.assertIn('manual recovery may be required',response.text)
        self.assertNotIn('checked',response.text.split('id="confirm-bootstrap"')[0].split('<input')[-1])
        self.assertNotIn(SECRET,response.text)
        for text in ('Running container (observed)','Observations come from Docker','Previous value: unknown','Unknown · no trusted baseline',
                     'Recreate service and establish trust','Reviewed configuration'):
            self.assertIn(text,response.text)
        actions=response.text.split('class="review-actions"')[1].split('</div>')[0]
        self.assertIn('Recreate service and establish trust',actions)
        self.assertIn('href="/services/container/'+'a'*64+'">Cancel</a>',actions)
        self.assertNotIn('btn-danger',response.text)
        self.agent.bootstrap_observations=[{'label':'Image','value':'x','extra':'y'}]
        self.agent.compose_status_data['bootstrap_observations']=self.agent.bootstrap_observations
        self.assertEqual(self.client.post('/compose/bootstrap/review',data=review).status_code,409)
        del self.agent.compose_status_data['bootstrap_observations']
        for route,payload in (('/compose/bootstrap/review',review),('/operations/compose-bootstrap',confirm)):
            self.assertEqual(self.client.post(route,data={**payload,'source_path':'tampered'}).status_code,400)
            self.assertEqual(self.client.post(route,data={**payload,'csrf':'wrong'}).status_code,403)
            self.assertEqual(self.client.post(route,data=payload,headers={'Origin':'https://hostile.example'}).status_code,403)
        self.assertEqual(self.client.post('/operations/compose-bootstrap',data={**confirm,'acknowledge_no_rollback':'no'}).status_code,400)
        self.assertEqual(self.client.post('/operations/compose-bootstrap',data=confirm,follow_redirects=False).status_code,303)
        self.assertEqual(set(self.agent.compose_apply_calls[0]),{'confirmation_id','acknowledge_no_rollback','requested_by','client_ip','user_agent'})
        self.client.cookies.clear()
        self.assertEqual(self.client.post('/compose/bootstrap/review',data=review,follow_redirects=False).status_code,303)

    def test_bootstrap_terminal_reload_and_sse_have_identical_presentation(self):
        for status in ('succeeded','blocked','failed'):
            operation={'id':'f'*32,'kind':'compose_bootstrap','service':'Sonarr','stack':'media','service_key':'container/'+'a'*64,
                       'status':status,'result':{'manual_recovery_required':status=='failed'},'events':[],'last_event_id':0}
            self.agent.operation=operation
            page=self.client.get('/operations/'+'f'*32)
            stream=self.client.get('/operations/'+'f'*32+'/events')
            name={'succeeded':'operation-complete','blocked':'operation-blocked','failed':'operation-failed'}[status]
            payload=json.loads(stream.text.split('event: '+name+'\ndata: ',1)[1].split('\n',1)[0])
            view=operation_presentation(operation)
            self.assertEqual(payload['presentation'],view)
            self.assertIn(view['status_label'],page.text)
            self.assertNotIn('Trusted baseline and desired configuration evidence',page.text)


if __name__ == '__main__':
    unittest.main()
