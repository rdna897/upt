import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import errno
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from docker_update_manager.compose import ComposeSourceNotWritable, backup_files
from docker_update_manager.config import Config
from docker_update_manager.models import ScanResult, Service
from docker_update_manager.lock import Lock
from docker_update_manager.operations import ReviewedTargetChanged, WebRollbackFailure, do_web_rollback
from docker_update_manager.progress import NULL_REPORTER, Reporter
from progress_assertions import assert_core_stage_model
from sqlite_faults import history_insert, sqlite_fault, terminal_operation_update
from docker_update_manager.state import State
from docker_update_manager.system import CommandError
from docker_update_manager.webservice import ReadOnlyService, _public_result, _public_service
from docker_update_manager.webviews import merge_service_items


class WebRollbackReviewTests(unittest.TestCase):
    def setUp(self):
        # This ordinary rollback fixture has no namespace relationship.
        namespace = patch("docker_update_manager.compose_namespace.mutation_refusal", return_value=None)
        namespace.start()
        self.addCleanup(namespace.stop)
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.compose=self.root/"compose.yml"
        self.compose.write_text("name: media\nservices:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:latest\n")
        self.state=State(self.root/"state")
        self.config=Config(path=str(self.root/"config.yml"))
        self.agent=ReadOnlyService(self.config,self.state)
        self.service=self.make_service()
        # Same-project refresh is a background follow-up; tests opt in explicitly.
        self.project_refresh_patch = patch.object(self.agent, "_queue_project_refresh", return_value="queued")
        self.project_refresh = self.project_refresh_patch.start()
        self.addCleanup(self.project_refresh_patch.stop)
        # Keep asynchronous follow-ups inside this fixture. The registry result
        # is explicit and delayed until cleanup, proving that terminal operation
        # status is not the worker's lifecycle boundary.
        self.refresh_gate = threading.Event()
        self.refresh_entered = threading.Event()
        def scan(current, _state):
            self.refresh_entered.set()
            self.refresh_gate.wait()
            return ScanResult(current, "CURRENT", current.digest)
        for target, kwargs in (
                ("discover", {"side_effect": lambda *_args, **_kwargs: [self.service]}),
                ("run", {"side_effect": self.inspect_run}),
                ("scan_service_with_tracking", {"side_effect": scan})):
            patcher = patch("docker_update_manager.webservice." + target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Registered after patches: join before their LIFO removal or temp cleanup.
        self.addCleanup(self.stop_workers)
        self.save_scan(self.service)
        self.history_id=self.add_update(self.service)

    def stop_workers(self):
        self.refresh_gate.set()
        self.agent.stop_health_monitor()
        deadline = time.monotonic() + 5
        while True:
            with self.agent._lock:
                workers = set(self.agent._refresh_threads.values())
                workers.update(self.agent._threads.values())
                workers.update(self.agent._operation_threads.values())
                if self.agent._project_refresh_thread is not None:
                    workers.add(self.agent._project_refresh_thread)
            workers = [thread for thread in workers if thread.is_alive()]
            if not workers or time.monotonic() >= deadline:
                break
            for thread in workers:
                thread.join(max(0, deadline - time.monotonic()))
        # The central guard fails and stops the suite if any worker survives.

    def test_fixture_cleanup_finishes_delayed_targeted_refresh_before_unpatch(self):
        self.agent.start_refresh("container/" + self.service.container_id)
        self.assertTrue(self.refresh_entered.wait(2))
        with self.agent._lock:
            worker = self.agent._refresh_threads["container/" + self.service.container_id]
        self.assertTrue(worker.is_alive())
        self.stop_workers()
        self.assertFalse(worker.is_alive())
        self.assertEqual(self.agent.refresh_status("container/" + self.service.container_id)["status"], "idle")
        self.assertEqual(self.agent.verification_snapshot()["records"][0]["result"]["status"], "CURRENT")

    def make_service(self,**changes):
        values=dict(name="sonarr",container_id="a"*64,
            image="lscr.io/linuxserver/sonarr:latest",image_id="sha256:"+"2"*64,
            digest="sha256:"+"2"*64,version="4.0.16",created="2026-09-01T00:00:00Z",
            architecture="amd64",state="running",health="healthy",restart_policy="unless-stopped",
            started_at="2026-09-20T00:00:00Z",stack="media",compose_service="sonarr",
            working_dir=str(self.root),compose_files=[str(self.compose)],
            labels={"com.docker.compose.config-hash":"a"*64,
                    "com.docker.compose.project":"media"},local_build=False,ignored=False)
        values.update(changes)
        return Service(**values)

    def save_scan(self,service):
        self.state.start_scan("scan-"+str(id(service))+str(len(self.state.history())))
        run=self.state.latest_scan_run()
        self.state.finish_scan(run["id"],"complete",services=[{
            "service":_public_service(service),"status":"CURRENT",
            "remote_digest":None,"remote_version":None,
        }])

    def add_update(self,service,*,backup=None,old_image=None,old_image_id=None,
                   old_digest=None,old_version="4.0.15",new_image=None,new_image_id=None,
                   details=None,result="SUCCESS"):
        if backup is None: backup=backup_files([str(self.compose)],self.state.root,service)
        return self.state.record(stack=service.stack,service=service.key,action="update",
            old_image=old_image or service.image,
            old_image_id=old_image_id or ("sha256:"+"1"*64),
            old_digest=old_digest or ("sha256:"+"1"*64),old_version=old_version,
            new_image=new_image or service.image,new_image_id=new_image_id or service.image_id,
            new_digest=service.digest,new_version=service.version,backup=str(backup),result=result,
            details=details or {})

    def compose_run(self,args,**_kwargs):
        if "--hash" in args: return "sonarr "+"a"*64+"\n"
        if "--format" in args:
            compose_files=[]
            for index,value in enumerate(args[:-1]):
                if value=="-f": compose_files.append(Path(args[index+1]))
            image=self.service.image
            project_name=os.environ.get("COMPOSE_PROJECT_NAME") or self.root.name
            for path in compose_files:
                try:
                    import yaml
                    parsed=yaml.safe_load(path.read_text()) or {}
                    project_name=parsed.get("name",project_name)
                    candidate=(parsed.get("services") or {}).get("sonarr",{}).get("image")
                    if candidate: image=str(candidate)
                except (OSError,ValueError): pass
            if "--project-name" in args:
                project_name=args[args.index("--project-name")+1]
            return json.dumps({"name":project_name,"services":{"sonarr":{"image":image}}})
        return ""

    def inspect_run(self,args,**kwargs):
        if "image" in args and "inspect" in args:
            image_id=args[-1]
            suffix=image_id.split(":",1)[-1][-1:]
            old_id="sha256:"+suffix*64
            digest="sha256:"+suffix*64
            return json.dumps({"Id":image_id,"Architecture":"amd64",
                               "RepoDigests":["lscr.io/linuxserver/sonarr@"+digest] if image_id==old_id else []})
        return self.compose_run(args,**kwargs)

    def review(self):
        return self.agent.rollback_review({"service_key":"container/"+self.service.container_id,
                                           "requested_by":"admin"})

    def patches(self):
        return (patch("docker_update_manager.webservice.discover",return_value=[self.service]),
                patch("docker_update_manager.webservice.run",side_effect=self.inspect_run))

    def test_latest_successful_update_selects_one_server_bound_rollback_point(self):
        older=self.history_id
        newest=self.add_update(self.service,old_image="lscr.io/linuxserver/sonarr:latest",
                               old_image_id="sha256:"+"3"*64,old_digest="sha256:"+"3"*64,
                               old_version="4.0.14")
        with self.patches()[0],self.patches()[1]: reviewed=self.review()
        intent=self.agent._rollback_intents[reviewed["confirmation_id"]]
        self.assertEqual(intent.rollback_identity[0],newest)
        self.assertNotEqual(intent.rollback_identity[0],older)
        self.assertRegex(reviewed["confirmation_id"],r"^[A-Za-z0-9_-]{43}$")
        self.assertNotIn("history_id",reviewed)
        self.assertNotIn("backup",reviewed)

    def test_stale_review_after_newer_update_fails_closed(self):
        with self.patches()[0],self.patches()[1]: reviewed=self.review()
        self.add_update(self.service,old_image="lscr.io/linuxserver/sonarr:latest",
                        old_image_id="sha256:"+"3"*64,old_digest="sha256:"+"3"*64,
                        old_version="4.0.14")
        payload={"confirmation_id":reviewed["confirmation_id"],"requested_by":"admin",
                 "client_ip":"127.0.0.1","user_agent":"tests"}
        with self.assertRaisesRegex(RuntimeError,"changed|stale"):
            with self.patches()[0],self.patches()[1]: self.agent.start_rollback(payload)
        self.assertEqual(self.state.history()[-1]["action"],"update")

    def test_compose_edit_after_review_is_preserved_and_stale_submission_fails_before_mutation(self):
        with self.patches()[0],self.patches()[1]: reviewed=self.review()
        operator_edit=b"services:\n  sonarr:\n    image: operator/changed:9\n"
        self.compose.write_bytes(operator_edit)
        with self.patches()[0],self.patches()[1],\
             patch("docker_update_manager.operations.run") as mutate,\
             self.assertRaisesRegex(RuntimeError,"stale|changed"):
            self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"tests"})
        self.assertEqual(self.compose.read_bytes(),operator_edit)
        mutate.assert_not_called()

    def test_read_only_source_parent_refuses_rollback_before_recovery_backup_or_restore(self):
        original=self.compose.read_bytes(); env=self.root/".env"; env.write_text("PORT=8989\n")
        backup=backup_files([str(self.compose),str(env)],self.state.root,self.service)
        with self.state.connect() as connection:
            connection.execute("UPDATE history SET backup=? WHERE id=?",(str(backup),self.history_id))
        compose_mutations=[]
        with self.patches()[0],self.patches()[1], \
             patch("docker_update_manager.webservice.verify_atomic_replace_access",
                   side_effect=ComposeSourceNotWritable(errno.EROFS)) as probe, \
             patch("docker_update_manager.operations.run",side_effect=lambda args,**kwargs: compose_mutations.append(list(args))), \
             patch("docker_update_manager.operations.backup_files") as recovery_backup, \
             self.assertLogs("docker_update_manager.webservice",level="ERROR") as captured:
            reviewed=self.review()
            started=self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"read-only-preflight"})
            operation_id=started["operation_id"]
            deadline=__import__("time").monotonic()+3
            while __import__("time").monotonic()<deadline:
                operation=self.state.operation_status(operation_id)
                if operation["status"] in {"succeeded","failed"}: break
                __import__("time").sleep(.01)

        self.assertEqual(operation["status"],"failed")
        self.assertIn("UPT cannot modify this service's Compose source from the agent sandbox",operation["error"])
        self.assertEqual(self.compose.read_bytes(),original,"rollback must not restore or alter sources after refusal")
        probe.assert_called_once_with([str(self.compose),str(env)])
        recovery_backup.assert_not_called()
        self.assertFalse(any("up" in command or "pull" in command for command in compose_mutations))
        rollback=next(item for item in self.state.history()
                      if item["action"]=="rollback" and json.loads(item.get("details") or "{}").get("operation_id")==operation_id)
        self.assertEqual(rollback["result"],"FAILED")
        self.assertEqual(rollback["rollback_result"],"NO CHANGES MADE")
        log="\n".join(captured.output)
        self.assertIn("operation=rollback",log); self.assertIn("stack=media",log)
        self.assertIn("service=sonarr",log); self.assertIn("errno=EROFS",log)
        self.assertNotIn(str(self.compose),log); self.assertNotIn(original.decode(),log)

    def test_changed_running_service_identity_invalidates_rollback_review(self):
        with self.patches()[0],self.patches()[1]: reviewed=self.review()
        changed=self.make_service(container_id="b"*64)
        with patch("docker_update_manager.webservice.discover",return_value=[changed]),\
             patch("docker_update_manager.webservice.run",side_effect=self.inspect_run),\
             self.assertRaisesRegex(RuntimeError,"changed|stale"):
            self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"tests"})

    def test_project_name_mismatch_or_process_override_refuses_rollback_before_restore(self):
        before=self.compose.read_bytes()
        self.compose.write_bytes(before.replace(b"name: media",b"name: other"))
        with self.patches()[0],self.patches()[1],self.assertRaisesRegex(ValueError,"project identity"):
            self.review()
        self.assertEqual(self.compose.read_bytes(),before.replace(b"name: media",b"name: other"))
        self.compose.write_bytes(before)
        with patch.dict(os.environ,{"COMPOSE_PROJECT_NAME":"other"}),self.patches()[0],self.patches()[1],\
             self.assertRaisesRegex(ValueError,"project identity"):
            self.review()
        self.assertEqual(self.agent._rollback_intents,{})

    def test_project_name_change_after_rollback_review_cannot_start_mutation(self):
        with self.patches()[0],self.patches()[1]: reviewed=self.review()
        original=self.compose.read_bytes()
        self.compose.write_bytes(original.replace(b"name: media",b"name: other"))
        with self.patches()[0],self.patches()[1],self.assertRaisesRegex(ReviewedTargetChanged,"reviewed rollback point or service changed"):
            self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"tests"})
        self.assertEqual(self.compose.read_bytes(),original.replace(b"name: media",b"name: other"))
        self.assertFalse(any(item["action"]=="rollback" for item in self.state.history()))

    def test_shared_mutation_lock_prevents_rollback_start(self):
        with self.patches()[0],self.patches()[1]: reviewed=self.review()
        with Lock(self.state.root/"update.lock"),self.assertRaisesRegex(RuntimeError,"another modifying"):
            with self.patches()[0],self.patches()[1]:
                self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                    "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"tests"})

    def test_tampered_and_requester_changed_review_cannot_start(self):
        with self.assertRaisesRegex(ValueError,"invalid or expired"):
            self.agent.start_rollback({"confirmation_id":"A"*43,"requested_by":"admin",
                "client_ip":"127.0.0.1","user_agent":"tests"})
        with self.patches()[0],self.patches()[1]: reviewed=self.review()
        payload={"confirmation_id":reviewed["confirmation_id"],"requested_by":"other",
                 "client_ip":"127.0.0.1","user_agent":"tests"}
        with self.assertRaisesRegex(ValueError,"invalid or expired"):
            self.agent.start_rollback(payload)

    def test_expired_reference_is_unavailable(self):
        with self.state.connect() as connection:
            connection.execute("UPDATE rollback_refs SET expired=1 WHERE history_id=?",(self.history_id,))
        with self.patches()[0],self.patches()[1],self.assertRaisesRegex(ValueError,"expired"):
            self.review()

    def test_missing_backup_is_unavailable(self):
        with self.state.connect() as connection:
            connection.execute("UPDATE history SET backup=? WHERE id=?",(str(self.root/"backups"/"missing"),self.history_id))
        with self.patches()[0],self.patches()[1],self.assertRaisesRegex(ValueError,"missing"):
            self.review()

    def test_missing_protected_rollback_reference_is_unavailable(self):
        with self.state.connect() as connection:
            connection.execute("DELETE FROM rollback_refs WHERE history_id=?",(self.history_id,))
        with self.patches()[0],self.patches()[1],\
             self.assertRaisesRegex(ValueError,"protected rollback image reference is missing"):
            self.review()

    def test_missing_protected_image_is_unavailable(self):
        def missing(args,**kwargs):
            if "image" in args and "inspect" in args:
                raise CommandError(["docker","image","inspect"],"no such image")
            return self.compose_run(args,**kwargs)
        with patch("docker_update_manager.webservice.discover",return_value=[self.service]),\
             patch("docker_update_manager.webservice.run",side_effect=missing),\
             self.assertRaisesRegex(ValueError,"unavailable locally"):
            self.review()

    def test_compose_source_drift_is_refused_during_review(self):
        self.compose.write_text("services:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:operator-change\n")
        with self.patches()[0],self.patches()[1],self.assertRaisesRegex(ValueError,"changed"):
            self.review()

    def test_unrelated_project_model_drift_is_refused(self):
        original=self.agent._compose_config_model
        def models(service):
            model=original(service); model["services"]["redis"]={"image":"redis:8"}; return model
        with self.patches()[0],self.patches()[1],\
             patch.object(self.agent,"_compose_config_model",side_effect=models),\
             self.assertRaisesRegex(ValueError,"Compose configuration changed"):
            self.review()

    def test_digest_pin_only_change_is_accepted_and_bound(self):
        old_image="lscr.io/linuxserver/sonarr:stable@sha256:"+"1"*64
        new_image="lscr.io/linuxserver/sonarr:stable@sha256:"+"2"*64
        self.compose.write_text("name: media\nservices:\n  sonarr:\n    image: "+old_image+"\n")
        backup=backup_files([str(self.compose)],self.state.root,self.service)
        self.compose.write_text("name: media\nservices:\n  sonarr:\n    image: "+new_image+"\n")
        self.service=self.make_service(image=new_image,digest="sha256:"+"2"*64)
        self.save_scan(self.service)
        self.history_id=self.state.record(stack="media",service="sonarr",action="update",
            old_image=old_image,old_image_id="sha256:"+"1"*64,old_digest="sha256:"+"1"*64,
            old_version="4.0.15",new_image=new_image,new_image_id=self.service.image_id,
            new_digest=self.service.digest,new_version="4.0.16",backup=str(backup),result="SUCCESS",
            details={"origin":"web","pin_advanced":True})
        with patch("docker_update_manager.webservice.discover",return_value=[self.service]),\
             patch("docker_update_manager.webservice.run",side_effect=self.inspect_run):
            reviewed=self.review()
        self.assertTrue(reviewed["rollback"]["digest_pin"])
        self.assertEqual(reviewed["rollback"]["target_image"],old_image)
        self.assertEqual(reviewed["rollback"]["tracking_tag"],"stable")
        intent=self.agent._rollback_intents[reviewed["confirmation_id"]]
        self.assertNotIn("tracking_tag", intent.__dict__)
        self.assertEqual(intent.source_identity[0][1],self.agent._bytes_fingerprint(self.compose.read_bytes()))

    def test_missing_runtime_config_identity_fails_closed(self):
        def no_hash(args,**kwargs):
            if "--hash" in args: return ""
            return self.inspect_run(args,**kwargs)
        with patch("docker_update_manager.webservice.discover",return_value=[self.service]),\
             patch("docker_update_manager.webservice.run",side_effect=no_hash),\
             self.assertRaisesRegex(ValueError,"identity is missing or ambiguous"):
            self.review()

    def test_agent_worker_persists_progress_history_and_audit_with_all_runtime_calls_mocked(self):
        commands=[]
        def operation_run(args,**kwargs):
            commands.append(list(args))
            if "image" in args and "inspect" in args:
                return "sha256:"+"1"*64
            return ""
        with patch("docker_update_manager.webservice.discover",return_value=[self.service]),\
             patch("docker_update_manager.webservice.run",side_effect=self.inspect_run),\
             patch("docker_update_manager.operations.discover",return_value=[
                 self.make_service(image_id="sha256:"+"1"*64)]),\
             patch("docker_update_manager.operations.run",side_effect=operation_run),\
             patch("docker_update_manager.compose.run",return_value=""):
            reviewed=self.review()
            started=self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"tests"})
            operation_id=started["operation_id"]
            with self.assertRaisesRegex(ValueError,"invalid or expired"):
                self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                    "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"tests"})
            deadline=__import__("time").monotonic()+3
            while __import__("time").monotonic()<deadline:
                operation=self.state.operation_status(operation_id)
                if operation["status"] in {"succeeded","failed"}: break
                __import__("time").sleep(.01)
        self.assertEqual(operation["status"],"succeeded",operation.get("error"))
        rollback=next(item for item in self.state.history() if item["action"]=="rollback")
        self.assertEqual(rollback["result"],"ROLLED BACK")
        self.assertEqual(rollback["rollback_result"],"SUCCESS")
        self.assertTrue(Path(rollback["backup"]).is_dir())
        self.assertNotIn("recovery_backup",operation["result"],
                         "the browser-facing operation API must not expose server filesystem paths")
        self.assertIn("5/8 Verify protected rollback image",[event["stage"] for event in operation["events"]])
        self.assertEqual(sum("up" in command for command in commands),1)
        self.assertTrue(all(command[command.index("--project-name")+1]=="media"
                            for command in commands if "up" in command))
        audits=self.state.audit_events(10)
        self.assertIn(("web_rollback","success"),{(event["action"],event["result"]) for event in audits})

    # S6-R1b (G2, issue #9): CURRENT-BEHAVIOUR characterisation, not the desired
    # contract. A healthy web rollback is followed by a SQLite failure inside a
    # real State transaction; the approved G2 fixes are expected to break these.
    def run_rollback_with_sqlite_fault(self,match,**fault):
        commands=[]
        def operation_run(args,**kwargs):
            commands.append(list(args))
            if "image" in args and "inspect" in args:
                return "sha256:"+"1"*64
            return ""
        with patch("docker_update_manager.webservice.discover",return_value=[self.service]),\
             patch("docker_update_manager.webservice.run",side_effect=self.inspect_run),\
             patch("docker_update_manager.operations.discover",return_value=[
                 self.make_service(image_id="sha256:"+"1"*64)]),\
             patch("docker_update_manager.operations.run",side_effect=operation_run),\
             patch("docker_update_manager.compose.run",return_value=""):
            reviewed=self.review()
            with sqlite_fault(self.state,match,**fault) as injected:
                started=self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                    "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"tests"})
                with self.agent._lock:
                    worker=self.agent._operation_threads.get(started["operation_id"])
                # A missing worker has already finished: it is removed only in
                # the worker's own finally block.
                if worker is not None: worker.join(10)
                self.assertFalse(worker is not None and worker.is_alive())
        self.assertEqual(len(injected.hits),1)
        # Docker outcome in every case: exactly one service-scoped rollback
        # recreation and no recovery recreation.
        self.assertEqual(sum("up" in command for command in commands),1)
        rollbacks=[item for item in self.state.history() if item["action"]=="rollback"]
        return self.state.operation_status(started["operation_id"]),rollbacks

    def test_current_behaviour_completed_rollback_with_failed_history_write_is_recorded_as_no_changes_made(self):
        with self.assertLogs("docker_update_manager.webservice","ERROR"):
            operation,rollbacks=self.run_rollback_with_sqlite_fault(
                history_insert(action="rollback",result="ROLLED BACK"))
        # DEFECT encoded as current behaviour: sqlite3.Error is outside
        # do_web_rollback's recovery handler, so the web wrapper's stale-review
        # fallback records the completed rollback as if nothing had changed.
        self.assertEqual(operation["status"],"failed")
        self.assertEqual(operation["result"],{"manual_recovery_required":False,"recovered":False})
        (rollback,)=rollbacks
        self.assertEqual((rollback["result"],rollback["rollback_result"]),("FAILED","NO CHANGES MADE"))
        self.assertEqual(json.loads(rollback["details"])["error"],"review became stale before mutation")
        self.assertIsNone(rollback["backup"])
        self.assertIn(("web_rollback","failed"),
                      {(event["action"],event["result"]) for event in self.state.audit_events(10)})

    def test_current_behaviour_failed_success_terminal_write_leaves_history_and_operation_disagreeing(self):
        with self.assertLogs("docker_update_manager.webservice","ERROR"):
            operation,rollbacks=self.run_rollback_with_sqlite_fault(terminal_operation_update("succeeded"))
        (rollback,)=rollbacks
        self.assertEqual((rollback["result"],rollback["rollback_result"]),("ROLLED BACK","SUCCESS"))
        self.assertTrue(Path(rollback["backup"]).is_dir())
        # The fallback finds this operation's rollback row and adds no FAILED row,
        # but still finishes the operation as failed.
        self.assertEqual(operation["status"],"failed")
        self.assertIn(("web_rollback","success"),
                      {(event["action"],event["result"]) for event in self.state.audit_events(10)})

    def test_current_behaviour_persistent_unavailability_after_rollback_leaves_no_terminal_state(self):
        with self.assertLogs("docker_update_manager.webservice","ERROR"),\
             self.assertLogs("docker_update_manager.reconciliation","WARNING"):
            operation,rollbacks=self.run_rollback_with_sqlite_fault(
                history_insert(action="rollback",result="ROLLED BACK"),mode="unavailable")
        # Nothing about the completed rollback is durable and the operation is
        # never finished: it stays running after its worker has exited. A fix
        # that keeps evidence outside SQLite must also update this test.
        self.assertEqual(rollbacks,[])
        self.assertEqual(operation["status"],"running")

    def test_agent_recovery_reconstructs_model_from_existing_verified_backup_paths(self):
        env_path=self.root/".env"
        env_before=b"RECOVERY_FIXTURE=stable\n"
        env_path.write_bytes(env_before)
        compose_before=self.compose.read_bytes()
        original_backup=backup_files([str(self.compose),str(env_path)],self.state.root,self.service)
        with self.state.connect() as connection:
            connection.execute("UPDATE history SET backup=? WHERE id=?",(str(original_backup),self.history_id))

        recreations=[]; compose_calls=[]; recovery_dirs=[]; recovery_model_inputs=[]
        image_tags={}; runtime_observed=[]
        original_model_builder=self.agent._compose_model_from_backups
        def require_compose_files(args):
            for index,argument in enumerate(args[:-1]):
                if argument not in {"-f","--env-file"}: continue
                path=Path(args[index+1])
                if not path.is_file():
                    raise AssertionError(f"Compose {argument} path must exist: {path!s}")

        def strict_agent_run(args,**kwargs):
            if args[:2]==["docker","compose"]:
                require_compose_files(args)
                compose_calls.append((len(recreations),list(args)))
            if "image" in args and "inspect" in args:
                return self.inspect_run(args,**kwargs)
            return self.compose_run(args,**kwargs)

        def strict_compose_run(args,**kwargs):
            require_compose_files(args)
            return ""

        def strict_model_builder(service,files,compose_paths,env_file=None):
            if recreations:
                recovery_dir=recovery_dirs[-1].resolve(strict=True)
                self.assertEqual(set(files),{str(self.compose.resolve()),str(env_path.resolve())})
                self.assertIsNotNone(env_file,"the captured project .env must participate in backup-model reconstruction")
                for source,path in files.items():
                    backup=Path(path)
                    self.assertTrue(backup.is_file(),f"backup path for {source} must be an existing file")
                    self.assertTrue(backup.resolve().is_relative_to(recovery_dir),
                                    "recovery model inputs must come from the verified pre-rollback backup")
                env_backup=Path(files[env_file]).resolve(strict=True)
                self.assertEqual(env_backup.read_bytes(),env_before)
                recovery_model_inputs.append(dict(files))
            return original_model_builder(service,files,compose_paths,env_file)

        def capture_recovery_backup(files,state_root,service):
            directory=backup_files(files,state_root,service).resolve(strict=True)
            recovery_dirs.append(directory)
            return directory

        def operation_run(args,**kwargs):
            if args[:3]==["docker","image","tag"]:
                image_tags[args[-1]]=args[-2]
                return ""
            if args[:3]==["docker","image","inspect"] and "{{.Id}}" in args:
                reference=args[-1]
                return image_tags.get(reference,self.service.image_id)
            if "up" in args:
                recreations.append(list(args))
                if len(recreations)==1:
                    raise CommandError(args,"simulated rollback recreation failure")
            return ""

        def operation_discover(*_args,**_kwargs):
            runtime_observed.append(self.service.image_id)
            return [self.service]

        with patch("docker_update_manager.webservice.discover",return_value=[self.service]),\
             patch("docker_update_manager.webservice.run",side_effect=strict_agent_run),\
             patch("docker_update_manager.operations.discover",side_effect=operation_discover),\
             patch("docker_update_manager.operations.run",side_effect=operation_run),\
             patch("docker_update_manager.operations.backup_files",side_effect=capture_recovery_backup),\
             patch("docker_update_manager.compose.run",side_effect=strict_compose_run),\
             patch.object(self.agent,"_compose_model_from_backups",side_effect=strict_model_builder):
            reviewed=self.review()
            started=self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"strict-path-test"})
            operation_id=started["operation_id"]
            deadline=__import__("time").monotonic()+5
            while __import__("time").monotonic()<deadline:
                operation=self.state.operation_status(operation_id)
                if operation["status"] in {"succeeded","failed"}: break
                __import__("time").sleep(.01)

        self.assertEqual(operation["status"],"failed",operation.get("error"))
        self.assertTrue(operation["result"]["recovered"],operation)
        self.assertFalse(operation["result"]["manual_recovery_required"])
        self.assertIn("Rollback did not complete, but UPT restored the previous configuration and service",
                      operation["error"])
        self.assertEqual(self.compose.read_bytes(),compose_before)
        self.assertEqual(env_path.read_bytes(),env_before)
        self.assertEqual(len(recreations),2,"rollback plus one recovery recreation; never a third")
        self.assertTrue(all("--no-deps" in command and "--pull" in command and "never" in command
                            and command[-1]=="sonarr" for command in recreations))
        self.assertTrue(all(command[command.index("--project-name")+1]=="media" for command in recreations))
        self.assertTrue(runtime_observed)
        self.assertEqual(runtime_observed[-1],self.service.image_id,
                         "the running service must verify against the pre-rollback image ID")
        self.assertTrue(recovery_dirs)
        self.assertTrue(recovery_dirs[0].is_relative_to((self.state.root/"backups").resolve()))
        self.assertTrue(recovery_model_inputs,"the recovery Compose model must use real backup-file paths")
        recovery_phase_calls=[args for attempts,args in compose_calls if attempts==1]
        self.assertTrue(recovery_phase_calls)
        for args in recovery_phase_calls:
            require_compose_files(args)
        recovery=next(item for item in self.state.history()
                      if item["action"]=="rollback"
                      and json.loads(item.get("details") or "{}").get("operation_id")==operation_id)
        self.assertEqual(recovery["result"],"FAILED")
        self.assertEqual(recovery["rollback_result"],"AUTOMATIC RECOVERY SUCCEEDED")
        self.assertTrue(Path(recovery["backup"]).is_dir())

    def test_failed_rollback_and_failed_single_recovery_report_manual_recovery_in_operation_history(self):
        commands=[]; ref_results=iter(["sha256:"+"1"*64,"sha256:"+"1"*64,
                                      "sha256:"+"2"*64,"sha256:"+"2"*64])
        def operation_run(args,**kwargs):
            commands.append(list(args))
            if "image" in args and "inspect" in args:
                return next(ref_results)
            if "up" in args: raise CommandError(args,"private compose command output")
            return ""
        with patch("docker_update_manager.webservice.discover",return_value=[self.service]),\
             patch("docker_update_manager.webservice.run",side_effect=self.inspect_run),\
             patch("docker_update_manager.operations.discover",return_value=[self.service]),\
             patch("docker_update_manager.operations.run",side_effect=operation_run),\
             patch("docker_update_manager.compose.run",return_value=""):
            reviewed=self.review()
            started=self.agent.start_rollback({"confirmation_id":reviewed["confirmation_id"],
                "requested_by":"admin","client_ip":"127.0.0.1","user_agent":"tests"})
            operation_id=started["operation_id"]
            deadline=__import__("time").monotonic()+3
            while __import__("time").monotonic()<deadline:
                operation=self.state.operation_status(operation_id)
                if operation["status"] in {"succeeded","failed"}: break
                __import__("time").sleep(.01)
        up=[command for command in commands if "up" in command]
        self.assertEqual(len(up),2,f"one rollback recreation and one recovery recreation are the maximum; operation={operation!r}; commands={commands!r}")
        self.assertTrue(all("--no-deps" in command and "--pull" in command and "never" in command for command in up))
        self.assertEqual(operation["status"],"failed")
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertNotIn("private compose command output",operation["error"])
        rollback=next(item for item in self.state.history() if item["action"]=="rollback")
        self.assertEqual(rollback["rollback_result"],"MANUAL RECOVERY REQUIRED")
        self.assertTrue(Path(rollback["backup"]).is_dir())
        original=next(item for item in self.state.history() if item["id"]==self.history_id)
        self.assertTrue(Path(original["backup"]).is_dir())
        self.assertTrue({"sha256:"+"1"*64,"sha256:"+"2"*64}.issubset(self.state.protected()),
                        "both the rollback target and pre-rollback service image remain protected")
        self.assertIn(("web_rollback","manual recovery required"),
                      {(event["action"],event["result"]) for event in self.state.audit_events(10)})


class WebRollbackExecutionTests(unittest.TestCase):
    def setUp(self):
        # This ordinary rollback fixture has no namespace relationship.
        namespace = patch("docker_update_manager.compose_namespace.mutation_refusal", return_value=None)
        namespace.start()
        self.addCleanup(namespace.stop)
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.compose=self.root/"compose.yml"
        self.before=b"services:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:latest\n"
        self.restored=b"services:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:4.0.15\n"
        self.compose.write_bytes(self.before)
        self.state=State(self.root/"state")
        self.current_id="sha256:"+"2"*64
        self.target_id="sha256:"+"1"*64
        self.service=Service(name="sonarr",container_id="a"*64,
            image="lscr.io/linuxserver/sonarr:latest",image_id=self.current_id,
            digest="sha256:"+"2"*64,version="4.0.16",created=None,architecture="amd64",
            state="running",health="healthy",restart_policy="unless-stopped",started_at=None,
            stack="media",compose_service="sonarr",working_dir=str(self.root),
            compose_files=[str(self.compose)])
        self.refresh=Mock()
        self.state.start_scan('before-rollback')
        self.state.finish_scan('before-rollback','complete',services=[_public_result(ScanResult(self.service,'UPDATE',self.target_id))])
        self.snapshot=self.state.latest_scan()
        self.rollback_backup=backup_files([str(self.compose)],self.state.root,self.service)
        history_id=self.state.record(stack="media",service="sonarr",action="update",
            old_image="lscr.io/linuxserver/sonarr:4.0.15",old_image_id=self.target_id,
            old_digest="sha256:"+"1"*64,old_version="4.0.15",
            new_image=self.service.image,new_image_id=self.current_id,new_digest=self.service.digest,
            new_version=self.service.version,backup=str(self.rollback_backup),result="SUCCESS")
        self.row=next(item for item in self.state.history() if item["id"]==history_id)
        self.sources=[{"path":str(self.compose),"before":self.before,"restore":self.restored}]
        self.command=["docker","compose","--project-directory",str(self.root),"--project-name","media","-f",str(self.compose),
                      "up","-d","--no-deps","--pull","never","sonarr"]

    def execute(self,run_effect,*,verify_pre=None,verify_sources=None,validate_effect=None,discover_effect=None,
                verify_image_effect=None,source_race=None,reporter=NULL_REPORTER):
        calls=[]; phases=[]; discovers=[]
        def run(args,**kwargs):
            calls.append(list(args))
            if "image" in args and "inspect" in args and "--format" in args and args[-2]=="{{.Id}}":
                return (verify_image_effect(args[-1]) if verify_image_effect
                        else self.target_id if args[-1]==self.row["old_image"] else self.current_id)
            return run_effect(args,kwargs,calls)
        def discover(**_kwargs):
            discovers.append(True)
            return [discover_effect() if discover_effect else self.service]
        def pre_restore(phase):
            phases.append(("restore",phase))
            if source_race and phase=="source-write": source_race()
        def pre_recreate(): phases.append(("recreate",))
        def source_guard(backup):
            phases.append(("sources",))
            for item in self.sources:
                if Path(item["path"]).read_bytes() not in {item["before"],item["restore"]}:
                    raise RuntimeError("concurrent source edit")
            if verify_sources: verify_sources(backup)
        def pre_rollback(phase,backup):
            phases.append(("pre-rollback",phase))
            if verify_pre: verify_pre(phase,backup)
        with patch("docker_update_manager.operations.run",side_effect=run),\
             patch("docker_update_manager.operations.discover",side_effect=discover),\
             patch("docker_update_manager.operations.validate",side_effect=validate_effect or (lambda _service,**_kw:None)):
            result=do_web_rollback(self.service,self.row,self.state,sources=self.sources,
                operation_id="b"*32,rollback_command=self.command,recovery_command=list(self.command),
                verify_before_restore=pre_restore,verify_before_recreate=pre_recreate,
                verify_recovery_sources=source_guard,verify_pre_rollback_recovery=pre_rollback,
                health_timeout=0,reporter=reporter,post_mutation=self.refresh)
        return result,calls,phases,discovers

    def assert_reconciled(self, service):
        self.refresh.assert_called_once_with(service)
        rows=merge_service_items(self.snapshot,self.state.runtime_snapshot(),
                                ReadOnlyService(Config(str(self.root/'fixture.yml')),self.state).verification_snapshot())
        self.assertEqual([(row['service']['container_id'],row['status']) for row in rows],
                         [(service.container_id,'CHECK REQUIRED')])
        self.assertIsNone(rows[0].get('target_image'))
        self.assertEqual(self.state.latest_scan(),self.snapshot)

    def test_rollback_reports_eight_real_stages_in_order(self):
        reporter=Reporter(enabled=False)
        target=Service(**{**self.service.__dict__,"container_id":"b"*64,"image_id":self.target_id,"state":"running","health":"healthy"})
        self.execute(lambda *_:"",discover_effect=lambda:target,reporter=reporter)
        self.assert_reconciled(target)
        self.assertEqual(assert_core_stage_model(self,reporter.events,8),list(range(1,9)))

    def test_failure_before_any_stage_executed_reports_no_numbered_final_stage(self):
        reporter=Reporter(enabled=False)
        def refuse(*_args,**_kwargs): raise RuntimeError("synthetic validation failure")
        with self.assertRaises(WebRollbackFailure):
            self.execute(lambda *_:"",validate_effect=refuse,reporter=reporter)
        steps=[(event.data["step"],event.status) for event in reporter.events if "step" in event.data]
        self.assertEqual([step for step,_status in steps],[1,2,3],"stages 4-7 never executed")
        self.assertNotIn(8,[step for step,_status in steps],"the final stage is the success record")
        self.assertFalse([status for _step,status in steps if status=="failed"],"nothing was running, so no step failed")

    def test_recovery_attempt_is_an_unnumbered_marker_not_a_repeated_stage(self):
        reporter=Reporter(enabled=False); ups=[]
        def effects(args,_kwargs,_calls):
            if "up" in args:
                ups.append(args)
                if len(ups)==1: raise CommandError(args,"rollback recreate failed")
            return ""
        target=Service(**{**self.service.__dict__,"container_id":"c"*64,"image_id":self.current_id,"state":"running","health":"healthy"})
        with self.assertRaises(WebRollbackFailure):
            self.execute(effects,discover_effect=lambda:target,reporter=reporter)
        completed=assert_core_stage_model(self,reporter.events,8)
        self.assertNotIn(8,completed)
        notes=[event for event in reporter.events if event.kind=="task_info"]
        self.assertEqual([event.message for event in notes],["Recovering previous service once","Recorded rollback failure"])
        self.assertTrue(all(event.status=="info" and event.current is None for event in notes))
        # The failure record is a marker, never a numbered stage; the in-flight step is what failed.
        stages=[(event.data["step"],event.status) for event in reporter.events if "step" in event.data]
        self.assertEqual(stages[-1],(6,"failed"))
        self.assertFalse([step for step,_status in stages if step==8])

    def test_recreates_only_selected_service_without_dependencies_or_pull(self):
        def effects(args,_kwargs,_calls): return ""
        target=Service(**{**self.service.__dict__,"image_id":self.target_id,"state":"running","health":"healthy"})
        result,calls,_phases,_discoveries=self.execute(effects,discover_effect=lambda:target)
        up=[call for call in calls if "up" in call]
        self.assertEqual(up,[self.command])
        self.assertIn("--no-deps",up[0]); self.assertIn("--pull",up[0]); self.assertIn("never",up[0])
        self.assertIn(["docker","image","tag",self.target_id,self.row["old_image"]],calls)
        self.assertIn(["docker","image","inspect","--format","{{.Id}}",self.row["old_image"]],calls)
        self.assertFalse(any(command[:2]==["docker","pull"] for command in calls))
        self.assertTrue(result["rolled_back"])
        self.assertEqual(self.compose.read_bytes(),self.restored)
        self.assertEqual(self.state.history()[0]["rollback_result"],"SUCCESS")

    def test_mutable_compose_reference_must_still_resolve_to_exact_protected_image(self):
        commands=[]
        def effects(args,_kwargs,_calls): commands.append(list(args)); return ""
        target=Service(**{**self.service.__dict__,"image_id":self.target_id,"state":"running","health":"healthy"})
        with self.assertRaises(WebRollbackFailure):
            self.execute(effects,discover_effect=lambda:target,
                         verify_image_effect=lambda _reference: self.current_id)
        self.assertEqual(self.compose.read_bytes(),self.before)
        self.assertFalse(any("up" in command for command in commands),
                         "a mutable Compose tag that no longer resolves to the protected ID must not be recreated")
        self.assertEqual(self.state.history()[0]["rollback_result"],"NO CHANGES MADE")

    def test_concurrent_operator_edit_before_source_replacement_is_never_overwritten(self):
        operator=b"services:\n  sonarr:\n    image: operator/concurrent:9\n"
        commands=[]
        def effects(args,_kwargs,_calls): commands.append(list(args)); return ""
        target=Service(**{**self.service.__dict__,"image_id":self.target_id,"state":"running","health":"healthy"})
        with self.assertRaises(WebRollbackFailure):
            self.execute(effects,discover_effect=lambda:target,
                         source_race=lambda:self.compose.write_bytes(operator))
        self.assertEqual(self.compose.read_bytes(),operator)
        self.assertFalse(any("up" in command for command in commands))

    def test_failed_rollback_recreation_recovers_once_and_records_history(self):
        ups=[]
        def effects(args,_kwargs,_calls):
            if "up" in args:
                ups.append(args)
                if len(ups)==1: raise CommandError(args,"rollback recreate failed")
            return ""
        result=[]
        target=Service(**{**self.service.__dict__,"image_id":self.current_id,"state":"running","health":"healthy"})
        with self.assertRaises(WebRollbackFailure) as caught:
            self.execute(effects,discover_effect=lambda:target)
        self.assertTrue(caught.exception.recovered)
        self.assert_reconciled(target)
        self.assertEqual(len(ups),2,"one rollback recreation and one recovery recreation are the maximum")
        self.assertEqual(self.compose.read_bytes(),self.before)
        failure=self.state.history()[0]
        self.assertEqual(failure["rollback_result"],"AUTOMATIC RECOVERY SUCCEEDED")
        self.assertTrue(Path(failure["backup"]).is_dir())
        self.assertTrue(Path(self.row["backup"]).is_dir())

    def test_recovery_guard_refusal_preserves_backup_and_makes_no_second_recreation(self):
        ups=[]
        def effects(args,_kwargs,_calls):
            if "up" in args:
                ups.append(args)
                raise CommandError(args,"recreate failed")
            return ""
        def guard(phase,_backup):
            if phase=="before-source-restore": raise RuntimeError("trusted model changed")
        with self.assertRaises(WebRollbackFailure) as caught:
            self.execute(effects,verify_pre=guard)
        self.assertTrue(caught.exception.manual_recovery_required)
        self.assertEqual(len(ups),1)
        self.assertEqual(self.compose.read_bytes(),self.restored)
        failure=self.state.history()[0]
        self.assertEqual(failure["rollback_result"],"MANUAL RECOVERY REQUIRED")
        self.assertTrue(Path(failure["backup"]).is_dir())
        self.assertTrue(Path(self.row["backup"]).is_dir())

    def test_recovery_recreation_failure_is_manual_and_never_attempts_a_third_up(self):
        ups=[]
        def effects(args,_kwargs,_calls):
            if "up" in args:
                ups.append(args)
                raise CommandError(args,"recreate failed")
            return ""
        with self.assertRaises(WebRollbackFailure) as caught:
            self.execute(effects)
        self.assertTrue(caught.exception.manual_recovery_required)
        self.assertEqual(len(ups),2)
        self.assert_reconciled(self.service)
        self.assertEqual(self.compose.read_bytes(),self.before)
        failure=self.state.history()[0]
        self.assertEqual(failure["rollback_result"],"MANUAL RECOVERY REQUIRED")
        self.assertTrue(Path(failure["backup"]).is_dir())

    def test_concurrent_operator_source_edit_is_not_overwritten_during_recovery(self):
        operator=b"services:\n  sonarr:\n    image: operator/edited:tag\n"
        ups=[]
        def effects(args,_kwargs,calls):
            if "up" in args:
                ups.append(args)
                if len(ups)==1:
                    self.compose.write_bytes(operator)
                    raise CommandError(args,"rollback recreate failed")
            return ""
        with self.assertRaises(WebRollbackFailure) as caught:
            self.execute(effects)
        self.assertTrue(caught.exception.manual_recovery_required)
        self.assertEqual(len(ups),1)
        self.assertEqual(self.compose.read_bytes(),operator)
        self.assertEqual(self.state.history()[0]["rollback_result"],"MANUAL RECOVERY REQUIRED")

    def test_compose_validation_failure_restores_source_without_recreating(self):
        validations=[]; ups=[]
        def validate(_service,**_kwargs):
            validations.append(True)
            if len(validations)==1: raise CommandError(["docker","compose","config"],"invalid")
        def effects(args,_kwargs,_calls):
            if "up" in args: ups.append(args)
            return ""
        with self.assertRaises(WebRollbackFailure): self.execute(effects,validate_effect=validate)
        self.assertGreaterEqual(len(validations),2)
        self.assertEqual(ups,[])
        self.assertEqual(self.compose.read_bytes(),self.before)
        self.assertEqual(self.state.history()[0]["rollback_result"],"NO CHANGES MADE")


if __name__=="__main__": unittest.main()
