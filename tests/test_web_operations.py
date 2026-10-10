import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import json
import errno
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("UPT_TESTING", "1")

from fastapi.testclient import TestClient

from docker_update_manager import __version__
from docker_update_manager.agent import AgentClient, AgentNotFound
from docker_update_manager.auth import new_token
from docker_update_manager.config import Config, WebConfig
from docker_update_manager.compose import ComposeSourceNotWritable
from docker_update_manager.compose_drift import ComposePreflightRefused
from docker_update_manager.lock import Lock
from docker_update_manager.models import ScanResult, Service, parse_image_ref
from docker_update_manager.operations import RecoveryFailed, RecoveryRefused, ReviewedTargetChanged
from docker_update_manager.release_identity import display_version
from docker_update_manager.state import State
from docker_update_manager.webapp import create_app, operation_event_role, operation_timeline
from progress_assertions import assert_stage_model
from docker_update_manager.webservice import AgentServer, ReadOnlyService, _public_result, _public_service
from docker_update_manager.webstate import WebState


class WebOperationAgentTests(unittest.TestCase):
    def setUp(self):
        # No namespace relation in this legacy fixture; live gates are covered
        # by test_compose_namespace's bounded Docker/Compose fixture.
        namespace = patch("docker_update_manager.compose_namespace.mutation_refusal", return_value=None)
        namespace.start()
        self.addCleanup(namespace.stop)
        namespace_status = patch("docker_update_manager.webservice.mutation_refusal", return_value=None)
        namespace_status.start()
        self.addCleanup(namespace_status.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.compose = self.root / "compose.yml"
        self.compose.write_text("name: media\nservices:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:latest\n")
        self.state = State(self.root / "state")
        self.config = Config(path=str(self.root / "config.yml"))
        self.agent = ReadOnlyService(self.config, self.state)
        self.service = self.make_service()
        # Same-project refresh is a background follow-up; tests opt in explicitly.
        self.project_refresh_patch = patch.object(self.agent, "_queue_project_refresh", return_value="queued")
        self.project_refresh = self.project_refresh_patch.start()
        self.addCleanup(self.project_refresh_patch.stop)
        self.save_snapshot(self.service, "UPDATE")
        live = patch("docker_update_manager.webservice.discover", side_effect=lambda _config: [self.service])
        live.start()
        self.addCleanup(live.stop)
        # update_review now runs an agent-side Compose preflight. Default to an
        # in-sync deterministic Compose fixture; tests that patch run override it.
        compose = patch("docker_update_manager.webservice.run", side_effect=lambda args, **kwargs: self.compose_run(args, **kwargs))
        compose.start()
        self.addCleanup(compose.stop)
        network = patch("docker_update_manager.webservice._runtime_project_network_id", return_value="b" * 64)
        network.start()
        self.addCleanup(network.stop)

    def make_service(self, **changes):
        values = dict(
            name="sonarr", container_id="a" * 64,
            image="lscr.io/linuxserver/sonarr:latest", image_id="sha256:" + "1" * 64,
            digest="sha256:" + "2" * 64, version="4.0.15", created="2026-09-01T00:00:00Z",
            architecture="amd64", state="running", health="healthy", restart_policy="unless-stopped",
            started_at="2026-09-01T00:00:00Z", stack="media", compose_service="sonarr",
            working_dir=str(self.root), compose_files=[str(self.compose)],
            labels={"com.docker.compose.config-hash": "a" * 64,
                    "com.docker.compose.project": "media"}, local_build=False,
            ignored=False,
        )
        values.update(changes)
        return Service(**values)

    def save_snapshot(self, service, status):
        self.state.start_scan("scan-" + str(time.time_ns()))
        run = self.state.latest_scan_run()
        item = {
            "service": _public_service(service), "status": status,
            "remote_digest": "sha256:" + "3" * 64, "remote_version": "4.0.16",
        }
        if status == "PINNED UPDATE":
            item["target_image"] = service.image.rsplit("@", 1)[0] + "@" + item["remote_digest"]
        self.state.finish_scan(run["id"], "complete", services=[item])

    def payload(self, **changes):
        record = self.agent.verification_snapshot()["records"][0]
        review = self.agent.update_review({"service_key": f"container/{self.service.container_id}",
                                           "requested_by": "admin",
                                           "verification_id": record["verification_id"]})
        data = {"confirmation_id": review["confirmation_id"], "requested_by": "admin",
                "client_ip": "127.0.0.1", "user_agent": "tests"}
        data.update(changes)
        return data

    def compose_run(self, args, **_kwargs):
        if "--hash" in args:
            return f"sonarr {'a' * 64}\n"
        return json.dumps({"name": "media", "services": {"sonarr": {"image": self.service.image}}})

    def wait_for_terminal(self, operation_id):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            operation = self.state.operation_status(operation_id)
            if operation["status"] in {"succeeded", "failed", "blocked"}:
                return operation
            time.sleep(.01)
        self.fail("web update worker did not reach a terminal state")

    def test_operation_timeline_collapses_active_stage_but_keeps_warning_failure_and_terminal(self):
        events = [
            {"id": 1, "kind": "task_started", "stage": "3/8 Pull image", "message": "In progress", "status": "running"},
            {"id": 2, "kind": "task_progress", "stage": "3/8 Pull image", "message": "Working", "status": "running"},
            {"id": 3, "kind": "task_completed", "stage": "3/8 Pull image", "message": "Completed", "status": "completed"},
            {"id": 4, "kind": "task_warning", "stage": "3/8 Pull image", "message": "Retrying layer", "status": "warning"},
            {"id": 5, "kind": "task_started", "stage": "4/8 Verify image", "message": "In progress", "status": "running"},
            {"id": 6, "kind": "task_failed", "stage": "4/8 Verify image", "message": "Step failed", "status": "failed"},
            {"id": 7, "kind": "operation_failed", "stage": "Failed", "message": "Operation failed", "status": "failed"},
        ]

        timeline = operation_timeline(events)

        self.assertEqual([item["id"] for item in timeline], [3, 4, 6, 7])
        self.assertEqual(timeline[0]["message"], "Completed")
        self.assertEqual(timeline[1]["message"], "Retrying layer")
        self.assertEqual(timeline[2]["status"], "failed")
        self.assertEqual(timeline[3]["kind"], "operation_failed")
        self.assertEqual([row["id"] for row in operation_timeline(events, terminal=True)], [3, 4, 6, 7])
        self.assertFalse(any(row["_timeline_active"] for row in operation_timeline(events, terminal=True)))
        self.assertNotIn("_timeline_active", events[0], "timeline projection must not rewrite persisted events")
        self.assertEqual(len(events), 7, "timeline rendering must not mutate persisted authoritative events")

    def test_timeline_marks_queued_and_transition_events_as_neutral_info_never_active_steps(self):
        events = [
            {"id": 1, "kind": "operation_started", "stage": "Queued", "message": "Update requested", "status": "queued"},
            {"id": 2, "kind": "task_started", "stage": "1/8 Back up", "message": "In progress", "status": "running"},
            {"id": 3, "kind": "task_info", "stage": "Recreation may have started", "message": "", "status": "info"},
            {"id": 4, "kind": "task_running", "stage": "Legacy marker", "message": "Recreation may have started", "status": "running"},
            {"id": 5, "kind": "task_warning", "stage": "1/8 Back up", "message": "Slow", "status": "warning"},
            {"id": 6, "kind": "operation_completed", "stage": "Complete", "message": "Done", "status": "succeeded"},
        ]
        roles = [operation_event_role(event) for event in events]
        self.assertEqual(roles, ["info", "stage", "info", "info", "warning", "terminal"])
        live = operation_timeline(events)
        self.assertEqual([row["_timeline_role"] for row in live], roles)
        # Only a real running stage can be active; informational rows never spin.
        self.assertEqual([row["id"] for row in live if row["_timeline_active"]], [2])
        self.assertFalse(any(row["_timeline_active"] for row in operation_timeline(events, terminal=True)))

    def test_progress_bridge_persists_numbered_stages_markers_and_drops_preview_only_states(self):
        operation_id = "d" * 32
        self.state.create_operation(operation_id, kind="update", service_key="container/" + "a" * 64,
                                    service="sonarr", stack="media", requested_by="admin", summary={})
        self.state.set_operation_running(operation_id, "Preparing update")
        reporter = self.agent._operation_progress_reporter(operation_id, "update", "Preparing update")
        reporter.stage(1, 3, "First", service="sonarr")
        reporter.stage(2, 3, "Second", state="running", service="sonarr")
        reporter.stage(3, 3, "Preview only", state="pending", service="sonarr")
        reporter.note("Recovering once", service="sonarr")
        reporter.stage(2, 3, "Second", service="sonarr")
        events = self.state.operation_status(operation_id)["events"]
        self.assertEqual([(e["kind"], e["stage"], e["status"]) for e in events[1:]], [
            ("task_completed", "1/3 First", "completed"), ("task_started", "2/3 Second", "running"),
            ("task_info", "Recovering once", "info"), ("task_completed", "2/3 Second", "completed")])
        self.assertEqual(operation_event_role(events[3]), "info")
        # The unnumbered marker neither completes nor repeats a numbered stage.
        self.state.finish_operation(operation_id, "succeeded", message="Done", result={})
        final = self.state.operation_status(operation_id)["events"]
        self.assertEqual(assert_stage_model(self, final, 3), [1, 2])

    def test_unverifiable_concurrent_pin_recovery_has_explicit_safe_copy(self):
        message = self.agent._safe_operation_error(
            RuntimeError("pinned update failed; Compose pin restoration could not be verified")
        )
        self.assertIn("preserved the changed file", message)
        self.assertIn("did not attempt another recreation", message)
        self.assertIn("UPT backup", message)

    def test_failed_recovery_recreate_has_curated_manual_recovery_copy(self):
        message = self.agent._safe_operation_error(RecoveryFailed("private compose failure detail"))
        self.assertIn("Automatic recovery was attempted", message)
        self.assertIn("manual recovery is required", message)
        self.assertNotIn("private compose failure detail", message)

    def test_review_intent_survives_unchanged_later_global_scan(self):
        payload = self.payload()
        intent = payload["confirmation_id"]
        self.assertRegex(intent, r"^[A-Za-z0-9_-]{43}$")
        self.save_snapshot(self.service, "UPDATE")
        self.assertEqual(self.agent._intent_candidate(self.agent._update_intents[intent])["container_id"], self.service.container_id)
        self.assertEqual(self.state.operation_status("f" * 32), None)

    def test_review_intent_refuses_changed_target_between_render_and_token_creation(self):
        rendered = self.agent.verification_snapshot()["records"][0]
        self.state.save_verification({"service": _public_service(self.service), "status": "UPDATE",
                                      "remote_digest": "sha256:" + "4" * 64, "remote_version": "4.0.17"})
        with self.assertRaisesRegex(ReviewedTargetChanged, "while its review page was being prepared"):
            self.agent.update_review({"service_key": f"container/{self.service.container_id}",
                                      "requested_by": "admin",
                                      "verification_id": rendered["verification_id"]})

    def test_tampered_review_reference_cannot_authorize_another_target(self):
        payload = self.payload(confirmation_id="A" * 43)
        with self.assertRaisesRegex(ValueError, "invalid or expired update review"):
            self.agent.start_update(payload)
        self.assertEqual(self.state.history(), [])

    @patch("docker_update_manager.webservice.scan_service_with_tracking",
           return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "4" * 64,
                                        remote_version="4.0.17", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_reviewed_target_a_fresh_target_b_fails_before_core_or_docker_mutation(self, do_update, discover, run, _scan):
        run.side_effect = self.compose_run
        discover.return_value = [self.service]
        payload = self.payload()
        started = self.agent.start_update(payload)
        operation = self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"], "blocked")
        self.assertIn("reviewed image target changed", operation["error"].lower())
        self.assertEqual(operation["result"], {"blocked_reason": "target_changed", "mutation_performed": False})
        do_update.assert_not_called()
        self.assertFalse(any(any(command in call.args[0] for command in ("pull", "up", "create", "rm"))
                             for call in run.call_args_list))

    @patch("docker_update_manager.webservice.scan_service_with_tracking",
           return_value=SimpleNamespace(status="PINNED UPDATE", remote_digest="sha256:" + "4" * 64,
                                        remote_version="4.0.17", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_digest_pinned_reviewed_target_b_fails_before_source_edit(self, do_update, discover, run, _scan):
        original = "services:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:stable@sha256:" + "2" * 64 + "\n"
        self.compose.write_text(original)
        pinned = self.make_service(image="lscr.io/linuxserver/sonarr:stable@sha256:" + "2" * 64,
                                   digest="sha256:" + "2" * 64)
        self.service = pinned
        self.save_snapshot(pinned, "PINNED UPDATE")
        run.side_effect = self.compose_run
        discover.return_value = [pinned]
        payload = self.payload()
        started = self.agent.start_update(payload)
        operation = self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"], "blocked")
        self.assertIn("reviewed image target changed", operation["error"].lower())
        do_update.assert_not_called()
        self.assertEqual(self.compose.read_text(), original)
        self.assertFalse(any(any(command in call.args[0] for command in ("pull", "up", "create", "rm"))
                             for call in run.call_args_list))

    @patch("docker_update_manager.webservice.scan_service_with_tracking",
           return_value=SimpleNamespace(status="PINNED UPDATE", remote_digest="sha256:" + "3" * 64,
                                        remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_pinned_update_read_only_source_fails_before_pull_with_safe_diagnostic(self, do_update, discover, run, _scan):
        original="services:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:stable@sha256:"+"2"*64+"\n"
        self.compose.write_text(original)
        pinned=self.make_service(image="lscr.io/linuxserver/sonarr:stable@sha256:"+"2"*64,
                                 digest="sha256:"+"2"*64)
        self.service=pinned; self.save_snapshot(pinned,"PINNED UPDATE")
        discover.return_value=[pinned]; run.side_effect=self.compose_run
        attempted=[]
        def core_update(_service,_state,**kwargs):
            kwargs["pre_source_write_check"](self.compose)
            attempted.append("pull")
        do_update.side_effect=core_update
        with patch("docker_update_manager.webservice.verify_atomic_replace_access",
                   side_effect=ComposeSourceNotWritable(errno.EROFS)) as probe, \
             self.assertLogs("docker_update_manager.webservice",level="ERROR") as captured:
            started=self.agent.start_update(self.payload())
            operation=self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"],"failed")
        self.assertIn("UPT cannot modify this service's Compose source from the agent sandbox",operation["error"])
        self.assertEqual(attempted,[])
        self.assertEqual(self.compose.read_text(),original)
        probe.assert_called_once_with([self.compose])
        self.assertFalse(any(any(command in call.args[0] for command in ("pull","up","create","rm"))
                             for call in run.call_args_list))
        log="\n".join(captured.output)
        self.assertIn("operation=update",log); self.assertIn("stack=media",log)
        self.assertIn("service=sonarr",log); self.assertIn("category=compose_source_not_writable",log)
        self.assertIn("errno=EROFS",log)
        self.assertNotIn(str(self.compose),log); self.assertNotIn(original,log)

    @patch("docker_update_manager.webservice.scan_service_with_tracking",
           return_value=SimpleNamespace(status="PINNED UPDATE", remote_digest="sha256:" + "3" * 64,
                                        remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_pinned_update_with_authorised_source_directory_passes_preflight(self, do_update, discover, run, _scan):
        self.compose.write_text("services:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:stable@sha256:"+"2"*64+"\n")
        pinned=self.make_service(image="lscr.io/linuxserver/sonarr:stable@sha256:"+"2"*64,
                                 digest="sha256:"+"2"*64)
        self.service=pinned; self.save_snapshot(pinned,"PINNED UPDATE")
        discover.return_value=[pinned]; run.side_effect=self.compose_run
        sequence=[]
        def core_update(_service,_state,**kwargs):
            kwargs["pre_source_write_check"](self.compose)
            sequence.append("source-write-capability-verified")
            kwargs["pre_pull_check"]()
            sequence.append("pull-may-start")
            return {"updated":True,"image":pinned.image,"version":"4.0.16","digest":"sha256:"+"3"*64}
        do_update.side_effect=core_update
        started=self.agent.start_update(self.payload())
        operation=self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"],"succeeded",operation.get("error"))
        self.assertEqual(sequence,["source-write-capability-verified","pull-may-start"])
        self.assertEqual(self.compose.read_text(),"services:\n  sonarr:\n    image: lscr.io/linuxserver/sonarr:stable@sha256:"+"2"*64+"\n")

    def test_local_pull_digest_mismatch_fails_closed(self):
        from docker_update_manager.webservice import UpdateReviewIntent
        intent = UpdateReviewIntent("scan", self.payload()["confirmation_id"], "admin",
                                    ("UPDATE", "sha256:" + "3" * 64, "4.0.16", None, None), (), time.monotonic() + 30)
        with patch("docker_update_manager.webservice.run", return_value=json.dumps([
                "lscr.io/linuxserver/sonarr@sha256:" + "4" * 64])):
            with self.assertRaisesRegex(ReviewedTargetChanged, "not be proven"):
                self.agent._verify_local_target(intent, "lscr.io/linuxserver/sonarr:latest")

    def test_compose_recovery_identity_accepts_unchanged_server_trusted_model(self):
        pinned = self.make_service(image="lscr.io/linuxserver/sonarr:latest@sha256:" + "2" * 64,
                                   digest="sha256:" + "2" * 64)
        baseline = {"name": "media", "services": {"sonarr": {"image": pinned.image},
                                                        "redis": {"image": "redis:7"}}}
        with patch.object(self.agent, "_compose_config_model", return_value=baseline), \
             patch.object(self.agent, "_compose_service_hash", return_value="a" * 64) as current_hash:
            self.agent._verify_compose_recovery_model(pinned, "a" * 64, baseline)
        current_hash.assert_called_once_with(pinned)

    def _run_web_recovery_identity_case(self, recovery_model):
        pinned = self.make_service(image="lscr.io/linuxserver/sonarr:latest@sha256:" + "2" * 64,
                                   digest="sha256:" + "2" * 64)
        self.service = pinned
        self.save_snapshot(pinned, "PINNED UPDATE")
        baseline = {"name": "media", "services": {"sonarr": {"image": pinned.image},
                                                        "redis": {"image": "redis:7"}}}
        # Review preflight and worker revalidation each read the model once.
        models = iter((baseline, baseline, recovery_model))
        mutations = []
        format_calls = 0

        def compose_run(args, **_kwargs):
            nonlocal format_calls
            if "--hash" in args:
                return f"sonarr {'a' * 64}\n"
            if "--format" in args:
                format_calls += 1
                if format_calls > 2 and isinstance(recovery_model, Exception):
                    raise recovery_model
                return json.dumps(next(models))
            mutations.append(args)
            return ""

        def core_update(_service, _state, **kwargs):
            kwargs["mutation_started"]("pull")
            kwargs["pre_recovery_check"]()
            mutations.append(["compose", "up", "-d", "--no-deps", "sonarr"])
            return {"updated": True, "image": pinned.image, "version": pinned.version}

        with patch("docker_update_manager.webservice.scan_service_with_tracking",
                   return_value=SimpleNamespace(status="PINNED UPDATE", remote_digest="sha256:" + "3" * 64,
                                                remote_version="4.0.16", remote_created=None)), \
             patch("docker_update_manager.webservice.run", side_effect=compose_run) as run, \
             patch("docker_update_manager.webservice.discover", return_value=[pinned]), \
             patch("docker_update_manager.webservice.do_update", side_effect=core_update):
            started = self.agent.start_update(self.payload())
            operation = self.wait_for_terminal(started["operation_id"])

        self.assertFalse(any(any(action in call.args[0] for action in ("pull", "up", "create", "rm"))
                             for call in run.call_args_list))
        self.assertEqual(mutations, [])
        return operation

    def test_web_automatic_recovery_refuses_unrelated_compose_drift(self):
        drifted = {"name": "media", "services": {
            "sonarr": {"image": "lscr.io/linuxserver/sonarr:latest@sha256:" + "2" * 64},
            "redis": {"image": "redis:8"}}}
        operation = self._run_web_recovery_identity_case(drifted)
        self.assertEqual(operation["status"], "failed")
        self.assertIn("Compose configuration changed or could not be verified", operation["error"])
        self.assertIn("manual recovery is required", operation["error"])
        recovery_events = [item for item in self.state.audit_events(10)
                           if item["result"] == "manual recovery required"]
        self.assertEqual(len(recovery_events), 1)
        self.assertEqual(recovery_events[0]["details"]["error"], operation["error"])
        self.assertTrue(recovery_events[0]["details"]["recovery_required"])

    def test_web_automatic_recovery_refuses_unverifiable_compose_model(self):
        operation = self._run_web_recovery_identity_case(RuntimeError("private compose output"))
        self.assertEqual(operation["status"], "failed")
        self.assertIn("manual recovery is required", operation["error"])
        self.assertNotIn("private compose output", operation["error"])

    @patch("docker_update_manager.webservice.scan_service_with_tracking",
           return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64,
                                        remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update", side_effect=RecoveryFailed("private recovery command output"))
    def test_failed_recovery_recreate_is_manual_in_operation_and_audit(self, do_update, discover, run, _scan):
        run.side_effect = self.compose_run
        discover.return_value = [self.service]
        audit_entered = threading.Event()
        release_audit = threading.Event()
        original_audit = self.state.audit

        def delayed_audit(*args, **kwargs):
            if len(args) > 1 and args[0] == "web_update" and args[1] == "manual recovery required":
                audit_entered.set()
                release_audit.wait(3)
            return original_audit(*args, **kwargs)

        with patch.object(self.state, "audit", side_effect=delayed_audit):
            started = self.agent.start_update(self.payload())
            self.assertTrue(audit_entered.wait(3), "manual-recovery audit should be reached before terminal state")
            try:
                self.assertEqual(self.state.operation_status(started["operation_id"])["status"], "running")
            finally:
                release_audit.set()
        operation = self.wait_for_terminal(started["operation_id"])

        self.assertEqual(operation["status"], "failed")
        self.assertIn("Automatic recovery was attempted but did not complete", operation["error"])
        self.assertIn("manual recovery is required", operation["error"])
        self.assertNotIn("private recovery command output", operation["error"])
        audit = [event for event in self.state.audit_events(10)
                 if event["action"] == "web_update" and event["result"] == "manual recovery required"]
        self.assertEqual(len(audit), 1)
        self.assertTrue(audit[0]["details"]["recovery_required"])
        self.assertEqual(audit[0]["details"]["error"], operation["error"])
        do_update.assert_called_once()

    def test_digest_confirmation_target_comes_from_trusted_tracking_resolution(self):
        pinned = self.make_service(image="registry.example/sonarr@sha256:" + "1" * 64)
        history = SimpleNamespace(history_for_service=lambda *_args: [{
            "new_image": pinned.image,
            "old_image": "registry.example/sonarr:stable",
        }])
        result = ScanResult(pinned, "PINNED UPDATE", remote_digest="sha256:" + "2" * 64)

        public = _public_result(result, history)
        untracked = _public_result(result, SimpleNamespace(history_for_service=lambda *_args: []))

        self.assertEqual(public["target_image"], "registry.example/sonarr:stable@sha256:" + "2" * 64)
        self.assertEqual(public["tracking_tag"], "stable")
        self.assertNotIn("target_image", untracked, "UPT must not guess an untracked digest pin's repository/channel")
        self.assertNotIn("tracking_tag", untracked, "untracked digest pins must not gain a display-only guessed channel")

    def test_tracking_label_parse_failure_cannot_suppress_resolved_update_target(self):
        pinned = self.make_service(image="registry.example/sonarr@sha256:" + "1" * 64)
        history = SimpleNamespace(history_for_service=lambda *_args: [{
            "new_image": pinned.image,
            "old_image": "registry.example/sonarr:stable",
        }])
        result = ScanResult(pinned, "PINNED UPDATE", remote_digest="sha256:" + "2" * 64)
        with patch("docker_update_manager.webservice.parse_image_ref", side_effect=[
            parse_image_ref(pinned.image), ValueError("display-only parsing failed"),
        ]):
            public = _public_result(result, history)

        self.assertEqual(public["status"], "PINNED UPDATE")
        self.assertEqual(public["target_image"], "registry.example/sonarr:stable@sha256:" + "2" * 64)
        self.assertNotIn("tracking_tag", public)

    def test_display_tag_fallback_never_enters_update_target_or_status(self):
        service = self.make_service(image="lscr.io/linuxserver/sonarr:v4.0.15", version=None)
        digest = "sha256:" + "3" * 64
        result = ScanResult(service, "UPDATE", remote_digest=digest)
        shown = display_version(service.version, service.image)
        target = self.agent._review_target(result, service)

        self.assertEqual((shown.value, shown.source), ("v4.0.15", "tag"))
        self.assertEqual(target, ("UPDATE", digest, None, None, None))
        self.assertEqual(result.status, "UPDATE")
        self.assertIsNone(result.as_dict()["service"]["version"])
        self.assertNotIn(shown.value, target)

    def test_mutation_schema_rejects_browser_supplied_execution_details(self):
        payload = self.payload(service_key="container/other", image="evil/image:latest",
                               compose_file="/tmp/other.yml", project_name="other")
        with self.assertRaisesRegex(ValueError, "invalid operation request"):
            self.agent.start_update(payload)
        self.assertEqual(self.state.history(), [])

    def test_server_side_snapshot_status_must_be_update_eligible(self):
        payload = self.payload()
        self.save_snapshot(self.service, "CURRENT")
        with self.assertRaisesRegex(ReviewedTargetChanged, "changed"):
            self.agent.start_update(payload)
        self.assertEqual(self.state.history(), [])

    def test_standalone_or_local_build_is_not_eligible(self):
        standalone = self.make_service(stack=None, compose_service=None, working_dir=None, compose_files=[])
        self.service = standalone
        self.save_snapshot(standalone, "UPDATE")
        with self.assertRaisesRegex(ValueError, "eligible running Compose"):
            self.agent.update_review({"service_key": f"container/{standalone.container_id}", "requested_by": "admin",
                                      "verification_id": self.agent.verification_snapshot()["records"][0]["verification_id"]})

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64, remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_web_update_revalidates_and_invokes_only_existing_core_operation(self, do_update, discover, _run, scan):
        _run.side_effect = self.compose_run
        discover.return_value = [self.service]

        def core_update(service, state, **kwargs):
            self.assertIs(service, self.service)
            self.assertIs(state, self.state)
            self.assertTrue(kwargs["yes"])
            self.assertEqual(kwargs["audit_context"]["origin"], "web")
            self.assertEqual(kwargs["project_name"], "media")
            self.assertFalse(kwargs["output"] is print)
            self.assertTrue(callable(kwargs["pre_recovery_check"]))
            return {"updated": True, "history_id": 17, "image": service.image,
                    "version": "4.0.16", "digest": "sha256:" + "3" * 64, "health": "healthy"}

        def core_update_with_guards(service, state, **kwargs):
            kwargs["pre_pull_check"]()
            kwargs["pre_recreate_check"]()
            return core_update(service, state, **kwargs)
        do_update.side_effect = core_update_with_guards
        with patch.object(self.state, "record", return_value=17):
            review_payload = self.payload()
            started = self.agent.start_update(review_payload)
            operation = self.wait_for_terminal(started["operation_id"])

        self.assertEqual(operation["status"], "succeeded")
        self.assertEqual(operation["result"]["version"], "4.0.16")
        self.assertEqual(discover.call_count, 6)
        self.assertTrue(all(call.args == (self.config,) for call in discover.call_args_list))
        scan.assert_called_once_with(self.service, self.state)
        do_update.assert_called_once()
        audit = self.state.audit_events(10)
        self.assertEqual({event["result"] for event in audit}, {"requested", "success"})
        self.assertTrue(all(event["details"]["origin"] == "web" for event in audit))
        with self.assertRaisesRegex(ValueError, "invalid or expired update review"):
            self.agent.start_update(review_payload)

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64, remote_version="4.0.16", remote_created=None, error=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_web_update_events_have_one_completed_row_per_stage_and_no_lingering_running_step(self, do_update, discover, _run, _scan):
        _run.side_effect = self.compose_run
        discover.return_value = [self.service]

        def core_update(service, state, **kwargs):
            for number, label in enumerate(("Record current state", "Backup configuration", "Check remote image",
                                            "Verify architecture", "Pull image", "Recreate container"), 1):
                kwargs["reporter"].stage(number, 8, label, service=service.key)
            kwargs["reporter"].stage(7, 8, "Verify startup and health", state="running", service=service.key)
            kwargs["reporter"].stage(7, 8, "Verify startup and health", service=service.key)
            kwargs["reporter"].stage(8, 8, "Record update", service=service.key)
            return {"updated": True, "history_id": 17, "image": service.image,
                    "version": "4.0.16", "digest": "sha256:" + "3" * 64, "health": "healthy"}
        do_update.side_effect = core_update
        with patch.object(self.state, "record", return_value=17):
            started = self.agent.start_update(self.payload())
            operation = self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"], "succeeded", operation.get("error"))
        events = operation["events"]
        self.assertEqual(assert_stage_model(self, events, 8), list(range(1, 9)))
        # The preliminary revalidation row is opened and closed under one stage key.
        revalidation = [(e["kind"], e["status"]) for e in events if e["stage"] == "Revalidating service eligibility"]
        self.assertEqual(revalidation, [("task_started", "running"), ("task_completed", "completed")])
        # Reloaded before the terminal event, no step is left spinning once its stage completed.
        active = [row["stage"] for row in operation_timeline(events[:-1]) if row["_timeline_active"]]
        self.assertEqual(active, [])

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="CURRENT", remote_digest=None, remote_version=None, remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_registry_update_disappearing_during_revalidation_never_deploys(self, do_update, discover, _run, _scan):
        _run.side_effect = self.compose_run
        discover.return_value = [self.service]
        started = self.agent.start_update(self.payload())
        operation = self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"], "blocked")
        self.assertIn("no longer available", operation["error"])
        do_update.assert_not_called()

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64, remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_changed_compose_image_fails_closed(self, do_update, discover, _run, _scan):
        drifted = lambda args, **kwargs: (
            f"sonarr {'a' * 64}\n" if "--hash" in args else
            json.dumps({"name": "media", "services": {"sonarr": {"image": "another/image:tag"}}})
        )
        discover.return_value = [self.service]
        _run.side_effect = drifted
        with self.assertRaises(ComposePreflightRefused) as refused:
            self.payload()
        self.assertEqual((refused.exception.status, refused.exception.reason), ("drifted", "image_differs"))
        _run.side_effect = self.compose_run
        payload = self.payload()
        _run.side_effect = drifted
        started = self.agent.start_update(payload)
        operation = self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"], "blocked")
        self.assertIn("Compose configuration changed after review", operation["error"])
        do_update.assert_not_called()

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64, remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_changed_non_image_compose_config_fails_before_core_or_docker_mutation(self, do_update, discover, run, _scan):
        discover.return_value = [self.service]
        drifted = lambda args, **kwargs: (
            f"sonarr {'b' * 64}\n" if "--hash" in args else
            json.dumps({"name": "media", "services": {"sonarr": {"image": self.service.image, "ports": ["9999:80"]}}})
        )
        run.side_effect = self.compose_run
        payload = self.payload()
        run.side_effect = drifted

        started = self.agent.start_update(payload)
        operation = self.wait_for_terminal(started["operation_id"])

        self.assertEqual(operation["status"], "blocked")
        self.assertIn("Compose configuration changed after review", operation["error"])
        self.assertNotIn("recovery", operation["error"].lower())
        do_update.assert_not_called()
        self.assertFalse(any(any(command in call.args[0] for command in ("pull", "up", "create", "rm"))
                             for call in run.call_args_list))

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64, remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_unrelated_service_change_does_not_invalidate_selected_execution_context(self, do_update, discover, run, _scan):
        discover.return_value = [self.service]
        models = iter((
            {"name": "media", "services": {"sonarr": {"image": self.service.image}, "redis": {"image": "redis:7"}}},
            {"name": "media", "services": {"sonarr": {"image": self.service.image}, "redis": {"image": "redis:7"}}},
            {"name": "media", "services": {"sonarr": {"image": self.service.image}, "redis": {"image": "redis:8"}}},
        ))
        run.side_effect = lambda args, **kwargs: (
            f"sonarr {'a' * 64}\n" if "--hash" in args else json.dumps(next(models))
        )
        do_update.side_effect = lambda _service, _state, **kwargs: kwargs["pre_pull_check"]()

        started = self.agent.start_update(self.payload())
        operation = self.wait_for_terminal(started["operation_id"])

        self.assertEqual(operation["status"], "succeeded")
        do_update.assert_called_once()
        self.assertFalse(any(any(command in call.args[0] for command in ("pull", "up", "create", "rm"))
                             for call in run.call_args_list))

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64, remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_hash_excluded_build_pull_scale_and_profile_fields_are_refused(self, do_update, discover, run, _scan):
        discover.return_value = [self.service]
        models = iter((
            {"build": {"context": "."}},
            {"deploy": {"replicas": 2}},
            {"pull_policy": "always"},
            {"profiles": ["experimental"]},
        ))
        for extra in models:
            excluded = lambda args, extra=extra, **kwargs: (
                f"sonarr {'a' * 64}\n" if "--hash" in args else
                json.dumps({"name": "media", "services": {"sonarr": {"image": self.service.image, **extra}}})
            )
            run.side_effect = excluded
            with self.assertRaises(ComposePreflightRefused) as refused:
                self.payload()
            self.assertEqual(refused.exception.reason, "hash_excluded_fields")
            run.side_effect = self.compose_run
            payload = self.payload()
            run.side_effect = excluded
            started = self.agent.start_update(payload)
            operation = self.wait_for_terminal(started["operation_id"])
            self.assertEqual(operation["status"], "blocked")
            self.assertIn("cannot verify", operation["error"])
        do_update.assert_not_called()

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64, remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_missing_or_ambiguous_compose_runtime_identity_fails_closed(self, do_update, discover, run, _scan):
        discover.return_value = [self.service]
        run.side_effect = self.compose_run
        payload = self.payload()
        self.service.labels = {}
        with self.assertRaises(ComposePreflightRefused) as refused:
            self.payload()
        self.assertEqual(refused.exception.reason, "runtime_hash_missing")
        started = self.agent.start_update(payload)
        operation = self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"], "blocked")
        self.assertIn("could not verify", operation["error"])
        do_update.assert_not_called()

        self.service.labels = {"com.docker.compose.config-hash": "a" * 64, "com.docker.compose.project": "media"}
        discover.reset_mock()
        discover.return_value = [self.service]
        run.reset_mock()
        run.side_effect = self.compose_run
        payload = self.payload()
        run.side_effect = lambda args, **kwargs: (
            f"sonarr {'a' * 64}\nsonarr {'a' * 64}\n" if "--hash" in args else
            json.dumps({"name": "media", "services": {"sonarr": {"image": self.service.image}}})
        )
        with self.assertRaises(ComposePreflightRefused) as refused:
            self.payload()
        self.assertEqual(refused.exception.reason, "compose_hash_unavailable")
        started = self.agent.start_update(payload)
        operation = self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"], "blocked")
        do_update.assert_not_called()

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64, remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run")
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update")
    def test_compose_drift_rechecked_immediately_before_recreate(self, do_update, discover, run, _scan):
        discover.return_value = [self.service]
        hashes = iter(["a" * 64, "a" * 64, "a" * 64, "b" * 64])
        run.side_effect = lambda args, **kwargs: (
            f"sonarr {next(hashes)}\n" if "--hash" in args else
            json.dumps({"name": "media", "services": {"sonarr": {"image": self.service.image}}})
        )

        def simulated_core(_service, _state, **kwargs):
            kwargs["pre_pull_check"]()
            kwargs["mutation_started"]("pull")  # the reviewed image is pulled here
            kwargs["pre_recreate_check"]()

        do_update.side_effect = simulated_core
        started = self.agent.start_update(self.payload())
        operation = self.wait_for_terminal(started["operation_id"])
        # A pull already happened, so this is not a no-side-effect refusal.
        self.assertEqual(operation["status"], "failed")
        self.assertIn("Pending or unverified Compose changes", operation["error"])
        do_update.assert_called_once()

    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.ReadOnlyService._compose_config_model")
    def test_digest_pin_model_allows_only_selected_image_reference_change(self, compose_model, discover):
        discover.return_value = [self.service]
        baseline = {
            "name": "media",
            "services": {
                "sonarr": {"image": self.service.image, "ports": ["8989:8989"], "environment": {"TZ": "UTC"}},
                "redis": {"image": "redis:7", "ports": ["6379:6379"]},
            },
            "volumes": {"config": {"name": "sonarr_config"}},
        }
        target = "lscr.io/linuxserver/sonarr:latest@sha256:" + "3" * 64
        expected = json.loads(json.dumps(baseline))
        expected["services"]["sonarr"]["image"] = target
        compose_model.return_value = expected

        self.agent._revalidate_compose_pin_model(f"container/{self.service.container_id}", self.service, baseline, target)

        changed_port = json.loads(json.dumps(expected))
        changed_port["services"]["sonarr"]["ports"] = ["9999:8989"]
        compose_model.return_value = changed_port
        with self.assertRaisesRegex(ValueError, "Pending or unverified Compose changes"):
            self.agent._revalidate_compose_pin_model(f"container/{self.service.container_id}", self.service, baseline, target)

        changed_other_service = json.loads(json.dumps(expected))
        changed_other_service["services"]["redis"]["image"] = "redis:8"
        compose_model.return_value = changed_other_service
        self.agent._revalidate_compose_pin_model(f"container/{self.service.container_id}", self.service, baseline, target)

    @patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=SimpleNamespace(status="PINNED UPDATE", remote_digest="sha256:" + "3" * 64, remote_version="4.0.16", remote_created=None))
    @patch("docker_update_manager.webservice.run", return_value=json.dumps({"name": "media", "services": {"sonarr": {"image": "lscr.io/linuxserver/sonarr:latest"}}}))
    @patch("docker_update_manager.webservice.discover")
    @patch("docker_update_manager.webservice.do_update", return_value={"updated": False, "image": "repo@sha256:abc"})
    def test_digest_race_noop_is_reported_as_unchanged_not_updated(self, do_update, discover, _run, _scan):
        self.service = self.make_service(image="lscr.io/linuxserver/sonarr:stable@sha256:" + "2" * 64,
                                         digest="sha256:" + "2" * 64)
        self.save_snapshot(self.service, "PINNED UPDATE")
        _run.side_effect = self.compose_run
        discover.return_value = [self.service]
        started = self.agent.start_update(self.payload())
        operation = self.wait_for_terminal(started["operation_id"])
        self.assertEqual(operation["status"], "succeeded")
        self.assertIs(operation["result"]["updated"], False)
        self.assertIn("no update was needed", operation["events"][-1]["message"])
        audit = self.state.audit_events(10)
        self.assertIn("unchanged", {event["result"] for event in audit})

    def test_concurrent_web_operation_claim_is_rejected(self):
        operation_id = "d" * 32
        self.state.create_operation(operation_id, kind="update", service_key="container/old",
                                    service="old", stack="media", requested_by="admin", summary={})
        with self.assertRaisesRegex(RuntimeError, "another web operation"):
            self.agent.start_update(self.payload())

    def test_agent_socket_mutation_requires_configured_web_uid(self):
        class Probe:
            def __init__(self): self.calls = []
            def handle(self, operation, payload):
                self.calls.append((operation, payload))
                return {"ok": True}

        probe = Probe()
        server = AgentServer(probe, "/tmp/unused.sock", allowed_mutation_uid=1234)
        request = json.dumps({"operation": "operation_status", "payload": {"operation_id": "a" * 32, "after_event_id": 0}}).encode() + b"\n"
        denied = json.loads(server.handle_line(request, peer_uid=4321))
        self.assertFalse(denied["ok"])
        self.assertEqual(probe.calls, [])
        allowed = json.loads(server.handle_line(request, peer_uid=1234))
        self.assertTrue(allowed["ok"])
        self.assertEqual(len(probe.calls), 1)
        mutation = json.dumps({"operation": "rollback_start", "payload": {"confirmation_id": "B" * 43, "_upt_client_version": __version__}, "client_version": __version__}).encode() + b"\n"
        denied_mutation = json.loads(server.handle_line(mutation, peer_uid=4321))
        self.assertFalse(denied_mutation["ok"])
        self.assertEqual(len(probe.calls), 1, "rollback cannot cross the agent boundary from an untrusted peer UID")
        allowed_mutation = json.loads(server.handle_line(mutation, peer_uid=1234))
        self.assertTrue(allowed_mutation["ok"])
        self.assertEqual(probe.calls[-1][0], "rollback_start")

    def test_agent_client_allows_only_fixed_operation_ids(self):
        from docker_update_manager.webservice import AGENT_OPERATIONS, MUTATION_OPERATIONS, READ_ONLY_OPERATIONS
        self.assertIn("update_start", AGENT_OPERATIONS)
        self.assertIn("update_review", MUTATION_OPERATIONS)
        self.assertNotIn("update_review", READ_ONLY_OPERATIONS)
        self.assertIn("rollback_start", AGENT_OPERATIONS)
        self.assertIn("rollback_review", MUTATION_OPERATIONS)
        self.assertIn("rollback_start", MUTATION_OPERATIONS)
        self.assertNotIn("rollback_start", READ_ONLY_OPERATIONS)
        self.assertIn("operation_status", AGENT_OPERATIONS)
        self.assertNotIn("update_start", READ_ONLY_OPERATIONS)
        with self.assertRaises(PermissionError):
            AgentClient("/tmp/nonexistent.sock").call("docker_exec", {"command": "id"})


class WebOperationRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.state = WebState(root / "web-state")
        self.user_id = self.state.create_user("admin", "not-used")
        self.csrf = new_token()
        self.sid = self.state.create_session(self.user_id, self.csrf,
                                             (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
                                             (datetime.now(timezone.utc) + timedelta(days=30)).isoformat())
        self.agent = RouteFixtureAgent()
        config = WebConfig(path=str(root / "web.yml"))
        self.client = TestClient(create_app(config, self.state, self.agent))
        self.client.cookies.set("upt_session", self.sid)

    def test_post_requires_auth_csrf_confirmation_and_exact_form_fields(self):
        anonymous = TestClient(self.client.app)
        denied = anonymous.post("/operations/update", data={"csrf": self.csrf, "confirmation_id": RouteFixtureAgent.REVIEW_ID, "confirm_update": "yes"}, follow_redirects=False)
        self.assertEqual(denied.status_code, 303)
        bad_csrf = self.client.post("/operations/update", data={"csrf": "wrong", "confirmation_id": RouteFixtureAgent.REVIEW_ID, "confirm_update": "yes"})
        self.assertEqual(bad_csrf.status_code, 403)
        no_confirmation = self.client.post("/operations/update", data={"csrf": self.csrf, "confirmation_id": RouteFixtureAgent.REVIEW_ID})
        self.assertEqual(no_confirmation.status_code, 400)
        extra_field = self.client.post("/operations/update", data={"csrf": self.csrf, "confirmation_id": RouteFixtureAgent.REVIEW_ID, "confirm_update": "yes", "image": "evil"})
        self.assertEqual(extra_field.status_code, 400)
        self.assertEqual(self.agent.update_calls, [])

    def test_service_refresh_requires_auth_csrf_and_accepts_no_target_fields(self):
        key = "container/" + "a" * 64
        path = "/services/" + key + "/refresh"
        anonymous = TestClient(self.client.app)
        self.assertEqual(anonymous.post(path, data={"csrf": self.csrf}).status_code, 401)
        self.assertEqual(self.client.post(path, data={"csrf": "wrong"}).status_code, 403)
        self.assertEqual(self.client.post(path, data={"csrf": self.csrf, "image": "evil:latest"}).status_code, 403)
        response = self.client.post(path, data={"csrf": self.csrf})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(self.agent.refresh_calls, [key])
        self.assertEqual(self.client.get("/api/services/" + key + "/refresh").json()["status"], "checking")
        self.assertEqual(anonymous.get("/api/services/" + key + "/refresh").status_code, 401)

    def test_confirmed_post_sends_only_server_context_and_redirects_to_persisted_operation(self):
        response = self.client.post("/operations/update", data={"csrf": self.csrf, "confirmation_id": RouteFixtureAgent.REVIEW_ID, "confirm_update": "yes"}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/operations/" + RouteFixtureAgent.OPERATION_ID)
        operation = self.agent.update_calls[0]
        self.assertEqual(set(operation), {"confirmation_id", "requested_by", "client_ip", "user_agent"})
        self.assertEqual(operation["confirmation_id"], RouteFixtureAgent.REVIEW_ID)
        self.assertEqual(operation["requested_by"], "admin")

    def test_rollback_post_requires_auth_csrf_confirmation_and_exact_form_fields(self):
        form = {"csrf": self.csrf, "confirmation_id": RouteFixtureAgent.ROLLBACK_REVIEW_ID,
                "confirm_rollback": "yes"}
        anonymous = TestClient(self.client.app)
        denied = anonymous.post("/operations/rollback", data=form, follow_redirects=False)
        self.assertEqual(denied.status_code, 303)
        bad_csrf = self.client.post("/operations/rollback", data={**form, "csrf": "wrong"})
        self.assertEqual(bad_csrf.status_code, 403)
        no_confirmation = self.client.post("/operations/rollback", data={
            "csrf": self.csrf, "confirmation_id": RouteFixtureAgent.ROLLBACK_REVIEW_ID,
        })
        self.assertEqual(no_confirmation.status_code, 400)
        extra_field = self.client.post("/operations/rollback", data={**form, "backup": "/etc/passwd"})
        self.assertEqual(extra_field.status_code, 400)
        self.assertEqual(self.agent.rollback_calls, [])

    def test_rollback_confirmation_submits_only_opaque_review_and_server_context(self):
        response = self.client.post("/operations/rollback", data={
            "csrf": self.csrf, "confirmation_id": RouteFixtureAgent.ROLLBACK_REVIEW_ID,
            "confirm_rollback": "yes",
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/operations/" + RouteFixtureAgent.OPERATION_ID)
        payload = self.agent.rollback_calls[0]
        self.assertEqual(set(payload), {"confirmation_id", "requested_by", "client_ip", "user_agent"})
        self.assertEqual(payload["confirmation_id"], RouteFixtureAgent.ROLLBACK_REVIEW_ID)
        self.assertEqual(payload["requested_by"], "admin")

    def test_operation_page_api_and_sse_are_authenticated_and_reconnectable(self):
        operation_id = RouteFixtureAgent.OPERATION_ID
        page = self.client.get("/operations/" + operation_id)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Backup Compose", page.text)
        self.assertIn('data-cursor="8"', page.text)
        response = self.client.get("/api/operations/" + operation_id + "?after=6")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual([row["id"] for row in response.json()["events"]], [7, 8])
        stream = self.client.get("/operations/" + operation_id + "/events?after=6")
        self.assertIn("id: 7\nevent: operation-event", stream.text)
        self.assertIn("event: operation-complete", stream.text)
        unauthenticated = TestClient(self.client.app).get("/api/operations/" + operation_id)
        self.assertEqual(unauthenticated.status_code, 401)

    def test_operation_stream_closes_after_session_revocation(self):
        self.agent.revoke_session = (self.state, self.sid)
        stream = self.client.get("/operations/" + RouteFixtureAgent.OPERATION_ID + "/events")
        self.assertIn("operation-auth-expired", stream.text)
        self.assertNotIn("operation-complete", stream.text)


class RouteFixtureAgent:
    OPERATION_ID = "e" * 32
    REVIEW_ID = "R" * 43
    ROLLBACK_REVIEW_ID = "B" * 43

    def __init__(self):
        self.update_calls = []
        self.rollback_calls = []
        self.refresh_calls = []
        self.revoke_session = None
        self.events = [
            {"id": 7, "kind": "task_completed", "stage": "2/8 Backup Compose", "message": "Completed", "status": "completed", "payload": {}},
            {"id": 8, "kind": "operation_completed", "stage": "Complete", "message": "Sonarr updated successfully", "status": "succeeded", "payload": {}},
        ]

    def call(self, operation, payload=None):
        payload = payload or {}
        if operation == "update_review":
            return {"confirmation_id": self.REVIEW_ID}
        if operation == "refresh_start":
            self.refresh_calls.append(payload["service_key"])
            return {"status": "checking", "existing": False}
        if operation == "refresh_status":
            return {"status": "checking", "record": None}
        if operation == "update_start":
            self.update_calls.append(payload)
            return {"operation_id": self.OPERATION_ID, "status": "queued", "service": "Sonarr"}
        if operation == "rollback_start":
            self.rollback_calls.append(payload)
            return {"operation_id": self.OPERATION_ID, "status": "queued", "service": "Sonarr"}
        if operation == "operation_status":
            if self.revoke_session:
                state, sid = self.revoke_session
                state.revoke_session(sid)
                self.revoke_session = None
            after = int(payload.get("after_event_id", 0))
            return {"id": self.OPERATION_ID, "kind": "update", "service_key": "container/abc",
                    "service": "Sonarr", "stack": "media", "requested_by": "admin",
                    "status": "succeeded", "created_at": "2026-09-25T10:00:00+00:00",
                    "current_stage": "Complete", "summary": {"old_version": "4.0.15"},
                    "result": {"version": "4.0.16"}, "error": None,
                    "events": [event for event in self.events if event["id"] > after], "last_event_id": 8}
        raise AssertionError(operation)


if __name__ == "__main__":
    unittest.main()
