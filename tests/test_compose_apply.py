"""Phase 2A uses real synthetic source bytes and deterministic fake Docker only."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import json
import os
import sqlite3
import stat
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from docker_update_manager import __version__
from docker_update_manager.compose import ComposeSourceNotWritable
from docker_update_manager.compose_baseline import BaselineStore
from docker_update_manager.compose_reconcile import do_compose_reconcile
from docker_update_manager.lock import Lock
from docker_update_manager.operation_presentation import operation_presentation
from docker_update_manager.state import State
from docker_update_manager.webapp import operation_event_role
from docker_update_manager.webservice import AgentServer, ReadOnlyService, _public_service

from progress_assertions import assert_stage_model
from sqlite_faults import history_insert, sqlite_fault
from test_compose_reconciliation import (BASE_COMPOSE, SECRET, ComposeFixture, FakeCompose, service_hash,
                                         use_named_runtime_network, with_named_network)
import test_compose_reconciliation as phase1_fixtures


class FakeApplyCompose(FakeCompose):
    def __init__(self, fixture):
        super().__init__()
        self.fixture = fixture
        self.local_image_id = fixture.service.image_id
        self.up_calls = []
        self.up_hook = None
        self.config_hook = None
        self.health = "healthy"
        self.mounts = [{"Type": "bind", "Source": "/srv/private/sonarr", "Destination": "/config",
                        "RW": True, "Propagation": "rprivate"}]

    def __call__(self, args, **kwargs):
        args = list(args)
        if "{{json .Mounts}}" in args:
            self.calls.append(args)
            return json.dumps(self.mounts)
        if args[:3] == ["docker", "image", "inspect"]:
            self.calls.append(args)
            assert args[-2] == "{{.Id}}", args
            return self.local_image_id
        if "up" in args:
            self.calls.append(args)
            self.up_calls.append(args)
            assert args[-6:] == ["up", "-d", "--no-deps", "--pull", "never", "sonarr"], args
            assert args[args.index("--project-name") + 1] == "media", args
            model = self.model([str(self.fixture.compose)], str(self.fixture.project), None)
            self.mounts = [{"Type": item["type"], "Source": item.get("source"), "Destination": item.get("target"),
                            "RW": not item.get("read_only", False),
                            "Propagation": (item.get("bind") or {}).get("propagation") or "rprivate"}
                           for item in model["services"]["sonarr"].get("volumes", [])]
            fresh = self.fixture.make_service(service_hash(model["services"]["sonarr"]),
                                               container_id=("c" if len(self.up_calls) == 1 else "e") * 64,
                                               health=self.health if len(self.up_calls) == 1 else "healthy")
            self.fixture.runtime = [item for item in self.fixture.runtime if item.compose_service != "sonarr"] + [fresh]
            if self.up_hook:
                self.up_hook(len(self.up_calls), fresh)
            return ""
        if self.config_hook and "config" in args:
            self.config_hook(args)
        return super().__call__(args, **kwargs)


class ComposeApplyTests(ComposeFixture):
    def setUp(self):
        super().setUp()
        self.fake = FakeApplyCompose(self)
        for module in ("webservice", "compose_reconcile", "compose"):
            mocked = patch(f"docker_update_manager.{module}.run", side_effect=self.fake)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.refresh = patch.object(self.agent, "start_refresh", return_value={"status": "checking"}).start()
        self.addCleanup(patch.stopall)
        self.status()  # Phase 1 proves and captures the running baseline.
        self.original = self.compose.read_bytes()
        self.baseline = self.records()[0]
        self.edit("restart: unless-stopped", "restart: always")
        self.desired = self.compose.read_bytes()

    def review(self, **changes):
        payload = {"service_key": "container/" + "a" * 64, "action": "apply", "requested_by": "admin"}
        payload.update(changes)
        return self.agent.compose_reconcile_review(payload)

    def start(self, reviewed=None, **changes):
        reviewed = reviewed or self.review()
        payload = {"confirmation_id": reviewed["confirmation_id"], "requested_by": "admin",
                   "client_ip": "127.0.0.1", "user_agent": "fixture"}
        payload.update(changes)
        intent = self.agent._compose_intents.get(payload["confirmation_id"])
        with patch("docker_update_manager.webservice.threading.Thread"):
            result = self.agent.start_compose_reconcile(payload)
        return result, payload, intent

    def execute(self, reviewed=None):
        result, payload, intent = self.start(reviewed)
        self.agent._compose_worker(result["operation_id"], payload, intent)
        return self.agent.operation_status({"operation_id": result["operation_id"], "after_event_id": 0})

    def assert_blocked(self, operation):
        self.assertEqual(operation["status"], "blocked")
        self.assertFalse(operation["result"]["mutation_performed"])
        self.assertEqual(self.fake.up_calls, [])
        self.assertEqual(self.state.history()[0]["result"], "BLOCKED")
        self.refresh.assert_not_called()

    def test_apply_success_reports_exactly_eight_real_stages_then_terminal(self):
        operation = self.execute()
        self.assertEqual(operation["status"], "succeeded")
        events = operation["events"]
        self.assertEqual(assert_stage_model(self, events, 8), list(range(1, 9)))
        labels = [event["stage"] for event in events if event["kind"] == "task_completed"]
        self.assertEqual(labels[-1], "8/8 Record result")
        self.assertFalse([label for label in labels if "efresh" in label or label.startswith("9/")])
        # Post-commit refresh is queued once, outside the numbered stages.
        self.refresh.assert_called_once()
        self.assertEqual(events[0]["kind"], "operation_started")
        self.assertEqual(operation_event_role(events[0]), "info")

    def test_project_refresh_dispatched_only_after_durable_success(self):
        result, payload, intent = self.start()
        seen = []
        def queue(service):
            seen.append((self.state.operation_status(result["operation_id"])["status"], service.compose_service))
            return "queued"
        with patch.object(self.agent, "_queue_project_refresh", side_effect=queue):
            self.agent._compose_worker(result["operation_id"], payload, intent)
        self.assertEqual(seen, [("succeeded", "sonarr")])

    def test_slow_project_refresh_never_delays_durable_success(self):
        self.project_refresh_patch.stop()  # exercise the real dispatcher
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def slow(service):
            entered.set()
            release.wait(5)
        with patch.object(self.agent, "_refresh_project_baselines", side_effect=slow):
            started = time.monotonic()
            operation = self.execute()
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(operation["status"], "succeeded")
            self.assertTrue(entered.wait(5))  # proof runs only in the background
            release.set()
            deadline = time.monotonic() + 5
            while self.agent._project_refresh_thread is not None and time.monotonic() < deadline:
                time.sleep(.01)
        self.assertIsNone(self.agent._project_refresh_thread)

    def test_failing_project_dispatch_never_alters_success(self):
        with patch.object(self.agent, "_queue_project_refresh", side_effect=RuntimeError("dispatch failed")):
            operation = self.execute()
        self.assertEqual(operation["status"], "succeeded")
        self.assertEqual(self.state.history()[0]["result"], "SUCCESS")

    def test_blocked_apply_queues_no_project_refresh(self):
        reviewed = self.review()
        self.edit("TZ: Europe/London", "TZ: Europe/Paris")
        with patch.object(self.agent, "_queue_project_refresh") as queue:
            operation = self.execute(reviewed)
        self.assertEqual(operation["status"], "blocked")
        queue.assert_not_called()

    def test_apply_blocked_has_no_record_stage_and_blocked_terminal(self):
        reviewed = self.review()
        self.edit("TZ: Europe/London", "TZ: Europe/Paris")
        operation = self.execute(reviewed)
        self.assert_blocked(operation)
        completed = assert_stage_model(self, operation["events"], 8)
        self.assertNotIn(8, completed)
        self.assertEqual(operation["events"][-1]["kind"], "operation_blocked")

    def test_apply_recovery_is_an_unnumbered_marker_not_a_repeated_stage(self):
        self.fake.health = "unhealthy"
        operation = self.execute()
        self.assertEqual(operation["status"], "failed")
        self.assertTrue(operation["result"]["recovered"])
        events = operation["events"]
        completed = assert_stage_model(self, events, 8)
        self.assertNotIn(8, completed)
        markers = [event for event in events if event["kind"] == "task_info"]
        self.assertEqual([event["stage"] for event in markers], ["Recovering trusted previous configuration once"])
        self.assertEqual(operation_event_role(markers[0]), "info")
        self.assertEqual(events[-1]["kind"], "operation_failed")

    def test_review_is_safe_and_only_exact_existing_baseline_can_authorize(self):
        reviewed = self.review()
        self.assertEqual(set(reviewed), {"confirmation_id", "review"})
        self.assertRegex(reviewed["confirmation_id"], r"^[A-Za-z0-9_-]{43}$")
        text = json.dumps(reviewed)
        for private in (SECRET, str(self.project), self.baseline.id, self.baseline.fingerprint,
                        self.service.image_id, self.service.digest, self.current_hash()):
            self.assertNotIn(private, text)
        self.assertTrue(reviewed["review"]["automatic_recovery"])
        self.assertEqual(self.records()[0].id, self.baseline.id)
        self.assertFalse(BaselineStore(self.state).load(self.baseline).project_trusted)
        self.assertTrue(self.status()["apply_eligible"])

    def test_no_baseline_and_replacement_container_remain_read_only(self):
        self.state.delete_compose_baseline(self.baseline.id)
        with self.assertRaises(ValueError):
            self.review()
        self.assertFalse(self.status()["apply_eligible"])
        self.assertFalse(self.records())
        # Reinsert the original record but move runtime to another container.
        # Review must not reproduce/adopt even a matching-hash old baseline.
        values = {**self.baseline.__dict__, "manifest": json.dumps(self.baseline.manifest)}
        self.state.insert_compose_baseline(values)
        self.runtime = [self.make_service(self.baseline.runtime_hash, container_id="d" * 64)]
        with self.assertRaises(ValueError):
            self.review(service_key="container/" + "d" * 64)
        self.assertEqual(self.records()[0].id, self.baseline.id)
        self.assertFalse(any("--env-file" in args for args in self.fake.calls))

    def test_review_and_start_have_exact_bounded_schemas(self):
        for field in ("source_path", "compose_yaml", "project_name", "image_id", "baseline_id",
                      "model_fingerprint", "command", "recovery_path"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.review(**{field: "operator-controlled"})
        for action in ("revert", "discard", "adopt", "apply_anyway", [], None):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.review(action=action)
        reviewed = self.review()
        for field in ("action", "service_key", "project_name", "source_path", "image_id", "command"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.start(reviewed, **{field: "tampered"})

    def test_confirmation_is_user_bound_one_use_and_expires(self):
        reviewed = self.review()
        with self.assertRaises(ValueError):
            self.start(reviewed, requested_by="different-user")
        reviewed = self.review()
        intent = self.agent._compose_intents[reviewed["confirmation_id"]]
        self.agent._compose_intents[reviewed["confirmation_id"]] = replace(intent, expires_at=time.monotonic() - 1)
        with self.assertRaises(ValueError):
            self.start(reviewed)
        reviewed = self.review()
        self.execute(reviewed)
        with self.assertRaises(ValueError):
            self.start(reviewed)
        with self.assertRaises(ValueError):
            self.start({"confirmation_id": "tampered"})

    def test_changed_source_after_review_is_blocked(self):
        reviewed = self.review()
        self.edit("TZ: Europe/London", "TZ: Europe/Paris")
        changed = self.compose.read_bytes()
        self.assert_blocked(self.execute(reviewed))
        self.assertEqual(self.compose.read_bytes(), changed)

    def test_changed_runtime_after_review_is_blocked(self):
        reviewed = self.review()
        self.runtime = [self.make_service(self.baseline.runtime_hash, container_id="d" * 64)]
        self.assert_blocked(self.execute(reviewed))

    def test_changed_baseline_after_review_is_blocked(self):
        reviewed = self.review()
        path = self.state.root / "compose-baselines" / self.baseline.id / "manifest.json"
        path.write_text("{}")
        self.assert_blocked(self.execute(reviewed))

    def test_changed_project_or_execution_context_after_review_is_blocked(self):
        for change in ("project", "network"):
            with self.subTest(change=change):
                reviewed = self.review()
                if change == "project":
                    self.edit("name: media", "name: redirected")
                else:
                    self.fake.network_id = "d" * 64
                self.assert_blocked(self.execute(reviewed))
                self.compose.write_bytes(self.desired)
                self.fake.network_id = "b" * 64
                self.fake.up_calls.clear()

    def test_model_change_without_source_change_is_blocked(self):
        reviewed = self.review()
        original = self.fake.model
        def model(*args, **kwargs):
            result = original(*args, **kwargs)
            result["services"]["sonarr"]["environment"]["TZ"] = "Europe/Paris"
            return result
        with patch.object(self.fake, "model", side_effect=model):
            self.assert_blocked(self.execute(reviewed))

    def test_local_mutable_tag_moved_blocks_review_and_execution(self):
        reviewed = self.review()
        self.fake.local_image_id = "sha256:" + "9" * 64
        self.assertFalse(self.status()["apply_eligible"])
        with self.assertRaises(ValueError):
            self.review()
        self.assert_blocked(self.execute(reviewed))

    def test_failure_of_desired_validation_or_backup_is_blocked(self):
        reviewed = self.review()
        def hook(args):
            if "--quiet" in args:
                raise RuntimeError(SECRET + " desired validation failed")
        self.fake.config_hook = hook
        self.assert_blocked(self.execute(reviewed))
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.fake.config_hook = None
        reviewed = self.review()
        with patch("docker_update_manager.compose_reconcile.RecoveryBundle", side_effect=OSError(SECRET)):
            self.assert_blocked(self.execute(reviewed))

    def test_last_pre_recreate_guard_catches_image_or_source_race(self):
        for race in ("image", "source"):
            with self.subTest(race=race):
                reviewed = self.review()
                def hook(args):
                    if "--quiet" in args:
                        if race == "image":
                            self.fake.local_image_id = "sha256:" + "9" * 64
                        else:
                            self.edit("restart: always", "restart: on-failure")
                self.fake.config_hook = hook
                self.assert_blocked(self.execute(reviewed))
                self.fake.config_hook = None
                self.fake.local_image_id = self.service.image_id
                self.compose.write_bytes(self.desired)

    def test_project_declared_bridge_network_uses_the_shared_context_proof(self):
        use_named_runtime_network(self.fake)
        self.compose.write_text(with_named_network())
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        self.status()  # Phase 1 proves and captures the named-network baseline.
        named = self.compose.read_text()
        self.edit("restart: unless-stopped", "restart: always")
        self.assertTrue(self.status()["apply_eligible"])
        # Only the selected service's own proven network is an allowed project
        # resource, and the runtime network must still prove independently.
        for change, reason in (("extra project network", "project_unproven"), ("runtime label", "network_unproven")):
            with self.subTest(change):
                if change == "extra project network":
                    self.compose.write_text(self.compose.read_text() + "  other: {}\n")
                else:
                    self.fake.network_logical = "default"
                status = self.status()
                self.assertFalse(status["apply_eligible"])
                self.assertIn(reason, [item["code"] for item in status["apply_reasons"]])
                self.compose.write_text(named.replace("restart: unless-stopped", "restart: always"))
                use_named_runtime_network(self.fake)
        operation = self.execute()
        self.assertEqual(operation["status"], "succeeded")
        self.assertEqual(len(self.fake.up_calls), 1)

    def test_success_preserves_image_dependencies_captures_baseline_and_refreshes_one_service(self):
        redis = self.make_service(self.current_hash("redis"), container_id="b" * 64,
                                  name="redis", compose_service="redis", image="redis:7")
        self.runtime.append(redis)
        self.state.save_verification({"service": _public_service(self.service), "status": "CURRENT"})
        previous_protected = self.state.protected()
        operation = self.execute()
        self.assertEqual(operation["kind"], "compose_reconcile")
        self.assertEqual(operation["status"], "succeeded")
        self.assertEqual(len(self.fake.up_calls), 1)
        from docker_update_manager.docker import compose_args
        self.assertEqual(self.fake.up_calls[0], compose_args(self.service, project_name="media") +
                         ["up", "-d", "--no-deps", "--pull", "never", "sonarr"])
        fresh = next(item for item in self.runtime if item.compose_service == "sonarr")
        self.assertNotEqual(fresh.container_id, self.service.container_id)
        self.assertEqual(fresh.image_id, self.service.image_id)
        self.assertEqual(fresh.labels["com.docker.compose.config-hash"], self.current_hash())
        self.assertIs(next(item for item in self.runtime if item.compose_service == "redis"), redis)
        current_baseline = self.records(fresh)[0]
        self.assertEqual(current_baseline.container_id, fresh.container_id)
        self.assertEqual(current_baseline.runtime_hash, self.current_hash())
        self.assertTrue(all(row["invalidated"] for row in self.state.verification_snapshot()))
        self.assertIn(fresh.container_id, [row["container_id"] for row in self.state.runtime_snapshot()["containers"]])
        self.refresh.assert_called_once_with("container/" + fresh.container_id, after_reconcile=True)
        self.assertEqual(self.state.protected(), previous_protected)
        with self.state.read() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM rollback_refs").fetchone()[0], 0)
        self.assertFalse(any("pull" in command or "tag" in command for command in self.fake.calls))
        self.assertEqual(self.status(fresh)["status"], "in_sync")
        self.assertEqual(operation["result"]["current_service_key"], "container/" + fresh.container_id)
        self.assertIn(self.baseline.id, self.state.compose_baseline_references())
        self.assertIn(current_baseline.id, self.state.compose_baseline_references())

    def test_unhealthy_apply_recovers_once_and_preserves_desired_pending_bytes(self):
        self.fake.health = "unhealthy"
        operation = self.execute()
        self.assertEqual(operation["status"], "failed")
        self.assertTrue(operation["result"]["recovered"])
        self.assertFalse(operation["result"]["manual_recovery_required"])
        self.assertEqual(len(self.fake.up_calls), 2)
        fresh = self.runtime[0]
        self.assertEqual(fresh.labels["com.docker.compose.config-hash"], self.baseline.runtime_hash)
        self.assertEqual(fresh.image_id, self.service.image_id)
        self.assertEqual(fresh.health, "healthy")
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.assertEqual(self.status(fresh)["status"], "drifted")
        self.assertTrue(self.status(fresh)["apply_eligible"])
        self.assertEqual(self.records(fresh)[0].container_id, fresh.container_id)
        self.refresh.assert_called_once_with("container/" + fresh.container_id, after_reconcile=True)

    def test_recreate_command_failure_after_boundary_attempts_one_recovery(self):
        def hook(number, fresh):
            if number == 1:
                raise RuntimeError(SECRET + " recreation failed")
        self.fake.up_hook = hook
        operation = self.execute()
        self.assertTrue(operation["result"]["mutation_performed"])
        self.assertTrue(operation["result"]["recovered"])
        self.assertEqual(len(self.fake.up_calls), 2)
        self.assertEqual(self.compose.read_bytes(), self.desired)

    def test_concurrent_source_edit_refuses_recovery_without_overwriting(self):
        def hook(number, fresh):
            if number == 1:
                self.edit("restart: always", "restart: on-failure")
                fresh.health = "unhealthy"
        self.fake.up_hook = hook
        operation = self.execute()
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertFalse(operation["result"]["recovered"])
        self.assertEqual(len(self.fake.up_calls), 1)
        self.assertIn(b"restart: on-failure", self.compose.read_bytes())
        recovery = self.state.root / "compose-recoveries" / operation["id"]
        self.assertEqual((recovery / "desired-00").read_bytes(), self.desired)
        self.assertEqual((recovery / "baseline-00").read_bytes(), self.original)

    def test_failed_recovery_is_manual_and_retains_private_evidence(self):
        self.fake.health = "unhealthy"
        def hook(number, fresh):
            if number == 2:
                fresh.health = "unhealthy"
        self.fake.up_hook = hook
        operation = self.execute()
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertEqual(len(self.fake.up_calls), 2)
        self.assertEqual(self.compose.read_bytes(), self.desired)
        recovery = self.state.root / "compose-recoveries" / operation["id"]
        for path in [recovery.parent, recovery, *recovery.iterdir()]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        self.assertTrue((self.state.root / "compose-baselines" / self.baseline.id).exists())

    def test_unsupported_input_execution_inventory_and_unrelated_changes_have_no_apply(self):
        for extra in ("    build: .\n", "    profiles: [test]\n", "    scale: 2\n",
                      "    pull_policy: always\n", "    deploy: {replicas: 2}\n",
                      "    depends_on: [redis]\n", "    networks: {custom: null}\n",
                      "    pid: service:redis\n", "    configs: [runtime]\n",
                      "    volumes_from: [redis]\n", "    secrets: [password]\n",
                      "    env_file: new.env\n"):
            with self.subTest(extra=extra):
                self.compose.write_bytes(self.desired.replace(b"    restart: always\n", b"    restart: always\n" + extra.encode()))
                with self.assertRaises(ValueError):
                    self.review()
        self.compose.write_bytes(self.desired.replace(
            b"type: bind, source: /srv/private/sonarr", b"type: volume, source: app"))
        with self.assertRaises(ValueError):
            self.review()
        self.compose.write_bytes(self.desired)
        self.edit("image: redis:7", "image: redis:8")
        with self.assertRaises(ValueError):
            self.review()
        self.compose.write_bytes(self.desired + b"networks:\n  default: {driver_opts: {arbitrary: change}}\n")
        with self.assertRaises(ValueError):
            self.review()
        self.assertEqual(self.fake.up_calls, [])

    def test_unwritable_recovery_directory_and_multiple_replicas_refuse_review(self):
        with patch("docker_update_manager.webservice.verify_atomic_replace_access", side_effect=ComposeSourceNotWritable()):
            with self.assertRaises(ValueError):
                self.review()
        self.runtime.append(self.make_service(self.baseline.runtime_hash, container_id="d" * 64))
        with self.assertRaises(ValueError):
            self.review()

    def test_shared_mutation_lock_and_single_active_operation_are_enforced(self):
        reviewed = self.review()
        with Lock(self.state.root / "update.lock"), self.assertRaises(RuntimeError):
            self.start(reviewed)
        first, _, _ = self.start(reviewed)
        with self.assertRaises(RuntimeError):
            self.start(self.review())
        self.assertEqual(self.state.operation_status(first["operation_id"])["status"], "queued")

    def test_history_audit_progress_and_operation_are_secret_safe_and_kind_specific(self):
        self.fake.health = "unhealthy"
        operation = self.execute()
        audit = self.state.audit_events()
        history = self.state.history()[0]
        self.assertEqual(history["action"], "compose_reconcile")
        self.assertEqual(audit[0]["action"], "web_compose_reconcile")
        self.assertEqual(audit[0]["result"], "recovered")
        for payload in (operation, audit, history):
            self.assertNotIn(SECRET, json.dumps(payload))
            self.assertNotIn("SONARR_API_KEY=", json.dumps(payload))
        self.assertNotIn(str(self.project), json.dumps(operation))
        self.assertNotIn(self.baseline.id, json.dumps(operation))
        self.assertEqual(operation_presentation(operation)["status_label"], "Apply failed · recovered")

    def test_bounded_socket_requires_privileged_web_identity(self):
        server = AgentServer(self.agent, str(self.root / "agent.sock"), allowed_mutation_uid=1234)
        request = {"operation": "compose_reconcile_review", "payload": {
            "service_key": "container/" + "a" * 64, "action": "apply", "requested_by": "admin",
            "_upt_client_version": __version__}, "client_version": __version__}
        raw = (json.dumps(request) + "\n").encode()
        self.assertEqual(json.loads(server.handle_line(raw, peer_uid=9999))["type"], "PermissionError")
        answer = json.loads(server.handle_line(raw, peer_uid=1234))
        self.assertTrue(answer["ok"])
        self.assertNotIn(SECRET, json.dumps(answer))

    def test_wrong_replacement_hash_image_or_project_is_manual_not_success(self):
        for field in ("hash", "image", "project"):
            with self.subTest(field=field):
                reviewed = self.review()
                def hook(number, fresh):
                    if field == "hash":
                        fresh.labels["com.docker.compose.config-hash"] = "9" * 64
                    elif field == "image":
                        fresh.image_id = "sha256:" + "9" * 64
                    else:
                        fresh.labels["com.docker.compose.project"] = "redirected"
                self.fake.up_hook = hook
                operation = self.execute(reviewed)
                self.assertEqual(operation["status"], "failed")
                self.assertTrue(operation["result"]["manual_recovery_required"])
                self.assertEqual(len(self.fake.up_calls), 1)
                self.runtime = [self.service]
                self.fake.up_calls.clear()

    def test_dependency_identity_change_never_claims_success_or_recreates_again(self):
        redis = self.make_service(self.current_hash("redis"), container_id="b" * 64, name="redis",
                                  compose_service="redis", image="redis:7")
        self.runtime.append(redis)
        def hook(number, fresh):
            redis.container_id = "9" * 64
        self.fake.up_hook = hook
        operation = self.execute()
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertEqual(len(self.fake.up_calls), 1)

    def test_recovery_validation_failure_restores_desired_without_second_recreate(self):
        self.fake.health = "unhealthy"
        def hook(args):
            if "--quiet" in args and b"restart: unless-stopped" in self.compose.read_bytes():
                raise RuntimeError(SECRET + " baseline validation failed")
        self.fake.config_hook = hook
        operation = self.execute()
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertEqual(len(self.fake.up_calls), 1)
        self.assertEqual(self.compose.read_bytes(), self.desired)

    def test_moved_tag_after_recreation_is_never_pulled_or_retagged_for_recovery(self):
        def hook(number, fresh):
            fresh.health = "unhealthy"
            self.fake.local_image_id = "sha256:" + "9" * 64
        self.fake.up_hook = hook
        operation = self.execute()
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertEqual(len(self.fake.up_calls), 1)
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.assertFalse(any("pull" in command or "tag" in command for command in self.fake.calls))

    def test_source_change_during_baseline_capture_prevents_false_success(self):
        original_capture = self.agent._capture_baseline
        def capture(*args, **kwargs):
            result = original_capture(*args, **kwargs)
            self.edit("TZ: Europe/London", "TZ: Europe/Paris")
            return result
        with patch.object(self.agent, "_capture_baseline", side_effect=capture):
            operation = self.execute()
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertEqual(len(self.fake.up_calls), 1)
        self.assertIn(b"Europe/Paris", self.compose.read_bytes())

    def test_multi_input_recovery_restores_exact_desired_env_and_compose_bytes(self):
        self.compose.write_bytes(self.original)
        self.compose.write_text(self.compose.read_text().replace("    restart: unless-stopped\n",
                                                                "    restart: unless-stopped\n    env_file: app.env\n"))
        env_file = self.project / "app.env"
        env_file.write_text(f"PRIVATE_KEY={SECRET}\n")
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        self.status()
        self.edit("restart: unless-stopped", "restart: always")
        env_file.write_text(f"PRIVATE_KEY={SECRET}-desired\n")
        self.desired = self.compose.read_bytes()
        desired_env = env_file.read_bytes()
        self.fake.health = "unhealthy"
        operation = self.execute()
        self.assertTrue(operation["result"]["recovered"])
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.assertEqual(env_file.read_bytes(), desired_env)
        self.assertNotIn(SECRET, json.dumps(operation))

    def test_concurrent_edit_immediately_before_atomic_replacement_is_preserved(self):
        from docker_update_manager.compose import atomic_write_bytes
        self.fake.health = "unhealthy"
        def replace_source(path, content, **kwargs):
            Path(path).write_bytes(b"# concurrent operator edit\n" + self.desired)
            return atomic_write_bytes(path, content, **kwargs)
        with patch("docker_update_manager.compose_reconcile.atomic_write_bytes", side_effect=replace_source):
            operation = self.execute()
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertEqual(len(self.fake.up_calls), 1)
        self.assertTrue(self.compose.read_bytes().startswith(b"# concurrent operator edit"))

    def test_running_health_timeout_recovers_and_never_skips_health(self):
        self.fake.health = "starting"
        self.config.data["health_timeout"] = 0
        operation = self.execute()
        self.assertTrue(operation["result"]["recovered"])
        self.assertEqual(len(self.fake.up_calls), 2)

    def test_interrupted_operation_is_blocked_before_boundary_and_manual_after(self):
        for crossed in (False, True):
            with self.subTest(crossed=crossed):
                result, _, _ = self.start()
                operation_id = result["operation_id"]
                self.state.set_operation_running(operation_id)
                if crossed:
                    self.state.mark_compose_mutation_started(operation_id)
                with self.state.connect() as c:
                    c.execute("UPDATE operation_runs SET started_at='2000-01-01T00:00:00Z' WHERE id=?", (operation_id,))
                with Lock(self.state.root / "update.lock"):
                    self.state.recover_abandoned_operations()
                operation = self.state.operation_status(operation_id)
                self.assertEqual(operation["status"], "failed" if crossed else "blocked")
                self.assertEqual(operation["result"]["manual_recovery_required"], crossed)
                self.assertEqual(self.state.audit_events()[0]["action"], "web_compose_reconcile")

    def test_targeted_refresh_waits_for_scan_then_checks_only_current_service_once(self):
        from docker_update_manager.models import ScanResult
        agent = ReadOnlyService(self.config, self.state)
        with patch.object(self.state, "active_scan", side_effect=[True, False]), \
                patch("docker_update_manager.webservice.time.sleep"), \
                patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=ScanResult(self.service, "CURRENT")) as scan:
            agent._refresh_worker("container/" + self.service.container_id, wait_for_scan=True)
        scan.assert_called_once_with(self.service, self.state)
        self.assertEqual(len(self.state.verification_snapshot()), 1)
        # A scan may have failed a query for this new container during health
        # verification. Apply must still queue its own one targeted check.
        self.state.save_verification({"service": _public_service(self.service), "status": "REGISTRY ERROR",
                                      "error": "registry query failed"})
        with patch("docker_update_manager.webservice.threading.Thread") as thread:
            self.assertEqual(agent.start_refresh("container/" + self.service.container_id)["status"], "retry_later")
            self.assertEqual(agent.start_refresh("container/" + self.service.container_id, after_reconcile=True)["status"], "checking")
            thread.return_value.start.assert_called_once()

    def test_anonymous_runtime_volume_and_runtime_mount_change_refuse_apply(self):
        reviewed = self.review()
        self.fake.mounts.append({"Type": "volume", "Source": "/private/docker-volume", "Destination": "/data", "RW": True})
        with self.assertRaises(ValueError):
            self.review()
        self.assert_blocked(self.execute(reviewed))

    def test_build_even_empty_and_extended_runtime_features_have_no_apply(self):
        for extra in ("    build: {}\n", "    develop: {watch: []}\n", "    provider: {type: external}\n",
                      "    tmpfs: [/tmp]\n", "    deploy: {mode: global}\n"):
            with self.subTest(extra=extra):
                self.compose.write_bytes(self.desired.replace(b"    restart: always\n", b"    restart: always\n" + extra.encode()))
                with self.assertRaises(ValueError):
                    self.review()

    def test_inherited_project_override_or_runtime_hash_change_after_review_blocks(self):
        reviewed = self.review()
        with patch.dict(os.environ, {"COMPOSE_PROJECT_NAME": "media"}):
            self.assert_blocked(self.execute(reviewed))
        reviewed = self.review()
        self.service.labels["com.docker.compose.config-hash"] = "9" * 64
        self.assert_blocked(self.execute(reviewed))

    def test_dry_run_revalidates_but_writes_no_recovery_bundle_and_recreates_nothing(self):
        service, plan, evidence = self.agent._compose_candidate("container/" + "a" * 64)
        outcome = do_compose_reconcile(service, self.state, plan, operation_id="f" * 32, binding={"evidence": evidence},
                                       revalidate=lambda: self.agent._compose_candidate("container/" + "a" * 64),
                                       discover_current=lambda: list(self.runtime), verify_configuration=lambda *_args: None,
                                       verify_context=lambda *_args: None, capture_baseline=lambda *_args: None, dry_run=True)
        self.assertEqual(outcome.status, "dry_run")
        self.assertFalse(outcome.mutation_performed)
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.assertFalse((self.state.root / "compose-recoveries").exists())
        self.assertEqual(self.fake.up_calls, [])

    def test_active_review_baseline_is_not_pruned_by_new_status_captures(self):
        self.review()
        for index in range(6):
            self.compose.write_bytes(self.original.replace(b"image: redis:7", f"image: redis:{index + 8}".encode()))
            self.status()
        self.assertIn(self.baseline.id, [record.id for record in self.records()])
        self.assertGreater(len(self.records()), 4)

    def test_late_terminal_persistence_failure_keeps_success_and_one_history_row(self):
        original_finish = self.state.finish_operation
        calls = []
        def finish(*args, **kwargs):
            calls.append(args)
            if len(calls) == 1:
                raise OSError("synthetic persistence failure")
            return original_finish(*args, **kwargs)
        with patch.object(self.state, "finish_operation", side_effect=finish):
            operation = self.execute()
        self.assertEqual(operation["status"], "succeeded")
        self.assertEqual(len(self.fake.up_calls), 1)
        self.assertEqual(len(self.state.history()), 1)

    def fail_first_terminal_event(self):
        """Make the terminal commit fail once after the final stage was inserted in the same transaction."""
        original = State._insert_operation_event
        failures = []
        def insert(c, operation_id, kind, **kwargs):
            if kind == "operation_completed" and not failures:
                failures.append(kind)
                raise OSError("synthetic terminal event failure")
            return original(c, operation_id, kind, **kwargs)
        return patch.object(State, "_insert_operation_event", staticmethod(insert)), failures

    def test_terminal_commit_failure_rolls_back_the_final_stage_so_a_retry_emits_it_once(self):
        patcher, failures = self.fail_first_terminal_event()
        with patcher:
            operation = self.execute()
        self.assertEqual(failures, ["operation_completed"])
        self.assertEqual(operation["status"], "succeeded")
        events = operation["events"]
        self.assertEqual(assert_stage_model(self, events, 8), list(range(1, 9)))
        self.assertEqual([event["stage"] for event in events].count("8/8 Record result"), 1)
        self.assertEqual(len(self.state.history()), 1)

    def test_history_write_is_retried_before_finalization(self):
        original = self.state.record
        attempts = []
        def record(**kwargs):
            attempts.append(1)
            if len(attempts) < 3:
                raise OSError("database is locked")
            return original(**kwargs)
        with patch.object(self.state, "record", side_effect=record), patch("docker_update_manager.webservice.time.sleep"):
            operation = self.execute()
        self.assertEqual(len(attempts), 3)
        self.assertEqual(operation["status"], "succeeded")
        self.assertIn("history_id", operation["result"])
        self.assertNotIn("warnings", operation["result"])
        self.assertEqual(assert_stage_model(self, operation["events"], 8), list(range(1, 9)))

    def test_persistent_history_failure_keeps_factual_success_but_never_claims_the_record_stage(self):
        with patch.object(self.state, "record", side_effect=OSError("database is locked")), \
                patch("docker_update_manager.webservice.time.sleep"):
            operation = self.execute()
        self.assertEqual(operation["status"], "succeeded")  # the committed workload outcome is not revoked
        self.assertIn("Core History could not be written", operation["result"]["warnings"][0])
        self.assertNotIn("history_id", operation["result"])
        self.assertEqual(assert_stage_model(self, operation["events"], 8), list(range(1, 8)))
        self.assertEqual(self.state.history(), [])

    def test_current_behaviour_unavailable_database_cannot_surface_the_history_warning(self):
        # S6-R3 (G2, issue #9) CURRENT-BEHAVIOUR characterisation: the retry and
        # factual-success policy above is the only one in place, but its warning
        # is itself a SQLite write. Here the database becomes unavailable at the
        # first History insert and stays unavailable.
        result, payload, intent = self.start()
        with sqlite_fault(self.state, history_insert(action="compose_reconcile"), mode="unavailable") as fault, \
                patch("docker_update_manager.webservice.time.sleep"), \
                self.assertLogs("docker_update_manager.webservice", "ERROR"), \
                self.assertRaisesRegex(sqlite3.OperationalError, "unable to open database file"):
            # The terminal write fails, the worker's fallback repeats the whole
            # finalisation once, and that failure escapes the worker thread.
            self.agent._compose_worker(result["operation_id"], payload, intent)
        self.assertEqual(len(fault.hits), 1)
        self.assertEqual(len(self.fake.up_calls), 1)  # applied once; never reversed
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.assertEqual(self.state.history(), [])
        operation = self.agent.operation_status({"operation_id": result["operation_id"], "after_event_id": 0})
        # No durable History row, warning or terminal state: the operation is
        # left running although the workload change is complete.
        self.assertEqual(operation["status"], "running")
        self.assertNotIn("warnings", operation.get("result") or {})

    def test_changed_bind_configuration_recovers_old_mount_then_restores_pending_source(self):
        self.edit("source: /srv/private/sonarr", "source: /srv/private/sonarr-new")
        desired = self.compose.read_bytes()
        self.fake.health = "unhealthy"
        operation = self.execute()
        self.assertTrue(operation["result"]["recovered"])
        self.assertEqual(self.compose.read_bytes(), desired)
        self.assertEqual(self.fake.mounts[0]["Source"], "/srv/private/sonarr")
        self.assertEqual(len(self.fake.up_calls), 2)

    def test_absent_replacement_recovers_only_with_exact_surviving_network(self):
        for changed_network in (False, True):
            with self.subTest(changed_network=changed_network):
                reviewed = self.review()
                def hook(number, fresh):
                    if number == 1:
                        self.runtime = []
                        if changed_network:
                            self.fake.network_id = "9" * 64
                        raise RuntimeError("replacement failed after removing original")
                self.fake.up_hook = hook
                operation = self.execute(reviewed)
                self.assertEqual(operation["result"]["recovered"], not changed_network)
                self.assertEqual(operation["result"]["manual_recovery_required"], changed_network)
                self.assertEqual(len(self.fake.up_calls), 1 if changed_network else 2)
                self.runtime = [self.service]
                self.fake.network_id = "b" * 64
                self.fake.up_calls.clear()

    def test_concurrent_source_directory_symlink_refuses_recovery_writes(self):
        alternative = self.root / "operator-project"
        def hook(number, fresh):
            if number == 1:
                fresh.health = "unhealthy"
                self.project.rename(self.root / "original-project")
                alternative.mkdir()
                (alternative / "compose.yml").write_bytes(self.desired)
                (alternative / ".env").write_text(f"SONARR_API_KEY={SECRET}\n")
                self.project.symlink_to(alternative, target_is_directory=True)
        self.fake.up_hook = hook
        operation = self.execute()
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertEqual(len(self.fake.up_calls), 1)
        self.assertEqual((alternative / "compose.yml").read_bytes(), self.desired)


class ComposeApplyWebTests(unittest.TestCase):
    setUp = phase1_fixtures.ServiceDetailAndOperationRouteTests.setUp

    def eligible(self):
        return phase1_fixtures.ServiceDetailAndOperationRouteTests.drifted(apply_eligible=True)

    def test_service_action_and_redacted_review_confirmation(self):
        self.agent.compose_status_data = self.eligible()
        page = self.client.get(self.url)
        self.assertIn('data-compose-apply', page.text)
        self.assertIn("Update available", page.text)
        self.assertIn('href="#configuration">Blocked by pending configuration changes', page.text)
        self.assertIn("Show changes", page.text)
        self.assertIn("Apply changes", page.text)
        self.assertNotIn("Configuration changes pending", page.text)
        self.assertNotIn('action="/operations/update"', page.text)
        review = self.client.post("/compose/apply/review", data={"csrf": self.csrf, "action": "apply",
                                                                "service_key": "container/" + "a" * 64})
        self.assertEqual(review.status_code, 200)
        self.assertIn("Review configuration changes", review.text)
        self.assertIn("Sonarr configuration", review.text)
        self.assertIn("Review changes · media", review.text)
        self.assertIn("Automatic from trusted configuration", review.text)
        self.assertIn("I confirm applying the reviewed configuration changes to Sonarr.", review.text)
        self.assertIn(">Apply configuration</button>", review.text)
        self.assertIn("trusted previous configuration", review.text)
        self.assertIn("<code>API_KEY</code>", review.text)
        self.assertNotIn(SECRET, review.text)
        self.assertIn('name="confirm_apply"', review.text)
        self.assertIn("required", review.text)
        confirmed = self.client.post("/operations/compose-reconcile", data={"csrf": self.csrf,
                                    "confirmation_id": "C" * 43, "confirm_apply": "yes"}, follow_redirects=False)
        self.assertEqual(confirmed.status_code, 303)
        self.assertEqual(set(self.agent.compose_apply_calls[0]), {"confirmation_id", "requested_by", "client_ip", "user_agent"})

    def test_no_baseline_never_exposes_apply_even_with_malformed_eligibility(self):
        self.agent.compose_status_data = {**self.eligible(), "baseline": None}
        self.assertNotIn('data-compose-apply', self.client.get(self.url).text)
        response = self.client.post("/compose/apply/review", data={"csrf": self.csrf, "service_key": "container/" + "a" * 64,
                                                                 "action": "apply"})
        self.assertEqual(response.status_code, 409)

    def test_review_and_confirm_enforce_csrf_auth_schema_and_explicit_acknowledgement(self):
        self.agent.compose_status_data = self.eligible()
        review = {"csrf": self.csrf, "service_key": "container/" + "a" * 64, "action": "apply"}
        confirm = {"csrf": self.csrf, "confirmation_id": "C" * 43, "confirm_apply": "yes"}
        for path, valid in (("/compose/apply/review", review), ("/operations/compose-reconcile", confirm)):
            with self.subTest(path=path):
                for field in ("project_name", "source_path", "compose_yaml", "image_id", "baseline_id", "command", "requested_by"):
                    self.assertEqual(self.client.post(path, data={**valid, field: "tampered"}).status_code, 400)
                self.assertEqual(self.client.post(path, data={**valid, "csrf": "invalid"}).status_code, 403)
                self.assertEqual(self.client.post(path, data=valid, headers={"Origin": "https://hostile.example"}).status_code, 403)
        self.assertEqual(self.client.post("/operations/compose-reconcile", data={**confirm, "confirm_apply": "no"}).status_code, 400)
        self.client.cookies.clear()
        self.assertEqual(self.client.post("/compose/apply/review", data=review, follow_redirects=False).status_code, 303)

    def test_terminal_html_and_sse_use_same_compose_presentation(self):
        for status, result in (("succeeded", {"current_service_key": "container/" + "c" * 64}),
                               ("blocked", {"mutation_performed": False}), ("failed", {"recovered": True}),
                               ("failed", {"manual_recovery_required": True})):
            with self.subTest(status=status, result=result):
                operation = {"id": "f" * 32, "kind": "compose_reconcile", "service": "Sonarr", "stack": "media",
                             "service_key": "container/" + "a" * 64, "status": status, "result": result,
                             "error": "Apply could not proceed safely." if status != "succeeded" else None,
                             "events": [], "last_event_id": 0}
                self.agent.operation = operation
                page = self.client.get("/operations/" + "f" * 32)
                stream = self.client.get("/operations/" + "f" * 32 + "/events")
                event = {"succeeded": "operation-complete", "blocked": "operation-blocked", "failed": "operation-failed"}[status]
                payload = json.loads(stream.text.split("event: " + event + "\ndata: ", 1)[1].split("\n", 1)[0])
                view = operation_presentation(operation)
                self.assertEqual(payload["presentation"], view)
                self.assertIn(view["status_label"], page.text)
                self.assertIn("Apply configuration", page.text)
                self.assertNotIn("Deployed image", page.text)
