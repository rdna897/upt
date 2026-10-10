"""Phase 2B1: exact synthetic bytes and fake read-only Docker inspections."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import json
import stat
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from docker_update_manager import __version__
from docker_update_manager.compose import atomic_write_bytes
from docker_update_manager.compose_discard import DISCARD_REASONS, DiscardRefused, do_compose_discard
from docker_update_manager.compose_recovery_retention import checked_bundle, lifecycle
from docker_update_manager.lock import Lock
from docker_update_manager.webservice import AgentServer, _public_service
from docker_update_manager.state import State
import test_compose_apply as apply_fixtures
from progress_assertions import assert_stage_model
from test_compose_reconciliation import ComposeFixture, SECRET

SIMPLE = f'''# operator heading café
name: media
services:
  sonarr:
    image: lscr.io/linuxserver/sonarr:latest
    restart: unless-stopped # retain this note
    command:
      - --api-key
      - {SECRET}
    environment:
      API_KEY: {SECRET}
      TZ: Europe/London
    labels:
      traefik.secret: "{SECRET}"
    ports:
      - target: 8989
        published: "8989"
        protocol: tcp
    volumes:
      - type: bind
        source: /srv/private/sonarr
        target: /config
  # peer heading belongs to the operator
  redis:
    image: redis:7
# final project note
'''.encode()


class ComposeDiscardTests(ComposeFixture):
    start = apply_fixtures.ComposeApplyTests.start
    execute = apply_fixtures.ComposeApplyTests.execute
    assert_blocked = apply_fixtures.ComposeApplyTests.assert_blocked

    def setUp(self):
        super().setUp()
        self.compose.write_bytes(SIMPLE)
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        self.fake = apply_fixtures.FakeApplyCompose(self)
        for module in ("webservice", "compose_reconcile", "compose"):
            mocked = patch(f"docker_update_manager.{module}.run", side_effect=self.fake)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.refresh = patch.object(self.agent, "start_refresh", return_value={"status": "checking"}).start()
        self.addCleanup(patch.stopall)
        self.status()
        self.original = self.compose.read_bytes()
        self.baseline = self.records()[0]
        self.edit("restart: unless-stopped", "restart: always")
        self.desired = self.compose.read_bytes()

    def review(self, **changes):
        payload = {"service_key": "container/" + "a" * 64, "action": "discard", "requested_by": "admin"}
        return self.agent.compose_reconcile_review({**payload, **changes})

    def test_success_exact_bytes_runtime_baseline_image_verification_and_history(self):
        peer = self.make_service(self.current_hash("redis"), container_id="b" * 64, name="redis",
                                 compose_service="redis", image="redis:7")
        self.runtime.append(peer)
        self.state.save_verification({"service": _public_service(self.service), "status": "CURRENT"})
        verification = self.state.verification_snapshot()
        records = self.records()
        before = [(item.container_id, item.image_id, item.image, item.health, item.state) for item in self.runtime]
        reviewed = self.review()
        for private in (SECRET, str(self.project), self.baseline.id, self.service.image_id):
            self.assertNotIn(private, json.dumps(reviewed))
        with patch.object(self.agent, "_capture_baseline", side_effect=AssertionError("Discard must not capture")):
            operation = self.execute(reviewed)
        self.assertEqual(operation["status"], "succeeded")
        self.assertEqual(operation["result"]["action"], "discard")
        self.assertEqual(self.compose.read_bytes(), self.original)
        self.assertEqual(before, [(item.container_id, item.image_id, item.image, item.health, item.state) for item in self.runtime])
        self.assertEqual(self.records(), records)
        invalidated = self.state.verification_snapshot()[0]
        self.assertTrue(invalidated["invalidated"])
        self.assertIsNone(invalidated["verification_id"])
        self.assertNotEqual(invalidated, verification[0])
        self.assertEqual(self.status()["status"], "in_sync")
        self.refresh.assert_called_once_with("container/" + self.service.container_id, after_reconcile=True)
        self.assertEqual(self.state.protected(), set())
        self.assertEqual(json.loads(self.state.history()[0]["details"])["action"], "discard")
        self.assertEqual(self.state.audit_events()[0]["details"]["action"], "discard")
        self.assert_no_workload_commands()
        for private in (SECRET, str(self.project), str(self.state.root), self.baseline.id):
            self.assertNotIn(private, json.dumps(operation))

    def assert_no_workload_commands(self):
        self.assertEqual(self.fake.up_calls, [])
        self.assertFalse(any(set(command) & {"up", "down", "restart", "pull", "build", "create", "rm", "stop", "start"}
                             for command in self.fake.calls))

    def test_eligibility_blocks_unrelated_bytes_shared_inputs_and_structural_edits(self):
        changes = [b"# new comment\n" + self.desired,
                   self.desired.replace(b"redis:7", b"redis:8"),
                   self.desired.replace(b"# peer heading", b"# edited peer heading"),
                   self.desired.replace(b"name: media", b"name: redirected"),
                   self.desired.replace(b"    labels:\n", b"    env_file: app.env\n    labels:\n"),
                   self.desired.replace(b"    restart: always", b"    restart: ${POLICY:-always}"),
                   self.desired.replace(b"    restart: always", b"    restart: &policy always"),
                   self.desired.replace(b"    restart: always", b"    restart: always\n    init: true"),
                   self.desired.replace(b"    restart: always", b"    restart: always\n    restart: always"),
                   self.desired.replace(b"    restart: always", b"    restart: >\n      always"),
                   self.desired.replace(b"    restart: always", b"    restart: always\n    <<: {init: true}")]
        (self.project / "app.env").write_text("PRIVATE=" + SECRET)
        for content in changes:
            with self.subTest(content=content[:45]):
                self.compose.write_bytes(content)
                self.assertFalse(self.status()["discard_eligible"])
                with self.assertRaises(ValueError):
                    self.review()
                self.assertEqual(self.compose.read_bytes(), content)
        self.assert_no_workload_commands()

    def test_no_baseline_input_layout_and_shared_dotenv_changes_block(self):
        self.assertTrue(self.status()["discard_eligible"])
        (self.project / ".env").write_text("NEW=value")
        self.assertFalse(self.status()["discard_eligible"])
        with self.assertRaises(ValueError):
            self.review()
        self.state.delete_compose_baseline(self.baseline.id)
        with self.assertRaises(ValueError):
            self.review()

    test_changed_source_after_review_is_blocked = apply_fixtures.ComposeApplyTests.test_changed_source_after_review_is_blocked
    test_changed_runtime_after_review_is_blocked = apply_fixtures.ComposeApplyTests.test_changed_runtime_after_review_is_blocked
    test_changed_baseline_after_review_is_blocked = apply_fixtures.ComposeApplyTests.test_changed_baseline_after_review_is_blocked
    test_confirmation_is_user_bound_one_use_and_expires = apply_fixtures.ComposeApplyTests.test_confirmation_is_user_bound_one_use_and_expires
    test_model_change_without_source_change_is_blocked = apply_fixtures.ComposeApplyTests.test_model_change_without_source_change_is_blocked
    test_local_mutable_tag_moved_blocks_review_and_execution = apply_fixtures.ComposeApplyTests.test_local_mutable_tag_moved_blocks_review_and_execution

    def test_peer_state_health_and_identity_changes_after_review_block(self):
        peer = self.make_service(self.current_hash("redis"), container_id="b" * 64, name="redis",
                                 compose_service="redis", image="redis:7")
        self.runtime.append(peer)
        for field, value in (("container_id", "d" * 64), ("health", "unhealthy"), ("state", "exited")):
            with self.subTest(field=field):
                reviewed = self.review()
                original = getattr(peer, field)
                setattr(peer, field, value)
                self.assert_blocked(self.execute(reviewed))
                setattr(peer, field, original)
                self.assertEqual(self.compose.read_bytes(), self.desired)

    def test_compare_and_swap_refusal_preserves_immediate_prewrite_edit(self):
        def write(path, content, **kwargs):
            Path(path).write_bytes(b"# immediate operator edit\n" + self.desired)
            return atomic_write_bytes(path, content, **kwargs)
        with patch("docker_update_manager.compose_discard.atomic_write_bytes", side_effect=write):
            self.assert_blocked(self.execute())
        self.assertTrue(self.compose.read_bytes().startswith(b"# immediate operator edit"))

    def test_prewrite_revalidation_failure_and_recovery_copy_failure_are_blocked(self):
        def hook(args):
            if "--quiet" in args:
                self.compose.write_bytes(b"# operator edit\n" + self.desired)
        self.fake.config_hook = hook
        self.assert_blocked(self.execute())
        self.fake.config_hook = None
        self.compose.write_bytes(self.desired)
        with patch("docker_update_manager.compose_discard.RecoveryBundle", side_effect=OSError(SECRET)):
            self.assert_blocked(self.execute())
        self.assertEqual(self.compose.read_bytes(), self.desired)

    def test_postwrite_validation_failure_restores_exact_pending_source(self):
        def hook(args):
            if "--quiet" in args and self.compose.read_bytes() == self.original:
                raise RuntimeError(SECRET + " invalid restored config")
        self.fake.config_hook = hook
        operation = self.execute()
        self.assertEqual(operation["status"], "failed")
        self.assertTrue(operation["result"]["source_recovered"])
        self.assertFalse(operation["result"]["manual_source_recovery_required"])
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.assertEqual(self.records()[0].id, self.baseline.id)
        self.assert_no_workload_commands()

    def test_third_state_refuses_recovery_and_retains_private_evidence_after_pruning(self):
        third = self.original + b"# concurrent operator edit\n"
        def hook(args):
            if "--quiet" in args and self.compose.read_bytes() == self.original:
                self.compose.write_bytes(third)
                raise RuntimeError(SECRET)
        self.fake.config_hook = hook
        operation = self.execute()
        self.assertEqual(operation["status"], "failed")
        self.assertTrue(operation["result"]["manual_source_recovery_required"])
        self.assertEqual(self.compose.read_bytes(), third)
        path = self.state.root / "compose-recoveries" / operation["id"]
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for entry in path.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
        self.assertEqual((path / "desired-00").read_bytes(), self.desired)
        with self.state.connect() as connection, checked_bundle(self.state.root, path) as bundle:
            self.assertEqual(lifecycle(connection, operation["id"], bundle)[0], "manual")
        with self.state.connect() as connection:
            connection.execute("UPDATE operation_runs SET finished_at='2000-01-01T00:00:00Z'")
        self.state.prune_operations()
        with self.state.connect() as connection, checked_bundle(self.state.root, path) as bundle:
            self.assertEqual(lifecycle(connection, operation["id"], bundle)[0], "manual")
        self.assert_no_workload_commands()

    def test_runtime_postwrite_change_requires_manual_source_recovery(self):
        def hook(args):
            if "--quiet" in args and self.compose.read_bytes() == self.original:
                self.service.health = "unhealthy"
        self.fake.config_hook = hook
        result = self.execute()
        self.assertTrue(result["result"]["manual_source_recovery_required"])
        self.assert_no_workload_commands()

    def test_dry_run_has_no_source_or_recovery_writes(self):
        service, plan, evidence = self.agent._compose_candidate("container/" + "a" * 64, "discard")
        outcome = do_compose_discard(service, self.state, plan, operation_id="f" * 32,
                                    binding={"baseline_id": self.baseline.id, "evidence": evidence},
                                    revalidate=lambda: None, discover_current=lambda: list(self.runtime),
                                    verify_configuration=lambda *_: None, verify_context=lambda *_: None, dry_run=True)
        self.assertEqual(outcome.status, "dry_run")
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.assertFalse((self.state.root / "compose-recoveries").exists())

    test_shared_mutation_lock_and_single_active_operation_are_enforced = apply_fixtures.ComposeApplyTests.test_shared_mutation_lock_and_single_active_operation_are_enforced

    def test_audit_and_worker_start_refusals_preserve_discard_action(self):
        for failure in ("audit", "worker"):
            reviewed = self.review()
            payload = {"confirmation_id": reviewed["confirmation_id"], "requested_by": "admin",
                       "client_ip": "127.0.0.1", "user_agent": "fixture"}
            with patch("docker_update_manager.webservice.threading.Thread") as thread:
                if failure == "worker":
                    thread.return_value.start.side_effect = RuntimeError("unavailable")
                with patch.object(self.state, "audit", side_effect=OSError("audit unavailable")) if failure == "audit" else patch.object(self.state, "audit", wraps=self.state.audit):
                    with self.assertRaises((RuntimeError, OSError)):
                        self.agent.start_compose_reconcile(payload)
            with self.state.connect() as c:
                row = c.execute("SELECT id FROM operation_runs ORDER BY rowid DESC LIMIT 1").fetchone()
            operation = self.state.operation_status(row[0])
            self.assertEqual(operation["status"], "blocked")
            self.assertEqual(operation["result"]["action"], "discard")
            self.assertTrue(any("No source changes were made" in event["message"] for event in operation["events"]))
            self.assertNotIn("application changes", json.dumps(operation))
            self.assertEqual(self.compose.read_bytes(), self.desired)

    def test_overlay_layout_change_refuses_review(self):
        overlay = self.project / "override.yml"
        overlay.write_text("services: {}\n")
        self.service.compose_files.append(str(overlay))
        with self.assertRaises(DiscardRefused):
            self.review()
        self.assertIn("multiple_compose_files", {item["code"] for item in self.status()["discard_reasons"]})

    def test_unreviewed_extension_edit_cannot_ride_along(self):
        # Existing extension material remains untouched; only the disclosed
        # restart field could be restored. An ignored x-field edit must block.
        self.compose.write_bytes(self.original.replace(b"    restart: unless-stopped", b"    x-note: before\n    restart: unless-stopped"))
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        self.status()
        self.edit("restart: unless-stopped", "restart: always")
        self.edit("x-note: before", "x-note: after")
        with self.assertRaises(ValueError):
            self.review()

    def test_error_after_atomic_replace_is_postboundary_and_recovers(self):
        writes = []
        def write(path, content, **kwargs):
            atomic_write_bytes(path, content, **kwargs)
            writes.append(content)
            if len(writes) == 1:
                raise OSError("post-replacement failure")
        with patch("docker_update_manager.compose_discard.atomic_write_bytes", side_effect=write):
            result = self.execute()
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["result"]["source_recovered"])
        self.assertEqual(self.compose.read_bytes(), self.desired)

    def test_discard_reports_exactly_five_real_stages_with_write_running_then_completed(self):
        operation = self.execute(self.review())
        self.assertEqual(operation["status"], "succeeded")
        events = operation["events"]
        self.assertEqual(assert_stage_model(self, events, 5), [1, 2, 3, 4, 5])
        write = [event["kind"] for event in events if event["stage"] == "3/5 Discarding configuration changes"]
        self.assertEqual(write, ["task_started", "task_completed"])
        self.assertEqual(events[-2]["stage"], "5/5 Record result")
        self.refresh.assert_called_once_with("container/" + self.service.container_id, after_reconcile=True)

    def test_discard_terminal_commit_failure_retry_emits_the_final_stage_once(self):
        original = State._insert_operation_event
        failures = []
        def insert(c, operation_id, kind, **kwargs):
            if kind == "operation_completed" and not failures:
                failures.append(kind)
                raise OSError("synthetic terminal event failure")
            return original(c, operation_id, kind, **kwargs)
        with patch.object(State, "_insert_operation_event", staticmethod(insert)):
            operation = self.execute(self.review())
        self.assertEqual(failures, ["operation_completed"])
        self.assertEqual(operation["status"], "succeeded")
        self.assertEqual(assert_stage_model(self, operation["events"], 5), [1, 2, 3, 4, 5])
        self.assertEqual([event["stage"] for event in operation["events"]].count("5/5 Record result"), 1)

    def test_discard_blocked_never_records_a_result_stage(self):
        result, payload, intent = self.start()
        self.agent._compose_worker(result["operation_id"], payload, replace(intent, expires_at=time.monotonic() - 1))
        blocked = self.agent.operation_status({"operation_id": result["operation_id"], "after_event_id": 0})
        self.assertEqual(blocked["status"], "blocked")
        self.assertNotIn(5, assert_stage_model(self, blocked["events"], 5))

    def test_discard_failure_after_replace_is_terminal_failed_without_record_stage(self):
        writes = []
        def write(path, content, **kwargs):
            atomic_write_bytes(path, content, **kwargs)
            writes.append(content)
            if len(writes) == 1:
                raise OSError("post-replacement failure")
        with patch("docker_update_manager.compose_discard.atomic_write_bytes", side_effect=write):
            operation = self.execute()
        self.assertEqual(operation["status"], "failed")
        completed = assert_stage_model(self, operation["events"], 5)
        self.assertEqual(completed, [1, 2])
        self.assertEqual(operation["events"][-1]["kind"], "operation_failed")

    def test_expiry_while_queued_blocks_before_write(self):
        result, payload, intent = self.start()
        self.agent._compose_worker(result["operation_id"], payload, replace(intent, expires_at=time.monotonic() - 1))
        self.assert_blocked(self.agent.operation_status({"operation_id": result["operation_id"], "after_event_id": 0}))
        self.assertEqual(self.compose.read_bytes(), self.desired)

    def test_late_terminal_persistence_failure_preserves_factual_success(self):
        finish = self.state.finish_operation
        calls = []
        def retry(*args, **kwargs):
            calls.append(args)
            if len(calls) == 1:
                raise OSError("temporary persistence failure")
            return finish(*args, **kwargs)
        with patch.object(self.state, "finish_operation", side_effect=retry):
            operation = self.execute()
        self.assertEqual(operation["status"], "succeeded")
        self.assertEqual(len(self.state.history()), 1)
        self.assert_no_workload_commands()

    def test_multiple_unicode_scalar_ranges_preserve_all_other_bytes(self):
        self.edit("TZ: Europe/London", "TZ: 'café/Paris'")
        _, plan, _ = self.agent._compose_candidate("container/" + "a" * 64, "discard")
        self.assertEqual(len(plan.discard_plan.ranges), 2)
        self.assertEqual(self.execute()["status"], "succeeded")
        self.assertEqual(self.compose.read_bytes(), self.original)

    def interrupted(self, source_state, *, marker=True):
        result, payload, intent = self.start()
        def interrupt(path, content, **kwargs):
            if source_state != "pending":
                atomic_write_bytes(path, content, **kwargs)
            if source_state == "unknown":
                Path(path).write_bytes(content + b"# concurrent third-party edit\n")
            raise SystemExit("synthetic process interruption")
        with patch("docker_update_manager.compose_discard.atomic_write_bytes", side_effect=interrupt):
            with self.assertRaises(SystemExit):
                self.agent._compose_worker(result["operation_id"], payload, intent)
        # Simulate restart from persisted state, not the original worker's flag.
        with self.state.connect() as c:
            row = c.execute("SELECT summary FROM operation_runs WHERE id=?", (result["operation_id"],)).fetchone()
            summary = json.loads(row[0])
            if not marker:
                summary.pop("mutation_started", None)
            c.execute("UPDATE operation_runs SET summary=?,started_at='2000-01-01T00:00:00Z' WHERE id=?",
                      (json.dumps(summary), result["operation_id"]))
        return result["operation_id"]

    def restart(self, operation_id):
        restarted = State(self.state.root)
        with Lock(restarted.root / "update.lock"):
            restarted.recover_abandoned_operations()
        return restarted.operation_status(operation_id)

    def test_interrupt_before_replace_uses_exact_pending_bytes_despite_marker(self):
        operation_id = self.interrupted("pending")
        operation = self.restart(operation_id)
        self.assertEqual(operation["status"], "blocked")
        self.assertEqual(operation["result"]["source_state"], "pending")
        self.assertFalse(operation["result"]["mutation_performed"])
        self.assertFalse(operation["result"]["manual_source_recovery_required"])
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.assertIn("no source changes", operation["error"])
        self.assert_no_workload_commands()

    def test_interrupt_after_replace_uses_exact_output_without_database_marker(self):
        operation_id = self.interrupted("discarded", marker=False)
        operation = self.restart(operation_id)
        self.assertEqual(operation["status"], "failed")
        self.assertEqual(operation["result"]["source_state"], "discarded")
        self.assertTrue(operation["result"]["mutation_performed"])
        self.assertTrue(operation["result"]["manual_source_recovery_required"])
        self.assertEqual(self.compose.read_bytes(), self.original)
        self.assert_no_workload_commands()

    def assert_unreadable_restart_unknown_and_protected(self, operation_id):
        path = self.state.root / "compose-recoveries" / operation_id
        with checked_bundle(self.state.root, path) as bundle:
            fingerprint_before = bundle["fingerprint"]
        commands_before = list(self.fake.calls)
        with patch("docker_update_manager.compose_discard.atomic_write_bytes") as write:
            operation = self.restart(operation_id)
        write.assert_not_called()
        self.assertEqual(operation["status"], "failed")
        self.assertEqual(operation["result"]["source_state"], "unknown")
        self.assertIsNone(operation["result"]["mutation_performed"])
        self.assertTrue(operation["result"]["manual_source_recovery_required"])
        self.assertEqual(self.fake.calls, commands_before)
        self.assert_no_workload_commands()
        with self.state.connect() as c:
            c.execute("UPDATE operation_runs SET finished_at='2000-01-01T00:00:00Z' WHERE id=?", (operation_id,))
        self.state.prune_operations()
        with self.state.connect() as c, checked_bundle(self.state.root, path) as bundle:
            self.assertEqual(bundle["fingerprint"], fingerprint_before)
            self.assertEqual(lifecycle(c, operation_id, bundle)[0], "manual")

    def test_interrupt_missing_source_is_unknown_and_protected(self):
        operation_id = self.interrupted("pending")
        self.compose.unlink()
        self.assertTrue(self.compose.parent.is_dir())
        self.assert_unreadable_restart_unknown_and_protected(operation_id)
        self.assertFalse(self.compose.exists())

    def test_interrupt_symlink_source_is_unknown_and_protected(self):
        operation_id = self.interrupted("pending")
        target = self.project / "operator-source.yml"
        target.write_bytes(self.desired)
        self.compose.unlink()
        self.compose.symlink_to(target)
        self.assert_unreadable_restart_unknown_and_protected(operation_id)
        self.assertTrue(self.compose.is_symlink())
        self.assertEqual(self.compose.readlink(), target)
        self.assertEqual(target.read_bytes(), self.desired)

    def test_interrupt_non_regular_source_is_unknown_and_protected(self):
        operation_id = self.interrupted("pending")
        self.compose.unlink()
        self.compose.mkdir()
        self.assert_unreadable_restart_unknown_and_protected(operation_id)
        self.assertTrue(self.compose.is_dir())
        self.assertEqual(list(self.compose.iterdir()), [])

    def test_interrupt_third_state_is_unknown_protected_and_never_written(self):
        operation_id = self.interrupted("unknown", marker=False)
        before = self.compose.read_bytes()
        operation = self.restart(operation_id)
        self.assertEqual(operation["status"], "failed")
        self.assertEqual(operation["result"]["source_state"], "unknown")
        self.assertIsNone(operation["result"]["mutation_performed"])
        self.assertTrue(operation["result"]["manual_source_recovery_required"])
        self.assertEqual(self.compose.read_bytes(), before)
        path = self.state.root / "compose-recoveries" / operation_id
        with self.state.connect() as c, checked_bundle(self.state.root, path) as bundle:
            self.assertEqual(lifecycle(c, operation_id, bundle)[0], "manual")
        with self.state.connect() as c:
            c.execute("UPDATE operation_runs SET finished_at='2000-01-01T00:00:00Z' WHERE id=?", (operation_id,))
        self.state.prune_operations()
        with self.state.connect() as c, checked_bundle(self.state.root, path) as bundle:
            self.assertEqual(lifecycle(c, operation_id, bundle)[0], "manual")
        self.assert_no_workload_commands()

    def test_interrupted_evidence_binding_or_integrity_failure_is_unknown(self):
        for corruption in ("binding", "stored", "missing"):
            with self.subTest(corruption=corruption):
                operation_id = self.interrupted("pending")
                path = self.state.root / "compose-recoveries" / operation_id
                if corruption == "binding":
                    with self.state.connect() as c:
                        summary = json.loads(c.execute("SELECT summary FROM operation_runs WHERE id=?", (operation_id,)).fetchone()[0])
                        summary["discard_evidence"] = "0" * 64
                        c.execute("UPDATE operation_runs SET summary=? WHERE id=?", (json.dumps(summary), operation_id))
                elif corruption == "stored":
                    (path / "desired-00").write_bytes(b"tampered")
                else:
                    (path / "manifest.json").unlink()
                operation = self.restart(operation_id)
                self.assertEqual(operation["result"]["source_state"], "unknown")
                self.assertTrue(operation["result"]["manual_source_recovery_required"])
                self.assertEqual(self.compose.read_bytes(), self.desired)

    def test_queued_operation_without_bundle_is_truthfully_not_started(self):
        result, _, _ = self.start()
        with self.state.connect() as c:
            c.execute("UPDATE operation_runs SET created_at='2000-01-01T00:00:00Z' WHERE id=?", (result["operation_id"],))
        operation = self.restart(result["operation_id"])
        self.assertEqual(operation["status"], "blocked")
        self.assertEqual(operation["result"]["source_state"], "not_started")

    def test_discard_reason_codes_are_specific_bounded_and_independent_of_apply(self):
        tests = ((self.desired.replace(b"# operator heading", b"# edited heading"), "source_not_isolated", True),
                 (self.desired.replace(b"restart: always", b"restart: &p always"), "unsupported_source_construct", True),
                 (self.desired.replace(b"restart: always", b"restart: always\n    init: true"), "source_layout_changed", True),
                 (self.desired.replace(b"redis:7", b"redis:8"), "project_changes", False),
                 (self.desired.replace(b"sonarr:latest", b"sonarr:other"), "image_identity_changed", False))
        for content, reason, apply in tests:
            with self.subTest(reason=reason):
                self.compose.write_bytes(content)
                status = self.status()
                self.assertEqual(status["apply_eligible"], apply)
                self.assertFalse(status["discard_eligible"])
                self.assertIn(reason, {item["code"] for item in status["discard_reasons"]})
                for item in status["discard_reasons"]:
                    self.assertEqual(item["message"], DISCARD_REASONS[item["code"]])
                self.assertNotIn(SECRET, json.dumps(status))
                with self.assertRaises(DiscardRefused):
                    self.review()
        self.compose.write_bytes(self.desired)
        with patch("docker_update_manager.webservice.verify_atomic_replace_access", side_effect=OSError(SECRET)):
            self.assertIn("source_not_writable", {item["code"] for item in self.status()["discard_reasons"]})
        from docker_update_manager.webservice import _ExecutionContextRefused
        with patch("docker_update_manager.webservice._execution_context_fingerprint", side_effect=_ExecutionContextRefused("network_unproven")):
            self.assertIn("execution_context_unproven", {item["code"] for item in self.status()["discard_reasons"]})
        (self.project / ".env").write_text("EDITED=value")
        self.assertIn("shared_input_changed", {item["code"] for item in self.status()["discard_reasons"]})
        self.state.delete_compose_baseline(self.baseline.id)
        self.assertIn("no_trusted_baseline", {item["code"] for item in self.status()["discard_reasons"]})

    def test_agent_client_reconstructs_discard_refusal_from_code_only(self):
        import io
        from docker_update_manager.agent import AgentClient
        response = {"ok": False, "type": "DiscardRefused", "reason": "source_not_isolated", "error": SECRET}
        class Socket:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def sendall(self, *_): pass
            def makefile(self, *_): return io.BytesIO(json.dumps(answers.pop(0)).encode() + b"\n")
        # The first exchange is the client's pre-mutation version probe.
        answers = [{"ok": True, "data": {"ok": True, "version": __version__}}, response]
        with patch("docker_update_manager.agent.socket.socket", return_value=Socket()):
            with self.assertRaises(DiscardRefused) as refused:
                AgentClient("/tmp/unused.sock").call("compose_reconcile_review", {})
        self.assertEqual(str(refused.exception), DISCARD_REASONS['source_not_isolated'])
        self.assertEqual(answers, [])
        self.assertNotIn(SECRET, str(refused.exception))

    def test_discard_refusal_projection_uses_only_known_codes(self):
        self.compose.write_bytes(b"# unrelated comment\n" + self.desired)
        server = AgentServer(self.agent, str(self.root / "unused.sock"), allowed_mutation_uid=12345)
        response = json.loads(server.handle_line(json.dumps({"operation": "compose_reconcile_review",
                                      "payload": {"action": "discard", "service_key": "container/" + "a" * 64,
                                                  "requested_by": "admin", "_upt_client_version": __version__},
                                      "client_version": __version__}).encode() + b"\n", peer_uid=12345))
        self.assertEqual(response["type"], "DiscardRefused")
        self.assertEqual(response["reason"], "source_not_isolated")
        self.assertEqual(response["error"], DISCARD_REASONS[response["reason"]])
        self.assertNotIn(str(self.project), json.dumps(response))
        self.assertNotIn(SECRET, json.dumps(response))
        self.assertEqual(DiscardRefused(SECRET).reason, "source_layout_unsupported")


class ComposeDiscardWebTests(unittest.TestCase):
    setUp = apply_fixtures.ComposeApplyWebTests.setUp

    def eligible(self):
        return {**apply_fixtures.ComposeApplyWebTests.eligible(self), "discard_eligible": True}

    def test_review_confirmation_exact_schema_auth_origin_csrf_and_one_use(self):
        self.agent.compose_status_data = self.eligible()
        page = self.client.get(self.url)
        self.assertIn('data-compose-discard', page.text)
        self.assertIn('Apply changes', page.text)
        review = {"csrf": self.csrf, "service_key": "container/" + "a" * 64, "action": "discard"}
        for field in ("source_path", "compose_yaml", "baseline_id", "model", "command", "requested_by", "recovery_path"):
            self.assertEqual(self.client.post('/compose/discard/review', data={**review, field: 'tampered'}).status_code, 400)
        self.assertEqual(self.client.post('/compose/discard/review', data={**review, 'action': 'apply'}).status_code, 400)
        self.assertEqual(self.client.post('/compose/discard/review', data={**review, 'csrf': 'bad'}).status_code, 403)
        self.assertEqual(self.client.post('/compose/discard/review', data=review, headers={'Origin': 'https://hostile.example'}).status_code, 403)
        page = self.client.post('/compose/discard/review', data=review)
        self.assertEqual(page.status_code, 200)
        for phrase in ('Discard changes', 'will not be recreated or restarted', 'Copy of current pending source', 'confirm-discard', 'required'):
            self.assertIn(phrase, page.text)
        self.assertNotIn(SECRET, page.text)
        confirm = {"csrf": self.csrf, "confirmation_id": "C" * 43, "confirm_apply": "yes"}
        self.assertEqual(self.client.post('/operations/compose-reconcile', data={**confirm, 'confirm_apply': 'no'}).status_code, 400)
        self.assertEqual(self.client.post('/operations/compose-reconcile', data={**confirm, 'source_path': 'tampered'}).status_code, 400)
        self.assertEqual(self.client.post('/operations/compose-reconcile', data=confirm, follow_redirects=False).status_code, 303)
        self.assertEqual(self.client.post('/operations/compose-reconcile', data=confirm, follow_redirects=False).status_code, 409)
        self.assertEqual(set(self.agent.compose_apply_calls[0]), {'confirmation_id', 'requested_by', 'client_ip', 'user_agent'})
        self.client.cookies.clear()
        self.assertEqual(self.client.post('/compose/discard/review', data=review, follow_redirects=False).status_code, 303)

    def test_discard_refusal_page_is_bounded_and_source_specific(self):
        self.agent.compose_status_data = self.eligible()
        self.agent.discard_review_refusal = "source_not_isolated"
        page = self.client.post('/compose/discard/review', data={'csrf': self.csrf, 'service_key': 'container/' + 'a' * 64,
                                                                 'action': 'discard'})
        self.assertEqual(page.status_code, 409)
        self.assertIn(DISCARD_REASONS['source_not_isolated'], page.text)
        self.assertIn('No source changes were made', page.text)
        self.assertNotIn(SECRET, page.text)
        self.agent.discard_review_refusal = None

    def test_no_baseline_never_offers_discard(self):
        self.agent.compose_status_data = {**self.eligible(), "baseline": None}
        self.assertNotIn('data-compose-discard', self.client.get(self.url).text)
        self.assertEqual(self.client.post('/compose/discard/review', data={'csrf': self.csrf, 'service_key': 'container/' + 'a' * 64,
                                                                          'action': 'discard'}).status_code, 409)

    def test_terminal_sse_reload_source_wording_parity(self):
        from docker_update_manager.operation_presentation import operation_presentation
        for status, result in (("succeeded", {}), ("blocked", {"mutation_performed": False}),
                               ("failed", {"recovered": True, "source_recovered": True}),
                               ("failed", {"manual_recovery_required": True, "manual_source_recovery_required": True})):
            with self.subTest(status=status, result=result):
                operation = {'id': 'f' * 32, 'kind': 'compose_reconcile', 'service': 'Sonarr', 'stack': 'media',
                             'service_key': 'container/' + 'a' * 64, 'status': status, 'result': {'action': 'discard', **result},
                             'error': 'Discard could not proceed safely.' if status != 'succeeded' else None,
                             'events': [], 'last_event_id': 0}
                self.agent.operation = operation
                page = self.client.get('/operations/' + 'f' * 32)
                stream = self.client.get('/operations/' + 'f' * 32 + '/events')
                event = {'succeeded': 'operation-complete', 'blocked': 'operation-blocked', 'failed': 'operation-failed'}[status]
                payload = json.loads(stream.text.split('event: ' + event + '\ndata: ', 1)[1].split('\n', 1)[0])
                view = operation_presentation(operation)
                self.assertEqual(payload['presentation'], view)
                self.assertIn(view['status_label'], page.text)
                self.assertIn('Discard configuration', page.text)
                self.assertNotIn('Apply configuration', page.text)
                self.assertNotIn('service recovered', page.text)
                self.assertNotIn(SECRET, page.text)
