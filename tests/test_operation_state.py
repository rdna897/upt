import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

os.environ.setdefault("UPT_TESTING", "1")

from docker_update_manager.state import CORE_SCHEMA_VERSION, State
from docker_update_manager.lock import Lock


class OperationStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = State(Path(self.tmp.name) / "state")

    def test_v4_database_migrates_to_v7_without_changing_history(self):
        self.state.record(service="sonarr", action="update", result="SUCCESS")
        self.state.history()
        with self.state.connect() as connection:
            connection.execute("DROP TABLE operation_events")
            connection.execute("DROP TABLE operation_runs")
            connection.execute("DROP TABLE IF EXISTS core_schema_identity")
            connection.execute("DROP TABLE IF EXISTS compose_bootstrap_fences")
            connection.execute("UPDATE schema_version SET version=4")

        with self.assertRaisesRegex(RuntimeError, "legacy schema 4"):
            State(self.state.root).history()
        migrated = State(self.state.root, quiescent_transition=True)
        self.assertEqual(migrated.history()[0]["service"], "sonarr")
        with migrated.read() as connection:
            self.assertEqual(connection.execute("SELECT version FROM schema_version").fetchone()[0], 9)
            self.assertEqual(CORE_SCHEMA_VERSION, 10)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE name='operation_runs'").fetchone()[0], "operation_runs")

    def test_operation_events_are_persisted_cursor_readable_and_terminal(self):
        operation_id = "a" * 32
        self.state.create_operation(
            operation_id, kind="update", service_key="container/abc", service="sonarr",
            stack="media", requested_by="admin", summary={"old_image": "repo:1"},
        )
        started = self.state.operation_status(operation_id)
        self.assertEqual(started["status"], "queued")
        self.assertEqual(started["events"][-1]["kind"], "operation_started")

        self.state.set_operation_running(operation_id, "Checking eligibility")
        self.state.operation_event(operation_id, "task_completed", stage="Eligibility verified",
                                   message="Verified update available", status="completed")
        cursor = self.state.operation_status(operation_id)["last_event_id"]
        self.state.operation_event(operation_id, "task_started", stage="Pull image",
                                   message="In progress", status="running")
        resumed = self.state.operation_status(operation_id, after_event_id=cursor)
        self.assertEqual([event["stage"] for event in resumed["events"]], ["Pull image"])

        self.assertTrue(self.state.finish_operation(operation_id, "succeeded", message="Service updated", result={"image": "repo:2"}))
        terminal = self.state.operation_status(operation_id, after_event_id=cursor)
        self.assertEqual(terminal["status"], "succeeded")
        self.assertEqual(terminal["result"], {"image": "repo:2"})
        self.assertEqual(terminal["events"][-1]["kind"], "operation_completed")
        with self.assertRaisesRegex(RuntimeError, "not active"):
            self.state.operation_event(operation_id, "task_started", message="late event")

    def test_active_operation_claim_is_atomic_across_competing_requests(self):
        def claim(index):
            try:
                self.state.create_operation(
                    f"{index + 1:032x}", kind="update", service_key=f"container/{index}",
                    service=f"service-{index}", stack="media", requested_by="admin", summary={},
                )
                return "claimed"
            except RuntimeError:
                return "busy"

        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(claim, range(8)))
        self.assertEqual(outcomes.count("claimed"), 1)
        self.assertEqual(outcomes.count("busy"), 7)

    def test_event_retention_is_bounded(self):
        operation_id = "b" * 32
        self.state.create_operation(operation_id, kind="update", service_key="container/abc",
                                    service="sonarr", stack="media", requested_by="admin", summary={})
        for index in range(250):
            self.state.operation_event(operation_id, "task_progress", stage="Pull image",
                                       message=f"step {index}", status="running")
        events = self.state.operation_status(operation_id)["events"]
        self.assertLessEqual(len(events), 200)
        self.assertEqual(events[-1]["message"], "step 249")

    def test_abandoned_record_recovery_requires_shared_lock_and_is_terminal(self):
        operation_id = "c" * 32
        self.state.create_operation(operation_id, kind="update", service_key="container/abc",
                                    service="sonarr", stack="media", requested_by="admin", summary={})
        with self.state.connect() as connection:
            connection.execute("UPDATE operation_runs SET started_at=datetime('now','-10 minutes') WHERE id=?", (operation_id,))
        with Lock(self.state.root / "update.lock"):
            self.assertEqual(self.state.recover_abandoned_operations(), 1)
        operation = self.state.operation_status(operation_id)
        self.assertEqual(operation["status"], "failed")
        self.assertIn("Agent stopped", operation["error"])
        self.assertEqual(operation["events"][-1]["kind"], "operation_failed")
        self.assertEqual(self.state.audit_events(1)[0]["result"], "interrupted")


if __name__ == "__main__":
    unittest.main()
