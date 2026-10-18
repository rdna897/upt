import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import os
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("UPT_TESTING", "1")

from fastapi.testclient import TestClient

from docker_update_manager.agent import AgentNotFound
from docker_update_manager.auth import new_token, utc_after
from docker_update_manager.config import Config, WebConfig
from docker_update_manager.state import CORE_SCHEMA_VERSION, State
from docker_update_manager.webapp import create_app, relative_time, utc_timestamp
from docker_update_manager.webservice import ReadOnlyService
from docker_update_manager.webstate import WEB_SCHEMA_VERSION, WebState


class PersistenceHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = State(Path(self.tmp.name) / "state")

    def test_migrations_run_once_per_state_instance_not_on_each_read(self):
        calls = []
        migrate = self.state._migrate

        def counted(connection, **options):
            calls.append(1)
            migrate(connection, **options)

        self.state._migrate = counted
        self.assertIsNone(self.state.latest_scan())
        self.state.audit_events()
        self.state.history()
        self.assertEqual(len(calls), 1)

    def test_disappearing_sqlite_sidecar_does_not_break_concurrent_reads(self):
        real_chmod = os.chmod

        def disappearing_sidecar(path, mode):
            if str(path).endswith("-shm"):
                raise FileNotFoundError(str(path))
            return real_chmod(path, mode)

        with patch("docker_update_manager.state.os.chmod", side_effect=disappearing_sidecar):
            self.assertIsNone(self.state.latest_scan())
            self.assertEqual(self.state.audit_events(), [])

    def test_concurrent_reads_do_not_wait_for_an_unrelated_writer(self):
        self.state.latest_scan()  # initialize schema and WAL before contention
        writer = sqlite3.connect(self.state.db_path, timeout=1, isolation_level=None)
        self.addCleanup(writer.close)
        writer.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        try:
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: self.state.latest_scan(), range(16)))
            elapsed = time.monotonic() - started
        finally:
            writer.rollback()
        self.assertTrue(all(item is None for item in results))
        self.assertLess(elapsed, 1.0)

    def test_scan_event_cursor_returns_only_new_persisted_events(self):
        self.state.start_scan("cursor-run", total=1)
        self.state.scan_event("cursor-run", "discovery_completed", payload={"count": 1, "total": 1}, completed=0)
        self.state.scan_event("cursor-run", "task_started", service="media/sonarr", payload={"total": 1}, completed=0)
        before = self.state.scan_run("cursor-run")
        cursor = before["events"][0]["id"]
        self.state.scan_event("cursor-run", "task_failed", service="media/sonarr", status="REGISTRY ERROR", payload={"total": 1}, completed=1)
        resumed = self.state.scan_run("cursor-run", after_event_id=cursor)
        self.assertEqual([event["kind"] for event in resumed["events"]], ["task_started", "task_failed"])
        self.assertEqual([event["payload"]["completed"] for event in before["events"]], [0, 0])
        self.assertEqual(resumed["events"][-1]["payload"], {"total": 1, "completed": 1})
        self.assertEqual(resumed["completed"], 1)

    def test_discovery_total_is_persisted_before_event_and_non_success_counts(self):
        self.state.start_scan("seventeen-run")
        self.state.set_scan_total("seventeen-run", 17)
        discovered = self.state.scan_run_summary("seventeen-run")
        self.assertEqual((discovered["completed"], discovered["total"]), (0, 17))
        self.state.scan_event("seventeen-run", "discovery_completed", payload={"count": 17, "total": 17}, completed=0)
        self.state.scan_event("seventeen-run", "task_started", service="media/failed", payload={"index": 1, "total": 17}, completed=0)
        self.state.scan_event("seventeen-run", "task_failed", service="media/failed", status="REGISTRY ERROR", payload={"index": 1, "total": 17}, completed=1)
        run = self.state.scan_run("seventeen-run")
        self.assertEqual((run["completed"], run["total"]), (1, 17))
        failed = run["events"][-1]
        self.assertEqual(failed["status"], "REGISTRY ERROR")
        self.assertEqual(failed["payload"]["completed"], 1)
        self.assertEqual(failed["payload"]["total"], 17)

    def test_failed_scan_does_not_claim_all_services_completed(self):
        self.state.start_scan("failed-run", total=4)
        self.state.scan_event("failed-run", "task_completed", service="one", completed=1)
        self.state.finish_scan("failed-run", "failed", error="test failure", services=[])
        run = self.state.scan_run("failed-run")
        self.assertEqual(run["completed"], 1)
        self.assertEqual(run["total"], 4)
        self.assertEqual(run["status"], "failed")

    def test_latest_scan_status_is_the_newest_attempt_and_keeps_only_event_tail(self):
        self.state.start_scan("good-run")
        self.state.finish_scan("good-run", "complete", services=[{"service": {"key": "media/a"}, "status": "CURRENT"}])
        self.state.start_scan("failed-run", total=20)
        for index in range(10):
            self.state.scan_event("failed-run", "task_completed", service=f"svc-{index}", completed=index + 1)
        self.state.finish_scan("failed-run", "failed", error="registry query failed", services=[])
        self.state.scan_event("failed-run", "operation_failed", status="failed", message="registry query failed")

        latest = self.state.latest_scan_run()

        self.assertEqual(latest["id"], "failed-run")
        self.assertEqual(latest["status"], "failed")
        self.assertEqual(latest["error"], "registry query failed")
        self.assertEqual(len(latest["events"]), 6)
        self.assertEqual(latest["events"][-1]["kind"], "operation_failed")
        self.assertEqual(latest["last_event_id"], latest["events"][-1]["id"])

    def test_schema_upgrade_repairs_legacy_failed_snapshot_pointer(self):
        self.state.start_scan("good", total=1)
        good_services = [{"service": {"key": "good-service"}, "status": "CURRENT"}]
        self.state.finish_scan("good", "complete", services=good_services)
        self.state.start_scan("bad")
        self.state.finish_scan("bad", "failed", error="old defect", services=[])
        # Simulate a v3 database written by the old implementation, which
        # incorrectly pointed latest_scan at the failed attempt.
        with self.state.connect() as connection:
            connection.execute("UPDATE latest_scan SET scan_id='bad',status='failed',finished_at=(SELECT finished_at FROM scan_runs WHERE id='bad') WHERE singleton=1")
            connection.execute("DROP TABLE IF EXISTS core_schema_identity")
            connection.execute("DROP TABLE IF EXISTS compose_bootstrap_fences")
            connection.execute("UPDATE schema_version SET version=3")
            connection.execute("ALTER TABLE scan_runs DROP COLUMN maintenance_warning")
        with self.assertRaisesRegex(RuntimeError, "legacy schema 3"):
            State(self.state.root).latest_scan()
        repaired = State(self.state.root, quiescent_transition=True).latest_scan()
        self.assertEqual(repaired["scan_id"], "good")
        self.assertEqual(repaired["status"], "complete")
        self.assertEqual(repaired["payload"]["services"], good_services)

    def test_schema_upgrade_does_not_trust_unknown_inventory_size(self):
        self.state.start_scan("candidate", total=0)
        self.state.finish_scan("candidate", "complete", services=[{"service": {"key": "subset"}, "status": "CURRENT"}])
        self.state.start_scan("bad")
        self.state.finish_scan("bad", "failed", error="old defect", services=[])
        with self.state.connect() as connection:
            connection.execute("UPDATE latest_scan SET scan_id='bad',status='failed',finished_at=(SELECT finished_at FROM scan_runs WHERE id='bad') WHERE singleton=1")
            connection.execute("DROP TABLE IF EXISTS core_schema_identity")
            connection.execute("DROP TABLE IF EXISTS compose_bootstrap_fences")
            connection.execute("UPDATE schema_version SET version=3")
            connection.execute("ALTER TABLE scan_runs DROP COLUMN maintenance_warning")
        repaired = State(self.state.root, quiescent_transition=True).latest_scan()
        self.assertEqual(repaired["status"], "stale")
        self.assertIsNone(repaired["finished_at"])

    def test_core_and_web_schema_versions_are_explicit_and_web_v3_upgrade_preserves_data(self):
        self.assertEqual(CORE_SCHEMA_VERSION, 10)
        self.assertEqual(WEB_SCHEMA_VERSION, 4)
        web = WebState(Path(self.tmp.name) / "web-state")
        user_id = web.create_user("admin", "hash-only")
        web.ensure_compatible()  # Core schema identity must not leak into web state.
        web.start_scan("old-good", total=1)
        web.finish_scan("old-good", "complete", services=[{"service": {"key": "svc"}, "status": "CURRENT"}])
        web.start_scan("old-bad")
        web.finish_scan("old-bad", "failed", services=[])
        with web.connect() as connection:
            connection.execute("UPDATE latest_scan SET scan_id='old-bad',status='failed',finished_at=(SELECT finished_at FROM scan_runs WHERE id='old-bad') WHERE singleton=1")
            connection.execute("UPDATE schema_version SET version=3")
            connection.execute("ALTER TABLE scan_runs DROP COLUMN maintenance_warning")
        migrated = WebState(web.root)
        self.assertEqual(migrated.latest_scan()["scan_id"], "old-good")
        self.assertEqual(migrated.web_user()["id"], user_id)
        migrated.add_scan_maintenance_warning("old-good", "bounded warning")
        self.assertEqual(migrated.scan_run("old-good")["maintenance_warning"], "bounded warning")
        with migrated.read() as connection:
            version = connection.execute("SELECT version FROM schema_version").fetchone()[0]
            self.assertEqual(version, WEB_SCHEMA_VERSION)
            self.assertFalse(connection.execute("SELECT name FROM sqlite_master WHERE name='history'").fetchone())
            self.assertFalse(connection.execute("SELECT name FROM sqlite_master WHERE name='compose_recovery_receipts'").fetchone())

    def test_future_core_and_web_schema_versions_fail_closed(self):
        for state_type, name in ((State, "core"), (WebState, "web")):
            with self.subTest(name=name):
                instance = state_type(Path(self.tmp.name) / name)
                instance.latest_scan()
                with instance.connect() as connection:
                    connection.execute("UPDATE schema_version SET version=99")
                with self.assertRaisesRegex(RuntimeError, "unsupported"):
                    state_type(instance.root).latest_scan()


class PresentationAndAgentTests(unittest.TestCase):
    def test_relative_time_is_compact_and_keeps_unknown_explicit(self):
        now = datetime(2026, 9, 22, 21, 43, tzinfo=timezone.utc)
        self.assertEqual(relative_time("2026-09-22T21:42:00+00:00", now=now), "1 min ago")
        self.assertEqual(relative_time("2026-09-22T18:00:00+00:00", now=now), "Today, 18:00 UTC")
        self.assertEqual(relative_time(None, now=now), "Unknown")
        self.assertEqual(utc_timestamp("2026-09-22 18:00:00"), "2026-09-22T18:00:00+00:00")

    def test_health_liveness_does_not_run_docker_inline(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = ReadOnlyService(Config(path=str(Path(tmp) / "config.yml")), State(Path(tmp) / "state"))
            with patch.object(service, "_docker_health") as probe:
                response = service.health()
            probe.assert_not_called()
        self.assertTrue(response["ok"])
        self.assertIsNone(response["docker"]["ok"])


class ScanResumeRouteTests(unittest.TestCase):
    def test_sse_honours_last_event_id_and_sends_final_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WebState(root / "web-state")
            user_id = state.create_user("admin", "not-used-by-this-test")
            session_id = state.create_session(
                user_id, new_token(), utc_after(minutes=30), utc_after(hours=1),
                "127.0.0.1", "browser-test",
            )
            state.start_scan("resume-run")
            state.set_scan_total("resume-run", 1)
            state.scan_event("resume-run", "discovery_completed", payload={"count": 1, "total": 1}, completed=0)
            run = state.scan_run("resume-run")
            old_cursor = run["events"][-1]["id"]
            state.scan_event("resume-run", "task_completed", service="sonarr", status="CURRENT", payload={"total": 1}, completed=1)
            state.finish_scan("resume-run", "complete", services=[])
            state.scan_event("resume-run", "operation_completed", status="complete")
            final_cursor = state.scan_run("resume-run")["events"][-1]["id"]

            class Agent:
                def call(self, operation, payload=None):
                    if operation == "scan_status":
                        request = payload or {}
                        return state.scan_run(request.get("run_id"), request.get("after_event_id", 0))
                    if operation == "snapshot":
                        return state.latest_scan() or {"status": "never", "payload": {"services": [], "count": 0}}
                    if operation == "health":
                        return {"ok": True, "docker": {"ok": True}}
                    if operation == "audit_recent":
                        return {"events": []}
                    raise AssertionError(operation)

            client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), state, Agent()))
            client.cookies.set("upt_session", session_id)
            response = client.get(
                "/scan/resume-run/events",
                headers={"Last-Event-ID": str(old_cursor)},
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn("id: " + str(final_cursor), response.text)
            self.assertNotIn("id: " + str(old_cursor) + "\n", response.text)
            self.assertIn("event: scan-complete", response.text)
            self.assertIn('"payload":{"total":1,"completed":1}', response.text)
            self.assertEqual(response.headers["x-accel-buffering"], "no")

    def test_sse_terminal_event_names_preserve_partial_and_failed_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WebState(root / "web-state")
            user_id = state.create_user("admin", "not-used-by-this-test")
            session_id = state.create_session(
                user_id, new_token(), utc_after(minutes=30), utc_after(hours=1),
                "127.0.0.1", "browser-test",
            )

            class Agent:
                def call(self, operation, payload=None):
                    if operation == "scan_status":
                        request = payload or {}
                        return state.scan_run(request.get("run_id"), request.get("after_event_id", 0))
                    if operation == "snapshot":
                        return state.latest_scan() or {"status": "never", "payload": {"services": [], "count": 0}}
                    if operation == "health":
                        return {"ok": True, "docker": {"ok": True}}
                    if operation == "audit_recent":
                        return {"events": []}
                    raise AssertionError(operation)

            client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), state, Agent()))
            client.cookies.set("upt_session", session_id)
            for status, expected in (("partial", "scan-partial"), ("failed", "scan-failed")):
                run_id = status + "-run"
                state.start_scan(run_id, total=1)
                state.finish_scan(run_id, status, error="registry query failed" if status == "failed" else None, services=[])
                response = client.get(f"/scan/{run_id}/events")
                self.assertIn("event: " + expected, response.text)
                self.assertIn('"status":"' + status + '"', response.text)

    def test_logout_password_change_and_expiry_terminate_long_lived_streams(self):
        for action in ("logout", "password", "expiry", "agent-error"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                state = WebState(root / "web-state")
                user_id = state.create_user("admin", "old-hash")
                session_id = state.create_session(user_id, new_token(), utc_after(minutes=30), utc_after(hours=1), "127.0.0.1", "browser-test")

                class RevokingAgent:
                    def call(self, operation, payload=None):
                        if operation != "scan_status":
                            raise AssertionError(operation)
                        if action == "logout":
                            state.revoke_session(session_id)
                        elif action == "password":
                            state.update_password(user_id, "replacement-hash")
                        elif action == "agent-error":
                            state.revoke_session(session_id)
                            raise RuntimeError("agent query failed after logout")
                        else:
                            with state.connect() as connection:
                                connection.execute("UPDATE web_sessions SET expires_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", session_id))
                        return {"id": "long-running", "status": "running", "events": [{"id": 1, "kind": "task_completed", "message": "must not be delivered"}]}

                client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), state, RevokingAgent()))
                client.cookies.set("upt_session", session_id)
                response = client.get("/scan/long-running/events")
                self.assertIn("event: scan-auth-expired", response.text)
                self.assertNotIn("scan-event", response.text)
                self.assertNotIn("scan-warning", response.text)
                self.assertNotIn("must not be delivered", response.text)

    def test_revocation_between_events_stops_the_rest_of_a_response_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WebState(root / "web-state")
            user_id = state.create_user("admin", "unused")
            session_id = state.create_session(user_id, new_token(), utc_after(minutes=30), utc_after(hours=1), "127.0.0.1", "browser-test")

            class BatchAgent:
                def call(self, operation, payload=None):
                    return {"id": "batch", "status": "running", "events": [
                        {"id": 1, "kind": "task_completed", "message": "first permitted event"},
                        {"id": 2, "kind": "task_completed", "message": "must not be delivered"},
                    ]}

            original_session = state.session
            checks = {"count": 0}
            def revoke_before_second_event(sid):
                checks["count"] += 1
                if checks["count"] == 5:
                    state.revoke_session(sid)
                return original_session(sid)
            state.session = revoke_before_second_event
            client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), state, BatchAgent()))
            client.cookies.set("upt_session", session_id)
            response = client.get("/scan/batch/events")
            self.assertIn("first permitted event", response.text)
            self.assertNotIn("must not be delivered", response.text)
            self.assertIn("event: scan-auth-expired", response.text)

    def test_pruned_scan_api_and_sse_are_explicit_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WebState(root / "web-state")
            user_id = state.create_user("admin", "unused")
            session_id = state.create_session(user_id, new_token(), utc_after(minutes=30), utc_after(hours=1), "127.0.0.1", "browser-test")

            class MissingAgent:
                def call(self, operation, payload=None):
                    if operation == "scan_status":
                        raise AgentNotFound("scan operation not found")
                    raise AssertionError(operation)

            client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), state, MissingAgent()))
            client.cookies.set("upt_session", session_id)
            api = client.get("/api/scan/pruned")
            self.assertEqual(api.status_code, 404)
            self.assertIn("scan is no longer available", api.json()["error"])
            self.assertNotIn("service", api.json()["error"].lower())
            stream = client.get("/scan/pruned/events")
            self.assertIn("event: scan-not-found", stream.text)
            self.assertNotIn("Agent temporarily unavailable", stream.text)

    def test_expired_before_sse_connection_gets_terminal_auth_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = WebState(root / "web-state")
            user_id = state.create_user("admin", "unused")
            session_id = state.create_session(user_id, new_token(), "2000-01-01T00:00:00+00:00", utc_after(hours=1), "127.0.0.1", "browser-test")

            class UnusedAgent:
                def call(self, operation, payload=None):
                    raise AssertionError("expired stream must not query scan data")

            client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), state, UnusedAgent()))
            client.cookies.set("upt_session", session_id)
            response = client.get("/scan/expired/events")
            self.assertEqual(response.status_code, 200)
            self.assertIn("event: scan-auth-expired", response.text)
            self.assertNotIn("location", response.headers)


if __name__ == "__main__":
    unittest.main()
