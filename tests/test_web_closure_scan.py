"""Closure-pass coverage: cached state, scan lifecycle, reconnect and classification."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import os
import json
import sqlite3
import re
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import time
import unittest
from unittest import mock

os.environ.setdefault("UPT_TESTING", "1")
from pathlib import Path

from fastapi.testclient import TestClient

from docker_update_manager.auth import new_token, token_hash, utc_after
from docker_update_manager.config import Config, WebConfig
from docker_update_manager.models import Service
from docker_update_manager.state import State
from docker_update_manager.webapp import create_app
from docker_update_manager.webservice import AgentServer, ReadOnlyService

CLASSIFICATIONS = ["CURRENT", "UPDATE", "DIGEST CHANGED", "PINNED", "PINNED UPDATE", "UNTRACKED DIGEST",
                   "IGNORED", "REGISTRY ERROR", "UNKNOWN"]


def make_service(name, stack="media", image="repo/app:1.0"):
    return Service(name=name, container_id=f"cid-{name}", image=image, image_id=f"sha256:{name}",
                   digest=None, version="1.0", created="2026-09-20T00:00:00+00:00",
                   architecture="amd64", state="running", health="healthy",
                   restart_policy="unless-stopped", started_at=None, stack=stack, compose_service=name)


class FakeResult:
    def __init__(self, service, status, error=None, tracking_issue=None):
        self.service, self.status, self.error = service, status, error
        self.tracking_issue = tracking_issue
        self.remote_digest = None
        self.remote_version = None
        self.remote_created = None


class FakeAgent:
    def __init__(self, snapshot):
        self.snapshot = snapshot

    def call(self, operation, payload=None):
        if operation == "health": return {"ok": True, "docker": {"ok": True}}
        if operation == "snapshot": return self.snapshot
        if operation == "service":
            for item in self.snapshot.get("payload", {}).get("services", []):
                if item["service"]["key"] == (payload or {}).get("service_key"):
                    return item
            raise RuntimeError("service not found")
        if operation == "audit_recent": return {"events": []}
        if operation == "scan_start": return {"run_id": "run-1", "status": "running"}
        if operation == "scan_status": return {"id": "run-1", "status": "complete", "events": []}
        raise AssertionError(operation)


class ScanClosureTests(unittest.TestCase):
    def make_state(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        return root, Config(path=str(root / "config.yml")), State(root / "state")

    def make_service_boundary(self):
        root, config, state = self.make_state()
        return root, config, state, ReadOnlyService(config, state, web_settings={"scan_retention_days": 30, "audit_retention_days": 365})

    def wait_for_terminal(self, service, run_id, timeout=15.0):
        """Wait for the worker to finish and its terminal state to persist."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            run = service.scan_status(run_id)
            if run.get("status") not in ("running", "finalizing", None) and run_id not in service._threads:
                return run
            time.sleep(0.02)
        self.fail(f"scan {run_id} did not reach a terminal state")

    def run_scan(self, service, results, services):
        def fake_scan(found, tracking):
            item = results[found.key]
            if isinstance(item, Exception):
                raise item
            return item
        with mock.patch("docker_update_manager.webservice.discover", return_value=services),              mock.patch("docker_update_manager.webservice.scan_service_with_tracking", side_effect=fake_scan):
            started = service.start_scan()
            return self.wait_for_terminal(service, started["run_id"])

    def test_worker_persists_discovered_total_and_authoritative_counts_on_service_events(self):
        _, _, state, service = self.make_service_boundary()
        services = [make_service(f"service-{index}") for index in range(17)]
        results = {item.key: FakeResult(item, "CURRENT") for item in services}
        results[services[0].key] = RuntimeError("registry request timed out")
        original_scan_event = state.scan_event

        def fake_scan(found, tracking):
            result = results[found.key]
            if isinstance(result, Exception):
                raise result
            return result

        def check_discovery_order(run_id, kind, **kwargs):
            if kind == "discovery_completed":
                self.assertEqual(state.scan_run_summary(run_id)["total"], 17)
            return original_scan_event(run_id, kind, **kwargs)

        with mock.patch("docker_update_manager.webservice.discover", return_value=services), \
             mock.patch("docker_update_manager.webservice.scan_service_with_tracking",
                        side_effect=fake_scan), \
             mock.patch.object(state, "scan_event", side_effect=check_discovery_order):
            started = service.start_scan()
            run = self.wait_for_terminal(service, started["run_id"])

        self.assertEqual((run["status"], run["completed"], run["total"]), ("partial", 17, 17))
        discovery = next(event for event in run["events"] if event["kind"] == "discovery_completed")
        self.assertEqual(discovery["payload"], {"count": 17, "total": 17, "completed": 0})
        checked = [event for event in run["events"] if event["kind"] in {"task_completed", "task_failed"}]
        self.assertEqual([event["payload"]["completed"] for event in checked], list(range(1, 18)))
        self.assertTrue(all(event["payload"]["total"] == 17 for event in checked))
        self.assertEqual(checked[0]["kind"], "task_failed")
        self.assertEqual(checked[0]["status"], "REGISTRY ERROR")

    def test_cached_pages_do_not_run_discovery_or_registry(self):
        """Overview/Services/Detail must render cached state with no live queries.

        The application talks to the real read-only service boundary (not a
        stub), so a regression that triggered discovery or registry work while
        rendering would raise here.
        """
        root, config, state, service = self.make_service_boundary()
        results = {"sonarr": FakeResult(make_service("sonarr"), "UPDATE")}
        self.run_scan(service, results, [make_service("sonarr")])

        class ServiceAgent:
            def call(self, operation, payload=None):
                return service.handle(operation, payload or {})

        client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), state, ServiceAgent()))
        code = new_token()
        state.create_credential("bootstrap", token_hash(code), utc_after(minutes=15))
        page = client.get("/setup")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        client.post("/setup", data={"csrf": csrf, "bootstrap": code, "username": "admin",
                                    "password": "correct horse battery staple",
                                    "password_confirm": "correct horse battery staple"})
        page = client.get("/login")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        client.post("/login", data={"csrf": csrf, "username": "admin", "password": "correct horse battery staple"})

        with mock.patch("docker_update_manager.webservice.discover", side_effect=AssertionError("discovery must not run")),              mock.patch("docker_update_manager.webservice.scan_service_with_tracking", side_effect=AssertionError("registry must not run")):
            overview = client.get("/")
            services = client.get("/services")
            detail = client.get("/services/sonarr")
        self.assertEqual(overview.status_code, 200)
        self.assertIn("sonarr", overview.text)
        self.assertEqual(services.status_code, 200)
        self.assertIn("sonarr", services.text)
        self.assertEqual(detail.status_code, 200)
        self.assertIn("sonarr", detail.text)

    def test_never_scanned_state_is_stable(self):
        _, _, state, service = self.make_service_boundary()
        self.assertIsNone(state.latest_scan())
        self.assertEqual(service.snapshot(), {"status": "never", "payload": {"services": [], "count": 0}})
        self.assertIsNone(state.latest_scan())

    def test_completed_scan_persists_snapshot_across_instances(self):
        root, config, state, service = self.make_service_boundary()
        services = [make_service("sonarr"), make_service("radarr")]
        results = {s.key: FakeResult(s, "UPDATE") for s in services}
        run = self.run_scan(service, results, services)
        self.assertEqual(run["status"], "complete")
        stored = State(root / "state").latest_scan()
        self.assertEqual(stored["payload"]["count"], 2)
        self.assertEqual(stored["status"], "complete")

    def test_partial_registry_failure_is_not_current(self):
        _, _, state, service = self.make_service_boundary()
        services = [make_service("sonarr"), make_service("radarr")]
        good = self.run_scan(service, {s.key: FakeResult(s, "CURRENT") for s in services}, services)
        cached_before = state.latest_scan()
        results = {"sonarr": FakeResult(services[0], "CURRENT"), "radarr": RuntimeError("registry rate limit reached")}
        run = self.run_scan(service, results, services)
        self.assertEqual(run["status"], "partial")
        cached_after = state.latest_scan()
        self.assertEqual(cached_after["scan_id"], good["id"])
        self.assertEqual(cached_after["finished_at"], cached_before["finished_at"])
        self.assertEqual(cached_after["payload"], cached_before["payload"])
        with state.read() as connection:
            rows = connection.execute("SELECT payload FROM service_snapshots WHERE scan_id=?", (run["id"],)).fetchall()
        by_name = {item["service"]["name"]: item for item in (json.loads(row[0]) for row in rows)}
        self.assertEqual(by_name["radarr"]["status"], "REGISTRY ERROR")
        self.assertEqual(by_name["sonarr"]["status"], "CURRENT")

    def test_duplicate_scan_starts_converge_on_one_run(self):
        _, _, state, service = self.make_service_boundary()
        first = state.claim_scan("run-a")
        second = state.claim_scan("run-b")
        self.assertFalse(first["existing"])
        self.assertTrue(second["existing"])
        self.assertEqual(second["run_id"], "run-a")
        state.finish_scan("run-a", "complete", services=[])

    def test_stale_heartbeat_recovery_is_deterministic(self):
        from datetime import datetime as RealDateTime, timezone

        _, _, state, _ = self.make_service_boundary()

        class FixedDateTime:
            current = RealDateTime(2026, 9, 24, 18, 0, 0, 500_000, tzinfo=timezone.utc)

            @classmethod
            def now(cls, tz=None):
                return cls.current.astimezone(tz) if tz else cls.current

            @staticmethod
            def fromisoformat(value):
                return RealDateTime.fromisoformat(value)

        # A one-second timeout is intentional here, so hold both lease checks
        # at a fixed half-second phase instead of racing the wall-clock second
        # boundary against the persisted whole-second heartbeat format.
        with mock.patch("docker_update_manager.state.datetime", FixedDateTime):
            state.claim_scan("run-a")
            with state.connect() as c:
                c.execute("UPDATE scan_runs SET heartbeat_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", "run-a"))
            replacement = state.claim_scan("run-b", stale_after_seconds=1)
            self.assertFalse(replacement["existing"])
            self.assertEqual(replacement["run_id"], "run-b")
            self.assertEqual(state.scan_run("run-a")["status"], "failed")
            # run-b is deterministically fresh; run-c is deterministically stale.
            self.assertEqual(state.recover_stale_scans(stale_after_seconds=1), 0)
            state.finish_scan("run-b", "complete", services=[])
            state.claim_scan("run-c")
            with state.connect() as c:
                c.execute("UPDATE scan_runs SET heartbeat_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", "run-c"))
            self.assertEqual(state.recover_stale_scans(stale_after_seconds=1), 1)
            self.assertEqual(state.scan_run("run-c")["status"], "failed")

    def test_stale_worker_cannot_replace_snapshot_after_lease_is_reclaimed(self):
        _, _, state, _ = self.make_service_boundary()
        state.claim_scan("old-run")
        with state.connect() as connection:
            connection.execute("UPDATE scan_runs SET heartbeat_at=? WHERE id='old-run'", ("2000-01-01T00:00:00+00:00",))
        self.assertFalse(state.claim_scan("new-run", stale_after_seconds=1)["existing"])
        with self.assertRaisesRegex(RuntimeError, "no longer owns"):
            state.stage_scan_result("old-run", "complete", services=[{"service": {"key": "stale"}, "status": "CURRENT"}])
        self.assertIsNone(state.latest_scan())
        with state.read() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM service_snapshots WHERE scan_id='old-run'").fetchone()[0], 0)
        state.finish_scan("new-run", "complete", services=[])

    def test_duplicate_discovered_service_keys_do_not_strand_scan(self):
        _, _, state, service = self.make_service_boundary()
        first = make_service("duplicate")
        second = make_service("duplicate")
        second.container_id = "cid-duplicate-second"
        with mock.patch("docker_update_manager.webservice.discover", return_value=[first, second]), \
             mock.patch("docker_update_manager.webservice.scan_service_with_tracking", side_effect=lambda found, tracking: FakeResult(found, "CURRENT")):
            started = service.start_scan()
            run = self.wait_for_terminal(service, started["run_id"])
        self.assertEqual(run["status"], "complete")
        self.assertEqual(state.latest_scan()["payload"]["count"], 2)
        public = state.latest_scan()["payload"]["services"]
        self.assertEqual(len({item["service"]["key"] for item in public}), 2)
        for item in public:
            self.assertEqual(service.service(item["service"]["key"])["service"]["container_id"], item["service"]["container_id"])
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            service.service("duplicate")
        with state.read() as connection:
            keys = [row[0] for row in connection.execute(
                "SELECT service_key FROM service_snapshots WHERE scan_id=? ORDER BY service_key", (started["run_id"],))]
        self.assertEqual(len(set(keys)), 2)

    def test_long_service_name_still_has_bounded_distinct_detail_key(self):
        from docker_update_manager.webservice import _public_result
        _, _, state, service = self.make_service_boundary()
        long_name = "service-" + "x" * 230
        found = make_service(long_name)
        found.container_id = "a" * 64
        item = _public_result(FakeResult(found, "CURRENT"))
        key = item["service"]["key"]
        self.assertLess(len(key), 200)
        state.start_scan("long-name", total=1)
        state.finish_scan("long-name", "complete", services=[item])
        self.assertEqual(service.service(key)["service"]["container_id"], found.container_id)

    def test_snapshot_write_failure_falls_back_to_terminal_failed_run(self):
        _, _, state, service = self.make_service_boundary()
        found = [make_service("sonarr")]
        original = state.stage_scan_result

        def fail_complete(run_id, status, **kwargs):
            if kwargs.get("services"):
                raise sqlite3.IntegrityError("fixture write failure")
            return original(run_id, status, **kwargs)

        with mock.patch("docker_update_manager.webservice.discover", return_value=found), \
             mock.patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=FakeResult(found[0], "CURRENT")), \
             mock.patch.object(state, "stage_scan_result", side_effect=fail_complete), \
             self.assertLogs("docker_update_manager.webservice", level="ERROR"):
            started = service.start_scan()
            run = self.wait_for_terminal(service, started["run_id"])
        self.assertEqual(run["status"], "failed")
        self.assertIsNotNone(run["finished_at"])
        self.assertTrue(any(event["kind"] == "operation_failed" for event in run["events"]))

    def test_second_state_instance_cannot_reclaim_live_finalizing_worker(self):
        _, _, first, _ = self.make_service_boundary()
        second = State(first.root)
        first.claim_scan("first-run")
        with first.scan_worker_guard():
            first.stage_scan_result("first-run", "partial", services=[])
            with first.connect() as connection:
                connection.execute("UPDATE scan_runs SET heartbeat_at=? WHERE id='first-run'", ("2000-01-01T00:00:00+00:00",))
            claim = second.claim_scan("second-run", stale_after_seconds=1)
            self.assertTrue(claim["existing"])
            self.assertEqual(claim["run_id"], "first-run")
            self.assertEqual(claim["status"], "finalizing")
            self.assertEqual(second.recover_stale_scans(stale_after_seconds=1), 0)
        claim = second.claim_scan("second-run", stale_after_seconds=1)
        self.assertFalse(claim["existing"])
        self.assertEqual(first.scan_run("first-run")["status"], "failed")
        second.finish_scan("second-run", "complete", services=[])

    def test_worker_lock_failure_is_promptly_terminal_and_thread_is_released(self):
        _, _, state, service = self.make_service_boundary()
        with mock.patch.object(state, "scan_worker_guard", side_effect=OSError("lock unavailable")):
            with self.assertLogs("docker_update_manager.webservice", level="ERROR"):
                started = service.start_scan()
                run = self.wait_for_terminal(service, started["run_id"])
        self.assertEqual(run["status"], "failed")
        self.assertEqual(run["error"], "scan worker lease unavailable")
        self.assertIsNotNone(run["finished_at"])
        self.assertTrue(any(event["kind"] == "operation_failed" for event in run["events"]))
        self.assertNotIn(started["run_id"], service._threads)

    def test_browser_disconnect_does_not_cancel_scan_and_reconnect_recovers_state(self):
        _, _, _, service = self.make_service_boundary()
        services = [make_service("sonarr")]
        results = {"sonarr": FakeResult(services[0], "DIGEST CHANGED")}
        with mock.patch("docker_update_manager.webservice.discover", return_value=services),              mock.patch("docker_update_manager.webservice.scan_service_with_tracking", side_effect=lambda found, tracking: results[found.key]):
            started = service.start_scan()
            # Simulate a client that disconnects immediately after starting.
            run = self.wait_for_terminal(service, started["run_id"])
        self.assertEqual(run["status"], "complete")
        reconnected = service.scan_status(started["run_id"])
        self.assertEqual(reconnected["status"], "complete")
        self.assertTrue(any(e["kind"] == "operation_completed" for e in reconnected["events"]))
        self.assertEqual(service.snapshot()["payload"]["count"], 1)

    def test_failed_new_scan_preserves_previous_snapshot(self):
        _, _, state, _ = self.make_service_boundary()
        previous = [{"service": {"key": "media/sonarr", "name": "sonarr"}, "status": "CURRENT"}]
        state.start_scan("run-1")
        state.finish_scan("run-1", "complete", services=previous)
        state.start_scan("run-2")
        state.finish_scan("run-2", "failed", error="discovery failed", services=[])
        snapshot = state.latest_scan()
        self.assertEqual(snapshot["payload"]["count"], 1)
        self.assertEqual(snapshot["payload"]["services"][0]["status"], "CURRENT")
        self.assertEqual(snapshot["status"], "complete")
        self.assertEqual(snapshot["scan_id"], "run-1")
        self.assertIsNotNone(snapshot["finished_at"])
        self.assertEqual(state.latest_scan_run()["status"], "failed")

    def test_post_scan_housekeeping_faults_do_not_relabel_completed_snapshot(self):
        for failing_stage, warning_fragment in (("progress_event", "progress reporting"), ("audit", "audit logging"), ("web_prune", "retention cleanup"),
                                                ("compact_if_needed", "database compaction"), ("final_event", "Completed scan progress")):
            with self.subTest(stage=failing_stage):
                _, _, state, service = self.make_service_boundary()
                services = [make_service("sonarr")]
                patches = [mock.patch("docker_update_manager.webservice.discover", return_value=services),
                           mock.patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=FakeResult(services[0], "CURRENT"))]
                if failing_stage == "progress_event":
                    original = state.scan_event
                    def fail_progress(run_id, kind, **kwargs):
                        if kind == "finalization_started":
                            raise OSError("event store unavailable")
                        return original(run_id, kind, **kwargs)
                    patches.append(mock.patch.object(state, "scan_event", side_effect=fail_progress))
                elif failing_stage == "final_event":
                    original = state.mark_scan_terminal
                    def fail_terminal(run_id, status, **kwargs):
                        if kwargs.get("emit_event", True):
                            raise OSError("event store unavailable")
                        return original(run_id, status, **kwargs)
                    patches.append(mock.patch.object(state, "mark_scan_terminal", side_effect=fail_terminal))
                else:
                    patches.append(mock.patch.object(state, failing_stage, side_effect=OSError("maintenance busy")))
                with patches[0], patches[1], patches[2], self.assertLogs("docker_update_manager.webservice", level="WARNING"):
                    started = service.start_scan()
                    run = self.wait_for_terminal(service, started["run_id"])
                self.assertEqual(run["status"], "complete")
                self.assertIn(warning_fragment, run["maintenance_warning"])
                self.assertEqual(state.latest_scan()["scan_id"], started["run_id"])
                self.assertEqual(state.latest_scan()["status"], "complete")

    def test_untracked_digest_pin_is_explicit_without_guessing_a_channel(self):
        from docker_update_manager.webservice import _public_result
        service = make_service("digest-pinned", image="repo/app@sha256:deadbeef")
        result = FakeResult(service, "PINNED", "digest pin has no recorded tracking tag; no release channel was guessed", "missing_channel")
        public = _public_result(result)
        self.assertEqual(public["status"], "UNTRACKED DIGEST")
        self.assertIn("No trusted tracking tag", public["error"])
        self.assertIsNone(public["remote_version"])

    def test_live_untracked_digest_classification_matches_persisted_result(self):
        _, _, state, service = self.make_service_boundary()
        pinned = make_service("digest-pinned", image="repo/app@sha256:deadbeef")
        with mock.patch("docker_update_manager.webservice.discover", return_value=[pinned]), \
             mock.patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=FakeResult(
                 pinned, "UNTRACKED DIGEST", "digest pin has no trusted tracking tag; no release channel was guessed", "missing_channel")):
            started = service.start_scan()
            run = self.wait_for_terminal(service, started["run_id"])
        live = next(event for event in run["events"] if event["kind"] == "task_completed")
        self.assertEqual(live["status"], "UNTRACKED DIGEST")
        self.assertEqual(live["message"], "UNTRACKED DIGEST")
        self.assertEqual(live["payload"]["tracking_issue"], "missing_channel")
        self.assertEqual(state.latest_scan()["payload"]["services"][0]["status"], live["status"])
        self.assertEqual(state.latest_scan()["payload"]["services"][0]["tracking_issue"], live["payload"]["tracking_issue"])

    def test_finalization_keeps_scan_claim_and_sse_nonterminal_until_housekeeping_ends(self):
        root, _, state, service = self.make_service_boundary()
        found = [make_service("sonarr")]
        entered, release = threading.Event(), threading.Event()
        original_audit = state.audit

        def held_audit(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(30), "test housekeeping gate timed out")
            return original_audit(*args, **kwargs)

        user_id = state.create_user("admin", "unused")
        session_id = state.create_session(user_id, new_token(), utc_after(minutes=30), utc_after(hours=1), "127.0.0.1", "test")
        polled = threading.Event()

        class ServiceAgent:
            def call(self, operation, payload=None):
                if operation == "scan_status" and (payload or {}).get("run_id"):
                    polled.set()
                return service.handle(operation, payload or {})

        client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), state, ServiceAgent()))
        client.cookies.set("upt_session", session_id)
        with mock.patch("docker_update_manager.webservice.discover", return_value=found), \
             mock.patch("docker_update_manager.webservice.scan_service_with_tracking", return_value=FakeResult(found[0], "CURRENT")), \
             mock.patch.object(state, "audit", side_effect=held_audit), ThreadPoolExecutor(max_workers=1) as pool:
            started = service.start_scan()
            try:
                self.assertTrue(entered.wait(5))
                stream = pool.submit(client.get, f"/scan/{started['run_id']}/events")
                self.assertTrue(polled.wait(10))
                run = service.scan_status(started["run_id"])
                self.assertEqual(run["status"], "finalizing")
                self.assertIsNone(run["finished_at"])
                self.assertFalse(any(event["kind"] == "operation_completed" for event in run["events"]))
                self.assertEqual(service.start_scan()["run_id"], started["run_id"])
                self.assertEqual(state.active_scan()["id"], started["run_id"])
                self.assertEqual(state.latest_scan()["payload"]["count"], 1)
                with state.connect() as connection:
                    connection.execute("UPDATE scan_runs SET heartbeat_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", started["run_id"]))
                self.assertEqual(service.start_scan()["run_id"], started["run_id"])
                self.assertEqual(client.get(f"/api/scan/{started['run_id']}").json()["status"], "finalizing")
                self.assertFalse(stream.done(),
                                 f"SSE must not terminate during housekeeping: {stream.result().text[:300] if stream.done() else ''}")
            finally:
                release.set()
            done = self.wait_for_terminal(service, started["run_id"])
            streamed = stream.result(timeout=5).text
        self.assertEqual(done["status"], "complete")
        self.assertEqual([event["kind"] for event in done["events"]].count("operation_completed"), 1)
        self.assertIn("event: scan-complete", streamed)
        self.assertNotIn("event: scan-failed", streamed)

    def test_latest_partial_attempt_has_bounded_diagnostics(self):
        _, _, state, service = self.make_service_boundary()
        found = [make_service(f"svc-{index}") for index in range(8)]
        with mock.patch("docker_update_manager.webservice.discover", return_value=found), \
             mock.patch("docker_update_manager.webservice.scan_service_with_tracking", side_effect=RuntimeError("registry rate limit reached")):
            started = service.start_scan()
            self.wait_for_terminal(service, started["run_id"])
        summary = state.latest_scan_run()
        self.assertEqual(summary["status"], "partial")
        self.assertEqual(len(summary["diagnostics"]), 5)
        self.assertTrue(all(item["status"] == "REGISTRY ERROR" for item in summary["diagnostics"]))

    def test_pruned_scan_is_a_typed_not_found_not_a_generic_failure(self):
        class MissingScanService:
            def handle(self, operation, payload):
                raise ValueError("scan operation not found")
        response = __import__("json").loads(AgentServer(MissingScanService(), "/tmp/unused.sock").handle_line(
            b'{"operation":"scan_status","payload":{"run_id":"pruned"}}\n'))
        self.assertFalse(response["ok"])
        self.assertEqual(response["type"], "AgentNotFound")

    def test_classification_values_round_trip(self):
        _, _, state, _ = self.make_service_boundary()
        services = [{"service": {"key": f"media/svc{index}", "name": f"svc{index}"}, "status": status}
                    for index, status in enumerate(CLASSIFICATIONS)]
        state.start_scan("run-classify")
        state.finish_scan("run-classify", "complete", services=services)
        stored = {item["service"]["key"]: item["status"] for item in state.latest_scan()["payload"]["services"]}
        self.assertEqual(sorted(stored.values()), sorted(CLASSIFICATIONS))


if __name__ == "__main__":
    unittest.main()
