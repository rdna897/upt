"""Exact, durable service update evidence without a global scan epoch."""

import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import itertools
import json
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from docker_update_manager.config import Config
from docker_update_manager.docker import discover
from docker_update_manager.models import ScanResult, Service
from docker_update_manager.operations import ReviewedTargetChanged
from docker_update_manager.state import State
from docker_update_manager.webservice import ComposePlan, ReadOnlyService, _public_result
from docker_update_manager.webapp import STATUS_LABELS
from docker_update_manager.webviews import merge_service_items


class ServiceVerificationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = State(self.root / "state")
        self.agent = ReadOnlyService(Config(path=str(self.root / "config.yml")), self.state)
        self.old = self.service("a" * 64)
        self.new = self.service("b" * 64)
        # These tests cover registry verification evidence. The update-review
        # Compose preflight is covered in test_compose_reconciliation.
        preflight = patch.object(ReadOnlyService, "_compose_plan", return_value=ComposePlan(
            "in_sync", update_eligible=True, execution_context_fingerprint="f" * 64))
        preflight.start()
        self.addCleanup(preflight.stop)

    def service(self, container_id, **changes):
        values = dict(name="sonarr", container_id=container_id, image="example/sonarr:latest",
                      image_id="sha256:" + "1" * 64, digest="sha256:" + "2" * 64,
                      version="1.0", created=None, architecture="amd64", state="running",
                      health="healthy", restart_policy="unless-stopped", started_at=None,
                      stack="media", compose_service="sonarr", working_dir=str(self.root),
                      compose_files=[str(self.root / "compose.yml")], local_build=False, ignored=False)
        values.update(changes)
        return Service(**values)

    def result(self, service, digest="3"):
        return _public_result(ScanResult(service, "UPDATE", "sha256:" + digest * 64, "1.1"))

    def runtime(self, service):
        return {"status": "current", "containers": [{"container_id": service.container_id,
                "name": service.name, "image": service.image, "stack": service.stack,
                "compose_service": service.compose_service, "state": service.state}]}

    def wait_refresh(self, key):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.agent.refresh_status(key)["status"] != "checking":
                return
            time.sleep(.01)
        self.fail("targeted check did not finish")

    def test_missing_digest_revokes_review_and_blocks_update_start(self):
        key="container/"+self.new.container_id
        self.state.save_verification(self.result(self.new))
        record=self.agent.verification_snapshot()["records"][0]
        with patch("docker_update_manager.webservice.discover", return_value=[self.new]):
            confirmation=self.agent.update_review({"service_key": key, "requested_by": "admin",
                "verification_id": record["verification_id"]})["confirmation_id"]
        self.new.digest=None
        self.new.image="docker.io/prom/prometheus"
        with patch("docker_update_manager.webservice.discover", return_value=[self.new]), \
             patch("docker_update_manager.registry.remote_manifest", return_value={
                 "digest": "sha256:"+"3"*64, "platforms": [], "version": None, "created": None}), \
             patch("docker_update_manager.webservice.run") as docker:
            self.agent.start_refresh(key)
            self.wait_refresh(key)
            refreshed=self.agent.verification_snapshot()["records"][0]
            self.assertFalse(refreshed["fresh"])
            self.assertEqual(refreshed["error"], "Local repository digest is unavailable; update comparison is unverified.")
            rows=merge_service_items(None, self.runtime(self.new), {"records": [refreshed]})
            self.assertEqual(rows[0]["status"], "UNKNOWN")
            self.assertIsNone(rows[0].get("remote_digest"))
            with self.assertRaises(ValueError):
                self.agent.update_review({"service_key": key, "requested_by": "admin",
                    "verification_id": refreshed["verification_id"]})
            with self.assertRaises(ReviewedTargetChanged):
                self.agent.start_update({"confirmation_id": confirmation, "requested_by": "admin",
                    "client_ip": "127.0.0.1", "user_agent": "test"})
            docker.assert_not_called()
        self.assertEqual(self.agent._operation_threads, {})
        restarted=ReadOnlyService(self.agent.config, State(self.state.root))
        self.assertFalse(restarted.verification_snapshot()["records"][0]["fresh"])

    def test_cached_update_with_only_remote_digest_cannot_authorise_review(self):
        self.new.digest=None
        self.state.save_verification(self.result(self.new))
        record=self.agent.verification_snapshot()["records"][0]
        self.assertTrue(record["fresh"])
        with patch("docker_update_manager.webservice.discover") as discover:
            with self.assertRaisesRegex(ValueError, "not an eligible"):
                self.agent.update_review({"service_key": "container/"+self.new.container_id,
                    "requested_by": "admin", "verification_id": record["verification_id"]})
            discover.assert_not_called()
        self.assertEqual(self.agent._update_intents, {})

    def test_targeted_check_queries_only_selected_current_service_and_survives_restart(self):
        key = "container/" + self.new.container_id
        with patch("docker_update_manager.webservice.discover", return_value=[self.old, self.new]), \
             patch("docker_update_manager.webservice.scan_service_with_tracking",
                   side_effect=lambda service, _state: ScanResult(service, "UPDATE", "sha256:" + "3" * 64, "1.1")) as scan:
            self.assertEqual(self.agent.start_refresh(key)["status"], "checking")
            self.wait_refresh(key)
        self.assertEqual([call.args[0].container_id for call in scan.call_args_list], [self.new.container_id])
        restarted = ReadOnlyService(self.agent.config, State(self.state.root))
        record = restarted.verification_snapshot()["records"][0]
        self.assertEqual(record["service_key"], key)
        self.assertTrue(record["fresh"])
        self.assertEqual(record["result"]["remote_digest"], "sha256:" + "3" * 64)

    def test_replacement_gets_targeted_facts_without_rewriting_global_scan(self):
        self.state.start_scan("old-scan")
        self.state.finish_scan("old-scan", "complete", services=[self.result(self.old)])
        original = self.state.latest_scan()
        self.state.save_verification(self.result(self.new))
        rows = merge_service_items(original, self.runtime(self.new), self.agent.verification_snapshot())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["service"]["container_id"], self.new.container_id)
        self.assertEqual(rows[0]["status"], "UPDATE")
        self.assertEqual(self.state.latest_scan(), original)
        with patch("docker_update_manager.webservice.discover", return_value=[self.new]):
            reviewed = self.agent.update_review({"service_key": "container/" + self.new.container_id,
                                                 "requested_by": "admin", "verification_id": rows[0]["verification_id"]})
        self.assertRegex(reviewed["confirmation_id"], r"^[A-Za-z0-9_-]{43}$")

    def test_failure_keeps_last_known_result_stale_and_redacts_registry_text(self):
        old_time = (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat()
        self.state.save_verification(self.result(self.new), checked_at=old_time)
        key = "container/" + self.new.container_id
        with patch("docker_update_manager.webservice.discover", return_value=[self.new]), \
             patch("docker_update_manager.webservice.scan_service_with_tracking", side_effect=ValueError("token=private 429")):
            self.agent.start_refresh(key)
            self.wait_refresh(key)
        record = self.agent.verification_snapshot()["records"][0]
        self.assertFalse(record["fresh"])
        self.assertEqual(record["result"]["status"], "UPDATE")
        self.assertEqual(record["error"], "registry rate limit reached")
        self.assertNotIn("private", str(record))
        row = merge_service_items(None, self.runtime(self.new), {"records": [record]})[0]
        self.assertEqual(row["status"], "CHECK REQUIRED")
        self.assertEqual(row["last_known_status"], "UPDATE")
        with patch("docker_update_manager.webservice.discover", return_value=[self.new]):
            with self.assertRaisesRegex(ValueError, "verification is required"):
                self.agent.update_review({"service_key": key, "requested_by": "admin",
                                          "verification_id": record["verification_id"]})

    def test_global_result_precedence_and_changed_target_invalidate_review(self):
        key = "container/" + self.new.container_id
        self.state.save_verification(self.result(self.new))
        first = self.agent.verification_snapshot()["records"][0]
        self.state.start_scan("new-scan")
        self.state.finish_scan("new-scan", "complete", services=[self.result(self.new)])
        same = self.agent.verification_snapshot()["records"][0]
        self.assertEqual(first["verification_id"], same["verification_id"])
        with patch("docker_update_manager.webservice.discover", return_value=[self.new]):
            reviewed = self.agent.update_review({"service_key": key, "requested_by": "admin",
                                                 "verification_id": same["verification_id"]})
            intent = self.agent._update_intents[reviewed["confirmation_id"]]
            self.agent._intent_candidate(intent)
            self.state.save_verification(self.result(self.new, digest="4"))
            with self.assertRaises(ReviewedTargetChanged):
                self.agent._intent_candidate(intent)
        self.state.save_verification(self.result(self.new, digest="3"), checked_at=first["checked_at"])
        self.assertEqual(self.agent.verification_snapshot()["records"][0]["result"]["remote_digest"], "sha256:" + "4" * 64)

    def test_duplicate_check_is_coalesced_and_active_scan_refuses_new_work(self):
        entered, release = threading.Event(), threading.Event()
        key = "container/" + self.new.container_id
        def slow(service, _state):
            entered.set()
            release.wait(2)
            return ScanResult(service, "UPDATE", "sha256:" + "3" * 64)
        with patch("docker_update_manager.webservice.discover", return_value=[self.new]), \
             patch("docker_update_manager.webservice.scan_service_with_tracking", side_effect=slow) as scan:
            self.agent.start_refresh(key)
            self.assertTrue(entered.wait(2))
            self.assertTrue(self.agent.start_refresh(key)["existing"])
            release.set()
            self.wait_refresh(key)
            self.assertEqual(scan.call_count, 1)
        self.state.start_scan("active")
        self.assertEqual(self.agent.start_refresh("container/" + self.old.container_id)["status"], "scan_active")

    def wait_scan(self, run_id):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            run = self.agent.scan_status(run_id)
            if run.get("status") not in ("running", "finalizing") and run_id not in self.agent._threads:
                return run
            time.sleep(.02)
        self.fail("scan did not finish")

    def test_full_scan_extraction_keeps_webservice_patches_and_blocks_live_io(self):
        # Guard the lowest execution layer, not docker.discover itself: an
        # accidentally early-bound import would bypass a module-function patch.
        service = self.new
        with patch("docker_update_manager.webservice.discover", return_value=[service]) as fake_discover, \
             patch("docker_update_manager.webservice.scan_service_with_tracking",
                   return_value=ScanResult(service, "UPDATE", "sha256:" + "3" * 64)) as fake_check, \
             patch("subprocess.run", side_effect=AssertionError("live subprocess access")) as run, \
             patch("subprocess.Popen", side_effect=AssertionError("live process access")) as popen, \
             patch("urllib.request.urlopen", side_effect=AssertionError("live network access")) as network:
            # Keep guards installed until the *background* worker has returned.
            completed = self.wait_scan(self.agent.start_scan()["run_id"])
            self.assertEqual(completed["status"], "complete")
            fake_discover.assert_called_once_with(self.agent.config)
            fake_check.assert_called_once_with(service, self.state)
            run.assert_not_called()
            popen.assert_not_called()
            network.assert_not_called()

        self.assertEqual(self.state.latest_scan()["payload"]["services"][0]["status"], "UPDATE")
        records = self.agent.verification_snapshot()["records"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["result"]["status"], "UPDATE")

    def test_full_scan_worker_uses_one_pre_discovery_timestamp_for_all_verifications(self):
        first = self.new
        second = self.service("c" * 64, name="radarr", compose_service="radarr")
        # Verification rows are keyed by exact container, not Service.key.
        first_key, second_key = "container/" + first.container_id, "container/" + second.container_id
        # One strictly increasing clock for the worker and State makes the
        # started_at/invalidation ordering explicit instead of wall-clock luck.
        ticks = itertools.count(1)
        base = datetime.now(timezone.utc)
        tick = lambda *_: base + timedelta(milliseconds=next(ticks))
        verification_starts = []
        save = self.state.save_verification
        called_during_discovery = []

        def discover_services(_config):
            called_during_discovery.append(clock.now.call_count)
            # A timestamp captured after discovery would allow this later
            # verification to resurrect the invalidated UPDATE.
            self.state.invalidate_verification(first_key)
            return [first, second]

        def registry_check(service, _state):
            if service.container_id == second.container_id:
                # A check that finishes after invalidation must not publish
                # an UPDATE, even when the historical scan succeeds.
                self.state.invalidate_verification(second_key)
            return ScanResult(service, "UPDATE", "sha256:" + "4" * 64)

        def save_verification(data, *, started_at=None):
            verification_starts.append(started_at)
            return save(data, started_at=started_at)

        # The worker currently calls datetime.now once, before discovery.
        # Counting calls catches re-capture after discovery or per service.
        with patch("docker_update_manager.state._utc_now", side_effect=lambda: tick().isoformat()), \
             patch("docker_update_manager.scan_worker.datetime", wraps=datetime) as clock, \
             patch("docker_update_manager.webservice.discover", side_effect=discover_services) as fake_discover, \
             patch("docker_update_manager.webservice.scan_service_with_tracking",
                   side_effect=registry_check) as fake_check, \
             patch.object(self.state, "save_verification", side_effect=save_verification), \
             patch("subprocess.run", side_effect=AssertionError("live subprocess access")) as run, \
             patch("subprocess.Popen", side_effect=AssertionError("live process access")) as popen:
            clock.now.side_effect = tick
            for service in (first, second):
                save(self.result(service))
            completed = self.wait_scan(self.agent.start_scan()["run_id"])
            self.assertEqual(completed["status"], "complete")
            self.assertEqual(called_during_discovery, [1])
            self.assertEqual(clock.now.call_count, 1)
            self.assertEqual(len(verification_starts), 2)
            self.assertIsNotNone(verification_starts[0])
            self.assertEqual(verification_starts[0], verification_starts[1])
            self.assertEqual(fake_discover.call_count, 1)
            self.assertEqual(fake_check.call_count, 2)
            run.assert_not_called()
            popen.assert_not_called()

        # Historical scan data may be UPDATE; current verification authority
        # must stay invalidated, without a usable pre-mutation review token.
        snapshot = self.state.latest_scan()
        self.assertEqual([item["status"] for item in snapshot["payload"]["services"]],
                         ["UPDATE", "UPDATE"])
        rows = {row["service_key"]: row for row in self.agent.verification_snapshot()["records"]}
        self.assertEqual(set(rows), {first_key, second_key})
        for key in (first_key, second_key):  # discovery window, then registry-check window
            with self.subTest(key=key):
                row = rows[key]
                self.assertTrue(row["invalidated"])
                self.assertGreater(datetime.fromisoformat(row["failed_at"]), datetime.fromisoformat(verification_starts[0]))
                self.assertIsNone(row["verification_id"])
                self.assertIsNone(row["checked_at"])
                self.assertIsNone(row["result"])

    def test_partial_scan_records_each_checked_service_independently(self):
        service_a = self.new
        service_b = self.service("c" * 64, name="radarr", compose_service="radarr")
        key_a, key_b = "container/" + service_a.container_id, "container/" + service_b.container_id
        self.state.start_scan("complete-before")
        self.state.finish_scan("complete-before", "complete",
                               services=[self.result(service_a), self.result(service_b)])
        snapshot_before = self.state.latest_scan()
        records = {r["service_key"]: r for r in self.agent.verification_snapshot()["records"]}
        old_a, old_b = records[key_a], records[key_b]

        def registry(service, _state):
            if service.container_id == service_b.container_id:
                raise ValueError("Authorization: Bearer secret-token timed out")
            return ScanResult(service, "UPDATE", "sha256:" + "4" * 64, "1.2")

        with patch("docker_update_manager.webservice.discover", return_value=[service_a, service_b]):
            intent_id = self.agent.update_review({"service_key": key_a, "requested_by": "admin",
                                                  "verification_id": old_a["verification_id"]})["confirmation_id"]
            intent = self.agent._update_intents[intent_id]
            with patch("docker_update_manager.webservice.scan_service_with_tracking", side_effect=registry):
                run = self.wait_scan(self.agent.start_scan()["run_id"])
            self.assertEqual(run["status"], "partial")
            with self.assertRaises(ReviewedTargetChanged):
                self.agent._intent_candidate(intent)

        records = {r["service_key"]: r for r in self.agent.verification_snapshot()["records"]}
        new_a, new_b = records[key_a], records[key_b]
        # A: checked successfully during a run that became partial.
        self.assertTrue(new_a["fresh"])
        self.assertEqual(new_a["result"]["remote_digest"], "sha256:" + "4" * 64)
        self.assertNotEqual(new_a["verification_id"], old_a["verification_id"])
        # B: failed, stale, last-known facts retained, previous ID revoked.
        self.assertFalse(new_b["fresh"])
        self.assertIsNotNone(new_b["failed_at"])
        self.assertEqual(new_b["result"]["remote_digest"], "sha256:" + "3" * 64)
        self.assertNotEqual(new_b["verification_id"], old_b["verification_id"])
        self.assertNotIn("secret", str(new_b))
        # The complete historical inventory is untouched by the partial run.
        self.assertEqual(self.state.latest_scan(), snapshot_before)

        # A late result older than the recorded evidence is discarded.
        self.state.save_verification(self.result(service_a, digest="3"), checked_at=old_a["checked_at"])
        self.state.save_verification({"service": self.result(service_a)["service"], "status": "REGISTRY ERROR",
                                      "error": "registry query failed"}, checked_at=old_a["checked_at"])
        latest_a = next(r for r in self.agent.verification_snapshot()["records"] if r["service_key"] == key_a)
        self.assertEqual(latest_a["result"]["remote_digest"], "sha256:" + "4" * 64)
        self.assertEqual(latest_a["verification_id"], new_a["verification_id"])
        self.assertTrue(latest_a["fresh"])

    def test_explicit_check_of_fresh_service_queries_registry_and_finds_new_target(self):
        key = "container/" + self.new.container_id
        self.state.save_verification(self.result(self.new))
        before = self.agent.verification_snapshot()["records"][0]
        self.assertTrue(before["fresh"])
        with patch("docker_update_manager.webservice.discover", return_value=[self.new]),              patch("docker_update_manager.webservice.scan_service_with_tracking",
                   side_effect=lambda service, _state: ScanResult(service, "UPDATE", "sha256:" + "5" * 64, "1.3")) as scan:
            self.assertEqual(self.agent.start_refresh(key)["status"], "checking")
            self.wait_refresh(key)
        self.assertEqual(scan.call_count, 1)
        after = self.agent.verification_snapshot()["records"][0]
        self.assertEqual(after["result"]["remote_digest"], "sha256:" + "5" * 64)
        self.assertNotEqual(after["verification_id"], before["verification_id"])

    def test_marked_local_build_reports_local_build_and_blocks_update_and_rollback(self):
        container={"Id": "e" * 64, "Name": "/example-stack", "Image": "sha256:" + "1" * 64,
                   "Config": {"Image": "example-stack", "Labels": {
                       "com.docker.compose.project": "example-stack", "com.docker.compose.service": "web",
                       "com.docker.compose.project.working_dir": str(self.root),
                       "com.docker.compose.project.config_files": str(self.root / "compose.yml"),
                       "io.upt.local-build": "true"}},
                   "State": {"Status": "running", "Health": {"Status": "healthy"}}, "HostConfig": {}}
        image={"Id": "sha256:" + "1" * 64, "RepoDigests": [], "Architecture": "amd64", "Config": {"Labels": None}}
        with patch("docker_update_manager.docker.run",
                   side_effect=["e\n", json.dumps([container]), json.dumps([image])]):
            service=discover()[0]
        self.assertTrue(service.local_build)
        key="container/" + service.container_id
        with patch("docker_update_manager.webservice.discover", return_value=[service]), \
             patch("docker_update_manager.registry.remote_manifest") as registry, \
             patch("docker_update_manager.webservice.run") as docker:
            self.agent.start_refresh(key)
            self.wait_refresh(key)
            record=self.agent.verification_snapshot()["records"][0]
            self.assertEqual(record["result"]["status"], "LOCAL BUILD")
            row=merge_service_items(None, self.runtime(service), {"records": [record]})[0]
            self.assertEqual(row["status"], "LOCAL BUILD")
            self.assertEqual(STATUS_LABELS[row["status"]], "Local build")
            # Even with a repository digest and a stale registry-update record,
            # the local-build gate alone refuses registry update and rollback.
            service.digest="sha256:" + "2" * 64
            self.state.save_verification(self.result(service))
            stale=self.agent.verification_snapshot()["records"][0]
            with self.assertRaisesRegex(ValueError, "eligible running Compose"):
                self.agent.update_review({"service_key": key, "requested_by": "admin",
                                          "verification_id": stale["verification_id"]})
            with self.assertRaisesRegex(ValueError, "eligible running Compose"):
                self.agent.rollback_review({"service_key": key, "requested_by": "admin"})
        registry.assert_not_called()
        docker.assert_not_called()

    def test_ignored_and_local_build_never_query_registry(self):
        for service in (self.service("c" * 64, ignored=True), self.service("d" * 64, local_build=True)):
            with self.subTest(service=service.container_id), \
                 patch("docker_update_manager.webservice.discover", return_value=[service]), \
                 patch("docker_update_manager.registry.remote_manifest") as registry:
                key = "container/" + service.container_id
                self.agent.start_refresh(key)
                self.wait_refresh(key)
                registry.assert_not_called()
                status = next(r["result"]["status"] for r in self.agent.verification_snapshot()["records"]
                              if r["service_key"] == key)
                self.assertEqual(status, "IGNORED" if service.ignored else "LOCAL BUILD")

    def test_v6_migration_seeds_additive_verification_without_changing_history(self):
        self.state.start_scan("legacy")
        self.state.finish_scan("legacy", "complete", services=[self.result(self.old)])
        self.state.record(service="sonarr", action="update", result="SUCCESS")
        before = self.state.latest_scan()
        with self.state.connect() as c:
            c.execute("DROP TABLE service_verifications")
            c.execute("DROP TABLE IF EXISTS core_schema_identity")
            c.execute("DROP TABLE IF EXISTS compose_bootstrap_fences")
            c.execute("UPDATE schema_version SET version=6")
        upgraded = State(self.state.root)
        self.assertEqual(upgraded.latest_scan(), before)
        self.assertEqual(len(upgraded.history()), 1)
        self.assertEqual(upgraded.verification_snapshot()[0]["service_key"], "container/" + self.old.container_id)


if __name__ == "__main__":
    unittest.main()
