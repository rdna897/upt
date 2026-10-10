"""Authenticated read-only web regressions for Phase 4 runtime views."""

import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import tempfile
import unittest
from html import unescape
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from docker_update_manager.agent import AgentNotFound
from docker_update_manager.auth import new_token
from docker_update_manager.config import WebConfig
from docker_update_manager.state import State
from docker_update_manager.webapp import create_app


def runtime_entry(container_id, name, *, state="running", health="healthy", stack="media",
                  service=None, oom=False, exit_code=0, restart_count=0, ignored=False):
    return {
        "key": "container/" + container_id, "container_id": container_id, "name": name,
        "stack": stack, "compose_service": service or name.lower(),
        "image": "registry.example/" + name.lower() + ":1.2.3", "state": state,
        "healthcheck": health, "restart_count": restart_count,
        "restart_policy": "unless-stopped", "started_at": "2026-09-27T09:00:00Z",
        "finished_at": "2026-09-27T13:30:00Z" if state != "running" else None,
        "exit_code": exit_code, "oom_killed": oom, "health_failing_streak": 2 if health == "unhealthy" else 0,
        "health_last_started_at": "2026-09-27T14:00:00Z",
        "health_last_finished_at": "2026-09-27T14:00:01Z", "health_last_exit_code": 1 if health == "unhealthy" else 0,
        "ignored": ignored,
    }


class RuntimeWebAgent:
    def __init__(self):
        self.sonarr_id = "a" * 64
        self.worker_id = "b" * 64
        self.scan = {
            "scan_id": "scan-1", "status": "complete", "finished_at": "2026-09-27T14:00:00+00:00",
            "payload": {"count": 1, "services": [{
                "service": {
                    "key": "container/" + self.sonarr_id, "container_id": self.sonarr_id,
                    "name": "Sonarr", "stack": "media", "compose_service": "sonarr",
                    "image": "registry.example/sonarr:1.2.3", "state": "running",
                    "health": "healthy", "working_dir": "/opt/media",
                    "compose_files": ["/opt/media/compose.yml"], "local_build": False, "ignored": False,
                },
                "status": "UPDATE", "remote_version": "1.2.4", "remote_digest": "sha256:" + "c" * 64,
            }]},
        }
        self.runtime = {
            "status": "current", "available": True, "stale": False,
            "captured_at": "2026-09-27T14:00:10+00:00", "last_success_at": "2026-09-27T14:00:10+00:00",
            "attempted_at": "2026-09-27T14:00:10+00:00", "attempt_success": True,
            "failure_category": None,
            "containers": [
                runtime_entry(self.sonarr_id, "Sonarr", health="unhealthy", service="sonarr"),
                runtime_entry(self.worker_id, "Worker", state="exited", health="none", service="worker", oom=True, exit_code=137, ignored=True),
            ],
        }
        self.update_reviews = []
        self.rollback_reviews = []

    def call(self, operation, payload=None):
        payload = payload or {}
        if operation == "health":
            return {"ok": True, "docker": {"ok": True, "version": "fixture"}}
        if operation == "snapshot":
            return self.scan
        if operation == "runtime_snapshot":
            return self.runtime
        if operation == "verification_snapshot":
            if not getattr(self, "verified", True):
                return {"records": []}
            return {"records": [{"service_key": "container/" + self.sonarr_id,
                                 "verification_id": "verified-sonarr", "checked_at": self.scan["finished_at"],
                                 "fresh": True, "failed_at": None,
                                 "result": self.scan["payload"]["services"][0]}]}
        if operation == "scan_status":
            return {"id": "scan-1", "status": "complete", "finished_at": self.scan["finished_at"], "events": []}
        if operation == "service":
            key = payload.get("service_key")
            for item in self.scan["payload"]["services"]:
                if item["service"]["key"] == key:
                    return {**item, "_review_scan_id": self.scan["scan_id"]}
            raise AgentNotFound("service not present in cached scan")
        if operation == "update_review":
            self.update_reviews.append(payload)
            return {"confirmation_id": "R" * 43}
        if operation == "rollback_review":
            self.rollback_reviews.append(payload)
            raise ValueError("not available")
        if operation == "audit_recent":
            return {"events": []}
        raise AssertionError(operation)


class RuntimeWebTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        config = WebConfig(path=str(root / "web.yml"))
        config.settings["allowed_hosts"] = ["testserver"]
        self.state = State(root / "web-state")
        self.agent = RuntimeWebAgent()
        self.client = TestClient(create_app(config, self.state, self.agent))
        self.user_id = self.state.create_user("phase4-admin", "test-only-unused-password-hash")
        now = datetime.now(timezone.utc)
        self.session_id = new_token()
        self.state.create_session(
            self.user_id, new_token(), (now + timedelta(hours=1)).isoformat(),
            (now + timedelta(hours=12)).isoformat(), "127.0.0.1", "phase4-test",
            session_id=self.session_id,
        )
        self.client.cookies.set("upt_session", self.session_id)

    def test_overview_separates_freshness_and_combines_runtime_with_update_once(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        body = response.text
        self.assertIn("Runtime health", body)
        self.assertIn("Maintenance", body)
        self.assertIn("Runtime checked", body)
        self.assertIn("Inventory scanned", body)
        self.assertIn("Unhealthy", body)
        self.assertIn("Update available", body)
        self.assertEqual(body.count("Sonarr"), 1)
        self.assertIn("OOM-killed", body)

    def test_first_failed_runtime_probe_does_not_claim_empty_inventory(self):
        self.agent.runtime = {
            "status": "unavailable", "available": False, "stale": False,
            "captured_at": None, "last_success_at": None,
            "attempted_at": "2026-09-27T14:00:10+00:00", "attempt_success": False,
            "failure_category": "probe_failed", "containers": [],
        }
        body = self.client.get("/").text
        runtime_section = body.split('class="runtime-health-section"', 1)[1].split(
            'class="maintenance-section"', 1,
        )[0]
        self.assertIn("Runtime information is not available yet.", runtime_section)
        self.assertIn("UPT has not completed a successful Docker runtime check.", runtime_section)
        self.assertNotIn("No containers were found", runtime_section)
        self.assertNotIn("runtime-summary-grid", runtime_section)
        self.assertIn("The Docker runtime check could not be completed", body)
        self.assertIn("Scanned services", body)
        self.assertIn("Updates available", body)

    def test_successful_current_empty_runtime_snapshot_has_empty_inventory_message(self):
        captured = "2026-09-27T14:00:10+00:00"
        self.agent.runtime = {
            "status": "current", "available": True, "stale": False,
            "captured_at": captured, "last_success_at": captured,
            "attempted_at": captured, "attempt_success": True,
            "failure_category": None, "containers": [],
        }
        body = self.client.get("/").text
        runtime_section = body.split('class="runtime-health-section"', 1)[1].split(
            'class="maintenance-section"', 1,
        )[0]
        self.assertIn("No containers were found in the latest runtime snapshot.", runtime_section)
        self.assertNotIn("Runtime information is not available yet", runtime_section)
        self.assertNotIn("runtime-summary-grid", runtime_section)
        self.assertIn("Runtime checked", body)
        self.assertIn("Scanned services", body)

    def test_services_include_stopped_runtime_only_row_as_not_scanned(self):
        response = self.client.get("/services")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Worker", response.text)
        self.assertIn("Not scanned", response.text)
        self.assertIn("Exited", response.text)
        self.assertIn("OOM-killed", response.text)
        self.assertIn("Excluded from updates", response.text)
        self.assertIn("No healthcheck", response.text)

    def test_runtime_only_detail_is_read_only_and_does_not_review_mutations(self):
        response = self.client.get("/services/container/" + self.agent.worker_id)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Runtime", response.text)
        self.assertIn("Exit code", response.text)
        self.assertIn("137", response.text)
        self.assertIn("OOM-killed", response.text)
        self.assertIn("has not been checked for updates", response.text)
        self.assertNotIn("Review update", response.text)
        self.assertNotIn("Review rollback", response.text)
        self.assertEqual(self.agent.update_reviews, [])
        self.assertEqual(self.agent.rollback_reviews, [])

    def test_current_runtime_exclusion_blocks_stale_scan_update_review(self):
        self.agent.runtime["containers"][0]["ignored"] = True
        response = self.client.get("/services/container/" + self.agent.sonarr_id)
        self.assertEqual(response.status_code, 200)
        self.assertIn("excluded from update maintenance", response.text.lower())
        self.assertNotIn("Review update", response.text)
        self.assertEqual(self.agent.update_reviews, [])

    def test_recreated_compose_identity_requires_new_update_verification_across_views(self):
        replacement_id = "c" * 64
        self.agent.runtime["containers"][0] = runtime_entry(
            replacement_id, "Sonarr", health="unhealthy", service="sonarr",
        )

        overview = self.client.get("/")
        self.assertEqual(overview.status_code, 200)
        self.assertIn("Unhealthy", overview.text)
        self.assertIn("Check required", overview.text)
        self.assertNotIn("Rescan required", overview.text)
        self.assertEqual(overview.text.count(replacement_id), 1)

        services = self.client.get("/services")
        self.assertEqual(services.status_code, 200)
        self.assertIn("Check required", services.text)
        self.assertNotIn("Rescan required", services.text)
        self.assertIn("Unhealthy", services.text)
        self.assertRegex(services.text, r'href="[^"]*' + replacement_id + r'"')
        self.assertNotRegex(services.text, r'href="[^"]*' + self.agent.sonarr_id + r'"')

        detail_new = self.client.get("/services/container/" + replacement_id)
        detail_old = self.client.get("/services/container/" + self.agent.sonarr_id)
        for detail in (detail_new, detail_old):
            self.assertEqual(detail.status_code, 200)
            self.assertIn("Check required", detail.text)
            self.assertNotIn("Rescan required", detail.text)
            self.assertNotIn("rescan", detail.text.lower())
            self.assertNotIn("Review update", detail.text)
            self.assertNotIn("Review rollback", detail.text)
            # No old target facts (remote version 1.2.4 / digest cccc…) are inherited.
            self.assertNotIn("1.2.4", detail.text)
            self.assertNotIn("sha256:" + "c" * 64, detail.text)
            self.assertNotIn("Last known update state", detail.text)
            self.assertIn("changed since the last inventory scan", detail.text)
            # The targeted service check still starts automatically.
            self.assertIn('data-refresh-state="stale"', detail.text)
            self.assertIn('data-auto="true"', detail.text)
            self.assertIn('data-service-key="container/' + replacement_id + '"', detail.text)
            self.assertIn("Update information needs checking.", detail.text)

        api_services = self.client.get("/api/services").json()["items"]
        sonarr_rows = [item for item in api_services if item["service"].get("name") == "Sonarr"]
        self.assertEqual(len(sonarr_rows), 1)
        self.assertEqual(sonarr_rows[0]["service"]["container_id"], replacement_id)
        self.assertEqual(sonarr_rows[0]["status"], "CHECK REQUIRED")
        self.assertTrue(sonarr_rows[0]["runtime_reconciled"])
        for key in ("remote_version", "remote_digest", "target_image", "tracking_tag", "verification_id", "last_known_status"):
            self.assertIsNone(sonarr_rows[0].get(key), key)
        self.assertNotIn("_scan_container_id", sonarr_rows[0])
        overview_rows = self.client.get("/api/overview").json()["services"]
        self.assertEqual(sum(item["service"].get("name") == "Sonarr" for item in overview_rows), 1)
        self.assertEqual(next(item for item in overview_rows if item["service"].get("name") == "Sonarr")
                         ["service"]["container_id"], replacement_id)
        for key in ("working_dir", "compose_files", "local_build", "digest"):
            self.assertNotIn(key, sonarr_rows[0]["service"])
        for key in (replacement_id, self.agent.sonarr_id):
            detail = self.client.get("/api/services/container/" + key)
            self.assertEqual(detail.status_code, 200)
            self.assertEqual(detail.json()["status"], "CHECK REQUIRED")
            self.assertTrue(detail.json()["runtime_reconciled"])
            self.assertEqual(detail.json()["service"]["container_id"], replacement_id)
            self.assertNotIn("_scan_container_id", detail.json())
        self.assertEqual(self.agent.update_reviews, [])
        self.assertTrue(self.agent.rollback_reviews)
        self.assertTrue(all(item["service_key"] == "container/" + replacement_id
                            for item in self.agent.rollback_reviews))

    def test_current_missing_scan_identity_is_explicit_in_html_and_api(self):
        self.agent.runtime["containers"] = [self.agent.runtime["containers"][1]]
        overview = self.client.get("/").text
        services = self.client.get("/services").text
        detail = self.client.get("/services/container/" + self.agent.sonarr_id).text
        self.assertIn("Not present in current Docker runtime", overview)
        self.assertIn("Not present in current Docker runtime", services)
        self.assertIn("not present in the current Docker runtime", detail)
        self.assertNotIn("Review update", detail)
        api_item = next(item for item in self.client.get("/api/services").json()["items"]
                        if item["service"].get("container_id") == self.agent.sonarr_id)
        self.assertTrue(api_item["runtime_missing"])
        overview_item = next(item for item in self.client.get("/api/overview").json()["services"]
                             if item["service"].get("container_id") == self.agent.sonarr_id)
        self.assertTrue(overview_item["runtime_missing"])
        api_detail = self.client.get("/api/services/container/" + self.agent.sonarr_id).json()
        self.assertTrue(api_detail["runtime_missing"])
        self.assertIsNone(api_detail["runtime"])
        self.assertEqual(self.agent.update_reviews, [])

    def test_stale_runtime_absence_does_not_claim_container_is_currently_missing(self):
        self.agent.runtime.update({"status": "unavailable", "available": False, "stale": True,
                                   "attempt_success": False, "failure_category": "docker_unavailable"})
        self.agent.runtime["containers"] = [self.agent.runtime["containers"][1]]
        overview = self.client.get("/").text
        detail = self.client.get("/services/container/" + self.agent.sonarr_id).text
        api_detail = self.client.get("/api/services/container/" + self.agent.sonarr_id).json()
        self.assertNotIn("Not present in current Docker runtime", overview)
        self.assertNotIn("not present in the current Docker runtime", detail)
        self.assertFalse(api_detail["runtime_missing"])

    def test_authenticated_runtime_api_is_additive_and_excludes_raw_docker_data(self):
        anonymous = TestClient(self.client.app)
        self.assertEqual(anonymous.get("/api/runtime").status_code, 401)
        runtime = self.client.get("/api/runtime")
        self.assertEqual(runtime.status_code, 200)
        self.assertEqual(runtime.json()["status"], "current")
        self.assertEqual(len(runtime.json()["containers"]), 2)
        services = self.client.get("/api/services").json()
        self.assertIn("payload", services)
        self.assertIn("runtime", services)
        self.assertEqual(len(services["items"]), 2)
        detail = self.client.get("/api/services/container/" + self.agent.worker_id)
        self.assertEqual(detail.status_code, 200)
        self.assertTrue(detail.json()["runtime_only"])
        encoded = runtime.text + services.__repr__() + detail.text
        for private in ("Config.Env", "State.Error", "Health.Log", "Mounts", "host-secret", "fixture-token"):
            self.assertNotIn(private, encoded)

    def test_failure_category_controls_overview_and_services_copy_and_retains_last_known_data(self):
        expected_messages = {
            "docker_unavailable": "Docker runtime unavailable",
            "inventory_changed": "Docker inventory changed during the runtime check",
            "probe_failed": "The Docker runtime check could not be completed",
            "invalid_docker_response": "Docker returned an invalid runtime response",
            "container_limit_exceeded": "The Docker runtime inventory exceeds UPT's monitoring limit",
        }
        healthy_id = "d" * 64
        self.agent.runtime["containers"].append(runtime_entry(healthy_id, "Healthy", health="healthy"))
        for category, message in expected_messages.items():
            with self.subTest(category=category):
                self.agent.runtime.update({
                    "status": "unavailable", "available": False, "stale": True,
                    "attempt_success": False, "failure_category": category,
                })
                overview_response = self.client.get("/")
                services_response = self.client.get("/services")
                self.assertEqual(overview_response.status_code, 200)
                self.assertEqual(services_response.status_code, 200)
                overview, services = unescape(overview_response.text), unescape(services_response.text)

                # The page context and warning card use the same category-aware copy.
                self.assertGreaterEqual(overview.count(message), 2)
                self.assertGreaterEqual(services.count(message), 2)
                for body in (overview, services):
                    if category == "docker_unavailable":
                        self.assertIn("Docker runtime unavailable", body)
                    else:
                        self.assertNotIn("Docker runtime unavailable", body)
                    self.assertIn('datetime="2026-09-27T14:00:10', body)
                self.assertIn("These are last-known Docker states and are not presented as current.", overview)
                self.assertIn("last-known state from", services)
                self.assertIn("Unhealthy", overview)
                self.assertIn("Exited", services)
                self.assertIn("Healthy", services)

        detail = self.client.get("/services/container/" + self.agent.worker_id).text
        self.assertIn("last-known docker state", detail.lower())

        # A successful next sample clears the failure and returns to current copy.
        self.agent.runtime.update({
            "status": "current", "available": True, "stale": False,
            "attempt_success": True, "failure_category": None,
            "captured_at": "2026-09-27T14:01:00+00:00",
            "last_success_at": "2026-09-27T14:01:00+00:00",
            "attempted_at": "2026-09-27T14:01:00+00:00",
        })
        recovered = self.client.get("/").text
        self.assertIn("Runtime checked", recovered)
        self.assertNotIn('class="alert alert-warning runtime-unavailable"', recovered)
        for message in expected_messages.values():
            self.assertNotIn(message, recovered)


if __name__ == "__main__":
    unittest.main()
