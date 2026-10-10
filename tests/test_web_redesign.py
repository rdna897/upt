"""Regression coverage for the web UI redesign's presentation helpers and views."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from docker_update_manager.auth import new_token
from docker_update_manager.config import WebConfig
from docker_update_manager.release_identity import update_identity
from docker_update_manager.state import State
from docker_update_manager.webapp import WebApplication, create_app, stage_step

from test_web_runtime import RuntimeWebAgent


def scan_item(status, *, version=None, image="registry.example/app:latest", digest="sha256:" + "1" * 64,
              remote_version=None, remote_digest="sha256:" + "2" * 64, error=None, **extra):
    return {
        "service": {"key": "media/app", "name": "App", "stack": "media", "image": image,
                    "digest": digest, "version": version},
        "status": status, "remote_version": remote_version, "remote_digest": remote_digest,
        "error": error, **extra,
    }


class UpdateIdentityTests(unittest.TestCase):
    def test_versioned_update_reports_current_and_available_versions(self):
        identity = update_identity(scan_item("UPDATE", version="4.0.15", image="registry.example/app:4.0.15",
                                             remote_version="4.0.16"))
        self.assertEqual(identity["state"], "update")
        self.assertEqual(identity["current"]["value"], "4.0.15")
        self.assertEqual(identity["current"]["kind"], "version")
        self.assertEqual(identity["available"]["value"], "4.0.16")
        self.assertIsNone(identity["reason"])

    def test_update_without_published_version_uses_digest_not_unknown(self):
        identity = update_identity(scan_item("DIGEST CHANGED"))
        self.assertEqual(identity["current"]["kind"], "channel")
        self.assertEqual(identity["current"]["value"], "latest")
        self.assertEqual(identity["available"]["kind"], "digest")
        self.assertTrue(identity["available"]["value"].startswith("sha256:2222"))
        self.assertNotIn("Unknown", str(identity))

    def test_missing_version_and_channel_is_labelled_not_guessed(self):
        identity = update_identity(scan_item("CURRENT", image="registry.example/app@sha256:" + "1" * 64))
        self.assertEqual(identity["state"], "current")
        self.assertEqual(identity["current"]["kind"], "digest")
        self.assertEqual(identity["current"]["label"], "Pinned digest")
        identity = update_identity(scan_item("CURRENT", image="registry.example/app@sha256:" + "1" * 64, digest=None))
        self.assertEqual(identity["current"], {"value": None, "kind": "none", "label": "No version published"})

    def test_undetermined_states_carry_recorded_or_default_reason(self):
        recorded = update_identity(scan_item("REGISTRY ERROR", error="registry request timed out"))
        self.assertEqual(recorded["state"], "undetermined")
        self.assertEqual(recorded["reason"], "registry request timed out")
        self.assertIsNone(recorded["available"])
        for status in ("UNKNOWN", "ARCH UNSUPPORTED", "CHECK REQUIRED"):
            with self.subTest(status=status):
                identity = update_identity(scan_item(status))
                self.assertEqual(identity["state"], "undetermined")
                self.assertTrue(identity["reason"])
        replaced = update_identity({**scan_item("CHECK REQUIRED"), "runtime_reconciled": True})
        self.assertIn("changed since the inventory scan", replaced["reason"])
        self.assertNotIn("rescan", replaced["reason"].lower())

    def test_untracked_digest_never_reports_a_channel(self):
        identity = update_identity(scan_item("UNTRACKED DIGEST", image="registry.example/app:latest@sha256:" + "1" * 64,
                                             tracking_tag="latest"))
        self.assertEqual(identity["current"]["kind"], "digest")
        self.assertEqual(identity["state"], "undetermined")

    def test_runtime_only_rows_are_not_scanned(self):
        identity = update_identity({"service": {"name": "x"}, "runtime_only": True, "status": "NOT SCANNED"})
        self.assertEqual(identity["state"], "not_scanned")
        self.assertIsNone(identity["available"])


class PresentationFilterTests(unittest.TestCase):
    def test_stage_step_only_reads_explicit_core_step_labels(self):
        self.assertEqual(stage_step("3/7 Pull exact reviewed image digest"), (3, 7))
        self.assertEqual(stage_step("[2/8] Back up Compose ●"), (2, 8))
        for label in ("Revalidating service eligibility", "Complete", "0/7 Nothing", "9/7 Invalid", None, "3/7"):
            with self.subTest(label=label):
                self.assertIsNone(stage_step(label))

    def test_status_colours_separate_available_updates_from_problems(self):
        status_class = WebApplication._status_class
        self.assertEqual(status_class("UPDATE"), "status-info")
        self.assertEqual(status_class("PINNED UPDATE"), "status-info")
        self.assertEqual(status_class("UNTRACKED DIGEST"), "status-warning")
        self.assertEqual(status_class("REGISTRY ERROR"), "status-danger")
        self.assertEqual(status_class("UNKNOWN"), "status-neutral")
        self.assertEqual(status_class("success"), "status-success")
        self.assertEqual(status_class("failure"), "status-danger")


class UpdatesViewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        config = WebConfig(path=str(root / "web.yml"))
        config.settings["allowed_hosts"] = ["testserver"]
        self.state = State(root / "web-state")
        self.agent = RuntimeWebAgent()
        services = self.agent.scan["payload"]["services"]
        services.append(deepcopy(services[0]))
        services[1]["service"].update({"key": "media/broken", "name": "Broken", "container_id": "e" * 64})
        services[1].update({"status": "REGISTRY ERROR", "error": "registry request timed out"})
        self.client = TestClient(create_app(config, self.state, self.agent))
        user_id = self.state.create_user("redesign-admin", "test-only-unused-password-hash")
        now = datetime.now(timezone.utc)
        session_id = new_token()
        self.state.create_session(user_id, new_token(), (now + timedelta(hours=1)).isoformat(),
                                  (now + timedelta(days=30)).isoformat(), "127.0.0.1", "test", session_id=session_id)
        self.client.cookies.set("upt_session", session_id)

    def test_updates_view_groups_available_and_unchecked_services(self):
        body = self.client.get("/updates").text
        available = body.split('id="updates-available-title"', 1)[1].split('id="updates-undetermined-title"', 1)[0]
        self.assertIn("Sonarr", available)
        self.assertIn("1.2.4", available)
        self.assertIn("#update-confirmation", available)
        self.assertNotIn("Broken", available)
        unchecked = body.split('id="updates-undetermined-title"', 1)[1]
        self.assertIn("Broken", unchecked)
        self.assertIn("registry request timed out", unchecked)
        self.assertIn('aria-current="page"', body.split('href="/updates"', 1)[1][:80])

    def test_updates_view_never_presents_incomplete_scan_as_result(self):
        self.agent.scan = {**self.agent.scan, "status": "partial"}
        self.agent.verified = False
        body = self.client.get("/updates").text
        self.assertIn("No update checks yet", body)
        self.assertNotIn("updates-available-title", body)

    def test_ignored_and_local_builds_have_their_own_excluded_group(self):
        services = self.agent.scan["payload"]["services"]
        for status, name in (("IGNORED", "Ignored"), ("LOCAL BUILD", "Local build")):
            item = deepcopy(services[0])
            item["service"].update(key="media/" + name.lower().replace(" ", "-"), name=name,
                                   container_id=name[0].lower() * 64)
            item["status"] = status
            services.append(item)
        body = self.client.get("/updates").text
        excluded = body.split('class="card disclosure-card updates-excluded"', 1)[1]
        self.assertIn("Excluded from checks", excluded)
        self.assertIn("Ignored", excluded)
        self.assertIn("Local build", excluded)
        available = body.split('id="updates-available-title"', 1)[1].split('class="card disclosure-card updates-excluded"', 1)[0]
        self.assertNotIn("Local build", available)

    def test_updates_view_is_read_only_and_requires_authentication(self):
        self.assertEqual(self.client.post("/updates").status_code, 405)
        self.client.cookies.clear()
        response = self.client.get("/updates", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers["location"].startswith("/login"))

    def test_settings_shows_session_expiry_and_sign_out(self):
        body = self.client.get("/settings").text
        self.assertIn("This session", body)
        self.assertIn("data-local-date", body)
        self.assertIn("Sign out of this session", body)
        self.assertIn("signs out every session", body)
        self.assertIn('<details class="settings-subsection">', body)


if __name__ == "__main__":
    unittest.main()
