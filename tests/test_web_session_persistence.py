"""Session persistence regressions: cookie SameSite, rejection diagnostics, upgrade policy."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("UPT_TESTING", "1")

from docker_update_manager.config import WebConfig, session_policy, session_policy_warnings
from docker_update_manager.state import SESSION_TOMBSTONE
from docker_update_manager.webapp import _duration_label
import test_web_closure_auth as auth_tests

ROOT = Path(__file__).resolve().parents[1]
SHORT_WEB_YML = "web:\n  session_idle_minutes: 60\n  session_absolute_hours: 12\n  trusted_proxies: [\"172.19.0.5\"]\n"


class SessionPersistenceTests(unittest.TestCase):
    # Reuse the auth fixtures without re-running the inherited test cases.
    make_env = auth_tests.AuthClosureTests.make_env
    make_client = auth_tests.AuthClosureTests.make_client
    create_admin = auth_tests.AuthClosureTests.create_admin
    csrf = auth_tests.AuthClosureTests.csrf
    sign_in = auth_tests.AuthClosureTests.sign_in
    session_cookie = auth_tests.AuthClosureTests.session_cookie
    cookie_expiry = auth_tests.AuthClosureTests.cookie_expiry
    cookie_max_age = auth_tests.AuthClosureTests.cookie_max_age

    def authed(self):
        root, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        response = self.sign_in(client)
        return root, config, state, client, response

    def audit_reasons(self, state):
        return [e["result"] for e in state.audit_events() if e["action"] == "session_rejected"]

    def test_authenticated_and_anonymous_cookies_are_lax_and_authenticated_is_persistent(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        anonymous = client.get("/login")
        self.assertIn("SameSite=lax", anonymous.headers["set-cookie"])
        self.assertNotIn("Max-Age", anonymous.headers["set-cookie"])
        login = self.sign_in(client)
        header = login.headers["set-cookie"]
        self.assertIn("SameSite=lax", header)
        self.assertIn("HttpOnly", header)
        self.assertGreater(self.cookie_max_age(login), 30 * 24 * 3600 - 120)
        self.assertIsNotNone(self.cookie_expiry(login))
        # Refreshing a page must keep the persistent attributes, never fall back to session-only.
        refreshed = client.get("/settings")
        self.assertIn("Max-Age", refreshed.headers["set-cookie"])
        self.assertIn("SameSite=lax", refreshed.headers["set-cookie"])

    def test_cookie_and_session_survive_process_and_browser_restart(self):
        root, config, state, client, _ = self.authed()
        sid = client.cookies.get("upt_session")
        from docker_update_manager.webstate import WebState
        restarted = self.make_client(WebState(root / "web-state"), config)
        restarted.cookies.set("upt_session", sid)
        self.assertEqual(restarted.get("/settings", follow_redirects=False).status_code, 200)
        self.assertIsNone(state.session_record(sid)["revoked_at"])

    def test_rejection_reasons_are_classified_without_leaking_the_token(self):
        past = "2000-01-01T00:00:00+00:00"
        cases = {"idle_expired": "expires_at", "absolute_expired": "absolute_expires_at"}
        for reason, column in cases.items():
            _, config, state, client, _ = self.authed()
            sid = client.cookies.get("upt_session")
            with state.connect() as c:
                c.execute(f"UPDATE web_sessions SET {column}=? WHERE id=?", (past, sid))
            client.get("/", follow_redirects=False)
            self.assertEqual(self.audit_reasons(state), [reason])
            self.assertNotIn(sid, str(state.audit_events()))
        _, config, state, client, _ = self.authed()
        sid = client.cookies.get("upt_session")
        state.revoke_session(sid)
        client.get("/", follow_redirects=False)
        self.assertEqual(self.audit_reasons(state), ["explicitly_revoked"])
        self.assertNotIn(sid, str(state.audit_events()))
        _, config, state, _, _ = self.authed()
        unknown = self.make_client(state, config)
        unknown.cookies.set("upt_session", "z" * 43)
        unknown.get("/", follow_redirects=False)
        self.assertEqual(self.audit_reasons(state), ["unknown_session"])
        self.assertNotIn("z" * 43, str(state.audit_events()))

    def test_missing_cookie_redirects_without_auditing(self):
        _, config, state, _, _ = self.authed()
        bare = self.make_client(state, config)
        self.assertEqual(bare.get("/", follow_redirects=False).headers["location"], "/login")
        self.assertEqual(self.audit_reasons(state), [])

    def test_rejection_audit_is_throttled_per_client_and_reason(self):
        _, config, state, client, _ = self.authed()
        probe = self.make_client(state, config)
        probe.cookies.set("upt_session", "y" * 43)
        for _ in range(5): probe.get("/", follow_redirects=False)
        self.assertEqual(self.audit_reasons(state), ["unknown_session"])

    def test_recently_ended_sessions_are_retained_then_pruned(self):
        _, config, state, client, _ = self.authed()
        sid = client.cookies.get("upt_session")
        state.revoke_session(sid)
        self.assertEqual(state.prune_sessions(), 0)
        self.assertIsNotNone(state.session_record(sid))
        later = (datetime.now(timezone.utc) + SESSION_TOMBSTONE + timedelta(minutes=1)).isoformat()
        state.prune_sessions(later)
        self.assertIsNone(state.session_record(sid))

    def test_valid_authenticated_session_is_never_pruned_or_revoked_by_pruning(self):
        _, config, state, client, _ = self.authed()
        sid = client.cookies.get("upt_session")
        state.prune_sessions((datetime.now(timezone.utc) + timedelta(days=29)).isoformat())
        self.assertIsNotNone(state.session(sid))

    def test_thirty_day_defaults_and_old_short_config_are_distinguished(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "web.yml"; old.write_text(SHORT_WEB_YML); os.chmod(old, 0o600)
            self.assertEqual(session_policy(WebConfig(path=str(old)).settings),
                             {"idle_minutes": 60, "absolute_hours": 12, "shorter_than_default": True})
            self.assertTrue(session_policy_warnings(WebConfig(path=str(old)).settings))
            fresh = WebConfig(path=str(Path(tmp) / "absent.yml")).settings
            self.assertEqual(session_policy(fresh), {"idle_minutes": 43200, "absolute_hours": 720, "shorter_than_default": False})
            self.assertEqual(session_policy_warnings(fresh), [])

    POLICY_MATRIX = (
        # (label, configured values, effective idle minutes, effective absolute hours, shorter than default)
        ("defaults", {}, 43200, 720, False),
        ("absolute zero", {"session_absolute_hours": 0}, 60, 1, True),
        ("absolute negative", {"session_absolute_hours": -1}, 60, 1, True),
        ("absolute malformed", {"session_absolute_hours": "banana"}, 43200, 720, False),
        ("absolute null", {"session_absolute_hours": None}, 43200, 720, False),
        ("idle zero", {"session_idle_minutes": 0}, 1, 720, True),
        ("idle malformed", {"session_idle_minutes": "banana"}, 43200, 720, False),
        ("valid short override", {"session_idle_minutes": 60, "session_absolute_hours": 12}, 60, 12, True),
        ("idle longer than absolute", {"session_idle_minutes": 43200, "session_absolute_hours": 3}, 180, 3, True),
    )

    def test_effective_policy_matches_settings_warnings_and_real_session_creation(self):
        import yaml
        snippet = (ROOT / "install.sh").read_text().split("<<'PY' || true\n", 1)[1].split("\nPY\n", 1)[0]
        for label, configured, idle, absolute, shorter in self.POLICY_MATRIX:
            with self.subTest(label):
                root, config, state = self.make_env()
                config.settings.update(configured)
                self.create_admin(state)
                with self.assertLogs("upt.web", "WARNING") if shorter else self.assertNoLogs("upt.web", "WARNING"):
                    client = self.make_client(state, config)
                self.assertEqual(session_policy(config.settings),
                                 {"idle_minutes": idle, "absolute_hours": absolute, "shorter_than_default": shorter})
                self.assertEqual(bool(session_policy_warnings(config.settings)), shorter)

                client.get("/login")
                anonymous = client.cookies.get("upt_session")
                login = self.sign_in(client)  # must not raise on a malformed setting
                self.assertEqual(login.status_code, 303)
                for sid in (anonymous, client.cookies.get("upt_session")):
                    with state.connect() as c:
                        row = c.execute("SELECT created_at,expires_at,absolute_expires_at FROM web_sessions WHERE id=?", (sid,)).fetchone()
                    created = datetime.fromisoformat(row[0])
                    self.assertAlmostEqual((datetime.fromisoformat(row[2]) - created).total_seconds(), absolute * 3600, delta=5)
                    self.assertAlmostEqual((datetime.fromisoformat(row[1]) - created).total_seconds(), idle * 60, delta=5)
                self.assertAlmostEqual(self.cookie_max_age(login), absolute * 3600, delta=5)

                page = client.get("/settings").text
                self.assertEqual("shorter than the 30-day defaults" in page, shorter)
                self.assertIn(_duration_label(idle), page)
                self.assertIn(_duration_label(absolute * 60), page)

                path = root / "installer-web.yml"
                path.write_text(yaml.safe_dump({"web": configured}))
                os.chmod(path, 0o600)
                before = path.read_bytes()
                done = subprocess.run([sys.executable, "-", str(path)], input=snippet, text=True, capture_output=True,
                                      env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual("WARNING" in done.stderr, shorter, done.stderr)
                self.assertEqual(path.read_bytes(), before)

    def test_settings_page_reports_effective_policy_and_warns_on_short_config(self):
        root, config, state, client, _ = self.authed()
        page = client.get("/settings").text
        self.assertIn("30 days", page)
        self.assertNotIn("shorter than the 30-day defaults", page)
        self.assertNotIn(client.cookies.get("upt_session"), page)
        config.settings["session_idle_minutes"] = 60; config.settings["session_absolute_hours"] = 12
        short = client.get("/settings").text
        self.assertIn("shorter than the 30-day defaults", short)
        self.assertNotIn(client.cookies.get("upt_session"), short)

    def test_installer_never_overwrites_existing_web_yml_and_reports_short_sessions(self):
        script = (ROOT / "install.sh").read_text()
        self.assertIn('if [ ! -e "$WEB_CONFIG" ]; then', script)
        snippet = script.split("<<'PY' || true\n", 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "web.yml"; path.write_text(SHORT_WEB_YML); os.chmod(path, 0o600)
            before = path.read_bytes()
            done = subprocess.run([sys.executable, "-", str(path)], input=snippet, text=True, capture_output=True,
                                  env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIn("WARNING", done.stderr)
            self.assertIn("session_idle_minutes=60", done.stderr)
            self.assertEqual(path.read_bytes(), before)
            path.write_text("web:\n  session_idle_minutes: 43200\n  session_absolute_hours: 720\n")
            done = subprocess.run([sys.executable, "-", str(path)], input=snippet, text=True, capture_output=True,
                                  env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
            self.assertEqual(done.stderr, "")


if __name__ == "__main__":
    unittest.main()
