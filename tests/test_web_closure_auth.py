"""Closure-pass coverage: bootstrap, recovery, password and session lifecycle."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import email.utils
import os
import re
import tempfile
import unittest
from http.cookies import SimpleCookie
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ.setdefault("UPT_TESTING", "1")
from pathlib import Path

from fastapi.testclient import TestClient

from docker_update_manager.auth import DUMMY_PASSWORD_HASH, hash_password, new_token, token_hash, utc_after, verify_password
from docker_update_manager.config import WebConfig
from docker_update_manager.webapp import WebApplication, create_app
from docker_update_manager.webstate import WebState


class FakeAgent:
    def call(self, operation, payload=None):
        if operation == "health": return {"ok": True, "docker": {"ok": True}}
        if operation == "snapshot": return {"status": "never", "payload": {"services": [], "count": 0}}
        if operation == "service": raise RuntimeError("service not found")
        if operation == "audit_recent": return {"events": []}
        if operation == "scan_start": return {"run_id": "run-1", "status": "running"}
        if operation == "scan_status": return {"id": "run-1", "status": "complete", "events": []}
        raise AssertionError(operation)


class AuthClosureTests(unittest.TestCase):
    def make_env(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        config = WebConfig(path=str(root / "web.yml"))
        state = WebState(root / "web-state")
        return root, config, state

    def make_client(self, state, config, agent=None):
        return TestClient(create_app(config, state, agent or FakeAgent()))

    def create_admin(self, state, username="admin", password="correct horse battery staple"):
        code = new_token()
        state.create_credential("bootstrap", token_hash(code), utc_after(minutes=15))
        user_id = state.create_user_with_credential(token_hash(code), username, hash_password(password))
        return code, user_id

    def csrf(self, client, path="/login"):
        page = client.get(path)
        return re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)

    def sign_in(self, client, username="admin", password="correct horse battery staple"):
        return client.post("/login", data={"csrf": self.csrf(client), "username": username, "password": password},
                           follow_redirects=False)

    def session_cookie(self, response):
        jar = SimpleCookie()
        jar.load(response.headers.get("set-cookie", ""))
        return jar["upt_session"]

    def cookie_expiry(self, response):
        raw = self.session_cookie(response)["expires"]
        return email.utils.parsedate_to_datetime(raw) if raw else None

    def cookie_max_age(self, response):
        raw = self.session_cookie(response)["max-age"]
        return int(raw) if raw else None

    def test_no_default_administrator_exists(self):
        _, config, state = self.make_env()
        self.assertIsNone(state.web_user())
        client = self.make_client(state, config)
        response = client.post("/login", data={"csrf": self.csrf(client), "username": "admin", "password": "whatever password"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid username or password", response.text)

    def test_unknown_username_uses_dummy_argon2_verification_and_generic_response(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        token = self.csrf(client)
        with patch("docker_update_manager.webapp.verify_password", wraps=verify_password) as verify:
            response = client.post("/login", data={"csrf": token, "username": "not-admin",
                                                   "password": "another password"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid username or password", response.text)
        self.assertEqual(verify.call_args.args[0], DUMMY_PASSWORD_HASH)

    def test_protected_render_reads_session_once_without_touching_each_request(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        original_session = state.session
        original_touch = state.touch_session
        counts = {"read": 0, "touch": 0}

        def counted_session(session_id):
            counts["read"] += 1
            return original_session(session_id)

        def counted_touch(*args, **kwargs):
            counts["touch"] += 1
            return original_touch(*args, **kwargs)

        state.session = counted_session
        state.touch_session = counted_touch
        response = client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(counts, {"read": 1, "touch": 0})

    def test_bootstrap_persists_across_instances_and_expires(self):
        root, config, state = self.make_env()
        code = new_token()
        state.create_credential("bootstrap", token_hash(code), utc_after(minutes=15))
        # A completely new state/app instance still accepts the same code.
        fresh = WebState(root / "web-state")
        client = self.make_client(fresh, config)
        response = client.post("/setup", data={"csrf": self.csrf(client, "/setup"), "bootstrap": code,
                                                "username": "admin", "password": "correct horse battery staple",
                                                "password_confirm": "correct horse battery staple"}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login?notice=setup")

        root2, config2, state2 = self.make_env()
        expired = new_token()
        state2.create_credential("bootstrap", token_hash(expired), "2000-01-01T00:00:00+00:00")
        client2 = self.make_client(state2, config2)
        rejected = client2.post("/setup", data={"csrf": self.csrf(client2, "/setup"), "bootstrap": expired,
                                                 "username": "admin", "password": "correct horse battery staple",
                                                 "password_confirm": "correct horse battery staple"})
        self.assertEqual(rejected.status_code, 200)
        self.assertIsNone(state2.web_user())

    def test_second_bootstrap_and_registration_are_rejected(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        with self.assertRaisesRegex(ValueError, "administrator already exists"):
            state.create_credential("bootstrap", token_hash(new_token()), utc_after(minutes=15))
        user_id = state.web_user()["id"]
        self.assertGreater(user_id, 0)

    def test_argon2_hash_and_verify_path(self):
        digest = hash_password("correct horse battery staple")
        self.assertTrue(digest.startswith("$argon2id$"))
        self.assertTrue(verify_password(digest, "correct horse battery staple"))
        self.assertFalse(verify_password(digest, "wrong password entirely"))
        with self.assertRaises(ValueError):
            hash_password("short")

    def test_failed_login_is_not_enumerable(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        unknown = client.post("/login", data={"csrf": self.csrf(client), "username": "nobody", "password": "correct horse battery staple"})
        wrong = client.post("/login", data={"csrf": self.csrf(client), "username": "admin", "password": "not the password"})
        self.assertEqual(unknown.status_code, wrong.status_code)
        self.assertEqual(unknown.text, wrong.text)

    def test_login_throttle_blocks_then_success_clears_it(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        for _ in range(8):
            client.post("/login", data={"csrf": self.csrf(client), "username": "admin", "password": "not the password"})
        limited = client.post("/login", data={"csrf": self.csrf(client), "username": "admin", "password": "correct horse battery staple"},
                              follow_redirects=False)
        self.assertIn("temporarily unavailable", limited.text)

    def test_successful_login_clears_recorded_failures(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        app = WebApplication(config, state, FakeAgent())
        app.login_limiter.limit = 2  # deterministic small window
        client = TestClient(app.app)
        client.post("/login", data={"csrf": self.csrf(client), "username": "admin", "password": "wrong password"})
        signed_in = self.sign_in(client)
        self.assertEqual(signed_in.status_code, 303)
        # Without clearing on success these two failures would already exhaust the
        # limit of 2 and the next attempt would be rate limited.
        client.post("/login", data={"csrf": self.csrf(client), "username": "admin", "password": "wrong password"})
        second = client.post("/login", data={"csrf": self.csrf(client), "username": "admin", "password": "wrong password"})
        self.assertIn("Invalid username or password", second.text)
        self.assertNotIn("temporarily unavailable", second.text)

    def test_session_id_rotates_on_login(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        csrf = self.csrf(client)  # establishes the anonymous CSRF session
        anonymous = client.cookies.get("upt_session")
        response = client.post("/login", data={"csrf": csrf, "username": "admin",
                                               "password": "correct horse battery staple"}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        authenticated = client.cookies.get("upt_session")
        self.assertTrue(anonymous and authenticated)
        self.assertNotEqual(anonymous, authenticated)
        self.assertIsNone(state.session(anonymous))

    def test_login_cookie_is_persistent_and_bounded_by_absolute_expiry(self):
        _, config, state = self.make_env()
        config.settings["session_absolute_hours"] = 3
        self.create_admin(state)
        client = self.make_client(state, config)
        response = self.sign_in(client)
        self.assertEqual(response.status_code, 303)
        cookie = self.session_cookie(response)
        max_age = self.cookie_max_age(response)
        expires = self.cookie_expiry(response)
        # A persistent cookie carries both attributes; the anonymous CSRF
        # session cookie intentionally does not.
        self.assertIsNotNone(max_age)
        self.assertIsNotNone(expires)
        sid = client.cookies.get("upt_session")
        absolute = datetime.fromisoformat(state.session(sid)["absolute_expires_at"])
        now = datetime.now(timezone.utc)
        remaining = (absolute - now).total_seconds()
        self.assertGreater(remaining, 2.9 * 3600)
        self.assertLessEqual(remaining, 3 * 3600)
        # Browser-visible expiry is bounded by the server absolute deadline.
        self.assertLessEqual(abs((expires - absolute).total_seconds()), 5)
        self.assertLessEqual(max_age, int(remaining) + 5)
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "lax")
        self.assertEqual(cookie["path"], "/")

    def test_default_session_policy_is_thirty_days_idle_and_absolute(self):
        _, config, state = self.make_env()
        self.assertEqual(config.settings["session_idle_minutes"], 30 * 24 * 60)
        self.assertEqual(config.settings["session_absolute_hours"], 30 * 24)
        self.create_admin(state)
        client = self.make_client(state, config)
        response = self.sign_in(client)
        self.assertEqual(response.status_code, 303)
        thirty_days = 30 * 24 * 3600
        self.assertLessEqual(self.cookie_max_age(response), thirty_days)
        self.assertGreater(self.cookie_max_age(response), thirty_days - 120)
        session = state.session(client.cookies.get("upt_session"))
        now = datetime.now(timezone.utc)
        idle = datetime.fromisoformat(session["expires_at"])
        absolute = datetime.fromisoformat(session["absolute_expires_at"])
        self.assertGreater((idle - now).total_seconds(), 29.9 * 24 * 3600)
        self.assertLessEqual((idle - now).total_seconds(), 30 * 24 * 3600)
        self.assertGreater((absolute - now).total_seconds(), 29.9 * 24 * 3600)
        self.assertLessEqual((absolute - now).total_seconds(), 30 * 24 * 3600)

    def test_login_notices_are_accurate_allowlisted_and_not_reflected(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        ordinary = client.get("/login")
        self.assertNotIn('class="alert alert-success"', ordinary.text)
        self.sign_in(client)
        page = client.get("/")
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        signed_out = client.post("/logout", data={"csrf": csrf}, follow_redirects=False)
        self.assertIn("notice=logout", signed_out.headers["location"])
        setup = client.get("/login?notice=setup")
        self.assertIn("Setup is complete", setup.text)
        password = client.get("/login?notice=password")
        self.assertIn("password was changed", password.text)
        injected = client.get("/login?notice=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertNotIn("<script>alert(1)</script>", injected.text)

    def test_anonymous_login_csrf_session_is_not_mislabelled_expired(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.csrf(client)
        protected = client.get("/", follow_redirects=False)
        self.assertEqual(protected.status_code, 303)
        self.assertEqual(protected.headers["location"], "/login")

    def test_logout_revokes_session(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        sid = client.cookies.get("upt_session")
        page = client.get("/")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        client.post("/logout", data={"csrf": csrf})
        self.assertIsNone(state.session(sid))
        self.assertIn(client.get("/", follow_redirects=False).status_code, (302, 303, 307))

    def test_idle_expiry_revokes_session(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        sid = client.cookies.get("upt_session")
        with state.connect() as c:
            c.execute("UPDATE web_sessions SET expires_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", sid))
        expired = client.get("/", follow_redirects=False)
        self.assertIn(expired.status_code, (302, 303, 307))
        self.assertEqual(expired.headers["location"], "/login?notice=session-expired")
        self.assertIsNone(state.session(sid))

    def test_absolute_expiry_is_independent_of_idle_touch(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        sid = client.cookies.get("upt_session")
        with state.connect() as c:
            c.execute("UPDATE web_sessions SET absolute_expires_at=? WHERE id=?", ("2000-01-01T00:00:00+00:00", sid))
        self.assertIn(client.get("/", follow_redirects=False).status_code, (302, 303, 307))
        self.assertIsNone(state.session(sid))

    def test_idle_touch_recomputes_idle_window_but_not_absolute_expiry(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        sid = client.cookies.get("upt_session")
        inflated = (datetime.now(timezone.utc) + timedelta(days=45)).replace(microsecond=0).isoformat()
        last_seen = (datetime.now(timezone.utc) - timedelta(minutes=6)).replace(microsecond=0).isoformat()
        with state.connect() as c:
            c.execute("UPDATE web_sessions SET expires_at=?,last_seen_at=? WHERE id=?", (inflated, last_seen, sid))
            absolute_before = c.execute("SELECT absolute_expires_at FROM web_sessions WHERE id=?", (sid,)).fetchone()[0]
        client.get("/")
        with state.connect() as c:
            row = c.execute("SELECT expires_at, absolute_expires_at FROM web_sessions WHERE id=?", (sid,)).fetchone()
        # The sliding 30-day idle window is recomputed from now, not left at an
        # artificially inflated value, and is capped at the original absolute
        # 30-day deadline rather than extending it.
        self.assertLess(datetime.fromisoformat(row[0]), datetime.fromisoformat(inflated))
        self.assertGreater(datetime.fromisoformat(row[0]), datetime.now(timezone.utc))
        self.assertEqual(row[1], absolute_before)
        self.assertEqual(row[0], absolute_before)

    def test_idle_touch_interval_scales_below_short_configured_idle_timeout(self):
        _, config, state = self.make_env()
        config.settings["session_idle_minutes"] = 2
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        sid = client.cookies.get("upt_session")
        last_seen = (datetime.now(timezone.utc) - timedelta(seconds=65)).replace(microsecond=0).isoformat()
        expires = (datetime.now(timezone.utc) + timedelta(seconds=55)).replace(microsecond=0).isoformat()
        with state.connect() as connection:
            connection.execute(
                "UPDATE web_sessions SET last_seen_at=?,expires_at=? WHERE id=?",
                (last_seen, expires, sid),
            )

        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        refreshed = state.session(sid)
        self.assertGreater(datetime.fromisoformat(refreshed["last_seen_at"]), datetime.fromisoformat(last_seen))
        self.assertGreater(datetime.fromisoformat(refreshed["expires_at"]), datetime.fromisoformat(expires))

    def _new_authenticated_cookie(self):
        root, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        return root, config, state, client.cookies.get("upt_session")

    def test_persisted_cookie_survives_browser_restart(self):
        root, config, state, cookie = self._new_authenticated_cookie()
        # A brand new client/context presenting only the persisted cookie stays
        # authenticated without an interactive login.
        restarted = self.make_client(state, config)
        restarted.cookies.set("upt_session", cookie)
        page = restarted.get("/", follow_redirects=False)
        self.assertEqual(page.status_code, 200)
        self.assertIn("/logout", page.text)

    def test_persisted_session_survives_web_process_restart(self):
        root, config, state, cookie = self._new_authenticated_cookie()
        # A new WebState/WebApplication over the same persistent DB must accept
        # the still-valid session.
        fresh_state = WebState(root / "web-state")
        fresh_client = self.make_client(fresh_state, config)
        fresh_client.cookies.set("upt_session", cookie)
        page = fresh_client.get("/services", follow_redirects=False)
        self.assertEqual(page.status_code, 200)
        self.assertIsNotNone(fresh_state.session(cookie))

    def test_rendered_response_cookie_never_exceeds_absolute_expiry(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        sid = client.cookies.get("upt_session")
        absolute = datetime.fromisoformat(state.session(sid)["absolute_expires_at"])
        for _ in range(3):
            response = client.get("/")
            self.assertEqual(response.status_code, 200)
            expires = self.cookie_expiry(response)
            max_age = self.cookie_max_age(response)
            self.assertIsNotNone(expires)
            # Refreshing on normal rendered responses must not push the
            # browser cookie beyond the fixed server absolute deadline.
            self.assertLessEqual(abs((expires - absolute).total_seconds()), 5)
            self.assertLessEqual(max_age, int((absolute - datetime.now(timezone.utc)).total_seconds()) + 5)

    def test_logout_revokes_persistent_session_and_expires_cookie(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        sid = client.cookies.get("upt_session")
        page = client.get("/")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        response = client.post("/logout", data={"csrf": csrf}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIsNone(state.session(sid))
        deleted = response.headers.get("set-cookie", "")
        self.assertIn("upt_session=", deleted)
        self.assertIn("Max-Age=0", deleted)
        redirected = client.get("/", follow_redirects=False)
        self.assertIn(redirected.status_code, (302, 303, 307))

    def test_absolute_expiry_rejects_stale_persistent_cookie(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        sid = client.cookies.get("upt_session")
        # Keep a valid-looking browser cookie while the server absolute deadline
        # has already passed; the request must still be rejected.
        with state.connect() as connection:
            connection.execute("UPDATE web_sessions SET absolute_expires_at=?,expires_at=? WHERE id=?",
                               ("2000-01-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00", sid))
        expired = client.get("/", follow_redirects=False)
        self.assertIn(expired.status_code, (302, 303, 307))
        self.assertEqual(expired.headers["location"], "/login?notice=session-expired")
        self.assertIsNone(state.session(sid))

    def test_shorter_custom_session_settings_stay_bounded(self):
        _, config, state = self.make_env()
        config.settings["session_idle_minutes"] = 60
        config.settings["session_absolute_hours"] = 2
        self.create_admin(state)
        client = self.make_client(state, config)
        response = self.sign_in(client)
        self.assertEqual(response.status_code, 303)
        max_age = self.cookie_max_age(response)
        self.assertIsNotNone(max_age)
        self.assertLessEqual(max_age, 2 * 3600)
        self.assertGreater(max_age, 1.9 * 3600)
        session = state.session(client.cookies.get("upt_session"))
        idle = datetime.fromisoformat(session["expires_at"])
        absolute = datetime.fromisoformat(session["absolute_expires_at"])
        self.assertLessEqual(idle, absolute)

    def test_anonymous_preauth_cookie_is_not_persistent(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        page = client.get("/login")
        cookie = self.session_cookie(page)
        self.assertFalse(cookie["max-age"])
        self.assertFalse(cookie["expires"])

    def test_password_change_revokes_sessions(self):
        _, config, state = self.make_env()
        self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        page = client.get("/settings")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        response = client.post("/settings/password", data={"csrf": csrf, "current_password": "correct horse battery staple",
                                                            "new_password": "another long password",
                                                            "new_password_confirm": "another long password"}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login?notice=password")
        with state.connect() as c:
            live = c.execute("SELECT COUNT(*) FROM web_sessions WHERE user_id IS NOT NULL AND revoked_at IS NULL").fetchone()[0]
        self.assertEqual(live, 0)
        self.assertTrue(verify_password(state.web_user()["password_hash"], "another long password"))

    def test_recovery_credential_expiry_one_time_and_replay(self):
        _, _, state = self.make_env()
        _, user_id = self.create_admin(state)

        expired = token_hash(new_token())
        state.create_credential("recovery", expired, "2000-01-01T00:00:00+00:00")
        with self.assertRaisesRegex(ValueError, "invalid or expired recovery code"):
            state.update_password_with_credential(expired, user_id, hash_password("another long password"))

        code = new_token(); digest = token_hash(code)
        state.create_credential("recovery", digest, utc_after(minutes=15))
        state.update_password_with_credential(digest, user_id, hash_password("another long password"))
        self.assertTrue(verify_password(state.web_user()["password_hash"], "another long password"))
        with self.assertRaises(ValueError):
            state.update_password_with_credential(digest, user_id, hash_password("third long password"))

    def test_failed_operation_does_not_consume_bootstrap_code(self):
        _, config, state = self.make_env()
        code = new_token(); digest = token_hash(code)
        state.create_credential("bootstrap", digest, utc_after(minutes=15))
        client = self.make_client(state, config)
        # Empty username fails validation after the credential lookup starts.
        rejected = client.post("/setup", data={"csrf": self.csrf(client, "/setup"), "bootstrap": code, "username": "",
                                                "password": "correct horse battery staple",
                                                "password_confirm": "correct horse battery staple"})
        self.assertEqual(rejected.status_code, 200)
        self.assertIsNone(state.web_user())
        accepted = client.post("/setup", data={"csrf": self.csrf(client, "/setup"), "bootstrap": code, "username": "admin",
                                                "password": "correct horse battery staple",
                                                "password_confirm": "correct horse battery staple"}, follow_redirects=False)
        self.assertEqual(accepted.status_code, 303)

    def test_failed_recovery_leaves_credential_usable(self):
        _, _, state = self.make_env()
        _, user_id = self.create_admin(state)
        code = new_token(); digest = token_hash(code)
        state.create_credential("recovery", digest, utc_after(minutes=15))
        with self.assertRaises(ValueError):
            state.update_password_with_credential(digest, user_id + 500, hash_password("another long password"))
        state.update_password_with_credential(digest, user_id, hash_password("another long password"))
        self.assertTrue(verify_password(state.web_user()["password_hash"], "another long password"))

    def test_secrets_absent_from_audit_and_rendered_pages(self):
        _, config, state = self.make_env()
        code, _ = self.create_admin(state)
        client = self.make_client(state, config)
        self.sign_in(client)
        sid = client.cookies.get("upt_session")
        page = client.get("/")
        body = page.text
        self.assertNotIn(sid, body)
        self.assertNotIn(code, body)
        digest = state.web_user()["password_hash"]
        self.assertNotIn(digest, body)
        for event in state.audit_events(50):
            blob = repr(event)
            self.assertNotIn(sid, blob)
            self.assertNotIn(code, blob)
            self.assertNotIn(digest, blob)
            self.assertNotIn("correct horse battery staple", blob)


if __name__ == "__main__":
    unittest.main()
