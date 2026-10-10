"""Closure-pass coverage: proxy identity, HTTP security, CSRF and session lifecycle."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import os
import re
import tempfile
import unittest

os.environ.setdefault("UPT_TESTING", "1")
from pathlib import Path

from fastapi.testclient import TestClient

from docker_update_manager.auth import new_token, token_hash, utc_after
from docker_update_manager.config import WebConfig
from docker_update_manager.state import State
from docker_update_manager.webapp import (
    create_app, effective_client_ip, forwarded_proto_is_https, parse_trusted_networks)


class FakeAgent:
    def __init__(self):
        self.snapshot = {"status": "complete", "finished_at": "2026-09-22T10:00:00+00:00",
                         "payload": {"count": 1, "services": [{"service": {"key": "media/sonarr", "name": "sonarr", "stack": "media", "image": "repo/sonarr:4.0.1", "version": "4.0.1", "state": "running", "health": "healthy", "image_id": "sha256:x", "compose_files": []}, "status": "CURRENT"}]}}

    def call(self, operation, payload=None):
        if operation == "health": return {"ok": True, "docker": {"ok": True}}
        if operation == "snapshot": return self.snapshot
        if operation == "service": return self.snapshot["payload"]["services"][0]
        if operation == "audit_recent": return {"events": []}
        if operation == "scan_start": return {"run_id": "run-1", "status": "running"}
        if operation == "scan_status": return {"id": "run-1", "status": "complete", "events": []}
        raise AssertionError(operation)


class ProxyIdentityTests(unittest.TestCase):
    """Pure algorithm tests: the direct peer is authoritative."""

    def test_forwarding_ignored_without_trusted_proxies(self):
        networks = parse_trusted_networks([])
        self.assertEqual(effective_client_ip("203.0.113.9", "198.51.100.7", networks), "203.0.113.9")
        self.assertFalse(forwarded_proto_is_https("203.0.113.9", "https", networks, False))

    def test_single_trusted_proxy_resolves_client(self):
        networks = parse_trusted_networks(["127.0.0.1"])
        self.assertEqual(effective_client_ip("127.0.0.1", "198.51.100.7", networks), "198.51.100.7")
        self.assertTrue(forwarded_proto_is_https("127.0.0.1", "https", networks, False))

    def test_spoofed_leading_address_cannot_change_identity(self):
        networks = parse_trusted_networks(["127.0.0.1"])
        # The proxy appends the real client on the right; the forged left entry is ignored.
        self.assertEqual(effective_client_ip("127.0.0.1", "1.2.3.4, 198.51.100.7", networks), "198.51.100.7")

    def test_multiple_trusted_hops_walk_to_first_untrusted(self):
        networks = parse_trusted_networks(["127.0.0.1", "10.0.0.0/8"])
        self.assertEqual(effective_client_ip("127.0.0.1", "198.51.100.7, 10.0.0.5", networks), "198.51.100.7")

    def test_padded_chain_cannot_discard_the_proxy_observed_client(self):
        networks = parse_trusted_networks(["127.0.0.1"])
        # 20 forged entries would previously push the real client out of the bound.
        padded = ", ".join(["203.0.113.7"] * 20 + ["198.51.100.7"])
        self.assertEqual(effective_client_ip("127.0.0.1", padded, networks), "198.51.100.7")
        huge = ", ".join(["203.0.113.7"] * 200 + ["198.51.100.7"])
        self.assertEqual(effective_client_ip("127.0.0.1", huge, networks), "198.51.100.7")

    def test_forwarded_chain_is_only_authoritative_when_the_proxy_appends(self):
        # Documented deployment contract: the trusted proxy must append or
        # overwrite X-Forwarded-For. When it does not, the caller controls the
        # value the nearest hop reports, so identity follows the header. This
        # test pins that assumption so a future change to the contract is
        # deliberate rather than silent.
        networks = parse_trusted_networks(["127.0.0.1"])
        self.assertEqual(effective_client_ip("127.0.0.1", "203.0.113.7", networks), "203.0.113.7")
        deployment_notes = (Path(__file__).resolve().parents[1] / "docs" / "deployment.md").read_text()
        self.assertIn("appends or", deployment_notes)

    def test_unparseable_hop_stops_the_walk(self):
        networks = parse_trusted_networks(["127.0.0.1", "10.0.0.0/8"])
        chain = "203.0.113.9, garbage, 10.0.0.5"
        self.assertEqual(effective_client_ip("127.0.0.1", chain, networks), "10.0.0.5")

    def test_ipv4_mapped_ipv6_peer_matches_ipv4_proxy_rule(self):
        networks = parse_trusted_networks(["127.0.0.1"])
        self.assertEqual(effective_client_ip("::ffff:127.0.0.1", "198.51.100.7", networks), "198.51.100.7")
        self.assertTrue(forwarded_proto_is_https("::ffff:127.0.0.1", "https", networks, False))

    def test_catch_all_trusted_proxy_entries_are_refused(self):
        self.assertEqual(parse_trusted_networks(["0.0.0.0/0", "::/0"]), [])
        self.assertEqual(effective_client_ip("203.0.113.9", "198.51.100.7", parse_trusted_networks(["0.0.0.0/0"])), "203.0.113.9")

    def test_malformed_entries_are_ignored_safely(self):
        networks = parse_trusted_networks(["127.0.0.1"])
        self.assertEqual(effective_client_ip("127.0.0.1", "garbage, 198.51.100.7", networks), "198.51.100.7")
        self.assertEqual(effective_client_ip("127.0.0.1", "not-an-ip", networks), "127.0.0.1")
        self.assertEqual(effective_client_ip("127.0.0.1", "", networks), "127.0.0.1")

    def test_ipv6_peers_and_hops(self):
        networks = parse_trusted_networks(["::1"])
        self.assertEqual(effective_client_ip("::1", "2001:db8::5", networks), "2001:db8::5")
        self.assertEqual(effective_client_ip("2001:db8::5", "198.51.100.7", networks), "2001:db8::5")

    def test_non_ip_peer_is_retained(self):
        networks = parse_trusted_networks(["127.0.0.1"])
        self.assertEqual(effective_client_ip("testclient", "198.51.100.7", networks), "testclient")

    def test_invalid_trusted_proxy_entries_are_skipped(self):
        self.assertEqual(parse_trusted_networks(["nonsense", "127.0.0.1/32"]).__len__(), 1)


class WebHttpSecurityTests(unittest.TestCase):
    def make_client(self, *, trusted=None, peer=None, bootstrap=True, base_url="http://testserver"):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.config = WebConfig(path=str(root / "web.yml"))
        if trusted is not None:
            self.config.settings["trusted_proxies"] = trusted
        self.state = State(root / "state")
        self.code = new_token()
        self.state.create_credential("bootstrap", token_hash(self.code), utc_after(minutes=15))
        kwargs = {"base_url": base_url}
        if peer:
            kwargs["client"] = peer
        return TestClient(create_app(self.config, self.state, FakeAgent()), **kwargs)

    def session_rows(self):
        with self.state.connect() as c:
            return c.execute("SELECT COUNT(*) FROM web_sessions").fetchone()[0]

    def csrf_from(self, client, path="/setup"):
        page = client.get(path)
        return re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)

    def sign_in(self, client):
        csrf = self.csrf_from(client)
        client.post("/setup", data={"csrf": csrf, "bootstrap": self.code, "username": "admin",
                                    "password": "correct horse battery staple",
                                    "password_confirm": "correct horse battery staple"})
        page = client.get("/login")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        client.post("/login", data={"csrf": csrf, "username": "admin", "password": "correct horse battery staple"})
        return client

    def test_unauthenticated_pages_do_not_create_sessions(self):
        client = self.make_client()
        for path in ("/", "/services", "/history", "/settings", "/services/media/sonarr"):
            with self.subTest(path=path):
                response = client.get(path, follow_redirects=False)
                self.assertIn(response.status_code, (302, 303, 307))
        self.assertEqual(self.session_rows(), 0)

    def test_repeated_unauthenticated_requests_do_not_grow_session_table(self):
        client = self.make_client()
        before = self.session_rows()
        for _ in range(5):
            client.get("/", follow_redirects=False)
        self.assertEqual(self.session_rows(), before)

    def test_unauthenticated_api_returns_401_without_session(self):
        client = self.make_client()
        for path in ("/api/overview", "/api/services", "/api/services/media/sonarr", "/api/scan/run-1"):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 401)
        self.assertEqual(self.session_rows(), 0)

    def test_setup_and_login_still_issue_anonymous_csrf_sessions(self):
        client = self.make_client()
        page = client.get("/setup")
        self.assertEqual(page.status_code, 200)
        self.assertEqual(self.session_rows(), 1)
        self.assertIn("HttpOnly", page.headers.get("set-cookie", ""))
        self.assertIn("SameSite=lax", page.headers.get("set-cookie", ""))
        self.assertNotIn("Secure", page.headers.get("set-cookie", ""))
        # Anonymous pre-auth CSRF sessions stay browser-session cookies.
        self.assertNotIn("max-age", page.headers.get("set-cookie", "").lower())

    def test_allowed_host_accepts_port_and_ipv6_forms(self):
        client = self.make_client()
        self.assertEqual(client.get("/login", headers={"host": "localhost:8787"}).status_code, 200)
        self.assertEqual(client.get("/login", headers={"host": "127.0.0.1:8787"}).status_code, 200)
        self.assertEqual(client.get("/login", headers={"host": "[::1]:8787"}).status_code, 200)
        rejected = client.get("/login", headers={"host": "evil.example"})
        self.assertEqual(rejected.status_code, 400)
        self.assertNotIn("evil.example", rejected.headers.get("set-cookie", ""))

    def test_security_headers_present_without_wildcard_cors(self):
        client = self.make_client()
        response = client.get("/login", headers={"origin": "https://evil.example"})
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertEqual(response.headers["referrer-policy"], "same-origin")
        self.assertIn("camera=()", response.headers["permissions-policy"])
        self.assertNotIn("access-control-allow-origin", {k.lower() for k in response.headers})
        self.assertNotIn("strict-transport-security", response.headers)

    def test_trusted_proxy_forwarding_sets_secure_cookie_and_hsts(self):
        client = self.make_client(trusted=["127.0.0.1"], peer=("127.0.0.1", 5555))
        response = client.get("/setup", headers={"x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.7"})
        cookie = response.headers.get("set-cookie", "")
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertEqual(response.headers.get("strict-transport-security"), "max-age=31536000; includeSubDomains")

    def test_authenticated_cookie_is_secure_on_trusted_proxy_https(self):
        client = self.make_client(trusted=["127.0.0.1"], peer=("127.0.0.1", 5555))
        self.sign_in(client)
        response = client.get("/", headers={"x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.7"})
        cookie = response.headers.get("set-cookie", "")
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=lax", cookie)
        self.assertIn("Path=/", cookie)
        self.assertIn("max-age=", cookie.lower())
        self.assertIn("expires=", cookie.lower())

    def test_authenticated_cookie_is_secure_on_direct_https(self):
        client = self.make_client(base_url="https://testserver")
        self.sign_in(client)
        response = client.get("/")
        cookie = response.headers.get("set-cookie", "")
        self.assertIn("Secure", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("Max-Age=", cookie)

    def test_authenticated_cookie_is_not_secure_on_plain_http(self):
        client = self.make_client()
        self.sign_in(client)
        response = client.get("/")
        cookie = response.headers.get("set-cookie", "")
        self.assertNotIn("Secure", cookie)
        self.assertIn("Max-Age=", cookie)

    def test_untrusted_peer_forwarding_is_ignored(self):
        client = self.make_client(trusted=["10.9.9.9"], peer=("127.0.0.1", 5555))
        response = client.get("/setup", headers={"x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.7"})
        self.assertNotIn("Secure", response.headers.get("set-cookie", ""))
        self.assertNotIn("strict-transport-security", response.headers)

    def test_audit_and_throttle_use_effective_client_identity(self):
        client = self.make_client(trusted=["127.0.0.1"], peer=("127.0.0.1", 5555))
        client.get("/setup")  # establish anonymous session for CSRF
        for _ in range(8):
            page = client.get("/login")
            csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
            client.post("/login", headers={"x-forwarded-for": "198.51.100.7"},
                        data={"csrf": csrf, "username": "admin", "password": "wrong password here"})
        events = self.state.audit_events(50)
        self.assertTrue(all(e["client_ip"] == "198.51.100.7" for e in events if e["action"] == "login"))
        page = client.get("/login")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        limited = client.post("/login", headers={"x-forwarded-for": "198.51.100.7"},
                              data={"csrf": csrf, "username": "admin", "password": "wrong password here"})
        self.assertIn("temporarily unavailable", limited.text)

    def test_padded_forwarded_chain_cannot_bypass_throttle_or_spoof_audit(self):
        client = self.make_client(trusted=["127.0.0.1"], peer=("127.0.0.1", 5555))
        for index in range(8):
            forged = ", ".join([f"203.0.113.{index}"] * 20 + ["198.51.100.7"])
            page = client.get("/login")
            csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
            client.post("/login", headers={"x-forwarded-for": forged},
                        data={"csrf": csrf, "username": "admin", "password": "wrong password here"})
        page = client.get("/login")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        limited = client.post("/login", headers={"x-forwarded-for": ", ".join(["203.0.113.99"] * 20 + ["198.51.100.7"])},
                              data={"csrf": csrf, "username": "admin", "password": "wrong password here"})
        self.assertIn("temporarily unavailable", limited.text)
        identities = {e["client_ip"] for e in self.state.audit_events(50) if e["action"] == "login"}
        self.assertEqual(identities, {"198.51.100.7"})

    def test_forged_client_cannot_bypass_throttle_through_proxy(self):
        client = self.make_client(trusted=["127.0.0.1"], peer=("127.0.0.1", 5555))
        for _ in range(8):
            page = client.get("/login")
            csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
            client.post("/login", headers={"x-forwarded-for": "9.9.9.9, 198.51.100.7"},
                        data={"csrf": csrf, "username": "admin", "password": "wrong password here"})
        page = client.get("/login")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        response = client.post("/login", headers={"x-forwarded-for": "9.9.9.9, 198.51.100.7"},
                               data={"csrf": csrf, "username": "admin", "password": "wrong password here"})
        self.assertIn("temporarily unavailable", response.text)

    def test_state_changing_routes_require_csrf(self):
        client = self.sign_in(self.make_client())
        self.assertEqual(client.post("/scan", data={}).status_code, 403)
        self.assertEqual(client.post("/logout", data={}).status_code, 403)
        # Form-based flows re-render with a curated error instead of a bare 403;
        # the security property is that no state changes without a valid token.
        with self.state.connect() as c:
            before = c.execute("SELECT password_hash FROM users").fetchone()[0]
        rejected = client.post("/settings/password", data={"current_password": "correct horse battery staple",
                                                            "new_password": "another long password",
                                                            "new_password_confirm": "another long password"})
        self.assertEqual(rejected.status_code, 200)
        self.assertIn("expired", rejected.text.lower())
        with self.state.connect() as c:
            after = c.execute("SELECT password_hash FROM users").fetchone()[0]
            live = c.execute("SELECT COUNT(*) FROM web_sessions WHERE revoked_at IS NULL AND user_id IS NOT NULL").fetchone()[0]
        self.assertEqual(before, after)
        self.assertEqual(live, 1)

    def test_cross_origin_state_changes_are_rejected(self):
        client = self.sign_in(self.make_client())
        page = client.get("/")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        response = client.post("/scan", headers={"origin": "https://evil.example"}, data={"csrf": csrf})
        self.assertEqual(response.status_code, 403)

    def test_password_change_revokes_sessions_and_requires_csrf(self):
        client = self.sign_in(self.make_client())
        page = client.get("/settings")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        changed = client.post("/settings/password", data={"csrf": csrf, "current_password": "correct horse battery staple",
                                                            "new_password": "another long password", "new_password_confirm": "another long password"},
                              follow_redirects=False)
        self.assertEqual(changed.status_code, 303)
        with self.state.connect() as c:
            live = c.execute("SELECT COUNT(*) FROM web_sessions WHERE revoked_at IS NULL AND user_id IS NOT NULL").fetchone()[0]
        self.assertEqual(live, 0)

    def test_errors_are_curated(self):
        client = self.make_client()
        response = client.get("/api/services")
        self.assertNotIn("Traceback", response.text)
        self.assertEqual(response.json(), {"error": "authentication required"})


if __name__ == "__main__":
    unittest.main()
