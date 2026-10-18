import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import os
import re
import sqlite3
import tempfile
import unittest

# Allow temporary state roots for tests; production keeps the managed-root check.
os.environ.setdefault("UPT_TESTING", "1")
from pathlib import Path

from fastapi.testclient import TestClient

from docker_update_manager.agent import AgentClient
from docker_update_manager.auth import new_token, token_hash, utc_after
from docker_update_manager.config import Config, WebConfig
from docker_update_manager.state import State
from docker_update_manager.webapp import create_app
from docker_update_manager.webservice import READ_ONLY_OPERATIONS, ReadOnlyService, _public_service, _public_result, _safe_error
from docker_update_manager.webstate import WebState
from docker_update_manager.webcli import _prepare_web_state_permissions


class FakeAgent:
    def __init__(self):
        self.snapshot = {"status": "complete", "finished_at": "2026-09-22T10:00:00+00:00", "payload": {"count": 1, "services": [{"service": {"key": "media/sonarr", "name": "sonarr", "stack": "media", "image": "repo/sonarr:4.0.1", "version": "4.0.1", "state": "running", "health": "healthy", "image_id": "sha256:x", "compose_files": []}, "status": "CURRENT"}]}}
    def call(self, operation, payload=None):
        if operation == "health": return {"ok": True, "docker": {"ok": True}}
        if operation == "snapshot": return self.snapshot
        if operation == "service":
            if (payload or {}).get("service_key") != "media/sonarr": raise RuntimeError("service not found")
            return self.snapshot["payload"]["services"][0]
        if operation == "audit_recent": return {"events": []}
        if operation == "scan_start": return {"run_id": "run-1", "status": "running"}
        if operation == "scan_status": return {"id": "run-1", "status": "complete", "events": []}
        raise AssertionError(operation)


class WebFoundationTests(unittest.TestCase):
    def make_app(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.config = WebConfig(path=str(root / "web.yml"))
        self.config.settings["socket"] = str(root / "agent.sock")
        self.state = State(root / "state")
        code = new_token()
        self.state.create_credential("bootstrap", token_hash(code), utc_after(minutes=15))
        app = create_app(self.config, self.state, FakeAgent())
        return TestClient(app), code

    def tearDown(self):
        if hasattr(self, "tmp"): self.tmp.cleanup()

    def test_web_state_permissions_reject_symlinked_directory(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        target = root / "target"; target.mkdir()
        link = root / "link"; link.symlink_to(target, target_is_directory=True)
        config = WebConfig(path=str(root / "web.yml"))
        state = WebState(link)
        with self.assertRaises(ValueError):
            _prepare_web_state_permissions(config, state)

    def test_web_state_permissions_reject_unmanaged_absolute_paths(self):
        # The config file path must be portable: a CI runner cannot read /root,
        # and config discovery must not mask the state-path checks under test.
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        config = WebConfig(path=str(Path(tmp.name) / "not-used-web-config.yml"))
        for unsafe in (Path("/"), Path("/etc/docker-update-manager"), Path("/var/lib/other-app")):
            with self.subTest(path=str(unsafe)), self.assertRaises(ValueError):
                _prepare_web_state_permissions(config, WebState(unsafe))

    def test_unreadable_configuration_path_reports_curated_error(self):
        # ``Path.exists()`` raises PermissionError on an unreadable parent for
        # some supported Python versions; configuration discovery must surface a
        # clear error rather than a traceback.
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        locked = Path(tmp.name) / "locked"
        locked.mkdir(); locked.chmod(0o000)
        self.addCleanup(locked.chmod, 0o700)
        unreadable = locked / "config.yml"
        if os.geteuid() == 0:
            self.skipTest("permission-based checks are not meaningful as root")
        with self.assertRaisesRegex(ValueError, "cannot access configuration file"):
            Config(path=str(unreadable))
        with self.assertRaisesRegex(ValueError, "cannot access configuration file"):
            WebConfig(path=str(unreadable))

    def test_web_state_is_separate_from_legacy_docker_state(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        state = WebState(Path(tmp.name) / "web")
        self.assertIsNone(state.web_user())
        with state.connect() as c:
            self.assertIsNone(c.execute("SELECT name FROM sqlite_master WHERE name='history'").fetchone())
            self.assertIsNotNone(c.execute("SELECT name FROM sqlite_master WHERE name='users'").fetchone())
            columns = {row[1] for row in c.execute("PRAGMA table_info(scan_runs)")}
            self.assertIn("heartbeat_at", columns)

    def test_migration_preserves_legacy_rows_and_adds_web_tables(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); root.mkdir(exist_ok=True)
        db = root / "history.sqlite3"
        conn = sqlite3.connect(db)
        conn.executescript("CREATE TABLE history(id INTEGER PRIMARY KEY, service TEXT NOT NULL, action TEXT NOT NULL, result TEXT NOT NULL); INSERT INTO history(service,action,result) VALUES('sonarr','update','SUCCESS');")
        conn.commit(); conn.close()
        with self.assertRaisesRegex(RuntimeError, "unversioned"):
            State(root).history()
        state = State(root, quiescent_transition=True)
        self.assertEqual(state.history()[0]["service"], "sonarr")
        with state.connect() as c:
            self.assertEqual(c.execute("SELECT version FROM schema_version").fetchone()[0], 9)
            self.assertIsNotNone(c.execute("SELECT name FROM sqlite_master WHERE name='users'").fetchone())

    def test_bootstrap_login_and_cached_overview(self):
        client, code = self.make_app()
        page = client.get("/setup")
        self.assertEqual(page.status_code, 200)
        csrf = re.search(r'name="csrf" value="([^"]+)', page.text).group(1)
        created = client.post("/setup", data={"csrf": csrf, "bootstrap": code, "username": "admin", "password": "correct horse battery staple", "password_confirm": "correct horse battery staple"}, follow_redirects=False)
        self.assertEqual(created.status_code, 303)
        page = client.get("/login")
        csrf = re.search(r'name="csrf" value="([^"]+)', page.text).group(1)
        login = client.post("/login", data={"csrf": csrf, "username": "admin", "password": "correct horse battery staple"}, follow_redirects=False)
        self.assertEqual(login.status_code, 303)
        home = client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn("Overview", home.text)
        self.assertIn("sonarr", client.get("/services").text)

    def test_csrf_rejects_scan_and_logout(self):
        client, code = self.make_app()
        page = client.get("/setup"); csrf = re.search(r'name="csrf" value="([^"]+)', page.text).group(1)
        client.post("/setup", data={"csrf": csrf, "bootstrap": code, "username": "admin", "password": "correct horse battery staple", "password_confirm": "correct horse battery staple"})
        page = client.get("/login"); csrf = re.search(r'name="csrf" value="([^"]+)', page.text).group(1)
        client.post("/login", data={"csrf": csrf, "username": "admin", "password": "correct horse battery staple"})
        self.assertEqual(client.post("/scan", data={}).status_code, 403)
        self.assertEqual(client.post("/logout", data={}).status_code, 403)

    def test_agent_allowlist_rejects_mutations(self):
        self.assertNotIn("update", READ_ONLY_OPERATIONS)
        with self.assertRaises(PermissionError): AgentClient("/tmp/no-such.sock").call("update", {"service": "x"})
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        service = ReadOnlyService(Config(path=str(Path(tmp.name) / "config.yml")), State(Path(tmp.name) / "state"))
        with self.assertRaises(PermissionError): service.handle("update", {})

    def test_web_route_inventory_exposes_only_bounded_single_service_update_and_rollback(self):
        client, _ = self.make_app()
        routes = [(getattr(route, "path", ""), set(getattr(route, "methods", None) or ())) for route in client.app.routes]
        mutation_paths = [path for path, methods in routes if any(word in path.lower() for word in
                         ("update", "rollback", "pin", "restart", "remove", "cleanup", "convert", "docker/exec"))
                          and not methods <= {"GET", "HEAD"}]
        self.assertEqual(mutation_paths, ["/operations/update", "/operations/rollback"])
        # The Updates overview is a read-only projection of cached scan data.
        self.assertEqual([methods for path, methods in routes if path == "/updates"], [{"GET"}])

    def test_service_path_is_cached_identifier_not_host_path(self):
        client, code = self.make_app()
        page = client.get("/setup"); csrf = re.search(r'name="csrf" value="([^"]+)', page.text).group(1)
        client.post("/setup", data={"csrf": csrf, "bootstrap": code, "username": "admin", "password": "correct horse battery staple", "password_confirm": "correct horse battery staple"})
        page = client.get("/login"); csrf = re.search(r'name="csrf" value="([^"]+)', page.text).group(1)
        client.post("/login", data={"csrf": csrf, "username": "admin", "password": "correct horse battery staple"})
        self.assertIn(client.get("/services/etc/passwd").status_code, (404, 503))

    def test_web_dto_omits_labels_and_redacts_errors(self):
        class Service:
            def as_dict(self):
                return {"key": "x", "name": "x", "image": "repo:x", "labels": {"password": "do-not-expose"}, "state": "running"}
        public = _public_service(Service())
        self.assertNotIn("labels", public)
        class Result:
            service = Service(); status = "CURRENT"; remote_digest = None; remote_version = None; remote_created = None; error = None
        self.assertEqual(_public_result(Result())["status"], "CURRENT")
        self.assertNotIn("do-not-expose", _safe_error("authorization=secret https://u:p@example.invalid"))

    def test_scan_state_is_atomic_and_reconnectable(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        state = State(Path(tmp.name) / "state")
        state.start_scan("run-1", 1)
        state.scan_event("run-1", "task_completed", service="media/sonarr", status="CURRENT", completed=1)
        state.finish_scan("run-1", "complete", services=[{"service": {"key": "media/sonarr", "name": "sonarr"}, "status": "CURRENT"}])
        run = state.scan_run("run-1")
        self.assertEqual(run["status"], "complete")
        self.assertEqual(len(run["events"]), 1)
        self.assertEqual(state.latest_scan()["payload"]["count"], 1)

    def test_cross_origin_state_change_is_rejected(self):
        client, code = self.make_app()
        page = client.get("/setup"); csrf = re.search(r'name="csrf" value="([^"]+)', page.text).group(1)
        response = client.post("/setup", headers={"Origin": "https://evil.example"}, data={"csrf": csrf, "bootstrap": code, "username": "admin", "password": "correct horse battery staple", "password_confirm": "correct horse battery staple"})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.state.web_user())

    def test_security_headers_host_validation_and_session_cookie(self):
        client, _ = self.make_app()
        response = client.get("/setup")
        self.assertEqual(response.status_code, 200)
        self.assertIn("default-src \x27self\x27", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        cookie = response.headers.get("set-cookie", "")
        self.assertIn("HttpOnly", cookie); self.assertIn("SameSite=lax", cookie)
        rejected = client.get("/setup", headers={"host": "attacker.example"})
        self.assertEqual(rejected.status_code, 400)

    def test_expired_session_is_rejected(self):
        client, code = self.make_app()
        page = client.get("/setup"); csrf = re.search(r'name="csrf" value="([^"]+)', page.text).group(1)
        client.post("/setup", data={"csrf": csrf, "bootstrap": code, "username": "admin", "password": "correct horse battery staple", "password_confirm": "correct horse battery staple"})
        page = client.get("/login"); csrf = re.search(r'name="csrf" value="([^"]+)', page.text).group(1)
        client.post("/login", data={"csrf": csrf, "username": "admin", "password": "correct horse battery staple"})
        with self.state.connect() as c: c.execute("UPDATE web_sessions SET expires_at='2000-01-01T00:00:00+00:00' WHERE user_id IS NOT NULL")
        self.assertEqual(client.get("/", follow_redirects=False).headers.get("location"), "/login?notice=session-expired")


if __name__ == "__main__": unittest.main()
