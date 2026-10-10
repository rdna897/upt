import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

from docker_update_manager.auth import hash_password, token_hash, utc_after
from docker_update_manager.config import Config, WebConfig
from docker_update_manager.lock import Lock
from docker_update_manager.state import State
from docker_update_manager.webservice import AgentServer, ReadOnlyService
from docker_update_manager.webcli import web_state
from docker_update_manager.webstate import WebState


class WebRemediationTests(unittest.TestCase):
    def make_state(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        return State(Path(self.tmp.name) / "state")

    def set_testing(self, enabled=True):
        previous = os.environ.get("UPT_TESTING")
        def restore():
            if previous is None: os.environ.pop("UPT_TESTING", None)
            else: os.environ["UPT_TESTING"] = previous
        self.addCleanup(restore)
        os.environ["UPT_TESTING"] = "1" if enabled else ""
        if not enabled: os.environ.pop("UPT_TESTING", None)

    def test_invalid_web_state_root_is_rejected_without_creation(self):
        self.set_testing(False)
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        target = Path(tmp.name) / "must-not-exist"
        config = WebConfig(path=str(Path(tmp.name) / "missing.yml")); config.settings["state_dir"] = str(target)
        with self.assertRaises(ValueError): web_state(config)
        self.assertFalse(target.exists())

    def test_symlinked_state_files_are_rejected_before_any_write(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.set_testing(True)
        root = Path(tmp.name) / "web"; outside = Path(tmp.name) / "outside"
        root.mkdir(); outside.mkdir()
        config = WebConfig(path=str(Path(tmp.name) / "missing.yml")); config.settings["state_dir"] = str(root)
        state = WebState(root)
        victim = outside / "escaped.sqlite3"

        (root / "history.sqlite3").symlink_to(victim)
        with self.assertRaisesRegex(ValueError, "symlinked web state file"):
            web_state(config)
        with self.assertRaisesRegex(ValueError, "symlinked web state file"):
            state.web_user()
        self.assertFalse(victim.exists())

        (root / "history.sqlite3").unlink()
        (root / "web.lock").symlink_to(outside / "escaped.lock")
        with self.assertRaisesRegex(ValueError, "symlinked web state file"):
            web_state(config)
        self.assertFalse((outside / "escaped.lock").exists())

    def test_lock_refuses_symlinked_path(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name); target = root / "outside.lock"
        link = root / "web.lock"; link.symlink_to(target)
        with self.assertRaises(ValueError):
            with Lock(link, no_follow=True): pass
        self.assertFalse(target.exists())

    def test_config_instances_do_not_share_mutable_defaults(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        first = WebConfig(str(Path(tmp.name) / "missing.yml")); first.settings["socket"] = "/tmp/mutated.sock"
        second = WebConfig(str(Path(tmp.name) / "missing.yml"))
        self.assertEqual(second.socket_path, Path("/run/docker-update-manager/agent.sock"))
        core = Config(str(Path(tmp.name) / "missing.yml"))
        core.data["retention"]["recovery_days"] = 1
        self.assertEqual(Config(str(Path(tmp.name) / "missing.yml")).data["retention"]["recovery_days"], 7)

    def test_nondefault_socket_is_shared_by_web_and_agent_config(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "web.yml"
        path.write_text("web:\n  socket: /tmp/custom-upt-agent.sock\n")
        first, second = WebConfig(str(path)), WebConfig(str(path))
        self.assertEqual(first.socket_path, second.socket_path)
        self.assertEqual(str(first.socket_path), "/tmp/custom-upt-agent.sock")

    def test_main_config_no_longer_owns_web_boundary(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "config.yml"; path.write_text("web:\n  socket: /tmp/wrong.sock\n")
        loaded = Config(str(path))
        self.assertNotIn("web", loaded.data)
        self.assertEqual(WebConfig(str(Path(tmp.name) / "missing.yml")).socket_path,
                         Path("/run/docker-update-manager/agent.sock"))

    def test_bootstrap_credential_rejected_after_admin_exists(self):
        state = self.make_state(); state.create_user("admin", hash_password("long enough password"))
        with self.assertRaisesRegex(ValueError, "administrator already exists"):
            state.create_credential("bootstrap", token_hash("new"), utc_after(minutes=15))

    def test_bootstrap_failure_does_not_consume_credential(self):
        state = self.make_state(); digest = token_hash("one-use")
        state.create_credential("bootstrap", digest, utc_after(minutes=15))
        with state.connect() as c:
            c.execute("INSERT INTO users(username,password_hash,disabled) VALUES(?,?,1)", ("taken", "x"))
        with self.assertRaises(Exception):
            state.create_user_with_credential(digest, "taken", hash_password("long enough password"))
        user_id = state.create_user_with_credential(digest, "admin", hash_password("long enough password"))
        self.assertGreater(user_id, 0)

    def test_bootstrap_code_has_exactly_one_concurrent_winner(self):
        state = self.make_state(); digest = token_hash("race")
        state.create_credential("bootstrap", digest, utc_after(minutes=15)); outcomes=[]
        def use(index):
            try: state.create_user_with_credential(digest, f"admin{index}", hash_password("long enough password")); outcomes.append("ok")
            except Exception: outcomes.append("rejected")
        threads=[threading.Thread(target=use,args=(i,)) for i in range(2)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual(outcomes.count("ok"), 1)

    def test_recovery_database_failure_keeps_credential(self):
        state = self.make_state(); user=state.create_user("admin", hash_password("long enough password")); digest=token_hash("recover")
        state.create_credential("recovery", digest, utc_after(minutes=15))
        with self.assertRaises(ValueError): state.update_password_with_credential(digest, user + 99, "replacement")
        state.update_password_with_credential(digest, user, hash_password("new long enough password"))
        self.assertFalse(state.consume_credential("recovery", digest))

    def test_agent_framing_and_allowlist(self):
        state=self.make_state(); service=ReadOnlyService(Config(path=str(Path(self.tmp.name)/"none.yml")), state)
        server=AgentServer(service, "/tmp/test.sock", allow_test_paths=True)
        malformed=json.loads(server.handle_line(b"not-json\n")); self.assertFalse(malformed["ok"])
        oversized=json.loads(server.handle_line(b"x"*65537)); self.assertFalse(oversized["ok"])
        denied=json.loads(server.handle_line(b"{\"operation\":\"update\",\"payload\":{}}\n")); self.assertFalse(denied["ok"]); self.assertEqual(denied["type"], "PermissionError")
        bad_payload=json.loads(server.handle_line(b"{\"operation\":\"health\",\"payload\":[]}\n")); self.assertFalse(bad_payload["ok"])

    def test_authorisation_rejection_is_not_reported_as_registry_failure(self):
        from unittest.mock import patch
        state=self.make_state(); service=ReadOnlyService(Config(path=str(Path(self.tmp.name)/"none.yml")), state)
        server=AgentServer(service, "/tmp/test.sock", allow_test_paths=True, allowed_mutation_uid=1234)
        raw=b"{\"operation\":\"update_review\",\"payload\":{}}\n"
        for kwargs, expected in (({"peer_uid": 9999}, "restricted to the configured web service identity"),
                                 ({}, "restricted to the configured web service identity")):
            answer=json.loads(server.handle_line(raw, **kwargs))
            self.assertEqual((answer["ok"], answer["type"]), (False, "PermissionError"))
            self.assertIn(expected, answer["error"]); self.assertNotIn("registry", answer["error"])
        denied=json.loads(server.handle_line(b"{\"operation\":\"update\",\"payload\":{}}\n"))
        self.assertEqual(denied["type"], "PermissionError"); self.assertNotIn("registry", denied["error"])
        # An OS-level permission error is not an authorisation decision: it keeps the generic sanitised category.
        with patch.object(service, "handle", side_effect=PermissionError("/secret/path: permission denied")):
            os_error=json.loads(server.handle_line(b"{\"operation\":\"health\",\"payload\":{}}\n"))
        self.assertNotIn("/secret/path", os_error["error"])
        # Genuine registry failures keep their existing conditions.
        for failure, message in ((RuntimeError("upstream exploded"), "registry query failed"),
                                 (RuntimeError("request timed out"), "registry request timed out"),
                                 (RuntimeError("429 too many requests"), "registry rate limit reached")):
            with patch.object(service, "handle", side_effect=failure):
                answer=json.loads(server.handle_line(b"{\"operation\":\"scan_start\",\"payload\":{}}\n"))
            self.assertEqual(answer["error"], message)

    def test_duplicate_and_stale_scan_claims_are_recovered(self):
        state = self.make_state()
        first = state.claim_scan("first")
        self.assertFalse(first["existing"])
        duplicate = state.claim_scan("second")
        self.assertTrue(duplicate["existing"]); self.assertEqual(duplicate["run_id"], "first")
        with state.connect() as c:
            c.execute("UPDATE scan_runs SET heartbeat_at='2000-01-01T00:00:00+00:00' WHERE id='first'")
        replacement = state.claim_scan("second", stale_after_seconds=1)
        self.assertFalse(replacement["existing"]); self.assertEqual(state.scan_run("first")["status"], "failed")

    def test_expired_bootstrap_code_is_not_consumed_or_accepted(self):
        state = self.make_state(); digest = token_hash("expired")
        state.create_credential("bootstrap", digest, "2000-01-01T00:00:00+00:00")
        with self.assertRaisesRegex(ValueError, "invalid or expired"):
            state.create_user_with_credential(digest, "admin", hash_password("long enough password"))
        self.assertIsNone(state.web_user())

    def test_tabler_is_local_and_loaded_before_custom_css(self):
        root=Path(__file__).parents[1]; base=(root/"src/docker_update_manager/templates/base.html").read_text()
        self.assertTrue((root/"src/docker_update_manager/static/tabler.min.css").stat().st_size > 100000)
        self.assertLess(base.index("tabler.min.css"), base.index("app.css")); self.assertIn('class="app-navbar"', base)


if __name__ == "__main__": unittest.main()
