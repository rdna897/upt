"""UPT unified product-version contract (docs/versioning.md).

Covers the single version authority, package metadata derivation, CLI/web/agent
reporting and the web/agent version-agreement mutation gate.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import contextlib
import importlib.metadata
import io
import json
import os
import re
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("UPT_TESTING", "1")

from fastapi.testclient import TestClient

import docker_update_manager
from docker_update_manager import _version, cli, webcli
from docker_update_manager.agent import AgentClient, AgentUnavailable
from docker_update_manager.auth import new_token
from docker_update_manager.component_version import (MATCH, MISMATCH, TRANSPORT_VERSION_FIELD, UNAVAILABLE, UNKNOWN,
                                                      VERSION_MISMATCH, VERSION_MISMATCH_MESSAGE, ComponentVersionMismatch,
                                                      version_agreement)
from docker_update_manager.config import WebConfig
from docker_update_manager.webapp import create_app
from docker_update_manager.webservice import (MUTATION_OPERATIONS, READ_ONLY_OPERATIONS, VERSION_GATED_OPERATIONS,
                                              AgentServer, ReadOnlyService)
from docker_update_manager.webstate import WebState

from fixtures.legacy_agent_054775d import LEGACY_EXACT_PAYLOADS, LegacyAgentServer, LegacyService

ROOT = Path(__file__).resolve().parents[1]
VERSION = docker_update_manager.__version__
OLD_VERSION = "0.3.1"


class VersionAuthorityTests(unittest.TestCase):
    def test_single_authoritative_source(self):
        self.assertEqual(VERSION, _version.__version__)
        self.assertRegex(VERSION, r"^[0-9]+\.[0-9]+\.[0-9]+$")
        literal = re.compile(r"""^\s*(__version__|version)\s*=\s*["'][0-9]""", re.M)
        sources = [p for p in (ROOT / "src").rglob("*.py") if literal.search(p.read_text())]
        self.assertEqual([p.relative_to(ROOT).as_posix() for p in sources], ["src/docker_update_manager/_version.py"])
        pyproject = (ROOT / "pyproject.toml").read_text()
        self.assertIsNone(literal.search(pyproject), "pyproject.toml must not carry a second version literal")
        self.assertRegex(pyproject, r'dynamic = \["version"\]')
        self.assertIn('version = {attr = "docker_update_manager._version.__version__"}', pyproject)

    def test_setuptools_resolves_package_version_from_authority(self):
        try:
            from setuptools.config.pyprojecttoml import read_configuration
        except ImportError:
            self.skipTest("setuptools is not installed in this environment")
        config = read_configuration(str(ROOT / "pyproject.toml"), expand=True, ignore_option_errors=False)
        self.assertEqual(config["project"]["version"], VERSION)

    def test_installed_metadata_matches_runtime_version(self):
        try:
            dist = importlib.metadata.distribution("docker-update-manager")
        except importlib.metadata.PackageNotFoundError:
            self.skipTest("package is not installed; CI installs it before running tests")
        if dist.read_text("RECORD") is None:
            # A leftover in-tree *.egg-info build artefact, not an installation.
            self.skipTest("metadata is not from a pip-installed distribution")
        direct_url = json.loads(dist.read_text("direct_url.json") or "{}")
        if direct_url.get("dir_info", {}).get("editable"):
            # Editable metadata is frozen at install time and cannot follow
            # source edits; CI tests a regular install.
            self.skipTest("editable install metadata does not track the source version")
        provided = Path(dist.locate_file("docker_update_manager/_version.py")).resolve()
        if provided != Path(_version.__file__).resolve():
            # e.g. PYTHONPATH=src over a separately installed copy; CI tests
            # the installed package and also checks `upt --version` directly.
            self.skipTest("runtime module is not provided by the installed distribution")
        self.assertEqual(dist.version, VERSION)

    def test_cli_version_reports_authority(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as done:
            cli.main(["--version"])
        self.assertEqual(done.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), f"upt {VERSION}")


class AgentHealthVersionTests(unittest.TestCase):
    def test_health_reports_exact_bounded_fields(self):
        service = SimpleNamespace(_health_lock=threading.Lock(), _docker_health_cache={"ok": True})
        health = ReadOnlyService.health(service)
        self.assertEqual(health, {"ok": True, "service": "upt-agent", "version": VERSION, "docker": {"ok": True}})


class VersionAgreementTests(unittest.TestCase):
    def test_states(self):
        self.assertEqual(version_agreement({"ok": True, "version": VERSION})["status"], MATCH)
        self.assertEqual(version_agreement({"ok": True, "version": OLD_VERSION}),
                         {"web": VERSION, "agent": OLD_VERSION, "status": MISMATCH})
        # Old agents omit the field: unknown, never assumed compatible.
        self.assertEqual(version_agreement({"ok": True, "service": "upt-agent"})["status"], UNKNOWN)
        for malformed in (None, 4, {"v": 1}, "", "latest", VERSION + "\n", "0.4.0; id", "9" * 80):
            with self.subTest(value=malformed):
                result = version_agreement({"ok": True, "version": malformed})
                self.assertEqual((result["status"], result["agent"]), (UNKNOWN, None))
        for unavailable in (None, [], {"_error": "x"}, {"ok": False, "version": VERSION}):
            self.assertEqual(version_agreement(unavailable)["status"], UNAVAILABLE)

    def test_schema_or_protocol_identity_never_implies_agreement(self):
        health = {"ok": True, "version": OLD_VERSION, "schema_version": 99, "protocol": 1}
        self.assertEqual(version_agreement(health)["status"], MISMATCH)

    def test_gate_covers_every_mutation_except_status_and_no_read_only_operation(self):
        self.assertEqual(VERSION_GATED_OPERATIONS, MUTATION_OPERATIONS - {"operation_status"})
        self.assertFalse(VERSION_GATED_OPERATIONS & READ_ONLY_OPERATIONS)
        for op in ("update_start", "rollback_start", "compose_reconcile_start", "compose_bootstrap_start"):
            self.assertIn(op, VERSION_GATED_OPERATIONS)


class ScriptedClient(AgentClient):
    """Real AgentClient gate with the socket exchange replaced by a fake agent."""

    def __init__(self, agent_version=VERSION, health_error=None):
        super().__init__("/tmp/unused.sock")
        self.agent_version, self.health_error, self.sent, self.payloads = agent_version, health_error, [], []

    def _request(self, operation, payload):
        self.sent.append(operation)
        self.payloads.append(payload)
        if operation == "health":
            if self.health_error: raise self.health_error
            health = {"ok": True, "service": "upt-agent", "docker": {"ok": True}}
            if self.agent_version is not None: health["version"] = self.agent_version
            return health
        if operation in {"update_start", "rollback_start", "compose_reconcile_start", "compose_bootstrap_start"}:
            return {"operation_id": "a" * 32}
        if operation == "operation_status":
            return {"id": "a" * 32, "status": "running", "events": []}
        if operation == "snapshot":
            return {"status": "complete", "finished_at": "2026-10-06T10:00:00+00:00", "payload": {"count": 0, "services": []}}
        if operation in {"runtime_snapshot", "verification_snapshot"}:
            return {"status": "current", "containers": [], "services": []}
        if operation == "scan_status":
            return {}
        raise AssertionError(operation)


class AgentClientGateTests(unittest.TestCase):
    def test_matching_versions_forward_mutation(self):
        client = ScriptedClient()
        self.assertEqual(client.call("update_start", {"confirmation_id": "x"}), {"operation_id": "a" * 32})
        self.assertEqual(client.sent, ["health", "update_start"])

    def test_new_web_old_or_unknown_agent_refuses_before_sending_mutation(self):
        for agent_version, status in ((OLD_VERSION, MISMATCH), (None, UNKNOWN), ("garbage", UNKNOWN)):
            for op in sorted(VERSION_GATED_OPERATIONS):
                with self.subTest(agent=agent_version, op=op):
                    client = ScriptedClient(agent_version)
                    with self.assertRaises(ComponentVersionMismatch) as refused:
                        client.call(op, {})
                    self.assertEqual(client.sent, ["health"])
                    self.assertEqual(refused.exception.status, status)
                    self.assertEqual(refused.exception.reason, VERSION_MISMATCH)
                    self.assertNotIsInstance(refused.exception, (PermissionError, RuntimeError, AgentUnavailable))

    def test_unreachable_agent_stays_distinct_from_mismatch(self):
        client = ScriptedClient(health_error=AgentUnavailable("UPT agent is unavailable"))
        with self.assertRaises(AgentUnavailable):
            client.call("update_start", {})
        self.assertEqual(client.sent, ["health"])

    def test_read_only_and_status_operations_skip_the_gate(self):
        client = ScriptedClient(OLD_VERSION)
        client.call("health"); client.call("snapshot"); client.call("operation_status", {"operation_id": "a" * 32})
        self.assertEqual(client.sent, ["health", "snapshot", "operation_status"])

    def test_wire_request_carries_client_version_and_maps_refusal(self):
        sent, answers = [], [{"ok": True, "data": {"ok": True, "version": VERSION}},
                             {"ok": False, "type": "ComponentVersionMismatch", "reason": VERSION_MISMATCH, "error": "x"}]

        class Socket:
            def __init__(self, *_): pass
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def sendall(self, data): sent.append(json.loads(data))
            def makefile(self, *_): return io.BytesIO(json.dumps(answers.pop(0)).encode() + b"\n")

        with patch("docker_update_manager.agent.socket.socket", Socket):
            with self.assertRaises(ComponentVersionMismatch) as refused:
                AgentClient("/tmp/unused.sock").call("rollback_start", {"confirmation_id": "c"})
        self.assertEqual([item["operation"] for item in sent], ["health", "rollback_start"])
        self.assertTrue(all(item["client_version"] == VERSION for item in sent))
        self.assertEqual(str(refused.exception), VERSION_MISMATCH_MESSAGE)


class AgentServerGateTests(unittest.TestCase):
    class Probe:
        def __init__(self): self.calls, self.payloads = [], []
        def handle(self, operation, payload):
            self.calls.append(operation); self.payloads.append(payload)
            if operation == "health": return {"ok": True, "service": "upt-agent", "version": VERSION}
            return {"ok": True}

    def line(self, operation, payload=None, **extra):
        return json.dumps({"operation": operation, "payload": payload or {}, **extra}).encode() + b"\n"

    def asserted(self, **payload):
        return {**payload, TRANSPORT_VERSION_FIELD: VERSION}

    def test_old_or_unknown_web_client_cannot_mutate(self):
        probe = self.Probe()
        server = AgentServer(probe, "/tmp/unused.sock", allowed_mutation_uid=1234)
        for extra in ({}, {"client_version": OLD_VERSION}, {"client_version": None}, {"client_version": [VERSION]}):
            with self.subTest(extra=extra):
                answer = json.loads(server.handle_line(self.line("update_start", **extra), peer_uid=1234))
                self.assertEqual(answer, {"ok": False, "error": VERSION_MISMATCH_MESSAGE,
                                          "type": "ComponentVersionMismatch", "reason": VERSION_MISMATCH})
        self.assertEqual(probe.calls, [])
        ok = json.loads(server.handle_line(self.line("update_start", self.asserted(confirmation_id="c"), client_version=VERSION), peer_uid=1234))
        self.assertTrue(ok["ok"])
        self.assertEqual(probe.calls, ["update_start"])
        # The transport strips its field; handlers see only their own schema.
        self.assertEqual(probe.payloads, [{"confirmation_id": "c"}])

    def test_payload_version_assertion_is_required_and_exact(self):
        probe = self.Probe()
        server = AgentServer(probe, "/tmp/unused.sock", allowed_mutation_uid=1234)
        for claim in ("missing", OLD_VERSION, None, 4, [VERSION], VERSION + "\n", "0.4.0; id", "9" * 80):
            payload = {"confirmation_id": "c"} if claim == "missing" else {"confirmation_id": "c", TRANSPORT_VERSION_FIELD: claim}
            for op in sorted(VERSION_GATED_OPERATIONS):
                with self.subTest(claim=claim, op=op):
                    answer = json.loads(server.handle_line(self.line(op, payload, client_version=VERSION), peer_uid=1234))
                    self.assertEqual((answer["type"], answer["reason"]), ("ComponentVersionMismatch", VERSION_MISMATCH))
        self.assertEqual(probe.calls, [])

    def test_top_level_client_version_still_required_with_payload_assertion(self):
        probe = self.Probe()
        server = AgentServer(probe, "/tmp/unused.sock", allowed_mutation_uid=1234)
        for extra in ({}, {"client_version": OLD_VERSION}):
            answer = json.loads(server.handle_line(self.line("rollback_start", self.asserted(confirmation_id="c"), **extra), peer_uid=1234))
            self.assertEqual(answer["type"], "ComponentVersionMismatch")
        self.assertEqual(probe.calls, [])

    def test_authorization_precedes_version_even_with_valid_assertion(self):
        server = AgentServer(self.Probe(), "/tmp/unused.sock", allowed_mutation_uid=1234)
        answer = json.loads(server.handle_line(self.line("update_start", self.asserted(confirmation_id="c"), client_version=VERSION), peer_uid=9))
        self.assertEqual(answer["type"], "PermissionError")

    def test_authorization_failure_is_reported_before_version(self):
        server = AgentServer(self.Probe(), "/tmp/unused.sock", allowed_mutation_uid=1234)
        answer = json.loads(server.handle_line(self.line("update_start"), peer_uid=9))
        self.assertEqual(answer["type"], "PermissionError")

    def test_read_only_diagnostics_need_no_client_version(self):
        probe = self.Probe()
        server = AgentServer(probe, "/tmp/unused.sock", allowed_mutation_uid=1234)
        self.assertTrue(json.loads(server.handle_line(self.line("health")))["ok"])
        self.assertTrue(json.loads(server.handle_line(self.line("operation_status"), peer_uid=1234))["ok"])
        self.assertEqual(probe.calls, ["health", "operation_status"])


class TransportAssertionClientTests(unittest.TestCase):
    def test_gated_operations_carry_assertion_without_mutating_caller_payload(self):
        for op in sorted(VERSION_GATED_OPERATIONS):
            with self.subTest(op=op):
                client, original = ScriptedClient(), {"confirmation_id": "c"}
                try:
                    client.call(op, original)
                except AssertionError:
                    pass  # ScriptedClient only fabricates start responses
                self.assertEqual(original, {"confirmation_id": "c"})
                self.assertEqual(client.payloads[0], {})  # health probe stays plain
                self.assertEqual(client.payloads[1], {"confirmation_id": "c", TRANSPORT_VERSION_FIELD: VERSION})

    def test_read_only_operations_carry_no_transport_field(self):
        client = ScriptedClient()
        client.call("snapshot"); client.call("operation_status", {"operation_id": "a" * 32}); client.call("health")
        self.assertTrue(all(TRANSPORT_VERSION_FIELD not in payload for payload in client.payloads))

    def test_caller_cannot_supply_or_override_reserved_field(self):
        for op in ("update_start", "rollback_review", "snapshot", "operation_status"):
            for value in (VERSION, OLD_VERSION):
                with self.subTest(op=op, value=value):
                    client = ScriptedClient()
                    with self.assertRaises(PermissionError):
                        client.call(op, {"confirmation_id": "c", TRANSPORT_VERSION_FIELD: value})
                    self.assertEqual(client.sent, [], "refused locally before any agent exchange")

    def test_browser_form_field_cannot_reach_reserved_field(self):
        agent = ScriptedClient()
        client = WebVersionTests.client(self, agent)
        response = client.post("/operations/update", data={"csrf": self.csrf, "confirmation_id": "B" * 43, "confirm_update": "yes",
                                                           TRANSPORT_VERSION_FIELD: OLD_VERSION}, follow_redirects=False)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(agent.sent, [])


class LegacyAgentRaceRegressionTests(unittest.TestCase):
    """Legacy compatibility regression: health passes on a new agent, then the
    mutation connection reaches a frozen pre-0.4 agent (tests/fixtures)."""

    PAYLOADS = {op: {name: (True if name == "acknowledge_no_rollback" else "x") for name in names}
                for op, names in LEGACY_EXACT_PAYLOADS.items()}

    def wire(self, servers):
        sent = []

        class Socket:
            def __init__(self, *_): self.data = b""
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, *_): pass
            def connect(self, *_): pass
            def sendall(self, data): self.data += data; sent.append(json.loads(data))
            def makefile(self, *_): return io.BytesIO(servers.pop(0).handle_line(self.data, peer_uid=1234))

        return Socket, sent

    def test_fixture_matches_current_handler_schemas(self):
        # Application schemas are unchanged since 54775df, so the frozen
        # allowlists are exactly what current handlers enforce first.
        class Stop(Exception): pass

        class Recording(ReadOnlyService):
            def __init__(self): self.seen = None
            def _exact_payload(self, payload, names): self.seen = set(names); raise Stop()

        self.assertEqual(set(LEGACY_EXACT_PAYLOADS), VERSION_GATED_OPERATIONS)
        for op, names in LEGACY_EXACT_PAYLOADS.items():
            service = Recording()
            with self.subTest(op=op), self.assertRaises(Stop):
                service.handle(op, {})
            self.assertEqual(service.seen, names, op)

    def test_mutation_reaching_legacy_agent_after_new_health_probe_fails_closed(self):
        for op in sorted(VERSION_GATED_OPERATIONS):
            with self.subTest(op=op):
                legacy = LegacyService()
                new_agent = AgentServer(AgentServerGateTests.Probe(), "/tmp/unused.sock", allowed_mutation_uid=1234)
                Socket, sent = self.wire([new_agent, LegacyAgentServer(legacy, allowed_mutation_uid=1234)])
                with patch("docker_update_manager.agent.socket.socket", Socket), self.assertRaises(ValueError):
                    AgentClient("/tmp/unused.sock").call(op, dict(self.PAYLOADS[op]))
                self.assertEqual([item["operation"] for item in sent], ["health", op])
                self.assertEqual(legacy.side_effects, [], "legacy agent must not perform the mutation")

    def test_fixture_is_not_vacuous_without_the_assertion(self):
        # The pre-remediation request shape (top-level client_version only) is
        # accepted by the legacy agent: the payload assertion is what closes it.
        for op in sorted(VERSION_GATED_OPERATIONS):
            legacy = LegacyService()
            line = json.dumps({"operation": op, "payload": self.PAYLOADS[op], "client_version": VERSION}).encode() + b"\n"
            answer = json.loads(LegacyAgentServer(legacy, allowed_mutation_uid=1234).handle_line(line, peer_uid=1234))
            self.assertTrue(answer["ok"], op)
            self.assertEqual([name for name, _ in legacy.side_effects], [op])

    def test_matching_new_web_and_new_agent_still_mutate(self):
        probe = AgentServerGateTests.Probe()
        new_agent = AgentServer(probe, "/tmp/unused.sock", allowed_mutation_uid=1234)
        Socket, sent = self.wire([new_agent, new_agent])
        with patch("docker_update_manager.agent.socket.socket", Socket):
            self.assertEqual(AgentClient("/tmp/unused.sock").call("update_start", dict(self.PAYLOADS["update_start"])), {"ok": True})
        self.assertEqual(sent[1]["payload"][TRANSPORT_VERSION_FIELD], VERSION)
        self.assertEqual(probe.payloads[-1], self.PAYLOADS["update_start"])


class WebVersionTests(unittest.TestCase):
    def client(self, agent):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        state = WebState(root / "web-state")
        user_id = state.create_user("admin", "not-used")
        self.csrf = new_token()
        now = datetime.now(timezone.utc)
        sid = state.create_session(user_id, self.csrf, (now + timedelta(hours=2)).isoformat(), (now + timedelta(days=30)).isoformat())
        client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), state, agent))
        client.cookies.set("upt_session", sid)
        return client

    def test_settings_reports_web_and_agent_versions(self):
        page = self.client(ScriptedClient()).get("/settings").text
        self.assertIn(f"<dd>{VERSION}</dd>", page)
        self.assertIn('data-version-status="match"', page)
        self.assertIn("Versions match", page)
        stale = self.client(ScriptedClient(OLD_VERSION)).get("/settings").text
        self.assertIn(f"<dd>{OLD_VERSION}</dd>", stale)
        self.assertIn('data-version-status="mismatch"', stale)
        self.assertIn("Upgrade incomplete", stale)
        legacy = self.client(ScriptedClient(None)).get("/settings").text
        self.assertIn('data-version-status="unknown"', legacy)

    def test_overview_surfaces_mismatch_and_stays_readable(self):
        matched = self.client(ScriptedClient()).get("/")
        self.assertEqual(matched.status_code, 200)
        self.assertNotIn("versions do not match", matched.text)
        stale = self.client(ScriptedClient(OLD_VERSION)).get("/")
        self.assertEqual(stale.status_code, 200)
        self.assertIn("UPT web and agent versions do not match.", stale.text)

    def test_mutation_routes_fail_closed_with_bounded_reason(self):
        routes = (("/operations/update", {"confirm_update": "yes"}),
                  ("/operations/rollback", {"confirm_rollback": "yes"}),
                  ("/operations/compose-reconcile", {"confirm_apply": "yes"}),
                  ("/operations/compose-bootstrap", {"acknowledge_no_rollback": "yes"}))
        for agent_version in (OLD_VERSION, None):
            for path, ack in routes:
                with self.subTest(path=path, agent=agent_version):
                    agent = ScriptedClient(agent_version)
                    response = self.client(agent).post(path, data={"csrf": self.csrf, "confirmation_id": "B" * 43, **ack},
                                                       follow_redirects=False)
                    self.assertEqual(response.status_code, 409)
                    self.assertEqual(response.json(), {"error": VERSION_MISMATCH_MESSAGE, "reason": VERSION_MISMATCH})
                    self.assertEqual(agent.sent, ["health"], "no mutation may reach the agent")
        agent = ScriptedClient()
        ok = self.client(agent).post("/operations/update", data={"csrf": self.csrf, "confirmation_id": "B" * 43, "confirm_update": "yes"},
                                     follow_redirects=False)
        self.assertEqual(ok.status_code, 303)
        self.assertEqual(agent.sent, ["health", "update_start"])

    def test_compose_review_refused_without_internal_detail(self):
        agent = ScriptedClient(OLD_VERSION)
        response = self.client(agent).post("/compose/apply/review", data={"csrf": self.csrf, "service_key": "container/" + "a" * 64, "action": "apply"})
        self.assertEqual(response.status_code, 409)
        self.assertIn(VERSION_MISMATCH_MESSAGE, response.text)
        self.assertNotIn("sock", response.text)
        self.assertEqual(agent.sent, ["health"])

    def test_unauthenticated_health_does_not_disclose_version(self):
        response = TestClient(self.client(ScriptedClient()).app).get("/api/health")
        self.assertEqual(response.json(), {"ok": True, "agent": "reachable"})


class WebStatusCommandTests(unittest.TestCase):
    def run_status(self, health):
        class Client:
            def __init__(self, *_): pass
            def call(self, operation): assert operation == "health"; return health
        out, err = io.StringIO(), io.StringIO()
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        with patch.object(webcli, "AgentClient", Client), patch.object(webcli, "WebConfig", lambda: WebConfig(path=str(Path(tmp.name) / "web.yml"))), \
                patch.object(webcli, "web_state", lambda _c: SimpleNamespace(db_path="web.db")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = webcli.web_command(None, SimpleNamespace(action="status", dry_run=False))
        return code, out.getvalue(), err.getvalue()

    def test_reports_agreement(self):
        code, out, _ = self.run_status({"ok": True, "version": VERSION})
        self.assertEqual(code, 0)
        self.assertIn(f"UPT version: {VERSION}\nWeb version (installed): {VERSION}\nAgent version (running): {VERSION}\nVersion status: versions match", out)

    def test_reports_stale_or_unknown_agent(self):
        for health, shown in (({"ok": True, "version": OLD_VERSION}, OLD_VERSION), ({"ok": True}, "unknown")):
            code, out, err = self.run_status(health)
            self.assertEqual(code, 20)
            self.assertIn(f"Agent version (running): {shown}", out)
            self.assertIn(VERSION_MISMATCH_MESSAGE, err)


class DoctorVersionTests(unittest.TestCase):
    SOCKET = "/run/secret-socket-dir/agent.sock"

    def run_doctor(self, health=None, error=None):
        socket_path = self.SOCKET

        class Client:
            def __init__(self, path, timeout=10.0): assert path == socket_path
            def call(self, operation):
                assert operation == "health"
                if error: raise error
                return health

        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        web_config = WebConfig(path=str(Path(tmp.name) / "web.yml"))
        web_config.data.setdefault("web", {})["socket"] = socket_path
        cfg = SimpleNamespace(data={}, path=Path(tmp.name) / "config.yml")
        state = SimpleNamespace(db_path=Path(tmp.name) / "state.db", root=Path(tmp.name) / "state", disk_snapshots=lambda limit: [])
        out, tables = io.StringIO(), []
        real_table = cli.table
        # Agent/version contract is the subject of this test. Model the
        # accessible Docker socket provided by hosted CI, without installing
        # Docker or giving the self-hosted runner host-daemon access.
        real_access = os.access
        def fixture_access(path, mode):
            if path == "/var/run/docker.sock":
                return True
            return real_access(path, mode)

        def capture_table(rows, headers):
            tables.append(list(rows)); return real_table(rows, headers)

        with patch.object(cli, "table", capture_table), patch.object(webcli, "AgentClient", Client), patch.object(webcli, "WebConfig", lambda: web_config), \
                patch.object(cli, "run", lambda *_a, **_k: "fixture"), patch.object(cli, "discover", lambda *_a, **_k: []), \
                patch.object(cli, "fs_metrics", lambda: {"usage_pct": 1, "available": 10 * 1024**3, "inodes_pct": 1}), \
                patch.object(cli, "docker_df", lambda: {"images": 0, "containers": 0, "volumes": 0, "build_cache": 0}), \
                patch.object(cli.os, "access", side_effect=fixture_access), \
                patch.object(cli, "container_logs", lambda: []), \
                patch.object(cli, "deleted_open", lambda: {"available": False, "total": 0}), \
                contextlib.redirect_stdout(out):
            code = cli.doctor(cfg, state)
        self.assertNotIn(socket_path, out.getvalue())
        rows = dict(tables[-1])
        self.assertFalse(any(socket_path in value for value in rows.values()))
        return code, {name: rows[name] for name in ("UPT version", "Agent version", "Version agreement")}

    def test_matching_versions(self):
        code, rows = self.run_doctor({"ok": True, "version": VERSION})
        self.assertEqual(rows, {"UPT version": f"OK - {VERSION}", "Agent version": f"OK - {VERSION}",
                                "Version agreement": "OK - versions match"})

    def test_mismatch_and_unknown_fail(self):
        for health, agent_row in (({"ok": True, "version": OLD_VERSION}, f"FAIL - {OLD_VERSION} (installed {VERSION})"),
                                  ({"ok": True}, "FAIL - unknown (agent reported no valid version)"),
                                  ({"ok": True, "version": "bad version"}, "FAIL - unknown (agent reported no valid version)")):
            with self.subTest(health=health):
                code, rows = self.run_doctor(health)
                self.assertEqual(rows["Agent version"], agent_row)
                self.assertEqual(rows["Version agreement"], "FAIL - " + VERSION_MISMATCH_MESSAGE)
                self.assertEqual(code, cli.EXIT_PARTIAL)

    def test_unavailable_agent_is_neither_match_nor_mismatch(self):
        code, rows = self.run_doctor(error=AgentUnavailable("UPT agent is unavailable"))
        self.assertEqual(rows["Agent version"], "WARNING - agent unavailable")
        self.assertEqual(rows["Version agreement"], "WARNING - not checked (agent unavailable)")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
