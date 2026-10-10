"""Closure-pass coverage: read-only UI states plus installer/systemd consistency."""
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
from docker_update_manager.webapp import create_app
from docker_update_manager.webstate import WebState

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "src/docker_update_manager/templates"


def item(key, status, stack="media", version="1.0", health="healthy", state="running"):
    return {"service": {"key": key, "name": key.split("/")[-1], "stack": stack, "image": f"repo/{key}:1.0",
                        "version": version, "state": state, "health": health},
            "status": status}


class FakeAgent:
    def __init__(self, snapshot, health=None, scan_status="complete"):
        self.snapshot = snapshot
        self.health = health if health is not None else {"ok": True, "docker": {"ok": True}}
        self.scan_attempt_status = scan_status

    def call(self, operation, payload=None):
        if operation == "health": return self.health
        if operation == "snapshot": return self.snapshot
        if operation == "service":
            for entry in self.snapshot.get("payload", {}).get("services", []):
                if entry["service"]["key"] == (payload or {}).get("service_key"):
                    return entry
            raise RuntimeError("service not found")
        if operation == "audit_recent": return {"events": []}
        if operation == "scan_start": return {"run_id": "run-1", "status": "running"}
        if operation == "scan_status": return {"id": "run-1", "status": self.scan_attempt_status, "error": "1 service result could not be verified" if self.scan_attempt_status == "partial" else None, "events": []}
        raise AssertionError(operation)


class UiClosureTests(unittest.TestCase):
    def make_client(self, agent):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        config = WebConfig(path=str(root / "web.yml"))
        state = WebState(root / "web-state")
        code = new_token()
        state.create_credential("bootstrap", token_hash(code), utc_after(minutes=15))
        client = TestClient(create_app(config, state, agent))
        page = client.get("/setup")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        client.post("/setup", data={"csrf": csrf, "bootstrap": code, "username": "admin",
                                    "password": "correct horse battery staple",
                                    "password_confirm": "correct horse battery staple"})
        page = client.get("/login")
        csrf = re.search(r'name="csrf" value="([^"]+)' , page.text).group(1)
        client.post("/login", data={"csrf": csrf, "username": "admin", "password": "correct horse battery staple"})
        return client

    def snapshot(self, services, status="complete", finished="2026-09-22T10:00:00+00:00"):
        return {"status": status, "finished_at": finished, "payload": {"count": len(services), "services": services}}

    def test_overview_never_scanned_and_populated_states(self):
        client = self.make_client(FakeAgent({"status": "never", "payload": {"count": 0, "services": []}}))
        body = client.get("/").text
        self.assertIn("Open a service to check its update information", body)
        self.assertIn("Scan now", body)

        populated = self.make_client(FakeAgent(self.snapshot([item("media/sonarr", "UPDATE"), item("net/gluetun", "DIGEST CHANGED", stack=None)])))
        body = populated.get("/").text
        self.assertIn("Inventory scanned", body)
        self.assertIn("sonarr", body)
        self.assertNotIn("Open a service to check its update information", body)

    def test_overview_handles_agent_unavailable_and_partial(self):
        unavailable = self.make_client(FakeAgent({"_error": "read-only UPT agent is unavailable"},
                                                 health={"_error": "read-only UPT agent is unavailable"}))
        self.assertIn("Agent unavailable", unavailable.get("/").text)
        partial = self.make_client(FakeAgent(self.snapshot([item("media/sonarr", "UPDATE")]), scan_status="partial"))
        body = partial.get("/").text
        self.assertIn("partial", body.lower())
        self.assertIn("incomplete service results", body)
        self.assertIn("sonarr", body)
        self.assertIn("previous complete snapshot", body)

    def test_services_filters_and_stable_sorting(self):
        services = [item("monitoring/grafana", "CURRENT", stack="monitoring"),
                    item("media/sonarr", "UPDATE"),
                    item("media/radarr", "CURRENT")]
        client = self.make_client(FakeAgent(self.snapshot(services)))
        filtered = client.get("/services", params={"stack": "media"}).text
        self.assertIn("sonarr", filtered)
        self.assertNotIn("grafana", filtered)
        by_status = client.get("/services", params={"status": "UPDATE"}).text
        self.assertIn("sonarr", by_status)
        self.assertNotIn("radarr", by_status)
        searched = client.get("/services", params={"q": "radarr"}).text
        self.assertIn("radarr", searched)
        self.assertNotIn("grafana", searched)
        ordered = client.get("/services").text
        self.assertLess(ordered.index("radarr"), ordered.index("sonarr"))

    def test_technical_values_are_escaped_and_unknown_is_honest(self):
        hostile = item("media/<script>alert(1)</script>", "CURRENT", version=None)
        client = self.make_client(FakeAgent(self.snapshot([hostile])))
        body = client.get("/services").text
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)
        detail = client.get("/services/media/%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertNotIn("<script>alert(1)</script>", detail.text)

    def test_internal_service_error_is_not_misclassified_as_not_found(self):
        class InternalFailureAgent(FakeAgent):
            def call(self, operation, payload=None):
                if operation == "snapshot":
                    raise RuntimeError("database record not found while reading cached service")
                return super().call(operation, payload)

        client = self.make_client(InternalFailureAgent(self.snapshot([item("media/sonarr", "CURRENT")])))
        response = client.get("/services/media/sonarr")
        self.assertEqual(response.status_code, 503)
        self.assertIn("Service details unavailable", response.text)

    def test_no_unapproved_mutation_affordances_in_templates(self):
        forbidden_actions = ('action="/update', 'action="/rollback', 'action="/pin', 'action="/restart',
                             'action="/remove', 'action="/cleanup', 'action="/convert', 'hx-post="/update')
        for template in TEMPLATES.glob("*.html"):
            text = template.read_text()
            for forbidden in forbidden_actions:
                self.assertNotIn(forbidden, text, f"{template.name} exposes {forbidden}")
        controls = " ".join(t.read_text() for t in TEMPLATES.glob("*.html"))
        interactive = re.findall(r"<(?:button|a)\b[^>]*>.*?</(?:button|a)>", controls, re.IGNORECASE | re.DOTALL)
        for element in interactive:
            self.assertNotRegex(element, re.compile(r"\b(?:start|stop|restart)\b", re.IGNORECASE))
        for word in (">Remove<", ">Pin<"):
            self.assertNotIn(word, controls)
        service = (TEMPLATES / "service.html").read_text()
        self.assertEqual(service.count('action="/operations/rollback"'), 1,
                         "Phase 3 adds only the explicitly reviewed single-service rollback form")
        rollback_form = service.split('action="/operations/rollback"', 1)[1].split("</form>", 1)[0]
        self.assertIn('name="confirmation_id"', rollback_form)
        for authority in ('name="history_id"', 'name="image"', 'name="backup"', 'name="compose_file"'):
            self.assertNotIn(authority, rollback_form)

    def test_theme_control_and_semantics_and_local_assets(self):
        settings = (TEMPLATES / "settings.html").read_text()
        for option in ("System", "Light", "Dark"):
            self.assertIn(f">{option}</option>", settings)
        self.assertIn("data-theme-select", settings)
        self.assertIn("Change password", settings)
        base = (TEMPLATES / "base.html").read_text()
        self.assertIn('aria-label="Primary"', base)
        self.assertIn('class="skip-link"', base)
        self.assertIn('href="#main"', base)
        self.assertLess(base.index("tabler.min.css"), base.index("app.css"))
        overview = (TEMPLATES / "overview.html").read_text()
        self.assertIn('role="status"', overview)
        self.assertIn('class="app-navbar"', base)
        self.assertIn("data-table", (TEMPLATES / "services.html").read_text())
        for template in TEMPLATES.glob("*.html"):
            text = template.read_text()
            self.assertNotIn("https://cdn", text)
            self.assertNotIn("//unpkg.com", text)


class DeploymentArtefactTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text()

    def test_web_unit_is_unprivileged_without_docker_access(self):
        unit = self.read("systemd/upt-web.service.example")
        self.assertIn("User=docker-update-manager-web", unit)
        self.assertIn("Group=docker-update-manager-web", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("ReadWritePaths=/var/lib/docker-update-manager-web", unit)
        self.assertNotIn("docker.sock", unit)
        self.assertNotIn("SupplementaryGroups=docker", unit)
        self.assertNotIn("Group=docker" + chr(10), unit)  # exact line, not the web group name

    def test_agent_unit_is_bounded_and_owns_the_socket_directory(self):
        unit = self.read("systemd/upt-agent.service.example")
        self.assertIn("User=root", unit)
        self.assertIn("RuntimeDirectory=docker-update-manager", unit)
        self.assertIn("RuntimeDirectoryMode=0750", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("UMask=007", unit)
        # The agent needs read access to Docker/state, so it uses `full` rather
        # than `strict`; assert the actual posture so future hardening is a
        # deliberate change rather than an accidental test break.
        self.assertIn("ProtectSystem=full", unit)
        self.assertIn("ProtectHome=read-only", unit)
        self.assertNotIn("ReadWritePaths=", unit,
                         "project write roots are operator opt-in, not a default agent capability")

    def test_compose_write_dropin_example_is_explicit_and_never_broadens_home(self):
        example=self.read("systemd/upt-agent.compose-writes.conf.example")
        self.assertIn("[Service]",example)
        self.assertIn("ReadWritePaths=/root/compose-example",example)
        self.assertNotIn("ReadWritePaths=/root\n",example)
        self.assertNotIn("ReadWritePaths=/home",example)
        self.assertNotIn("ReadWritePaths=/etc",example)
        self.assertNotIn("ReadWritePaths=/\n",example)
        deployment_notes=" ".join(self.read("docs/deployment.md").split())
        for text in ("ProtectHome=read-only","ProtectSystem=full","/root/compose-example",
                     "systemctl daemon-reload","systemctl restart upt-agent",
                     "Never use `ReadWritePaths=/root`", "CLI commands run as the host operator"):
            self.assertIn(text,deployment_notes)

    def test_socket_mode_is_group_limited_and_documented(self):
        from docker_update_manager.webservice import AgentServer
        self.assertEqual(AgentServer(service=None, socket_path="x").mode, 0o660)
        deployment_notes = self.read("docs/deployment.md")
        self.assertIn("docker-update-manager-web", deployment_notes)
        self.assertIn("chmod 0640 /etc/docker-update-manager/web.yml", deployment_notes)

    def test_installer_installs_without_enabling_or_starting_services(self):
        installer = self.read("install.sh")
        self.assertNotIn("systemctl", installer)
        self.assertNotIn("service upt", installer)
        self.assertIn('if [ ! -e "$CONFIG_DIR/config.yml" ]', installer)
        self.assertIn('if [ ! -e "$WEB_CONFIG" ]', installer)
        self.assertIn("WEB_STATE_DIR must remain under /var/lib/docker-update-manager-web", installer)
        # Ownership changes are documented operator steps, so a custom prefix or
        # test path can never cause the installer to chown production paths.
        self.assertNotIn("chown", installer)
        for entry in ("upt", "upt-web", "upt-agent"):
            self.assertIn(f'ln -sfn "$PREFIX/lib/docker-update-manager/venv/bin/{entry}" "$PREFIX/bin/{entry}"', installer)

    def test_uninstaller_preserves_configuration_and_state(self):
        uninstaller = self.read("uninstall.sh")
        self.assertNotIn("rm -rf /etc", uninstaller)
        self.assertNotIn("rm -rf /var/lib", uninstaller)
        self.assertIn("deliberately preserved", uninstaller)
        self.assertIn("$PREFIX/lib/docker-update-manager", uninstaller)

    def test_config_examples_do_not_duplicate_web_settings(self):
        self.assertNotIn(chr(10) + "web:" + chr(10), self.read("config/config.example.yml"))
        self.assertIn("state_dir: /var/lib/docker-update-manager-web", self.read("config/web.example.yml"))


if __name__ == "__main__":
    unittest.main()
