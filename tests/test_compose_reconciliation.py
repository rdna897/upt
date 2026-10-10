"""Phase 1 Compose drift detection, trusted baselines, preflight and blocked semantics.

A deterministic fake 'docker compose config' reads the real fixture files named
by -f/--env-file/--project-directory, so baseline capture, backup adoption and
replacement re-proof exercise real bytes. No Docker command is executed.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import hashlib
import io
import json
import os
import re
import stat
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("UPT_TESTING", "1")

import yaml
from fastapi.testclient import TestClient

from docker_update_manager import __version__
from docker_update_manager import compose_drift
from docker_update_manager import webservice
from docker_update_manager.agent import AgentClient
from docker_update_manager.auth import new_token
from docker_update_manager.compose import backup_files
from docker_update_manager.compose_baseline import BaselineStore, logical_key
from docker_update_manager.compose_drift import ComposePreflightRefused, build_inventory, compute_diff
from docker_update_manager.config import Config, WebConfig
from docker_update_manager.models import Service
from docker_update_manager.operation_presentation import operation_presentation
from docker_update_manager.operations import PreMutationRefusal, do_update
from docker_update_manager.retention import rollback_points
from docker_update_manager.system import CommandError
from docker_update_manager.state import State
from docker_update_manager.webapp import create_app
from docker_update_manager.webservice import AgentServer, ReadOnlyService, _public_service
from docker_update_manager.webstate import WebState

from test_web_browser import BrowserFixtureAgent

SECRET = "super-secret-value-7f3a"


def parse_env(path):
    values = {}
    if not os.path.exists(path):
        return values
    for line in Path(path).read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value
    return values


def service_hash(service_model):
    return hashlib.sha256(json.dumps(service_model, sort_keys=True).encode()).hexdigest()


class FakeCompose:
    """Stand-in for 'docker compose ... config' over the named files only."""

    def __init__(self):
        self.calls = []
        self.hook = None
        self.network_id = "b" * 64
        # Runtime network the selected container is attached to, and its
        # Compose logical-network label.
        self.network_name = "media_default"
        self.network_logical = "default"

    def __call__(self, args, cwd=None, timeout=None, **_kwargs):
        args = list(args)
        self.calls.append(args)
        if args[:3] == ["docker", "image", "inspect"] and args[-2] == "{{.Id}}":
            return "sha256:" + "1" * 64
        if args[:3] == ["docker", "inspect", "--type"]:
            if "{{json .Mounts}}" in args:
                return json.dumps([{"Type": "bind", "Source": "/srv/private/sonarr", "Destination": "/config",
                                    "RW": True, "Propagation": "rprivate"}])
            return json.dumps({self.network_name: {"NetworkID": self.network_id}})
        if args[:3] == ["docker", "network", "inspect"]:
            return json.dumps({"Id": self.network_id, "Name": self.network_name, "Driver": "bridge",
                               "Internal": False, "Attachable": False, "Ingress": False,
                               "Scope": "local", "EnableIPv6": False, "IPAM": {"Driver": "default"},
                               "Options": {}, "Labels": {"com.docker.compose.project": "media",
                                                       "com.docker.compose.network": self.network_logical}})
        assert args[:2] == ["docker", "compose"], args
        files, env_file, project, pinned_name, index = [], None, cwd, None, 2
        while index < len(args) and args[index] in {"-f", "--env-file", "--project-directory", "--project-name"}:
            flag, value = args[index], args[index + 1]
            if flag == "-f":
                files.append(value)
            elif flag == "--env-file":
                env_file = value
            elif flag == "--project-name":
                pinned_name = value
            else:
                project = value
            index += 2
        rest = args[index:]
        assert rest[0] == "config", rest
        model = self.model(files, project, env_file, pinned_name)
        if self.hook:
            self.hook(rest)
        if "--hash" in rest:
            name = rest[-1]
            return f"{name} {service_hash(model['services'][name])}\n"
        return json.dumps(model)

    @staticmethod
    def model(files, project, env_file, pinned_name=None):
        env = parse_env(env_file or os.path.join(project, ".env"))
        env.update(os.environ)  # Compose gives the process environment precedence.
        services, top = {}, {}
        for path in files:
            document = yaml.safe_load(Path(path).read_text()) or {}
            for name, node in (document.get("services") or {}).items():
                services.setdefault(name, {}).update(node or {})
            if "name" in document:
                top["name"] = document["name"]
            for key in ("networks", "volumes"):
                if key in document:
                    top.setdefault(key, {}).update(document[key] or {})

        def interpolate(value):
            if isinstance(value, str):
                return re.sub(r"\$\{(\w+)\}", lambda match: env.get(match.group(1), ""), value)
            if isinstance(value, dict):
                return {key: interpolate(item) for key, item in value.items()}
            if isinstance(value, list):
                return [interpolate(item) for item in value]
            return value
        services = interpolate(services)
        for node in services.values():
            environment = {}
            refs = node.pop("env_file", None) or []
            for ref in [refs] if isinstance(refs, str) else refs:
                environment.update(parse_env(os.path.join(project, ref)))
            environment.update(node.get("environment") or {})
            if environment:
                node["environment"] = environment
        name = pinned_name or env.get("COMPOSE_PROJECT_NAME") or interpolate(top.get("name")) or Path(project).name
        top.pop("name", None)
        return {"name": name, "services": services, **interpolate(top)}


BASE_COMPOSE = f"""name: media
services:
  sonarr:
    image: lscr.io/linuxserver/sonarr:latest
    restart: unless-stopped
    command: ["--api-key", "{SECRET}"]
    environment:
      API_KEY: ${{SONARR_API_KEY}}
      TZ: Europe/London
    labels:
      traefik.secret: "{SECRET}"
    ports:
      - {{target: 8989, published: "8989", protocol: tcp}}
    volumes:
      - {{type: bind, source: /srv/private/sonarr, target: /config}}
  redis:
    image: redis:7
"""


def with_service_lines(extra):
    return BASE_COMPOSE.replace("    restart: unless-stopped\n", "    restart: unless-stopped\n" + extra, 1)


# The normalised shape `docker compose config` emits for a plain declared
# bridge network (observed for a production `driver: bridge` declaration).
NAMED_NETWORK = "networks:\n  monitoring:\n    name: media_monitoring\n    driver: bridge\n    ipam: {}\n"


def with_named_network(attachment="      monitoring:\n", project_network=NAMED_NETWORK, source=None):
    source = source or BASE_COMPOSE
    anchor = "    image: lscr.io/linuxserver/sonarr:latest\n"
    assert anchor in source
    return source.replace(anchor, anchor + "    networks:\n" + attachment, 1) + project_network


def use_named_runtime_network(fake):
    fake.network_name, fake.network_logical = "media_monitoring", "monitoring"


class ComposeFixture(unittest.TestCase):
    def setUp(self):
        # No namespace relation in this legacy fixture; live gates are covered
        # by test_compose_namespace's bounded Docker/Compose fixture.
        namespace = patch("docker_update_manager.compose_namespace.mutation_refusal", return_value=None)
        namespace.start()
        self.addCleanup(namespace.stop)
        namespace_status = patch("docker_update_manager.webservice.mutation_refusal", return_value=None)
        namespace_status.start()
        self.addCleanup(namespace_status.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.compose = self.project / "compose.yml"
        self.compose.write_text(BASE_COMPOSE)
        (self.project / ".env").write_text(f"SONARR_API_KEY={SECRET}\n")
        self.state = State(self.root / "state")
        self.config = Config(path=str(self.root / "config.yml"))
        self.agent = ReadOnlyService(self.config, self.state)
        self.fake = FakeCompose()
        # Same-project refresh is a background follow-up; tests opt in explicitly.
        self.project_refresh_patch = patch.object(self.agent, "_queue_project_refresh", return_value="queued")
        self.project_refresh = self.project_refresh_patch.start()
        self.addCleanup(self.project_refresh_patch.stop)
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        for target, value in (("run", self.fake), ("discover", lambda *_args, **_kwargs: list(self.runtime))):
            patcher = patch(f"docker_update_manager.webservice.{target}", side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        image = patch("docker_update_manager.compose_reconcile.run", side_effect=self.fake)
        image.start()
        self.addCleanup(image.stop)
        # These legacy services have no proved restart identity. Bootstrap
        # eligibility stays unknown when runtime inspection is unavailable.
        def restart_unavailable(args, **_kwargs):
            self.assertEqual(args[:-1], ["docker", "inspect", "--type", "container",
                                        "--format", "{{json .RestartCount}}"])
            raise CommandError(args, "fixture restart inspection unavailable")
        restart = patch("docker_update_manager.compose_bootstrap.run", side_effect=restart_unavailable)
        restart.start()
        self.addCleanup(restart.stop)

    def current_hash(self, service_name="sonarr"):
        model = FakeCompose.model([str(self.compose)], str(self.project), None)
        return service_hash(model["services"][service_name])

    def make_service(self, runtime_hash, container_id="a" * 64, **changes):
        values = dict(name="sonarr", container_id=container_id, image="lscr.io/linuxserver/sonarr:latest",
                      image_id="sha256:" + "1" * 64, digest="sha256:" + "2" * 64, version="4.0.15",
                      created=None, architecture="amd64", state="running", health="healthy",
                      restart_policy="unless-stopped", started_at=None, stack="media", compose_service="sonarr",
                      working_dir=str(self.project), compose_files=[str(self.compose)],
                      labels={"com.docker.compose.config-hash": runtime_hash,
                              "com.docker.compose.project": "media"}, local_build=False, ignored=False)
        values.update(changes)
        return Service(**values)

    def status(self, service=None):
        service = service or self.service
        self.agent._compose_status_cache.clear()
        return self.agent.compose_status({"service_key": f"container/{service.container_id}"})

    def records(self, service=None):
        service = service or self.service
        return BaselineStore(self.state).records(
            logical_key(service.stack, service.compose_service, service.working_dir, service.compose_files))

    def edit(self, old, new):
        text = self.compose.read_text()
        self.assertIn(old, text)
        self.compose.write_text(text.replace(old, new))


class ComposeStatusTests(ComposeFixture):
    def test_matching_runtime_hash_is_in_sync_and_captures_private_persistent_baseline(self):
        status = self.status()
        self.assertEqual(status["status"], "in_sync")
        self.assertFalse(status["update_blocked"])
        self.assertEqual(status["baseline"]["origin"], "captured")
        records = self.records()
        self.assertEqual(len(records), 1)
        root = self.state.root / "compose-baselines"
        directory = root / records[0].id
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        for path in [directory, *directory.rglob("*")]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600, path.name)
        stored = sorted(path.read_bytes() for path in (directory / "inputs").iterdir())
        self.assertEqual(stored, sorted([self.compose.read_bytes(), (self.project / ".env").read_bytes()]))
        # Restart: a fresh State and store verify and return the same baseline.
        restarted = BaselineStore(State(self.state.root))
        self.assertEqual(restarted.load(restarted.records(records[0].logical_key)[0]).record.id, records[0].id)
        # An unchanged second check does not write a duplicate baseline.
        self.assertEqual(self.status()["status"], "in_sync")
        self.assertEqual(len(self.records()), 1)

    def test_display_cache_is_invalidated_by_any_source_change(self):
        payload = {"service_key": f"container/{self.service.container_id}"}
        # checked_at has whole-second resolution; pin consecutive checks to
        # different seconds so the test cannot depend on wall-clock timing.
        clock = {"now": "2026-01-01T00:00:00+00:00"}
        with patch("docker_update_manager.webservice.utc_now", side_effect=lambda: clock["now"]):
            first = self.agent.compose_status(payload)
            calls = len(self.fake.calls)
            clock["now"] = "2026-01-01T00:00:01+00:00"
            second = self.agent.compose_status(payload)
            # Runtime network proof is refreshed even if source bytes are stable.
            self.assertGreater(len(self.fake.calls), calls)
            self.edit("restart: unless-stopped", "restart: always")
            self.assertEqual(self.agent.compose_status(payload)["status"], "drifted")

        def stable(status):
            return {key: value for key, value in status.items() if key != "checked_at"}

        self.assertEqual(stable(second), stable(first))
        self.assertLess(datetime.fromisoformat(first["checked_at"]), datetime.fromisoformat(second["checked_at"]))
        # A whole-response comparison would fail here; a real stable-field
        # difference must still be detected by the stable comparison.
        self.assertNotEqual(second, first)
        self.assertNotEqual(stable({**second, "status": "drifted"}), stable(first))

    def test_hash_mismatch_is_drifted_with_redacted_itemised_diff(self):
        self.status()
        self.edit("restart: unless-stopped", "restart: always")
        self.edit("TZ: Europe/London", "TZ: UTC\n      NEW_FLAG: '1'")
        self.edit('published: "8989"', 'published: "9999"')
        self.edit(f'["--api-key", "{SECRET}"]', f'["--api-key", "{SECRET}-rotated"]')
        self.edit("source: /srv/private/sonarr", "source: /srv/private/sonarr-new")
        status = self.status()
        self.assertEqual(status["status"], "drifted")
        self.assertTrue(status["update_blocked"])
        self.assertEqual(status["scope"], "service")
        self.assertTrue(status["changes_itemised"])
        changes = {entry["field"]: entry for entry in status["service_changes"]}
        self.assertEqual((changes["restart"]["old"], changes["restart"]["new"]), ("unless-stopped", "always"))
        self.assertEqual(changes["environment"]["added"], ["NEW_FLAG"])
        self.assertEqual(changes["environment"]["changed"], ["TZ"])
        self.assertEqual(changes["ports"]["added"], ["9999:8989/tcp"])
        self.assertEqual(changes["ports"]["removed"], ["8989:8989/tcp"])
        self.assertEqual(changes["command"]["summary"], "changed")
        self.assertEqual(changes["volumes"]["changed"], ["/config"])
        encoded = json.dumps(status)
        for private in (SECRET, "Europe/London", "UTC", "/srv/private", str(self.project)):
            self.assertNotIn(private, encoded)
        self.assertFalse(re.search(r"[0-9a-f]{64}", encoded), "no hashes or fingerprints reach the browser")
        # No trusted baseline is written for drifted source.
        self.assertEqual(len(self.records()), 1)

    def test_missing_or_malformed_runtime_hash_is_unverifiable(self):
        for labels in ({}, {"com.docker.compose.config-hash": "not-a-hash"}):
            self.service.labels = labels
            status = self.status()
            self.assertEqual(status["status"], "unverifiable")
            self.assertEqual(status["reasons"][0]["code"], "runtime_hash_missing")
            self.assertTrue(status["update_blocked"])
        self.assertEqual(self.records(), [])

    def test_hash_excluded_fields_are_unverifiable(self):
        self.compose.write_text(with_service_lines("    pull_policy: always\n"))
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        status = self.status()
        self.assertEqual((status["status"], status["reasons"][0]["code"]), ("unverifiable", "hash_excluded_fields"))
        self.assertEqual(self.records(), [])

    def test_unsupported_inventory_is_classified_and_never_captured(self):
        for extra, reason in (("include:\n  - other.yml\n", "compose_include"),
                              ("secrets:\n  token:\n    file: ./token.txt\n", "external_secret_or_config"),
                              ("configs:\n  app:\n    environment: APP_CONFIG\n", "external_secret_or_config")):
            self.compose.write_text(BASE_COMPOSE + extra)
            self.service = self.make_service(self.current_hash())
            self.runtime = [self.service]
            status = self.status()
            self.assertEqual(status["status"], "unsupported", extra)
            self.assertIn(reason, [item["code"] for item in status["reasons"]])
            self.assertTrue(status["update_blocked"])
            self.assertIsNone(status["baseline"])
        for extra, reason in (("    label_file: ./labels\n", "label_file"),
                              ("    env_file: ${ENV_DIR}/app.env\n", "interpolated_input_path"),
                              ("    extends:\n      file: base.yml\n      service: base\n", "compose_extends_file")):
            self.compose.write_text(with_service_lines(extra))
            self.assertIn(reason, build_inventory([str(self.compose)], str(self.project)).unsupported)
        self.compose.write_text("services:\n  sonarr: !reset {}\n")
        self.assertIn("unsupported_yaml", build_inventory([str(self.compose)], str(self.project)).unsupported)
        self.assertEqual(self.records(), [])

    def test_env_file_inputs_are_inventoried_copied_and_diffed_by_name(self):
        (self.project / "app.env").write_text(f"DB_PASSWORD={SECRET}\n")
        self.compose.write_text(with_service_lines("    env_file: app.env\n"))
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        self.assertEqual(self.status()["status"], "in_sync")
        loaded = BaselineStore(self.state).load(self.records()[0])
        roles = {item.role: item for item in loaded.inputs}
        self.assertEqual(roles["env_file"].path, str(self.project / "app.env"))
        self.assertEqual(roles["env_file"].content, (self.project / "app.env").read_bytes())
        (self.project / "app.env").write_text("DB_PASSWORD=another-secret\n")
        status = self.status()
        self.assertEqual(status["status"], "drifted")
        environment = next(entry for entry in status["service_changes"] if entry["field"] == "environment")
        self.assertEqual(environment["changed"], ["DB_PASSWORD"])
        self.assertNotIn("another-secret", json.dumps(status))

    def test_model_reported_env_file_outside_inventory_is_unsupported(self):
        model = {"services": {"sonarr": {"env_file": [str(self.project / "hidden.env")]}}}
        inventory = build_inventory([str(self.compose)], str(self.project), model=model)
        self.assertIn("env_file_unlisted", inventory.unsupported)

    def test_env_file_symlink_or_fifo_is_unsupported(self):
        (self.project / "real.env").write_text("A=1\n")
        os.symlink(self.project / "real.env", self.project / "link.env")
        os.mkfifo(self.project / "pipe.env")
        for name in ("link.env", "pipe.env"):
            self.compose.write_text(with_service_lines(f"    env_file: {name}\n"))
            self.assertIn("input_not_regular_file",
                          build_inventory([str(self.compose)], str(self.project)).unsupported)

    def test_source_changed_between_model_read_and_capture_aborts_baseline(self):
        def edit_during_hash(rest):
            if "--hash" in rest:
                self.compose.write_text(self.compose.read_text() + "# concurrent edit\n")
        self.fake.hook = edit_during_hash
        status = self.status()
        self.assertEqual(status["status"], "unverifiable")
        self.assertEqual(status["reasons"][0]["code"], "sources_changed_during_check")
        self.assertEqual(self.records(), [])

    def test_runtime_change_before_persist_aborts_baseline(self):
        calls = {"count": 0}
        replaced = self.make_service(self.current_hash(), image_id="sha256:" + "9" * 64)

        def discover(*_args, **_kwargs):
            calls["count"] += 1
            return [self.service] if calls["count"] == 1 else [replaced]
        with patch("docker_update_manager.webservice.discover", side_effect=discover):
            status = self.status()
        self.assertEqual(status["status"], "unverifiable")
        self.assertEqual(status["reasons"][0]["code"], "runtime_changed_during_check")
        self.assertEqual(self.records(), [])

    def test_service_and_project_level_drift_are_distinguished(self):
        self.status()
        self.edit("restart: unless-stopped", "restart: always")
        plan = self.agent._compose_plan(self.service, self.runtime, persist=True)
        self.assertEqual((plan.status, plan.diff.scope), ("drifted", "service"))
        self.assertTrue(plan.apply_eligible)
        self.assertFalse(plan.discard_eligible)
        self.edit("image: redis:7", "image: redis:8")
        status = self.status()
        self.assertEqual(status["scope"], "project")
        self.assertEqual(status["project_changes"][0]["changed"], ["redis"])
        plan = self.agent._compose_plan(self.service, self.runtime, persist=True)
        self.assertFalse(plan.apply_eligible)
        self.assertIn("project_changes", plan.eligibility_reasons)

    def test_local_build_service_is_never_reconcile_eligible(self):
        # Gate-level: classification (conventional name or explicit marker) is
        # covered by test_discovery; here only local_build drives eligibility.
        self.service = self.make_service(self.current_hash(), local_build=True)
        self.runtime = [self.service]
        self.status()
        self.edit("restart: unless-stopped", "restart: always")
        plan = self.agent._compose_plan(self.service, self.runtime, persist=True)
        self.assertEqual((plan.status, plan.diff.scope), ("drifted", "service"))
        self.assertFalse(plan.apply_eligible)
        self.assertFalse(plan.update_eligible)
        self.assertIn("service_ineligible", plan.eligibility_reasons)

    def test_image_reference_drift_is_not_generic_reconcile_safe(self):
        self.status()
        self.edit("image: lscr.io/linuxserver/sonarr:latest", "image: lscr.io/linuxserver/sonarr:develop")
        status = self.status()
        self.assertEqual(status["status"], "drifted")
        self.assertIn("image_differs", [item["code"] for item in status["reasons"]])
        self.assertTrue(status["image_change"])
        plan = self.agent._compose_plan(self.service, self.runtime, persist=True)
        self.assertFalse(plan.apply_eligible)
        self.assertIn("image_change", plan.eligibility_reasons)

    def test_drift_without_any_trusted_evidence_is_not_itemised(self):
        self.edit("restart: unless-stopped", "restart: always")
        status = self.status()
        self.assertEqual(status["status"], "drifted")
        self.assertFalse(status["changes_itemised"])
        self.assertEqual(status["scope"], "unknown")
        self.assertIsNone(status["baseline"])
        self.assertEqual(self.records(), [])


class BaselineTrustTests(ComposeFixture):
    def test_selected_service_does_not_trust_or_store_unrelated_pending_model(self):
        running_redis_hash = self.current_hash("redis")
        running_redis = self.make_service(running_redis_hash, container_id="b" * 64,
                                          name="redis", compose_service="redis", image="redis:7")
        self.edit("image: redis:7", f"image: redis:7\n    command: ['{SECRET}-pending']")
        self.compose.write_text(self.compose.read_text() + "networks:\n  pending_net: {}\n")
        self.runtime = [self.service, running_redis]
        self.assertNotEqual(self.current_hash("redis"), running_redis_hash)
        status = self.status()
        self.assertEqual(status["status"], "in_sync")
        loaded = BaselineStore(self.state).load(self.records()[0])
        self.assertFalse(loaded.project_trusted)
        self.assertEqual(loaded.record.manifest["trust_scope"], "selected_service")
        self.assertRegex(loaded.model["services"]["redis"], r"^[0-9a-f]{64}$")
        self.assertRegex(loaded.model["networks"]["pending_net"], r"^[0-9a-f]{64}$")
        stored = (self.state.root / "compose-baselines" / loaded.record.id / "model.json").read_text()
        self.assertNotIn(f"{SECRET}-pending", stored)
        self.edit("restart: unless-stopped", "restart: always")
        plan = self.agent._compose_plan(self.service, self.runtime, persist=True)
        self.assertFalse(plan.apply_eligible or plan.discard_eligible)
        self.assertIn("project_unproven", plan.eligibility_reasons)

    def test_retained_backup_is_adopted_only_after_reproducing_runtime_identity(self):
        backup_files([self.compose, self.project / ".env"], self.state.root, self.service)
        self.edit("restart: unless-stopped", "restart: always")
        status = self.status()
        self.assertEqual(status["status"], "drifted")
        self.assertEqual(status["baseline"]["origin"], "adopted_backup")
        self.assertTrue(status["changes_itemised"])
        proof = [call for call in self.fake.calls if "--env-file" in call]
        self.assertTrue(proof, "adoption must reproduce the runtime hash from the backup bytes")
        self.assertTrue(all(call[call.index("--project-directory") + 1] == str(self.project) for call in proof))
        loaded = BaselineStore(self.state).load(self.records()[0])
        self.assertEqual(loaded.record.runtime_hash, self.service.labels["com.docker.compose.config-hash"])
        self.assertIn(b"restart: unless-stopped", next(item.content for item in loaded.inputs if item.role == "compose"))
        self.assertFalse(list((self.state.root / "tmp").glob("compose-proof-*")))

    def test_unrelated_or_non_reproducing_backup_is_rejected(self):
        original = self.compose.read_text()
        self.compose.write_text(original.replace("restart: unless-stopped", "restart: on-failure"))
        backup_files([self.compose, self.project / ".env"], self.state.root, self.service)  # same names, wrong bytes
        backup_files([self.compose], self.state.root, self.make_service("f" * 64, stack="other"))
        self.compose.write_text(original.replace("restart: unless-stopped", "restart: always"))
        status = self.status()
        self.assertEqual(status["status"], "drifted")
        self.assertIsNone(status["baseline"])
        self.assertFalse(status["changes_itemised"])
        self.assertEqual(self.records(), [])
        # A failed adoption attempt is not retried on every page view.
        calls = len(self.fake.calls)
        self.status()
        self.assertFalse([call for call in self.fake.calls[calls:] if "--env-file" in call])

    def test_replacement_container_must_reprove_and_cannot_inherit_other_identity(self):
        self.status()
        captured = self.records()[0]
        self.edit("restart: unless-stopped", "restart: always")
        # A replacement created from a different configuration inherits nothing.
        replacement = self.make_service("c" * 64, container_id="d" * 64)
        self.runtime = [replacement]
        status = self.status(replacement)
        self.assertIsNone(status["baseline"])
        self.assertFalse(status["changes_itemised"])
        # A replacement with the original runtime identity must re-prove it.
        same_identity = self.make_service(captured.runtime_hash, container_id="e" * 64)
        self.runtime = [same_identity]
        before = len(self.fake.calls)
        status = self.status(same_identity)
        self.assertEqual(status["baseline"]["origin"], "reproduced")
        self.assertTrue(any("--env-file" in call for call in self.fake.calls[before:]))
        self.assertEqual(self.records(same_identity)[0].container_id, same_identity.container_id)

    def test_tampered_baseline_material_is_not_trusted(self):
        self.status()
        record = self.records()[0]
        stored = next((self.state.root / "compose-baselines" / record.id / "inputs").iterdir())
        stored.write_bytes(stored.read_bytes() + b"# tampered\n")
        self.edit("restart: unless-stopped", "restart: always")
        status = self.status()
        self.assertEqual(status["status"], "drifted")
        self.assertIsNone(status["baseline"])

    def test_retention_is_bounded_per_logical_service(self):
        for index in range(7):
            self.compose.write_text(BASE_COMPOSE + f"# revision {index}\n")
            self.service = self.make_service(self.current_hash(), container_id=format(index, "064x"))
            self.runtime = [self.service]
            self.assertEqual(self.status()["status"], "in_sync")
        records = self.records()
        self.assertEqual(len(records), 4)
        directories = [path.name for path in (self.state.root / "compose-baselines").iterdir()]
        self.assertEqual(sorted(directories), sorted(record.id for record in records))


class UpdatePreflightTests(ComposeFixture):
    def save_update_evidence(self):
        self.state.start_scan("scan-" + str(time.time_ns()))
        run = self.state.latest_scan_run()
        item = {"service": _public_service(self.service), "status": "UPDATE",
                "remote_digest": "sha256:" + "3" * 64, "remote_version": "4.0.16"}
        self.state.finish_scan(run["id"], "complete", services=[item])
        return self.agent.verification_snapshot()["records"][0]["verification_id"]

    def review(self, verification_id):
        return self.agent.update_review({"service_key": f"container/{self.service.container_id}",
                                         "requested_by": "admin", "verification_id": verification_id})

    def assert_in_sync_but_update_blocked(self, reason):
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        status = self.status()
        self.assertEqual(status["status"], "in_sync")
        self.assertTrue(status["update_blocked"])
        self.assertEqual(status["update_reasons"][0]["code"], reason)
        with self.assertRaises(ComposePreflightRefused) as refused:
            self.review(self.save_update_evidence())
        self.assertEqual((refused.exception.status, refused.exception.reason), ("in_sync", reason))
        return status

    def test_effective_project_name_and_process_override_are_separate_from_service_hash(self):
        verification_id = self.save_update_evidence()
        reviewed = self.review(verification_id)
        self.assertRegex(reviewed["confirmation_id"], r"^[A-Za-z0-9_-]{43}$")
        self.assertEqual(self.status()["status"], "in_sync")
        self.edit("name: media", "name: other")
        status = self.assert_in_sync_but_update_blocked("project_identity")
        self.assertNotIn(str(self.project), json.dumps(status))
        with patch.dict(os.environ, {"COMPOSE_PROJECT_NAME": "redirected"}):
            process_status = self.status()
            self.assertTrue(process_status["update_blocked"])
            with self.assertRaises(ComposePreflightRefused):
                self.review(verification_id)
        self.compose.write_text(BASE_COMPOSE)
        (self.project / ".env").write_text(f"SONARR_API_KEY={SECRET}\nCOMPOSE_PROJECT_NAME=other\n")
        self.assert_in_sync_but_update_blocked("project_identity")
        self.assertEqual(FakeCompose.model([str(self.compose)], str(self.project), None, "media")["name"], "media")
        with self.assertRaises(ValueError):
            self.agent.update_review({"service_key": f"container/{self.service.container_id}",
                                      "requested_by": "admin", "verification_id": verification_id,
                                      "project_name": "media"})

    def test_selected_project_resources_require_runtime_proof(self):
        cases = (
            (BASE_COMPOSE + "networks:\n  default:\n    driver: overlay\n", "network_unproven"),
            (BASE_COMPOSE.replace("type: bind, source: /srv/private/sonarr",
                                  "type: volume, source: data")
             + "volumes:\n  data:\n    driver: local\n", "named_volume_unproven"),
            (with_service_lines("    configs: [settings]\n")
             + "configs:\n  settings:\n    content: safe-example\n", "service_resource_unproven"),
            (with_service_lines("    secrets: [password]\n")
             + "secrets:\n  password:\n    content: safe-example\n", "service_resource_unproven"),
        )
        for source, reason in cases:
            with self.subTest(reason=reason):
                self.compose.write_text(source)
                self.assert_in_sync_but_update_blocked(reason)
        self.assertTrue(all("pull" not in call and "up" not in call for call in self.fake.calls))

    def test_project_declared_plain_bridge_network_is_proven(self):
        use_named_runtime_network(self.fake)
        for project_network in (NAMED_NETWORK, NAMED_NETWORK.replace("    driver: bridge\n", "")):
            with self.subTest(project_network=project_network):
                self.compose.write_text(with_named_network(project_network=project_network))
                self.service = self.make_service(self.current_hash())
                self.runtime = [self.service]
                status = self.status()
                self.assertEqual(status["status"], "in_sync")
                self.assertFalse(status["update_blocked"])
                self.review(self.save_update_evidence())  # Preflight consumes the same proof.

    def test_named_network_user_semantics_remain_unproven(self):
        use_named_runtime_network(self.fake)
        declared = NAMED_NETWORK
        cases = {
            "external": with_named_network(project_network=declared + "    external: true\n"),
            "custom name": with_named_network(project_network=declared.replace("media_monitoring", "shared")),
            "non-bridge driver": with_named_network(project_network=declared.replace("bridge", "overlay")),
            "driver options": with_named_network(project_network=declared + "    driver_opts:\n      mtu: '1400'\n"),
            "custom ipam": with_named_network(project_network=declared.replace(
                "ipam: {}", "ipam:\n      config:\n        - subnet: 172.30.0.0/24")),
            "internal": with_named_network(project_network=declared + "    internal: true\n"),
            "attachable": with_named_network(project_network=declared + "    attachable: true\n"),
            "ipv6": with_named_network(project_network=declared + "    enable_ipv6: true\n"),
            "labels": with_named_network(project_network=declared + "    labels:\n      a: b\n"),
            "undeclared": with_named_network(project_network=""),
            "static address": with_named_network("      monitoring:\n        ipv4_address: 172.30.0.5\n"),
            "alias": with_named_network("      monitoring:\n        aliases: [metrics]\n"),
            "multiple networks": with_named_network("      monitoring:\n      default:\n"),
            "network_mode": with_named_network(source=with_service_lines("    network_mode: host\n")),
        }
        for name, source in cases.items():
            with self.subTest(name):
                self.compose.write_text(source)
                self.assert_in_sync_but_update_blocked("network_unproven")
        with self.subTest("runtime logical network label differs"):
            self.fake.network_logical = "default"
            self.compose.write_text(with_named_network())
            self.assert_in_sync_but_update_blocked("network_unproven")
        with self.subTest("runtime attachment differs from declared network"):
            self.fake.network_name, self.fake.network_logical = "media_default", "default"
            self.assert_in_sync_but_update_blocked("network_unproven")

    def test_used_network_definition_change_keeps_service_in_sync_but_blocks_update(self):
        self.assertEqual(self.status()["status"], "in_sync")
        self.compose.write_text(BASE_COMPOSE + "networks:\n  default:\n    driver: overlay\n")
        self.assert_in_sync_but_update_blocked("network_unproven")

    def test_named_volume_definition_change_keeps_service_hash_but_blocks_update(self):
        source = BASE_COMPOSE.replace("type: bind, source: /srv/private/sonarr",
                                      "type: volume, source: data") + "volumes:\n  data: {}\n"
        self.compose.write_text(source)
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        self.compose.write_text(source.replace("data: {}", "data: {driver: local}"))
        self.assert_in_sync_but_update_blocked("named_volume_unproven")

    def test_project_or_resource_change_after_review_blocks_before_mutation(self):
        for change in ("project", "network", "runtime_network"):
            with self.subTest(change=change):
                self.compose.write_text(BASE_COMPOSE)
                self.fake.network_id = "b" * 64
                self.service = self.make_service(self.current_hash())
                self.runtime = [self.service]
                confirmation = self.review(self.save_update_evidence())["confirmation_id"]
                if change == "project":
                    self.edit("name: media", "name: other")
                elif change == "network":
                    self.compose.write_text(BASE_COMPOSE + "networks:\n  default:\n    driver: overlay\n")
                else:
                    self.fake.network_id = "c" * 64
                with patch("docker_update_manager.webservice.do_update") as update, \
                     patch("docker_update_manager.webservice.scan_service_with_tracking",
                           return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64,
                                                        remote_version="4.0.16", remote_created=None)):
                    started = self.agent.start_update({"confirmation_id": confirmation, "requested_by": "admin",
                                                       "client_ip": "127.0.0.1", "user_agent": "tests"})
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        operation = self.state.operation_status(started["operation_id"])
                        if operation["status"] in {"blocked", "failed", "succeeded"}:
                            break
                        time.sleep(.01)
                self.assertEqual(operation["status"], "blocked")
                update.assert_not_called()
                self.assertFalse(any("pull" in call or "up" in call for call in self.fake.calls))
                self.assertEqual(self.state.audit_events(1)[0]["result"], "blocked")

    def test_runtime_network_change_at_pre_pull_gate_blocks_without_mutation(self):
        confirmation = self.review(self.save_update_evidence())["confirmation_id"]
        def core(_service, _state, **kwargs):
            self.fake.network_id = "c" * 64
            kwargs["pre_pull_check"]()
        with patch("docker_update_manager.webservice.do_update", side_effect=core) as update, \
             patch("docker_update_manager.webservice.scan_service_with_tracking",
                   return_value=SimpleNamespace(status="UPDATE", remote_digest="sha256:" + "3" * 64,
                                                remote_version="4.0.16", remote_created=None)):
            started = self.agent.start_update({"confirmation_id": confirmation, "requested_by": "admin",
                                               "client_ip": "127.0.0.1", "user_agent": "tests"})
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                operation = self.state.operation_status(started["operation_id"])
                if operation["status"] in {"blocked", "failed", "succeeded"}:
                    break
                time.sleep(.01)
        self.assertEqual(operation["status"], "blocked")
        update.assert_called_once()
        self.assertFalse(any("pull" in call or "up" in call for call in self.fake.calls))

    def test_unrelated_service_and_resource_change_does_not_gain_project_trust(self):
        self.compose.write_text(BASE_COMPOSE.replace("image: redis:7", "image: redis:8")
                                + "volumes:\n  other:\n    driver: local\n")
        status = self.status()
        self.assertEqual(status["status"], "in_sync")
        self.assertFalse(status["update_blocked"])
        self.review(self.save_update_evidence())
        loaded = BaselineStore(self.state).load(self.records()[0])
        self.assertFalse(loaded.project_trusted)
        self.assertRegex(loaded.model["services"]["redis"], r"^[0-9a-f]{64}$")
        self.assertRegex(loaded.model["volumes"]["other"], r"^[0-9a-f]{64}$")

    def test_public_status_excludes_runtime_network_and_source_material(self):
        status = self.status()
        serialised = json.dumps(status)
        for private in (self.fake.network_id, self.service.container_id, SECRET, str(self.project),
                        "/srv/private/sonarr"):
            self.assertNotIn(private, serialised)
        self.assertFalse(status["update_blocked"])
        with patch("docker_update_manager.webservice._runtime_project_network_id",
                   side_effect=RuntimeError(SECRET + str(self.project) + "x" * 70000)):
            blocked = self.status()
        self.assertEqual(blocked["update_reasons"][0]["code"], "network_unproven")
        self.assertNotIn(SECRET, json.dumps(blocked))
        self.assertNotIn(str(self.project), json.dumps(blocked))

    def test_second_replica_cannot_borrow_selected_container_network_proof(self):
        second = self.make_service(self.current_hash(), container_id="c" * 64)
        self.runtime.append(second)
        status = self.status()
        self.assertEqual(status["status"], "in_sync")
        self.assertEqual(status["update_reasons"][0]["code"], "multiple_replicas")
        with self.assertRaises(ComposePreflightRefused):
            self.review(self.save_update_evidence())

    def test_update_review_refuses_drift_independently_of_the_page(self):
        verification_id = self.save_update_evidence()
        self.assertRegex(self.review(verification_id)["confirmation_id"], r"^[A-Za-z0-9_-]{43}$")
        self.edit("restart: unless-stopped", "restart: always")
        with self.assertRaises(ComposePreflightRefused) as refused:
            self.review(verification_id)
        self.assertEqual((refused.exception.status, refused.exception.reason), ("drifted", "config_hash_differs"))
        # Preflight never captures or adopts baselines.
        self.assertEqual(self.records(), [])

    def test_update_review_refuses_incomplete_inventory_even_with_matching_hash(self):
        for source, reason in ((BASE_COMPOSE + "configs:\n  app:\n    file: ./app.conf\n", "external_secret_or_config"),
                               (BASE_COMPOSE + "secrets:\n  token:\n    external: true\n", "external_secret_or_config"),
                               (with_service_lines("    label_file: ./labels\n"), "label_file"),
                               (BASE_COMPOSE + "include:\n  - extra.yml\n", "compose_include")):
            self.compose.write_text(source)
            self.service = self.make_service(self.current_hash())
            self.runtime = [self.service]
            verification_id = self.save_update_evidence()
            self.assertEqual(self.status()["status"], "unsupported")
            self.assertTrue(self.status()["update_blocked"])
            with self.assertRaises(ComposePreflightRefused) as refused:
                self.review(verification_id)
            self.assertEqual((refused.exception.status, refused.exception.reason), ("unsupported", reason))
        self.assertEqual(self.records(), [])

    def test_process_interpolation_precedence_never_creates_recoverable_baseline(self):
        with patch.dict(os.environ, {"SONARR_API_KEY": "uncaptured-process-secret"}):
            self.service = self.make_service(self.current_hash())
            self.runtime = [self.service]
            verification_id = self.save_update_evidence()
            status = self.status()
            self.assertEqual(status["status"], "unsupported")
            self.assertEqual(status["reasons"][0]["code"], "interpolation_unproven")
            self.assertTrue(status["update_blocked"])
            self.assertEqual(self.records(), [])
            with self.assertRaises(ComposePreflightRefused) as refused:
                self.review(verification_id)
            self.assertEqual(refused.exception.status, "unsupported")
            self.assertNotIn("uncaptured-process-secret", refused.exception.public_message)

    def test_shell_inherited_environment_is_unsupported(self):
        self.compose.write_text(BASE_COMPOSE.replace("      API_KEY: ${SONARR_API_KEY}",
                                                    "      HOST_TOKEN:\n      API_KEY: ${SONARR_API_KEY}"))
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        verification_id = self.save_update_evidence()
        self.assertIn("shell_environment_inheritance",
                      build_inventory([str(self.compose)], str(self.project)).unsupported)
        self.assertEqual(self.status()["status"], "unsupported")
        self.assertEqual(self.records(), [])
        with self.assertRaises(ComposePreflightRefused):
            self.review(verification_id)

    def test_process_environment_change_invalidates_status_cache(self):
        self.assertEqual(self.status()["status"], "in_sync")
        with patch.dict(os.environ, {"SONARR_API_KEY": SECRET}):
            status = self.agent.compose_status({"service_key": f"container/{self.service.container_id}"})
            self.assertEqual(status["status"], "unsupported")

    def test_mutation_boundary_refuses_newly_unsupported_inputs_with_unchanged_model(self):
        key = f"container/{self.service.container_id}"
        expected_model = FakeCompose.model([str(self.compose)], str(self.project), None)
        self.agent._revalidate_compose_runtime_identity(key, self.service, self.current_hash(), expected_model)
        # Same effective value and hash, but its provenance is now the shell.
        with patch.dict(os.environ, {"SONARR_API_KEY": SECRET}):
            self.assertEqual(FakeCompose.model([str(self.compose)], str(self.project), None), expected_model)
            with self.assertRaises(PreMutationRefusal) as refused:
                self.agent._revalidate_compose_runtime_identity(key, self.service, self.current_hash(), expected_model)
            self.assertEqual(refused.exception.reason, "compose_unverifiable")

    def test_socket_refusal_is_structured_and_rebuilt_from_bounded_codes(self):
        verification_id = self.save_update_evidence()
        self.edit("restart: unless-stopped", "restart: always")
        server = AgentServer(self.agent, "/tmp/unused.sock", allowed_mutation_uid=1000)
        line = json.dumps({"operation": "update_review", "payload": {
            "service_key": f"container/{self.service.container_id}", "requested_by": "admin",
            "verification_id": verification_id, "_upt_client_version": __version__}, "client_version": __version__}).encode() + b"\n"
        response = json.loads(server.handle_line(line, peer_uid=1000))
        self.assertEqual(set(response), {"ok", "error", "type", "status", "reason"})
        self.assertEqual((response["type"], response["status"], response["reason"]),
                         ("ComposePreflightRefused", "drifted", "config_hash_differs"))
        self.assertNotIn(SECRET, json.dumps(response))

        class Socket:
            def __init__(self, *_args): pass
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def settimeout(self, _value): pass
            def connect(self, _path): pass
            def sendall(self, _data): pass
            def makefile(self, _mode):
                return io.BytesIO(json.dumps(answers.pop(0)).encode() + b"\n")
        # The first exchange is the client's pre-mutation version probe.
        answers = [{"ok": True, "data": {"ok": True, "version": __version__}}, {**response, "error": "tampered text"}]
        with patch("docker_update_manager.agent.socket.socket", Socket):
            with self.assertRaises(ComposePreflightRefused) as refused:
                AgentClient("/tmp/unused.sock").call("update_review", {})
        self.assertNotIn("tampered", refused.exception.public_message)
        self.assertEqual(answers, [])

    def test_status_is_a_bounded_read_only_agent_operation(self):
        self.assertIn("compose_status", webservice.READ_ONLY_OPERATIONS)
        self.assertNotIn("compose_status", webservice.MUTATION_OPERATIONS)
        with self.assertRaises(ValueError):
            self.agent.compose_status({"service_key": f"container/{self.service.container_id}", "path": "/etc"})
        with self.assertRaises(ValueError):
            self.agent.compose_status({"service_key": "../../etc"})
        self.status()
        self.assertTrue(self.fake.calls)
        self.assertTrue(all((call[2] == "--project-directory" and "config" in call)
                            or call[:3] in (["docker", "inspect", "--type"],
                                            ["docker", "network", "inspect"])
                            for call in self.fake.calls))


class BlockedOperationTests(ComposeFixture):
    def test_core_update_records_blocked_only_before_mutation_boundary(self):
        state = State(self.root / "core-state")
        state.record(service="another-service", action="update", result="SUCCESS",
                     old_image_id="sha256:" + "9" * 64)
        protected_before = state.protected()
        points_before = rollback_points(self.config, state)
        boundary = []
        refused = PreMutationRefusal("Pending or unverified Compose changes were detected", "compose_drift")

        def refuse():
            raise refused
        manifest = {"digest": "sha256:" + "3" * 64, "platforms": []}
        with patch("docker_update_manager.operations.remote_manifest", return_value=manifest), \
             patch("docker_update_manager.operations.run") as run:
            with self.assertRaises(PreMutationRefusal):
                do_update(self.service, state, yes=True, audit_context={"origin": "web"}, pre_pull_check=refuse,
                          target_guard=lambda *_args: None, mutation_started=boundary.append, output=lambda *_: None)
            run.assert_not_called()
        self.assertEqual(boundary, [])
        row = state.history()[0]
        self.assertEqual(row["result"], "BLOCKED")
        self.assertIs(json.loads(row["details"])["mutation_performed"], False)
        self.assertEqual(state.protected(), protected_before)
        self.assertEqual(rollback_points(self.config, state), points_before)
        with state.connect() as connection:
            self.assertIsNone(connection.execute("SELECT 1 FROM rollback_refs WHERE history_id=?", (row["id"],)).fetchone())

        with patch("docker_update_manager.operations.remote_manifest", return_value=manifest), \
             patch("docker_update_manager.operations.run"):
            with self.assertRaises(PreMutationRefusal):
                do_update(self.service, state, yes=True, audit_context={"origin": "web"}, pre_recreate_check=refuse,
                          target_guard=lambda *_args: None, mutation_started=boundary.append, output=lambda *_: None)
        self.assertEqual(boundary, ["pull"])
        self.assertEqual(state.history()[0]["result"], "FAILED")
        self.assertIn(self.service.image_id, state.protected())
        self.assertEqual(len(rollback_points(self.config, state)), len(points_before) + 1)

    def test_blocked_is_terminal_not_active(self):
        self.state.create_operation("a" * 32, kind="update", service_key="container/" + "a" * 64,
                                    service="sonarr", stack="media", requested_by="admin", summary={})
        self.assertTrue(self.state.finish_operation("a" * 32, "blocked", message="No changes", error="No changes"))
        operation = self.state.operation_status("a" * 32)
        self.assertEqual((operation["status"], operation["current_stage"]), ("blocked", "Blocked"))
        self.assertEqual(operation["events"][-1]["kind"], "operation_blocked")
        self.assertFalse(self.state.finish_operation("a" * 32, "failed", message="late"))
        # Not active: another operation may be claimed.
        self.state.create_operation("b" * 32, kind="update", service_key="container/" + "a" * 64,
                                    service="sonarr", stack="media", requested_by="admin", summary={})

    def test_blocked_presentation_says_no_mutation_and_is_not_failure(self):
        view = operation_presentation({"status": "blocked", "kind": "update",
                                       "error": "Compose configuration changed after review."})
        self.assertEqual(view["outcome"], "blocked")
        self.assertFalse(view["error"])
        self.assertEqual(view["badge_class"], "status-warning")
        self.assertTrue(view["alert"].startswith("No changes were made."))
        self.assertNotIn("recovery", view["alert"].lower())
        self.assertEqual(view["stage"], "Update blocked")


class ServiceDetailAndOperationRouteTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.state = WebState(root / "web-state")
        user_id = self.state.create_user("admin", "not-used")
        self.csrf = new_token()
        sid = self.state.create_session(user_id, self.csrf,
                                        (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
                                        (datetime.now(timezone.utc) + timedelta(days=30)).isoformat())
        self.agent = BrowserFixtureAgent()
        self.client = TestClient(create_app(WebConfig(path=str(root / "web.yml")), self.state, self.agent))
        self.client.cookies.set("upt_session", sid)
        self.url = "/services/container/" + "a" * 64

    @staticmethod
    def drifted(**changes):
        data = {"status": "drifted", "reasons": [{"code": "config_hash_differs",
                                                  "message": compose_drift.REASONS["config_hash_differs"]}],
                "inventory_reasons": [], "checked_at": "2026-09-27T14:00:00+00:00",
                "baseline": {"captured_at": "2026-09-27T13:55:00+00:00", "origin": "captured"},
                "update_blocked": True, "image_change": False, "scope": "service", "changes_itemised": True,
                "service_changes": [
                    {"field": "environment", "label": "Environment", "summary": "1 changed", "changed": ["API_KEY"]},
                    {"field": "restart", "label": "Restart policy", "summary": "unless-stopped → always",
                     "old": "unless-stopped", "new": "always"},
                    {"field": "ports", "label": "Ports", "summary": "1 added, 1 removed",
                     "added": ["9999:8989/tcp"], "removed": ["8989:8989/tcp"]}],
                "project_changes": []}
        data.update(changes)
        return data

    def test_in_sync_service_keeps_review_update(self):
        page = self.client.get(self.url)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Compose configuration in sync", page.text)
        self.assertIn('action="/operations/update"', page.text)

    def test_in_sync_service_with_unproven_execution_context_shows_bounded_block(self):
        self.agent.compose_status_data.update(update_blocked=True,
            update_reasons=[{"code": "network_unproven", "message": compose_drift.REASONS["network_unproven"]}])
        page = self.client.get(self.url)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Compose configuration in sync", page.text)
        self.assertIn("The selected service&#39;s Compose network cannot be proven", page.text)
        self.assertNotIn('action="/operations/update"', page.text)

    def test_drift_blocks_review_update_and_offers_redacted_review(self):
        self.agent.compose_status_data = self.drifted()
        page = self.client.get(self.url)
        self.assertIn("Changes pending", page.text)
        self.assertNotIn("Configuration changes pending", page.text)
        self.assertIn("Update available", page.text)
        self.assertIn('href="#configuration">Blocked by pending configuration changes', page.text)
        self.assertIn("3 service settings changed", page.text)
        self.assertIn("Show changes", page.text)
        self.assertIn("<code>API_KEY</code>", page.text)
        self.assertIn("Pending configuration changes must be resolved before updating the image.", page.text)
        self.assertNotIn("applied or reverted", page.text)
        self.assertNotIn('action="/operations/update"', page.text)
        self.assertNotIn("Apply pending changes", page.text)
        self.assertNotIn("Revert pending", page.text)
        self.assertEqual(self.agent.review_ids, {})

    def test_unsupported_inputs_block_update_on_service_page(self):
        self.agent.compose_status_data = {
            "status": "unsupported", "reasons": [{"code": "label_file", "message": compose_drift.REASONS["label_file"]}],
            "inventory_reasons": [], "checked_at": "2026-09-27T14:00:00+00:00", "baseline": None,
            "update_blocked": True, "image_change": False,
        }
        page = self.client.get(self.url)
        self.assertIn("Inputs unverified", page.text)
        self.assertIn("All Compose configuration inputs must be verified before updating the image.", page.text)
        self.assertIn("Blocked by unverified configuration", page.text)
        self.assertNotIn("Blocked by pending configuration changes", page.text)
        self.assertNotIn('action="/operations/update"', page.text)

    def test_agent_preflight_refusal_is_shown_when_page_status_is_stale(self):
        original = BrowserFixtureAgent.call

        def refusing(agent, operation, payload=None):
            if operation == "update_review":
                raise ComposePreflightRefused("drifted", "config_hash_differs")
            return original(agent, operation, payload)
        with patch.object(BrowserFixtureAgent, "call", refusing):
            page = self.client.get(self.url)
        self.assertNotIn('action="/operations/update"', page.text)
        self.assertIn("Image updates are blocked until the running service matches its Compose configuration", page.text)

    def test_unavailable_or_malformed_status_does_not_invent_state(self):
        self.agent.compose_status_data = {"status": "totally-fine", "raw": SECRET}
        page = self.client.get(self.url)
        self.assertIn("Configuration status is temporarily unavailable.", page.text)
        self.assertNotIn(SECRET, page.text)

    def test_blocked_operation_renders_identically_live_and_reloaded(self):
        operation = {"id": "f" * 32, "kind": "update", "service_key": "container/" + "a" * 64,
                     "service": "Sonarr", "stack": "media", "requested_by": "admin", "status": "blocked",
                     "current_stage": "Blocked", "result": {"blocked_reason": "compose_drift", "mutation_performed": False},
                     "error": "Compose configuration changed after review. Review the pending configuration changes on the service page before trying again.",
                     "events": [{"id": 1, "kind": "operation_blocked", "stage": "Blocked", "status": "blocked",
                                 "message": "Compose configuration changed after review.", "payload": {}}],
                     "last_event_id": 1}
        self.agent.operation = operation
        page = self.client.get("/operations/" + "f" * 32)
        view = operation_presentation(operation)
        self.assertIn('data-status="blocked"', page.text)
        self.assertIn('data-outcome="blocked"', page.text)
        self.assertIn("No changes were made. Compose configuration changed after review.", page.text)
        self.assertIn("Blocked · no changes made", page.text)
        self.assertNotIn("data-operation-error", page.text)
        self.assertNotIn("recovery details", page.text)
        stream = self.client.get("/operations/" + "f" * 32 + "/events")
        self.assertIn("event: operation-blocked", stream.text)
        payload = json.loads(stream.text.split("event: operation-blocked\ndata: ", 1)[1].split("\n", 1)[0])
        self.assertEqual(payload["presentation"], view)


class DiffProjectionTests(unittest.TestCase):
    def test_unsafe_names_and_values_are_counted_not_projected(self):
        old = {"environment": {"A": "1"}, "labels": {"x": "y"}, "user": "1000:1000",
               "security_opt": ["seccomp=/etc/private.json"], "x-custom": {"token": SECRET}}
        new = {"environment": {"A": "2", "bad name; rm": SECRET}, "labels": {"x": "z"}, "user": "root; id",
               "security_opt": ["seccomp=unconfined"], "x-custom": {"token": "other"},
               "cap_add": ["NET_ADMIN", "bad cap"]}
        entries = {entry["field"]: entry for entry in compose_drift.service_changes(old, new)}
        self.assertEqual(entries["environment"], {"field": "environment", "label": "Environment",
                                                  "summary": "1 added, 1 changed", "changed": ["A"], "hidden": 1})
        self.assertEqual(entries["user"]["summary"], "changed")
        self.assertEqual(entries["security_opt"]["summary"], "changed")
        self.assertEqual(entries["other"]["summary"], "1 changed")
        self.assertEqual(entries["cap_add"]["added"], ["NET_ADMIN"])
        encoded = json.dumps(entries)
        for private in (SECRET, "rm", "/etc/private.json", "unconfined", "root", "bad cap", "x-custom"):
            self.assertNotIn(private, encoded)

    def test_diff_fingerprint_binds_baseline_and_desired_model(self):
        old = {"services": {"s": {"image": "a:1", "restart": "no"}}}
        new = {"services": {"s": {"image": "a:1", "restart": "always"}}}
        first = compute_diff(old, new, "s", "b" * 64)
        self.assertEqual(first.fingerprint, compute_diff(old, new, "s", "b" * 64).fingerprint)
        self.assertNotEqual(first.fingerprint, compute_diff(old, new, "s", "c" * 64).fingerprint)
        self.assertFalse(first.image_change)


if __name__ == "__main__":
    unittest.main()
