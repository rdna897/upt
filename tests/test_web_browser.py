"""Real Chromium viewport and interaction tests for the authenticated UPT web UI.

Run with: python -m pip install '.[test,browser-test]'
          python -m playwright install chromium
          python -m unittest discover -s tests -p 'test_web_browser.py' -v
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import os
import socket
import tempfile
import threading
import time
import unittest
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("UPT_TESTING", "1")

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # Unit-test jobs need not install browser tooling.
    sync_playwright = None

from uvicorn import Config as UvicornConfig, Server

from docker_update_manager import __version__
from docker_update_manager.auth import hash_password, new_token, utc_after
from docker_update_manager.agent import AgentNotFound
from docker_update_manager.compose_drift import ComposePreflightRefused
from docker_update_manager.config import Config, WebConfig
from docker_update_manager.state import State
from docker_update_manager.webapp import create_app
from docker_update_manager.models import Service
from docker_update_manager.registry import scan_service
from docker_update_manager.webservice import ReadOnlyService, _public_result


def screenshot_dir(name):
    """Scratch location for screenshots captured as a side effect of tests.

    Committed screenshot sets under docs/screenshots/ are curated evidence for
    a specific change; routine test runs must not overwrite them. Set
    UPT_SCREENSHOT_DIR to collect captures somewhere deliberate.
    """
    root = Path(os.environ.get("UPT_SCREENSHOT_DIR") or Path(tempfile.gettempdir()) / "upt-browser-screenshots")
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def build_snapshot():
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    definitions = [
        ("media/sonarr", "Sonarr", "UPDATE", "4.0.15", "4.0.16"),
        ("media/radarr", "Radarr", "CURRENT", "5.28.0", None),
        ("monitoring/grafana", "Grafana", "PINNED UPDATE", "12.1.0", "12.1.1"),
        ("media/gluetun", "Gluetun", "DIGEST CHANGED", "latest", None),
        ("media/long-service-" + "x" * 72, "Long service identity " + "y" * 48, "REGISTRY ERROR", None, None),
        ("media/arch-agent", "Architecture agent", "ARCH UNSUPPORTED", "1.0", None),
        ("media/unknown-agent", "Unknown agent", "UNKNOWN", None, None),
        ("media/unknown-agent-two", "Unknown agent two", "UNKNOWN", None, None),
        ("media/registry-agent", "Registry agent", "REGISTRY ERROR", None, None),
        ("media/digest-untracked", "Digest-pinned service", "UNTRACKED DIGEST", "1.2.3", None),
    ]
    results = []
    for index, (key, name, status, version, remote) in enumerate(definitions):
        image = "registry.example/" + name.lower().replace(" ", "-") + (":latest" if version == "latest" else ":1.2.3")
        service = {
            "key": key,
            "name": name,
            "stack": "monitoring" if key.startswith("monitoring/") else "media",
            "image": image,
            "image_id": "sha256:" + format(index, "064x"),
            "digest": "sha256:" + format(index + 1, "064x"),
            "version": version,
            "state": "running",
            "health": "healthy",
            "architecture": "amd64",
            "working_dir": "/opt/" + "path-component-" * 12,
            "compose_files": ["/opt/" + "compose-directory-" * 8 + "/compose.yml"],
        }
        if key == "media/sonarr":
            service.update({
                "container_id": "a" * 64,
                "compose_service": "sonarr",
                "local_build": False,
                "ignored": False,
            })
        results.append({
            "service": service,
            "status": status,
            "remote_version": remote,
            "remote_digest": "sha256:" + format(index + 2, "064x"),
            "error": "No trusted tracking tag is recorded for this digest pin. UPT did not guess a release channel, so update tracking is unavailable." if status == "UNTRACKED DIGEST" else None,
        })
    return {
        "scan_id": "b" * 32,
        "status": "complete",
        "started_at": now,
        "finished_at": now,
        "payload": {"count": len(results), "services": results},
    }


def build_runtime_container(container_id, name, *, stack="media", service=None, state="running",
                            healthcheck="healthy", restart_count=0, exit_code=0, oom_killed=False):
    return {
        "key": "container/" + container_id,
        "container_id": container_id,
        "name": name,
        "stack": stack,
        "compose_service": service or name.lower(),
        "image": "registry.example/" + name.lower() + ":1.2.3",
        "state": state,
        "healthcheck": healthcheck,
        "restart_count": restart_count,
        "restart_policy": "unless-stopped",
        "started_at": "2026-09-27T08:00:00Z",
        "finished_at": "2026-09-27T13:30:00Z" if state != "running" else None,
        "exit_code": exit_code,
        "oom_killed": oom_killed,
        "health_failing_streak": 3 if healthcheck == "unhealthy" else 0,
        "health_last_started_at": "2026-09-27T14:00:00Z",
        "health_last_finished_at": "2026-09-27T14:00:01Z",
        "health_last_exit_code": 1 if healthcheck == "unhealthy" else 0,
        "ignored": False,
    }


class BrowserFixtureAgent:
    product_version = __version__
    def __init__(self):
        self.snapshot_data = build_snapshot()
        self.runtime_data = {
            "status": "current", "available": True, "stale": False,
            "captured_at": "2026-09-27T14:00:00+00:00",
            "last_success_at": "2026-09-27T14:00:00+00:00",
            "attempted_at": "2026-09-27T14:00:00+00:00", "attempt_success": True,
            "failure_category": None,
            "containers": [build_runtime_container("a" * 64, "Sonarr", service="sonarr", healthcheck="healthy")],
        }
        self.scan = None
        self.cursor_values = []
        self.scan_start_calls = 0
        self.hold_scan = False
        self.expire_session_on_stream = False
        self.missing_scan = False
        self.state = None
        self.session_to_revoke = None
        self._lock = threading.Lock()
        self.scan_services = ["media/sonarr", "media/radarr"]
        self.scan_status_by_service = {}
        self.hold_after_discovery = False
        self.hold_after_completed = None
        self.update_calls = []
        self.rollback_calls = []
        self.compose_review_ids = {}
        self.compose_apply_calls = []
        self.review_ids = {}
        self.rollback_review_ids = {}
        self.rollback_available = False
        self.rollback_digest_pin = False
        self.rollback_terminal_status = "running"
        self.operation = None
        self.emit_operation_warning = False
        self.refresh_calls = []
        self.refresh_mode = "scan_active"
        self.targeted_results = {}
        self.compose_status_data = {
            "status": "in_sync", "reasons": [], "inventory_reasons": [],
            "checked_at": "2026-09-27T14:00:00+00:00",
            "baseline": {"captured_at": "2026-09-27T13:55:00+00:00", "origin": "captured"},
            "update_blocked": False, "image_change": False,
        }

    def call(self, operation, payload=None):
        payload = payload or {}
        if operation == "health":
            return {"ok": True, "version": self.product_version, "docker": {"ok": True, "version": "fixture"}}
        if operation == "compose_status":
            return deepcopy(self.compose_status_data)
        if operation == "snapshot":
            return deepcopy(self.snapshot_data)
        if operation == "runtime_snapshot":
            return deepcopy(self.runtime_data)
        if operation == "verification_snapshot":
            records = []
            for item in self.snapshot_data["payload"]["services"]:
                service = item["service"]
                container_id = service.get("container_id")
                if not container_id or item.get("status") in {"UNKNOWN", "REGISTRY ERROR"}:
                    continue
                current = deepcopy(item)
                current["service"]["key"] = "container/" + container_id
                records.append({"service_key": "container/" + container_id,
                                "verification_id": "fixture-" + container_id[:8],
                                "checked_at": self.snapshot_data["finished_at"],
                                "fresh": True, "failed_at": None, "result": current})
            records.extend(deepcopy(list(self.targeted_results.values())))
            return {"records": records}
        if operation == "refresh_start":
            key = payload["service_key"]
            self.refresh_calls.append(key)
            if self.refresh_mode == "scan_active":
                return {"status": "scan_active", "existing": True}
            runtime = next((item for item in self.runtime_data["containers"] if item.get("key") == key), None)
            if runtime and self.refresh_mode == "success":
                service = deepcopy(self.snapshot_data["payload"]["services"][0]["service"])
                service.update({"key": key, "container_id": runtime["container_id"],
                                "image": runtime["image"], "name": runtime["name"]})
                result = deepcopy(self.snapshot_data["payload"]["services"][0])
                result["service"] = service
                self.targeted_results[key] = {"service_key": key, "verification_id": "targeted-" + key[-8:],
                                              "checked_at": datetime.now(timezone.utc).isoformat(),
                                              "fresh": True, "failed_at": None, "result": result}
            elif runtime and self.refresh_mode == "failed":
                self.targeted_results[key] = {"service_key": key, "verification_id": None,
                                              "checked_at": None, "fresh": False,
                                              "failed_at": datetime.now(timezone.utc).isoformat(),
                                              "error": "registry query failed", "result": None}
            return {"status": "checking", "existing": False}
        if operation == "refresh_status":
            key = payload["service_key"]
            record = self.targeted_results.get(key)
            if self.refresh_mode == "checking":
                return {"status": "checking", "record": deepcopy(record)}
            return {"status": "failed" if record and record.get("failed_at") else "idle",
                    "record": deepcopy(record)}
        if operation == "audit_recent":
            return {"events": []}
        if operation == 'compose_bootstrap_review':
            if not self.compose_status_data.get('bootstrap_eligible'):
                raise ValueError('bootstrap unavailable')
            token = 'B' * 43
            self.compose_review_ids[token] = (payload.get('service_key'),payload.get('requested_by'),'bootstrap')
            return {'confirmation_id':token,'review': {'service':'Sonarr','stack':'media','action':'bootstrap',
                    'image_unchanged':True,'service_recreated':True,'automatic_recovery':False,
                    'previous_source_known':False,'proposal':deepcopy(self.compose_status_data.get('bootstrap_proposal',[])),
                    'observations':deepcopy(self.compose_status_data.get('bootstrap_observations',[
                        {'label':'Image','value':'lscr.io/linuxserver/sonarr:4.0'},{'label':'Container state','value':'running'},
                        {'label':'Health','value':'healthy'},{'label':'Restart policy (runtime)','value':'unless-stopped'}]))}}
        if operation == 'compose_bootstrap_start':
            if payload.get('acknowledge_no_rollback') is not True:
                raise ValueError('acknowledgement required')
            key, user, action = self.compose_review_ids.pop(payload.get('confirmation_id'),(None,None,None))
            if action != 'bootstrap' or user != payload.get('requested_by'):
                raise ValueError('invalid review')
            self.compose_apply_calls.append(deepcopy(payload))
            self.operation = {'id':'f'*32,'kind':'compose_bootstrap','service_key':key,'service':'Sonarr','stack':'media',
                              'status':'succeeded','current_stage':'Complete','result': {'action':'bootstrap','trust_established':True},
                              'events':[],'last_event_id':0}
            return {'operation_id':'f'*32,'status':'queued'}
        if operation == "compose_reconcile_review":
            action = payload.get("action")
            if action == "discard" and getattr(self, "discard_review_refusal", None):
                from docker_update_manager.compose_discard import DiscardRefused
                raise DiscardRefused(self.discard_review_refusal)
            if (action not in {"apply", "discard"} or not self.compose_status_data.get("discard_eligible" if action == "discard" else "apply_eligible")
                    or not self.compose_status_data.get("baseline")):
                raise ValueError("configuration Apply unavailable")
            confirmation_id = "C" * 43
            self.compose_review_ids[confirmation_id] = (payload.get("service_key"), payload.get("requested_by"), action)
            return {"confirmation_id": confirmation_id, "review": {
                "service": self.snapshot_data["payload"]["services"][0]["service"]["name"], "stack": "media", "image_unchanged": True,
                "action": action, "service_recreated": action == "apply", "automatic_recovery": True,
                "service_changes": deepcopy(self.compose_status_data.get("service_changes", [])),
                **({"namespace": deepcopy(self.namespace_review)} if getattr(self, "namespace_review", None) else {})}}
        if operation == "compose_reconcile_start":
            self.compose_apply_calls.append(deepcopy(payload))
            service_key, username, action = self.compose_review_ids.pop(payload.get("confirmation_id"), (None, None, None))
            if username != payload.get("requested_by") or not service_key:
                raise ValueError("invalid configuration review")
            self.operation = {"id": "f" * 32, "kind": "compose_reconcile", "service_key": service_key,
                              "service": "Sonarr", "stack": "media", "status": "succeeded", "current_stage": "Complete",
                              "result": {"action": action, "mutation_performed": True,
                                         "current_service_key": "container/" + "c" * 64}, "error": None,
                              "events": [{"id": 1, "kind": "operation_completed", "stage": "Complete",
                                          "message": "Configuration applied", "status": "succeeded", "payload": {}}],
                              "last_event_id": 1}
            return {"operation_id": "f" * 32, "status": "queued"}
        if operation == "update_review":
            if self.compose_status_data.get("update_blocked"):
                raise ComposePreflightRefused(self.compose_status_data["status"], "config_hash_differs")
            confirmation_id = "R" * 43
            self.review_ids[confirmation_id] = (payload.get("service_key"), payload.get("requested_by"), payload.get("verification_id"))
            return {"confirmation_id": confirmation_id}
        if operation == "update_start":
            self.update_calls.append(deepcopy(payload))
            operation_id = "f" * 32
            reviewed_service, reviewed_user, _reviewed_scan_id = self.review_ids.get(payload.get("confirmation_id"), (None, None, None))
            self.operation = {
                "id": operation_id,
                "kind": "update",
                "service_key": reviewed_service,
                "service": "Sonarr",
                "stack": "media",
                "requested_by": reviewed_user,
                "status": "running",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "current_stage": "3/8 Pull image",
                "summary": {"old_version": "4.0.15"},
                "result": None,
                "error": None,
                "events": [
                    {"id": 1, "kind": "task_completed", "stage": "1/8 Revalidate service", "message": "Completed", "status": "completed", "payload": {}},
                    {"id": 2, "kind": "task_completed", "stage": "2/8 Back up Compose", "message": "Completed", "status": "completed", "payload": {}},
                    {"id": 3, "kind": "task_started", "stage": "3/8 Pull image", "message": "In progress", "status": "running", "payload": {}},
                ],
                "last_event_id": 3,
            }
            return {"operation_id": operation_id, "status": "queued", "service": "Sonarr"}
        if operation == "rollback_review":
            if not self.rollback_available:
                return {"_error": "No rollback point in this fixture."}
            confirmation_id = "Q" * 43
            self.rollback_review_ids[confirmation_id] = (
                payload.get("service_key"), payload.get("requested_by"),
            )
            service = self.snapshot_data["payload"]["services"][0]["service"]
            target = {
                "service": service["name"], "stack": service["stack"],
                "current_image": service["image"], "current_version": service.get("version") or "4.0.16",
                "current_digest": service["digest"],
                "target_image": "registry.example/sonarr@sha256:" + "1" * 64
                    if self.rollback_digest_pin else "registry.example/sonarr:4.0.15",
                "target_version": None if self.rollback_digest_pin else "4.0.15",
                "target_digest": "sha256:" + "1" * 64,
                "history_timestamp": "2026-09-25 10:00:00", "digest_pin": self.rollback_digest_pin,
            }
            if self.rollback_digest_pin:
                target["tracking_tag"] = "latest"
            return {"confirmation_id": confirmation_id, "rollback": target}
        if operation == "rollback_start":
            self.rollback_calls.append(deepcopy(payload))
            reviewed_service, reviewed_user = self.rollback_review_ids.get(
                payload.get("confirmation_id"), (None, None),
            )
            operation_id = "c" * 32
            status = self.rollback_terminal_status
            events = [
                {"id": 1, "kind": "task_completed", "stage": "1/8 Revalidate rollback point", "message": "Completed", "status": "completed", "payload": {}},
                {"id": 2, "kind": "task_completed", "stage": "2/8 Protect current configuration and image", "message": "Completed", "status": "completed", "payload": {}},
                {"id": 3, "kind": "task_started", "stage": "3/8 Restore retained Compose configuration", "message": "In progress", "status": "running", "payload": {}},
            ]
            error = None
            result = None
            current_stage = "3/8 Restore retained Compose configuration"
            if status == "succeeded":
                events[2] = {**events[2], "kind": "task_completed", "message": "Completed", "status": "completed"}
                events.extend([
                    {"id": 4, "kind": "task_completed", "stage": "4/8 Validate restored Compose", "message": "Completed", "status": "completed", "payload": {}},
                    {"id": 5, "kind": "task_completed", "stage": "5/8 Verify protected rollback image", "message": "Completed", "status": "completed", "payload": {}},
                    {"id": 6, "kind": "task_completed", "stage": "6/8 Recreate selected service", "message": "Completed", "status": "completed", "payload": {}},
                    {"id": 7, "kind": "task_completed", "stage": "7/8 Verify rollback health", "message": "Completed", "status": "completed", "payload": {}},
                    {"id": 8, "kind": "task_completed", "stage": "8/8 Record rollback outcome", "message": "Completed", "status": "completed", "payload": {}},
                    {"id": 9, "kind": "operation_completed", "stage": "Complete", "message": "Rollback complete", "status": "succeeded", "payload": {}},
                ])
                current_stage = "Complete"
                result = {"image": "registry.example/sonarr:4.0.15", "version": "4.0.15", "digest": "sha256:" + "1" * 64}
            elif status == "failed":
                events[2] = {**events[2], "kind": "task_completed", "message": "Completed", "status": "completed"}
                events.extend([
                    {"id": 4, "kind": "task_completed", "stage": "4/8 Validate restored Compose", "message": "Completed", "status": "completed", "payload": {}},
                    {"id": 5, "kind": "task_completed", "stage": "5/8 Verify protected rollback image", "message": "Completed", "status": "completed", "payload": {}},
                    {"id": 6, "kind": "task_failed", "stage": "6/8 Recreate selected service", "message": "Recovery required", "status": "failed", "payload": {}},
                    {"id": 7, "kind": "operation_failed", "stage": "Manual recovery required", "message": "Automatic recovery was refused or failed; recovery backups and protected images were retained. Manual recovery is required.", "status": "failed", "payload": {}},
                ])
                current_stage = "Manual recovery required"
                error = "Rollback did not complete. Automatic recovery was refused or failed; recovery backups and protected images were retained. Manual recovery is required."
                result = {"manual_recovery_required": True}
            self.operation = {
                "id": operation_id, "kind": "rollback", "service_key": reviewed_service,
                "service": "Sonarr", "stack": "media", "requested_by": reviewed_user,
                "status": status, "created_at": datetime.now(timezone.utc).isoformat(),
                "current_stage": current_stage, "summary": {"target_version": "4.0.15"},
                "result": result, "error": error, "events": events, "last_event_id": events[-1]["id"],
            }
            return {"operation_id": operation_id, "status": "queued", "service": "Sonarr"}
        if operation == "operation_status":
            if not self.operation or payload.get("operation_id") != self.operation["id"]:
                raise RuntimeError("operation not found")
            cursor = int(payload.get("after_event_id", 0))
            self.cursor_values.append(cursor)
            if self.operation.get("kind") == "update" and cursor >= 3 and not self.operation.get("live_event_added"):
                self.operation["events"].append({
                    "id": 4, "kind": "task_progress", "stage": "3/8 Pull image",
                    "message": "Working", "status": "running", "payload": {},
                })
                self.operation["last_event_id"] = 4
                self.operation["live_event_added"] = True
            if cursor >= 4 and self.emit_operation_warning and not self.operation.get("warning_event_added"):
                self.operation["events"].append({
                    "id": 5, "kind": "task_warning", "stage": "3/8 Pull image",
                    "message": "Layer transfer was retried; progress is continuing.", "status": "warning", "payload": {},
                })
                self.operation["last_event_id"] = 5
                self.operation["warning_event_added"] = True
            operation_data = deepcopy(self.operation)
            operation_data["events"] = [event for event in operation_data["events"] if event["id"] > cursor]
            return operation_data
        if operation == "service":
            key = payload.get("service_key")
            for result in self.snapshot_data["payload"]["services"]:
                if result["service"]["key"] == key or result["service"]["name"] == key:
                    return {**deepcopy(result), "_review_scan_id": self.snapshot_data["scan_id"]}
            raise RuntimeError("service not found")
        if operation == "scan_start":
            with self._lock:
                self.scan_start_calls += 1
                if self.scan and self.scan["status"] == "running":
                    return {"run_id": self.scan["id"], "status": "running", "existing": True}
                self.scan = {
                    "id": "browser-scan",
                    "status": "running",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "finished_at": None,
                    "total": 0,
                    "completed": 0,
                    "events": [{
                        "id": 1, "kind": "operation_started",
                        "message": "Read-only scan started", "payload": {},
                    }],
                }
                return {"run_id": self.scan["id"], "status": "running", "existing": False}
        if operation == "scan_status":
            with self._lock:
                if not self.scan:
                    return {"status": "never", "events": []}
                if self.missing_scan and payload.get("run_id"):
                    raise AgentNotFound("scan operation not found")
                run = self.scan
                run_id = payload.get("run_id")
                if run_id and run_id != run["id"]:
                    raise AgentNotFound("scan operation not found")
                if run_id:
                    self.cursor_values.append(int(payload.get("after_event_id", 0)))
                    if self.expire_session_on_stream and self.state and self.session_to_revoke:
                        self.state.revoke_session(self.session_to_revoke)
                        self.expire_session_on_stream = False
                    self._advance_scan()
                cursor = int(payload.get("after_event_id", 0))
                result = deepcopy(run)
                result["events"] = [event for event in run["events"] if event["id"] > cursor]
                return result
        raise AssertionError(operation)

    def _advance_scan(self):
        run = self.scan
        if run["status"] != "running" or self.hold_scan:
            return
        if run["total"] == 0:
            run["total"] = len(self.scan_services)
            run["completed"] = 0
            self._append_event("discovery_completed", message=f"Discovered {run['total']} services",
                               payload={"count": run["total"], "total": run["total"]}, completed=0)
            if self.hold_after_discovery:
                self.hold_scan = True
            return
        completed = run["completed"]
        if completed < run["total"]:
            service = self.scan_services[completed]
            self._append_event("task_started", service=service, message="Checking registry",
                               payload={"index": completed + 1, "total": run["total"]}, completed=completed)
            status = self.scan_status_by_service.get(service, "CURRENT")
            kind = "task_failed" if status == "REGISTRY ERROR" else "task_completed"
            self._append_event(kind, service=service, status=status,
                               message=status,
                               payload={"index": completed + 1, "total": run["total"]},
                               completed=completed + 1)
            run["completed"] += 1
            if self.hold_after_completed is not None and run["completed"] >= self.hold_after_completed:
                self.hold_scan = True
            return
        run["status"] = "complete"
        run["finished_at"] = datetime.now(timezone.utc).isoformat()
        self._append_event("operation_completed", status="complete", message="Scan complete")

    def _append_event(self, kind, *, service=None, status=None, message=None, payload=None, completed=None):
        run = self.scan
        event = {
            "id": run["events"][-1]["id"] + 1,
            "kind": kind,
            "service": service,
            "status": status,
            "message": message,
            "payload": payload or {},
        }
        if completed is not None:
            event["payload"]["completed"] = completed
        run["events"].append(event)


@unittest.skipUnless(sync_playwright, "Install the browser-test extra to run Chromium tests")
class WebBrowserRegressionTests(unittest.TestCase):
    def test_registry_image_without_digest_is_unknown_and_cannot_review_update(self):
        for attr in ("snapshot_data", "runtime_data", "targeted_results"):
            self.addCleanup(setattr, self.agent, attr, deepcopy(getattr(self.agent, attr)))
        service=Service("Prometheus", "e"*64, "docker.io/prom/prometheus", "sha256:"+"1"*64,
                        None, None, None, "amd64", "running", "healthy", "unless-stopped", None,
                        "monitoring", "prometheus", "/synthetic/monitoring", ["/synthetic/monitoring/compose.yml"])
        with patch("docker_update_manager.registry.remote_manifest", return_value={
                "digest": "sha256:"+"2"*64, "platforms": [], "version": None, "created": None}):
            result=_public_result(scan_service(service))
        self.assertEqual(result["status"], "UNKNOWN")
        self.agent.snapshot_data=build_snapshot()
        self.agent.snapshot_data["payload"]={"count": 1, "services": [result]}
        runtime=build_runtime_container(service.container_id, "Prometheus", stack="monitoring", service="prometheus")
        runtime["image"]=service.image
        self.agent.runtime_data=dict(self.agent.runtime_data, status="current", stale=False, containers=[runtime])
        with tempfile.TemporaryDirectory() as temp:
            state=State(Path(temp)/"state")
            state.save_verification(result)
            record=ReadOnlyService(Config(path=str(Path(temp)/"config.yml")), state).verification_snapshot()["records"][0]
        self.agent.targeted_results={result["service"]["key"]: record}
        screenshots=screenshot_dir("local-build-classification")
        for width, height in ((1440, 900), (390, 844)):
            context, page=self.make_page(width, height)
            try:
                for route in ("/", "/services", "/services/"+result["service"]["key"]):
                    page.goto(self.base_url+route, wait_until="networkidle")
                    self.assertNotIn("Local build", page.locator("main").inner_text())
                    self.assertIn("Unknown", page.locator("main").inner_text())
                self.assertIn(result["error"], page.locator("main").inner_text())
                self.assertEqual(page.locator("#update-confirmation").count(), 0)
                self.assertLessEqual(page.evaluate("document.documentElement.scrollWidth"), width)
                page.screenshot(path=str(screenshots/f"prometheus-unverified-{width}x{height}.png"), full_page=True)
            finally:
                context.close()

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="upt-web-browser-")
        root = Path(cls.tmp.name)
        cls.state = State(root / "web-state")
        # Browser geometry/auth tests use a fixture account only; the password
        # hash is never verified and no production credentials are present.
        user_id = cls.state.create_user("review-admin-" + "u" * 56, "browser-fixture-only")
        cls.user_id = user_id
        cls.agent = BrowserFixtureAgent()
        cls.agent.state = cls.state
        config = WebConfig(path=str(root / "web.yml"))
        config.settings["allowed_hosts"] = ["127.0.0.1"]
        cls.app = create_app(config, cls.state, cls.agent)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            cls.port = listener.getsockname()[1]
        cls.base_url = "http://127.0.0.1:" + str(cls.port)
        cls.server = Server(UvicornConfig(cls.app, host="127.0.0.1", port=cls.port, log_level="critical"))
        cls.server_thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.server_thread.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=.2):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("temporary UPT test server did not start")
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(headless=True, args=["--no-sandbox"])

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "browser", None):
            cls.browser.close()
        if getattr(cls, "playwright", None):
            cls.playwright.stop()
        if getattr(cls, "server", None):
            cls.server.should_exit = True
        if getattr(cls, "server_thread", None):
            cls.server_thread.join(timeout=5)
        cls.tmp.cleanup()

    def make_page(self, width, height, color_scheme="light", timezone_id=None):
        session_id = new_token()
        now = datetime.now(timezone.utc)
        self.state.create_session(
            self.user_id, new_token(), (now + timedelta(hours=1)).isoformat(),
            (now + timedelta(hours=12)).isoformat(), "127.0.0.1", "playwright",
            session_id=session_id,
        )
        self.agent.session_to_revoke = session_id
        context = self.browser.new_context(
            viewport={"width": width, "height": height},
            color_scheme=color_scheme,
            **({"timezone_id": timezone_id} if timezone_id else {}),
        )
        context.add_cookies([{
            "name": "upt_session",
            "value": session_id,
            "url": self.base_url,
            "httpOnly": True,
            "sameSite": "Lax",
        }])
        page = context.new_page()
        return context, page

    def seed_current_sonarr_runtime(self):
        previous = deepcopy(self.agent.runtime_data)
        self.addCleanup(setattr, self.agent, "runtime_data", previous)
        sonarr = self.agent.snapshot_data["payload"]["services"][0]["service"]
        container_id = sonarr.get("container_id") or "a" * 64
        captured = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        self.agent.runtime_data = {
            "status": "current", "available": True, "stale": False,
            "captured_at": captured, "last_success_at": captured,
            "attempted_at": captured, "attempt_success": True,
            "failure_category": None,
            "containers": [build_runtime_container(container_id, "Sonarr", service="sonarr", healthcheck="healthy")],
        }

    def test_reference_viewports_have_no_layout_overlap_or_horizontal_overflow(self):
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        for width, height in (
            (1440, 900), (1440, 960), (1280, 800), (1024, 768),
            (932, 430), (768, 1024), (844, 390), (390, 844), (360, 800),
        ):
            with self.subTest(viewport=(width, height)):
                page.set_viewport_size({"width": width, "height": height})
                page.wait_for_timeout(50)
                metrics = page.evaluate("""() => {
                  const rect = selector => {
                    const element = document.querySelector(selector);
                    if (!element) return null;
                    const box = element.getBoundingClientRect();
                    return {x: box.x, y: box.y, right: box.right, bottom: box.bottom,
                            width: box.width, height: box.height};
                  };
                  return {
                    bodyWidth: document.body.scrollWidth,
                    viewportWidth: document.documentElement.clientWidth,
                    sidebar: rect('.app-navbar'),
                    wrapper: rect('.page-wrapper'),
                    content: rect('.app-content'),
                    heading: rect('.app-page-header h1'),
                    cards: [...document.querySelectorAll('.runtime-summary-grid .summary-card')].map(card => {
                      const box = card.getBoundingClientRect();
                      return {x: box.x, y: box.y, right: box.right, bottom: box.bottom};
                    }),
                    freshness: rect('.freshness'),
                    scanAction: rect('.scan-action'),
                    attentionPanel: rect('.attention-panel'),
                    attentionRows: [...document.querySelectorAll('.attention-row')].map(row => ({
                      identity: row.querySelector('.attention-identity')?.innerText || '',
                      status: row.querySelector('.badge')?.innerText || '',
                      ...(() => {
                        const box = row.getBoundingClientRect();
                        return {x: box.x, right: box.right};
                      })(),
                    })),
                  };
                }""")
                self.assertEqual(metrics["bodyWidth"], metrics["viewportWidth"])
                self.assertIsNotNone(metrics["heading"])
                if width >= 992:
                    self.assertLessEqual(metrics["sidebar"]["bottom"], metrics["wrapper"]["y"] + 1)
                    self.assertGreaterEqual(metrics["heading"]["x"], metrics["wrapper"]["x"])
                    self.assertGreaterEqual(metrics["heading"]["y"], 0)
                    self.assertLessEqual(metrics["heading"]["bottom"], height)
                    for section in (metrics["freshness"], metrics["scanAction"]):
                        self.assertGreaterEqual(section["x"], metrics["wrapper"]["x"])
                        self.assertLessEqual(section["right"], metrics["content"]["right"] + 1)
                    self.assertEqual(len(metrics["cards"]), 4)
                    self.assertGreaterEqual(metrics["attentionPanel"]["y"], 0)
                    self.assertGreaterEqual(metrics["attentionPanel"]["x"], metrics["content"]["x"])
                    self.assertLessEqual(metrics["attentionPanel"]["right"], metrics["content"]["right"] + 1)
                    for card in metrics["cards"]:
                        self.assertGreaterEqual(card["x"], metrics["content"]["x"])
                        self.assertLessEqual(card["right"], metrics["content"]["right"] + 1)
                        self.assertGreaterEqual(card["y"], 0)
                        if width >= 1100:
                            self.assertLessEqual(card["bottom"], height)
                    self.assertTrue(metrics["attentionRows"])
                    for row in metrics["attentionRows"]:
                        self.assertGreaterEqual(row["x"], metrics["wrapper"]["x"])
                        self.assertLessEqual(row["right"], metrics["content"]["right"] + 1)
                        self.assertTrue(row["identity"])
                        self.assertTrue(row["status"])

    def test_tablet_overview_keeps_attention_above_side_content(self):
        context, page = self.make_page(1024, 768)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        for width, height in ((1024, 768), (768, 1024)):
            with self.subTest(viewport=(width, height)):
                page.set_viewport_size({"width": width, "height": height})
                layout = page.evaluate("""() => {
                  const grid = document.querySelector('.overview-grid');
                  const attention = grid.querySelector('.attention-panel').getBoundingClientRect();
                  const side = grid.querySelector('.overview-side').getBoundingClientRect();
                  return {areas: getComputedStyle(grid).gridTemplateAreas,
                          attentionBottom: attention.bottom, sideTop: side.top};
                }""")
                self.assertEqual(layout["areas"], '"attention" "side"')
                self.assertLessEqual(layout["attentionBottom"], layout["sideTop"])

    def test_service_check_states_and_affected_viewports(self):
        screenshots = screenshot_dir("scan-decoupling-phase1")
        previous_snapshot = deepcopy(self.agent.snapshot_data)
        previous_runtime = deepcopy(self.agent.runtime_data)
        previous_targeted = deepcopy(self.agent.targeted_results)
        previous_mode = self.agent.refresh_mode
        self.addCleanup(setattr, self.agent, "snapshot_data", previous_snapshot)
        self.addCleanup(setattr, self.agent, "runtime_data", previous_runtime)
        self.addCleanup(setattr, self.agent, "targeted_results", previous_targeted)
        self.addCleanup(setattr, self.agent, "refresh_mode", previous_mode)
        replacement = "e" * 64
        key = "container/" + replacement
        self.agent.snapshot_data = build_snapshot()
        self.agent.snapshot_data["payload"]["services"] = [self.agent.snapshot_data["payload"]["services"][0]]
        self.agent.snapshot_data["payload"]["count"] = 1
        self.agent.runtime_data["containers"] = [build_runtime_container(replacement, "Sonarr", service="sonarr")]
        self.agent.targeted_results = {}
        self.agent.refresh_calls.clear()

        def capture(route, filename, width, height, expected):
            context, page = self.make_page(width, height)
            try:
                page.goto(self.base_url + route, wait_until="domcontentloaded")
                page.get_by_text(expected, exact=False).first.wait_for(timeout=10000)
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)
                page.screenshot(path=str(screenshots / filename), full_page=True)
            finally:
                context.close()

        # The page is immediately useful while a single service registry check
        # runs. A prior result remains labelled last known during that check.
        self.agent.refresh_mode = "success"
        self.agent.call("refresh_start", {"service_key": key})
        stale = deepcopy(self.agent.targeted_results[key])
        stale["fresh"] = False
        stale["checked_at"] = (datetime.now(timezone.utc) - timedelta(hours=7)).isoformat()
        self.agent.targeted_results = {key: stale}
        self.agent.refresh_mode = "checking"
        for width, height, suffix in ((1440, 900, "desktop-1440x900"), (390, 844, "mobile-390x844")):
            capture("/services/" + key, "service-checking-" + suffix + ".png", width, height,
                    "Checking update information")

        self.agent.targeted_results = {}
        self.agent.refresh_mode = "failed"
        for width, height, suffix in ((1440, 900, "desktop-1440x900"), (390, 844, "mobile-390x844")):
            capture("/services/" + key, "service-failed-" + suffix + ".png", width, height,
                    "Last check failed")

        self.agent.targeted_results = {}
        self.agent.refresh_mode = "success"
        for width, height, suffix in ((1440, 900, "desktop-1440x900"), (390, 844, "mobile-390x844")):
            capture("/services/" + key, "service-verified-" + suffix + ".png", width, height,
                    "Review update")
            capture("/updates", "updates-" + suffix + ".png", width, height,
                    "Available updates")
            capture("/", "overview-" + suffix + ".png", width, height,
                    "Needs attention")
        self.assertIn(key, self.agent.refresh_calls)

    def test_scan_progress_projects_one_row_per_service_live_reload_and_replay(self):
        screenshots = screenshot_dir("scan-progress-and-service-refresh-ui")
        saved = (self.agent.scan, self.agent.hold_scan)
        self.addCleanup(setattr, self.agent, "scan", saved[0])
        self.addCleanup(setattr, self.agent, "hold_scan", saved[1])
        services = [("alpha", "CURRENT"), ("bravo", "PINNED"), ("charlie", "CURRENT"), ("delta", "UPDATE"),
                    ("echo", "REGISTRY ERROR"), ("redis", "CURRENT"), ("redis", "PINNED"),
                    ("a-very-long-compose-service-name-for-" + "x" * 40, None)]
        total = len(services) + 1
        head = [
            {"id": 1, "kind": "operation_started", "message": "Read-only scan started", "payload": {}},
            {"id": 2, "kind": "discovery_started", "message": "Discovering running services", "payload": {}},
            {"id": 3, "kind": "discovery_completed", "message": f"Discovered {total} services",
             "payload": {"count": total, "total": total, "completed": 0}},
        ]
        body, event_id, completed = [], 3, 0
        for index, (name, status) in enumerate(services, 1):
            event_id += 1
            body.append({"id": event_id, "kind": "task_started", "service": name, "message": "Checking registry",
                         "payload": {"index": index, "total": total, "completed": completed}})
            if status is None:
                continue
            event_id += 1
            completed += 1
            failed = status == "REGISTRY ERROR"
            body.append({"id": event_id, "kind": "task_failed" if failed else "task_completed", "service": name,
                         "status": status, "message": "registry request timed out" if failed else status,
                         "payload": {"index": index, "total": total, "completed": completed}})
        self.agent.hold_scan = True
        self.agent.scan = {"id": "projection-scan", "status": "running",
                           "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None,
                           "total": total, "completed": 0, "events": deepcopy(head)}
        rows_js = """() => [...document.querySelectorAll('[data-scan-events] li')].map(li =>
          [li.dataset.rowKey, li.dataset.state, li.querySelector('.scan-service-name').textContent,
           li.querySelector('.scan-service-state').textContent, li.title])"""

        live_context, live = self.make_page(1440, 900)
        self.addCleanup(live_context.close)
        live.add_init_script("""(() => { window.__uptScanStreams = []; const Native = window.EventSource;
          window.EventSource = class extends Native { constructor(...args) { super(...args); window.__uptScanStreams.push(this); } };
        })();""")
        live.goto(self.base_url + "/", wait_until="domcontentloaded")
        self.assertEqual(live.locator("[data-scan-events] li").count(), 0, "global events never become rows")
        self.agent.scan["events"].extend(deepcopy(body))
        self.agent.scan["completed"] = completed
        live.wait_for_function("() => document.querySelector('[data-scan-events] li[data-state=active]')", timeout=8000)
        live.wait_for_function(f"() => document.querySelector('[data-scan-progress]').dataset.cursor === '{event_id}'", timeout=8000)
        live_rows = live.evaluate(rows_js)
        live_stage = live.locator("[data-scan-stage]").inner_text()

        # One active service plus the four most recently finished services.
        self.assertEqual([row[1] for row in live_rows], ["active", "complete", "complete", "failed", "complete"])
        self.assertEqual([row[2] for row in live_rows][1:], ["redis", "redis", "echo", "delta"])
        self.assertEqual(len({row[0] for row in live_rows}), len(live_rows), "service keys stay unique")
        self.assertEqual(live_rows[3][3], "Registry error")
        self.assertEqual(live_rows[3][4], "registry request timed out")
        self.assertTrue(live_rows[0][2].startswith("a-very-long-compose-service-name"))
        self.assertNotIn("Scan", [row[2] for row in live_rows])
        self.assertFalse(any("Discover" in row[3] or "Discover" in row[2] for row in live_rows))
        self.assertIn("Checking a-very-long-compose-service-name", live_stage)
        self.assertEqual(live.locator("[data-scan-count]").inner_text().strip(), f"{completed} / {total}")

        # Replayed events and a transient disconnect neither duplicate nor regress rows.
        for replay in (body[0], body[1], body[-2], body[-1]):
            live.evaluate("event => window.__uptScanStreams.at(-1).dispatchEvent(new MessageEvent('scan-event', {data: JSON.stringify(event)}))", replay)
        live.evaluate("() => window.__uptScanStreams.at(-1).dispatchEvent(new Event('error'))")
        live.wait_for_timeout(100)
        self.assertEqual(live.evaluate(rows_js), live_rows)
        self.assertIn("Connection interrupted", live.locator("[data-scan-connection]").inner_text())

        # Reloading the same history renders the same projected rows and stage.
        for width, height, dark, filename in ((1440, 900, False, "scan-active-desktop-1440x900.png"),
                                              (390, 844, False, "scan-active-mobile-390x844.png"),
                                              (390, 844, True, "scan-active-mobile-dark-390x844.png")):
            context, page = self.make_page(width, height, color_scheme="dark" if dark else "light")
            try:
                page.goto(self.base_url + "/", wait_until="domcontentloaded")
                self.assertEqual(page.evaluate(rows_js), live_rows)
                self.assertEqual(page.locator("[data-scan-stage]").inner_text(), live_stage)
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)
                panel = page.locator("[data-scan-progress]").bounding_box()
                self.assertLess(panel["height"], 330, "the progress panel stays compact")
                name_box = page.locator("[data-scan-events] li").first.locator(".scan-service-name").bounding_box()
                self.assertLessEqual(name_box["x"] + name_box["width"], width)
                page.screenshot(path=str(screenshots / filename), full_page=False)
            finally:
                context.close()

    def test_service_detail_refresh_control_matches_verification_state(self):
        screenshots = screenshot_dir("scan-progress-and-service-refresh-ui")
        saved = (deepcopy(self.agent.snapshot_data), deepcopy(self.agent.runtime_data),
                 deepcopy(self.agent.targeted_results), self.agent.refresh_mode)
        self.addCleanup(setattr, self.agent, "snapshot_data", saved[0])
        self.addCleanup(setattr, self.agent, "runtime_data", saved[1])
        self.addCleanup(setattr, self.agent, "targeted_results", saved[2])
        self.addCleanup(setattr, self.agent, "refresh_mode", saved[3])
        replacement = "e" * 64
        key = "container/" + replacement
        self.agent.snapshot_data = build_snapshot()
        self.agent.snapshot_data["payload"]["services"] = [self.agent.snapshot_data["payload"]["services"][0]]
        self.agent.snapshot_data["payload"]["count"] = 1
        self.agent.runtime_data["containers"] = [build_runtime_container(replacement, "Sonarr", service="sonarr")]

        def open_page(width, height, dark=False):
            context, page = self.make_page(width, height, color_scheme="dark" if dark else "light")
            self.addCleanup(context.close)
            page.goto(self.base_url + "/services/" + key, wait_until="domcontentloaded")
            return page

        def no_overflow(page, width):
            self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)

        # Fresh: the Verified fact carries a compact inline action; no alert.
        self.agent.refresh_mode = "success"
        self.agent.targeted_results = {}
        self.agent.call("refresh_start", {"service_key": key})
        self.agent.refresh_mode = "checking"
        for width, height, dark, filename in ((1440, 900, False, "service-fresh-desktop-1440x900.png"),
                                              (390, 844, False, "service-fresh-mobile-390x844.png"),
                                              (390, 844, True, "service-fresh-mobile-dark-390x844.png")):
            page = open_page(width, height, dark)
            line = page.locator(".verification-line")
            self.assertIn("Verified", line.inner_text())
            self.assertEqual(page.locator(".alert-info").count(), 0)
            self.assertNotIn("verified for this service", page.locator("body").inner_text())
            self.assertEqual(page.locator(".refresh-notice").count(), 0)
            action = line.get_by_role("button", name="Check update information again for this service")
            self.assertEqual(action.inner_text(), "Check again")
            self.assertLess(action.bounding_box()["height"], 30)
            no_overflow(page, width)
            page.screenshot(path=str(screenshots / filename), full_page=True)

        # Explicit Check again: one targeted refresh, never a full scan.
        page = open_page(390, 844)
        calls, scans = len(self.agent.refresh_calls), self.agent.scan_start_calls
        page.get_by_role("button", name="Check update information again for this service").click()
        page.locator(".verification-line [data-refresh-status]").get_by_text("Checking update information…").wait_for(timeout=5000)
        self.assertTrue(page.locator(".verification-line [data-refresh-action]").is_hidden())
        self.assertEqual(page.locator(".verification-line .refresh-spinner").count(), 1)
        self.assertIn("Verified", page.locator(".verification-line").inner_text())
        self.assertEqual(self.agent.refresh_calls[calls:], [key])
        self.assertEqual(self.agent.scan_start_calls, scans)

        # Missing/stale: concise status, one Check now action, auto check runs.
        self.agent.targeted_results = {}
        page = open_page(390, 844)
        notice = page.locator(".refresh-notice.is-warning")
        self.assertIn("Update information needs checking.", notice.inner_text())
        notice.get_by_text("Checking update information…").wait_for(timeout=5000)
        self.assertTrue(notice.get_by_role("button", name="Check now").is_hidden())
        no_overflow(page, 390)
        page.screenshot(path=str(screenshots / "service-stale-checking-mobile-390x844.png"), full_page=True)
        self.agent.refresh_mode = "scan_active"
        page = open_page(390, 844)
        page.locator(".refresh-notice").get_by_text("An inventory scan is running").wait_for(timeout=5000)
        self.assertTrue(page.locator(".refresh-notice").get_by_role("button", name="Check now").is_visible())

        # Failed: last-known facts are called out and Retry is offered.
        self.agent.refresh_mode = "failed"
        self.agent.targeted_results = {}
        self.agent.call("refresh_start", {"service_key": key})
        page = open_page(390, 844)
        notice = page.locator(".refresh-notice.is-danger")
        self.assertIn("Last check failed: registry query failed.", notice.inner_text())
        self.assertEqual(page.locator(".service-summary .alert").count(), 0, "one failure notice, not two")
        self.assertEqual(notice.get_by_role("button", name="Retry").count(), 1)
        self.assertEqual(page.locator("#update-confirmation").count(), 0)
        no_overflow(page, 390)
        page.screenshot(path=str(screenshots / "service-failed-mobile-390x844.png"), full_page=True)

    def test_phase4_runtime_health_screenshots(self):
        screenshots = screenshot_dir("web-phase-4-runtime-health")
        screenshots.mkdir(parents=True, exist_ok=True)
        previous_scan = deepcopy(self.agent.snapshot_data)
        previous_runtime = deepcopy(self.agent.runtime_data)
        self.addCleanup(setattr, self.agent, "snapshot_data", previous_scan)
        self.addCleanup(setattr, self.agent, "runtime_data", previous_runtime)

        def set_scan():
            self.agent.snapshot_data = build_snapshot()
            self.agent.snapshot_data["started_at"] = "2026-09-27T13:50:00+00:00"
            self.agent.snapshot_data["finished_at"] = "2026-09-27T14:00:00+00:00"
            ids = {"Sonarr": "a" * 64, "Radarr": "b" * 64, "Grafana": "d" * 64}
            services = []
            for item in self.agent.snapshot_data["payload"]["services"]:
                service = item.get("service") or {}
                container_id = ids.get(service.get("name"))
                if not container_id:
                    continue
                service["container_id"] = container_id
                service["key"] = "container/" + container_id
                services.append(item)
            self.agent.snapshot_data["payload"] = {"count": len(services), "services": services}

        def set_runtime(containers, status="current", failure_category=None, successful_sample=True):
            captured_at = "2026-09-27T14:59:30+00:00" if successful_sample else None
            self.agent.runtime_data = {
                "status": status,
                "available": status == "current",
                "stale": status != "current",
                "captured_at": captured_at,
                "last_success_at": captured_at,
                "attempted_at": "2026-09-27T15:00:00+00:00" if status == "unavailable" else captured_at,
                "attempt_success": status == "current",
                "failure_category": (failure_category or "docker_unavailable") if status == "unavailable" else None,
                "containers": deepcopy(containers),
            }

        def capture(route, name, width, height):
            context, page = self.make_page(width, height, color_scheme="light", timezone_id="UTC")
            page.add_init_script("Date.now = () => Date.parse('2026-09-27T15:00:00Z');")
            try:
                page.goto(self.base_url + route, wait_until="networkidle")
                page.wait_for_timeout(50)
                self.assertEqual(page.evaluate("document.body.scrollWidth"), page.evaluate("document.documentElement.clientWidth"))
                if route == "/":
                    summary = page.evaluate("""() => {
                      const runtime = document.querySelector('.runtime-summary-grid');
                      const maintenance = document.querySelector('.maintenance-summary-grid');
                      const last = maintenance?.lastElementChild?.getBoundingClientRect();
                      const box = maintenance?.getBoundingClientRect();
                      const detail = document.querySelector('.runtime-summary-detail');
                      return {
                        runtimeSummaryPresent: !!runtime,
                        runtimeColumns: runtime ? getComputedStyle(runtime).gridTemplateColumns.split(' ').length : 0,
                        maintenanceColumns: maintenance ? getComputedStyle(maintenance).gridTemplateColumns.split(' ').length : 0,
                        maintenanceCards: maintenance?.children.length || 0,
                        thirdCardWidth: last?.width || 0,
                        maintenanceWidth: box?.width || 0,
                        summaryChildren: detail?.children.length || 0,
                        summaryText: detail?.innerText || '',
                        availabilityDirection: getComputedStyle(document.querySelector('.runtime-unavailable-copy') || document.body).flexDirection,
                        freshnessTimeInsideSentence: !!document.querySelector('.runtime-unavailable-copy span time')
                      };
                    }""")
                    columns = 2
                    if "empty-current" in name:
                        self.assertFalse(summary["runtimeSummaryPresent"])
                        self.assertEqual(summary["runtimeColumns"], 0)
                    elif self.agent.runtime_data.get("captured_at") or self.agent.runtime_data.get("containers"):
                        self.assertTrue(summary["runtimeSummaryPresent"])
                        self.assertEqual(summary["runtimeColumns"], columns)
                    else:
                        self.assertFalse(summary["runtimeSummaryPresent"])
                        self.assertEqual(summary["runtimeColumns"], 0)
                    maintenance_columns = 3
                    self.assertEqual(summary["maintenanceColumns"], maintenance_columns)
                    self.assertEqual(summary["maintenanceCards"], 3)
                    if any(item.get("healthcheck") == "starting" for item in self.agent.runtime_data.get("containers", [])):
                        self.assertIn("healthcheck starting", summary["summaryText"])
                    if width <= 767:
                        if page.locator(".runtime-unavailable-copy").count():
                            self.assertEqual(summary["availabilityDirection"], "column")
                            self.assertEqual(summary["freshnessTimeInsideSentence"],
                                             bool(self.agent.runtime_data.get("last_success_at")))
                    if "no-success" in name:
                        runtime_text = page.locator(".runtime-health-section").inner_text()
                        self.assertIn("Runtime information is not available yet.", runtime_text)
                        self.assertIn("UPT has not completed a successful Docker runtime check.", runtime_text)
                        self.assertNotIn("No containers were found", runtime_text)
                        self.assertFalse(summary["runtimeSummaryPresent"])
                        self.assertTrue(page.locator(".maintenance-summary-grid").is_visible())
                    if "empty-current" in name:
                        runtime_text = page.locator(".runtime-health-section").inner_text()
                        self.assertIn("No containers were found in the latest runtime snapshot.", runtime_text)
                        self.assertNotIn("Runtime information is not available yet", runtime_text)
                    if "inventory-changed" in name:
                        self.assertIn("Docker inventory changed during the runtime check",
                                      page.locator("[data-runtime-freshness]").inner_text())
                        warning_copy = page.locator(".runtime-unavailable").inner_text()
                        self.assertIn("Docker inventory changed during the runtime check", warning_copy)
                        self.assertIn("last known as of", warning_copy)
                if route.startswith("/services/container/"):
                    facts = page.evaluate("""() => {
                      const grid = document.querySelector('.runtime-facts');
                      const labels = [...(grid?.querySelectorAll('dt') || [])];
                      const health = labels.find(label => label.innerText.trim() === 'Docker healthcheck');
                      return {
                        columns: grid ? getComputedStyle(grid).gridTemplateColumns.split(' ').length : 0,
                        health: health?.nextElementSibling?.innerText.trim() || '',
                        state: labels.find(label => label.innerText.trim() === 'Container state')?.nextElementSibling?.innerText.trim() || ''
                      };
                    }""")
                    # Label/value list; phones stack each label above its value.
                    self.assertEqual(facts["columns"], 1 if width < 480 else 2)
                    self.assertEqual(page.locator(".runtime-fact dt").count(), page.locator(".runtime-fact dd").count())
                    if "no-healthcheck" in name:
                        self.assertEqual(facts["state"], "Running")
                        self.assertEqual(facts["health"], "No healthcheck")
                    if "exited-oom" in name and width <= 767:
                        self.assertEqual(page.locator(".runtime-oom").evaluate("element => getComputedStyle(element).display"), "block")
                    if "rescan-required" in name:
                        self.assertIn("Check required", page.locator("body").inner_text())
                        self.assertNotIn("Rescan required", page.locator("body").inner_text())
                        self.assertIn("This container changed since the last inventory scan", page.locator("body").inner_text())
                        self.assertNotIn("Review update", page.locator("body").inner_text())
                        self.assertNotIn("Review rollback", page.locator("body").inner_text())
                page.screenshot(path=str(screenshots / name), full_page=True)
            finally:
                context.close()

        set_scan()
        all_running = [
            build_runtime_container("a" * 64, "Sonarr", service="sonarr", healthcheck="healthy"),
            build_runtime_container("b" * 64, "Radarr", service="radarr", healthcheck="none"),
            build_runtime_container("d" * 64, "Grafana", stack="monitoring", service="grafana", healthcheck="healthy"),
            build_runtime_container("f" * 64, "Recyclarr", service="recyclarr", healthcheck="starting"),
        ]
        set_runtime(all_running)
        capture("/", "overview-all-running-desktop-1440x900.png", 1440, 900)
        capture("/", "overview-all-running-mobile-390x844.png", 390, 844)

        attention = [
            build_runtime_container("a" * 64, "Sonarr", service="sonarr", healthcheck="unhealthy", restart_count=2),
            build_runtime_container("e" * 64, "Recyclarr", service="recyclarr", state="restarting", healthcheck="none", restart_count=5),
            build_runtime_container("c" * 64, "Worker", service="worker", state="exited", healthcheck="none", exit_code=137, oom_killed=True, restart_count=4),
            build_runtime_container("b" * 64, "Radarr", service="radarr", healthcheck="healthy"),
            build_runtime_container("d" * 64, "Grafana", stack="monitoring", service="grafana", healthcheck="healthy"),
        ]
        set_runtime(attention)
        capture("/", "overview-runtime-attention-desktop-1440x900.png", 1440, 900)
        capture("/", "overview-runtime-attention-mobile-390x844.png", 390, 844)
        capture("/services", "services-runtime-maintenance-desktop-1440x900.png", 1440, 900)
        capture("/services", "services-runtime-maintenance-mobile-390x844.png", 390, 844)

        unavailable = deepcopy(attention)
        set_runtime(unavailable, status="unavailable")
        capture("/", "overview-docker-unavailable-desktop-1440x900.png", 1440, 900)
        capture("/", "overview-docker-unavailable-mobile-390x844.png", 390, 844)
        set_runtime(unavailable, status="unavailable", failure_category="inventory_changed")
        capture("/", "overview-inventory-changed-mobile-390x844.png", 390, 844)

        set_runtime([], status="unavailable", failure_category="probe_failed", successful_sample=False)
        capture("/", "overview-runtime-no-success-desktop-1440x900.png", 1440, 900)
        capture("/", "overview-runtime-no-success-mobile-390x844.png", 390, 844)

        set_runtime([], status="current")
        capture("/", "overview-runtime-empty-current-desktop-1440x900.png", 1440, 900)
        capture("/", "overview-runtime-empty-current-mobile-390x844.png", 390, 844)

        set_runtime([build_runtime_container("a" * 64, "Sonarr", service="sonarr", healthcheck="none")])
        capture("/services/container/" + "a" * 64, "service-detail-no-healthcheck-desktop-1440x900.png", 1440, 900)
        capture("/services/container/" + "a" * 64, "service-detail-no-healthcheck-mobile-390x844.png", 390, 844)

        set_runtime([build_runtime_container("a" * 64, "Sonarr", service="sonarr", healthcheck="unhealthy", restart_count=2)])
        capture("/services/container/" + "a" * 64, "service-detail-unhealthy-update-desktop-1440x900.png", 1440, 900)
        capture("/services/container/" + "a" * 64, "service-detail-unhealthy-update-mobile-390x844.png", 390, 844)

        set_runtime([build_runtime_container("c" * 64, "Worker", service="worker", state="exited", healthcheck="none", exit_code=137, oom_killed=True, restart_count=4)])
        capture("/services/container/" + "c" * 64, "service-detail-exited-oom-desktop-1440x900.png", 1440, 900)
        capture("/services/container/" + "c" * 64, "service-detail-exited-oom-mobile-390x844.png", 390, 844)

        replacement_id = "e" * 64
        set_runtime([build_runtime_container(replacement_id, "Sonarr", service="sonarr", healthcheck="unhealthy", restart_count=2)])
        capture("/services/container/" + replacement_id, "service-detail-rescan-required-desktop-1440x900.png", 1440, 900)
        capture("/services/container/" + replacement_id, "service-detail-rescan-required-mobile-390x844.png", 390, 844)

    def test_authenticated_page_geometry_is_consistent_across_viewports(self):
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        pages = (
            ("overview", "/"),
            ("services", "/services"),
            ("detail", "/services/media%2Fsonarr"),
            ("history", "/history"),
            ("settings", "/settings"),
        )
        viewports = (
            (1440, 900), (1440, 960), (1280, 800), (1024, 768),
            (932, 430), (844, 390), (768, 1024), (390, 844), (360, 800),
        )
        for page_name, path in pages:
            response = page.goto(self.base_url + path, wait_until="networkidle")
            self.assertEqual(response.status, 200, page_name)
            for width, height in viewports:
                with self.subTest(page=page_name, viewport=(width, height)):
                    page.set_viewport_size({"width": width, "height": height})
                    geometry = page.evaluate("""() => {
                      const rect = element => {
                        if (!element || !element.getClientRects().length) return null;
                        const box = element.getBoundingClientRect();
                        return {x: box.x, y: box.y, right: box.right,
                                bottom: box.bottom, width: box.width, height: box.height};
                      };
                      const visible = element => element.getClientRects().length > 0
                        && getComputedStyle(element).visibility !== "hidden"
                        && element.checkVisibility();
                      const overlapPairs = [];
                      const checkPairs = (leftSelector, rightSelector, label) => {
                        const left = [...document.querySelectorAll(leftSelector)].filter(visible);
                        const right = [...document.querySelectorAll(rightSelector)].filter(visible);
                        for (const a of left) for (const b of right) {
                          if (a === b || a.contains(b) || b.contains(a)) continue;
                          const x = a.getBoundingClientRect();
                          const y = b.getBoundingClientRect();
                          if (x.left < y.right - 1 && x.right > y.left + 1
                              && x.top < y.bottom - 1 && x.bottom > y.top + 1) {
                            overlapPairs.push(label);
                          }
                        }
                      };
                      checkPairs(".attention-panel .card-title", ".attention-panel .card-header .btn", "attention header");
                      checkPairs(".attention-identity", ".attention-row .badge", "attention row");
                      checkPairs(".service-summary-heading > div", ".service-summary-heading .badge", "service heading");
                      checkPairs(".service-card-name", ".service-card-heading .badge", "service card");
                      checkPairs(".app-brand", ".account-menu", "navbar brand/account");
                      checkPairs(".service-filters label", ".service-filters > .btn", "service filter");
                      const controls = [...document.querySelectorAll(
                        "a[href], button, input:not([type=hidden]), select, textarea, [role=button]"
                      )].filter(visible);
                      for (let index = 0; index < controls.length; index++) {
                        for (let other = index + 1; other < controls.length; other++) {
                          const a = controls[index];
                          const b = controls[other];
                          if (a.contains(b) || b.contains(a)) continue;
                          // The fixed mobile destination bar may cover content at
                          // the viewport edge while the page remains scrollable.
                          if (Boolean(a.closest('.mobile-destinations')) !== Boolean(b.closest('.mobile-destinations'))) continue;
                          const x = a.getBoundingClientRect();
                          const y = b.getBoundingClientRect();
                          if (x.left < y.right - 1 && x.right > y.left + 1
                              && x.top < y.bottom - 1 && x.bottom > y.top + 1) {
                            overlapPairs.push("interactive controls");
                          }
                        }
                      }
                      const content = document.querySelector(".app-content");
                      const children = content ? [...content.children].filter(visible).map(rect) : [];
                      const childGaps = children.slice(1).map((child, index) => child.y - children[index].bottom);
                      const filters = document.querySelector(innerWidth < 768
                        ? ".service-filters-mobile" : ".service-filters-desktop");
                      const filterItems = filters
                        ? [...filters.children].filter(visible).map(rect) : [];
                      const filtersRemainOrdered = filterItems.every((item, index) => {
                        const previous = filterItems[index - 1];
                        return !previous || item.y > previous.y + 1
                          || (Math.abs(item.y - previous.y) <= 1 && item.x >= previous.x - 1);
                      });
                      const container = element => {
                        const style = getComputedStyle(element);
                        const box = element.getBoundingClientRect();
                        return {x: box.x + parseFloat(style.paddingLeft),
                                right: box.right - parseFloat(style.paddingRight),
                                width: box.width};
                      };
                      const headerContainer = document.querySelector(".app-topbar");
                      const contentContainer = document.querySelector(".app-content");
                      const headerRect = rect(document.querySelector(".app-page-header"));
                      const mainRect = rect(document.querySelector("#main"));
                      const sidebar = rect(document.querySelector(".app-navbar"));
                      const wrapper = rect(document.querySelector(".page-wrapper"));
                      const display = selector => {
                        const element = document.querySelector(selector);
                        return element ? getComputedStyle(element).display : "absent";
                      };
                      const intersects = (a, b) => a && b && a.x < b.right && a.right > b.x
                        && a.y < b.bottom && a.bottom > b.y;
                      const summary = document.querySelector(".summary-grid");
                      return {
                        documentWidth: document.documentElement.scrollWidth,
                        viewportWidth: document.documentElement.clientWidth,
                        sidebar, wrapper, header: headerRect, main: mainRect,
                        topbar: container(headerContainer), contentBox: container(contentContainer),
                        heading: rect(document.querySelector(".app-page-header h1")),
                        content: rect(contentContainer),
                        contentStartGap: content ? content.getBoundingClientRect().top - headerRect.bottom : null,
                        rowGap: parseFloat(getComputedStyle(content).rowGap), childGaps,
                        childBoxes: children,
                        filtersRemainOrdered, filterItems,
                        sidebarHeaderOverlap: intersects(sidebar, headerRect),
                        sidebarMainOverlap: intersects(sidebar, mainRect),
                        overlapPairs,
                        serviceTable: display(".service-table-wrap"),
                        serviceCards: display(".service-card-list"),
                        summaryColumns: summary ? getComputedStyle(summary).gridTemplateColumns.split(" ").length : 0,
                        summaryHeights: [...document.querySelectorAll(".runtime-summary-grid .summary-card")].map(node => rect(node)?.height),
                        settingsColumns: document.querySelector(".settings-grid")
                          ? getComputedStyle(document.querySelector(".settings-grid")).gridTemplateColumns.split(" ").length : 0,
                      };
                    }""")
                    self.assertEqual(geometry["documentWidth"], geometry["viewportWidth"])
                    self.assertIsNotNone(geometry["heading"])
                    self.assertFalse(geometry["sidebarHeaderOverlap"], geometry)
                    self.assertFalse(geometry["sidebarMainOverlap"], geometry)
                    self.assertFalse(geometry["overlapPairs"], geometry["overlapPairs"])
                    self.assertLessEqual(abs(geometry["topbar"]["x"] - geometry["contentBox"]["x"]), 1)
                    self.assertLessEqual(abs(geometry["topbar"]["right"] - geometry["contentBox"]["right"]), 1)
                    self.assertLessEqual(geometry["header"]["bottom"], geometry["main"]["y"] + 1)
                    self.assertGreaterEqual(geometry["contentStartGap"], 0)
                    self.assertLessEqual(geometry["contentStartGap"], 64)
                    self.assertGreaterEqual(geometry["heading"]["x"], geometry["topbar"]["x"] - 1)
                    self.assertLessEqual(geometry["heading"]["right"], geometry["topbar"]["right"] + 1)
                    self.assertGreaterEqual(geometry["rowGap"], 8)
                    self.assertLessEqual(geometry["rowGap"], 24)
                    for gap in geometry["childGaps"]:
                        self.assertGreaterEqual(gap, -1, geometry["childGaps"])
                        self.assertLessEqual(gap, 28, geometry["childGaps"])
                    for child in geometry["childBoxes"]:
                        self.assertGreaterEqual(child["x"], geometry["content"]["x"] - 1)
                        self.assertLessEqual(child["right"], geometry["content"]["right"] + 1)
                    self.assertLessEqual(geometry["sidebar"]["bottom"], geometry["wrapper"]["y"] + 1)
                    if page_name == "overview":
                        self.assertEqual(geometry["summaryColumns"], 2)
                        self.assertLessEqual(max(geometry["summaryHeights"]) - min(geometry["summaryHeights"]), 1)
                    if page_name == "services":
                        self.assertTrue(geometry["filtersRemainOrdered"])
                        for control in geometry["filterItems"]:
                            self.assertGreaterEqual(control["x"], geometry["content"]["x"] - 1)
                            self.assertLessEqual(control["right"], geometry["content"]["right"] + 1)
                        # The table remains the tablet representation; phones get cards.
                        if width >= 768:
                            self.assertNotEqual(geometry["serviceTable"], "none")
                            self.assertEqual(geometry["serviceCards"], "none")
                        else:
                            self.assertEqual(geometry["serviceTable"], "none")
                            self.assertEqual(geometry["serviceCards"], "grid")
                    if page_name == "settings":
                        self.assertEqual(geometry["settingsColumns"], 2 if width >= 768 else 1)

    def test_shell_header_adjacency_and_history_empty_body(self):
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        pages = ("/", "/services", "/services/media%2Fsonarr", "/history", "/settings")
        for width, height in ((1440, 900), (390, 844)):
            page.set_viewport_size({"width": width, "height": height})
            for path in pages:
                with self.subTest(viewport=(width, height), path=path):
                    if path == "/history":
                        with patch.object(self.state, "audit_events", return_value=[]):
                            page.goto(self.base_url + path, wait_until="domcontentloaded")
                    else:
                        page.goto(self.base_url + path, wait_until="domcontentloaded")
                    gap = page.evaluate("""() => {
                      const header = document.querySelector('.app-page-header').getBoundingClientRect();
                      const shell = document.querySelector('.page-wrapper').getBoundingClientRect();
                      return header.top - shell.top;
                    }""")
                    self.assertGreaterEqual(gap, -1)
                    self.assertLessEqual(gap, 1, (path, width, gap))
                    if path == "/history":
                        body = page.locator(".history-panel .card-body.app-state-panel")
                        self.assertEqual(body.count(), 1)
                        layout = body.evaluate("""e => {
                          const style = getComputedStyle(e);
                          return {height: e.getBoundingClientRect().height,
                                  top: parseFloat(style.paddingTop),
                                  bottom: parseFloat(style.paddingBottom)};
                        }""")
                        self.assertGreaterEqual(layout["height"], 80)
                        self.assertGreaterEqual(layout["top"], 12)
                        self.assertGreaterEqual(layout["bottom"], 12)

    def test_phase_one_page_headers_status_vocabulary_and_hierarchy(self):
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        for path, expected_title in (
            ("/", "Overview"), ("/services", "Services"),
            ("/services/media%2Fsonarr", "Sonarr"), ("/history", "History"),
            ("/settings", "Settings"),
        ):
            with self.subTest(path=path):
                page.goto(self.base_url + path, wait_until="domcontentloaded")
                self.assertEqual(page.locator(".app-page-header h1").count(), 1)
                self.assertEqual(page.locator(".app-page-header h1").inner_text(), expected_title)
                self.assertEqual(page.locator(".app-page-header .page-pretitle").count(), 0)
                self.assertTrue(page.locator(".app-page-header-layout").is_visible())
                self.assertNotIn("Phase 1", page.locator("body").inner_text())

        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        self.assertIn("Inventory scanned", page.locator(".page-header-text").inner_text())
        self.assertTrue(page.locator(".app-page-header-actions [data-scan-form]").is_visible())
        self.assertIn("Updates available", page.locator(".maintenance-summary-grid .summary-card").nth(1).inner_text())
        self.assertTrue(page.locator("#attention-title").inner_text().startswith("Needs attention"))
        self.assertEqual(page.locator("#attention-title .badge").inner_text(), "9")

        page.goto(self.base_url + "/services", wait_until="domcontentloaded")
        sonarr = page.locator(".service-table tbody tr").filter(has_text="Sonarr")
        self.assertIn("Update available", sonarr.inner_text())
        self.assertNotIn("UPDATE", sonarr.inner_text())
        radarr = page.locator(".service-table tbody tr").filter(has_text="Radarr")
        self.assertIn("Up to date", radarr.inner_text())
        self.assertEqual(page.locator('.service-filters-desktop [name="status"] option[value="UPDATE"]').inner_text(), "Update available")
        digest = page.locator(".service-table tbody tr").filter(has_text="Digest-pinned service")
        self.assertIn("Tracking unavailable", digest.inner_text())
        self.assertEqual(page.locator(".service-table thead th").count(), 4)
        self.assertIn("registry.example/sonarr", sonarr.locator(".service-repository").inner_text())

        page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
        self.assertEqual(page.get_by_role("navigation", name="Breadcrumb").get_by_role("link", name="Services").count(), 1)
        self.assertIn("media", page.locator(".service-header-context").inner_text())
        self.assertIn("Update available", page.locator(".service-header-context").inner_text())
        self.assertEqual(page.locator("[data-page-action-slot]").count(), 0)
        self.assertEqual(page.get_by_role("link", name="Review update").count(), 0)
        self.assertEqual(page.get_by_role("heading", name="Maintenance", level=2).count(), 1)
        self.assertIn("Image", page.locator(".maintenance-facts").inner_text())
        self.assertFalse(page.locator(".technical-details").evaluate("element => element.open"))
        self.assertTrue(page.locator("#update-confirmation").is_visible())
        self.assertEqual(page.locator("#update-confirmation button[type=submit]").count(), 1)
        self.assertNotIn("Unknown → Unknown", page.locator("#update-confirmation").inner_text())

        page.goto(self.base_url + "/settings", wait_until="domcontentloaded")
        self.assertEqual(page.locator(".settings-grid .card").count(), 3)
        self.assertEqual(page.locator(".settings-administrator h2").inner_text(), "Administrator")
        self.assertEqual(page.locator(".settings-appearance h2").inner_text(), "Appearance")
        self.assertEqual(page.locator(".settings-system h2").inner_text(), "System status")
        self.assertEqual(page.locator(".settings-system h3").count(), 0)
        self.assertIn("Change password", page.locator(".settings-subsection > summary").inner_text())
        self.assertFalse(page.locator(".settings-subsection").evaluate("e => e.open"))
        page.locator(".settings-subsection > summary").click()
        self.assertTrue(page.locator(".settings-subsection form").is_visible())
        self.assertIn("Web access", page.locator(".settings-system").inner_text())
        self.assertIn("confirmed service updates", page.locator(".settings-system").inner_text())

        page.goto(self.base_url + "/login", wait_until="domcontentloaded")
        self.assertNotIn("Read-only web foundation", page.locator("body").inner_text())
        with self.state.connect() as connection:
            connection.execute("UPDATE users SET disabled=1")
        try:
            page.goto(self.base_url + "/setup", wait_until="domcontentloaded")
            self.assertNotIn("Read-only web foundation", page.locator("body").inner_text())
        finally:
            with self.state.connect() as connection:
                connection.execute("UPDATE users SET disabled=0")

    def test_single_service_update_confirmation_progress_reload_and_screenshots(self):
        from pathlib import Path

        screenshots = screenshot_dir("web-phase-2")
        screenshots.mkdir(parents=True, exist_ok=True)
        self.seed_current_sonarr_runtime()

        for viewport, filename in (
            ((1440, 900), "service-detail-update-confirmation-desktop-1440x900.png"),
            ((390, 844), "service-detail-update-confirmation-mobile-390x844.png"),
        ):
            with self.subTest(state="confirmation", viewport=viewport):
                context, page = self.make_page(*viewport)
                self.addCleanup(context.close)
                page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
                form = page.locator("#update-confirmation .update-confirmation-form")
                self.assertTrue(form.is_visible())
                self.assertEqual(form.locator('input[name="confirmation_id"]').count(), 1)
                self.assertEqual(form.locator('input[name="service_key"]').count(), 0,
                                 "the submitted form must not choose its service outside the reviewed agent intent")
                self.assertIn("Sonarr", page.locator(".app-page-header h1").inner_text())
                self.assertNotIn("Sonarr", form.locator(".form-check-label").inner_text())
                self.assertIn("4.0.15", page.locator("#update-confirmation").inner_text())
                self.assertIn("4.0.16", page.locator("#update-confirmation").inner_text())
                self.assertIn("Docker healthcheck", page.locator(".runtime-detail").inner_text())
                self.assertIn("Healthy", page.locator(".runtime-detail").inner_text())
                self.assertNotIn("registry.example/sonarr:1.2.3", form.locator(".form-check-label").inner_text())
                self.assertIn("recreates only this service", form.inner_text())
                self.assertNotIn("change this service’s image reference", form.inner_text())
                self.assertTrue(form.get_by_role("checkbox").is_visible())
                self.assertFalse(page.locator("#update-confirmation .identity-disclosure").evaluate("element => element.open"))
                self.assertEqual(page.locator("#update-confirmation button[type=submit]").count(), 1)
                if viewport[0] == 390:
                    form_box = form.bounding_box()
                    button_box = form.get_by_role("button", name="Update service").bounding_box()
                    self.assertGreaterEqual(button_box["width"], form_box["width"] - 2)
                disclosure = page.locator("#update-confirmation .identity-disclosure")
                disclosure.locator("summary").click()
                exact_values = disclosure.inner_text()
                self.assertIn("Current image reference", exact_values)
                self.assertIn("Target image reference", exact_values)
                self.assertIn("Current digest", exact_values)
                self.assertIn("Target digest", exact_values)
                self.assertIn("registry.example/sonarr:1.2.3", exact_values)
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), viewport[0])
                disclosure.locator("summary").click()
                page.screenshot(path=str(screenshots / filename), full_page=True)

        self.assertEqual(self.agent.review_ids["R" * 43][2], "fixture-aaaaaaaa",
                         "the review intent must bind to the exact scan represented by the rendered service")

        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        self.agent.update_calls.clear()
        self.agent.cursor_values.clear()
        self.agent.operation = None
        page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
        form = page.locator("#update-confirmation .update-confirmation-form")
        submit = form.get_by_role("button", name="Update service")
        submit.click()
        self.assertEqual(self.agent.update_calls, [], "browser confirmation must be deliberate")
        form.get_by_role("checkbox").check()
        submit.click()
        page.wait_for_url("**/operations/" + "f" * 32)
        self.assertEqual(len(self.agent.update_calls), 1)
        self.assertEqual(set(self.agent.update_calls[0]), {"confirmation_id", "requested_by", "client_ip", "user_agent"})
        self.assertEqual(self.agent.update_calls[0]["confirmation_id"], "R" * 43)
        self.assertEqual(page.locator("[data-operation-progress]").get_attribute("data-status"), "running")
        self.assertIn("3/8 Pull image", page.locator("[data-operation-stage]").inner_text())
        page.wait_for_function("document.querySelector('[data-operation-progress]').dataset.cursor === '4'")
        self.assertEqual(page.locator('[data-operation-events] [data-stage-key="3/8 Pull image"]').count(), 1)
        self.assertEqual(page.locator('[data-operation-events] [data-stage-key="3/8 Pull image"]').inner_text().splitlines()[-1], "Working")
        self.assertIn(3, self.agent.cursor_values, "SSE must resume after the rendered event cursor")
        # Step count comes only from the real "3/8" stage label; the log stays open while running.
        self.assertEqual(page.locator("[data-operation-step]").inner_text(), "Step 3 of 8")
        self.assertEqual(page.locator("[data-operation-meter]").evaluate("e => [e.value, e.max]"), [2, 8])
        self.assertTrue(page.locator("[data-operation-log]").evaluate("e => e.open"))
        page.screenshot(path=str(screenshots / "service-update-progress-desktop-1440x900.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload(wait_until="domcontentloaded")
        self.assertIn("3/8 Pull image", page.locator("[data-operation-stage]").inner_text())
        self.assertEqual(page.locator("[data-operation-events] li").count(), 3)
        self.assertEqual(page.locator('[data-operation-events] [data-stage-key="3/8 Pull image"]').count(), 1)
        self.assertEqual(page.locator('[data-operation-events] [data-stage-key="3/8 Pull image"]').inner_text().splitlines()[-1], "Working")
        self.assertIn(4, self.agent.cursor_values, "reload must reconnect from the persisted latest event")
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
        header_geometry = page.evaluate("""() => {
          const title = document.querySelector('.app-page-header h1').getBoundingClientRect();
          const subtitle = document.querySelector('.operation-header-context > span:first-child').getBoundingClientRect();
          const status = document.querySelector('[data-operation-status]').getBoundingClientRect();
          const overlaps = (a, b) => a.left < b.right - 1 && a.right > b.left + 1
            && a.top < b.bottom - 1 && a.bottom > b.top + 1;
          return {subtitleOverlap: overlaps(subtitle, status), titleOverlap: overlaps(title, status),
            titleGap: status.left - title.right,
            sameTitleRow: title.top < status.bottom && title.bottom > status.top};
        }""")
        self.assertFalse(header_geometry["subtitleOverlap"], "operation status must not cover the service subtitle")
        self.assertFalse(header_geometry["titleOverlap"], "operation status must not cover the heading")
        if header_geometry["sameTitleRow"]:
            self.assertGreaterEqual(header_geometry["titleGap"], 8)
        page.screenshot(path=str(screenshots / "service-update-progress-mobile-390x844.png"), full_page=True)

        self.agent.emit_operation_warning = True
        page.locator("[data-operation-events] li").filter(has_text="Layer transfer was retried").wait_for()
        # Live rows carry the same attributes as server-rendered ones: the warning row shares the
        # stage key (as it does after a reload) while exactly one row remains the active stage.
        self.assertEqual(page.locator('[data-operation-events] [data-stage-key="3/8 Pull image"]').count(), 2)
        self.assertEqual(page.locator('[data-operation-events] [data-stage-key="3/8 Pull image"][data-stage-active="true"]').count(), 1)
        self.assertIn("Layer transfer was retried", page.locator("[data-operation-events]").text_content())
        self.assertEqual(page.locator("[data-operation-events] li").count(), 4,
                         "a warning remains visible without duplicating its active stage")

        self.agent.operation["status"] = "failed"
        self.agent.operation["current_stage"] = "Failed"
        self.agent.operation["error"] = "The replacement service failed startup or health verification; recovery information was retained."
        self.agent.operation["events"].append({"id": 6, "kind": "operation_failed", "stage": "Failed", "message": "The replacement service failed startup or health verification; recovery information was retained.", "status": "failed", "payload": {}})
        self.agent.operation["last_event_id"] = 6
        page.locator('[data-operation-progress][data-status="failed"]').wait_for()
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)
        self.assertFalse(page.locator("[data-operation-log]").evaluate("e => e.open"),
                         "the transient stage log collapses into the final state")
        self.assertIn("recovery information was retained", page.locator(".operation-panel .alert-danger").inner_text())
        self.assertIn("Failed", page.locator("[data-operation-events]").text_content())
        self.assertNotIn("recovery information was retained", page.locator("[data-operation-events]").text_content())
        page.goto(self.base_url + "/operations/" + "f" * 32, wait_until="domcontentloaded")
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)
        self.assertTrue(page.locator("[data-operation-error]").is_visible())
        self.assertIn("recovery information was retained", page.locator("[data-operation-error]").inner_text())
        self.assertIn("Layer transfer was retried", page.locator("[data-operation-events]").text_content())
        self.assertNotIn("recovery information was retained", page.locator("[data-operation-events]").text_content())

        source_access_error=("UPT cannot modify this service's Compose source from the agent sandbox. "
                             "Authorise the Compose project directory for UPT writes and try again.")
        # This is a distinct synthetic preflight refusal: it must not inherit
        # the earlier pull/backup timeline because the real writeability check
        # fails before either operation can begin.
        self.agent.operation.update(status="failed",current_stage="Failed",error=source_access_error,
                                    result=None,events=[
            {"id":1,"kind":"task_completed","stage":"Eligibility verified","message":"Completed","status":"completed","payload":{}},
            {"id":2,"kind":"operation_failed","stage":"Failed","message":source_access_error,"status":"failed","payload":{}},
        ],last_event_id=2)
        page.set_viewport_size({"width":1440,"height":900})
        page.goto(self.base_url + "/operations/" + "f" * 32, wait_until="domcontentloaded")
        self.assertIn(source_access_error,page.locator("[data-operation-error]").inner_text())
        self.assertNotIn("Pull image",page.locator("[data-operation-events]").text_content())
        self.assertNotIn("Back up Compose",page.locator("[data-operation-events]").text_content())
        page.screenshot(path=str(screenshots / "service-update-source-access-denied-desktop-1440x900.png"),full_page=True)
        page.set_viewport_size({"width":390,"height":844})
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"),390)
        self.assertIn(source_access_error,page.locator("[data-operation-error]").inner_text())
        page.screenshot(path=str(screenshots / "service-update-source-access-denied-mobile-390x844.png"),full_page=True)

        self.agent.operation["status"] = "succeeded"
        self.agent.operation["current_stage"] = "Complete"
        self.agent.operation["error"] = None
        self.agent.operation["result"] = {"updated": False}
        page.goto(self.base_url + "/operations/" + "f" * 32, wait_until="domcontentloaded")
        self.assertIn("No image change was required", page.locator(".alert-info").inner_text())

    def test_single_service_rollback_confirmation_progress_reload_and_recovery_screenshots(self):
        screenshots = screenshot_dir("web-phase-3-rollback")
        screenshots.mkdir(parents=True, exist_ok=True)
        self.seed_current_sonarr_runtime()
        original_snapshot = deepcopy(self.agent.snapshot_data)
        self.addCleanup(setattr, self.agent, "snapshot_data", original_snapshot)
        self.agent.rollback_available = True
        self.addCleanup(setattr, self.agent, "rollback_available", False)
        sonarr_result = self.agent.snapshot_data["payload"]["services"][0]
        sonarr_result["status"] = "CURRENT"
        sonarr_result["remote_version"] = "4.0.16"
        sonarr_result["service"]["version"] = "4.0.16"
        sonarr_result["service"]["image"] = "registry.example/sonarr:4.0.16"
        sonarr_result["service"]["digest"] = "sha256:" + "2" * 64

        def open_detail(width, height):
            context, page = self.make_page(width, height)
            self.addCleanup(context.close)
            page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
            section = page.locator(".rollback-confirmation")
            form = page.locator(".rollback-confirmation .update-confirmation-form")
            self.assertTrue(form.is_visible())
            self.assertEqual(form.locator('input[name="confirmation_id"]').count(), 1)
            self.assertEqual(form.locator('input[name="history_id"], input[name="image"], input[name="backup"], input[name="compose_file"]').count(), 0)
            self.assertIn("restore the Compose configuration saved before this update", form.inner_text())
            return context, page, section, form

        self.agent.rollback_digest_pin = False
        for viewport, filename in (
            ((1440, 900), "rollback-confirmation-desktop-1440x900.png"),
            ((390, 844), "rollback-confirmation-mobile-390x844.png"),
        ):
            with self.subTest(state="confirmation", viewport=viewport):
                _context, page, section, form = open_detail(*viewport)
                self.assertIn("Restore version", section.inner_text())
                self.assertIn("4.0.15", section.inner_text())
                self.assertIn("Healthy", page.locator(".runtime-detail").inner_text())
                self.assertTrue(form.get_by_role("checkbox").is_visible())
                page.screenshot(path=str(screenshots / filename), full_page=True)

        self.assertEqual(len(self.agent.rollback_review_ids["Q" * 43]), 2)

        self.agent.rollback_digest_pin = True
        sonarr_result["service"]["image"] = "registry.example/sonarr@sha256:" + "2" * 64
        for viewport, filename in (
            ((1440, 900), "rollback-digest-pinned-confirmation-desktop-1440x900.png"),
            ((390, 844), "rollback-digest-pinned-confirmation-mobile-390x844.png"),
        ):
            with self.subTest(state="digest-pinned-confirmation", viewport=viewport):
                _context, page, section, form = open_detail(*viewport)
                text = section.inner_text()
                self.assertIn("Current digest", text)
                self.assertIn("Restore digest", text)
                self.assertNotIn("registry.example/sonarr@sha256:", text)
                disclosure = section.locator(".identity-disclosure")
                self.assertFalse(disclosure.evaluate("element => element.open"))
                disclosure.locator("summary").click()
                exact = disclosure.inner_text()
                self.assertIn("Current image reference", exact)
                self.assertIn("Protected rollback image", exact)
                self.assertIn("registry.example/sonarr@sha256:", exact)
                checkbox_copy = form.locator(".form-check-label").inner_text()
                self.assertNotIn("sha256:", checkbox_copy)
                self.assertIn("reviewed rollback image", checkbox_copy)
                if viewport[0] == 390:
                    for value in section.locator(".technical-value").all():
                        box = value.bounding_box()
                        self.assertIsNotNone(box)
                        self.assertLessEqual(box["x"] + box["width"], viewport[0] + 1)
                disclosure.locator("summary").click()
                page.screenshot(path=str(screenshots / filename), full_page=True)
        self.agent.rollback_digest_pin = False
        sonarr_result["service"]["image"] = "registry.example/sonarr:4.0.16"

        self.agent.rollback_terminal_status = "running"
        context, page, section, form = open_detail(1440, 900)
        self.assertIn("reviewed rollback image", form.inner_text())
        self.agent.cursor_values.clear()
        form.get_by_role("checkbox").check()
        form.get_by_role("button", name="Rollback service").click()
        page.wait_for_url("**/operations/" + "c" * 32)
        self.assertEqual(len(self.agent.rollback_calls), 1)
        self.assertEqual(set(self.agent.rollback_calls[0]), {"confirmation_id", "requested_by", "client_ip", "user_agent"})
        self.assertEqual(self.agent.rollback_calls[0]["confirmation_id"], "Q" * 43)
        self.assertEqual(page.locator("[data-operation-progress]").get_attribute("data-status"), "running")
        self.assertIn("3/8 Restore retained Compose configuration", page.locator("[data-operation-stage]").inner_text())
        page.wait_for_timeout(150)
        self.assertIn(3, self.agent.cursor_values, "SSE must resume after the persisted rollback event cursor")
        page.screenshot(path=str(screenshots / "rollback-progress-desktop-1440x900.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        page.reload(wait_until="domcontentloaded")
        self.assertEqual(page.locator("[data-operation-progress]").get_attribute("data-status"), "running")
        self.assertIn("3/8 Restore retained Compose configuration", page.locator("[data-operation-stage]").inner_text())
        self.assertEqual(page.locator('[data-operation-events] [data-stage-key="3/8 Restore retained Compose configuration"]').count(), 1)
        page.wait_for_timeout(150)
        self.assertGreaterEqual(self.agent.cursor_values.count(3), 2,
                                "reload must reconnect from the persisted rollback event cursor")
        page.screenshot(path=str(screenshots / "rollback-progress-mobile-390x844.png"), full_page=True)

        self.agent.operation.update({
            "status": "succeeded", "current_stage": "Complete", "error": None,
            "result": {"image": "registry.example/sonarr:stable", "version": "stable",
                       "digest": "sha256:" + "1" * 64},
        })
        self.agent.operation["events"].append({
            "id": 4, "kind": "operation_completed", "stage": "Complete",
            "message": "Rollback complete", "status": "succeeded", "payload": {},
        })
        self.agent.operation["last_event_id"] = 4
        page.locator('[data-operation-progress][data-status="succeeded"]').wait_for()
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)
        self.assertIn("Rollback completed successfully", page.locator(".alert-success").inner_text())
        self.assertNotIn("updated successfully", page.locator(".alert-success").inner_text())
        self.assertEqual(page.locator(".operation-result h3").inner_text(), "Restored image")
        self.assertNotIn("Published version", page.locator(".operation-result").inner_text())
        self.assertNotIn("stable", page.locator(".operation-result").inner_text())

        self.agent.operation.update({"status": "running", "current_stage": "3/8 Restore retained Compose configuration",
                                     "result": None, "events": self.agent.operation["events"][:3], "last_event_id": 3})
        page.reload(wait_until="domcontentloaded")
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 1)
        self.agent.operation.update({"status": "succeeded", "current_stage": "Complete",
                                     "result": {"image": "registry.example/sonarr:stable",
                                                "version": "4.0.15-nightly", "digest": "sha256:" + "1" * 64}})
        self.agent.operation["events"].append({"id": 4, "kind": "operation_completed", "stage": "Complete",
                                               "message": "Rollback complete", "status": "succeeded", "payload": {}})
        self.agent.operation["last_event_id"] = 4
        page.locator('[data-operation-progress][data-status="succeeded"]').wait_for()
        self.assertIn("Published version", page.locator(".operation-result").inner_text())
        self.assertIn("4.0.15-nightly", page.locator(".operation-result").inner_text())
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)

        self.agent.rollback_terminal_status = "succeeded"
        _context, page, section, form = open_detail(1440, 900)
        form.get_by_role("checkbox").check()
        form.get_by_role("button", name="Rollback service").click()
        page.wait_for_url("**/operations/" + "c" * 32)
        self.assertTrue(page.locator(".alert-success").is_visible())
        page.screenshot(path=str(screenshots / "rollback-completed-desktop-1440x900.png"), full_page=True)

        self.agent.rollback_terminal_status = "failed"
        for viewport, filename in (
            ((1440, 900), "rollback-manual-recovery-required-desktop-1440x900.png"),
            ((390, 844), "rollback-manual-recovery-required-mobile-390x844.png"),
        ):
            with self.subTest(state="manual-recovery-required", viewport=viewport):
                _context, page, section, form = open_detail(*viewport)
                form.get_by_role("checkbox").check()
                form.get_by_role("button", name="Rollback service").click()
                page.wait_for_url("**/operations/" + "c" * 32)
                self.assertIn("Manual recovery is required", page.locator("[data-operation-error]").inner_text())
                self.assertIn("recovery backups and protected images were retained", page.locator("[data-operation-error]").inner_text())
                self.assertIn("Manual recovery required", page.locator("[data-operation-events]").text_content())
                self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)
                page.screenshot(path=str(screenshots / filename), full_page=True)

    def test_operation_progress_live_and_reload_project_the_same_semantic_history(self):
        screenshots = screenshot_dir("operation-progress-correctness")
        screenshots.mkdir(parents=True, exist_ok=True)
        operation_id = "e" * 32
        now = datetime.now(timezone.utc).isoformat()

        def event(event_id, kind, stage, status, message=""):
            return {"id": event_id, "kind": kind, "stage": stage, "message": message, "status": status, "payload": {}}

        recreate = "4/8 Recreate selected service without pulling"
        marker = "Recreation may have started. The namespace owner will not be changed."
        events = [
            event(1, "operation_started", "Queued", "queued", "Apply requested for Sonarr"),
            event(2, "task_completed", "1/8 Revalidate reviewed configuration", "completed", "Completed"),
            event(3, "task_completed", "2/8 Protect desired and trusted recovery evidence", "completed", "Completed"),
            event(4, "task_started", recreate, "running", "In progress"),
            event(5, "task_info", marker, "info"),
        ]
        self.agent.operation = {
            "id": operation_id, "kind": "compose_reconcile", "service_key": "container/" + "c" * 64,
            "service": "Sonarr", "stack": "media", "requested_by": "admin", "status": "running",
            "created_at": now, "started_at": now, "current_stage": recreate, "result": None, "error": None,
            "summary": {"action": "apply"}, "events": list(events), "last_event_id": 5,
        }
        snapshot_js = """() => Array.from(document.querySelectorAll('[data-operation-events] > li')).map(li => [
            li.dataset.eventId, li.dataset.eventRole, li.dataset.eventStatus, li.dataset.stageKey,
            li.dataset.stageActive, Boolean(li.querySelector('.op-step-message'))])"""
        rows = '[data-operation-events] > li'
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/operations/" + operation_id, wait_until="domcontentloaded")
        roles = page.eval_on_selector_all(rows, "items => items.map(li => li.dataset.eventRole)")
        self.assertEqual(roles, ["info", "stage", "stage", "stage", "info"])
        self.assertIn("Step 4 of 8", page.locator("[data-operation-step]").inner_text())
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 1)
        # Queued and transition markers are neutral dots, not incomplete or spinning steps.
        for index in (0, 4):
            row = page.locator(rows).nth(index)
            self.assertEqual(row.get_attribute("data-stage-active"), "false")
            self.assertEqual(row.locator(".op-step-icon").evaluate(
                "icon => getComputedStyle(icon, '::before').content"), "none")
        self.assertEqual(page.locator(rows).nth(1).locator(".op-step-icon").evaluate(
            "icon => getComputedStyle(icon, '::before').content"), '"✓"')
        page.screenshot(path=str(screenshots / "operation-progress-markers-desktop-1440x900.png"), full_page=True)
        page.set_viewport_size({"width": 390, "height": 844})
        page.screenshot(path=str(screenshots / "operation-progress-markers-mobile-390x844.png"), full_page=True)
        page.set_viewport_size({"width": 1440, "height": 900})
        page.wait_for_timeout(150)

        result = {"action": "apply", "mutation_performed": True, "recovered": False,
                  "manual_recovery_required": False, "namespace": True, "image_unchanged": True,
                  "owner_unchanged": True, "refresh_required": True,
                  "current_service_key": "container/" + "d" * 64}
        self.agent.operation["events"] += [
            event(6, "task_completed", recreate, "completed", "Completed"),
            event(7, "task_completed", "8/8 Publish trusted baseline and result", "completed", "Completed"),
            event(8, "operation_completed", "Configuration applied.", "succeeded", "Configuration applied."),
        ]
        self.agent.operation.update(status="succeeded", current_stage="Configuration applied.", result=result,
                                    last_event_id=8)
        page.locator('[data-operation-progress][data-status="succeeded"]').wait_for()
        live = page.evaluate(snapshot_js)
        live_alert = page.locator(".operation-terminal-result").inner_text()
        page.reload(wait_until="domcontentloaded")
        reloaded = page.evaluate(snapshot_js)
        self.assertEqual(live, reloaded, "live SSE and a reloaded page must project the same ordered history")
        self.assertEqual([row[0] for row in reloaded], ["1", "2", "3", "6", "5", "7", "8"])
        self.assertEqual([row[1] for row in reloaded], ["info", "stage", "stage", "stage", "info", "stage", "terminal"])
        self.assertTrue(all(row[4] == "false" for row in reloaded))
        self.assertEqual(page.locator(".operation-terminal-result").inner_text(), live_alert)
        self.assertIn("A targeted refresh is required. UPT normally queues it automatically", live_alert)

    def test_digest_pinned_confirmation_names_current_and_target_compose_pins(self):
        from pathlib import Path

        self.seed_current_sonarr_runtime()
        current_digest = "sha256:" + "a" * 63 + "1"
        target_digest = "sha256:" + "a" * 63 + "2"
        old_pin = "registry.example/sonarr@" + current_digest
        target_pin = "registry.example/sonarr:stable@" + target_digest
        result = self.agent.snapshot_data["payload"]["services"][0]
        original_result = deepcopy(result)
        self.addCleanup(self.agent.snapshot_data["payload"]["services"].__setitem__, 0, original_result)
        result["status"] = "PINNED UPDATE"
        result["service"]["image"] = old_pin
        result["service"]["digest"] = current_digest
        result["service"]["version"] = None
        result["remote_version"] = None
        result["tracking_tag"] = "stable"
        result["remote_digest"] = target_digest
        result["target_image"] = target_pin
        screenshots = screenshot_dir("web-phase-2")
        for viewport, filename in (
            ((1440, 900), "service-detail-digest-pinned-confirmation-desktop-1440x900.png"),
            ((390, 844), "service-detail-digest-pinned-confirmation-mobile-390x844.png"),
        ):
            with self.subTest(viewport=viewport):
                context, page = self.make_page(*viewport)
                self.addCleanup(context.close)
                page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
                form = page.locator("#update-confirmation .update-confirmation-form")
                text = page.locator("#update-confirmation").inner_text()
                self.assertIn("Tracking channel", text)
                self.assertIn("stable", text)
                self.assertIn("Current digest", text)
                self.assertIn("Target digest", text)
                self.assertNotIn(old_pin, text)
                self.assertNotIn(target_pin, text)
                self.assertNotIn("Unknown → Unknown", text)
                self.assertEqual(page.locator("#update-confirmation button[type=submit]").count(), 1)
                checkbox_copy = form.locator(".form-check-label").inner_text()
                self.assertIn("reviewed target image", checkbox_copy)
                self.assertNotIn(old_pin, checkbox_copy)
                self.assertNotIn(target_pin, checkbox_copy)
                self.assertIn("Healthy", page.locator(".runtime-detail").inner_text())
                self.assertTrue(form.get_by_role("checkbox").is_visible())
                disclosure = page.locator("#update-confirmation .identity-disclosure")
                self.assertFalse(disclosure.evaluate("element => element.open"))
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), viewport[0])
                disclosure.locator("summary").click()
                exact_text = disclosure.inner_text()
                self.assertIn(old_pin, exact_text)
                self.assertIn(target_pin, exact_text)
                self.assertIn(current_digest, exact_text)
                self.assertIn(target_digest, exact_text)
                self.assertNotEqual(current_digest, target_digest)
                disclosure.locator("summary").click()
                if viewport[0] == 390:
                    button = form.get_by_role("button", name="Update service").bounding_box()
                    form_box = form.bounding_box()
                    self.assertGreaterEqual(button["width"], form_box["width"] - 2)
                page.screenshot(path=str(screenshots / filename), full_page=True)

    def test_phase5_services_release_identity_desktop_mobile(self):
        screenshots = screenshot_dir("web-phase-5-update-workflow-polish")
        screenshots.mkdir(parents=True, exist_ok=True)
        previous = deepcopy(self.agent.snapshot_data)
        previous_runtime = deepcopy(self.agent.runtime_data)
        self.addCleanup(setattr, self.agent, "snapshot_data", previous)
        self.addCleanup(setattr, self.agent, "runtime_data", previous_runtime)
        base = build_snapshot()
        model = base["payload"]["services"][0]
        digest = "sha256:" + "a" * 64
        cases = (
            ("Published update", "4.0.15", "registry.example/published:latest", "UPDATE", "4.0.16", None, "4.0.15 → 4.0.16", None),
            ("Configured tag", None, "registry.example/tagged:1.2.3", "CURRENT", None, None, "Configured tag 1.2.3", None),
            ("Mutable channel", None, "registry.example/mutable:latest", "DIGEST CHANGED", None, None, "Digest changed · channel latest", None),
            ("Tracked pin", None, "registry.example/tracked@" + digest, "PINNED UPDATE", None, "stable", "Tracking channel stable · update available", None),
            ("Untracked pin", None, "registry.example/untracked@" + digest, "UNTRACKED DIGEST", None, None, "Digest pinned · tracking unavailable", None),
            ("Remote version", None, "registry.example/remote:latest", "UPDATE", "v2.0.0-rc.1", None, "Channel latest → target version v2.0.0-rc.1", None),
            ("Published prerelease", "4.0.15-nightly", "registry.example/prerelease:latest", "CURRENT", None, None, "Published version 4.0.15-nightly", None),
            # Finding 6: trusted version-like tracking tag kept as display-only target identity.
            ("Pinned target tag", None, "registry.example/pinned@" + digest, "PINNED UPDATE", None, "1.2.4", "Target tag 1.2.4", "registry.example/pinned:1.2.4@" + digest),
        )
        services = []
        for index, (name, version, image, status, remote, channel, _expected, target_image) in enumerate(cases):
            item = deepcopy(model)
            item["service"].update({"key": f"media/identity-{index}", "name": name,
                                    "image": image, "version": version, "digest": digest,
                                    "container_id": format(index + 1, "064x")})
            item.update({"status": status, "remote_version": remote, "tracking_tag": channel,
                         "remote_digest": digest, "target_image": target_image, "error": None})
            services.append(item)
        base["payload"] = {"count": len(services), "services": services}
        self.agent.snapshot_data = base
        self.agent.runtime_data["containers"] = [
            build_runtime_container(format(index + 1, "064x"), case[0], service=f"identity-{index}")
            for index, case in enumerate(cases)
        ]
        for width, height, filename, selector in (
            (1440, 900, "services-release-identity-desktop-1440x900.png", ".service-table tbody tr"),
            (390, 844, "services-release-identity-mobile-390x844.png", ".service-card"),
        ):
            context, page = self.make_page(width, height)
            self.addCleanup(context.close)
            page.goto(self.base_url + "/services", wait_until="domcontentloaded")
            self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)
            self.assertEqual(page.locator(selector).count(), len(cases))
            for name, _version, _image, _status, _remote, _channel, expected, _target_image in cases:
                row = page.locator(selector).filter(has=page.get_by_text(name, exact=True))
                self.assertEqual(row.count(), 1, f"{width}px: {name}")
                # Desktop shows structured current/available values; the full
                # provenance sentence remains available on the version cell.
                identity = row.inner_text()
                if selector.startswith(".service-table"):
                    identity += " " + (row.locator(".service-version-cell").get_attribute("title") or "")
                self.assertIn(expected, identity)
                self.assertNotIn("Version unknown", row.inner_text())
                self.assertNotIn("Unknown →", row.inner_text())
            page.screenshot(path=str(screenshots / filename), full_page=True)

    def test_phase5_update_rollback_and_operation_screenshots(self):
        screenshots = screenshot_dir("web-phase-5-update-workflow-polish")
        screenshots.mkdir(parents=True, exist_ok=True)
        saved_snapshot = deepcopy(self.agent.snapshot_data)
        saved_runtime = deepcopy(self.agent.runtime_data)
        saved_rollback = (self.agent.rollback_available, self.agent.rollback_digest_pin)
        saved_operation = deepcopy(self.agent.operation)
        self.addCleanup(setattr, self.agent, "snapshot_data", saved_snapshot)
        self.addCleanup(setattr, self.agent, "runtime_data", saved_runtime)
        self.addCleanup(setattr, self.agent, "rollback_available", saved_rollback[0])
        self.addCleanup(setattr, self.agent, "rollback_digest_pin", saved_rollback[1])
        self.addCleanup(setattr, self.agent, "operation", saved_operation)

        self.agent.snapshot_data = build_snapshot()
        self.agent.snapshot_data["finished_at"] = "2026-09-27T14:00:00+00:00"
        sonarr = self.agent.snapshot_data["payload"]["services"][0]
        service = sonarr["service"]
        service.update({
            "container_id": "a" * 64, "compose_service": "sonarr", "local_build": False,
            "ignored": False, "image": "registry.example/sonarr:4.0.15",
            "version": "4.0.15", "digest": "sha256:" + "1" * 64,
        })
        sonarr.update({"status": "UPDATE", "remote_version": "4.0.16", "remote_digest": "sha256:" + "2" * 64})
        self.agent.runtime_data = {
            "status": "current", "available": True, "stale": False,
            "captured_at": "2026-09-27T14:59:30+00:00", "last_success_at": "2026-09-27T14:59:30+00:00",
            "attempted_at": "2026-09-27T15:00:00+00:00", "attempt_success": True,
            "failure_category": None,
            "containers": [build_runtime_container("a" * 64, "Sonarr", service="sonarr", healthcheck="healthy")],
        }
        self.agent.rollback_available = False
        self.agent.rollback_digest_pin = False

        def capture_detail(filename, width, height, *, dark=False, open_exact=False):
            context, page = self.make_page(width, height, color_scheme="dark" if dark else "light", timezone_id="UTC")
            self.addCleanup(context.close)
            page.add_init_script("Date.now = () => Date.parse('2026-09-27T15:00:00Z');")
            page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
            self.assertEqual(page.evaluate("document.documentElement.dataset.bsTheme"), "dark" if dark else "light")
            initial_geometry = page.evaluate("""() => ({scrollWidth: document.documentElement.scrollWidth,
              offenders: [...document.querySelectorAll('body *')].map(element => {
                const box = element.getBoundingClientRect();
                return {tag: element.tagName, className: String(element.className || ''),
                  text: (element.innerText || '').slice(0, 90), right: Math.round(box.right),
                  width: Math.round(box.width), scrollWidth: element.scrollWidth,
                  clientWidth: element.clientWidth};
              }).filter(item => item.scrollWidth > item.clientWidth + 2 || item.right > innerWidth + 1).slice(-20)})""")
            self.assertEqual(initial_geometry["scrollWidth"], width, initial_geometry)
            if page.locator("#update-confirmation").count():
                form = page.locator("#update-confirmation .update-confirmation-form")
                self.assertEqual(page.locator("#update-confirmation button[type=submit]").count(), 1)
                self.assertTrue(form.locator("input[type=checkbox]").evaluate("e => e.closest('label') === e.parentElement"))
                if width == 390 and page.locator(".maintenance-fact").count() == 3:
                    facts = page.locator(".maintenance-fact").evaluate_all("els => els.map(e => { const b=e.getBoundingClientRect(); return {y:b.y,width:b.width}; })")
                    self.assertAlmostEqual(facts[0]["y"], facts[2]["y"], delta=2)
                    self.assertGreater(facts[1]["y"], facts[0]["y"] + 2)
                    self.assertGreaterEqual(facts[1]["width"], facts[0]["width"] + facts[2]["width"] - 2)
                disclosure = page.locator("#update-confirmation .identity-disclosure")
                self.assertFalse(disclosure.evaluate("e => e.open"))
                if open_exact:
                    disclosure.locator("summary").click()
                    geometry = page.evaluate("""() => ({scrollWidth: document.documentElement.scrollWidth,
                      offenders: [...document.querySelectorAll('body *')].map(element => {
                        const box = element.getBoundingClientRect();
                        return {tag: element.tagName, className: String(element.className || ''),
                          text: (element.innerText || '').slice(0, 90), right: Math.round(box.right),
                          width: Math.round(box.width)};
                      }).filter(item => item.right > innerWidth + 1).slice(-12)})""")
                    self.assertEqual(geometry["scrollWidth"], width, geometry)
            if page.locator("#rollback-confirmation").count():
                self.assertEqual(page.locator("#rollback-confirmation button[type=submit]").count(), 1)
            page.screenshot(path=str(screenshots / filename), full_page=True)
            return page

        versioned_update_page = capture_detail("service-detail-versioned-update-desktop-1440x900.png", 1440, 900)
        capture_detail("service-detail-versioned-update-mobile-390x844.png", 390, 844)
        versioned_maintenance = versioned_update_page.locator(".service-summary").inner_text()
        self.assertIn("Published version", versioned_maintenance)
        self.assertNotIn("Available version", versioned_maintenance)

        current_digest = "sha256:" + "b" * 63 + "1"
        target_digest = "sha256:" + "b" * 63 + "2"
        service.update({
            "image": "registry.example/sonarr:latest@" + current_digest,
            "version": None, "digest": current_digest,
        })
        sonarr.update({
            "status": "PINNED UPDATE", "remote_version": None, "remote_digest": target_digest,
            "tracking_tag": "latest", "target_image": "registry.example/sonarr:latest@" + target_digest,
        })
        capture_detail("service-detail-pinned-channel-no-version-desktop-1440x900.png", 1440, 900)
        pinned_update_page = capture_detail("service-detail-pinned-channel-no-version-mobile-dark-390x844.png", 390, 844, dark=True)
        pinned_maintenance = pinned_update_page.locator(".service-summary").inner_text()
        self.assertIn("Tracking channel", pinned_maintenance)
        self.assertIn("Current digest", pinned_maintenance)
        self.assertNotIn("Target digest", pinned_maintenance)

        service.update({
            "image": "registry.example/sonarr:4.0.16", "version": "4.0.16",
            "digest": "sha256:" + "2" * 64,
        })
        sonarr.update({"status": "CURRENT", "remote_version": "4.0.16", "remote_digest": "sha256:" + "2" * 64})
        self.agent.rollback_available = True
        capture_detail("service-detail-versioned-rollback-desktop-1440x900.png", 1440, 900)
        capture_detail("service-detail-versioned-rollback-mobile-390x844.png", 390, 844)

        self.agent.rollback_digest_pin = True
        pinned_current = "sha256:" + "c" * 63 + "1"
        service.update({
            "image": "registry.example/sonarr:latest@" + pinned_current,
            "version": None, "digest": pinned_current,
        })
        sonarr["status"] = "PINNED"
        capture_detail("service-detail-digest-pinned-rollback-mobile-390x844.png", 390, 844)

        self.agent.rollback_available = False
        self.agent.rollback_digest_pin = False
        long_service = "Nginx Proxy Manager — " + "north-" * 8
        long_repository = "registry.example/very-long-registry-name/" + "long-repository-component-" * 3
        service.update({
            "name": long_service,
            "image": long_repository + ":latest@" + pinned_current,
            "version": None, "digest": pinned_current,
        })
        sonarr.update({
            "status": "PINNED UPDATE", "remote_version": None,
            "remote_digest": "sha256:" + "c" * 63 + "2", "tracking_tag": "latest",
            "target_image": long_repository + ":latest@" + "sha256:" + "c" * 63 + "2",
        })
        long_page = capture_detail("service-long-service-repository-digest-mobile-390x844.png", 390, 844, open_exact=True)
        long_form = long_page.locator("#update-confirmation .update-confirmation-form")
        self.assertIn(long_service, long_page.locator(".app-page-header h1").inner_text())
        self.assertNotIn(long_service, long_form.locator(".form-check-label").inner_text())
        self.assertEqual(long_form.get_by_role("button", name="Update service").inner_text(), "Update service")
        self.assertLess(long_form.get_by_role("button", name="Update service").bounding_box()["height"], 54)
        self.assertGreaterEqual(long_page.locator(".maintenance-fact").nth(1).bounding_box()["width"],
                                long_page.locator(".maintenance-facts").bounding_box()["width"] - 2)
        long_form.get_by_role("checkbox").check()
        long_form.get_by_role("button", name="Update service").click()
        long_page.wait_for_url("**/operations/" + "f" * 32)
        self.assertEqual(set(self.agent.update_calls[-1]), {"confirmation_id", "requested_by", "client_ip", "user_agent"})
        self.assertEqual(self.agent.review_ids[self.agent.update_calls[-1]["confirmation_id"]][0], "container/" + "a" * 64)

        service.update({
            "name": "Sonarr", "image": "registry.example/sonarr@" + pinned_current,
            "version": None, "digest": pinned_current,
        })
        sonarr.update({"status": "UNTRACKED DIGEST", "remote_version": None, "remote_digest": None})
        sonarr.pop("tracking_tag", None)
        sonarr.pop("target_image", None)
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
        maintenance_text = page.locator(".service-summary").inner_text()
        self.assertNotIn("Tracking channel", maintenance_text)
        self.assertNotIn("latest", maintenance_text.lower())
        self.assertNotIn("Unknown → Unknown", maintenance_text)

        def set_operation(operation_id, *, kind="update", status="running", result=None, error=None, events=None):
            current_stage = {
                "queued": None,
                "running": "3/7 Pull exact reviewed image digest",
                "succeeded": "Complete",
                "failed": "Failed",
            }[status]
            self.agent.operation = {
                "id": operation_id, "kind": kind, "service_key": "container/" + "a" * 64,
                "service": "Sonarr", "stack": "media", "requested_by": "browser-fixture",
                "status": status, "created_at": "2026-09-27T14:00:00+00:00",
                "current_stage": current_stage, "summary": {"old_version": "4.0.15"},
                "result": result, "error": error, "events": events or [],
                "last_event_id": (events or [{"id": 0}])[-1]["id"],
                "live_event_added": True,
            }

        queued = [{"id": 1, "kind": "operation_queued", "stage": "Queued", "message": "Waiting for the UPT worker to begin.", "status": "queued", "payload": {}}]
        set_operation("1" * 32, status="queued", events=queued)
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/operations/" + "1" * 32, wait_until="domcontentloaded")
        self.assertIn("Queued", page.locator("[data-operation-status]").inner_text())
        page.screenshot(path=str(screenshots / "operation-update-queued-mobile-390x844.png"), full_page=True)

        stage = "3/7 Pull exact image digest after validating architecture and target identity"
        running_events = [
            {"id": 1, "kind": "task_completed", "stage": "1/7 Revalidate reviewed service", "message": "Completed", "status": "completed", "payload": {}},
            {"id": 2, "kind": "task_completed", "stage": "2/7 Back up Compose source", "message": "Completed", "status": "completed", "payload": {}},
            {"id": 3, "kind": "task_started", "stage": stage, "message": "Pulling the exact reviewed digest from the registry.", "status": "running", "payload": {}},
            {"id": 4, "kind": "task_progress", "stage": stage, "message": "Layer 4 of 9 is transferring; registry response is slower than usual.", "status": "running", "payload": {}},
            {"id": 5, "kind": "task_warning", "stage": stage, "message": "One layer transfer was retried; the verified target remains unchanged.", "status": "warning", "payload": {}},
        ]
        set_operation("2" * 32, status="running", events=running_events)
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/operations/" + "2" * 32, wait_until="domcontentloaded")
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"][data-stage-key="' + stage + '"]').count(), 1)
        self.assertEqual(page.locator('[data-operation-events] [data-event-status="warning"]').count(), 1)
        self.assertIn("Layer 4 of 9", page.locator("[data-operation-stage-detail]").inner_text())
        page.screenshot(path=str(screenshots / "operation-update-progress-desktop-1440x900.png"), full_page=True)
        context, page = self.make_page(390, 844, color_scheme="dark")
        self.addCleanup(context.close)
        page.goto(self.base_url + "/operations/" + "2" * 32, wait_until="domcontentloaded")
        self.assertEqual(page.evaluate("document.documentElement.dataset.bsTheme"), "dark")
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
        page.screenshot(path=str(screenshots / "operation-update-progress-mobile-dark-390x844.png"), full_page=True)

        success_events = running_events + [{"id": 6, "kind": "operation_completed", "stage": "Complete", "message": "Update completed successfully.", "status": "succeeded", "payload": {}}]
        set_operation("3" * 32, status="succeeded", events=success_events, result={
            "image": "registry.example/sonarr:4.0.16", "version": "4.0.16", "digest": "sha256:" + "2" * 64,
        })
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/operations/" + "3" * 32, wait_until="domcontentloaded")
        self.assertEqual(page.locator(".operation-terminal-result").count(), 1)
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)
        page.screenshot(path=str(screenshots / "operation-update-succeeded-mobile-390x844.png"), full_page=True)

        rollback_events = [
            {"id": 1, "kind": "task_completed", "stage": "1/7 Revalidate protected rollback point", "message": "Completed", "status": "completed", "payload": {}},
            {"id": 2, "kind": "task_started", "stage": "2/7 Restore saved Compose configuration", "message": "Restoring the verified backup for this service.", "status": "running", "payload": {}},
        ]
        rollback_events.append({"id": 3, "kind": "operation_completed", "stage": "Complete", "message": "Rollback completed successfully.", "status": "succeeded", "payload": {}})
        set_operation("4" * 32, kind="rollback", status="succeeded", events=rollback_events, result={
            "image": "registry.example/sonarr:4.0.15", "version": "4.0.15", "digest": "sha256:" + "1" * 64,
        })
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/operations/" + "4" * 32, wait_until="domcontentloaded")
        self.assertEqual(page.locator(".operation-terminal-result").count(), 1)
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)
        page.screenshot(path=str(screenshots / "operation-rollback-succeeded-desktop-1440x900.png"), full_page=True)

        failure_error = "Update failed. Automatic recovery restored the previous image and Compose configuration; application data was not changed."
        failed_events = running_events + [{"id": 6, "kind": "operation_failed", "stage": "Failed", "message": failure_error, "status": "failed", "payload": {}}]
        set_operation("5" * 32, status="failed", events=failed_events, error=failure_error, result={"recovered": True})
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/operations/" + "5" * 32, wait_until="domcontentloaded")
        self.assertEqual(page.locator(".operation-terminal-result").count(), 1)
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)
        self.assertEqual(page.locator("[data-operation-events]").text_content().count("Automatic recovery restored"), 0)
        page.screenshot(path=str(screenshots / "operation-update-failed-recovered-mobile-390x844.png"), full_page=True)

        ordinary_error = "The replacement did not pass health verification."
        set_operation("7" * 32, status="failed", events=running_events + [
            {"id": 6, "kind": "operation_failed", "stage": "Failed", "message": ordinary_error,
             "status": "failed", "payload": {}},
        ], error=ordinary_error)
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/operations/" + "7" * 32, wait_until="domcontentloaded")
        self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)
        self.assertIn(ordinary_error, page.locator("[data-operation-error]").inner_text())
        page.screenshot(path=str(screenshots / "operation-update-failed-mobile-390x844.png"), full_page=True)

        manual_error = "Automatic recovery was refused because Compose changed. Recovery backups and protected images were retained; manual recovery is required."
        manual_events = running_events + [{"id": 6, "kind": "operation_failed", "stage": "Manual recovery required", "message": manual_error, "status": "failed", "payload": {}}]
        set_operation("6" * 32, status="failed", events=manual_events, error=manual_error, result={"manual_recovery_required": True})
        for width, height, filename in (
            (1440, 900, "operation-manual-recovery-required-desktop-1440x900.png"),
            (390, 844, "operation-manual-recovery-required-mobile-390x844.png"),
        ):
            context, page = self.make_page(width, height)
            self.addCleanup(context.close)
            page.goto(self.base_url + "/operations/" + "6" * 32, wait_until="domcontentloaded")
            self.assertEqual(page.locator(".operation-terminal-result").count(), 1)
            self.assertEqual(page.locator('[data-operation-events] [data-stage-active="true"]').count(), 0)
            self.assertEqual(page.locator("[data-operation-events]").text_content().count("Recovery backups and protected images"), 0)
            self.assertIn("recovery backups and protected images were retained", page.locator("[data-operation-error]").inner_text().lower())
            page.screenshot(path=str(screenshots / filename), full_page=True)

    def test_missing_runtime_detail_fallback_remains_explicit(self):
        previous = deepcopy(self.agent.runtime_data)
        self.addCleanup(setattr, self.agent, "runtime_data", previous)
        self.agent.runtime_data = {
            "status": "never", "available": False, "stale": False,
            "captured_at": None, "last_success_at": None, "attempted_at": None,
            "attempt_success": None, "failure_category": None, "containers": [],
        }
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
        self.assertIn("No runtime record is available for this container yet", page.locator(".runtime-detail").inner_text())
        self.assertNotIn("Not present in the current Docker runtime", page.locator(".runtime-detail").inner_text())

    def test_manual_recovery_required_is_visible_without_compose_details(self):
        from pathlib import Path

        operation_id = "e" * 32
        safe_message = (
            "Automatic recovery was refused because Compose configuration changed or could not be verified. "
            "The backup and previous image were retained; manual recovery is required."
        )
        self.agent.operation = {
            "id": operation_id, "kind": "update", "service_key": "media/sonarr",
            "service": "Sonarr", "stack": "media", "requested_by": "admin",
            "status": "failed", "created_at": datetime.now(timezone.utc).isoformat(),
            "current_stage": "Failed", "summary": {"old_version": "4.0.15"},
            "result": {}, "error": safe_message, "last_event_id": 1,
            "events": [{"id": 1, "kind": "operation_failed", "stage": "Failed",
                        "message": safe_message, "status": "failed", "payload": {}}],
        }
        screenshots = screenshot_dir("web-phase-2")
        screenshots.mkdir(parents=True, exist_ok=True)
        for viewport, filename in (
            ((1440, 900), "service-update-manual-recovery-required-desktop-1440x900.png"),
            ((390, 844), "service-update-manual-recovery-required-mobile-390x844.png"),
        ):
            with self.subTest(viewport=viewport):
                context, page = self.make_page(*viewport)
                self.addCleanup(context.close)
                page.goto(self.base_url + "/operations/" + operation_id, wait_until="domcontentloaded")
                self.assertEqual(page.locator("[data-operation-progress]").get_attribute("data-status"), "failed")
                self.assertIn("manual recovery is required", page.locator("[data-operation-error]").inner_text())
                self.assertIn("previous image were retained", page.locator("[data-operation-error]").inner_text())
                self.assertEqual(page.locator("[data-operation-events]").text_content().strip(), "Failed")
                self.assertNotIn("compose.yml", page.locator("body").inner_text())
                self.assertNotIn("/opt/", page.locator("body").inner_text())
                page.screenshot(path=str(screenshots / filename), full_page=True)

    def test_failed_automatic_recovery_recreate_uses_manual_recovery_state(self):
        from pathlib import Path

        operation_id = "e" * 32
        safe_message = (
            "Automatic recovery was attempted but did not complete successfully. "
            "The backup and previous image were retained; manual recovery is required."
        )
        self.agent.operation = {
            "id": operation_id, "kind": "update", "service_key": "media/sonarr",
            "service": "Sonarr", "stack": "media", "requested_by": "admin",
            "status": "failed", "created_at": datetime.now(timezone.utc).isoformat(),
            "current_stage": "Failed", "summary": {"old_version": "4.0.15"},
            "result": {}, "error": safe_message, "last_event_id": 1,
            "events": [{"id": 1, "kind": "operation_failed", "stage": "Failed",
                        "message": safe_message, "status": "failed", "payload": {}}],
        }
        screenshots = screenshot_dir("web-phase-2")
        for viewport, filename in (
            ((1440, 900), "service-update-manual-recovery-failed-desktop-1440x900.png"),
            ((390, 844), "service-update-manual-recovery-failed-mobile-390x844.png"),
        ):
            with self.subTest(viewport=viewport):
                context, page = self.make_page(*viewport)
                self.addCleanup(context.close)
                page.goto(self.base_url + "/operations/" + operation_id, wait_until="domcontentloaded")
                self.assertEqual(page.locator("[data-operation-progress]").get_attribute("data-status"), "failed")
                self.assertIn("Automatic recovery was attempted", page.locator("[data-operation-error]").inner_text())
                self.assertIn("manual recovery is required", page.locator("[data-operation-error]").inner_text())
                self.assertNotIn("compose.yml", page.locator("body").inner_text())
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), viewport[0])
                page.screenshot(path=str(screenshots / filename), full_page=True)

    def test_settings_sections_stack_on_mobile_and_password_button_is_compact_on_desktop(self):
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/settings", wait_until="domcontentloaded")
        self.assertFalse(page.locator(".settings-subsection").evaluate("e => e.open"))
        page.locator(".settings-subsection > summary").click()
        positions = page.evaluate("""() => {
          const box = selector => {
            const r = document.querySelector(selector).getBoundingClientRect();
            return {x: r.x, y: r.y, right: r.right, bottom: r.bottom, width: r.width};
          };
          return {admin: box('.settings-administrator'), appearance: box('.settings-appearance'),
            system: box('.settings-system'), button: box('.settings-form button'),
            form: box('.settings-form')};
        }""")
        self.assertLess(positions["admin"]["x"], positions["appearance"]["x"])
        self.assertGreaterEqual(positions["system"]["y"], positions["appearance"]["bottom"] - 1)
        self.assertLess(positions["button"]["width"], positions["form"]["width"] / 2)

        page.set_viewport_size({"width": 390, "height": 844})
        page.reload(wait_until="domcontentloaded")
        boxes = [page.locator(selector).bounding_box() for selector in (
            ".settings-administrator", ".settings-appearance", ".settings-system")]
        self.assertLess(boxes[0]["y"] + boxes[0]["height"], boxes[1]["y"] + 1)
        self.assertLess(boxes[1]["y"] + boxes[1]["height"], boxes[2]["y"] + 1)
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 390)

    def test_populated_history_is_contained_on_desktop_and_mobile(self):
        events = [
            {"timestamp": "2026-09-23T18:42:00+00:00", "username": "fixture-admin", "action": "scan", "result": "success", "client_ip": "192.0.2.20"},
            {"timestamp": "2026-09-23T12:00:00+00:00", "username": "fixture-admin", "action": "login", "result": "success", "client_ip": "192.0.2.20"},
            {"timestamp": "2026-09-22T22:15:00+00:00", "username": "System", "action": "retention_check", "result": "success", "client_ip": "Unknown"},
        ]
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        for width, height in ((1440, 900), (390, 844)):
            with self.subTest(viewport=(width, height)), patch.object(self.state, "audit_events", return_value=events):
                page.set_viewport_size({"width": width, "height": height})
                page.goto(self.base_url + "/history", wait_until="domcontentloaded")
                self.assertEqual(page.locator(".history-table tbody tr").count(), 3)
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)
                panel = page.locator(".history-panel").bounding_box()
                table = page.locator(".history-table").bounding_box()
                self.assertGreaterEqual(table["x"], panel["x"])
                self.assertLessEqual(table["x"] + table["width"], panel["x"] + panel["width"] + 1)

    def test_standalone_not_found_state_has_readable_bounded_width(self):
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/services/no-such-service", wait_until="domcontentloaded")
        card = page.locator(".app-state-card")
        content = page.locator(".app-content")
        self.assertLessEqual(card.bounding_box()["width"], 768)
        self.assertLess(card.bounding_box()["width"], content.bounding_box()["width"])
        page.set_viewport_size({"width": 390, "height": 844})
        self.assertLessEqual(card.bounding_box()["width"], content.bounding_box()["width"] + 1)
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 390)

    def test_dark_theme_applies_to_overview_and_services_surfaces(self):
        context, page = self.make_page(1440, 900, color_scheme="dark")
        self.addCleanup(context.close)
        for path, width, height in (("/", 1440, 900), ("/services", 390, 844)):
            with self.subTest(path=path, viewport=(width, height)):
                page.set_viewport_size({"width": width, "height": height})
                page.goto(self.base_url + path, wait_until="domcontentloaded")
                self.assertEqual(page.evaluate("document.documentElement.dataset.bsTheme"), "dark")
                surface = page.locator(".card").first.evaluate("e => getComputedStyle(e).backgroundColor")
                body = page.locator("body").evaluate("e => getComputedStyle(e).backgroundColor")
                self.assertNotEqual(surface, body)
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)

    def test_desktop_table_facts_and_account_have_bounded_typography(self):
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/services", wait_until="domcontentloaded")
        table = page.locator(".service-table")
        stack = table.locator("tbody tr").filter(has_text="Grafana").first.locator(".cell-sub")
        lines = stack.evaluate("""e => {
          const range = document.createRange();
          range.selectNodeContents(e.firstChild);
          return range.getClientRects().length;
        }""")
        self.assertEqual(lines, 1, "ordinary stack names must not break across lines")
        self.assertTrue(stack.inner_text().startswith("monitoring"))
        self.assertIn("registry.example/grafana", stack.inner_text())
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 1440)
        desktop_scroller = page.locator(".service-table-wrap .table-responsive")
        self.assertLessEqual(desktop_scroller.evaluate("e => e.scrollWidth"), desktop_scroller.evaluate("e => e.clientWidth") + 1)
        runtime_header = page.locator(".service-table thead th").last.bounding_box()
        scroller_box = desktop_scroller.bounding_box()
        self.assertLessEqual(runtime_header["x"] + runtime_header["width"], scroller_box["x"] + scroller_box["width"] + 1)
        long_name = table.locator("tbody tr").filter(has_text="Long service identity").locator("td").first
        self.assertGreater(long_name.bounding_box()["height"], stack.bounding_box()["height"])
        page.set_viewport_size({"width": 1024, "height": 768})
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 1024)
        scroller = page.locator(".service-table-wrap .table-responsive")
        # The compact four-column table has no image-reference column.
        self.assertLessEqual(scroller.evaluate("e => e.scrollWidth"), scroller.evaluate("e => e.clientWidth") + 1)
        page.set_viewport_size({"width": 1440, "height": 900})
        account = page.locator(".app-nav-user")
        identity = account.evaluate("""e => ({height: e.getBoundingClientRect().height,
          lineHeight: parseFloat(getComputedStyle(e).lineHeight),
          clipped: e.scrollWidth > e.clientWidth, title: e.title, text: e.textContent})""")
        self.assertLessEqual(identity["height"], identity["lineHeight"] + 1)
        self.assertTrue(identity["clipped"])
        self.assertEqual(identity["title"], identity["text"])
        page.locator(".account-menu > summary").click()
        logout = page.get_by_role("button", name="Sign out").bounding_box()
        user = account.bounding_box()
        self.assertGreaterEqual(logout["y"], user["y"] + user["height"])

        page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
        update_fact = page.locator(".service-summary .maintenance-fact").filter(has_text="Update state").first
        gap = update_fact.evaluate("""e => {
          const label = e.querySelector('dt').getBoundingClientRect();
          const value = e.querySelector('dd').getBoundingClientRect();
          return value.top - label.bottom;
        }""")
        self.assertGreaterEqual(gap, 0)
        self.assertLessEqual(gap, 8)
        self.assertLessEqual(update_fact.evaluate("e => e.scrollWidth"), update_fact.evaluate("e => e.clientWidth") + 1)

    def test_phone_service_cards_stack_identity_metadata_and_warning(self):
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        for width, height in ((430, 932), (390, 844), (360, 800)):
            with self.subTest(viewport=(width, height)):
                page.set_viewport_size({"width": width, "height": height})
                page.goto(self.base_url + "/services", wait_until="domcontentloaded")
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)
                self.assertEqual(page.locator(".service-table-wrap").evaluate("e => getComputedStyle(e).display"), "none")
                card = page.locator(".service-card").filter(has_text="Digest-pinned service")
                layout = card.evaluate("""e => {
                  const box = selector => {
                    const r = e.querySelector(selector).getBoundingClientRect();
                    return {left: r.left, right: r.right, top: r.top, bottom: r.bottom, height: r.height};
                  };
                  const card = e.getBoundingClientRect();
                  return {card: {left: card.left, right: card.right, top: card.top, bottom: card.bottom},
                    heading: box('.service-card-heading'), version: box('.service-card-version'),
                    stack: box('.service-card-stack'), runtime: box('.service-card-runtime'),
                    warning: box('.service-card-warning'), link: box('.service-card-link'),
                    warningText: e.querySelector('.service-card-warning').innerText,
                    // Labels exist for assistive technology only; phones show no label clutter.
                    renderedLabels: [...e.querySelectorAll('.service-card-meta-label')]
                      .filter(label => label.getBoundingClientRect().width > 1).length};
                }""")
                self.assertIn("No trusted tracking tag is recorded", layout["warningText"])
                self.assertGreater(layout["version"]["top"], layout["heading"]["top"] + 8)
                self.assertGreater(layout["stack"]["top"], layout["version"]["top"] + 8)
                self.assertLessEqual(abs(layout["stack"]["top"] - layout["runtime"]["top"]), 4)
                self.assertGreaterEqual(layout["warning"]["top"], layout["stack"]["bottom"] - 1)
                for part in ("heading", "version", "stack", "runtime", "warning", "link"):
                    self.assertGreaterEqual(layout[part]["left"], layout["card"]["left"])
                    self.assertLessEqual(layout[part]["right"], layout["card"]["right"] + 1)
                self.assertLess(layout["warning"]["right"], layout["link"]["left"] + 1)
                self.assertEqual(layout["renderedLabels"], 0)

    def test_mobile_services_filters_are_disclosed_keyboard_accessible_and_stateful(self):
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/services", wait_until="domcontentloaded")

        mobile_form = page.locator(".service-filters-mobile")
        desktop_form = page.locator(".service-filters-desktop")
        self.assertTrue(mobile_form.is_visible())
        self.assertFalse(desktop_form.is_visible())
        search = mobile_form.locator('[name="q"]')
        self.assertTrue(search.is_visible())
        first_card_top = page.locator(".service-card").first.bounding_box()["y"]
        self.assertLess(first_card_top, 400, "service content should appear materially before the old 455px baseline")
        self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), 390)
        first_card = page.locator(".service-card").first
        self.assertIsNone(first_card.get_attribute("aria-label"))
        self.assertEqual(page.get_by_role("link", name="Architecture agent Architecture unsupported", exact=False).count(), 1)
        self.assertNotIn("View details", first_card.inner_text())
        self.assertEqual(first_card.locator(".service-card-link").get_attribute("aria-hidden"), "true")

        disclosure = mobile_form.locator("details.filter-disclosure")
        summary = disclosure.locator("summary")
        self.assertFalse(disclosure.evaluate("e => e.open"))
        self.assertEqual(summary.inner_text().strip(), "Filters")
        self.assertEqual(disclosure.locator(".filter-active-count").count(), 0)
        self.assertFalse(mobile_form.locator('[name="stack"]').is_visible())
        summary.focus()
        self.assertEqual(page.evaluate("document.activeElement.tagName"), "SUMMARY")
        page.keyboard.press("Enter")
        self.assertTrue(disclosure.evaluate("e => e.open"))
        self.assertTrue(mobile_form.locator('[name="stack"]').is_visible())
        self.assertTrue(mobile_form.get_by_role("button", name="Apply filters").is_visible())
        for width, height in ((390, 844), (360, 800)):
            with self.subTest(open_filters_viewport=(width, height)):
                page.set_viewport_size({"width": width, "height": height})
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)
                content = page.locator(".app-content").bounding_box()
                panel = mobile_form.locator(".service-filter-panel").bounding_box()
                self.assertGreaterEqual(panel["x"], content["x"] - 1)
                self.assertLessEqual(panel["x"] + panel["width"], content["x"] + content["width"] + 1)

        page.set_viewport_size({"width": 390, "height": 844})
        search.fill("Sonarr")
        mobile_form.locator('[name="stack"]').select_option(label="media")
        mobile_form.locator('[name="status"]').select_option(label="Update available")
        mobile_form.get_by_role("button", name="Apply filters").click()
        applied = page.evaluate("""() => {
          const params = new URL(location.href).searchParams;
          return {q: params.get('q'), stack: params.get('stack'), status: params.get('status')};
        }""")
        self.assertEqual(applied, {"q": "Sonarr", "stack": "media", "status": "UPDATE"})
        self.assertEqual(page.locator(".service-filters-mobile .filter-active-count").inner_text(), "2")
        self.assertEqual(page.locator(".service-filters-mobile .filter-active-count").get_attribute("aria-label"), "2 active filters")
        self.assertEqual(page.locator(".service-card").count(), 1)
        self.assertIn("Sonarr", page.locator(".service-card").first.inner_text())

        # Search remains a direct, visible action without opening secondary filters.
        page.goto(self.base_url + "/services", wait_until="domcontentloaded")
        search = page.locator(".service-filters-mobile [name=\"q\"]")
        search.fill("Radarr")
        page.locator(".service-filters-mobile .mobile-search-submit").click()
        self.assertEqual(page.locator(".service-card").count(), 1)
        self.assertIn("Radarr", page.locator(".service-card").first.inner_text())

    def test_desktop_navigation_and_empty_error_states_are_intentional(self):
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        navigation = page.get_by_role("navigation", name="Primary")
        active = navigation.get_by_role("link", name="Overview", exact=True)
        inactive = navigation.get_by_role("link", name="Services", exact=True)
        active_style = active.evaluate("e => ({border: getComputedStyle(e).borderBottomColor, weight: getComputedStyle(e).fontWeight})")
        inactive_style = inactive.evaluate("e => getComputedStyle(e).borderBottomColor")
        self.assertEqual(active.get_attribute("aria-current"), "page")
        self.assertNotEqual(active_style["border"], inactive_style)
        self.assertGreaterEqual(int(active_style["weight"]), 600)
        self.assertEqual(page.get_by_role("link", name="Overview", exact=True).get_attribute("aria-current"), "page")

        with patch.object(self.state, "audit_events", return_value=[]):
            page.goto(self.base_url + "/history", wait_until="domcontentloaded")
        history_state = page.locator(".history-panel .app-state-panel")
        self.assertTrue(history_state.is_visible())
        self.assertIn("No activity has been recorded yet", history_state.inner_text())
        self.assertEqual(history_state.locator("h2").inner_text(), "No activity yet")

        response = page.goto(self.base_url + "/services/no-such-service", wait_until="domcontentloaded")
        self.assertEqual(response.status, 404)
        error_state = page.locator(".app-state-card .app-state-panel")
        self.assertTrue(error_state.is_visible())
        self.assertIn("not present in the current inventory", error_state.inner_text())
        self.assertTrue(error_state.get_by_role("link", name="Return to overview").is_visible())
        self.assertEqual(page.locator(".app-state-card .alert-warning").count(), 0)

    def test_settings_identity_is_visually_bounded_and_fully_available(self):
        full_username = "review-admin-" + "u" * 56
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        for width, height in ((1440, 900), (390, 844)):
            with self.subTest(viewport=(width, height)):
                page.set_viewport_size({"width": width, "height": height})
                page.goto(self.base_url + "/settings", wait_until="domcontentloaded")
                identity = page.locator(".settings-identity")
                metrics = identity.evaluate("""e => ({
                  width: e.getBoundingClientRect().width,
                  height: e.getBoundingClientRect().height,
                  clientWidth: e.clientWidth,
                  scrollWidth: e.scrollWidth,
                  lineHeight: parseFloat(getComputedStyle(e).lineHeight), elementTag: e.tagName,
                  title: e.title, label: e.getAttribute('aria-label'), text: e.textContent
                })""")
                self.assertEqual(metrics["elementTag"], "SPAN")
                self.assertLessEqual(metrics["height"], metrics["lineHeight"] + 1)
                self.assertGreater(metrics["scrollWidth"], metrics["clientWidth"])
                self.assertEqual(metrics["text"], full_username)
                self.assertEqual(metrics["title"], "Full username: " + full_username)
                self.assertEqual(metrics["label"], "Full username: " + full_username)
                self.assertEqual(page.get_by_label("Full username: " + full_username).count(), 1)
                self.assertEqual(page.locator(".settings-identity code").count(), 0)
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)
                account_identity = page.locator(".app-nav-user")
                self.assertEqual(account_identity.inner_text(), full_username)
                self.assertTrue(account_identity.evaluate("e => e.scrollWidth > e.clientWidth"))

    def test_mobile_navigation_and_compact_service_cards_and_detail(self):
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        destinations = page.get_by_role("navigation", name="Mobile primary")
        self.assertTrue(destinations.is_visible())
        self.assertEqual(destinations.get_by_role("link").count(), 4)
        account = page.locator(".account-menu")
        account.locator("summary").click()
        self.assertTrue(page.get_by_role("button", name="Sign out").is_visible())
        self.assertTrue(account.get_by_role("link", name="Account & settings").is_visible())
        account.locator("summary").click()
        destinations.get_by_role("link", name="Services").click()
        self.assertTrue(page.url.endswith("/services"))
        self.assertEqual(destinations.get_by_role("link", name="Services").get_attribute("aria-current"), "page")
        self.assertEqual(page.locator(".service-table-wrap").evaluate("(e) => getComputedStyle(e).display"), "none")
        self.assertGreater(page.locator(".service-card").count(), 0)
        self.assertNotIn("registry.example", page.locator(".service-card").first.inner_text())
        self.assertEqual(page.locator(".app-nav-user").count(), 1)
        self.assertEqual(page.locator(".app-user-chip").count(), 0)

        previous_snapshot = deepcopy(self.agent.snapshot_data)
        previous_runtime = deepcopy(self.agent.runtime_data)
        self.addCleanup(setattr, self.agent, "snapshot_data", previous_snapshot)
        self.addCleanup(setattr, self.agent, "runtime_data", previous_runtime)
        self.agent.snapshot_data = {
            "status": "complete",
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "payload": {"count": 0, "services": []},
        }
        self.agent.runtime_data = {
            "status": "current", "available": True, "stale": False,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "last_success_at": datetime.now(timezone.utc).isoformat(),
            "attempted_at": datetime.now(timezone.utc).isoformat(), "attempt_success": True,
            "failure_category": None, "containers": [],
        }
        page.reload(wait_until="domcontentloaded")
        self.assertIn("No services found", page.locator(".empty-state").inner_text())
        self.agent.snapshot_data = previous_snapshot
        self.agent.runtime_data = previous_runtime

        long_key = "media/long-service-" + "x" * 72
        page.goto(self.base_url + "/services/" + long_key, wait_until="domcontentloaded")
        details = page.locator("details.technical-details")
        self.assertTrue(details.count() == 1)
        self.assertFalse(details.evaluate("(e) => e.open"))
        details.locator("summary").click()
        self.assertTrue(details.evaluate("(e) => e.open"))
        self.assertEqual(page.evaluate("document.body.scrollWidth"), page.evaluate("document.documentElement.clientWidth"))

    def test_tablet_services_keep_scannable_table_without_overflow(self):
        context, page = self.make_page(844, 390)
        self.addCleanup(context.close)
        for width, height in ((844, 390), (932, 430), (768, 1024), (1024, 768)):
            with self.subTest(viewport=(width, height)):
                page.set_viewport_size({"width": width, "height": height})
                page.goto(self.base_url + "/services", wait_until="domcontentloaded")
                self.assertEqual(page.locator(".mobile-destinations").is_visible(), width < 768)
                self.assertNotEqual(page.locator(".service-table-wrap").evaluate("e => getComputedStyle(e).display"), "none")
                self.assertEqual(page.locator(".service-card-list").evaluate("e => getComputedStyle(e).display"), "none")
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)
                table = page.locator(".service-table").bounding_box()
                self.assertLessEqual(table["x"] + table["width"], width)
        page.set_viewport_size({"width": 932, "height": 430})
        page.locator('.service-filters-desktop [name="q"]').fill("Digest-pinned")
        page.get_by_role("button", name="Filter").click()
        self.assertEqual(page.locator(".service-table tbody tr").count(), 1)
        self.assertIn("Digest-pinned service", page.locator(".service-table tbody").inner_text())
        page.get_by_role("navigation", name="Primary").get_by_role("link", name="History").click()
        self.assertTrue(page.url.endswith("/history"))
        page.get_by_role("navigation", name="Primary").get_by_role("link", name="Services").click()
        self.assertTrue(page.url.endswith("/services"))

    def test_updates_page_is_responsive_and_links_to_reviewed_update(self):
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        for width, height in ((1440, 900), (1024, 768), (768, 1024), (430, 932), (375, 812)):
            with self.subTest(viewport=(width, height)):
                page.set_viewport_size({"width": width, "height": height})
                page.goto(self.base_url + "/updates", wait_until="domcontentloaded")
                self.assertEqual(page.evaluate("document.documentElement.scrollWidth"), width)
                rows = page.locator(".updates-table tbody tr")
                self.assertEqual(rows.count(), 3)
                sonarr = rows.filter(has_text="Sonarr")
                self.assertIn("4.0.16", sonarr.inner_text())
                review = sonarr.get_by_role("link", name="Review update for Sonarr")
                box = review.bounding_box()
                self.assertLessEqual(box["x"] + box["width"], width)
                self.assertNotIn("Unknown →", page.locator(".updates-table").inner_text())
                self.assertGreater(page.locator(".undetermined-table tbody tr").count(), 0)
        page.set_viewport_size({"width": 1440, "height": 900})
        page.locator(".updates-table").get_by_role("link", name="Review update for Sonarr").click()
        page.wait_for_url(lambda url: url.endswith("a" * 64 + "#update-confirmation"))
        self.assertTrue(page.locator("#update-confirmation").is_visible())
        self.assertEqual(errors, [])

    def test_compose_apply_review_confirmation_and_no_baseline(self):
        from capture_compose_reconciliation import DRIFTED
        saved = deepcopy(self.agent.compose_status_data)
        saved_operation = deepcopy(self.agent.operation)
        self.addCleanup(setattr, self.agent, "compose_status_data", saved)
        self.addCleanup(setattr, self.agent, "operation", saved_operation)
        for width, height in ((1440, 900), (390, 844)):
            self.agent.compose_status_data = {**deepcopy(DRIFTED), "apply_eligible": True}
            context, page = self.make_page(width, height)
            try:
                page.goto(self.base_url + "/services/container/" + "a" * 64)
                self.assertIn("Update available", page.locator(".service-header-context").inner_text())
                qualifier = page.locator(".service-execution-note")
                self.assertEqual(qualifier.inner_text(), "Blocked by pending configuration changes")
                self.assertEqual(qualifier.get_attribute("href"), "#configuration")
                self.assertEqual(page.locator("#update-confirmation").count(), 0)
                disclosure = page.locator("[data-compose-review]")
                summary = disclosure.get_by_text("Show changes")
                self.assertFalse(disclosure.evaluate("e => e.open"))
                self.assertEqual(summary.locator(".disclosure-chevron").count(), 1)
                summary.focus()
                summary.press("Enter")
                self.assertTrue(disclosure.evaluate("e => e.open"))
                self.assertTrue(disclosure.get_by_text("This service", exact=True).is_visible())
                summary.press("Enter")
                self.assertFalse(disclosure.evaluate("e => e.open"))
                entry = page.locator("[data-compose-apply]")
                self.assertEqual(entry.get_attribute("action"), "/compose/apply/review")
                self.assertEqual(entry.locator('input[name="action"]').input_value(), "apply")
                entry.get_by_role("button", name="Apply changes", exact=True).click()
                page.wait_for_url("**/compose/apply/review")
                self.assertEqual(page.locator("h1").inner_text(), "Sonarr configuration")
                self.assertEqual(page.locator(".page-meta").inner_text(), "Review changes · media")
                self.assertEqual(page.locator('.breadcrumb [aria-current="page"]').inner_text(), "Configuration")
                self.assertTrue(page.get_by_role("heading", name="Review configuration changes").is_visible())
                self.assertIn("Unchanged · no pull", page.locator("main").inner_text())
                # Exercise presentation wrapping with long safe synthetic names.
                page.locator(".review-identity .review-channel strong").first.evaluate(
                    "e => e.textContent = 'Sonarr_with_a_long_service_name_'.repeat(6)")
                page.locator(".compose-change-head strong").first.evaluate(
                    "e => e.textContent = 'Long_redacted_configuration_category_'.repeat(5)")
                form_width = page.locator("[data-compose-confirmation] button").evaluate("e => e.getBoundingClientRect().width")
                self.assertEqual(page.locator("[data-compose-confirmation]").get_attribute("data-busy-form"), "")
                if width == 390:
                    self.assertAlmostEqual(form_width, page.locator("[data-compose-confirmation]").evaluate("e => e.getBoundingClientRect().width"), delta=2)
                self.assertFalse(page.evaluate("document.documentElement.scrollWidth > innerWidth"))
                form = page.locator("[data-compose-confirmation]")
                self.assertEqual(form.get_attribute("action"), "/operations/compose-reconcile")
                self.assertEqual(form.get_by_role("button").inner_text(), "Apply configuration")
                self.assertEqual(form.locator(".form-check-label").inner_text(),
                                 "I confirm applying the reviewed configuration changes to Sonarr.")
                self.assertEqual(form.locator('input[type="hidden"]').count(), 2)
                self.assertEqual(form.locator('input[type="checkbox"]').get_attribute("required"), "")
                calls = len(self.agent.compose_apply_calls)
                form.get_by_role("button").click()
                self.assertEqual(len(self.agent.compose_apply_calls), calls)
                form.get_by_role("checkbox").check()
                form.get_by_role("button").click()
                page.wait_for_url("**/operations/" + "f" * 32)
                self.assertEqual(page.locator("[data-operation-status]").inner_text(), "Applied successfully")
                self.assertIn("Sonarr configuration", page.locator("h1").inner_text())
                self.assertNotIn("image_id", page.content())
                self.agent.compose_status_data = {**deepcopy(DRIFTED), "baseline": None, "apply_eligible": True}
                page.goto(self.base_url + "/services/container/" + "a" * 64)
                self.assertEqual(page.locator("[data-compose-apply]").count(), 0)
            finally:
                context.close()

    def test_compose_discard_review_and_terminal_source_states(self):
        from capture_compose_discard import DISCARD_STATUS
        saved = deepcopy(self.agent.compose_status_data)
        self.addCleanup(setattr, self.agent, "compose_status_data", saved)
        self.agent.compose_status_data = deepcopy(DISCARD_STATUS)
        for width, height in ((1440, 900), (390, 844)):
            with self.subTest(width=width):
                context, page = self.make_page(width, height)
                try:
                    page.goto(self.base_url + "/services/container/" + "a" * 64)
                    page.locator("[data-compose-discard] button").click()
                    page.wait_for_url("**/compose/discard/review")
                    self.assertIn("will not be recreated or restarted", page.content())
                    self.assertFalse(page.evaluate("document.documentElement.scrollWidth > innerWidth"))
                    form = page.locator("[data-compose-confirmation]")
                    form.get_by_role("checkbox").check()
                    form.get_by_role("button", name="Discard changes", exact=True).click()
                    page.wait_for_url("**/operations/" + "f" * 32)
                    self.assertEqual(page.locator("[data-operation-status]").inner_text(), "Pending configuration changes discarded")
                    for result, label in (({"recovered": True}, "Discard failed — pending source restored"),
                                          ({"manual_recovery_required": True}, "Manual source recovery required")):
                        self.agent.operation.update(status="failed", result={"action": "discard", **result})
                        page.reload()
                        self.assertEqual(page.locator("[data-operation-status]").inner_text(), label)
                        self.assertIn("UPT did not recreate", page.content())
                        self.assertFalse(page.evaluate("document.documentElement.scrollWidth > innerWidth"))
                    self.agent.discard_review_refusal = "source_not_isolated"
                    page.goto(self.base_url + "/services/container/" + "a" * 64)
                    page.locator("[data-compose-discard] button").click()
                    page.wait_for_url("**/compose/discard/review")
                    self.assertIn("outside the reviewed scalar value changes", page.content())
                    self.assertIn("No source changes were made", page.content())
                    self.assertFalse(page.evaluate("document.documentElement.scrollWidth > innerWidth"))
                finally:
                    self.agent.discard_review_refusal = None
                    context.close()

    def test_compose_review_long_server_labels_wrap(self):
        from capture_compose_reconciliation import DRIFTED
        saved_snapshot = deepcopy(self.agent.snapshot_data)
        saved_status = deepcopy(self.agent.compose_status_data)
        self.addCleanup(setattr, self.agent, "snapshot_data", saved_snapshot)
        self.addCleanup(setattr, self.agent, "compose_status_data", saved_status)
        name = "Sonarr_with_a_long_service_name_" * 4
        self.agent.snapshot_data["payload"]["services"][0]["service"]["name"] = name
        self.agent.compose_status_data = {**deepcopy(DRIFTED), "apply_eligible": True}
        self.agent.compose_status_data["service_changes"][0]["label"] = "Long_redacted_configuration_category_" * 5
        for theme in ("light", "dark"):
            with self.subTest(theme=theme):
                context, page = self.make_page(390, 844, color_scheme=theme)
                try:
                    page.goto(self.base_url + "/services/container/" + "a" * 64)
                    page.locator("[data-compose-apply] button").click()
                    page.wait_for_url("**/compose/apply/review")
                    self.assertEqual(page.locator("h1").inner_text(), name + " configuration")
                    self.assertIn(name, page.locator(".form-check-label").inner_text())
                    self.assertFalse(page.evaluate("document.documentElement.scrollWidth > innerWidth"))
                    self.assertTrue(page.locator(".breadcrumb-item a").last.is_visible())
                    page.locator("[data-compose-confirmation] button").scroll_into_view_if_needed()
                    self.assertLessEqual(page.locator("[data-compose-confirmation] button").bounding_box()["y"] + 44,
                                         page.locator(".mobile-destinations").bounding_box()["y"])
                finally:
                    context.close()

    def test_shared_review_checkbox_contrast_focus_and_mobile_actions(self):
        from capture_compose_reconciliation import DRIFTED
        saved = deepcopy(self.agent.compose_status_data)
        self.addCleanup(setattr, self.agent, "compose_status_data", saved)
        self.addCleanup(setattr, self.agent, "rollback_available", self.agent.rollback_available)
        self.agent.rollback_available = True
        for theme in ("light", "dark"):
            for kind in ("update", "rollback", "compose"):
                with self.subTest(theme=theme, kind=kind):
                    self.agent.compose_status_data = ({**deepcopy(DRIFTED), "apply_eligible": True}
                                                     if kind == "compose" else deepcopy(saved))
                    context, page = self.make_page(390, 844, color_scheme=theme)
                    try:
                        page.goto(self.base_url + "/services/container/" + "a" * 64)
                        if kind == "compose":
                            page.locator("[data-compose-apply] button").click()
                            page.wait_for_url("**/compose/apply/review")
                            form = page.locator("[data-compose-confirmation]")
                        else:
                            form = page.locator(f"#{kind}-confirmation .update-confirmation-form")
                        checkbox = form.get_by_role("checkbox")
                        self.assertEqual(checkbox.get_attribute("required"), "")
                        contrast = checkbox.evaluate("""e => {
                            const s = getComputedStyle(e);
                            const luminance = rgb => {
                                const c = rgb.match(/[\\d.]+/g).slice(0, 3).map(Number)
                                    .map(v => v / 255).map(v => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4);
                                return .2126 * c[0] + .7152 * c[1] + .0722 * c[2];
                            };
                            const a = luminance(s.borderTopColor), b = luminance(s.backgroundColor);
                            return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
                        }""")
                        self.assertGreaterEqual(contrast, 3)
                        checkbox.focus()
                        checkbox.press("Tab")
                        page.keyboard.press("Shift+Tab")
                        self.assertTrue(checkbox.evaluate("e => e.matches(':focus-visible')"))
                        self.assertNotEqual(checkbox.evaluate("e => getComputedStyle(e).boxShadow"), "none")
                        checkbox.press("Space")
                        self.assertTrue(checkbox.is_checked())
                        self.assertTrue(checkbox.evaluate("e => getComputedStyle(e).borderTopColor === getComputedStyle(e).backgroundColor"))
                        checkbox.press("Space")
                        self.assertFalse(checkbox.is_checked())
                        self.assertAlmostEqual(form.get_by_role("button").bounding_box()["width"],
                                               form.bounding_box()["width"], delta=2)
                    finally:
                        context.close()

    def test_live_terminal_outcomes_match_reload(self):
        saved = deepcopy(self.agent.operation)
        self.addCleanup(setattr, self.agent, "operation", saved)
        running = {"id": "f" * 32, "kind": "update", "service": "Sonarr", "stack": "media",
                   "status": "running", "current_stage": "3/8 Pull image", "result": None, "error": None,
                   "events": [{"id": 1, "kind": "task_started", "stage": "3/8 Pull image",
                               "message": "In progress", "status": "running", "payload": {}}],
                   "last_event_id": 1}
        cases = (
            ("update", "succeeded", {"updated": True, "image": "registry.example/sonarr:4.0.16",
                                      "version": "4.0.16", "digest": "sha256:" + "2" * 64}, None,
             "Completed", "alert-success"),
            ("rollback", "succeeded", {"image": "registry.example/sonarr:4.0.15"}, None,
             "Completed", "alert-success"),
            ("update", "succeeded", {"updated": False}, None, "No change needed", "alert-info"),
            ("update", "failed", {}, "Pull failed.", "Failed", "alert-danger"),
            ("update", "failed", {"recovered": True, "image": "registry.example/sonarr:4.0.16"},
             "Pull failed.", "Failed · recovered", "alert-warning"),
            ("rollback", "failed", {"recovered": True}, "Restore failed.",
             "Failed · recovered", "alert-warning"),
            ("rollback", "failed", {"manual_recovery_required": True}, "Restore failed.",
             "Manual recovery required", "alert-danger"),
            ("update", "blocked", {"blocked_reason": "compose_drift", "mutation_performed": False},
             "Compose configuration changed after review.", "Blocked · no changes made", "alert-warning"),
            ("compose_reconcile", "succeeded", {"action": "apply", "mutation_performed": True,
                                                "current_service_key": "container/" + "c" * 64}, None,
             "Applied successfully", "alert-success"),
            ("compose_reconcile", "blocked", {"mutation_performed": False},
             "The configuration changed after review.", "Blocked · no changes made", "alert-warning"),
            ("compose_reconcile", "failed", {"recovered": True, "current_service_key": "container/" + "e" * 64},
             "Apply failed.", "Apply failed · recovered", "alert-warning"),
            ("compose_reconcile", "failed", {"manual_recovery_required": True},
             "Recovery was refused.", "Manual recovery required", "alert-danger"),
        )
        for kind, terminal, result, error, label, alert_class in cases:
            with self.subTest(kind=kind, status=terminal, result=result):
                self.agent.operation = deepcopy(running)
                self.agent.operation["kind"] = kind
                if kind == "compose_reconcile":
                    self.agent.operation["service_key"] = "container/" + "a" * 64
                    self.agent.operation["current_stage"] = "1/9 Applying configuration"
                    self.agent.operation["events"][0]["stage"] = "1/9 Applying configuration"
                context, page = self.make_page(390, 844)
                try:
                    page.goto(self.base_url + "/operations/" + "f" * 32, wait_until="domcontentloaded")
                    self.assertEqual(page.locator('[data-stage-active="true"]').count(), 1)
                    self.assertIn("status-info", page.locator("[data-operation-status]").get_attribute("class"))
                    stage = {"succeeded": "Complete", "failed": "Failed", "blocked": "Blocked"}[terminal]
                    self.agent.operation.update(status=terminal, result=result, error=error, current_stage=stage)
                    self.agent.operation["events"].append({
                        "id": 2, "kind": {"succeeded": "operation_completed", "failed": "operation_failed",
                                          "blocked": "operation_blocked"}[terminal],
                        "stage": self.agent.operation["current_stage"], "message": error or "Complete",
                        "status": terminal, "payload": {}})
                    self.agent.operation["last_event_id"] = 2
                    page.locator(f'[data-operation-progress][data-status="{terminal}"]').wait_for()
                    def state():
                        return (page.locator("[data-operation-status]").inner_text(),
                                page.locator("[data-operation-stage]").inner_text().strip(),
                                page.locator(".operation-terminal-result").inner_text(),
                                page.locator(".operation-terminal-result").get_attribute("class"),
                                page.locator(".operation-result-facts").inner_text()
                                if page.locator(".operation-result-facts").count() else "",
                                page.locator("[data-operation-service-link]").first.get_attribute("href")
                                if page.locator("[data-operation-service-link]").count() else "")
                    live = state()
                    self.assertEqual(live[0], label)
                    self.assertIn(alert_class, live[3])
                    if terminal in {"failed", "blocked"}:
                        self.assertEqual(live[4], "", "a failed operation has no proven deployed image")
                    if terminal == "blocked":
                        self.assertTrue(live[2].startswith("No changes were made."))
                        self.assertEqual(page.locator("[data-operation-error]").count(), 0)
                    self.assertEqual(page.locator('[data-stage-active="true"]').count(), 0)
                    self.assertFalse(page.locator("[data-operation-log]").evaluate("e => e.open"))
                    self.assertTrue(page.locator("[data-operation-meter]").is_hidden())
                    self.assertTrue(page.locator("[data-operation-step]").is_hidden())
                    page.reload(wait_until="domcontentloaded")
                    self.assertEqual(state(), live)
                    self.assertEqual(page.locator('[data-stage-active="true"]').count(), 0)
                    self.assertTrue(page.locator("[data-operation-meter]").is_hidden())
                finally:
                    context.close()

    def test_confirmed_mutation_form_prevents_duplicate_submission(self):
        self.agent.update_calls.clear()
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/services/media%2Fsonarr", wait_until="domcontentloaded")
        form = page.locator("#update-confirmation .update-confirmation-form")
        form.get_by_role("checkbox").check()
        form.evaluate("f => { f.requestSubmit(); f.requestSubmit(); }")
        page.wait_for_url("**/operations/" + "f" * 32)
        self.assertEqual(len(self.agent.update_calls), 1)

    @staticmethod
    def wait_for_dataset(page, name, expected, timeout=5.0):
        """Poll via evaluate(): the page CSP forbids wait_for_function's string predicates."""
        deadline = time.monotonic() + timeout
        while page.evaluate(f"document.documentElement.dataset.{name}") != expected:
            if time.monotonic() > deadline:
                break
            page.wait_for_timeout(50)

    def test_overview_counts_theme_auth_pages_and_keyboard_focus(self):
        context, page = self.make_page(1440, 900, color_scheme="dark")
        self.addCleanup(context.close)
        csp_violations = []
        page.on("console", lambda message: csp_violations.append(message.text)
                if "violates the following Content Security Policy" in message.text else None)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        themes = page.evaluate("() => [document.documentElement.dataset.theme, document.documentElement.dataset.bsTheme]")
        self.assertEqual(themes, ["dark", "dark"])
        cards = page.locator(".maintenance-summary-grid .summary-card")
        self.assertIn("Updates available", cards.nth(1).inner_text())
        self.assertIn("3", cards.nth(1).inner_text())
        self.assertIn("Pinned", cards.nth(2).inner_text())
        self.assertIn("2", cards.nth(2).inner_text())
        self.assertEqual(page.locator("#attention-title .badge").inner_text(), "9")
        page.goto(self.base_url + "/services", wait_until="domcontentloaded")
        first_version = page.locator(".service-table tbody tr").filter(has_text="Sonarr").locator("td").nth(2).inner_text()
        self.assertIn("4.0.15", first_version)
        self.assertIn("4.0.16", first_version)

        page.goto(self.base_url + "/settings", wait_until="domcontentloaded")
        theme_select = page.locator("[data-theme-select]")
        theme_select.select_option("light")
        self.assertEqual(page.evaluate("document.documentElement.dataset.bsTheme"), "light")
        theme_select.select_option("system")
        # Wait on the media-change listener's effect rather than a fixed delay,
        # which raced on loaded CI runners.
        page.emulate_media(color_scheme="light")
        self.wait_for_dataset(page, "theme", "light")
        self.assertEqual(page.evaluate("document.documentElement.dataset.theme"), "light")
        page.emulate_media(color_scheme="dark")
        self.wait_for_dataset(page, "bsTheme", "dark")
        self.assertEqual(page.evaluate("document.documentElement.dataset.bsTheme"), "dark")

        page.keyboard.press("Tab")
        focus = page.evaluate("({name: document.activeElement.getAttribute('class'), outline: getComputedStyle(document.activeElement).outlineStyle})")
        self.assertNotEqual(focus["outline"], "none")

        page.goto(self.base_url + "/login", wait_until="domcontentloaded")
        self.assertEqual(page.evaluate("document.documentElement.dataset.bsTheme"), "dark")
        self.assertEqual(page.locator(".alert-success").count(), 0)
        page.goto(self.base_url + "/login?notice=setup", wait_until="domcontentloaded")
        self.assertIn("Setup is complete", page.locator('[role="status"]').inner_text())
        page.goto(self.base_url + "/login?notice=password", wait_until="domcontentloaded")
        self.assertIn("password was changed", page.locator('[role="status"]').inner_text())
        page.goto(self.base_url + "/login?notice=logout", wait_until="domcontentloaded")
        self.assertIn("signed out", page.locator('[role="status"]').inner_text())
        page.goto(self.base_url + "/login?notice=session-expired", wait_until="domcontentloaded")
        self.assertIn("session expired or was revoked", page.locator('[role="status"]').inner_text())
        page.goto(self.base_url + "/login?notice=%3Cscript%3Ealert(1)%3C/script%3E", wait_until="domcontentloaded")
        self.assertEqual(page.locator(".alert-success").count(), 0)
        with self.state.connect() as connection:
            connection.execute("UPDATE users SET disabled=1")
        try:
            page.goto(self.base_url + "/setup", wait_until="domcontentloaded")
            self.assertIn("Create administrator", page.locator("h1").inner_text())
            self.assertEqual(page.evaluate("document.documentElement.dataset.bsTheme"), "dark")
        finally:
            with self.state.connect() as connection:
                connection.execute("UPDATE users SET disabled=0")
        self.assertEqual(csp_violations, [])

    def test_failed_attempt_does_not_refresh_cached_service_timestamp(self):
        captured = "2026-09-20T12:00:00+00:00"
        attempted = "2026-09-23T08:00:00+00:00"
        self.agent.snapshot_data["finished_at"] = captured
        self.agent.scan = {
            "id": "recent-failed-attempt", "status": "failed", "started_at": attempted,
            "finished_at": attempted, "total": 5, "completed": 1, "events": [],
            "error": "registry request timed out",
        }
        context, page = self.make_page(1440, 900)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        self.assertEqual(page.locator(".scan-freshness time").get_attribute("datetime"), captured)
        self.assertEqual(page.locator(".scan-attempt-time time").get_attribute("datetime"), attempted)
        self.assertIn("Last scan failed", page.locator('[data-scan-result="failed"]').inner_text())

    def test_untracked_digest_pin_is_prominent_and_does_not_guess_a_tag(self):
        context, page = self.make_page(1440, 960)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        attention = page.locator(".attention-row").filter(has_text="Digest-pinned service")
        self.assertTrue(attention.count() > 0)
        self.assertIn("Tracking unavailable", attention.first.inner_text())
        page.goto(self.base_url + "/services", wait_until="domcontentloaded")
        row = page.locator(".service-table tbody tr").filter(has_text="Digest-pinned service")
        self.assertIn("Tracking unavailable", row.inner_text())
        self.assertIn("No trusted tracking channel recorded", row.inner_text())
        card = page.locator(".service-card").filter(has_text="Digest-pinned service")
        self.assertIn("Digest pinned · tracking unavailable", card.inner_text())
        self.assertIn("did not guess a release channel", card.inner_text())

    def test_live_untracked_digest_event_matches_saved_classification(self):
        old_services = self.agent.scan_services
        old_statuses = self.agent.scan_status_by_service
        self.addCleanup(setattr, self.agent, "scan_services", old_services)
        self.addCleanup(setattr, self.agent, "scan_status_by_service", old_statuses)
        self.agent.scan_services = ["media/digest-pinned"]
        self.agent.scan_status_by_service = {"media/digest-pinned": "UNTRACKED DIGEST"}
        self.agent.scan = None
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        page.get_by_role("button", name="Scan now").click()
        page.locator("[data-scan-events] li").filter(has_text="Tracking unavailable").wait_for(timeout=8000)
        self.assertIn("Tracking unavailable", page.locator("[data-scan-stage]").inner_text())
        self.assertNotIn("UNTRACKED DIGEST", page.locator("[data-scan-progress]").inner_text())
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        self.assertIn("Tracking unavailable", page.locator(".attention-row").filter(has_text="Digest-pinned service").first.inner_text())

    def test_live_scan_counter_tracks_17_services_and_ignores_replayed_completion(self):
        old_scan = self.agent.scan
        old_services = self.agent.scan_services
        old_statuses = self.agent.scan_status_by_service
        old_hold = self.agent.hold_scan
        old_hold_after_discovery = self.agent.hold_after_discovery
        old_hold_after_completed = self.agent.hold_after_completed
        self.addCleanup(setattr, self.agent, "scan", old_scan)
        self.addCleanup(setattr, self.agent, "scan_services", old_services)
        self.addCleanup(setattr, self.agent, "scan_status_by_service", old_statuses)
        self.addCleanup(setattr, self.agent, "hold_scan", old_hold)
        self.addCleanup(setattr, self.agent, "hold_after_discovery", old_hold_after_discovery)
        self.addCleanup(setattr, self.agent, "hold_after_completed", old_hold_after_completed)
        self.agent.scan = None
        self.agent.scan_services = [f"media/service-{index}" for index in range(17)]
        self.agent.scan_status_by_service = {self.agent.scan_services[0]: "REGISTRY ERROR"}
        self.agent.hold_scan = False
        self.agent.hold_after_discovery = True
        self.agent.hold_after_completed = 1
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.add_init_script("""(() => { window.__uptScanStreams = []; const Native = window.EventSource;
          window.EventSource = class extends Native { constructor(...args) { super(...args); window.__uptScanStreams.push(this); } };
        })();""")
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        page.get_by_role("button", name="Scan now").click()
        panel = page.locator("[data-scan-progress]")
        page.wait_for_function("() => document.querySelector('[data-scan-count]')?.textContent.trim() === '0 / 17'", timeout=8000)
        self.assertEqual(panel.locator("[data-scan-bar]").evaluate("node => [node.value, node.max]"), [0, 17])
        self.agent.hold_after_discovery = False
        self.agent.hold_scan = False
        page.wait_for_function("() => document.querySelector('[data-scan-count]')?.textContent.trim() === '1 / 17'", timeout=8000)
        self.assertEqual(panel.locator("[data-scan-count]").inner_text().strip(), "1 / 17")
        self.assertEqual(panel.locator("[data-scan-bar]").evaluate("node => node.value"), 1)
        self.assertEqual(panel.locator("[data-scan-bar]").evaluate("node => node.max"), 17)
        self.assertEqual(panel.get_attribute("data-completed"), "1")
        self.assertEqual(self.agent.scan["events"][-1]["kind"], "task_failed")
        self.assertEqual(self.agent.scan["events"][-1]["status"], "REGISTRY ERROR")
        completed_event = next(event for event in reversed(self.agent.scan["events"])
                               if event.get("payload", {}).get("completed") == 1)
        self.assertNotIn("completed", completed_event)  # the persisted contract carries it in payload
        page.evaluate("event => window.__uptScanStreams.at(-1).dispatchEvent(new MessageEvent('scan-event', {data: JSON.stringify(event)}))", deepcopy(completed_event))
        page.wait_for_timeout(100)
        self.assertEqual(panel.locator("[data-scan-count]").inner_text().strip(), "1 / 17")
        self.assertEqual(panel.locator("[data-scan-bar]").evaluate("node => node.value"), 1)

    def test_active_scan_reloads_from_authoritative_count_then_resumes(self):
        old_scan = self.agent.scan
        old_services = self.agent.scan_services
        old_hold = self.agent.hold_scan
        old_cursors = list(self.agent.cursor_values)
        self.addCleanup(setattr, self.agent, "scan", old_scan)
        self.addCleanup(setattr, self.agent, "scan_services", old_services)
        self.addCleanup(setattr, self.agent, "hold_scan", old_hold)
        self.addCleanup(setattr, self.agent, "cursor_values", old_cursors)
        self.agent.scan_services = [f"media/service-{index}" for index in range(17)]
        events = [{"id": 1, "kind": "operation_started", "message": "Read-only scan started", "payload": {}}]
        events.append({"id": 2, "kind": "discovery_completed", "message": "Discovered 17 services",
                       "payload": {"count": 17, "total": 17, "completed": 0}})
        for index in range(1, 6):
            events.append({"id": index + 2, "kind": "task_completed", "service": f"media/service-{index - 1}",
                           "status": "CURRENT", "message": "CURRENT",
                           "payload": {"index": index, "total": 17, "completed": index}})
        self.agent.scan = {
            "id": "resumable-progress", "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None,
            "total": 17, "completed": 5, "events": events,
        }
        self.agent.hold_scan = True
        self.agent.cursor_values.clear()
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        panel = page.locator("[data-scan-progress]")
        self.assertEqual(panel.locator("[data-scan-count]").inner_text().strip(), "5 / 17")
        self.assertEqual(panel.locator("[data-scan-bar]").evaluate("node => [node.value, node.max]"), [5, 17])
        page.reload(wait_until="domcontentloaded")
        self.assertEqual(panel.locator("[data-scan-count]").inner_text().strip(), "5 / 17")
        self.assertEqual(panel.locator("[data-scan-bar]").evaluate("node => [node.value, node.max]"), [5, 17])
        self.assertGreaterEqual(panel.evaluate("node => Number(node.dataset.cursor)"), 7)
        self.agent.hold_scan = False
        page.wait_for_function("() => document.querySelector('[data-scan-count]')?.textContent.trim() === '6 / 17'", timeout=8000)
        self.assertEqual(panel.locator("[data-scan-bar]").evaluate("node => [node.value, node.max]"), [6, 17])
        self.assertTrue(any(cursor >= 7 for cursor in self.agent.cursor_values))

    def test_active_scan_suppresses_old_failure_copy_without_refreshing_snapshot_freshness(self):
        old_scan = self.agent.scan
        old_hold = self.agent.hold_scan
        old_finished_at = self.agent.snapshot_data.get("finished_at")
        self.addCleanup(setattr, self.agent, "scan", old_scan)
        self.addCleanup(setattr, self.agent, "hold_scan", old_hold)
        self.addCleanup(self.agent.snapshot_data.__setitem__, "finished_at", old_finished_at)
        self.agent.snapshot_data["finished_at"] = "2026-09-20T12:00:00+00:00"
        self.agent.scan = {
            "id": "new-active-scan", "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None,
            "total": 17, "completed": 2, "error": "previous scan timed out", "events": [],
        }
        self.agent.hold_scan = True
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        self.assertEqual(page.locator('[data-scan-result="failed"]').count(), 0)
        self.assertEqual(page.locator('[data-scan-result="partial"]').count(), 0)
        self.assertEqual(page.locator(".scan-freshness time").get_attribute("datetime"), "2026-09-20T12:00:00+00:00")
        self.assertEqual(page.locator("[data-scan-count]").inner_text().strip(), "2 / 17")

    def test_terminal_partial_scan_warning_is_visible_after_reconciliation(self):
        old_scan = self.agent.scan
        self.addCleanup(setattr, self.agent, "scan", old_scan)
        now = datetime.now(timezone.utc).isoformat()
        self.agent.scan = {
            "id": "partial-browser-scan", "status": "partial", "started_at": now,
            "finished_at": now, "total": 2, "completed": 2,
            "error": "1 service result could not be verified",
            "diagnostics": [{"service": "media/sonarr", "status": "REGISTRY ERROR", "message": "registry query failed"}],
            "events": [],
        }
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        alert = page.locator('[data-scan-result="partial"]')
        self.assertTrue(alert.is_visible())
        self.assertIn("Latest scan attempt finished with incomplete service results", alert.inner_text())
        alert.locator("summary").click()
        self.assertIn("media/sonarr", alert.inner_text())

    def test_reloaded_active_scan_events_use_human_status_labels(self):
        previous_scan = self.agent.scan
        previous_hold = self.agent.hold_scan
        self.addCleanup(setattr, self.agent, "scan", previous_scan)
        self.addCleanup(setattr, self.agent, "hold_scan", previous_hold)
        self.agent.hold_scan = True
        self.agent.scan = {
            "id": "saved-untracked-scan", "status": "running",
            "started_at": datetime.now(timezone.utc).isoformat(), "finished_at": None,
            "total": 1, "completed": 1,
            "events": [
                {"id": 1, "kind": "operation_started", "message": "Read-only scan started", "payload": {}},
                {"id": 2, "kind": "task_completed", "service": "media/digest-pinned",
                 "status": "UNTRACKED DIGEST", "message": "UNTRACKED DIGEST", "payload": {}},
            ],
        }
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        self.assertIn("Tracking unavailable", page.locator("[data-scan-stage]").inner_text())
        self.assertIn("Tracking unavailable", page.locator("[data-scan-events]").inner_text())
        self.assertNotIn("UNTRACKED DIGEST", page.locator("[data-scan-progress]").inner_text())

    def test_scan_now_during_active_scan_reuses_single_eventsource_and_cursor(self):
        self.agent.scan = None
        self.agent.scan_start_calls = 0
        self.agent.hold_scan = True
        self.addCleanup(setattr, self.agent, "hold_scan", False)
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.add_init_script("""(() => { window.__eventSourceCount = 0; const Native = window.EventSource;
          window.EventSource = class extends Native { constructor(...args) { window.__eventSourceCount += 1; window.__eventSourceUrl = args[0]; super(...args); } };
        })();""")
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        page.get_by_role("button", name="Scan now").click()
        page.wait_for_function("() => Number(document.querySelector('[data-scan-progress]').dataset.cursor) > 0")
        cursor = page.locator("[data-scan-progress]").get_attribute("data-cursor")
        event_count = page.locator("[data-scan-events] li").count()
        self.assertEqual(page.evaluate("window.__eventSourceCount"), 1)
        page.evaluate("document.querySelector('[data-scan-form]').requestSubmit()")
        page.wait_for_timeout(200)
        self.assertEqual(self.agent.scan_start_calls, 2)
        self.assertEqual(page.evaluate("window.__eventSourceCount"), 1)
        self.assertEqual(page.locator("[data-scan-progress]").get_attribute("data-cursor"), cursor)
        self.assertEqual(page.locator("[data-scan-events] li").count(), event_count)

    def test_revoked_session_closes_sse_and_offers_sign_in(self):
        self.agent.scan = None
        self.agent.hold_scan = True
        self.agent.expire_session_on_stream = True
        self.addCleanup(setattr, self.agent, "hold_scan", False)
        self.addCleanup(setattr, self.agent, "expire_session_on_stream", False)
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        page.get_by_role("button", name="Scan now").click()
        page.locator('[data-scan-connection] a').get_by_text("Sign in again").wait_for(timeout=5000)
        self.assertIn("session expired or was revoked", page.locator("[data-scan-status]").inner_text())

    def test_scan_stream_handles_pruned_run_and_local_time_is_browser_local(self):
        self.agent.scan = {
            "id": "pruned-browser-scan", "status": "running", "started_at": "2026-09-20T12:00:00+00:00",
            "finished_at": None, "total": 2, "completed": 1,
            "events": [{"id": 2, "kind": "task_completed", "message": "done"}],
        }
        self.agent.missing_scan = True
        self.agent.snapshot_data["finished_at"] = "2026-01-02T01:30:00+00:00"
        context, page = self.make_page(1440, 900, timezone_id="America/Los_Angeles")
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        page.locator("[data-scan-stage]").get_by_text("This scan is no longer available.").wait_for(timeout=5000)
        timestamp = page.locator(".scan-freshness time")
        expected = page.evaluate("value => new Intl.DateTimeFormat(undefined, {day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit'}).format(new Date(value))", timestamp.get_attribute("datetime"))
        self.assertEqual(timestamp.inner_text(), expected)
        self.assertNotIn("UTC", timestamp.inner_text())
        with self.state.connect() as connection:
            connection.execute("UPDATE users SET created_at=? WHERE id=?", ("2026-01-02 01:30:00", self.user_id))
        page.goto(self.base_url + "/settings", wait_until="domcontentloaded")
        created = page.locator(".settings-facts time[data-local-time]")
        self.assertEqual(created.get_attribute("datetime"), "2026-01-02T01:30:00+00:00")
        expected_created = page.evaluate("value => new Intl.DateTimeFormat(undefined, {day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit'}).format(new Date(value))", created.get_attribute("datetime"))
        self.assertEqual(created.inner_text(), expected_created)

    def test_scan_progress_resumes_after_reload_and_completes(self):
        self.agent.scan = None
        self.agent.cursor_values.clear()
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        page.get_by_role("button", name="Scan now").click()
        panel = page.locator("[data-scan-progress]")
        panel.wait_for(state="visible")
        self.assertTrue(panel.is_visible())
        page.wait_for_function(
            "() => Number(document.querySelector('[data-scan-progress]').dataset.completed) >= 1",
            timeout=12000,
        )
        page.reload(wait_until="domcontentloaded")
        self.assertTrue(page.locator("[data-scan-progress]").is_visible())
        page.wait_for_function(
            "() => document.querySelector('[data-scan-progress]').hidden",
            timeout=15000,
        )
        self.assertTrue(any(cursor > 1 for cursor in self.agent.cursor_values))

    def test_failed_scan_reconnect_shows_honest_terminal_state(self):
        self.agent.scan = {
            "id": "failed-browser-scan",
            "status": "failed",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "total": 4,
            "completed": 1,
            "error": "registry request timed out",
            "events": [{
                "id": 11,
                "kind": "operation_failed",
                "status": "failed",
                "message": "registry request timed out",
            }],
        }
        context, page = self.make_page(390, 844)
        self.addCleanup(context.close)
        page.goto(self.base_url + "/", wait_until="domcontentloaded")
        alert = page.locator('[data-scan-result="failed"]')
        self.assertTrue(alert.is_visible())
        self.assertIn("Last scan failed", alert.inner_text())
        self.assertIn("registry request timed out", alert.inner_text())

    def test_persistent_session_survives_browser_restart_and_logout(self):
        """A real Chromium login stays authenticated across a fresh context."""
        user = self.state.web_user()
        password = "browser-restart-password"
        self.state.update_password(user["id"], hash_password(password))

        context = self.browser.new_context(viewport={"width": 390, "height": 844})
        self.addCleanup(context.close)
        page = context.new_page()
        page.goto(self.base_url + "/login", wait_until="domcontentloaded")
        page.fill('input[name="username"]', user["username"])
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')
        page.wait_for_url(self.base_url + "/")

        stored = next(c for c in context.cookies(self.base_url) if c["name"] == "upt_session")
        # The persistent cookie carries a real browser expiry rather than a
        # session-only cookie that Safari/browsers drop on restart.
        self.assertGreater(stored["expires"], 0)
        self.assertTrue(stored["httpOnly"])
        self.assertEqual(stored["sameSite"], "Lax")

        # Simulate a browser/app restart: a brand new context presenting only the
        # persisted cookie reaches authenticated pages without logging in again.
        restarted = self.browser.new_context(viewport={"width": 390, "height": 844})
        self.addCleanup(restarted.close)
        restarted.add_cookies([stored])
        restarted_page = restarted.new_page()
        restarted_page.goto(self.base_url + "/settings", wait_until="domcontentloaded")
        self.assertEqual(restarted_page.url, self.base_url + "/settings")
        self.assertIn("/logout", restarted_page.content())

        # Logout revokes the server-side session and clears the browser cookie.
        # The header logout control can be collapsed on narrow viewports, so
        # submit the page's own logout form directly.
        restarted_page.evaluate("document.querySelector('form[action=\"/logout\"]').submit()")
        restarted_page.wait_for_url(self.base_url + "/login?notice=logout")
        self.assertIsNone(self.state.session(stored["value"]))
        # A stale client replaying the revoked cookie must not be authenticated.
        after = self.browser.new_context(viewport={"width": 390, "height": 844})
        self.addCleanup(after.close)
        after.add_cookies([stored])
        after_page = after.new_page()
        after_page.goto(self.base_url + "/settings", wait_until="domcontentloaded")
        self.assertIn("/login", after_page.url)


    def test_cross_site_link_navigation_keeps_persistent_login(self):
        """Opening UPT from a link on another site (Messages/Notes/mail) must not log the user out.

        With SameSite=Strict the browser withheld the cookie on that navigation, the
        server issued an anonymous session-only cookie, and that replaced the
        persistent authenticated cookie.
        """
        user = self.state.web_user()
        password = "browser-cross-site-password"
        self.state.update_password(user["id"], hash_password(password))
        context = self.browser.new_context(viewport={"width": 390, "height": 844})
        self.addCleanup(context.close)
        page = context.new_page()
        page.goto(self.base_url + "/login", wait_until="domcontentloaded")
        page.fill('input[name="username"]', user["username"])
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')
        page.wait_for_url(self.base_url + "/")
        before = next(c for c in context.cookies(self.base_url) if c["name"] == "upt_session")

        context.route("http://other-site.test/**", lambda route: route.fulfill(
            content_type="text/html", body='<a id="go" href="%s/settings">open UPT</a>' % self.base_url))
        page.goto("http://other-site.test/", wait_until="domcontentloaded")
        page.click("#go")
        page.wait_for_url(self.base_url + "/settings")
        self.assertIn("/logout", page.content())
        after = next(c for c in context.cookies(self.base_url) if c["name"] == "upt_session")
        self.assertEqual(after["value"], before["value"])
        self.assertGreater(after["expires"], 0)
        self.assertEqual(after["sameSite"], "Lax")

if __name__ == "__main__":
    unittest.main()
