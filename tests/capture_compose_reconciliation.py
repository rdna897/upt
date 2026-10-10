"""Capture Compose reconciliation Phase 1 evidence with the synthetic Chromium fixture.

Run: PYTHONPATH=src:tests .venv/bin/python tests/capture_compose_reconciliation.py [destination]
All data is synthetic fixture data; nothing is read from a real Docker host.
"""

import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import sys
from copy import deepcopy
from pathlib import Path

from test_web_browser import WebBrowserRegressionTests

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "docs/screenshots/compose-reconciliation-phase1"
SERVICE = "/services/container/" + "a" * 64

DRIFTED = {
    "status": "drifted",
    "reasons": [{"code": "config_hash_differs",
                 "message": "The Compose configuration on disk differs from the configuration used to create this container."}],
    "inventory_reasons": [], "checked_at": "2026-09-27T14:00:00+00:00",
    "baseline": {"captured_at": "2026-09-27T13:55:00+00:00", "origin": "captured"},
    "update_blocked": True, "image_change": False, "scope": "service", "changes_itemised": True,
    "service_changes": [
        {"field": "environment", "label": "Environment", "summary": "1 added, 1 changed",
         "added": ["SONARR__LOG_LEVEL"], "changed": ["TZ"]},
        {"field": "restart", "label": "Restart policy", "summary": "unless-stopped → always",
         "old": "unless-stopped", "new": "always"},
        {"field": "ports", "label": "Ports", "summary": "1 added, 1 removed",
         "added": ["9999:8989/tcp"], "removed": ["8989:8989/tcp"]},
        {"field": "healthcheck", "label": "Healthcheck", "summary": "changed"},
    ],
    "project_changes": [],
}
UNVERIFIABLE = {
    "status": "unverifiable",
    "reasons": [{"code": "runtime_hash_missing",
                 "message": "The container has no valid Compose configuration identity label."}],
    "inventory_reasons": [], "checked_at": "2026-09-27T14:00:00+00:00", "baseline": None,
    "update_blocked": True, "image_change": False,
}
UNSUPPORTED = {
    "status": "unsupported",
    "reasons": [{"code": "label_file", "message": "A service reads labels from a label file."}],
    "inventory_reasons": [], "checked_at": "2026-09-27T14:00:00+00:00",
    "baseline": None, "update_blocked": True, "image_change": False,
}
EXECUTION_BLOCKED = {
    "status": "in_sync", "reasons": [], "inventory_reasons": [],
    "checked_at": "2026-09-27T14:00:00+00:00",
    "baseline": {"captured_at": "2026-09-27T13:55:00+00:00", "origin": "captured"},
    "update_blocked": True, "update_reasons": [{"code": "network_unproven",
        "message": "The selected service's Compose network cannot be proven to match its running network."}],
    "image_change": False,
}
BLOCKED = {
    "id": "f" * 32, "kind": "update", "service": "Sonarr", "stack": "media",
    "service_key": "container/" + "a" * 64, "status": "blocked", "current_stage": "Blocked",
    "result": {"blocked_reason": "compose_drift", "mutation_performed": False},
    "error": "Compose configuration changed after review. Review the pending configuration changes on the service page before trying again.",
    "events": [
        {"id": 1, "kind": "task_started", "stage": "Revalidating service eligibility",
         "message": "Checking current service identity and registry status", "status": "running", "payload": {}},
        {"id": 2, "kind": "operation_blocked", "stage": "Blocked", "status": "blocked",
         "message": "Compose configuration changed after review.", "payload": {}},
    ],
    "last_event_id": 2,
}


def main():
    unsupported_only = "--unsupported-only" in sys.argv[1:]
    execution_only = "--execution-blocked-only" in sys.argv[1:]
    destinations = [arg for arg in sys.argv[1:] if arg not in {"--unsupported-only", "--execution-blocked-only"}]
    destination = Path(destinations[0]) if destinations else DEFAULT
    destination.mkdir(parents=True, exist_ok=True)
    WebBrowserRegressionTests.setUpClass()
    fixture = WebBrowserRegressionTests("test_live_terminal_outcomes_match_reload")
    agent = fixture.agent
    in_sync = deepcopy(agent.compose_status_data)

    def capture(name, route, width, height, *, status=None, open_review=False, scroll_to=None):
        agent.compose_status_data = deepcopy(status or in_sync)
        context, page = fixture.make_page(width, height)
        try:
            page.goto(fixture.base_url + route, wait_until="domcontentloaded")
            page.locator("body").wait_for()
            if open_review:
                page.locator("[data-compose-review] > summary").click()
            if scroll_to:
                page.locator(scroll_to).evaluate("e => e.scrollIntoView({block: 'start', behavior: 'instant'})")
            page.wait_for_timeout(75)
            if page.evaluate("document.documentElement.scrollWidth > innerWidth"):
                raise RuntimeError(f"horizontal overflow in {name}")
            page.screenshot(path=str(destination / f"{name}-{width}x{height}.png"), full_page=False)
        finally:
            context.close()

    try:
        for width, height in ((1440, 900), (390, 844)):
            if unsupported_only:
                capture("service-config-unsupported", SERVICE, width, height, status=UNSUPPORTED,
                        scroll_to="#configuration")
                continue
            if execution_only:
                capture("service-config-execution-blocked", SERVICE, width, height,
                        status=EXECUTION_BLOCKED, scroll_to="#configuration")
                continue
            capture("service-config-in-sync", SERVICE, width, height, scroll_to="#configuration")
            capture("service-config-drifted-review", SERVICE, width, height, status=DRIFTED,
                    open_review=True, scroll_to="#configuration")
            capture("service-config-unverifiable", SERVICE, width, height, status=UNVERIFIABLE,
                    scroll_to="#configuration")
            capture("service-config-unsupported", SERVICE, width, height, status=UNSUPPORTED,
                    scroll_to="#configuration")
            agent.operation = deepcopy(BLOCKED)
            capture("operation-update-blocked", "/operations/" + "f" * 32, width, height)
    finally:
        WebBrowserRegressionTests.tearDownClass()


if __name__ == "__main__":
    main()
