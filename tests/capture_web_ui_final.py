"""Capture the final UI baseline with the existing synthetic Chromium fixture.

Run: PYTHONPATH=src:tests .venv/bin/python tests/capture_web_ui_final.py
Use --representative for the bounded first visual review under /tmp.
"""

import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import sys
from copy import deepcopy
from pathlib import Path

from test_web_browser import WebBrowserRegressionTests, build_snapshot


ROOT = Path(__file__).resolve().parents[1]
FINAL = ROOT / "docs/screenshots/web-ui-final-integration"
REPRESENTATIVE = Path("/tmp/upt-ui-final-representative")


def operation(kind, status, result=None, error=None):
    stage = "3/8 Pull image" if kind == "update" else "3/8 Restore Compose"
    events = [{"id": 1, "kind": "task_completed", "stage": "2/8 Back up Compose source",
               "message": "Completed", "status": "completed", "payload": {}},
              {"id": 2, "kind": "task_started", "stage": stage,
               "message": "Working on the reviewed image.", "status": "running", "payload": {}}]
    if status in {"succeeded", "failed"}:
        events.append({"id": 3, "kind": "operation_completed" if status == "succeeded" else "operation_failed",
                       "stage": "Complete" if status == "succeeded" else "Failed",
                       "message": error or "Complete", "status": status, "payload": {}})
    return {"id": "f" * 32, "kind": kind, "service": "Sonarr", "stack": "media",
            "service_key": "media/sonarr", "status": status,
            "current_stage": stage if status == "running" else "Complete" if status == "succeeded" else "Failed",
            "result": result, "error": error, "events": events, "last_event_id": events[-1]["id"]}


def main():
    representative = "--representative" in sys.argv
    affected = "--affected" in sys.argv
    reviews_only = "--reviews" in sys.argv
    destination = REPRESENTATIVE if representative else FINAL
    destination.mkdir(parents=True, exist_ok=True)
    WebBrowserRegressionTests.setUpClass()
    fixture = WebBrowserRegressionTests("test_reference_viewports_have_no_layout_overlap_or_horizontal_overflow")
    agent = fixture.agent
    agent.snapshot_data = build_snapshot()

    def excluded_fixture():
        agent.snapshot_data = build_snapshot()
        for status, name in (("IGNORED", "Ignored example"), ("LOCAL BUILD", "Local build example")):
            item = deepcopy(agent.snapshot_data["payload"]["services"][0])
            item["service"].update(key="examples/" + name.lower().replace(" ", "-"), name=name,
                                   container_id=name[0].lower() * 64)
            item["status"] = status
            agent.snapshot_data["payload"]["services"].append(item)

    def capture(name, route, width, height, theme="light", *, setup=None, authenticated=True, scroll_to=None):
        if setup:
            setup()
        if authenticated:
            context, page = fixture.make_page(width, height, color_scheme=theme)
        else:
            context = fixture.browser.new_context(viewport={"width": width, "height": height}, color_scheme=theme)
            page = context.new_page()
        try:
            page.goto(fixture.base_url + route, wait_until="domcontentloaded")
            page.locator("body").wait_for()
            page.wait_for_timeout(75)
            if scroll_to:
                if scroll_to == ".updates-excluded":
                    page.locator(scroll_to).evaluate("e => e.open = true")
                page.locator(scroll_to).evaluate("e => e.scrollIntoView({block: e.matches('button') ? 'end' : 'start', behavior: 'instant'})")
            if page.evaluate("document.documentElement.scrollWidth > innerWidth"):
                raise RuntimeError(f"horizontal overflow in {name}")
            page.screenshot(path=str(destination / f"{name}-{width}x{height}-{theme}.png"), full_page=False)
        finally:
            context.close()

    try:
        sizes = ((1440, 900, "desktop"), (390, 844, "mobile"))
        if "--tablet-overview" in sys.argv:
            capture("overview", "/", 768, 1024)
            return
        if "--running" in sys.argv:
            for width, height, label in sizes:
                for theme in ("light", "dark"):
                    capture("operation-running", "/operations/" + "f" * 32, width, height, theme=theme,
                            setup=lambda: setattr(agent, "operation", operation("update", "running")))
            return
        if "--rollback-recovered" in sys.argv:
            for width, height, label in sizes:
                capture("operation-rollback-recovered", "/operations/" + "f" * 32, width, height,
                        setup=lambda: setattr(agent, "operation", operation("rollback", "failed",
                                                                            {"recovered": True}, "Restore failed.")))
            return
        if representative:
            for width, height, label in sizes:
                capture("overview", "/", width, height)
                capture("services", "/services", width, height)
                capture("updates-exclusions", "/updates", width, height, setup=excluded_fixture)
                agent.snapshot_data = build_snapshot()
                capture("settings", "/settings", width, height)
                capture("operation-failed-recovered", "/operations/" + "f" * 32, width, height,
                        setup=lambda: setattr(agent, "operation", operation("update", "failed", {"recovered": True}, "Pull failed.")))
            return

        pages = (("overview", "/"), ("services", "/services"),
                 ("updates", "/updates"), ("service-detail", "/services/media%2Fsonarr"),
                 ("history", "/history"), ("settings", "/settings"))
        for width, height, label in sizes:
            if not affected and not reviews_only:
                for name, route in pages:
                    agent.rollback_available = False
                    capture(name, route, width, height)
                capture("updates-exclusions", "/updates", width, height, setup=excluded_fixture,
                        scroll_to=".updates-excluded")
                agent.snapshot_data = build_snapshot()
            agent.rollback_available = False
            capture("service-update-review", "/services/media%2Fsonarr", width, height,
                    scroll_to="#update-confirmation")
            agent.rollback_available = True
            capture("service-rollback-review", "/services/media%2Fsonarr", width, height,
                    scroll_to="#rollback-confirmation")
            agent.rollback_available = False
            if not affected and not reviews_only:
                capture("login", "/login", width, height, authenticated=False)

        if reviews_only:
            return
        if not affected:
            for width, height, label in sizes:
                for name, route in (("overview", "/"), ("services", "/services"),
                                    ("updates", "/updates"), ("settings", "/settings")):
                    capture(name, route, width, height, theme="dark")

        states = (
            ("running", "update", "running", None, None),
            ("update-success", "update", "succeeded",
             {"updated": True, "image": "registry.example/sonarr:4.0.16", "version": "4.0.16",
              "digest": "sha256:" + "2" * 64}, None),
            ("rollback-success", "rollback", "succeeded", {"image": "registry.example/sonarr:4.0.15"}, None),
            ("no-change", "update", "succeeded", {"updated": False}, None),
            ("failure", "update", "failed", {}, "Pull failed; previous image retained."),
            ("failed-recovered", "update", "failed", {"recovered": True}, "Deployment failed."),
            ("rollback-recovered", "rollback", "failed", {"recovered": True}, "Restore failed."),
            ("manual-recovery", "rollback", "failed", {"manual_recovery_required": True}, "Restore failed."),
        )
        for width, height, label in sizes:
            for name, kind, status, result, error in states:
                if affected and status == "running":
                    continue
                capture("operation-" + name, "/operations/" + "f" * 32, width, height,
                        setup=lambda k=kind, s=status, r=result, e=error: setattr(agent, "operation", operation(k, s, r, e)))
        for width, height, label in sizes:
            if not affected:
                capture("operation-running", "/operations/" + "f" * 32, width, height, theme="dark",
                        setup=lambda: setattr(agent, "operation", operation("update", "running")))
            capture("operation-failed-recovered", "/operations/" + "f" * 32, width, height, theme="dark",
                    setup=lambda: setattr(agent, "operation", operation("update", "failed", {"recovered": True}, "Deployment failed.")))
    finally:
        WebBrowserRegressionTests.tearDownClass()


if __name__ == "__main__":
    main()
