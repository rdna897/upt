"""Capture affected Phase 2A UI using the synthetic Chromium fixture.

Run: PYTHONPATH=src:tests .venv/bin/python tests/capture_compose_apply.py
No real Docker, Compose, host inventory or production account is accessed.
Unchanged terminal-result captures are retained from the earlier review pass.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
from argparse import ArgumentParser
from copy import deepcopy
from pathlib import Path

from capture_compose_reconciliation import DRIFTED, SERVICE
from test_web_browser import WebBrowserRegressionTests

DESTINATION = Path(__file__).resolve().parents[1] / "docs/screenshots/compose-reconciliation-phase2a"


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="+", help="Capture only these filename prefixes.")
    selected = set(parser.parse_args().only or [])
    DESTINATION.mkdir(parents=True, exist_ok=True)
    WebBrowserRegressionTests.setUpClass()
    fixture = WebBrowserRegressionTests("test_compose_apply_review_confirmation_and_no_baseline")
    in_sync = deepcopy(fixture.agent.compose_status_data)
    fixture.agent.compose_status_data = {**deepcopy(DRIFTED), "apply_eligible": True}

    def capture(name, width, height, *, review=False, position="configuration",
                expanded=False, theme="light", full_page=False):
        if selected and name not in selected:
            return
        context, page = fixture.make_page(width, height, color_scheme=theme)
        try:
            page.goto(fixture.base_url + SERVICE, wait_until="domcontentloaded")
            if review:
                page.get_by_role("button", name="Apply changes", exact=True).click()
                page.wait_for_url("**/compose/apply/review")
            if expanded:
                page.locator("[data-compose-review] summary").click()
            if position == "final":
                page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
            elif position != "first":
                page.locator("#" + position).evaluate("e => e.scrollIntoView({block: 'start', behavior: 'instant'})")
            page.wait_for_timeout(75)
            if page.evaluate("document.documentElement.scrollWidth > innerWidth"):
                raise RuntimeError(f"horizontal overflow in {name}")
            page.screenshot(path=str(DESTINATION / f"{name}-{width}x{height}{'-dark' if theme == 'dark' else ''}.png"),
                            full_page=full_page)
        finally:
            context.close()

    try:
        for width, height, theme in ((1440, 900, "light"), (390, 844, "light"),
                                     (1440, 900, "dark"), (390, 844, "dark")):
            capture("service-eligible-apply", width, height, theme=theme)
            capture("apply-review-confirmation", width, height, review=True, theme=theme,
                    position="final" if width == 390 else "first", full_page=width != 390)
        for theme in ("light", "dark"):
            capture("service-update-blocked-first", 390, 844, position="first", theme=theme)
            capture("apply-review-first", 390, 844, review=True, position="first", theme=theme)
        for width, height in ((1440, 900), (390, 844)):
            capture("service-changes-expanded", width, height, expanded=True, theme="dark")

        # Long names come from server-side fixture presentation data, not DOM edits.
        service = fixture.agent.snapshot_data["payload"]["services"][0]["service"]
        service["name"] = "Sonarr_with_a_long_service_name_for_configuration_review"
        fixture.agent.compose_status_data["service_changes"][0]["label"] = (
            "Environment_variable_names_with_a_long_redacted_configuration_category")
        capture("apply-review-long-labels", 390, 844, review=True, position="first", theme="dark")
        service["name"] = "Sonarr"

        # The shared checkbox changes also affect the existing Update/Rollback cards.
        fixture.agent.compose_status_data = in_sync
        fixture.agent.rollback_available = True
        capture("shared-update-rollback-review", 1440, 900, position="first", full_page=True)
        capture("shared-update-review", 390, 844, position="update-confirmation", theme="dark")
        capture("shared-rollback-review", 390, 844, position="rollback-confirmation", theme="dark")
    finally:
        WebBrowserRegressionTests.tearDownClass()


if __name__ == "__main__":
    main()
