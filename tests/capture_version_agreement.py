"""Capture Settings/Overview version-agreement states with the synthetic Chromium fixture.

Run: PYTHONPATH=src:tests .venv/bin/python tests/capture_version_agreement.py
"""

import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
from pathlib import Path

from test_web_browser import WebBrowserRegressionTests, build_snapshot

DESTINATION = Path(__file__).resolve().parents[1] / "docs/screenshots/unified-versioning"


def main():
    DESTINATION.mkdir(parents=True, exist_ok=True)
    WebBrowserRegressionTests.setUpClass()
    fixture = WebBrowserRegressionTests("test_reference_viewports_have_no_layout_overlap_or_horizontal_overflow")
    agent = fixture.agent
    agent.snapshot_data = build_snapshot()
    matched = agent.product_version

    def capture(name, route, width, height, scroll_to=None):
        context, page = fixture.make_page(width, height, color_scheme="light")
        try:
            page.goto(fixture.base_url + route, wait_until="domcontentloaded")
            page.locator("body").wait_for()
            page.wait_for_timeout(75)
            if scroll_to:
                page.locator(scroll_to).evaluate("e => e.scrollIntoView({block: 'start', behavior: 'instant'})")
            if page.evaluate("document.documentElement.scrollWidth > innerWidth"):
                raise RuntimeError(f"horizontal overflow in {name}")
            page.screenshot(path=str(DESTINATION / f"{name}-{width}x{height}-light.png"), full_page=False)
        finally:
            context.close()

    try:
        for width, height in ((1440, 900), (390, 844)):
            agent.product_version = matched
            capture("settings-versions-match", "/settings", width, height, scroll_to=".settings-system")
            agent.product_version = "0.3.1"
            capture("settings-versions-mismatch", "/settings", width, height, scroll_to=".settings-system")
            capture("overview-versions-mismatch", "/", width, height)
    finally:
        agent.product_version = matched
        WebBrowserRegressionTests.tearDownClass()


if __name__ == "__main__":
    main()
