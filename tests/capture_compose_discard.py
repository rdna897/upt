"""Bounded synthetic Phase 2B1 captures; no production data or Docker access.

Run: PYTHONPATH=src:tests .venv/bin/python tests/capture_compose_discard.py
Viewport sizes are 1440x900 and 390x844. Mobile captures show the lower
action/confirmation area with the real fixed navigation in its normal position.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
from argparse import ArgumentParser
from copy import deepcopy
from pathlib import Path

from capture_compose_reconciliation import DRIFTED, SERVICE
from test_web_browser import WebBrowserRegressionTests

DISCARD_STATUS = {**deepcopy(DRIFTED), 'apply_eligible': True, 'discard_eligible': True,
                  'service_changes': [
                      {'field': 'environment', 'label': 'Environment', 'summary': '1 changed', 'changed': ['TZ']},
                      {'field': 'restart', 'label': 'Restart policy', 'summary': 'unless-stopped → always',
                       'old': 'unless-stopped', 'new': 'always'}]}

DESTINATION = Path(__file__).resolve().parents[1] / 'docs/screenshots/compose-reconciliation-phase2b1'


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--only", nargs="+")
    selected = set(parser.parse_args().only or [])
    DESTINATION.mkdir(parents=True, exist_ok=True)
    WebBrowserRegressionTests.setUpClass()
    fixture = WebBrowserRegressionTests('test_compose_discard_review_and_terminal_source_states')
    fixture.agent.compose_status_data = deepcopy(DISCARD_STATUS)
    try:
        for width, height in ((1440, 900), (390, 844)):
            context, page = fixture.make_page(width, height)
            try:
                page.goto(fixture.base_url + SERVICE, wait_until='domcontentloaded')
                page.locator('#configuration').scroll_into_view_if_needed()
                card_path = str(DESTINATION / f'service-discard-{width}x{height}.png')
                if not selected or Path(card_path).name in selected:
                    if width == 390:
                        page.locator('[data-compose-discard] button').evaluate("e => e.scrollIntoView({block: 'center', behavior: 'instant'})")
                        page.screenshot(path=card_path)
                    else:
                        page.locator('#configuration').screenshot(path=card_path)
                page.locator('[data-compose-discard] button').click()
                page.wait_for_url('**/compose/discard/review')
                if page.evaluate('document.documentElement.scrollWidth > innerWidth'):
                    raise RuntimeError('horizontal overflow')
                review_path = str(DESTINATION / f'discard-confirmation-{width}x{height}.png')
                if not selected or Path(review_path).name in selected:
                    if width == 390:
                        page.locator('[data-compose-confirmation] button').scroll_into_view_if_needed()
                        page.screenshot(path=review_path)
                    else:
                        page.locator('.update-confirmation').screenshot(path=review_path)
                refusal_name = f'discard-refusal-{width}x{height}.png'
                if not selected or refusal_name in selected:
                    fixture.agent.discard_review_refusal = 'source_not_isolated'
                    page.goto(fixture.base_url + SERVICE, wait_until='domcontentloaded')
                    page.locator('[data-compose-discard] button').click()
                    page.wait_for_url('**/compose/discard/review')
                    page.screenshot(path=str(DESTINATION / refusal_name))
                    fixture.agent.discard_review_refusal = None
            finally:
                context.close()
    finally:
        WebBrowserRegressionTests.tearDownClass()


if __name__ == '__main__':
    main()
