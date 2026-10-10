"""Capture only Stage-1 namespace refusal copy, using synthetic UI fixtures."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
from copy import deepcopy
from pathlib import Path
import sys

from docker_update_manager.compose_drift import REASONS
from test_web_browser import WebBrowserRegressionTests


def main():
    destination = Path(__file__).resolve().parents[1] / 'docs/screenshots/compose-namespace-stage1'
    destination.mkdir(parents=True, exist_ok=True)
    WebBrowserRegressionTests.setUpClass()
    fixture = WebBrowserRegressionTests('test_live_terminal_outcomes_match_reload')
    try:
        original = deepcopy(fixture.agent.snapshot_data)
        for name, reason in (('consumer', 'namespace_unsupported_compose'), ('owner', 'namespace_owner_has_dependents')):
            fixture.agent.snapshot_data = deepcopy(original)
            service = fixture.agent.snapshot_data['payload']['services'][0]['service']
            service.update(name='Namespace ' + name, compose_service=name, stack='synthetic',
                           image='registry.example/' + name + ':1.0', working_dir='/synthetic/project',
                           compose_files=['/synthetic/project/compose.yml'])
            fixture.agent.compose_status_data = {
                'status': 'in_sync', 'reasons': [], 'inventory_reasons': [],
                'checked_at': '2026-10-04T12:00:00+00:00',
                'baseline': {'captured_at': '2026-10-04T12:00:00+00:00', 'origin': 'captured'},
                'update_blocked': True, 'update_reasons': [{'code': reason, 'message': REASONS[reason]}],
                'apply_eligible': False, 'bootstrap_eligible': False, 'image_change': False,
            }
            sizes = ((390, 844),) if '--mobile-only' in sys.argv else ((1440, 900), (390, 844))
            for width, height in sizes:
                context, page = fixture.make_page(width, height)
                try:
                    page.goto(fixture.base_url + '/services/container/' + 'a' * 64, wait_until='domcontentloaded')
                    card = page.locator('#configuration')
                    card.evaluate("e => e.scrollIntoView({block: 'start', behavior: 'instant'})")
                    page.wait_for_timeout(75)
                    assert card.get_by_text(REASONS[reason], exact=True).is_visible()
                    assert page.locator('button:has-text("Apply changes")').count() == 0
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                    page.screenshot(path=str(destination / f'{name}-{width}x{height}.png'))
                finally:
                    context.close()
    finally:
        WebBrowserRegressionTests.tearDownClass()


if __name__ == '__main__':
    main()
