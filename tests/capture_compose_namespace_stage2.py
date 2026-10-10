"""Capture only namespace Stage 2 views with synthetic data; no Docker access.

Run: PYTHONPATH=src:tests PYTHONDONTWRITEBYTECODE=1 .venv/bin/python tests/capture_compose_namespace_stage2.py
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
from argparse import ArgumentParser
from pathlib import Path

from test_compose_reconciliation import ServiceDetailAndOperationRouteTests
from test_web_browser import WebBrowserRegressionTests

DESTINATION = Path(__file__).resolve().parents[1] / 'docs/screenshots/compose-namespace-stage2'
OUTCOMES = {
    'succeeded': {'action': 'apply', 'namespace': True, 'mutation_performed': True, 'recovered': False,
                  'manual_recovery_required': False, 'image_unchanged': True, 'owner_unchanged': True,
                  'current_service_key': 'container/' + 'c' * 64},
    'recovered': {'action': 'apply', 'namespace': True, 'mutation_performed': True, 'recovered': True,
                  'manual_recovery_required': False, 'image_unchanged': True, 'owner_unchanged': True,
                  'current_service_key': 'container/' + 'e' * 64},
    'manual': {'action': 'apply', 'namespace': True, 'mutation_performed': None, 'possible_mutation': True,
               'recovered': False, 'manual_recovery_required': True},
    'blocked': {'action': 'apply', 'namespace': True, 'mutation_performed': False, 'recovered': False,
                'manual_recovery_required': False, 'blocked_reason': 'review_changed'},
}
ERRORS = {'recovered': 'Apply failed — previous configuration recovered. Desired changes remain pending.',
          'manual': 'Apply failed or was interrupted — manual recovery required. Recreation may have occurred; '
                    'evidence was retained and further trust and mutation are fenced.',
          'blocked': 'Blocked — no workload changes. Review the configuration changes again.'}


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('--only', nargs='+')
    selected = set(parser.parse_args().only or [])

    def save(page, name, *, full_page=False):
        if not selected or name in selected:
            assert not page.evaluate('document.documentElement.scrollWidth>innerWidth'), name
            page.screenshot(path=str(DESTINATION / (name + '.png')), full_page=full_page)
    DESTINATION.mkdir(parents=True, exist_ok=True)
    WebBrowserRegressionTests.setUpClass()
    fixture = WebBrowserRegressionTests('test_compose_apply_review_confirmation_and_no_baseline')
    fixture.agent.compose_status_data = ServiceDetailAndOperationRouteTests.drifted(apply_eligible=True)
    # Only supported consumer edits: namespace consumers never publish ports.
    fixture.agent.compose_status_data['service_changes'] = [
        entry for entry in fixture.agent.compose_status_data['service_changes'] if entry['field'] != 'ports']
    fixture.agent.snapshot_data['payload']['services'][0]['service']['name'] = 'qbittorrent'
    fixture.agent.namespace_review = {'owner': 'gluetun', 'owner_unchanged': True,
                                      'configuration_only_recovery': True}
    service = '/services/container/' + 'a' * 64
    try:
        for width, height in ((1440, 900), (390, 844)):
            context, page = fixture.make_page(width, height)
            try:
                page.goto(fixture.base_url + service, wait_until='domcontentloaded')
                page.get_by_role('button', name='Apply changes', exact=True).click()
                page.wait_for_url('**/compose/apply/review')
                assert page.get_by_text('Shares the network namespace of gluetun; the owner will not be changed.').count() == 1
                save(page, f'namespace-apply-review-{width}x{height}', full_page=width != 390)
                if width == 390:
                    page.evaluate('window.scrollTo(0,document.documentElement.scrollHeight)')
                    save(page, f'namespace-apply-confirmation-{width}x{height}')
                for label, result in OUTCOMES.items():
                    status = {'succeeded': 'succeeded', 'blocked': 'blocked'}.get(label, 'failed')
                    fixture.agent.operation = {
                        'id': 'f' * 32, 'kind': 'compose_reconcile', 'service': 'qbittorrent', 'stack': 'media',
                        'service_key': 'container/' + 'a' * 64, 'status': status, 'current_stage': 'Complete',
                        'summary': {'action': 'apply', 'namespace': True}, 'result': result,
                        'error': ERRORS.get(label), 'events': [], 'last_event_id': 0}
                    page.goto(fixture.base_url + '/operations/' + 'f' * 32, wait_until='domcontentloaded')
                    save(page, f'namespace-apply-{label}-{width}x{height}', full_page=True)
                print(f'Captured and checked namespace Stage 2 views at {width}x{height}')
            finally:
                context.close()
    finally:
        WebBrowserRegressionTests.tearDownClass()


if __name__ == '__main__':
    main()
