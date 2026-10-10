"""Capture only Phase 2B2 views with synthetic data; no Docker access."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
from argparse import ArgumentParser
from pathlib import Path
from test_web_browser import WebBrowserRegressionTests
from test_compose_reconciliation import ServiceDetailAndOperationRouteTests

DESTINATION = Path(__file__).resolve().parents[1]/'docs/screenshots/compose-reconciliation-phase2b2'


def main():
    parser=ArgumentParser(description=__doc__)
    parser.add_argument('--only',nargs='+')
    selected=set(parser.parse_args().only or [])
    def save(page,name,*,full_page=False):
        if not selected or name in selected:
            page.screenshot(path=str(DESTINATION/(name+'.png')),full_page=full_page)
    DESTINATION.mkdir(parents=True,exist_ok=True)
    WebBrowserRegressionTests.setUpClass()
    fixture=WebBrowserRegressionTests('test_compose_apply_review_confirmation_and_no_baseline')
    fixture.agent.compose_status_data=ServiceDetailAndOperationRouteTests.drifted(
        baseline=None,apply_eligible=False,bootstrap_eligible=True,changes_itemised=False,service_changes=[],project_changes=[],scope="unknown",
        bootstrap_proposal=[{'field':'restart','label':'Restart policy','summary':'always'},
                            {'field':'environment','label':'Environment','items':['API_KEY','TZ'],'summary':'2 set · names only'},
                            {'field':'command','label':'Command','summary':'Configured'},
                            {'field':'healthcheck','label':'Healthcheck','summary':'Configured'}])
    service='/services/container/'+'a'*64
    try:
        for width,height in ((1440,900),(390,844)):
            context,page=fixture.make_page(width,height)
            try:
                page.goto(fixture.base_url+service,wait_until='domcontentloaded')
                page.locator('#configuration').evaluate("e=>e.scrollIntoView({block:'start',behavior:'instant'})")
                save(page,f'service-bootstrap-{width}x{height}')
                page.get_by_role('button',name='Apply configuration and establish trust',exact=True).click()
                page.wait_for_url('**/compose/bootstrap/review')
                ack=page.locator('#confirm-bootstrap')
                assert not ack.is_checked()
                assert ack.evaluate('e=>e.required && e.validity.valueMissing')
                assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
                save(page,f'bootstrap-confirmation-{width}x{height}',full_page=width!=390)
                if width==390:
                    page.evaluate('window.scrollTo(0,document.documentElement.scrollHeight)')
                    save(page,f'bootstrap-confirmation-acknowledgement-{width}x{height}')
                for status in ('succeeded','blocked','failed'):
                    fixture.agent.operation={'id':'f'*32,'kind':'compose_bootstrap','service':'Sonarr','stack':'media',
                        'service_key':'container/'+'a'*64,'status':status,'current_stage':'Complete',
                        'result':{'action':'bootstrap','manual_recovery_required':status=='failed','refresh_required':status=='succeeded'},
                        'events':[],'last_event_id':0}
                    page.goto(fixture.base_url+'/operations/'+'f'*32,wait_until='domcontentloaded')
                    assert not page.evaluate('document.documentElement.scrollWidth>innerWidth')
                    save(page,f'bootstrap-{status}-{width}x{height}',full_page=True)
                print(f'Captured and checked five affected views at {width}x{height}')
            finally:
                context.close()
    finally:
        WebBrowserRegressionTests.tearDownClass()


if __name__=='__main__':
    main()
