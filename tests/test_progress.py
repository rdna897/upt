import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import io, json, unittest
from unittest.mock import patch
from docker_update_manager.progress import Reporter
from docker_update_manager.cli import scan, interactive_selector, actionable_updates
from docker_update_manager.models import Service
from docker_update_manager.registry import ScanResult
from docker_update_manager.system import run_compose_progress

class NonTTY(io.StringIO):
    def isatty(self): return False

def svc():
    return Service("sonarr","c","repo/sonarr:latest","i","sha256:a","1.0",None,"amd64","running","none","no",None,"media","sonarr","/x",["/x/c.yml"])

class ProgressTests(unittest.TestCase):
    def test_non_tty_is_timestamped_and_append_only(self):
        out=NonTTY(); r=Reporter(stream=out); r.start("scan","Starting",total=2); r.advance(1,2,"a","CURRENT"); r.finish("Done")
        text=out.getvalue(); self.assertIn("[1/2]",text); self.assertIn("a:",text); self.assertNotIn("\r",text)
    def test_events_are_machine_reusable(self):
        r=Reporter(enabled=False); r.start("scan","Starting",total=1); r.advance(1,1,"sonarr","CURRENT")
        self.assertEqual(r.events[-1].kind,"task_completed"); json.dumps(r.events[-1].as_dict())
    def test_disabled_reporter_is_silent(self):
        out=NonTTY(); r=Reporter(enabled=False,stream=out); r.start("x","hidden"); r.finish("hidden"); self.assertEqual(out.getvalue(),"")
    def test_json_scan_stdout_has_no_progress(self):
        out=NonTTY(); r=Reporter(enabled=False,stream=out)
        with patch("docker_update_manager.cli.services",return_value=[svc()]), patch("docker_update_manager.cli.scan_service_with_tracking",return_value=ScanResult(svc(),"CURRENT")), patch("builtins.print") as pr:
            scan(None,None,json_out=True,reporter=r)
        payload=pr.call_args.args[0]; self.assertEqual(json.loads(payload)["current"],1)
    def test_untracked_digest_is_not_counted_current_in_json_or_exit_status(self):
        service=svc(); service.image="repo/app@sha256:running"
        result=ScanResult(service,"UNTRACKED DIGEST",error="no trusted tracking tag",tracking_issue="missing_channel")
        with patch("docker_update_manager.cli.services",return_value=[service]), patch("docker_update_manager.cli.scan_service_with_tracking",return_value=result), patch("builtins.print") as pr:
            code=scan(None,None,json_out=True,reporter=Reporter(enabled=False))
        payload=json.loads(pr.call_args.args[0])
        self.assertEqual(code,20); self.assertEqual(payload["current"],0); self.assertEqual(payload["untracked"],1)
        self.assertEqual(payload["services"][0]["status"],"UNTRACKED DIGEST")
        self.assertEqual(payload["services"][0]["tracking_issue"],"missing_channel")
    def test_docker_progress_uses_real_totals(self):
        class P:
            stdout=iter(['{"id":"layer1","status":"downloading","current":50,"total":100}\n'])
            def wait(self): return 0
            def poll(self): return 0
        r=Reporter(enabled=False)
        with patch("docker_update_manager.system.subprocess.Popen",return_value=P()) as popen:
            run_compose_progress(["docker","compose","pull","sonarr"],r,"sonarr")
        self.assertEqual(r.events[-1].current,50)
        self.assertIn("--progress",popen.call_args.args[0])
    def test_selector_quit_does_not_update(self):
        r=Reporter(enabled=False); r.prompt=lambda *a,**k: "q"
        result=ScanResult(svc(),"DIGEST CHANGED",remote_digest="sha256:b")
        with patch("docker_update_manager.cli.do_update") as update:
            interactive_selector([result],None,None,r)
        update.assert_not_called()
    def test_bulk_updates_filter_current_and_failures(self):
        a=svc(); b=svc(); b.name=b.compose_service="radarr"; c=svc(); c.name=c.compose_service="grafana"
        outcomes=[ScanResult(a,"DIGEST CHANGED"),ScanResult(b,"CURRENT"),ScanResult(c,"REGISTRY ERROR",error="rate limit")]
        with patch("docker_update_manager.cli.scan_service_with_tracking",side_effect=outcomes): selected,results=actionable_updates([a,b,c],None,Reporter(enabled=False))
        self.assertEqual(selected,[a]); self.assertEqual([x.status for x in results],["DIGEST CHANGED","CURRENT","REGISTRY ERROR"])
    def test_bulk_updates_never_select_standalone(self):
        a=svc(); a.stack=None
        with patch("docker_update_manager.cli.scan_service_with_tracking",return_value=ScanResult(a,"DIGEST CHANGED")): selected,_=actionable_updates([a],None,Reporter(enabled=False))
        self.assertEqual(selected,[])
    def test_bulk_updates_select_pinned_update(self):
        a=svc()
        with patch("docker_update_manager.cli.scan_service_with_tracking",return_value=ScanResult(a,"PINNED UPDATE")): selected,_=actionable_updates([a],None,Reporter(enabled=False))
        self.assertEqual(selected,[a])

if __name__=="__main__": unittest.main()
