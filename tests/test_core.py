import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import contextlib, errno, io, json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import Mock, patch
from docker_update_manager.models import parse_image_ref, Service
from docker_update_manager.compose import (ComposeSourceNotWritable, pin_plan, atomic_write,
                                           backup_files, verify_atomic_replace_access)
from docker_update_manager.config import Config
from docker_update_manager.state import State
from docker_update_manager.cli import execute, main, parser
from docker_update_manager.removal import remove_service, resource_plan, _remaining_container_images, _safe_bind_source
from docker_update_manager.progress import Reporter
from docker_update_manager.operations import PreMutationRefusal, RecoveryFailed, RecoveryRefused, RecoveryRequired, ReviewedTargetChanged, do_pin, do_update, do_rollback
from docker_update_manager.registry import LOCAL_DIGEST_UNVERIFIED
from docker_update_manager.removal import _service_rollback_images, _other_active_rollback

def service(root,image="grafana/grafana:latest",version="12.1.0",digest="sha256:"+"a"*64):
    return Service("grafana","cid",image,"iid",digest,version,None,"amd64","running","none","unless-stopped",None,"monitoring","grafana",str(root),[str(root/"compose.yml")])

class ImageTests(unittest.TestCase):
    def test_latest_mutable(self): self.assertTrue(parse_image_ref("redis:latest").mutable)
    def test_stable_mutable(self): self.assertTrue(parse_image_ref("x/y:stable").mutable)
    def test_semver_pinned(self): self.assertEqual(parse_image_ref("x/y:1.2.3").pin_type,"VERSION PIN")
    def test_digest(self): self.assertEqual(parse_image_ref("ghcr.io/x/y@sha256:abc").digest,"sha256:abc")
    def test_registry(self): self.assertEqual(parse_image_ref("lscr.io/linuxserver/sonarr:latest").registry,"lscr.io")

class ComposeTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(); self.root=Path(self.t.name)
    def tearDown(self): self.t.cleanup()
    def test_semantic_pin(self):
        (self.root/"compose.yml").write_text("services:\n  grafana:\n    image: grafana/grafana:latest # keep\n")
        _,_,new,kind=pin_plan(service(self.root)); self.assertIn("grafana/grafana:12.1.0 # keep",new); self.assertEqual(kind,"VERSION PIN")
    def test_digest_pin(self):
        (self.root/"compose.yml").write_text("services:\n  grafana:\n    image: grafana/grafana:latest\n")
        _,_,new,kind=pin_plan(service(self.root),True); self.assertIn("@sha256:",new); self.assertEqual(kind,"DIGEST PIN")
    def test_env_pin(self):
        (self.root/"compose.yml").write_text("services:\n  grafana:\n    image: grafana/grafana:${GRAFANA_VERSION}\n")
        (self.root/".env").write_text("SECRET=x\nGRAFANA_VERSION=latest\n")
        p,_,new,_=pin_plan(service(self.root)); self.assertEqual(p,self.root/".env"); self.assertIn("SECRET=x",new); self.assertIn("GRAFANA_VERSION=12.1.0",new)
    def test_multiple_files_override(self):
        (self.root/"compose.yml").write_text("services:\n  grafana: {}\n"); (self.root/"override.yml").write_text("services:\n  grafana:\n    image: grafana/grafana:latest\n")
        s=service(self.root); s.compose_files.append(str(self.root/"override.yml")); self.assertEqual(pin_plan(s)[0],self.root/"override.yml")
    def test_malformed_yaml(self):
        (self.root/"compose.yml").write_text("services: [bad")
        with self.assertRaises(Exception): pin_plan(service(self.root))
    def test_backup_and_restore_material(self):
        p=self.root/"compose.yml"; p.write_text("old"); b=backup_files([p],self.root,service(self.root)); self.assertEqual((b/"compose.yml").read_text(),"old"); self.assertTrue((b/"metadata.json").exists())
    def test_atomic_write(self):
        p=self.root/"x"; p.write_text("a"); os.chmod(p,0o640); atomic_write(p,"b"); self.assertEqual(p.read_text(),"b"); self.assertEqual(p.stat().st_mode&0o777,0o640)
    def test_atomic_replace_access_probe_is_removed_and_does_not_change_source(self):
        source=self.root/"compose.yml"; original=b"services: {}\n"; source.write_bytes(original)
        verify_atomic_replace_access([source,source])
        self.assertEqual(source.read_bytes(),original)
        self.assertEqual(list(self.root.glob(".upt-write-probe-*")),[])

    def test_atomic_replace_access_read_only_error_is_curated_and_keeps_errno(self):
        source=self.root/"compose.yml"; source.write_text("PRIVATE_COMPOSE_VALUE=do-not-log\n")
        with patch("docker_update_manager.compose.tempfile.mkstemp",
                   side_effect=OSError(errno.EROFS,"private diagnostic",str(source))):
            with self.assertRaises(ComposeSourceNotWritable) as raised:
                verify_atomic_replace_access([source])
        self.assertEqual(raised.exception.errno,errno.EROFS)
        self.assertNotIn("private diagnostic",str(raised.exception))
        self.assertNotIn(str(source),str(raised.exception))

    def test_atomic_replace_access_rejects_symlinked_source(self):
        source=self.root/"compose.yml"; source.write_text("services: {}\n")
        link=self.root/"compose-link.yml"
        try: link.symlink_to(source)
        except (NotImplementedError,OSError): self.skipTest("symlinks unavailable")
        with self.assertRaises(ComposeSourceNotWritable): verify_atomic_replace_access([link])

class PinOperationTests(unittest.TestCase):
    def setUp(self):
        discovery = patch("docker_update_manager.operations.discover", return_value=[])
        discovery.start(); self.addCleanup(discovery.stop)
        # No namespace relation in this legacy fixture; live gates are covered
        # by test_compose_namespace's bounded Docker/Compose fixture.
        namespace = patch("docker_update_manager.compose_namespace.mutation_refusal", return_value=None)
        namespace.start()
        self.addCleanup(namespace.stop)
        self.t=tempfile.TemporaryDirectory(); self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        self.source=self.root/"compose.yml"
        self.original="services:\n  grafana:\n    image: grafana/grafana:latest # keep\n"
        self.source.write_text(self.original)
        self.env=self.root/".env"; self.env.write_text("GRAFANA_VERSION=latest\n")
        self.state=State(self.root/"state")

    def assert_missing_digest_refused(self, invoke):
        with contextlib.ExitStack() as stack:
            calls=[stack.enter_context(patch("docker_update_manager.operations."+name))
                   for name in ("pin_plan", "backup_files", "atomic_write", "atomic_write_bytes",
                                "validate", "run", "run_compose_progress")]
            record=stack.enter_context(patch.object(self.state,"record"))
            invoke()
            for call in calls+[record]: call.assert_not_called()
        self.assertEqual(self.source.read_text(),self.original)
        self.assertEqual(self.env.read_text(),"GRAFANA_VERSION=latest\n")
        self.assertEqual(self.state.history("grafana"),[])
        self.assertEqual(list(self.state.root.rglob("metadata.json")),[])

    def test_missing_digest_refuses_both_pin_modes_before_any_side_effect(self):
        for local_digest in (None, ""):
            for digest_mode in (False, True):
                for dry_run in (False, True):
                    with self.subTest(local_digest=local_digest,digest_mode=digest_mode,dry_run=dry_run):
                        current=service(self.root,digest=local_digest)
                        self.assertFalse(current.local_build)
                        def invoke():
                            prompt=Mock(); output=Mock()
                            with self.assertRaises(PreMutationRefusal) as refused:
                                do_pin(current,self.state,digest=digest_mode,dry_run=dry_run,
                                       input_fn=prompt,output=output)
                            self.assertEqual(refused.exception.reason,"target_unavailable")
                            self.assertEqual(str(refused.exception),LOCAL_DIGEST_UNVERIFIED)
                            prompt.assert_not_called(); output.assert_not_called()
                        self.assert_missing_digest_refused(invoke)

    def test_explicit_cli_pin_without_digest_is_non_mutating(self):
        for local_digest in (None, ""):
            for digest_mode in (False, True):
                for dry_run in (False, True):
                    with self.subTest(local_digest=local_digest,digest_mode=digest_mode,dry_run=dry_run):
                        args=["pin","grafana","--yes","--no-progress"]
                        if digest_mode: args.append("--digest")
                        if dry_run: args.append("--dry-run")
                        def invoke():
                            with patch("docker_update_manager.cli.Config",return_value=Mock()), \
                                 patch("docker_update_manager.cli.State",return_value=self.state), \
                                 patch("docker_update_manager.cli.services",return_value=[service(self.root,digest=local_digest)]), \
                                 patch("docker_update_manager.cli.retention_cleanup") as retention, \
                                 patch("docker_update_manager.cli.quick_snapshot") as snapshot, \
                                 contextlib.redirect_stdout(io.StringIO()), \
                                 contextlib.redirect_stderr(io.StringIO()) as error:
                                self.assertEqual(main(args),30)
                            self.assertIn(LOCAL_DIGEST_UNVERIFIED,error.getvalue())
                            retention.assert_not_called(); snapshot.assert_not_called()
                        self.assert_missing_digest_refused(invoke)

    def test_valid_digest_keeps_version_and_digest_pin_behaviour(self):
        for digest_mode in (False, True):
            for dry_run in (False, True):
                with self.subTest(digest_mode=digest_mode,dry_run=dry_run):
                    self.source.write_text(self.original)
                    current=service(self.root)
                    with patch("docker_update_manager.operations.validate") as validate, \
                         patch("docker_update_manager.operations.run") as docker:
                        backup=do_pin(current,self.state,digest=digest_mode,dry_run=dry_run,
                                      yes=True,output=lambda _:None)
                    docker.assert_not_called()
                    if dry_run:
                        self.assertIsNone(backup); validate.assert_not_called()
                        self.assertEqual(self.source.read_text(),self.original)
                    else:
                        validate.assert_called_once_with(current)
                        self.assertEqual((backup/"compose.yml").read_text(),self.original)
                        target=current.image+"@"+current.digest if digest_mode else "grafana/grafana:12.1.0"
                        self.assertIn("image: "+target+" # keep",self.source.read_text())
                        self.assertEqual(self.state.history("grafana")[0]["action"],"pin")

class StateConfigCliTests(unittest.TestCase):
    def setUp(self):
        discovery = patch("docker_update_manager.removal.discover", return_value=[])
        discovery.start(); self.addCleanup(discovery.stop)
        # No namespace relation in this legacy fixture; live gates are covered
        # by test_compose_namespace's bounded Docker/Compose fixture.
        namespace = patch("docker_update_manager.compose_namespace.mutation_refusal", return_value=None)
        namespace.start()
        self.addCleanup(namespace.stop)
        self.t=tempfile.TemporaryDirectory(); self.root=Path(self.t.name)
    def tearDown(self): self.t.cleanup()
    def test_history_reports_explicit_manual_recovery_over_generic_image_availability(self):
        row={"id":7,"timestamp":"2026-09-25 12:00:00","stack":"monitoring","service":"grafana",
             "action":"update","old_version":"12.1.0","old_digest":None,"new_version":None,
             "new_digest":"sha256:"+"b"*64,"result":"FAILED","rollback_result":"MANUAL RECOVERY REQUIRED"}
        state=type("HistoryState",(),{"history":lambda _self,_service: [row]})()
        cfg=object(); p=parser()
        with patch("docker_update_manager.cli.rollback_points",return_value=[{"history_id":7,"status":"AVAILABLE"}]), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            execute(p.parse_args(["history"]),p,cfg,state)
        self.assertIn("MANUAL RECOVERY REQUIRED",output.getvalue())
        self.assertNotIn("AVAILABLE",output.getvalue())

        with patch("docker_update_manager.cli.rollback_points",return_value=[{"history_id":7,"status":"AVAILABLE"}]), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            execute(p.parse_args(["history","--json"]),p,cfg,state)
        self.assertEqual(json.loads(output.getvalue())[0]["rollback_status"],"MANUAL RECOVERY REQUIRED")
    def test_config_redacts_common_secret_keys(self):
        path=self.root/"config.yml"
        path.write_text("api_key: example\nauthorization: example\nwebhook_url: example\nsafe: visible\n")
        redacted=Config(str(path)).redacted()
        self.assertEqual(redacted["api_key"],"<redacted>")
        self.assertEqual(redacted["authorization"],"<redacted>")
        self.assertEqual(redacted["webhook_url"],"<redacted>")
        self.assertEqual(redacted["safe"],"visible")
    def test_history_and_rollback_protection(self):
        st=State(self.root); st.record(service="x",action="update",old_image_id="sha256:old",result="SUCCESS"); self.assertEqual(st.history("x")[0]["service"],"x"); self.assertIn("sha256:old",st.protected())
    def test_rollback_selects_stack_scoped_point_and_backup(self):
        st=State(self.root/"state"); media=self.root/"media-backup"; test=self.root/"test-backup"; media.mkdir(); test.mkdir()
        st.record(stack="media",service="app",action="update",old_image="repo/app:1.0",old_image_id="sha256:media",backup=str(media),result="SUCCESS")
        st.record(stack="test",service="app",action="update",old_image="repo/app:2.0",old_image_id="sha256:test",backup=str(test),result="SUCCESS")
        target=Service("app","cid","repo/app:3.0","new","sha256:new","3.0",None,"amd64","running","none","no",None,"test","app",str(self.root),[str(self.root/"compose.yml")])
        output=io.StringIO()
        with contextlib.redirect_stdout(output): do_rollback(target,st,dry_run=True,reporter=Reporter(enabled=False))
        self.assertIn("sha256:test",output.getvalue()); self.assertIn(str(test),output.getvalue()); self.assertNotIn(str(media),output.getvalue())
    def test_rollback_uses_explicit_stack_history_despite_unprovable_legacy_namesake(self):
        st=State(self.root/"state"); scoped=self.root/"scoped-backup"; scoped.mkdir()
        st.record(stack="media",service="app",action="update",old_image="repo/app:stable",old_image_id="sha256:media",result="SUCCESS")
        st.record(stack="test",service="app",action="update",old_image="repo/app:beta",old_image_id="sha256:test",backup=str(scoped),result="SUCCESS")
        st.record(service="app",action="update",old_image="repo/app:unknown",old_image_id="sha256:unknown",result="SUCCESS")
        target=Service("app","cid","repo/app:latest","new","sha256:new",None,None,"amd64","running","none","no",None,"test","app",str(self.root),[str(self.root/"compose.yml")])
        output=io.StringIO()
        with contextlib.redirect_stdout(output): do_rollback(target,st,dry_run=True,reporter=Reporter(enabled=False))
        self.assertIn("sha256:test",output.getvalue()); self.assertIn(str(scoped),output.getvalue()); self.assertNotIn("sha256:unknown",output.getvalue())
    def test_removal_rollback_protection_uses_stack_identity(self):
        st=State(self.root/"state")
        st.record(stack="media",service="app",action="update",old_image_id="sha256:shared",result="SUCCESS")
        st.record(stack="test",service="app",action="update",old_image_id="sha256:other",result="SUCCESS")
        target=Service("app","cid","repo/app:latest","new","sha256:new",None,None,"amd64","running","none","no",None,"test","app",str(self.root),[])
        self.assertEqual(_service_rollback_images(st,target),["sha256:other"])
        self.assertTrue(_other_active_rollback(st,"sha256:shared",target))
        self.assertFalse(_other_active_rollback(st,"sha256:other",target))
    def test_ambiguous_legacy_rollback_history_fails_before_selection(self):
        st=State(self.root/"state"); backup=self.root/"backup"; backup.mkdir()
        st.record(service="app",action="update",old_image="repo/app:old",old_image_id="sha256:old",backup=str(backup),result="SUCCESS")
        st.start_scan("duplicate-inventory",total=2)
        st.stage_scan_result("duplicate-inventory","complete",services=[
            {"service":{"stack":"media","compose_service":"app","key":"app","name":"app"},"status":"CURRENT"},
            {"service":{"stack":"test","compose_service":"app","key":"app","name":"app"},"status":"CURRENT"},
        ])
        st.mark_scan_terminal("duplicate-inventory","complete",emit_event=False)
        target=Service("app","cid","repo/app:latest","new","sha256:new",None,None,"amd64","running","none","no",None,"test","app",str(self.root),[])
        with self.assertRaisesRegex(ValueError,"legacy history.*no trustworthy stack metadata"):
            do_rollback(target,st,dry_run=True,reporter=Reporter(enabled=False))
    def test_ignored_service(self):
        p=self.root/"c.yml"; p.write_text("exclude:\n  services: [grafana]\n"); c=Config(str(p)); self.assertTrue(c.ignored(service(self.root)))
    def test_help(self): self.assertIn("update",parser().format_help())
    def test_canonical_program_name_is_upt(self): self.assertEqual(parser().prog,"upt")
    def test_retention_help_explains_protection_and_override(self):
        root=parser(); sub=next(a for a in root._actions if hasattr(a,"choices") and a.choices)
        help_text=sub.choices["retention"].format_help()
        self.assertIn("Protected images",help_text); self.assertIn("--override-protection",help_text); self.assertIn("required with",help_text)
        self.assertIn("unproven legacy history is refused",help_text)
    def test_retention_all_aliases(self):
        self.assertTrue(parser().parse_args(["retention","cleanup","--all","--dry-run"]).all_protected)
        self.assertTrue(parser().parse_args(["retention","cleanup","-all","--dry-run"]).all_protected)
        self.assertEqual(parser().parse_args(["retention","cleanup","--service","app","--stack","media","--dry-run"]).stack,"media")
    @patch("docker_update_manager.removal._remaining_container_images",return_value=set())
    @patch("docker_update_manager.removal.run")
    def test_remove_dry_run_changes_nothing(self,run_,*_):
        st=State(self.root); result=remove_service(service(self.root),st,images=True,dry_run=True,reporter=Reporter(enabled=False))
        self.assertFalse(result["removed"]); run_.assert_not_called(); self.assertEqual(st.history(),[])
    @patch("docker_update_manager.removal._remaining_container_images",return_value=set())
    @patch("docker_update_manager.removal.run",return_value="")
    def test_remove_standalone_preserves_volumes_and_removes_image(self,run_,*_):
        s=service(self.root); s.stack=None; s.compose_service=None; s.compose_files=[]; s.working_dir=None
        result=remove_service(s,State(self.root),images=True,yes=True,reporter=Reporter(enabled=False))
        self.assertTrue(result["removed"]); commands=[c.args[0] for c in run_.call_args_list]
        self.assertIn(["docker","rm","--force",s.container_id],commands); self.assertNotIn("-v",commands[0]); self.assertIn(["docker","image","rm",s.image_id],commands)
    @patch("docker_update_manager.removal._remaining_container_images",return_value=set())
    @patch("docker_update_manager.removal.run",return_value="")
    def test_remove_compose_is_service_scoped_without_volumes(self,run_,*_):
        s=service(self.root); remove_service(s,State(self.root),yes=True,reporter=Reporter(enabled=False))
        command=run_.call_args_list[0].args[0]; self.assertEqual(command[-4:],["rm","--stop","--force",s.key]); self.assertNotIn("--volumes",command)
    @patch("docker_update_manager.removal.run",return_value="abcdef123456\n")
    def test_remove_preview_excludes_short_form_of_selected_container_id(self,run_):
        self.assertEqual(_remaining_container_images("abcdef1234567890"),set()); self.assertEqual(run_.call_count,1)
    def test_remove_parser_accepts_purge_data_aliases(self):
        self.assertTrue(parser().parse_args(["remove","app","--purge-data","--dry-run"]).purge_data)
        self.assertTrue(parser().parse_args(["remove","app","--data","--dry-run"]).purge_data)
    def test_purge_data_never_deletes_docker_socket_or_system_trees(self):
        eligible,reason=_safe_bind_source("/var/run/docker.sock",[])
        self.assertFalse(eligible); self.assertEqual(reason,"protected system path")
        self.assertFalse(_safe_bind_source("/etc/example-app",[])[0])

    @patch("docker_update_manager.removal.resource_plan")
    @patch("docker_update_manager.removal.run")
    def test_remove_purge_data_dry_run_changes_nothing(self,run_,plan_):
        data=self.root/"data"; data.mkdir(); config=self.root/"compose.yml"; config.write_text("services: {}")
        plan_.return_value={"volumes":[{"name":"app_data","target":"/data","eligible":True,"reason":"exclusive named volume"}],"binds":[{"path":str(data),"target":"/config","eligible":True,"reason":"exclusive root-filesystem bind"}],"configs":[{"path":str(config),"eligible":True,"reason":"eligible source file"}],"shared_project_services":[]}
        result=remove_service(service(self.root),State(self.root/"state"),purge_data=True,dry_run=True,reporter=Reporter(enabled=False))
        self.assertFalse(result["removed"]); self.assertTrue(data.exists()); self.assertTrue(config.exists()); run_.assert_not_called()

    @patch("docker_update_manager.removal.resource_plan")
    @patch("docker_update_manager.removal.run",return_value="")
    def test_remove_purge_data_deletes_only_eligible_resources(self,run_,plan_):
        data=self.root/"data"; data.mkdir(); (data/"payload").write_text("x")
        shared=self.root/"shared"; shared.mkdir(); config=self.root/"compose.yml"; config.write_text("services: {}")
        plan_.return_value={"volumes":[{"name":"app_data","target":"/data","eligible":True,"reason":"exclusive named volume"},{"name":"shared_data","target":"/shared","eligible":False,"reason":"shared with another container"}],"binds":[{"path":str(data),"target":"/config","eligible":True,"reason":"exclusive root-filesystem bind"},{"path":str(shared),"target":"/shared","eligible":False,"reason":"shared with another container"}],"configs":[{"path":str(config),"eligible":True,"reason":"eligible source file"}],"shared_project_services":[]}
        result=remove_service(service(self.root),State(self.root/"state"),purge_data=True,yes=True,reporter=Reporter(enabled=False))
        self.assertTrue(result["removed"]); self.assertFalse(data.exists()); self.assertTrue(shared.exists()); self.assertFalse(config.exists())
        commands=[call.args[0] for call in run_.call_args_list]
        self.assertIn(["docker","volume","rm","app_data"],commands); self.assertNotIn(["docker","volume","rm","shared_data"],commands)

    @patch("docker_update_manager.removal.resource_plan",return_value={"volumes":[],"binds":[],"configs":[],"shared_project_services":[]})
    @patch("docker_update_manager.removal.run")
    def test_remove_purge_data_requires_exact_confirmation(self,run_,*_):
        result=remove_service(service(self.root),State(self.root/"state"),purge_data=True,input_fn=lambda _:"y",reporter=Reporter(enabled=False))
        self.assertFalse(result["removed"]); run_.assert_not_called()
    @patch("docker_update_manager.removal.run")
    def test_resource_plan_protects_multi_service_compose_config(self,run_):
        config=self.root/"compose.yml"; config.write_text("services: {}")
        bind=self.root/"project"; bind.mkdir()
        selected={"Mounts":[{"Type":"bind","Source":str(self.root),"Destination":"/config"}]}
        run_.side_effect=[json.dumps([selected]),"", "grafana\nworker\n"]
        plan=resource_plan(service(self.root))
        self.assertFalse(plan["configs"][0]["eligible"]); self.assertFalse(plan["binds"][0]["eligible"])
        self.assertIn("worker",plan["shared_project_services"])
    @patch("docker_update_manager.operations.remote_manifest",return_value={"digest":"sha256:"+"b"*64,"platforms":[{"os":"linux","architecture":"amd64"}],"version":"13.0","created":None})
    @patch("docker_update_manager.operations.run")
    def test_digest_pinned_update_dry_run_plans_new_exact_digest(self,run_,_remote):
        compose=self.root/"compose.yml"; compose.write_text("services:\n  grafana:\n    image: grafana/grafana:latest@sha256:"+"a"*64+"\n")
        s=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64,digest="sha256:"+"a"*64)
        do_update(s,State(self.root/"state"),dry_run=True,reporter=Reporter(enabled=False))
        run_.assert_not_called(); self.assertIn("sha256:"+"a"*64,compose.read_text())

    @patch("docker_update_manager.operations.remote_manifest",return_value={"digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None})
    @patch("docker_update_manager.operations.run")
    def test_pinned_update_source_write_refusal_happens_before_backup_or_pull(self,run_,_remote):
        compose=self.root/"compose.yml"
        original="services:\n  grafana:\n    image: grafana/grafana:latest@sha256:"+"a"*64+"\n"
        compose.write_text(original)
        current=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64,digest="sha256:"+"a"*64)
        state=State(self.root/"state"); checked=[]
        def refuse(path):
            checked.append(Path(path))
            raise ComposeSourceNotWritable(errno.EROFS)
        with self.assertRaises(ComposeSourceNotWritable):
            do_update(current,state,yes=True,reporter=Reporter(enabled=False),pre_source_write_check=refuse)
        self.assertEqual(checked,[compose])
        self.assertEqual(compose.read_text(),original)
        self.assertFalse(state.history())
        run_.assert_not_called()

    @patch("docker_update_manager.operations.remote_manifest",return_value={"digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None})
    @patch("docker_update_manager.operations.run")
    def test_pinned_update_preflight_targets_env_file_when_it_controls_image(self,run_,_remote):
        compose=self.root/"compose.yml"; env=self.root/".env"
        compose.write_text("services:\n  grafana:\n    image: ${GRAFANA_IMAGE}\n")
        env.write_text("GRAFANA_IMAGE=grafana/grafana:latest@sha256:"+"a"*64+"\n")
        current=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64,digest="sha256:"+"a"*64)
        checked=[]
        def stop_after_check(path): checked.append(Path(path)); raise ComposeSourceNotWritable(errno.EROFS)
        with self.assertRaises(ComposeSourceNotWritable):
            do_update(current,State(self.root/"state"),yes=True,reporter=Reporter(enabled=False),
                      pre_source_write_check=stop_after_check)
        self.assertEqual(checked,[env])
        run_.assert_not_called()

    @patch("docker_update_manager.operations.remote_manifest",return_value={"digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None})
    @patch("docker_update_manager.operations.validate")
    @patch("docker_update_manager.operations.run")
    @patch("docker_update_manager.operations.discover")
    def test_pinned_update_proceeds_when_atomic_source_probe_succeeds(self,discover_,run_,_validate,_remote):
        compose=self.root/"compose.yml"
        compose.write_text("services:\n  grafana:\n    image: grafana/grafana:latest@sha256:"+"a"*64+"\n")
        current=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64,digest="sha256:"+"a"*64)
        target="grafana/grafana:latest@sha256:"+"b"*64
        fresh=Service(**{**current.__dict__,"image":target,"image_id":"sha256:"+"b"*64,
                         "digest":"sha256:"+"b"*64,"version":"13.0"})
        discover_.return_value=[fresh]
        ordering=[]
        def execute(args,**_kwargs): ordering.append("pull" if args[:2]==["docker","pull"] else "recreate")
        run_.side_effect=execute
        def writable(path):
            verify_atomic_replace_access([path]); ordering.append("write-probe")
        result=do_update(current,State(self.root/"state"),yes=True,reporter=Reporter(enabled=False),
                         pre_source_write_check=writable,project_name=current.stack)
        self.assertTrue(result["updated"])
        self.assertEqual(compose.read_text(),"services:\n  grafana:\n    image: "+target+"\n")
        self.assertEqual(ordering,["write-probe","pull","recreate"])
        self.assertEqual(run_.call_args.args[0][run_.call_args.args[0].index("--project-name")+1],current.stack)
        self.assertEqual(_validate.call_args.kwargs["project_name"],current.stack)

    @patch("docker_update_manager.operations.remote_manifest",return_value={"digest":"sha256:"+"b"*64,"platforms":[{"os":"linux","architecture":"amd64"}],"version":"13.0","created":None})
    @patch("docker_update_manager.operations.run_compose_progress")
    @patch("docker_update_manager.operations.run")
    @patch("docker_update_manager.operations.discover")
    def test_update_output_callback_reuses_service_scoped_core_path(self,discover_,run_,pull_,_remote):
        compose=self.root/"compose.yml"
        compose.write_text("services:\n  grafana:\n    image: grafana/grafana:latest\n")
        current=service(self.root)
        fresh=Service("grafana","cid","grafana/grafana:latest","new-iid","sha256:"+"b"*64,"13.0",None,"amd64","running","healthy","unless-stopped",None,"monitoring","grafana",str(self.root),[str(compose)])
        discover_.return_value=[fresh]
        state=State(self.root/"state")
        output=[]
        ordering=[]
        pull_.side_effect=lambda *_args,**_kwargs: ordering.append("pull")
        run_.side_effect=lambda *_args,**_kwargs: ordering.append("up")
        result=do_update(current,state,yes=True,reporter=Reporter(enabled=False),output=output.append,
                         audit_context={"origin":"web","operation_id":"a"*32},
                         project_name=current.stack,
                         pre_source_write_check=lambda _path: self.fail("mutable-tag update must not probe Compose write access"),
                         pre_pull_check=lambda: ordering.append("before-pull"),
                         pre_recreate_check=lambda: ordering.append("before-recreate"))
        pull_args=pull_.call_args.args[0]
        self.assertEqual(pull_args[-2:],["pull","grafana"])
        self.assertEqual(pull_args[pull_args.index("--project-name")+1],current.stack)
        recreate=run_.call_args.args[0]
        self.assertEqual(recreate[-4:], ["up","-d","--no-deps","grafana"])
        self.assertEqual(recreate[recreate.index("--project-name")+1],current.stack)
        self.assertEqual(result["version"],"13.0")
        self.assertEqual(ordering,["before-pull","pull","before-recreate","up"])
        history=state.history("grafana")[0]
        self.assertEqual(json.loads(history["details"]),{"origin":"web","operation_id":"a"*32})
        self.assertTrue(output)

    @patch("docker_update_manager.operations.remote_manifest",return_value={"digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None})
    @patch("docker_update_manager.operations.run")
    def test_digest_pin_pre_recreate_refusal_does_not_reapply_compose(self,run_,_remote):
        compose=self.root/"compose.yml"
        original="services:\n  grafana:\n    image: grafana/grafana:latest@sha256:"+"a"*64+"\n"
        compose.write_text(original)
        current=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64)
        state=State(self.root/"state")
        def refuse(): raise RuntimeError("Compose configuration identity changed")
        with self.assertRaisesRegex(RuntimeError,"original Compose pin was unchanged"):
            do_update(current,state,yes=True,reporter=Reporter(enabled=False),pre_recreate_check=refuse)
        self.assertEqual(compose.read_text(),original)
        self.assertEqual([call.args[0][:2] for call in run_.call_args_list],[["docker","pull"]])
        history=state.history("grafana")[0]
        self.assertEqual(history["result"],"FAILED")
        self.assertEqual(json.loads(history["details"])["configuration_restored"],True)

    @patch("docker_update_manager.operations.validate")
    @patch("docker_update_manager.operations.remote_manifest",return_value={"digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None})
    @patch("docker_update_manager.operations.run")
    def test_digest_pin_post_edit_drift_refusal_restores_pin_without_recreate(self,run_,_remote,_validate):
        compose=self.root/"compose.yml"
        original="services:\n  grafana:\n    image: grafana/grafana:latest@sha256:"+"a"*64+"\n"
        compose.write_text(original)
        current=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64)
        state=State(self.root/"state")
        target=[]
        def refuse(image):
            target.append(image)
            raise RuntimeError("unrelated Compose service configuration changed")

        # Failed pre-recreate update: recovery discovery has no replacement.
        with patch("docker_update_manager.operations.discover", return_value=[]), \
             self.assertRaisesRegex(RuntimeError,"original Compose pin was restored"):
            do_update(current,state,yes=True,reporter=Reporter(enabled=False),
                      post_pin_check=refuse)

        self.assertEqual(target,["grafana/grafana:latest@sha256:"+"b"*64])
        self.assertEqual(compose.read_text(),original)
        self.assertEqual([call.args[0][:2] for call in run_.call_args_list],[ ["docker","pull"] ])
        self.assertEqual(state.history("grafana")[0]["result"],"FAILED")

    def test_digest_pin_failure_allows_automatic_recovery_when_web_guard_matches(self):
        compose=self.root/"compose.yml"
        original="services:\n  grafana:\n    image: grafana/grafana:latest@sha256:"+"a"*64+"\n"
        compose.write_text(original)
        current=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64)
        state=State(self.root/"state")
        events=[]; up_count=0

        def run(args,**_kwargs):
            nonlocal up_count
            if args[:2]==["docker","pull"]:
                events.append("pull"); return ""
            if "up" in args:
                up_count+=1
                events.append("update-recreate" if up_count==1 else "recovery-recreate")
                if up_count==1: raise RuntimeError("replacement failed health verification")
            return ""

        def verify_recovery():
            events.append("verify-original-model")
            self.assertEqual(compose.read_text(),original)

        with patch("docker_update_manager.operations.remote_manifest",return_value={
                "digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None}), \
             patch("docker_update_manager.operations.validate"), \
             patch("docker_update_manager.operations.discover",return_value=[]), \
             patch("docker_update_manager.operations.run",side_effect=run):
            with self.assertRaisesRegex(RuntimeError,"original Compose pin was restored"):
                do_update(current,state,yes=True,reporter=Reporter(enabled=False),pre_recovery_check=verify_recovery)

        self.assertEqual(events,["pull","update-recreate","verify-original-model","recovery-recreate"])
        history=state.history("grafana")[0]
        self.assertEqual(history["result"],"FAILED")
        self.assertIn(current.image_id,state.protected())
        backup=Path(history["backup"])
        self.assertTrue((backup/"metadata.json").is_file())
        self.assertEqual((backup/"compose.yml").read_text(),original)
        self.assertEqual(json.loads(history["details"])["recovery_required"],False)

    def test_digest_pin_failure_refuses_recovery_on_web_guard_drift_and_retains_recovery(self):
        compose=self.root/"compose.yml"
        original="services:\n  grafana:\n    image: grafana/grafana:latest@sha256:"+"a"*64+"\n"
        compose.write_text(original)
        current=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64)
        state=State(self.root/"state")
        events=[]; up_count=0

        def run(args,**_kwargs):
            nonlocal up_count
            if args[:2]==["docker","pull"]:
                events.append("pull"); return ""
            if "up" in args:
                up_count+=1; events.append("update-recreate")
                raise RuntimeError("replacement failed health verification")
            return ""

        def refuse_recovery():
            events.append("compose-drift-detected")
            raise RecoveryRefused("Compose model changed")

        with patch("docker_update_manager.operations.remote_manifest",return_value={
                "digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None}), \
             patch("docker_update_manager.operations.validate"), \
             patch("docker_update_manager.operations.discover", return_value=[]), \
             patch("docker_update_manager.operations.run",side_effect=run):
            with self.assertRaises(RecoveryRequired):
                do_update(current,state,yes=True,reporter=Reporter(enabled=False),
                          audit_context={"origin":"web","operation_id":"a"*32},
                          pre_recovery_check=refuse_recovery)

        self.assertEqual(events,["pull","update-recreate","compose-drift-detected"])
        history=state.history("grafana")[0]
        self.assertEqual(history["result"],"FAILED")
        self.assertEqual(history["rollback_result"],"MANUAL RECOVERY REQUIRED")
        details=json.loads(history["details"])
        self.assertTrue(details["recovery_required"])
        self.assertTrue(details["configuration_restored"])
        self.assertEqual(details["error"],"details redacted for web-triggered operation")
        self.assertIn(current.image_id,state.protected())
        with state.connect() as connection:
            reference=connection.execute("SELECT image_id,expired FROM rollback_refs WHERE history_id=?",(history["id"],)).fetchone()
        self.assertEqual(tuple(reference),(current.image_id,0))
        backup=Path(history["backup"])
        self.assertTrue((backup/"metadata.json").is_file())
        self.assertEqual((backup/"compose.yml").read_text(),original)

    def test_failed_automatic_recovery_recreation_is_manual_and_not_retried(self):
        compose=self.root/"compose.yml"
        original="services:\n  grafana:\n    image: grafana/grafana:latest@sha256:"+"a"*64+"\n"
        compose.write_text(original)
        current=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64)
        state=State(self.root/"state")
        calls=[]; recreate_count=0

        def run(args,**_kwargs):
            nonlocal recreate_count
            calls.append(args)
            if args[:2]==["docker","pull"]:
                return ""
            if "up" in args:
                recreate_count+=1
                if recreate_count==1:
                    raise RuntimeError("replacement recreate failed")
                raise RuntimeError("recovery recreate failed")
            return ""

        with patch("docker_update_manager.operations.remote_manifest",return_value={
                "digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None}), \
             patch("docker_update_manager.operations.validate"), \
             patch("docker_update_manager.operations.discover",return_value=[]), \
             patch("docker_update_manager.operations.run",side_effect=run):
            with self.assertRaises(RecoveryFailed):
                do_update(current,state,yes=True,reporter=Reporter(enabled=False),
                          audit_context={"origin":"web","operation_id":"c"*32},
                          pre_recovery_check=lambda: None)

        self.assertEqual(recreate_count,2,"one replacement and one recovery recreation only")
        self.assertEqual(sum("up" in args for args in calls),2)
        history=state.history("grafana")[0]
        self.assertEqual(history["result"],"FAILED")
        self.assertEqual(history["rollback_result"],"MANUAL RECOVERY REQUIRED")
        details=json.loads(history["details"])
        self.assertTrue(details["recovery_required"])
        self.assertTrue(details["recovery_attempted"])
        self.assertEqual(details["recovery_result"],"failed")
        self.assertEqual(details["recovery_failure"],"recovery recreation command failed")
        self.assertEqual(details["error"],"details redacted for web-triggered operation")
        self.assertIn(current.image_id,state.protected())
        with state.connect() as connection:
            reference=connection.execute("SELECT image_id,expired FROM rollback_refs WHERE history_id=?",(history["id"],)).fetchone()
        self.assertEqual(tuple(reference),(current.image_id,0))
        self.assertEqual(calls[0][:2], ["docker", "pull"])
        recreate_calls=[args for args in calls if "up" in args]
        self.assertEqual(len(recreate_calls),2)
        self.assertTrue(all(args[-4:] == ["up","-d","--no-deps","grafana"] for args in recreate_calls))
        self.assertEqual(compose.read_text(),original)
        backup=Path(history["backup"])
        self.assertTrue((backup/"metadata.json").is_file())
        self.assertEqual((backup/"compose.yml").read_text(),original)

    def test_web_mutable_pull_uses_reviewed_digest_and_refuses_changed_local_alias(self):
        compose=self.root/"compose.yml"
        original="services:\n  grafana:\n    image: grafana/grafana:latest\n"
        compose.write_text(original)
        state=State(self.root/"state")
        digest="sha256:"+"b"*64
        target=f"grafana/grafana@{digest}"
        phases=[]; commands=[]; resolved_checks=0

        def guard(stage, value):
            nonlocal resolved_checks
            phases.append(stage)
            if stage=="registry":
                self.assertEqual(value["digest"],digest)
            elif stage=="pulled":
                self.assertEqual(value,target)
            elif stage=="resolved":
                resolved_checks+=1
                if resolved_checks==2:
                    raise ReviewedTargetChanged("local alias no longer matches reviewed digest")

        def run(args,**_kwargs):
            commands.append(args)
            return ""

        with patch("docker_update_manager.operations.remote_manifest",return_value={
                "digest":digest,"platforms":[],"version":"13.0","created":None}), \
             patch("docker_update_manager.operations.run",side_effect=run):
            with self.assertRaises(ReviewedTargetChanged):
                do_update(service(self.root),state,yes=True,reporter=Reporter(enabled=False),
                          output=lambda *_:None,target_guard=guard,
                          pre_recreate_check=lambda:None)

        self.assertEqual(phases,["registry","pulled","resolved","resolved"])
        self.assertEqual(commands[0], ["docker","pull",target])
        self.assertEqual(commands[1], ["docker","image","tag",target,"grafana/grafana:latest"])
        self.assertFalse(any("up" in command for command in commands))
        self.assertEqual(compose.read_text(),original)
        self.assertEqual(state.history("grafana")[0]["result"],"FAILED")

    def test_web_mutable_reviewed_target_a_passes_exact_digest_to_recreation(self):
        compose=self.root/"compose.yml"
        compose.write_text("services:\n  grafana:\n    image: grafana/grafana:latest\n")
        current=service(self.root)
        digest="sha256:"+"b"*64
        target=f"grafana/grafana@{digest}"
        fresh=Service("grafana","cid",current.image,"new-iid",digest,"13.0",None,"amd64","running","healthy","unless-stopped",None,"monitoring","grafana",str(self.root),[str(compose)])
        state=State(self.root/"state")
        calls=[]; phases=[]

        def run(args,**_kwargs):
            calls.append(args)
            return ""

        def guard(stage,value):
            phases.append(stage)
            if stage=="registry": self.assertEqual(value["digest"],digest)
            else: self.assertEqual(value,target if stage=="pulled" else current.image)

        with patch("docker_update_manager.operations.remote_manifest",return_value={
                "digest":digest,"platforms":[],"version":"13.0","created":None}), \
             patch("docker_update_manager.operations.run",side_effect=run), \
             patch("docker_update_manager.operations.discover",return_value=[fresh]):
            result=do_update(current,state,yes=True,reporter=Reporter(enabled=False),
                             output=lambda *_:None,target_guard=guard,
                             pre_recreate_check=lambda: phases.append("compose-check"))

        self.assertTrue(result["updated"])
        self.assertEqual(calls[0], ["docker","pull",target])
        self.assertEqual(calls[1], ["docker","image","tag",target,current.image])
        self.assertEqual(calls[2][-6:], ["up","-d","--no-deps","--pull","never","grafana"])
        self.assertEqual(phases, ["registry","pulled","resolved","compose-check","resolved"])

    def test_digest_pin_failure_preserves_concurrent_source_edit_and_marks_manual_recovery(self):
        compose=self.root/"compose.yml"
        original="services:\n  grafana:\n    image: grafana/grafana:latest@sha256:"+"a"*64+"\n"
        concurrent="services:\n  grafana:\n    image: operator/edited:tag\n"
        compose.write_text(original)
        current=service(self.root,image="grafana/grafana:latest@sha256:"+"a"*64)
        state=State(self.root/"state")
        events=[]

        def run(args,**_kwargs):
            if args[:2]==["docker","pull"]:
                events.append("pull"); return ""
            if "up" in args:
                events.append("failed-update-recreate")
                compose.write_text(concurrent)
                raise RuntimeError("replacement failed health verification")
            return ""

        def recovery_check(): events.append("unexpected-recovery-check")

        with patch("docker_update_manager.operations.remote_manifest",return_value={
                "digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None}), \
             patch("docker_update_manager.operations.validate"), \
             patch("docker_update_manager.operations.discover", return_value=[]), \
             patch("docker_update_manager.operations.run",side_effect=run):
            with self.assertRaises(RecoveryRequired):
                do_update(current,state,yes=True,reporter=Reporter(enabled=False),
                          audit_context={"origin":"web","operation_id":"b"*32},
                          pre_recovery_check=recovery_check)

        self.assertEqual(events,["pull","failed-update-recreate"])
        self.assertEqual(compose.read_text(),concurrent,"the concurrent source edit must not be overwritten")
        history=state.history("grafana")[0]
        self.assertEqual(history["rollback_result"],"MANUAL RECOVERY REQUIRED")
        self.assertFalse(json.loads(history["details"])["configuration_restored"])
        self.assertIn(current.image_id,state.protected())
        backup=Path(history["backup"])
        self.assertTrue((backup/"metadata.json").is_file())
        self.assertEqual((backup/"compose.yml").read_text(),original)
    @patch("docker_update_manager.operations.remote_manifest",return_value={"digest":"sha256:"+"b"*64,"platforms":[],"version":"13.0","created":None})
    @patch("docker_update_manager.operations.run_compose_progress",side_effect=RuntimeError("registry password=fixture-secret"))
    def test_web_update_failure_history_redacts_raw_error_text(self,_pull_,_remote):
        compose=self.root/"compose.yml"
        compose.write_text("services:\n  grafana:\n    image: grafana/grafana:latest\n")
        state=State(self.root/"state")
        with self.assertRaisesRegex(RuntimeError,"fixture-secret"):
            do_update(service(self.root),state,yes=True,reporter=Reporter(enabled=False),
                      output=lambda *_:None,audit_context={"origin":"web","operation_id":"a"*32})
        history=state.history("grafana")[0]
        details=json.loads(history["details"])
        self.assertEqual(details["origin"],"web")
        self.assertEqual(details["error"],"details redacted for web-triggered operation")
        self.assertNotIn("fixture-secret",history["details"])
    def test_all_subcommands_parse_help(self):
        for name in ("scan","update","pin","rollback","cleanup","web"):
            with self.assertRaises(SystemExit) as x: parser().parse_args([name,"--help"])
            self.assertEqual(x.exception.code,0)
    def test_unknown_suggestion(self): self.assertEqual(main(["updte"]),30)
    def test_dry_run_no_command(self):
        from docker_update_manager.operations import do_pull
        with patch("docker_update_manager.operations.run") as r: do_pull(service(self.root),True); r.assert_not_called()

if __name__=="__main__": unittest.main()
