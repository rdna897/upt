import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import tempfile, unittest
from unittest.mock import patch
from pathlib import Path
from docker_update_manager.conversion import build_conversion, render_compose, generate_conversion, default_stack_path, rollback_conversion
from docker_update_manager.models import Service
from docker_update_manager.progress import Reporter
from docker_update_manager.state import State

CONTAINER={"Id":"abcdef1234567890","Image":"sha256:image","Config":{"Image":"portainer/portainer-ce:latest","Env":["PATH=/bin","ADMIN_TOKEN=example-value-not-a-credential"],"Cmd":["/portainer"],"Entrypoint":None,"Hostname":"abcdef123456","Labels":{},"Tty":False,"OpenStdin":False},"HostConfig":{"RestartPolicy":{"Name":"always"},"PortBindings":{"9443/tcp":[{"HostIp":"0.0.0.0","HostPort":"9443"},{"HostIp":"::","HostPort":"9443"}]},"NetworkMode":"default","Privileged":False},"Mounts":[{"Type":"volume","Name":"portainer_data","Source":"/var/lib/docker/volumes/portainer_data/_data","Destination":"/data","RW":True},{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":True}],"NetworkSettings":{"Networks":{"bridge":{}}},"State":{"Status":"running"}}
IMAGE={"Config":{"Env":["PATH=/bin"],"Cmd":["/portainer"],"Entrypoint":None,"Labels":{}}}

def service(): return Service("portainer","cid","portainer/portainer-ce:latest","sha256:image","sha256:"+"a"*64,None,None,"amd64","running","none","always",None)

class ConversionTests(unittest.TestCase):
    def setUp(self):
        # Namespace safety uses a dedicated bounded fixture in test_compose_namespace.
        namespace = patch("docker_update_manager.compose_namespace.mutation_refusal", return_value=None)
        namespace.start()
        self.addCleanup(namespace.stop)

    def test_default_conversion_path_is_root_stack_folder(self):
        self.assertEqual(default_stack_path("portainer"),Path("/root/portainer-stack"))
        self.assertEqual(default_stack_path("my stack"),Path("/root/my-stack"))
    @patch("docker_update_manager.conversion._image",return_value=IMAGE)
    @patch("docker_update_manager.conversion._inspect",return_value=CONTAINER)
    def test_exact_digest_and_runtime_resources(self,_inspect,_image):
        compose,env,summary,_=build_conversion(service()); node=compose["services"]["portainer"]
        self.assertIn("@sha256:",node["image"]); self.assertEqual(node["ports"],["9443:9443/tcp"])
        self.assertIn("portainer_data:/data",node["volumes"]); self.assertTrue(compose["volumes"]["portainer_data"]["external"])
        self.assertNotIn("hostname",node)
        self.assertIn('ADMIN_TOKEN="example-value-not-a-credential"',env); self.assertNotIn("example-value-not-a-credential",render_compose(compose)); self.assertEqual(summary["environment_keys"],["ADMIN_TOKEN"])
    def test_refuses_existing_compose_service(self):
        s=service(); s.stack="existing"
        with self.assertRaises(ValueError): build_conversion(s)
    @patch("docker_update_manager.conversion._image",return_value=IMAGE)
    @patch("docker_update_manager.conversion._inspect",return_value=CONTAINER)
    def test_track_tag_preserves_update_channel(self,_inspect,_image):
        compose,_,summary,_=build_conversion(service(),track_tag=True)
        self.assertEqual(compose["services"]["portainer"]["image"],"portainer/portainer-ce:latest")
        self.assertTrue(summary["track_tag"])
    @patch("docker_update_manager.conversion.build_conversion")
    def test_dry_run_writes_nothing(self,build):
        build.return_value=({"services":{"portainer":{"image":"sha256:x"}}},"SECRET=x\n",{"environment_keys":["SECRET"],"service":"portainer"},CONTAINER)
        with __import__("tempfile").TemporaryDirectory() as tmp:
            class State: root=Path(tmp)/"state"
            generate_conversion(service(),State,Path(tmp)/"out",dry_run=True,reporter=Reporter(enabled=False))
            self.assertFalse((Path(tmp)/"out").exists())
    def test_conversion_rollback_refuses_cross_stack_namesake_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            state=State(Path(tmp))
            state.record(stack="portainer-stack",service="portainer",action="convert",result="SUCCESS",details={"backup_container":"portainer-upt-backup"})
            state.record(stack="other-stack",service="portainer",action="convert",result="SUCCESS",details={"backup_container":"other-portainer-backup"})
            with self.assertRaisesRegex(ValueError,"multiple stacks"):
                rollback_conversion("portainer",state,yes=True,reporter=Reporter(enabled=False))
    @patch("docker_update_manager.conversion.run",return_value="")
    def test_conversion_rollback_records_resolved_stack(self,_run):
        with tempfile.TemporaryDirectory() as tmp:
            state=State(Path(tmp))
            state.record(stack="portainer-stack",service="portainer",action="convert",old_image="portainer/standalone:1",new_image="portainer/compose:1",old_image_id="sha256:standalone",result="SUCCESS",details={"backup_container":"portainer-upt-backup"})
            state.record(service="portainer",action="convert",old_image="portainer/old:legacy",result="SUCCESS",details={"backup_container":"unknown-legacy-backup"})
            retained=service(); retained.name="portainer-upt-backup"; retained.container_id="retained"
            with patch("docker_update_manager.conversion.discover", return_value=[service(), retained]):
                rollback_conversion("portainer",state,yes=True,reporter=Reporter(enabled=False))
            rows=state.history_for_service("portainer-stack","portainer")
            rollback=next(row for row in rows if row["action"]=="convert-rollback")
            self.assertEqual(rollback["stack"],"portainer-stack")
            self.assertIn(["docker","rename","portainer-upt-backup","portainer"],[call.args[0] for call in _run.call_args_list])

if __name__=="__main__": unittest.main()
