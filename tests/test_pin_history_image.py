"""Regression: pin History rows record only the resulting image reference.

A non-digest pin previously stored the whole rewritten Compose document in
history.new_image, persisting anything inline in that file (including secrets).
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import contextlib, io, json, tempfile, unittest
from pathlib import Path
from unittest.mock import Mock, patch
from docker_update_manager.cli import main
from docker_update_manager.models import Service
from docker_update_manager.operations import do_pin
from docker_update_manager.registry import tracking_image
from docker_update_manager.state import State

FAKE_SECRET="upt-fake-secret-0123456789abcdef"
DIGEST="sha256:"+"a"*64
COMPOSE=f"""name: monitoring
services:
  grafana:
    image: {{image}} # keep
    environment:
      GF_SECURITY_ADMIN_PASSWORD: {FAKE_SECRET}
      GF_DATABASE_URL: postgres://grafana:{FAKE_SECRET}@db:5432/grafana
    volumes:
      - grafana-data:/var/lib/grafana
  db:
    image: postgres:16.4
    environment:
      POSTGRES_PASSWORD: {FAKE_SECRET}
volumes:
  grafana-data:
"""

def service(root,image="grafana/grafana:latest",version="12.1.0"):
    return Service("grafana","cid",image,"sha256:"+"b"*64,DIGEST,version,None,"amd64","running","none",
                   "unless-stopped",None,"monitoring","grafana",str(root),[str(root/"compose.yml")])

class PinHistoryImageTests(unittest.TestCase):
    def setUp(self):
        namespace=patch("docker_update_manager.compose_namespace.mutation_refusal",return_value=None)
        namespace.start(); self.addCleanup(namespace.stop)
        t=tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup)
        self.root=Path(t.name); self.source=self.root/"compose.yml"
        self.state=State(self.root/"state")
        discovery=patch("docker_update_manager.operations.discover",return_value=[])
        discovery.start(); self.addCleanup(discovery.stop)

    def pin(self,current,digest):
        with patch("docker_update_manager.operations.validate"), patch("docker_update_manager.operations.run") as docker:
            do_pin(current,self.state,digest=digest,yes=True,output=lambda _:None)
        docker.assert_not_called()
        rows=self.state.history("grafana"); self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["action"],"pin")
        return rows[0]

    def assert_image_fields_clean(self,row):
        for key in ("old_image","new_image"):
            value=row[key]
            self.assertIsInstance(value,str)
            self.assertNotIn(FAKE_SECRET,value)
            self.assertNotIn("\n",value)
            self.assertNotIn("services:",value)
            self.assertNotIn("environment",value)
        # Nothing else in the newly written row may carry the secret either.
        self.assertNotIn(FAKE_SECRET,json.dumps(row))

    def test_version_pin_records_only_resulting_image_reference(self):
        self.source.write_text(COMPOSE.format(image="grafana/grafana:latest"))
        row=self.pin(service(self.root),digest=False)
        self.assertEqual(row["new_image"],"grafana/grafana:12.1.0")
        self.assertEqual(row["old_image"],"grafana/grafana:latest")
        self.assertIn("image: grafana/grafana:12.1.0 # keep",self.source.read_text())
        self.assert_image_fields_clean(row)

    def test_digest_pin_records_exact_resulting_image(self):
        self.source.write_text(COMPOSE.format(image="grafana/grafana:latest"))
        row=self.pin(service(self.root),digest=True)
        self.assertEqual(row["new_image"],"grafana/grafana:latest@"+DIGEST)
        self.assertEqual(row["old_digest"],DIGEST)
        self.assertIn(f"image: {row['new_image']} # keep",self.source.read_text())
        self.assert_image_fields_clean(row)

    def test_env_controlled_version_pin_records_only_resulting_image_reference(self):
        self.source.write_text(COMPOSE.format(image="grafana/grafana:${GRAFANA_VERSION}"))
        env=self.root/".env"; env.write_text(f"GRAFANA_VERSION=latest\nGRAFANA_ADMIN_TOKEN={FAKE_SECRET}\n")
        row=self.pin(service(self.root),digest=False)
        self.assertEqual(row["new_image"],"grafana/grafana:12.1.0")
        self.assertIn("GRAFANA_VERSION=12.1.0\n",env.read_text())
        self.assert_image_fields_clean(row)

    def test_history_json_output_does_not_expose_compose_secret(self):
        self.source.write_text(COMPOSE.format(image="grafana/grafana:latest"))
        self.pin(service(self.root),digest=False)
        out=io.StringIO()
        with patch("docker_update_manager.cli.Config",return_value=Mock()), \
             patch("docker_update_manager.cli.State",return_value=self.state), \
             patch("docker_update_manager.cli.rollback_points",return_value=[]), \
             contextlib.redirect_stdout(out):
            self.assertEqual(main(["history","grafana","--json"]),0)
        rows=json.loads(out.getvalue())
        self.assertEqual([r["new_image"] for r in rows],["grafana/grafana:12.1.0"])
        self.assertNotIn(FAKE_SECRET,out.getvalue())

    def test_tracking_channel_recovery_still_uses_pin_history(self):
        # An untagged digest pin must still let scans recover the original channel from history.
        self.source.write_text(COMPOSE.format(image="grafana/grafana"))
        row=self.pin(service(self.root,image="grafana/grafana"),digest=True)
        self.assertEqual(row["new_image"],"grafana/grafana@"+DIGEST)
        pinned=service(self.root,image=row["new_image"])
        self.assertEqual(tracking_image(pinned,self.state),"grafana/grafana")

if __name__=="__main__": unittest.main()
