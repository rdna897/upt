import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import io, json, os, sqlite3, tempfile, unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from docker_update_manager.config import Config
from docker_update_manager.diskdiag import parse_size, snapshot_diff, container_sizes, container_logs, journal_usage, deleted_open, largest_dirs, fs_metrics
from docker_update_manager.retention import expires, expired, inventory, cleanup, rollback_points
from docker_update_manager.state import State
from docker_update_manager.progress import Reporter
from docker_update_manager.system import CommandError

class Cfg:
    def __init__(self,root):
        self.data={"retention":{"recovery_days":7,"compose_backups_days":7,"rollback_images_days":7,"operational_logs_days":7,"temporary_files_days":7,"disk_history_days":30}}
        self.log_dir=Path(root)/"logs"

class DiskTests(unittest.TestCase):
    def test_size_parsing(self): self.assertEqual(parse_size("1.5GiB"),int(1.5*1024**3))
    def test_snapshot_diff_growth(self):
        old={"timestamp":"2026-08-26T00:00:00+00:00","filesystem":{"used":100},"paths":{"/var":40},"docker":{},"journal":{}}
        new={"timestamp":"2026-08-27T00:00:00+00:00","filesystem":{"used":180},"paths":{"/var":110},"docker":{},"journal":{}}
        d=snapshot_diff(new,old); self.assertEqual(d["used_change"],80); self.assertEqual(d["changes"]["/var"],70)
    def test_disk_history_roundtrip(self):
        with tempfile.TemporaryDirectory() as t:
            s=State(Path(t)); s.save_disk_snapshot("quick",{"filesystem":{"used":1}}); self.assertEqual(s.disk_snapshots()[0]["metrics"]["filesystem"]["used"],1)
    @patch("docker_update_manager.diskdiag.run",return_value='100\t/var\n50\t/var/log\n')
    @patch("docker_update_manager.diskdiag.os.stat")
    def test_largest_uses_same_filesystem_du(self,stat,run):
        stat.return_value.st_dev=1; largest_dirs("/var",10,2); self.assertIn("-x",run.call_args.args[0])
    @patch("docker_update_manager.diskdiag.run",side_effect=['{"Names":"a","ID":"1","Size":"1.2GB (virtual 2GB)"}\n'])
    def test_writable_layer_parsing(self,_): self.assertGreater(container_sizes()[0]["size"],1_000_000_000)
    @patch("docker_update_manager.diskdiag.os.stat")
    @patch("docker_update_manager.diskdiag.run")
    def test_docker_log_size(self,run_,stat_):
        run_.side_effect=["id\n",json.dumps([{"Name":"/a","LogPath":"/x.log","HostConfig":{"LogConfig":{"Type":"json-file","Config":{}}}}])]; stat_.return_value.st_size=123
        self.assertEqual(container_logs()[0]["size"],123)
    @patch("docker_update_manager.diskdiag.run")
    def test_journal_parsing(self,run_):
        run_.side_effect=["Archived and active journals take up 1.4G in the file system.\n","2026-08-01T00:00:00+0000 msg\n"]
        self.assertGreater(journal_usage()["size"],1_000_000_000)
    @patch("docker_update_manager.diskdiag.shutil.which",return_value="/usr/bin/lsof")
    @patch("docker_update_manager.diskdiag.run",return_value="p12\ncpython\nf3\ns430\nn/tmp/x (deleted)\n")
    def test_deleted_open_parsing(self,*_): self.assertEqual(deleted_open()["total"],430)
    @patch("docker_update_manager.diskdiag.shutil.which",return_value="/usr/bin/lsof")
    @patch("docker_update_manager.diskdiag.run",return_value="p12\ndotnet\nf3\ns2199023255552\nn/memfd:doublemapper (deleted)\n")
    def test_deleted_open_ignores_memory_backed_sparse_mapping(self,*_): self.assertEqual(deleted_open()["total"],0)
    @patch("docker_update_manager.diskdiag.os.statvfs")
    def test_inode_reporting(self,sv):
        x=sv.return_value; x.f_blocks=100; x.f_frsize=1; x.f_bavail=20; x.f_files=1000; x.f_favail=100
        self.assertEqual(fs_metrics()["inodes_pct"],90.0)

class RetentionTests(unittest.TestCase):
    def test_seven_day_expiry(self):
        created=datetime(2026,8,1,tzinfo=timezone.utc); self.assertEqual(expires(created,7),datetime(2026,8,8,tzinfo=timezone.utc)); self.assertTrue(expired(created,7,datetime(2026,8,9,tzinfo=timezone.utc)))
    def test_retention_defaults(self): self.assertEqual(Config("/nonexistent").data["retention"]["recovery_days"],7)
    def test_backup_inventory_and_managed_usage(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)/"state"); p=state.root/"backups"/"old"; p.mkdir(parents=True); (p/"x").write_bytes(b"123")
            old=(datetime.now().timestamp()-8*86400); os.utime(p,(old,old)); inv=inventory(Cfg(t),state)
            self.assertTrue(inv["artifacts"][0]["expired"]); self.assertGreaterEqual(inv["total_size"],3)
    def test_dry_run_retention_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)/"state"); p=state.root/"backups"/"old"; p.mkdir(parents=True); old=datetime.now().timestamp()-8*86400; os.utime(p,(old,old))
            result=cleanup(Cfg(t),state,dry_run=True,reporter=Reporter(enabled=False)); self.assertTrue(p.exists()); self.assertEqual(result["files_removed"],0)
    def test_expired_rollback_status(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); hid=state.record(service="x",action="update",old_image_id="sha256:old",result="SUCCESS")
            with state.connect() as c: c.execute("UPDATE rollback_refs SET created='2026-01-01 00:00:00' WHERE history_id=?",(hid,))
            self.assertEqual(rollback_points(Cfg(t),state,datetime(2026,1,9,tzinfo=timezone.utc))[0]["status"],"EXPIRED")
    @patch("docker_update_manager.retention._docker_image_accounting")
    def test_rollback_report_includes_image_and_reclaimable_size(self,accounting):
        accounting.return_value={"sha256:old":{"image":"example/app:old","size":1200,"unique_size":1000,"shared_size":200,"containers":0}}
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); state.record(service="app",action="update",old_image="example/app:old",old_image_id="sha256:old",result="SUCCESS")
            point=rollback_points(Cfg(t),state,image_details=True)[0]
            self.assertEqual(point["image"],"example/app:old"); self.assertEqual(point["potential_reclaimable"],1000)
    @patch("docker_update_manager.retention._image_exists",return_value=False)
    @patch("docker_update_manager.retention._docker_image_accounting",return_value={})
    @patch("docker_update_manager.retention._container_image_ids",return_value=set())
    def test_override_protection_dry_run_is_scoped_and_non_mutating(self,*_):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); state.record(stack="media",service="app",action="update",old_image_id="sha256:old",result="SUCCESS")
            result=cleanup(Cfg(t),state,dry_run=True,service="app",override_protection=True,reporter=Reporter(enabled=False))
            self.assertEqual(result["expired_images"],1); self.assertEqual(rollback_points(Cfg(t),state)[0]["status"],"AVAILABLE")
    @patch("docker_update_manager.retention._docker_image_accounting",return_value={})
    def test_override_protection_refuses_unproven_legacy_null_stack(self,_accounting):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); state.record(service="app",action="update",old_image_id="sha256:legacy",result="SUCCESS")
            with self.assertRaisesRegex(ValueError,"unproven stack identity"):
                cleanup(Cfg(t),state,dry_run=True,service="app",override_protection=True,reporter=Reporter(enabled=False))
    @patch("docker_update_manager.retention._image_exists",return_value=True)
    @patch("docker_update_manager.retention._docker_image_accounting",return_value={})
    @patch("docker_update_manager.retention._container_image_ids",return_value=set())
    def test_stack_override_selects_only_scoped_and_proven_legacy_refs(self,*_):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t))
            state.record(stack="media",service="app",action="update",old_image_id="sha256:media",result="SUCCESS")
            state.record(stack="test",service="app",action="update",old_image_id="sha256:test",result="SUCCESS")
            backup=state.root/"backups"/"legacy-test"; backup.mkdir(parents=True)
            (backup/"metadata.json").write_text(json.dumps({"stack":"test","service":"app","files":[]}))
            state.record(service="app",action="update",old_image_id="sha256:legacy-test",backup=str(backup),result="SUCCESS")
            state.record(service="app",action="update",old_image_id="sha256:ambiguous",result="SUCCESS")
            result=cleanup(Cfg(t),state,dry_run=True,service="app",stack="test",override_protection=True,reporter=Reporter(enabled=False))
            self.assertEqual(result["expired_images"],2)
            self.assertEqual({item["image_id"] for item in result["planned_images"]},{"sha256:test","sha256:legacy-test"})
    @patch("docker_update_manager.retention._image_exists",return_value=True)
    @patch("docker_update_manager.retention._docker_image_accounting",return_value={})
    @patch("docker_update_manager.retention._container_image_ids",return_value=set())
    def test_override_protection_requires_stack_for_duplicate_service_names(self,*_):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t))
            state.record(stack="media",service="app",action="update",old_image_id="sha256:media",result="SUCCESS")
            state.record(stack="test",service="app",action="update",old_image_id="sha256:test",result="SUCCESS")
            with self.assertRaisesRegex(ValueError,"multiple stacks; specify --stack"):
                cleanup(Cfg(t),state,dry_run=True,service="app",override_protection=True,reporter=Reporter(enabled=False))
            result=cleanup(Cfg(t),state,dry_run=True,service="app",stack="test",override_protection=True,reporter=Reporter(enabled=False))
            self.assertEqual(result["expired_images"],1)
            self.assertEqual(result["planned_images"][0]["image_id"],"sha256:test")
    def test_override_requires_service(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ValueError): cleanup(Cfg(t),State(Path(t)),dry_run=True,override_protection=True,reporter=Reporter(enabled=False))
    @patch("docker_update_manager.retention._image_exists",return_value=False)
    @patch("docker_update_manager.retention._container_image_ids",return_value=set())
    @patch("docker_update_manager.retention._docker_image_accounting",return_value={})
    def test_all_protected_dry_run_selects_all_and_changes_nothing(self,*_):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); state.record(service="a",action="update",old_image_id="sha256:a",result="SUCCESS"); state.record(service="b",action="update",old_image_id="sha256:b",result="SUCCESS")
            result=cleanup(Cfg(t),state,dry_run=True,all_protected=True,reporter=Reporter(enabled=False))
            self.assertEqual(result["expired_images"],2); self.assertTrue(result["all_protected"])
            self.assertTrue(all(p["status"]=="AVAILABLE" for p in rollback_points(Cfg(t),state)))
    @patch("docker_update_manager.retention._docker_image_accounting", return_value={})
    @patch("docker_update_manager.retention._container_image_ids",return_value={"sha256:shared"})
    def test_in_use_image_protected(self,_,_accounting):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); hid=state.record(service="x",action="update",old_image_id="sha256:shared",result="SUCCESS")
            with state.connect() as c: c.execute("UPDATE rollback_refs SET created='2026-01-01 00:00:00' WHERE history_id=?",(hid,))
            result=cleanup(Cfg(t),state,dry_run=False,reporter=Reporter(enabled=False),now=datetime(2026,1,9,tzinfo=timezone.utc)); self.assertIn("IMAGE IN USE",result["skipped"][0]["reason"])
    def test_shared_image_retained_when_one_reference_active(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); a=state.record(service="a",action="update",old_image_id="sha256:same",result="SUCCESS"); b=state.record(service="b",action="update",old_image_id="sha256:same",result="SUCCESS")
            with state.connect() as c: c.execute("UPDATE rollback_refs SET created='2026-01-01 00:00:00' WHERE history_id=?",(a,))
            with patch("docker_update_manager.retention.run") as rm:
                cleanup(Cfg(t),state,reporter=Reporter(enabled=False),now=datetime.now(timezone.utc))
                self.assertFalse(any(call.args and call.args[0][:3]==["docker","image","rm"] for call in rm.call_args_list))
    @patch("docker_update_manager.retention._container_image_ids",return_value=set())
    @patch("docker_update_manager.retention._docker_image_accounting",return_value={})
    @patch("docker_update_manager.retention.run",side_effect=CommandError(["docker"],"No such image: sha256:gone"))
    def test_missing_image_is_reconciled_and_not_retried(self,*_):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); hid=state.record(service="x",action="update",old_image_id="sha256:gone",result="SUCCESS")
            with state.connect() as c: c.execute("UPDATE rollback_refs SET created='2026-01-01 00:00:00' WHERE history_id=?",(hid,))
            result=cleanup(Cfg(t),state,reporter=Reporter(enabled=False),now=datetime(2026,1,9,tzinfo=timezone.utc))
            self.assertEqual(result["images_absent"],1); self.assertFalse(result["failures"])
            self.assertEqual(rollback_points(Cfg(t),state,datetime(2026,1,9,tzinfo=timezone.utc))[0]["status"],"ALREADY ABSENT")
            again=cleanup(Cfg(t),state,reporter=Reporter(enabled=False),now=datetime(2026,1,9,tzinfo=timezone.utc))
            self.assertEqual(again["expired_images"],0)

    @patch("docker_update_manager.retention._container_image_ids",return_value=set())
    @patch("docker_update_manager.retention._docker_image_accounting",return_value={})
    @patch("docker_update_manager.retention.run",side_effect=CommandError(["docker"],"No such image: sha256:same"))
    def test_progress_counts_unique_images_not_rollback_references(self,*_):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); a=state.record(service="a",action="update",old_image_id="sha256:same",result="SUCCESS"); b=state.record(service="b",action="update",old_image_id="sha256:same",result="SUCCESS")
            with state.connect() as c: c.execute("UPDATE rollback_refs SET created='2026-01-01 00:00:00'")
            reporter=Reporter(enabled=False)
            result=cleanup(Cfg(t),state,reporter=reporter,now=datetime(2026,1,9,tzinfo=timezone.utc))
            self.assertEqual(result["expired_images"],2); self.assertEqual(result["unique_images"],1)
            self.assertEqual(reporter.events[0].total,1)
            completed=[e for e in reporter.events if e.kind=="task_completed"]
            self.assertEqual((completed[-1].current,completed[-1].total),(1,1))

    @patch("docker_update_manager.retention._container_image_ids",return_value=set())
    @patch("docker_update_manager.retention._docker_image_accounting",return_value={})
    @patch("docker_update_manager.retention.run",side_effect=CommandError(["docker"],"permission denied"))
    def test_real_docker_failure_is_reported(self,*_):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); hid=state.record(service="x",action="update",old_image_id="sha256:x",result="SUCCESS")
            with state.connect() as c: c.execute("UPDATE rollback_refs SET created='2026-01-01 00:00:00' WHERE history_id=?",(hid,))
            result=cleanup(Cfg(t),state,reporter=Reporter(enabled=False),now=datetime(2026,1,9,tzinfo=timezone.utc))
            self.assertEqual(len(result["failures"]),1); self.assertEqual(result["images_absent"],0)

    def test_database_permissions_and_bounded_metadata(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); old=state.record(service="old",action="scan",result="SUCCESS")
            hid=state.record(service="x",action="update",old_image_id="sha256:gone",result="SUCCESS")
            with state.connect() as c:
                c.execute("UPDATE history SET timestamp='2020-01-01 00:00:00' WHERE id=?",(old,))
                c.execute("UPDATE rollback_refs SET created='2020-01-01 00:00:00',expired=1,purge_status='ALREADY ABSENT' WHERE history_id=?",(hid,))
                c.execute("UPDATE history SET rollback_result='ALREADY ABSENT' WHERE id=?",(hid,))
                c.execute("INSERT INTO disk_snapshots(timestamp,kind,metrics) VALUES('2020-01-01 00:00:00','quick','{}')")
            with patch("docker_update_manager.retention._docker_image_accounting",return_value={}):
                result=cleanup(Cfg(t),state,reporter=Reporter(enabled=False),now=datetime(2026,9,9,tzinfo=timezone.utc))
            self.assertGreaterEqual(result["database"]["rows_pruned"],3)
            self.assertEqual(state.db_path.stat().st_mode&0o777,0o600)
            self.assertFalse(state.disk_snapshots())
            self.assertFalse(any(r["id"]==old for r in state.history()))

if __name__=="__main__": unittest.main()
