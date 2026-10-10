"""Deterministic private-artifact lifecycle tests; no Docker commands."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from docker_update_manager.compose_drift import InputFile, read_input
from docker_update_manager.compose_reconcile import RecoveryBundle
from docker_update_manager.compose_recovery_retention import checked_bundle, remove_bundle
from docker_update_manager.retention import inventory, cleanup
from docker_update_manager.state import State
from test_disk_retention import Cfg


class ComposeRecoveryRetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = State(self.root / "state")
        self.cfg = Cfg(self.root)
        self.now = datetime.now(timezone.utc)
        self.operation_id = "a" * 32
        self.baseline_id = "b" * 32
        self.source = self.root / "operator-source.yml"
        self.source.write_text("private-secret-value")
        item = read_input("compose", str(self.source))
        inputs = SimpleNamespace(files=(item, InputFile("project_env", str(self.root / ".env"), False, None, 0)))
        self.state.create_operation(self.operation_id, kind="compose_reconcile", service_key="container/" + "c" * 64,
                                    service="sonarr", stack="media", requested_by="admin",
                                    summary={"baseline_id": self.baseline_id})
        self.bundle = RecoveryBundle(self.state.root, self.operation_id, inputs, SimpleNamespace(inventory=inputs),
                                     {"baseline_id": self.baseline_id, "evidence": "d" * 64})
        self.state.set_operation_running(self.operation_id)

    def finish(self, status="succeeded", recovered=False, manual=False):
        self.state.finish_operation(self.operation_id, status, message="Configuration result",
                                    result={"manual_recovery_required": manual, "recovered": recovered})
        with self.state.connect() as c:
            old = (self.now - timedelta(days=10)).isoformat()
            c.execute("UPDATE operation_runs SET created_at=?,finished_at=? WHERE id=?", (old, old, self.operation_id))

    def artifacts(self):
        return inventory(self.cfg, self.state, self.now)["artifacts"]

    def clean(self, **kwargs):
        with patch("docker_update_manager.retention.run", return_value="{}") as run:
            result = cleanup(self.cfg, self.state, now=self.now, **kwargs)
            self.assertFalse(any("rm" in call.args[0] for call in run.call_args_list))
        return result

    def test_terminal_success_recovered_blocked_policy_and_expiry(self):
        for status, recovered in (("succeeded", False), ("failed", True), ("blocked", False)):
            with self.subTest(status=status):
                # Reuse exact validated bundle while varying terminal evidence.
                with self.state.connect() as c:
                    c.execute("UPDATE operation_runs SET status='running' WHERE id=?", (self.operation_id,))
                self.finish(status, recovered)
                self.cfg.data["retention"]["compose_backups_days"] = 11
                self.assertFalse(self.artifacts()[0]["expired"])
                self.cfg.data["retention"]["compose_backups_days"] = 7
                self.assertTrue(self.artifacts()[0]["expired"])
                self.clean(dry_run=True)
                self.assertTrue(self.bundle.path.exists())
        self.assertEqual(self.clean()["files_removed"], 1)
        self.assertTrue(self.source.exists())

    def test_active_bundle_retained_regardless_of_age(self):
        os.utime(self.bundle.path, (0, 0))
        self.assertEqual(self.artifacts()[0]["protection"], "active")
        self.assertFalse(self.artifacts()[0]["expired"])
        self.clean()
        self.state.prune_operations(retention_days=1)
        self.assertTrue(self.bundle.path.exists())
        self.assertIsNotNone(self.state.operation_status(self.operation_id))

    def test_manual_evidence_protected_after_operation_pruning(self):
        self.finish("failed", manual=True)
        self.state.prune_operations(retention_days=1)
        self.assertIsNone(self.state.operation_status(self.operation_id))
        self.assertEqual(self.artifacts()[0]["protection"], "manual")
        self.assertEqual(inventory(self.cfg, self.state, self.now)["expiring_24h_size"], 0)
        self.assertFalse(self.artifacts()[0]["expired"])
        self.clean()
        self.assertTrue(self.bundle.path.exists())

    def test_proven_orphan_receipt_removed_with_bundle(self):
        self.finish()
        self.state.prune_operations(retention_days=1)
        self.assertIsNone(self.state.operation_status(self.operation_id))
        self.assertTrue(self.artifacts()[0]["expired"])
        self.clean()
        with self.state.read() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM compose_recovery_receipts").fetchone()[0], 0)

    def test_unknown_orphan_and_failed_unrecovered_are_protected(self):
        self.finish("failed")
        self.assertEqual(self.artifacts()[0]["protection"], "unproven")
        self.state.prune_operations(retention_days=1)
        self.clean()
        self.assertTrue(self.bundle.path.exists())
        self.assertFalse(self.artifacts()[0]["expired"])

    def test_receipt_is_bound_to_exact_manifest(self):
        self.finish()
        self.state.prune_operations(retention_days=1)
        manifest = self.bundle.path / "manifest.json"
        data = json.loads(manifest.read_text())
        data["binding"]["evidence"] = "e" * 64
        manifest.write_text(json.dumps(data))
        self.assertEqual(self.artifacts()[0]["protection"], "unproven")
        self.clean()
        self.assertTrue(self.bundle.path.exists())

    def test_inventory_exposes_only_bounded_metadata(self):
        self.finish()
        encoded = json.dumps(self.artifacts())
        for private in ("private-secret-value", str(self.source), ".env", "sha256", "baseline_id", "evidence"):
            self.assertNotIn(private, encoded)
        self.assertEqual(set(self.artifacts()[0]), {"kind", "path", "created", "expires", "expired", "size", "protection"})

    def test_malformed_manifest_and_unexpected_files_refused(self):
        self.finish()
        manifest = self.bundle.path / "manifest.json"
        original = manifest.read_bytes()
        for content in (b"{}", b"not json", json.dumps({**json.loads(original), "files": json.loads(original)["files"][:2]}).encode()):
            manifest.write_bytes(content)
            self.assertEqual(self.artifacts(), [])
            self.clean()
            self.assertTrue(manifest.exists())
        manifest.write_bytes(original)
        (self.bundle.path / "unexpected").write_text("keep")
        self.assertEqual(self.artifacts(), [])

    def test_symlinks_modes_ownership_and_outside_root_refused(self):
        self.finish()
        stored = self.bundle.path / "desired-00"
        data = stored.read_bytes()
        stored.unlink()
        stored.symlink_to(self.source)
        self.assertEqual(self.artifacts(), [])
        self.clean()
        self.assertEqual(self.source.read_text(), "private-secret-value")
        stored.unlink()
        stored.write_bytes(data)
        os.chmod(stored, 0o644)
        self.assertEqual(self.artifacts(), [])
        os.chmod(stored, 0o600)
        with patch("docker_update_manager.compose_recovery_retention.os.geteuid", return_value=12345):
            with self.assertRaises(ValueError):
                with checked_bundle(self.state.root, self.bundle.path):
                    pass
        with self.assertRaises(ValueError):
            with checked_bundle(self.state.root, self.root / self.operation_id):
                pass
        parent = self.bundle.path.parent
        renamed = self.state.root / "kept-recoveries"
        parent.rename(renamed)
        parent.symlink_to(renamed, target_is_directory=True)
        self.assertEqual(self.artifacts(), [])
        self.clean()
        self.assertTrue((renamed / self.operation_id).exists())

    def test_final_cleanup_rechecks_lifecycle_after_inventory(self):
        self.finish()
        original_inventory = inventory(self.cfg, self.state, self.now)
        with self.state.connect() as c:
            c.execute("UPDATE operation_runs SET result=? WHERE id=?",
                      (json.dumps({"manual_recovery_required": True}), self.operation_id))
        with patch("docker_update_manager.retention.inventory", return_value=original_inventory):
            result = self.clean()
        self.assertEqual(result["files_removed"], 0)
        self.assertTrue(result["skipped"])
        self.assertTrue(self.bundle.path.exists())

    def test_schema8_additive_migration_preserves_existing_state(self):
        with self.state.connect() as c:
            c.execute("DROP TABLE compose_recovery_receipts")
            c.execute("DROP TABLE IF EXISTS core_schema_identity")
            c.execute("DROP TABLE IF EXISTS compose_bootstrap_fences")
            c.execute("UPDATE schema_version SET version=8")
        migrated = State(self.state.root, quiescent_transition=True)
        self.assertEqual(migrated.operation_status(self.operation_id)["status"], "running")
        with migrated.read() as c:
            self.assertEqual(c.execute("SELECT version FROM schema_version").fetchone()[0], 9)
            self.assertEqual(c.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_unsafe_stored_path_and_bundle_symlink_refused(self):
        self.finish()
        manifest = self.bundle.path / "manifest.json"
        original = manifest.read_bytes()
        data = json.loads(original)
        data["files"][0]["stored"] = "../../operator-source.yml"
        manifest.write_text(json.dumps(data))
        self.assertEqual(self.artifacts(), [])
        self.clean()
        self.assertTrue(self.source.exists())
        manifest.write_bytes(original)
        moved = self.state.root / "outside-bundle"
        self.bundle.path.rename(moved)
        self.bundle.path.symlink_to(moved, target_is_directory=True)
        self.assertEqual(self.artifacts(), [])
        self.clean()
        self.assertTrue((moved / "manifest.json").exists())

    def test_cleanup_rechecks_changed_material_and_refuses_forged_kind(self):
        self.finish()
        with checked_bundle(self.state.root, self.bundle.path) as checked:
            os.chmod(self.bundle.path, 0o750)
            with self.assertRaises(ValueError):
                remove_bundle(self.bundle.path, checked)
            os.chmod(self.bundle.path, 0o700)
            extra = self.bundle.path / "concurrent-file"
            extra.write_text("keep")
            with self.assertRaises(ValueError):
                remove_bundle(self.bundle.path, checked)
            extra.unlink()
        inv = inventory(self.cfg, self.state, self.now)
        (self.bundle.path / "baseline-00").write_text("concurrent edit")
        with patch("docker_update_manager.retention.inventory", return_value=inv):
            self.assertEqual(self.clean()["files_removed"], 0)
        inv["artifacts"][0]["kind"] = "backups"
        with patch("docker_update_manager.retention.inventory", return_value=inv):
            self.assertEqual(self.clean()["files_removed"], 0)
        self.assertTrue(self.bundle.path.exists())

    def test_operation_count_pruning_also_preserves_manual_receipt(self):
        self.finish("failed", manual=True)
        with self.state.connect() as c:
            for number in range(25):
                c.execute("INSERT INTO operation_runs(id,kind,service_key,service,status,created_at,finished_at) "
                          "VALUES(?, 'update', 'container/test', 'other', 'succeeded', ?, ?)",
                          (f"{number:032x}", self.now.isoformat(), self.now.isoformat()))
        self.state.prune_operations(retention_days=3650, limit=20)
        self.assertIsNone(self.state.operation_status(self.operation_id))
        self.assertEqual(self.artifacts()[0]["protection"], "manual")
        self.assertEqual(inventory(self.cfg, self.state, self.now)["expiring_24h_size"], 0)
        self.clean()
        self.assertTrue(self.bundle.path.exists())
