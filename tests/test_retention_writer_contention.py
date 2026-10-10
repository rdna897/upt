"""S6-R10: retention inventory must not reserve SQLite's writer slot.

All state and Docker input is synthetic; the guarded test runner is mandatory.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py

import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from docker_update_manager.progress import Reporter
from docker_update_manager.retention import _migrate_refs, cleanup, inventory, rollback_points
from docker_update_manager.state import State


class _Cfg:
    def __init__(self, root):
        self.data = {"retention": {"recovery_days": 7}}
        self.log_dir = root / "logs"


class RetentionWriterContentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = State(self.root / "state")
        self.cfg = _Cfg(self.root)
        self.original = self.state.record(
            stack="synthetic", service="first", action="update",
            old_image="example/first:previous", old_image_id="sha256:initial",
            result="SUCCESS",
        )

    def test_other_writer_commits_while_docker_accounting_is_blocked(self):
        accounting_started = threading.Event()
        release_accounting = threading.Event()
        inventory_done = threading.Event()
        writer_done = threading.Event()
        errors = []
        observed = []

        def blocked_accounting():
            accounting_started.set()
            if not release_accounting.wait(10):
                raise AssertionError("test accounting release was not signalled")
            return {}

        def inventory_worker():
            try:
                observed.extend(rollback_points(self.cfg, self.state, image_details=True))
            except BaseException as exc:
                errors.append(exc)
            finally:
                inventory_done.set()

        def competing_writer():
            try:
                # A distinct State instance and connection model the separate
                # agent/CLI writers that previously exhausted busy_timeout.
                State(self.state.root).record(
                    stack="synthetic", service="second", action="update",
                    old_image_id="sha256:second", result="SUCCESS",
                )
            except BaseException as exc:
                errors.append(exc)
            finally:
                writer_done.set()

        reader = threading.Thread(target=inventory_worker, daemon=True)
        writer = threading.Thread(target=competing_writer, daemon=True)
        with patch("docker_update_manager.retention._docker_image_accounting",
                   side_effect=blocked_accounting):
            reader.start()
            try:
                self.assertTrue(accounting_started.wait(5), "inventory did not reach accounting")
                writer.start()
                # This must succeed BEFORE the accounting call is released.
                # It fails deterministically on the original BEGIN IMMEDIATE path.
                self.assertTrue(writer_done.wait(5),
                                "Docker accounting retained the SQLite writer slot")
                self.assertFalse(inventory_done.is_set())
            finally:
                release_accounting.set()
                reader.join(timeout=5)
                if writer.ident is not None:
                    writer.join(timeout=5)
        self.assertFalse(reader.is_alive(), "inventory thread did not exit")
        self.assertFalse(writer.is_alive(), "writer thread did not exit")
        self.assertEqual(errors, [])
        # Inventory rows were captured in a short snapshot before accounting,
        # not re-read after the concurrent writer completed.
        self.assertEqual([r["history_id"] for r in observed], [self.original])
        self.assertEqual(len(self.state.history()), 2)

    def test_inventory_and_dry_run_project_legacy_refs_without_any_write(self):
        with self.state.connect() as c:
            c.execute("UPDATE protected_images SET created='2026-01-01 00:00:00' WHERE history_id=?",
                      (self.original,))
            c.execute("DELETE FROM rollback_refs WHERE history_id=?", (self.original,))
        with patch.object(self.state, "connect",
                          side_effect=AssertionError("read-only inventory used a write transaction")), \
             patch("docker_update_manager.retention._docker_image_accounting", return_value={}):
            point, = rollback_points(self.cfg, self.state,
                                     now=datetime(2026, 1, 2, tzinfo=timezone.utc),
                                     image_details=True)
            report = inventory(self.cfg, self.state,
                               now=datetime(2026, 1, 2, tzinfo=timezone.utc))
            preview = cleanup(self.cfg, self.state, dry_run=True,
                              reporter=Reporter(enabled=False),
                              now=datetime(2026, 1, 2, tzinfo=timezone.utc))
        self.assertEqual((point["history_id"], point["image_id"], point["created"]),
                         (self.original, "sha256:initial", "2026-01-01 00:00:00"))
        self.assertEqual((point["expired"], point["purge_status"], point["status"]),
                         (0, None, "AVAILABLE"))
        self.assertEqual(len(report["rollback_images"]), 1)
        self.assertEqual(preview["images_removed"], 0)
        with self.state.read() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM rollback_refs").fetchone()[0], 0)
            self.assertEqual(c.execute("SELECT count(*) FROM protected_images").fetchone()[0], 1)

    def test_real_cleanup_materialises_legacy_refs_without_changing_protection(self):
        with self.state.connect() as c:
            c.execute("UPDATE protected_images SET created='2026-01-01 00:00:00' WHERE history_id=?",
                      (self.original,))
            c.execute("DELETE FROM rollback_refs WHERE history_id=?", (self.original,))
        when = datetime(2026, 1, 2, tzinfo=timezone.utc)
        before, = rollback_points(self.cfg, self.state, now=when)
        with patch("docker_update_manager.retention._docker_image_accounting", return_value={}):
            result = cleanup(self.cfg, self.state, now=when,
                             reporter=Reporter(enabled=False))
        after, = rollback_points(self.cfg, self.state, now=when)
        for key in ("history_id", "image_id", "created", "expired", "purge_status",
                    "status", "service", "stack", "expires"):
            self.assertEqual(after[key], before[key], key)
        self.assertEqual(result["images_removed"], 0)
        with self.state.read() as c:
            row = c.execute("SELECT image_id,expired FROM rollback_refs WHERE history_id=?",
                            (self.original,)).fetchone()
        self.assertEqual(tuple(row), ("sha256:initial", 0))

    def _database_snapshot(self):
        with self.state.read() as c:
            rows = tuple(c.iterdump())
        return self.state.db_path.read_bytes(), rows

    def _assert_legacy_projection(self, rows, eligible):
        when = datetime(2026, 1, 9, tzinfo=timezone.utc)
        with self.state.connect() as c:
            c.execute("DELETE FROM rollback_refs")
            c.execute("DELETE FROM protected_images")
            c.executemany(
                "INSERT INTO protected_images(image_id,history_id,created) VALUES(?,?,?)",
                [(image, history_id, "2026-01-01 00:00:00") for image, history_id in rows],
            )
        before = self._database_snapshot()
        accounting = {image: {"unique_size": 1, "containers": 0} for image, _ in rows}
        accounting["sha256:eligible"] = {"unique_size": 1, "containers": 0}
        with patch("docker_update_manager.retention._docker_image_accounting", return_value=accounting), \
             patch("docker_update_manager.retention._container_image_ids", return_value=set()), \
             patch("docker_update_manager.retention.run", return_value="") as run:
            with patch.object(self.state, "connect",
                              side_effect=AssertionError("inventory attempted a write")):
                projected = inventory(self.cfg, self.state, now=when,
                                      image_details=True)["rollback_images"]
                preview = cleanup(self.cfg, self.state, now=when, dry_run=True)
            self.assertEqual(self._database_snapshot(), before)
            self.assertEqual({p["image_id"] for p in projected}, set(eligible))
            for point in projected:
                self.assertEqual((point["expired"], point["purge_status"], point["status"]),
                                 (0, None, "EXPIRED"))
                if point["history_id"] != self.original:
                    self.assertIsNone(point["stack"])
                    self.assertIsNone(point["service"])
                else:
                    self.assertEqual((point["stack"], point["service"]), ("synthetic", "first"))

            _migrate_refs(self.state)
            self.assertEqual(rollback_points(self.cfg, self.state, now=when, image_details=True),
                             projected)
            self.assertEqual(cleanup(self.cfg, self.state, now=when, dry_run=True), preview)
            self.assertEqual({p["image_id"] for p in preview["planned_images"]}, set(eligible))
            real = cleanup(self.cfg, self.state, now=when)
            self.assertEqual(real["expired_images"], preview["expired_images"])
            self.assertEqual(real["images_removed"], len(eligible))
            self.assertEqual([call.args[0] for call in run.call_args_list],
                             [["docker", "image", "rm", image] for image in eligible])
            with self.state.read() as c:
                count = c.execute("SELECT count(*) FROM rollback_refs").fetchone()[0]
                protected = [tuple(row) for row in c.execute(
                    "SELECT image_id,history_id FROM protected_images ORDER BY image_id")]
            self.assertEqual(count, len(eligible))
            self.assertEqual(protected, sorted(rows) if not eligible else [])
            run.reset_mock()
            again = cleanup(self.cfg, self.state, now=when)
            self.assertEqual(again["images_removed"], 0)
            run.assert_not_called()
            with self.state.read() as c:
                self.assertEqual(c.execute("SELECT count(*) FROM rollback_refs").fetchone()[0], count)

            if not eligible:
                # --all cannot invent eligibility for these protections. Also
                # exercise its real cleanup/prune path with an eligible image.
                with self.assertRaisesRegex(ValueError, "no rollback protection found"):
                    cleanup(self.cfg, self.state, now=when, all_protected=True)
                self.state.record(service="eligible", action="update", result="SUCCESS",
                                  old_image_id="sha256:eligible")
                forced_preview = cleanup(self.cfg, self.state, now=when, dry_run=True,
                                         all_protected=True)
                self.assertEqual([p["image_id"] for p in forced_preview["planned_images"]],
                                 ["sha256:eligible"])
                forced = cleanup(self.cfg, self.state, now=when, all_protected=True)
                self.assertEqual(forced["images_removed"], 1)
                self.assertEqual([call.args[0] for call in run.call_args_list],
                                 [["docker", "image", "rm", "sha256:eligible"]])
                cleanup(self.cfg, self.state, now=when)
                with self.state.read() as c:
                    self.assertEqual([tuple(row) for row in c.execute(
                        "SELECT image_id,history_id FROM protected_images ORDER BY image_id")],
                        sorted(rows))
                    self.assertEqual([tuple(row) for row in c.execute(
                        "SELECT image_id,expired FROM rollback_refs")], [("sha256:eligible", 1)])

    def test_normal_legacy_projection_matches_materialisation_and_cleanup(self):
        self._assert_legacy_projection([("sha256:initial", self.original)], ["sha256:initial"])

    def test_duplicate_legacy_rows_remain_protected_without_refs(self):
        self._assert_legacy_projection(
            [("sha256:duplicate-a", self.original), ("sha256:duplicate-b", self.original)], [])

    def test_null_history_legacy_row_remains_protected_without_refs(self):
        self._assert_legacy_projection([("sha256:manual-recovery", None)], [])

    def test_orphaned_unique_legacy_projection_matches_materialisation_and_cleanup(self):
        self._assert_legacy_projection([("sha256:orphaned", 999)], ["sha256:orphaned"])

    def test_prune_retains_legacy_row_without_its_own_matching_image_ref(self):
        with self.state.connect() as c:
            c.execute("UPDATE rollback_refs SET image_id='sha256:different', "
                      "created='2026-01-01 00:00:00',expired=1 WHERE history_id=?",
                      (self.original,))
        with patch("docker_update_manager.retention._docker_image_accounting", return_value={}), \
             patch("docker_update_manager.retention._container_image_ids",
                   return_value={"sha256:different"}), \
             patch("docker_update_manager.retention.run") as run:
            for _ in range(2):
                cleanup(self.cfg, self.state, now=datetime(2026, 1, 9, tzinfo=timezone.utc))
            run.assert_not_called()
        with self.state.read() as c:
            self.assertEqual([tuple(row) for row in c.execute(
                "SELECT history_id,image_id FROM protected_images")],
                [(self.original, "sha256:initial")])
            self.assertEqual(c.execute("SELECT count(*) FROM rollback_refs").fetchone()[0], 1)

    def test_expired_in_use_matching_ref_still_prunes_protection(self):
        with self.state.connect() as c:
            c.execute("UPDATE rollback_refs SET created='2026-01-01 00:00:00' WHERE history_id=?",
                      (self.original,))
        with patch("docker_update_manager.retention._docker_image_accounting", return_value={}), \
             patch("docker_update_manager.retention._container_image_ids", return_value={"sha256:initial"}), \
             patch("docker_update_manager.retention.run") as run:
            result = cleanup(self.cfg, self.state, now=datetime(2026, 1, 9, tzinfo=timezone.utc))
            run.assert_not_called()
        self.assertEqual(result["skipped"], [{"image": "sha256:initial", "reason": "SKIPPED - IMAGE IN USE"}])
        with self.state.read() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM protected_images").fetchone()[0], 0)
            self.assertEqual([tuple(row) for row in c.execute(
                "SELECT expired,purge_status FROM rollback_refs")], [(1, "SKIPPED - IMAGE IN USE")])

    def test_accounting_exception_does_not_leave_writer_locked(self):
        with patch("docker_update_manager.retention._docker_image_accounting",
                   side_effect=RuntimeError("synthetic accounting failure")):
            with self.assertRaisesRegex(RuntimeError, "synthetic accounting failure"):
                rollback_points(self.cfg, self.state, image_details=True)
        State(self.state.root).record(service="after", action="update", result="SUCCESS")
        self.assertEqual(len(self.state.history()), 2)


if __name__ == "__main__":
    unittest.main()
