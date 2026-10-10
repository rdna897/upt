"""CURRENT-BEHAVIOUR characterisation of SQLite completion failures (G2, issue #9).

These tests document how image update (S6-R1), CLI rollback (S6-R1b) and
pinned update (S6-R2) behave today when the History write fails after the
Docker mutation. They are not the desired contract: the approved G2
corrections are expected to break them, and each must then be updated
deliberately. Every Docker, Compose and registry boundary is mocked and the
SQLite database is a temporary file; failures are injected inside real
``State`` transactions by ``sqlite_faults``.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from docker_update_manager.compose import backup_files
from docker_update_manager.models import Service
from docker_update_manager.operations import RecoveryRefused, RecoveryRequired, do_rollback, do_update
from docker_update_manager.progress import Reporter
from docker_update_manager.state import State
from sqlite_faults import history_insert, sqlite_fault
from test_core import service

OLD_ID = "sha256:" + "a" * 64
NEW_ID = "sha256:" + "b" * 64
EARLIER_ID = "sha256:" + "0" * 64


class _Fixture(unittest.TestCase):
    def setUp(self):
        namespace = patch("docker_update_manager.compose_namespace.mutation_refusal", return_value=None)
        namespace.start()
        self.addCleanup(namespace.stop)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.compose = self.root / "compose.yml"
        self.state = State(self.root / "state")
        self.docker = []  # every mocked Docker/Compose mutation, in order

    def patch(self, target, **kwargs):
        patcher = patch("docker_update_manager.operations." + target, **kwargs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def rollback_target(self, current):
        """Return the image id a CLI rollback would select now (dry run, no mutation)."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            do_rollback(current, self.state, dry_run=True, reporter=Reporter(enabled=False))
        return out.getvalue().splitlines()[0].removeprefix("Rollback target: ")

    def rollback_ref(self, history_id):
        with self.state.read() as connection:
            row = connection.execute("SELECT image_id,expired FROM rollback_refs WHERE history_id=?",
                                     (history_id,)).fetchone()
        return tuple(row) if row else None


class OrdinaryUpdateHistoryFailureCurrentBehaviour(_Fixture):
    """S6-R1: healthy mutable-tag update, then ``record(SUCCESS)`` fails."""

    def setUp(self):
        super().setUp()
        self.compose.write_text("services:\n  grafana:\n    image: grafana/grafana:latest\n")
        base = service(self.root)
        self.current = Service(**{**base.__dict__, "image_id": OLD_ID, "health": "healthy"})
        self.fresh = Service(**{**base.__dict__, "image_id": NEW_ID, "digest": "sha256:" + "c" * 64,
                                "version": "13.0", "health": "healthy"})
        self.patch("remote_manifest", return_value={"digest": "sha256:" + "c" * 64, "platforms": [],
                                                    "version": "13.0", "created": None})
        self.patch("run_compose_progress", side_effect=lambda args, *_a, **_k: self.docker.append("pull"))
        self.patch("run", side_effect=lambda args, **_k: self.docker.append("recreate" if "up" in args else args))
        self.patch("discover", side_effect=lambda *_a, **_k: [self.fresh])

    def update(self):
        return do_update(self.current, self.state, yes=True, reporter=Reporter(enabled=False),
                         output=lambda *_args: None)

    def test_current_behaviour_success_write_fails_before_commit_and_handler_records_failed(self):
        with sqlite_fault(self.state, history_insert(result="SUCCESS")) as fault, \
                self.assertRaisesRegex(sqlite3.OperationalError, "database is locked"):
            self.update()
        self.assertEqual(len(fault.hits), 1)
        # Docker outcome: one pull and one recreate; the service now runs NEW_ID
        # and no compensating Docker action was taken.
        self.assertEqual(self.docker, ["pull", "recreate"])
        # History outcome: the completed update is recorded only as FAILED, with
        # no replacement identity and the raw CLI exception text.
        (row,) = self.state.history("grafana")
        self.assertEqual((row["action"], row["result"]), ("update", "FAILED"))
        self.assertIsNone(row["new_image_id"])
        self.assertEqual(row["details"], "database is locked")
        # Protection versus eligibility: the FAILED row protects the previous
        # image, but rollback only selects SUCCESS rows, so it is refused.
        self.assertIn(OLD_ID, self.state.protected())
        self.assertEqual(self.rollback_ref(row["id"]), (OLD_ID, 0))
        with self.assertRaisesRegex(ValueError, "no successful update rollback point exists"):
            self.rollback_target(self.fresh)

    def test_current_behaviour_failed_success_write_makes_rollback_select_an_earlier_point(self):
        backup = backup_files([self.compose], self.state.root, self.current)
        self.state.record(stack="monitoring", service="grafana", action="update", old_image="grafana/grafana:11.0",
                          old_image_id=EARLIER_ID, new_image="grafana/grafana:latest", new_image_id=OLD_ID,
                          backup=str(backup), result="SUCCESS")
        with sqlite_fault(self.state, history_insert(result="SUCCESS")), \
                self.assertRaisesRegex(sqlite3.OperationalError, "database is locked"):
            self.update()
        self.assertEqual(self.docker, ["pull", "recreate"])
        self.assertEqual([r["result"] for r in self.state.history("grafana")], ["FAILED", "SUCCESS"])
        # The update just left OLD_ID, but rollback now targets the older point.
        self.assertEqual(self.rollback_target(self.fresh), EARLIER_ID)

    def test_current_behaviour_success_write_ambiguous_commit_is_followed_by_failed_row(self):
        with sqlite_fault(self.state, history_insert(result="SUCCESS"), mode="after_commit") as fault, \
                self.assertRaisesRegex(sqlite3.OperationalError, "disk I/O error"):
            self.update()
        self.assertEqual(len(fault.hits), 1)
        self.assertEqual(self.docker, ["pull", "recreate"])
        # The SUCCESS row did commit; the handler then adds a contradictory
        # FAILED row for the same update. No durable state is re-read.
        failed, success = self.state.history("grafana")
        self.assertEqual((success["result"], success["new_image_id"]), ("SUCCESS", NEW_ID))
        self.assertEqual((failed["result"], failed["new_image_id"]), ("FAILED", None))
        self.assertEqual(self.rollback_target(self.fresh), OLD_ID)

    def test_current_behaviour_persistent_unavailability_leaves_no_history_row(self):
        with sqlite_fault(self.state, history_insert(result="SUCCESS"), mode="unavailable") as fault, \
                self.assertLogs("docker_update_manager.reconciliation", "WARNING"), \
                self.assertRaisesRegex(sqlite3.OperationalError, "unable to open database file") as raised:
            self.update()
        self.assertEqual(len(fault.hits), 1)
        # The handler's own FAILED write fails too and replaces the original error.
        self.assertIsInstance(raised.exception.__context__, sqlite3.OperationalError)
        self.assertEqual(self.docker, ["pull", "recreate"])
        # The service runs NEW_ID, yet nothing about the mutation is durable:
        # no History row, no rollback reference, no protection of OLD_ID.
        # A fix that keeps evidence outside SQLite must also update this test.
        self.assertEqual(self.state.history(), [])
        self.assertNotIn(OLD_ID, self.state.protected())


class CliRollbackHistoryFailureCurrentBehaviour(_Fixture):
    """S6-R1b (CLI): completed ``do_rollback``, then ``record(ROLLED BACK)`` fails."""

    def test_current_behaviour_rollback_completes_then_raises_without_history(self):
        self.compose.write_text("services:\n  grafana:\n    image: grafana/grafana:12.0\n")
        previous = Service(**{**service(self.root, image="grafana/grafana:12.0").__dict__, "image_id": OLD_ID})
        backup = backup_files([self.compose], self.state.root, previous)
        update_id = self.state.record(stack="monitoring", service="grafana", action="update",
                                      old_image="grafana/grafana:12.0", old_image_id=OLD_ID,
                                      new_image="grafana/grafana:13.0", new_image_id=NEW_ID,
                                      backup=str(backup), result="SUCCESS")
        self.compose.write_text("services:\n  grafana:\n    image: grafana/grafana:13.0\n")
        current = Service(**{**service(self.root, image="grafana/grafana:13.0").__dict__,
                             "image_id": NEW_ID, "health": "healthy"})
        rolled_back = Service(**{**previous.__dict__, "health": "healthy"})
        self.patch("validate")
        self.patch("run", side_effect=lambda args, **_k: self.docker.append("recreate" if "up" in args else args[:3]))
        self.patch("discover", side_effect=lambda *_a, **_k: [rolled_back])

        with sqlite_fault(self.state, history_insert(action="rollback")) as fault, \
                self.assertRaisesRegex(sqlite3.OperationalError, "database is locked"):
            with contextlib.redirect_stdout(io.StringIO()):
                do_rollback(current, self.state, yes=True, reporter=Reporter(enabled=False))
        self.assertEqual(len(fault.hits), 1)
        # Docker/Compose outcome: sources restored, old image retagged, one recreate.
        self.assertEqual(self.compose.read_text(), "services:\n  grafana:\n    image: grafana/grafana:12.0\n")
        self.assertEqual(self.docker, [["docker", "image", "tag"], "recreate"])
        # History outcome: no rollback row; the update still reads as the
        # latest SUCCESS and remains the selected rollback point.
        self.assertEqual([(r["id"], r["action"]) for r in self.state.history("grafana")], [(update_id, "update")])
        self.assertEqual(self.rollback_target(rolled_back), OLD_ID)


class PinnedUpdateHistoryFailureCurrentBehaviour(_Fixture):
    """S6-R2: healthy digest-pinned update, then ``record(SUCCESS)`` fails."""

    def setUp(self):
        super().setUp()
        self.original = "services:\n  grafana:\n    image: grafana/grafana:latest@sha256:" + "a" * 64 + "\n"
        self.target = "grafana/grafana:latest@sha256:" + "b" * 64
        self.compose.write_text(self.original)
        self.current = Service(**{**service(self.root, image="grafana/grafana:latest@sha256:" + "a" * 64).__dict__,
                                  "image_id": OLD_ID, "health": "healthy"})
        self.fresh = Service(**{**self.current.__dict__, "image": self.target, "image_id": NEW_ID,
                                "digest": "sha256:" + "b" * 64, "version": "13.0"})
        self.on_recreate = None
        self.patch("remote_manifest", return_value={"digest": "sha256:" + "b" * 64, "platforms": [],
                                                    "version": "13.0", "created": None})
        self.patch("validate")
        self.patch("run", side_effect=self.docker_run)
        self.patch("discover", side_effect=lambda *_a, **_k: [self.fresh])

    def docker_run(self, args, **_kwargs):
        if args[:2] == ["docker", "pull"]:
            self.docker.append("pull")
        elif "up" in args:
            # Each recreate applies whatever pin Compose holds at that moment.
            self.docker.append(("recreate", self.compose.read_text() == self.original and "old-pin" or "new-pin"))
            if self.on_recreate:
                self.on_recreate()
        return ""

    def update(self, **kwargs):
        return do_update(self.current, self.state, yes=True, reporter=Reporter(enabled=False),
                         output=lambda *_args: None, **kwargs)

    def assert_single_failed_row(self):
        (row,) = self.state.history("grafana")
        self.assertEqual((row["action"], row["result"]), ("update", "FAILED"))
        return row, json.loads(row["details"])

    def test_current_behaviour_cli_history_failure_reverses_healthy_update(self):
        with sqlite_fault(self.state, history_insert(result="SUCCESS")) as fault, \
                self.assertRaisesRegex(RuntimeError, "original Compose pin was restored: database is locked"):
            self.update()
        self.assertEqual(len(fault.hits), 1)
        # Compensating Docker action caused solely by the database failure:
        # the healthy new-pin service is recreated once more on the old pin.
        self.assertEqual(self.docker, ["pull", ("recreate", "new-pin"), ("recreate", "old-pin")])
        self.assertEqual(self.compose.read_text(), self.original)
        row, details = self.assert_single_failed_row()
        self.assertTrue(details["configuration_restored"])
        self.assertEqual(details["recovery_result"], "automatic recovery recreated the previous service")
        self.assertIsNone(row["rollback_result"])

    def test_current_behaviour_web_recovery_guard_refusal_prevents_reversal(self):
        def refuse():
            self.docker.append("recovery-check")
            raise RecoveryRefused("Compose model changed")
        with sqlite_fault(self.state, history_insert(result="SUCCESS")), self.assertRaises(RecoveryRequired):
            self.update(audit_context={"origin": "web", "operation_id": "a" * 32}, pre_recovery_check=refuse)
        # The guard runs after the pin restore and refuses the recreate, so the
        # service stays on the new digest while Compose names the old one.
        self.assertEqual(self.docker, ["pull", ("recreate", "new-pin"), "recovery-check"])
        self.assertEqual(self.compose.read_text(), self.original)
        row, details = self.assert_single_failed_row()
        self.assertEqual(row["rollback_result"], "MANUAL RECOVERY REQUIRED")
        self.assertEqual((details["recovery_attempted"], details["recovery_result"]), (False, "refused"))

    def test_current_behaviour_operator_edit_after_pin_write_prevents_restore_and_reversal(self):
        edited = self.original.replace("services:", "# operator edit\nservices:")
        self.on_recreate = lambda: self.compose.write_text(edited)
        with sqlite_fault(self.state, history_insert(result="SUCCESS")), \
                self.assertRaisesRegex(RuntimeError, "Compose pin restoration could not be verified"):
            self.update()
        self.assertEqual(self.docker, ["pull", ("recreate", "new-pin")])
        self.assertEqual(self.compose.read_text(), edited)
        _row, details = self.assert_single_failed_row()
        self.assertFalse(details["configuration_restored"])
        self.assertNotIn("recovery_result", details)

    def test_current_behaviour_ambiguous_commit_reverses_update_recorded_as_success(self):
        with sqlite_fault(self.state, history_insert(result="SUCCESS"), mode="after_commit"), \
                self.assertRaisesRegex(RuntimeError, "original Compose pin was restored: disk I/O error"):
            self.update()
        self.assertEqual(self.docker, ["pull", ("recreate", "new-pin"), ("recreate", "old-pin")])
        # The committed SUCCESS row (new digest) and the later FAILED row both
        # exist, although the service was returned to the old digest.
        failed, success = self.state.history("grafana")
        self.assertEqual((success["result"], success["new_image"]), ("SUCCESS", self.target))
        self.assertEqual(failed["result"], "FAILED")

    def test_current_behaviour_persistent_unavailability_reverses_update_without_history(self):
        with sqlite_fault(self.state, history_insert(result="SUCCESS"), mode="unavailable"), \
                self.assertLogs("docker_update_manager.reconciliation", "WARNING"), \
                self.assertRaisesRegex(sqlite3.OperationalError, "unable to open database file"):
            self.update()
        # The compensating recreate still runs; neither outcome is durable in
        # SQLite. A fix that keeps evidence elsewhere must also update this test.
        self.assertEqual(self.docker, ["pull", ("recreate", "new-pin"), ("recreate", "old-pin")])
        self.assertEqual(self.compose.read_text(), self.original)
        self.assertEqual(self.state.history(), [])


if __name__ == "__main__":
    unittest.main()
