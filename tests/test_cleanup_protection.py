"""Issue #17: ``upt cleanup`` must honour R10 rollback protection.

Docker is mocked and every database is a temporary SQLite file.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py

import io
import os
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlite_faults import select_from, sqlite_fault

from docker_update_manager import cli
from docker_update_manager.retention import CleanupState, canonical_image_id, cleanup_blocker
from docker_update_manager.state import State
from docker_update_manager.system import CommandError

PROTECTED = "sha256:a1b2c3d4e5f6" + "0" * 52
FREE = "sha256:" + "c" * 64
OTHER = "sha256:" + "d" * 64
NEW = "sha256:" + "b" * 64


class _Docker:
    """Fake ``run``: lists ``listing`` and records every removal."""

    def __init__(self, listing, on_rm=None):
        self.listing = listing
        self.on_rm = on_rm
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if args[:3] == ["docker", "image", "ls"]:
            return "\n".join(self.listing) + "\n"
        if args[:3] == ["docker", "image", "rm"]:
            if self.on_rm:
                self.on_rm(args[-1])
            return ""
        raise AssertionError(f"unexpected Docker call: {args}")

    @property
    def removed(self):
        return [a[-1] for a in self.calls if a[:3] == ["docker", "image", "rm"]]


class CleanupProtectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        State(self.root / "state").ensure_compatible()
        # A State that initialised the schema itself is refused by cleanup.
        self.state = State(self.root / "state")

    def record(self, image_id, service="app", stack="s"):
        self.state.record(stack=stack, service=service, action="update", old_image=f"{service}:1",
                          old_image_id=image_id, new_image=f"{service}:2", new_image_id=NEW, result="SUCCESS")
        with self.state.read() as c:
            return c.execute("SELECT MAX(id) FROM history").fetchone()[0]

    def sql(self, statement, params=()):
        with self.state.connect() as c:
            c.execute(statement, params)

    def cleanup(self, docker, *, dry_run=False):
        out = io.StringIO()
        with patch.object(cli, "run", docker), redirect_stdout(out):
            cli.cleanup(self.state, SimpleNamespace(dry_run=dry_run, yes=True))
        return out.getvalue()

    def refused(self, docker, *, dry_run=False):
        with patch.object(cli, "run", docker), redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError) as raised:
                cli.cleanup(self.state, SimpleNamespace(dry_run=dry_run, yes=True))
        self.assertEqual(docker.removed, [])
        return str(raised.exception)

    def test_listing_requests_full_ids(self):
        docker = _Docker([FREE])
        self.cleanup(docker)
        self.assertEqual(docker.calls[0], ["docker", "image", "ls", "-q", "--no-trunc", "--filter", "dangling=true"])

    def test_protected_image_listed_with_truncated_id_is_never_removed(self):
        self.record(PROTECTED)
        self.assertIn("unrecognised", self.refused(_Docker([PROTECTED[7:19]])))
        self.assertIn("unrecognised", self.refused(_Docker([PROTECTED[7:19], FREE])))

    def test_protected_image_with_full_id_is_never_removed(self):
        self.record(PROTECTED)
        for listed in (PROTECTED, PROTECTED.upper().replace("SHA256", "sha256")):
            docker = _Docker([listed])
            out = self.cleanup(docker)
            self.assertEqual(docker.removed, [])
            self.assertIn("Dangling image candidates: 0", out)
            self.assertIn(f"{PROTECTED}  ROLLBACK PROTECTED", out)

    def test_unprotected_dangling_image_is_removed(self):
        docker = _Docker([FREE])
        self.assertIn("Removed 1 images.", self.cleanup(docker))
        self.assertEqual(docker.removed, [FREE])

    def test_mixed_set_removes_only_eligible_images(self):
        self.record(PROTECTED)
        docker = _Docker([PROTECTED, FREE, OTHER])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [FREE, OTHER])

    def test_null_history_manual_protection_blocks_removal(self):
        self.sql("INSERT INTO protected_images(image_id,reason) VALUES(?,?)", (PROTECTED, "namespace update manual recovery"))
        docker = _Docker([PROTECTED, FREE])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [FREE])

    def test_manual_protection_survives_an_expired_ref_for_the_same_image(self):
        history = self.record(PROTECTED)
        self.sql("UPDATE rollback_refs SET expired=1,purge_status='EXPIRED' WHERE history_id=?", (history,))
        self.sql("UPDATE protected_images SET history_id=NULL WHERE image_id=?", (PROTECTED,))
        docker = _Docker([PROTECTED])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [])

    def test_active_rollback_ref_blocks_removal(self):
        self.record(PROTECTED)
        self.sql("DELETE FROM protected_images")
        docker = _Docker([PROTECTED])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [])

    def test_unmigrated_legacy_protection_blocks_removal(self):
        self.record(PROTECTED)
        self.sql("DELETE FROM rollback_refs")
        docker = _Docker([PROTECTED])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [])

    def test_expired_resolved_reference_stays_eligible(self):
        history = self.record(PROTECTED)
        self.sql("UPDATE rollback_refs SET expired=1,purge_status='EXPIRED' WHERE history_id=?", (history,))
        docker = _Docker([PROTECTED])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [PROTECTED])
        # A fully retired protection (only the terminal audit ref left) too.
        self.sql("DELETE FROM protected_images")
        docker = _Docker([PROTECTED])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [PROTECTED])

    def test_shared_image_stays_protected_while_any_owner_requires_it(self):
        first = self.record(PROTECTED, service="app")
        second = self.record(PROTECTED, service="worker")
        self.sql("UPDATE rollback_refs SET expired=1,purge_status='EXPIRED' WHERE history_id=?", (second,))
        docker = _Docker([PROTECTED])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [])
        self.sql("UPDATE rollback_refs SET expired=1,purge_status='EXPIRED' WHERE history_id=?", (first,))
        docker = _Docker([PROTECTED])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [PROTECTED])

    def test_protection_published_after_listing_blocks_removal(self):
        def concurrent_update(image):
            # Holding any transaction across Docker would stall this writer.
            if image == FREE:
                self.record(OTHER, service="worker")
        docker = _Docker([FREE, OTHER], on_rm=concurrent_update)
        out = self.cleanup(docker)
        self.assertEqual(docker.removed, [FREE])
        self.assertIn(f"skipped {OTHER}: ROLLBACK PROTECTED", out)
        self.assertIn("Removed 1 images. Skipped 1 newly protected image(s).", out)

    def test_state_read_failure_removes_nothing(self):
        self.record(PROTECTED)
        docker = _Docker([PROTECTED, FREE])
        with sqlite_fault(self.state, select_from("rollback_refs"), mode="read_failure"):
            self.assertIn("could not be read", self.refused(docker))

    def test_revalidation_read_failure_stops_further_removals(self):
        def fail_next_read(image):
            fault = sqlite_fault(self.state, select_from("rollback_refs"), mode="unavailable")
            fault.__enter__()
            self.addCleanup(fault.__exit__, None, None, None)
        docker = _Docker([FREE, OTHER], on_rm=fail_next_read)
        out = io.StringIO()
        with patch.object(cli, "run", docker), redirect_stdout(out), self.assertRaises(RuntimeError):
            cli.cleanup(self.state, SimpleNamespace(dry_run=False, yes=True))
        self.assertEqual(docker.removed, [FREE])
        self.assertIn("Removed 1 images.", out.getvalue())

    def test_missing_database_fails_closed_without_creating_it(self):
        state = State(self.root / "absent")
        with self.assertRaisesRegex(RuntimeError, "missing"):
            CleanupState(state)
        self.assertFalse(state.db_path.exists())

    def test_incompatible_database_fails_closed(self):
        self.sql("UPDATE schema_version SET version=99")
        docker = _Docker([FREE])
        self.refused(docker, dry_run=True)
        self.refused(docker)

    def test_main_refuses_cleanup_when_database_is_missing(self):
        state_dir = self.root / "fresh"
        docker = _Docker([FREE])
        err = io.StringIO()
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(state_dir)}), patch.object(cli, "run", docker), \
                redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cli.main(["cleanup", "--yes"])
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertIn("database is missing", err.getvalue())
        self.assertEqual(docker.calls, [])
        self.assertFalse((state_dir / "history.sqlite3").exists())

    def test_main_reports_state_read_failure_as_fatal(self):
        docker = _Docker([FREE])
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state.root)}), patch.object(cli, "run", docker), \
                patch.object(cli, "State", lambda root, **options: self.state), \
                sqlite_fault(self.state, select_from("rollback_refs"), mode="read_failure", times=5), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["cleanup", "--dry-run"])
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertEqual(docker.removed, [])

    def test_malformed_ambiguous_and_colliding_listings_remove_nothing_unsafe(self):
        self.record(PROTECTED)
        for bad in ("", "sha256:" + "a" * 63, "sha256:" + "g" * 64, "sha512:" + "a" * 64, "a" * 64,
                    "sha256:" + "a" * 64 + "0", "<none>"):
            if bad:
                self.refused(_Docker([FREE, bad]))
        # Duplicates are one image, removed once.
        docker = _Docker([FREE, FREE.upper().replace("SHA256", "sha256")])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [FREE])
        # Full IDs sharing the protected image's 12-character prefix stay distinct.
        collider = PROTECTED[:19] + "f" * 52
        docker = _Docker([PROTECTED, collider])
        self.cleanup(docker)
        self.assertEqual(docker.removed, [collider])

    def test_non_canonical_stored_identity_fails_closed(self):
        # Retention matches stored IDs exactly, so cleanup must not proceed on
        # a record that only cleanup could interpret (review finding).
        for stored in (PROTECTED[7:19], PROTECTED[:19], PROTECTED.upper(), " " + PROTECTED, "app:1"):
            self.sql("DELETE FROM protected_images")
            self.sql("INSERT INTO protected_images(image_id,reason) VALUES(?,?)", (stored, "manual"))
            self.assertIn("non-canonical", self.refused(_Docker([FREE])))

    def test_main_does_not_reach_retention_when_stored_identity_is_abbreviated(self):
        history = self.record(PROTECTED)
        self.sql("UPDATE rollback_refs SET expired=1,purge_status='EXPIRED',created='2000-01-01 00:00:00' WHERE history_id=?", (history,))
        self.sql("INSERT INTO protected_images(image_id,reason) VALUES(?,?)", (PROTECTED[7:19], "manual"))
        docker = _Docker([PROTECTED])
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state.root)}), patch.object(cli, "run", docker), \
                patch("docker_update_manager.retention.run", docker), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["cleanup", "--yes"])
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertEqual(docker.removed, [])

    def test_empty_or_uninitialised_database_fails_closed_without_initialising(self):
        for content in (b"", None):
            state = State(self.root / f"uninitialised-{content is None}")
            state.root.mkdir()
            if content is None:
                sqlite3.connect(state.db_path).close()  # valid SQLite, no UPT schema
            else:
                state.db_path.write_bytes(content)
            with self.assertRaisesRegex(RuntimeError, "not initialised"):
                CleanupState(state)
            with state.db_path.open("rb") as f:
                self.assertEqual(f.read(), b"")

    def test_database_replaced_during_cleanup_fails_closed(self):
        self.record(PROTECTED)
        with CleanupState(self.state) as pinned:
            self.assertEqual(pinned.protection(), {PROTECTED})
            os.replace(self.state.db_path, self.root / "moved.sqlite3")
            for suffix in ("-wal", "-shm"):
                Path(str(self.state.db_path) + suffix).unlink(missing_ok=True)
            State(self.state.root).ensure_compatible()  # another process recreates it
            with self.assertRaisesRegex(RuntimeError, "replaced"):
                pinned.protection()

    def test_database_reinitialised_in_place_fails_closed(self):
        self.record(PROTECTED)
        with CleanupState(self.state) as pinned:
            for suffix in ("-wal", "-shm"):
                Path(str(self.state.db_path) + suffix).unlink(missing_ok=True)
            with self.state.db_path.open("r+b") as f:
                f.truncate(0)  # same inode
            self.state._schema_ready = False
            self.state.ensure_compatible()  # re-initialises the empty file
            with self.assertRaisesRegex(RuntimeError, "initialised during this run"):
                pinned.protection()

    def test_main_refuses_when_state_is_emptied_before_compatibility_check(self):
        self.record(PROTECTED)
        real = State.ensure_compatible

        def truncate_then_check(state):
            State.ensure_compatible = real  # only the first check races
            for suffix in ("-wal", "-shm"):
                Path(str(state.db_path) + suffix).unlink(missing_ok=True)
            with state.db_path.open("r+b") as f:
                f.truncate(0)
            return real(state)
        docker = _Docker([PROTECTED])
        codes = []
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state.root)}), patch.object(cli, "run", docker), \
                patch("docker_update_manager.retention.run", docker), \
                patch.object(State, "ensure_compatible", truncate_then_check), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            codes.append(cli.main(["cleanup", "--yes"]))
            # The refusal must not leave a valid empty database for a retry.
            self.assertEqual(self.state.db_path.stat().st_size, 0)
            codes.append(cli.main(["cleanup", "--yes"]))
        self.assertEqual(codes, [cli.EXIT_FATAL, cli.EXIT_FATAL])
        self.assertEqual(self.state.db_path.stat().st_size, 0)
        self.assertEqual(docker.removed, [])

    def test_stub_schema_is_never_initialised_and_retry_still_refuses(self):
        import sqlite3 as sql
        # Version cases carry the core tables so only version validation refuses them.
        core = ("CREATE TABLE history(id INTEGER PRIMARY KEY); CREATE TABLE protected_images(image_id TEXT PRIMARY KEY); "
                "CREATE TABLE rollback_refs(history_id INTEGER PRIMARY KEY, image_id TEXT); ")
        stubs = {
            "no-row": core + "CREATE TABLE schema_version(version INTEGER)",
            "zero": core + "CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(0)",
            "negative": core + "CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(-1)",
            "text": core + "CREATE TABLE schema_version(version TEXT); INSERT INTO schema_version VALUES('9')",
            "two-rows": core + "CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(9),(9)",
            "no-tables": "CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(9)",
            "partial-tables": "CREATE TABLE history(id INTEGER PRIMARY KEY); CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(9)",
        }
        for name, script in stubs.items():
            root = self.root / f"stub-{name}"
            root.mkdir()
            with sql.connect(root / "history.sqlite3") as c:
                c.executescript(script)
            before = (root / "history.sqlite3").read_bytes()
            docker = _Docker([PROTECTED])
            codes = []
            with patch.dict(os.environ, {"UPT_STATE_DIR": str(root)}), patch.object(cli, "run", docker), \
                    patch("docker_update_manager.retention.run", docker), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                for _ in range(2):
                    codes.append(cli.main(["cleanup", "--yes"]))
            self.assertEqual(codes, [cli.EXIT_FATAL, cli.EXIT_FATAL], name)
            self.assertEqual((root / "history.sqlite3").read_bytes(), before, name)
            self.assertEqual(docker.removed, [], name)

    def test_unopenable_database_is_fatal_not_a_traceback(self):
        real_open = os.open

        def denied(path, *args, **kwargs):
            if Path(path) == self.state.db_path:
                raise PermissionError(13, "Permission denied")
            return real_open(path, *args, **kwargs)
        docker = _Docker([FREE])
        err = io.StringIO()
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state.root)}), patch.object(cli, "run", docker), \
                patch("docker_update_manager.retention.os.open", denied), \
                redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cli.main(["cleanup", "--yes"])
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertIn("cannot be opened", err.getvalue())
        self.assertEqual(docker.calls, [])

    def test_retention_pass_refuses_when_state_is_replaced_after_cleanup(self):
        self.record(PROTECTED)

        def replace_state(image):
            os.replace(self.state.db_path, self.root / "moved.sqlite3")
            for suffix in ("-wal", "-shm"):
                Path(str(self.state.db_path) + suffix).unlink(missing_ok=True)
            State(self.state.root).ensure_compatible()  # another valid database
        docker = _Docker([FREE], on_rm=replace_state)
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state.root)}), patch.object(cli, "run", docker), \
                patch.object(cli, "quick_snapshot", lambda *a, **k: None), \
                patch.object(cli, "retention_cleanup") as retention, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["cleanup", "--yes"])
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertEqual(docker.removed, [FREE])
        retention.assert_not_called()

    def test_retention_pass_revalidates_pinned_state_before_each_removal(self):
        self.record(PROTECTED, service="app")
        self.record(OTHER, service="worker")
        # Both refs are past retention; OTHER also has unresolved manual protection.
        self.sql("UPDATE rollback_refs SET created='2000-01-01 00:00:00'")
        self.sql("UPDATE protected_images SET history_id=NULL WHERE image_id=?", (OTHER,))
        removed = []

        def docker(args, **kwargs):
            if args[:3] == ["docker", "image", "ls"]:
                return "\n"
            if args[:3] == ["docker", "image", "rm"]:
                removed.append(args[-1])
                # Another valid, empty database appears mid-retention.
                os.replace(self.state.db_path, self.root / "moved.sqlite3")
                for suffix in ("-wal", "-shm"):
                    Path(str(self.state.db_path) + suffix).unlink(missing_ok=True)
                State(self.state.root).ensure_compatible()
                return ""
            if args[:3] == ["docker", "ps", "-aq"]:
                return ""
            raise CommandError("not mocked")
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state.root)}), patch.object(cli, "run", docker), \
                patch("docker_update_manager.retention.run", docker), \
                patch.object(cli, "quick_snapshot", lambda *a, **k: None), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["cleanup", "--yes"])
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertEqual(removed, [PROTECTED])  # OTHER's removal was refused
        self.assertNotIn(OTHER, removed)

    def test_state_errors_during_cleanup_are_fatal_not_tracebacks(self):
        real = State.ensure_compatible

        def vanish(state):
            State.ensure_compatible = real
            state.db_path.unlink()
            return real(state)
        docker = _Docker([FREE])
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state.root)}), patch.object(cli, "run", docker), \
                patch.object(State, "ensure_compatible", vanish), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["cleanup", "--yes"])
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertEqual(docker.calls, [])
        self.assertFalse(self.state.db_path.exists())

    def test_web_state_supports_existing_only_reads(self):
        from docker_update_manager.webstate import WebState
        web = WebState(self.root / "web")
        with patch.dict(os.environ, {"UPT_TESTING": "1"}):
            web.ensure_compatible()
            with web.read_existing() as c:
                self.assertTrue(c.execute("SELECT version FROM schema_version").fetchone())

    def test_existing_only_state_never_creates_or_initialises(self):
        missing = State(self.root / "absent", require_existing=True)
        with self.assertRaises(sqlite3.OperationalError):
            missing.ensure_compatible()
        self.assertFalse(missing.db_path.exists())
        empty = State(self.root / "empty", require_existing=True)
        empty.root.mkdir()
        empty.db_path.write_bytes(b"")
        with self.assertRaisesRegex(RuntimeError, "not initialised"):
            empty.ensure_compatible()
        with self.assertRaisesRegex(RuntimeError, "not initialised"):
            with empty.connect():
                pass
        self.assertEqual(empty.db_path.stat().st_size, 0)
        existing = State(self.state.root, require_existing=True)
        existing.ensure_compatible()
        self.assertFalse(existing.created_schema)

    def test_main_does_not_reach_retention_with_expired_abbreviated_ref(self):
        self.record(PROTECTED)  # active canonical ref
        self.sql("INSERT INTO rollback_refs(history_id,image_id,expired,purge_status,created) VALUES(999,?,1,'EXPIRED','2000-01-01 00:00:00')", (PROTECTED[7:19],))
        self.sql("INSERT INTO protected_images(image_id,reason,history_id) VALUES(?,?,999)", (PROTECTED[7:19], "rollback"))
        docker = _Docker([PROTECTED])
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state.root)}), patch.object(cli, "run", docker), \
                patch("docker_update_manager.retention.run", docker), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["cleanup", "--yes"])
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertEqual(docker.removed, [])

    def test_dry_run_lists_only_eligible_images_and_mutates_nothing(self):
        self.record(PROTECTED)
        with self.state.read() as c:
            before = [tuple(r) for r in c.execute("SELECT * FROM rollback_refs UNION ALL SELECT image_id,reason,history_id,created,NULL FROM protected_images")]
        docker = _Docker([PROTECTED, FREE])
        out = self.cleanup(docker, dry_run=True)
        self.assertEqual([c[:3] for c in docker.calls], [["docker", "image", "ls"]])
        candidates = out.split("Dangling image candidates: ", 1)[1]
        self.assertTrue(candidates.startswith("1\n"))
        self.assertIn(f"  {FREE}\nProtected (not removed; rollback images still expire through normal retention, see `upt retention`):\n  {PROTECTED}  ROLLBACK PROTECTED", out)
        self.assertIn("DRY RUN — no images removed.", out)
        with self.state.read() as c:
            after = [tuple(r) for r in c.execute("SELECT * FROM rollback_refs UNION ALL SELECT image_id,reason,history_id,created,NULL FROM protected_images")]
        self.assertEqual(before, after)

    def test_canonical_identity_and_blocker_reject_abbreviations(self):
        self.assertEqual(canonical_image_id(" " + PROTECTED.upper().replace("SHA256", "SHA256") + "\n"), PROTECTED)
        for value in (None, 12, PROTECTED[7:], PROTECTED[:19], "sha256:", PROTECTED + "0"):
            self.assertIsNone(canonical_image_id(value))
        self.assertEqual(cleanup_blocker(frozenset(), PROTECTED[:19]), "INVALID IMAGE IDENTITY")
        self.assertIsNone(cleanup_blocker(frozenset({PROTECTED}), FREE))


if __name__ == "__main__":
    unittest.main()
