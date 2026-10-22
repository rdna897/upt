"""Issue #17: ``upt cleanup`` must honour R10 rollback protection.

Docker is mocked and every database is a temporary SQLite file.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py

import io
import hashlib
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlite_faults import select_from, sqlite_fault

from docker_update_manager import cli, diskdiag, retention
from docker_update_manager.retention import CleanupState, canonical_image_id, cleanup_blocker
from docker_update_manager.state import State, CORE_SCHEMA_VERSION, LEGACY_SCHEMA, SCHEMA9_VERSION
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
                patch.object(cli, "retention_cleanup") as retention_pass, \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["cleanup", "--yes"])
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertEqual(docker.removed, [FREE])
        retention_pass.assert_not_called()

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

    def test_retention_pass_skips_image_protected_just_before_removal(self):
        self.record(PROTECTED, service="app")
        self.record(OTHER, service="worker")
        self.sql("UPDATE rollback_refs SET created='2000-01-01 00:00:00'")
        removed = []
        real_blocker = retention._removal_blocker

        def concurrent_writer(state, image_id, **kwargs):
            reason = real_blocker(state, image_id, **kwargs)
            if image_id == OTHER:  # a new update publishes an active ref now
                self.record(OTHER, service="third")
            return reason

        def docker(args, **kwargs):
            if args[:3] == ["docker", "image", "ls"]:
                return "\n"
            if args[:3] == ["docker", "image", "rm"]:
                removed.append(args[-1])
                return ""
            if args[:3] == ["docker", "ps", "-aq"]:
                return ""
            raise CommandError("not mocked")
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state.root)}), patch.object(cli, "run", docker), \
                patch("docker_update_manager.retention.run", docker), \
                patch.object(retention, "_removal_blocker", concurrent_writer), \
                patch.object(cli, "quick_snapshot", lambda *a, **k: None), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = cli.main(["cleanup", "--yes"])
        self.assertEqual(code, 0)
        self.assertEqual(removed, [PROTECTED])

    def test_existing_only_compaction_never_recreates_a_removed_database(self):
        state = State(self.state.root, require_existing=True)
        with self.state.connect() as c:
            c.execute("CREATE TABLE filler(x)")
            c.executemany("INSERT INTO filler VALUES(?)", [("x" * 4000,)] * 600)
        with self.state.connect() as c:
            c.execute("DROP TABLE filler")
        real_read = State.read

        @contextmanager
        def read_then_vanish(self_, *args, **kwargs):
            with real_read(self_, *args, **kwargs) as c:
                yield c
            for suffix in ("", "-wal", "-shm"):
                Path(str(self_.db_path) + suffix).unlink(missing_ok=True)
        with patch.object(State, "read", read_then_vanish), self.assertRaises(sqlite3.OperationalError):
            state.compact_if_needed()
        self.assertFalse(state.db_path.exists())

    def test_database_vanishing_before_compaction_is_fatal(self):
        state = State(self.state.root, require_existing=True)
        for suffix in ("", "-wal", "-shm"):
            Path(str(state.db_path) + suffix).unlink(missing_ok=True)
        with self.assertRaisesRegex(RuntimeError, "disappeared"):
            state.compact_if_needed()
        self.assertEqual(State(self.root / "other").compact_if_needed(), {"compacted": False, "bytes_reclaimed": 0})

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

    def retention_fixture(self):
        """Expired legacy/ref rows, audit data and two synthetic recovery files."""
        legacy = self.record(PROTECTED)
        self.record(OTHER, service="worker")
        self.sql("DELETE FROM rollback_refs WHERE history_id=?", (legacy,))
        self.sql("UPDATE protected_images SET created='2000-01-01 00:00:00'")
        self.sql("UPDATE rollback_refs SET created='2000-01-01 00:00:00'")
        self.sql("UPDATE history SET timestamp='2000-01-01 00:00:00'")
        self.state.save_disk_snapshot("synthetic", {})
        self.sql("UPDATE disk_snapshots SET timestamp='2000-01-01 00:00:00'")
        paths = [self.state.root / "backups" / name for name in ("first", "second")]
        paths[0].parent.mkdir()
        for path in paths:
            path.write_text("synthetic recovery evidence")
            os.utime(path, (0, 0))
        self.replacement = self.root / "replacement.sqlite3"
        with closing(sqlite3.connect(self.state.db_path)) as source, closing(sqlite3.connect(self.replacement)) as target:
            source.backup(target)
        self.replacement_rows = self.database_rows(self.replacement)
        return paths

    @staticmethod
    def database_rows(path):
        with closing(sqlite3.connect(path)) as c:
            return {name: c.execute(f"SELECT * FROM {name}").fetchall()
                    for name in ("history", "protected_images", "rollback_refs", "disk_snapshots", "compose_recovery_receipts")}

    def replace_retention_state(self):
        os.replace(self.state.db_path, self.root / "displaced.sqlite3")
        for suffix in ("-wal", "-shm"):
            Path(str(self.state.db_path) + suffix).unlink(missing_ok=True)
        os.replace(self.replacement, self.state.db_path)

    def automatic_retention(self, on_rm=None):
        """Exercise the actual CLI wiring with no snapshots or live Docker."""
        docker = _Docker([], on_rm=on_rm)
        cfg = SimpleNamespace(state_dir=self.state.root, log_dir=self.root / "logs", data={"retention": {"recovery_days": 7}})
        out, err = io.StringIO(), io.StringIO()
        with patch.object(cli, "Config", return_value=cfg), patch.object(cli, "run", docker), \
                patch.object(cli, "quick_snapshot"), patch.object(retention, "run", docker), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(["cleanup", "--yes", "--no-progress"])
        return code, docker, err.getvalue()

    def assert_retention_refused(self, result):
        code, docker, error = result
        self.assertEqual(code, cli.EXIT_FATAL, error)
        self.assertIn("replaced", error)
        self.assertEqual(docker.removed, [])
        self.assertEqual(self.database_rows(self.state.db_path), self.replacement_rows)

    def test_retention_inventory_replacement_preserves_all_recovery_evidence(self):
        paths = self.retention_fixture()
        real_inventory = retention.inventory

        def inventory_then_replace(*args, **kwargs):
            result = real_inventory(*args, **kwargs)
            self.replace_retention_state()
            return result

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(retention, "inventory", side_effect=inventory_then_replace), \
                patch.object(retention, "_migrate_refs", wraps=retention._migrate_refs) as migrate:
            self.assert_retention_refused(self.automatic_retention())
        migrate.assert_not_called()
        self.assertTrue(all(path.exists() for path in paths))

    def test_retention_accounting_replacement_prevents_migration_expiry_and_deletion(self):
        paths = self.retention_fixture()

        def accounting():
            # The callback runs after the rollback SELECT snapshot is closed.
            # A distinct writer can commit here before replacing the database.
            with State(self.state.root).connect() as c:
                c.execute("UPDATE disk_snapshots SET kind='accounting-writer'")
            self.replace_retention_state()
            return {}

        with patch.object(retention, "_docker_image_accounting", side_effect=accounting), \
                patch.object(retention, "_container_image_ids", return_value=set()):
            self.assert_retention_refused(self.automatic_retention())
        self.assertTrue(all(path.exists() for path in paths))

    def test_retention_replacement_before_expiry_preserves_reference_state(self):
        self.retention_fixture()

        def accounting_for_containers():
            self.replace_retention_state()
            return set()

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", side_effect=accounting_for_containers):
            self.assert_retention_refused(self.automatic_retention())

    def test_retention_revalidates_between_individual_recovery_deletions(self):
        paths = self.retention_fixture()
        removed = []
        real_unlink = Path.unlink

        def unlink_then_replace(path, *args, **kwargs):
            result = real_unlink(path, *args, **kwargs)
            if path in paths:
                removed.append(path)
                if len(removed) == 1:
                    self.replace_retention_state()
            return result

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(Path, "unlink", unlink_then_replace):
            self.assert_retention_refused(self.automatic_retention())
        self.assertEqual(len(removed), 1)
        self.assertTrue(next(path for path in paths if path != removed[0]).exists())

    def test_retention_replacement_before_final_pruning_preserves_metadata(self):
        self.retention_fixture()

        def skip_then_replace(state, image_id, **kwargs):
            if self.replacement.exists():
                self.replace_retention_state()
            return "SKIPPED - UNRESOLVED PROTECTION"

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(retention, "_removal_blocker", side_effect=skip_then_replace), \
                patch.object(State, "compact_if_needed") as compact:
            self.assert_retention_refused(self.automatic_retention())
        compact.assert_not_called()

    def retention_transaction_replacement(self, boundary):
        # 1: legacy migration, 2: ref expiry, 3: final pruning (images skipped).
        self.retention_fixture()
        real_connect = State.connect
        transactions = []

        @contextmanager
        def replace_before_transaction(state):
            transactions.append(state)
            if len(transactions) == boundary:
                # The separate pinned read has already succeeded.
                self.replace_retention_state()
            with real_connect(state) as c:
                yield c

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(retention, "_removal_blocker", return_value="SKIPPED"), \
                patch.object(State, "connect", replace_before_transaction):
            self.assert_retention_refused(self.automatic_retention())
        self.assertEqual(len(transactions), boundary)

    def test_retention_checks_migration_transaction_after_verification(self):
        self.retention_transaction_replacement(1)

    def test_retention_checks_expiry_transaction_after_verification(self):
        self.retention_transaction_replacement(2)

    def test_retention_checks_pruning_transaction_after_verification(self):
        self.retention_transaction_replacement(3)

    def test_retention_checks_protection_inside_write_transaction(self):
        paths = self.retention_fixture()
        before = self.database_rows(self.state.db_path)
        real_connect = State.connect

        @contextmanager
        def invalidate_transaction(state):
            with real_connect(state) as c:
                c.execute("UPDATE protected_images SET image_id='short-id' WHERE image_id=?", (PROTECTED,))
                yield c

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(State, "connect", invalidate_transaction):
            code, docker, error = self.automatic_retention()
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertIn("non-canonical", error)
        self.assertEqual(docker.removed, [])
        self.assertEqual(self.database_rows(self.state.db_path), before)
        self.assertTrue(all(path.exists() for path in paths))

    def test_retention_checks_before_commit_and_rolls_back_pruning(self):
        self.retention_fixture()
        real_connect = State.connect
        pruning_rows = []

        # Invalidate during the transaction body, before CleanupState's exit
        # check (rather than after its context manager has already exited).
        class PruningConnection:
            def __init__(self, c): self.c = c
            def __getattr__(self, name): return getattr(self.c, name)
            def execute(self, sql, params=()):
                result = self.c.execute(sql, params)
                if sql == "PRAGMA optimize":
                    self.c.execute("INSERT INTO protected_images(image_id,reason) VALUES('short-id','synthetic invalidation')")
                return result

        @contextmanager
        def pruning_connection(state):
            with real_connect(state) as c:
                # Record the committed state before the pruning transaction.
                pruning_rows[:] = [self.database_rows(self.state.db_path)]
                yield PruningConnection(c)

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(retention, "_removal_blocker", return_value="SKIPPED"), \
                patch.object(State, "connect", pruning_connection):
            code, docker, error = self.automatic_retention()
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertIn("non-canonical", error)
        self.assertEqual(docker.removed, [])
        self.assertEqual(self.database_rows(self.state.db_path), pruning_rows[0])

    def test_retention_replacement_after_pruning_prevents_compaction(self):
        self.retention_fixture()
        real_connect = State.connect
        transactions = []

        @contextmanager
        def replace_after_pruning(state):
            transactions.append(state)
            with real_connect(state) as c:
                yield c
            if len(transactions) == 3:
                self.replace_retention_state()

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(retention, "_removal_blocker", return_value="SKIPPED"), \
                patch.object(State, "connect", replace_after_pruning), \
                patch.object(State, "compact_if_needed") as compact:
            self.assert_retention_refused(self.automatic_retention())
        compact.assert_not_called()

    def test_retention_compaction_checks_the_actual_vacuum_connection(self):
        self.retention_fixture()
        with self.state.connect() as c:
            c.execute("CREATE TABLE filler(x)")
            c.executemany("INSERT INTO filler VALUES(?)", [("x" * 4000,)] * 600)
        self.sql("DROP TABLE filler")
        real_sqlite_connect = sqlite3.connect
        vacuum_statements = []

        class VacuumConnection(sqlite3.Connection):
            def execute(self, sql, *args, **kwargs):
                if sql == "VACUUM": vacuum_statements.append(sql)
                return super().execute(sql, *args, **kwargs)

        def replace_before_vacuum(*args, **kwargs):
            if kwargs.get("isolation_level", "default") is None:
                self.replace_retention_state()
                kwargs["factory"] = VacuumConnection
            return real_sqlite_connect(*args, **kwargs)

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(retention, "_removal_blocker", return_value="SKIPPED"), \
                patch.object(sqlite3, "connect", side_effect=replace_before_vacuum):
            self.assert_retention_refused(self.automatic_retention())
        self.assertEqual(vacuum_statements, [])

    def compose_retention_bundle(self):
        from docker_update_manager.compose_reconcile import RecoveryBundle
        operation_id = "e" * 32
        source = self.root / "synthetic-compose.yml"
        source.write_text("services: {}\n")
        content = source.read_bytes()
        item = SimpleNamespace(role="compose", path=str(source), present=True,
                               sha256=hashlib.sha256(content).hexdigest(), size=len(content), content=content)
        inputs = SimpleNamespace(files=(item,))
        self.state.create_operation(operation_id, kind="compose_reconcile", service_key="container/" + "f" * 64,
                                    service="app", stack="synthetic", requested_by="operator", summary={"baseline_id": "f" * 32})
        bundle = RecoveryBundle(self.state.root, operation_id, inputs, SimpleNamespace(inventory=inputs),
                                {"baseline_id": "f" * 32, "evidence": "a" * 64})
        self.state.set_operation_running(operation_id)
        self.state.finish_operation(operation_id, "succeeded", message="Synthetic completion", result={"manual_recovery_required": False})
        self.sql("UPDATE operation_runs SET created_at='2000-01-01 00:00:00',finished_at='2000-01-01 00:00:00'")
        self.state.prune_operations(retention_days=1)
        with closing(sqlite3.connect(self.state.db_path)) as source, closing(sqlite3.connect(self.replacement)) as target:
            source.backup(target)
        self.replacement_rows = self.database_rows(self.replacement)
        return bundle

    def test_retention_invalidated_compose_bundle_keeps_files_and_receipt(self):
        self.retention_fixture()
        bundle = self.compose_retention_bundle()
        real_cleanup = retention._cleanup_compose_artifact

        def invalidate_before_bundle(*args, **kwargs):
            self.replace_retention_state()
            return real_cleanup(*args, **kwargs)

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(retention, "_cleanup_compose_artifact", side_effect=invalidate_before_bundle):
            self.assert_retention_refused(self.automatic_retention())
        self.assertTrue((bundle.path / "manifest.json").exists())
        self.assertEqual(len(self.replacement_rows["compose_recovery_receipts"]), 1)

    def test_pinned_retention_releases_transactions_before_bundle_and_docker_removal(self):
        self.retention_fixture()
        bundle = self.compose_retention_bundle()
        from docker_update_manager import compose_recovery_retention
        real_remove = compose_recovery_retention.remove_bundle
        active = []

        def tracked(method):
            @contextmanager
            def transaction(state, *args, **kwargs):
                with method(state, *args, **kwargs) as c:
                    active.append(c)
                    try: yield c
                    finally: active.remove(c)
            return transaction

        def remove_bundle(*args):
            self.assertEqual(active, [], "SQLite transaction spans filesystem deletion")
            return real_remove(*args)

        def remove_image(image):
            self.assertEqual(active, [], "SQLite transaction spans Docker removal")

        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(State, "connect", tracked(State.connect)), \
                patch.object(State, "read", tracked(State.read)), \
                patch.object(State, "read_existing", tracked(State.read_existing)), \
                patch.object(compose_recovery_retention, "remove_bundle", side_effect=remove_bundle):
            code, docker, error = self.automatic_retention(on_rm=remove_image)
        self.assertEqual(code, 0, error)
        self.assertCountEqual(docker.removed, [PROTECTED, OTHER])
        self.assertFalse(bundle.path.exists())
        self.assertEqual(self.database_rows(self.state.db_path)["compose_recovery_receipts"], [])

    def test_retention_replacement_during_image_removal_prevents_outcome_writes(self):
        self.retention_fixture()
        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()):
            code, docker, error = self.automatic_retention(on_rm=lambda image: self.replace_retention_state())
        self.assertEqual(code, cli.EXIT_FATAL)
        self.assertIn("replaced", error)
        self.assertEqual(len(docker.removed), 1)
        self.assertEqual(self.database_rows(self.state.db_path), self.replacement_rows)

    def test_standalone_retention_preserves_age_expiry_and_forced_operations(self):
        self.record(PROTECTED)
        self.record(OTHER, service="worker")
        self.sql("UPDATE rollback_refs SET created='2000-01-01 00:00:00' WHERE image_id=?", (PROTECTED,))
        cfg = SimpleNamespace(log_dir=self.root / "logs", data={"retention": {"recovery_days": 7}})
        with patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(retention, "run", return_value="") as docker:
            result = retention.cleanup(cfg, self.state)
            self.assertEqual(result["images_removed"], 1)
            self.assertEqual([call.args[0][-1] for call in docker.call_args_list], [PROTECTED])
            self.assertEqual(retention.rollback_points(cfg, self.state)[0]["status"], "AVAILABLE")
            result = retention.cleanup(cfg, self.state, all_protected=True)
            self.assertEqual(result["images_removed"], 1)
            self.assertEqual(docker.call_args_list[-1].args[0], ["docker", "image", "rm", OTHER])

    def legacy_database(self, name):
        root = self.root / name
        root.mkdir()
        path = root / "history.sqlite3"
        with closing(sqlite3.connect(path)) as c, c:
            c.executescript(LEGACY_SCHEMA)
            c.execute("INSERT INTO protected_images(image_id,reason) VALUES(?,?)", (PROTECTED, "manual"))
        return root, path

    def test_existing_only_unversioned_legacy_refusal_is_unchanged_on_retries(self):
        root, path = self.legacy_database("legacy-refusal")
        before = path.read_bytes()
        state = State(root, require_existing=True)
        for candidate in (state, state, State(root, require_existing=True)):
            with self.assertRaisesRegex(RuntimeError, "not initialised"):
                candidate.ensure_compatible()
            self.assertFalse(candidate.created_schema)
            self.assertEqual(path.read_bytes(), before)
            with closing(sqlite3.connect(path)) as c:
                self.assertIsNone(c.execute("SELECT 1 FROM sqlite_master WHERE name='schema_version'").fetchone())
        self.assertEqual(sorted(p.name for p in root.iterdir()), ["history.sqlite3"])

    def test_unversioned_legacy_state_refused_unchanged_and_explicit_migration_preserves_protection(self):
        # Schema 10 never converts existing state on open (G2-S0b); only the
        # explicit offline path migrates, preserving NULL-history protection.
        root, path = self.legacy_database("legacy-migration")
        before = path.read_bytes()
        for options in ({}, {"require_existing": True}):
            with self.assertRaisesRegex(RuntimeError, "unversioned|not initialised"):
                State(root, **options).ensure_compatible()
        self.assertEqual(path.read_bytes(), before)
        state = State(root, quiescent_transition=True)
        state.ensure_compatible()
        with state.read() as c:
            self.assertEqual(c.execute("SELECT version FROM schema_version").fetchone()[0], SCHEMA9_VERSION)
            self.assertEqual(tuple(c.execute("SELECT image_id,reason,history_id FROM protected_images").fetchone()),
                             (PROTECTED, "manual", None))
        with self.assertRaisesRegex(RuntimeError, "schema-10 transition"):
            State(root, require_existing=True).ensure_compatible()

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

    def snapshot_fixture(self):
        """A protected image plus a byte-identical replacement database."""
        self.record(PROTECTED)
        self.state.save_disk_snapshot("synthetic", {})
        self.replacement = self.root / "replacement.sqlite3"
        with closing(sqlite3.connect(self.state.db_path)) as source, closing(sqlite3.connect(self.replacement)) as target:
            source.backup(target)
        self.replacement_rows = self.database_rows(self.replacement)
        self.original_rows = dict(self.replacement_rows)
        self.displaced = self.root / "displaced.sqlite3"

    def snapshot_command(self, argv, *, on_collect=None, connect=None):
        """Run ``argv`` through main with the real snapshot path and mocked collectors.

        ``on_collect(n)`` runs during the nth snapshot collection; ``connect``
        replaces State.connect. Returns (code, docker, stderr, retention mock).
        """
        collections = []

        def journal():
            collections.append(None)
            if on_collect:
                on_collect(len(collections))
            return {"size": 0}

        docker = _Docker([FREE])
        cfg = SimpleNamespace(state_dir=self.state.root, log_dir=self.root / "logs", data={"retention": {"recovery_days": 7}})
        err = io.StringIO()
        with patch.object(cli, "Config", return_value=cfg), patch.object(cli, "run", docker), \
                patch.object(retention, "run", docker), \
                patch.object(retention, "_docker_image_accounting", return_value={}), \
                patch.object(retention, "_container_image_ids", return_value=set()), \
                patch.object(cli, "retention_cleanup", wraps=cli.retention_cleanup) as retention_pass, \
                patch.object(diskdiag, "fs_metrics", return_value={"used": 1}), \
                patch.object(diskdiag, "docker_df", return_value={}), \
                patch.object(diskdiag, "container_logs", return_value=[]), \
                patch.object(diskdiag, "container_sizes", return_value=[]), \
                patch.object(diskdiag, "journal_usage", side_effect=journal), \
                patch.object(State, "connect", connect or State.connect), \
                redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = cli.main(argv)
        return code, docker, err.getvalue(), retention_pass, len(collections)

    def snapshot_kinds(self, path):
        with closing(sqlite3.connect(path)) as c:
            return [row[0] for row in c.execute("SELECT kind FROM disk_snapshots ORDER BY id")]

    def assert_snapshot_refused(self, result, message, *, removed):
        code, docker, error, retention_pass, _ = result
        self.assertEqual(code, cli.EXIT_FATAL, error)
        self.assertIn(message, error)
        self.assertEqual(docker.removed, removed)
        retention_pass.assert_not_called()

    def replace_snapshot_state(self):
        os.replace(self.state.db_path, self.displaced)
        for suffix in ("-wal", "-shm"):
            Path(str(self.state.db_path) + suffix).unlink(missing_ok=True)
        os.replace(self.replacement, self.state.db_path)

    def test_cleanup_snapshot_refuses_replacement_during_pre_cleanup_collection(self):
        self.snapshot_fixture()
        result = self.snapshot_command(["cleanup", "--yes", "--no-progress"],
                                       on_collect=lambda n: n == 1 and self.replace_snapshot_state())
        self.assert_snapshot_refused(result, "replaced", removed=[])
        self.assertEqual(result[4], 1)
        self.assertEqual(self.database_rows(self.state.db_path), self.replacement_rows)
        self.assertEqual(self.database_rows(self.displaced), self.original_rows)

    def test_cleanup_snapshot_refuses_replacement_during_post_cleanup_collection(self):
        self.snapshot_fixture()
        result = self.snapshot_command(["cleanup", "--yes", "--no-progress"],
                                       on_collect=lambda n: n == 2 and self.replace_snapshot_state())
        self.assert_snapshot_refused(result, "replaced", removed=[FREE])
        self.assertEqual(self.database_rows(self.state.db_path), self.replacement_rows)
        self.assertEqual(self.snapshot_kinds(self.displaced), ["synthetic", "before-cleanup"])

    def snapshot_transaction_replacement(self, collection):
        # The pinned read before the transaction succeeds; the file is then
        # replaced before BEGIN IMMEDIATE opens on the path.
        self.snapshot_fixture()
        real_connect = State.connect
        collected = []

        @contextmanager
        def replace_before_transaction(state):
            if collected == [collection]:
                collected.append("replaced")
                self.replace_snapshot_state()
            with real_connect(state) as c:
                yield c

        result = self.snapshot_command(["cleanup", "--yes", "--no-progress"], connect=replace_before_transaction,
                                       on_collect=lambda n: collected.append(n) if n == collection else None)
        self.assertEqual(collected, [collection, "replaced"])
        self.assert_snapshot_refused(result, "replaced", removed=[] if collection == 1 else [FREE])
        self.assertEqual(self.database_rows(self.state.db_path), self.replacement_rows)

    def test_cleanup_pre_snapshot_checks_transaction_opened_after_verification(self):
        self.snapshot_transaction_replacement(1)

    def test_cleanup_post_snapshot_checks_transaction_opened_after_verification(self):
        self.snapshot_transaction_replacement(2)

    def snapshot_transaction_invalidation(self, invalidate):
        """Invalidate state after the snapshot INSERT, before commit."""
        real_connect = State.connect

        class SnapshotConnection:
            def __init__(self, c): self.c = c
            def __getattr__(self, name): return getattr(self.c, name)
            def execute(self, sql, params=()):
                result = self.c.execute(sql, params)
                if sql.startswith("INSERT INTO disk_snapshots"):
                    invalidate(self.c)
                return result

        @contextmanager
        def snapshot_connection(state):
            with real_connect(state) as c:
                yield SnapshotConnection(c)

        return self.snapshot_command(["cleanup", "--yes", "--no-progress"], connect=snapshot_connection)

    def test_cleanup_snapshot_replacement_before_commit_rolls_back(self):
        self.snapshot_fixture()
        real_save, refusals = State.save_disk_snapshot, []

        def save(state, *args, **kwargs):
            try:
                return real_save(state, *args, **kwargs)
            except RuntimeError as exc:
                refusals.append(str(exc))
                raise

        with patch.object(State, "save_disk_snapshot", save):
            result = self.snapshot_transaction_invalidation(lambda c: self.replace_snapshot_state())
        self.assert_snapshot_refused(result, "replaced", removed=[])
        # The snapshot write itself refused, rather than a later cleanup check.
        self.assertEqual(len(refusals), 1)
        self.assertIn("replaced", refusals[0])
        self.assertEqual(self.database_rows(self.state.db_path), self.replacement_rows)
        # The open transaction on the displaced file was rolled back.
        self.assertEqual(self.database_rows(self.displaced), self.original_rows)

    def test_cleanup_snapshot_protection_invalidated_in_transaction_rolls_back(self):
        self.snapshot_fixture()
        result = self.snapshot_transaction_invalidation(
            lambda c: c.execute("INSERT INTO protected_images(image_id,reason) VALUES('short-id','synthetic invalidation')"))
        self.assert_snapshot_refused(result, "non-canonical", removed=[])
        self.assertEqual(self.database_rows(self.state.db_path), self.original_rows)

    def test_successful_cleanup_persists_before_and_after_snapshots(self):
        self.snapshot_fixture()
        code, docker, error, retention_pass, collections = self.snapshot_command(["cleanup", "--yes", "--no-progress"])
        self.assertEqual(code, 0, error)
        self.assertEqual(docker.removed, [FREE])
        retention_pass.assert_called_once()
        self.assertEqual(collections, 2)
        self.assertEqual(self.snapshot_kinds(self.state.db_path), ["synthetic", "before-cleanup", "after-cleanup"])
        snapshots = {row["kind"]: row["metrics"] for row in self.state.disk_snapshots()}
        self.assertEqual(snapshots["after-cleanup"]["filesystem"], {"used": 1})

    def test_other_modifying_commands_keep_ordinary_snapshot_persistence(self):
        self.snapshot_fixture()
        with patch.object(cli, "execute", return_value=0), patch.object(cli, "CleanupState", side_effect=AssertionError):
            code, docker, error, retention_pass, collections = self.snapshot_command(["update", "app", "--yes", "--no-progress"])
        self.assertEqual(code, 0, error)
        self.assertEqual(collections, 2)
        self.assertEqual(self.snapshot_kinds(self.state.db_path), ["synthetic", "before-update", "after-update"])


if __name__ == "__main__":
    unittest.main()
