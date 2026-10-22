"""G2-S0b: schema-10 recovery fences/claims, offline migration and inert enforcement.

Synthetic fences and claims are inserted with raw SQL by these tests only; no
production code path writes the G2 tables. Docker, Compose and registry
boundaries are mocked; every database is an isolated temporary file.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import contextlib
import hashlib
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from docker_update_manager import completion_fence, retention, state_transition
from docker_update_manager.compose_baseline import logical_key
from docker_update_manager.completion_fence import CompletionFenceError
from docker_update_manager.lock import Lock
from docker_update_manager.models import Service
from docker_update_manager.progress import Reporter
from docker_update_manager.state import CORE_SCHEMA_VERSION, State
from docker_update_manager.state_transition import refuse_schema10_downgrade, transition, upgrade_schema10
from docker_update_manager.webstate import WEB_SCHEMA_VERSION, WebState
import test_compose_apply as apply_fixtures
import test_compose_discard as discard_fixtures
from test_compose_reconciliation import ComposeFixture

FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(FIXTURES))
try:
    import release_schema9_state as schema9
finally:
    sys.path.remove(str(FIXTURES))

IMAGE_A = "sha256:" + "a" * 64
IMAGE_B = "sha256:" + "b" * 64
IMAGE_C = "sha256:" + "c" * 64
OP_1, OP_2 = "1" * 32, "2" * 32
NOW = "2026-10-18T00:00:00+00:00"
COMPOSE = "services:\n  app:\n    image: example/app:latest\n"


def db_version(root):
    with contextlib.closing(sqlite3.connect(f"file:{Path(root) / 'history.sqlite3'}?mode=ro", uri=True)) as c:
        return c.execute("SELECT version FROM schema_version").fetchone()[0]


def table_rows(path, tables=None):
    with contextlib.closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as c:
        names = tables or [r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_version'")]
        return {name: sorted(map(repr, c.execute(f'SELECT * FROM "{name}"'))) for name in names}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def compose_service(root, name="app", stack="media", files=None, working_dir=None, image_id=IMAGE_C,
                    image=None):
    working_dir = str(working_dir or (Path(root) / stack))
    files = files or [str(Path(working_dir) / "compose.yml")]
    return Service(name, "c" * 64, image or f"example/{name}:latest", image_id, "sha256:" + "d" * 64, "1.0.0", None,
                   "amd64", "running", "none", "unless-stopped", None, stack, name, working_dir, list(files))


def insert_fence(state, operation_id, service, *, lifecycle="active", action="update", evidence=None, key=None):
    evidence = evidence if evidence is not None else json.dumps(
        {"version": 1, "working_dir": os.path.abspath(service.working_dir),
         "compose_files": [os.path.abspath(f) for f in service.compose_files]})
    key = key or logical_key(service.stack, service.compose_service, service.working_dir, service.compose_files)
    with state.connect() as c:
        c.execute("INSERT INTO completion_fences VALUES(?,?,?,?,?,?,?,?,?)",
                  (operation_id, key, service.stack, service.compose_service, action, lifecycle, evidence, NOW, NOW))


def insert_claim(state, operation_id, kind, value):
    with state.connect() as c:
        c.execute("INSERT INTO completion_fence_claims VALUES(?,?,?)", (operation_id, kind, value))


def resolve(state, operation_id):
    with state.connect() as c:
        c.execute("UPDATE completion_fences SET lifecycle='resolved',updated_at=? WHERE operation_id=?", (NOW, operation_id))


def raw(state, *statements):
    """Simulate corrupted rows that bypass CHECK constraints."""
    with contextlib.closing(sqlite3.connect(state.db_path)) as c:
        c.execute("PRAGMA ignore_check_constraints=ON")
        for statement, *args in statements:
            c.execute(statement, *args)
        c.commit()


class Base(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state_dir = self.root / "state"


class Schema9Fixture(Base):
    """A populated schema-9 database written by the frozen schema-9 binary."""

    def make_schema9(self):
        old = schema9.State(self.state_dir)
        old.ensure_compatible()
        history = old.record(stack="media", service="app", action="update", old_image_id=IMAGE_A, result="SUCCESS")
        with old.connect() as c:
            c.execute("INSERT INTO protected_images(image_id,reason,history_id) VALUES(?,?,NULL)", (IMAGE_B, "manual"))
            c.execute("INSERT INTO compose_bootstrap_fences VALUES('k1','op-manual','proof','manual','2000-01-01','2000-01-01')")
            c.execute("INSERT INTO compose_bootstrap_fences VALUES('k2','op-done','proof','resolved','2000-01-01','2000-01-01')")
            c.execute("INSERT INTO compose_recovery_receipts VALUES('r1','f','terminal','2000-01-01')")
            c.execute("INSERT INTO operation_runs(id,kind,service_key,service,requested_by,status,created_at) "
                      "VALUES('done','update','container/x','app','fixture','succeeded','2000-01-01')")
        self.assertEqual(db_version(self.state_dir), 9)
        return history

    @property
    def db(self):
        return self.state_dir / "history.sqlite3"

    @property
    def snapshot(self):
        return self.state_dir / "schema-transitions" / state_transition.SCHEMA10_SNAPSHOT


class FreshAndCompatibilityTests(Schema9Fixture):
    def test_fresh_state_initialises_exact_schema10_separately_from_upgrades(self):
        state = State(self.state_dir)
        state.ensure_compatible()
        self.assertTrue(state.created_schema)
        self.assertEqual(db_version(self.state_dir), CORE_SCHEMA_VERSION)
        with state.read() as c:
            self.assertTrue(completion_fence.schema_matches(c))
            names = {r[0] for r in c.execute("SELECT name FROM sqlite_master")}
            self.assertEqual(c.execute("SELECT identity FROM core_schema_identity").fetchone()[0], State.core_schema_identity)
        self.assertTrue({"completion_fences", "completion_fence_claims", "idx_completion_fences_unresolved",
                         "idx_completion_fence_claims_value", "compose_bootstrap_fences"} <= names)
        self.assertFalse(list((self.state_dir).glob("schema-transitions")))

    def test_schema9_is_never_upgraded_by_open_cli_or_cleanup(self):
        self.make_schema9()
        before = self.db.read_bytes()
        for options in ({}, {"require_existing": True}):
            state = State(self.state_dir, **options)
            for call in (state.ensure_compatible, state.history, lambda: state.connect().__enter__()):
                with self.assertRaisesRegex(RuntimeError, "schema-10 transition"):
                    call()
        with retention.CleanupState(State(self.state_dir, require_existing=True)) as pinned, \
                self.assertRaisesRegex(RuntimeError, "not compatible"):
            pinned.protection()
        from docker_update_manager import cli
        config = Mock(state_dir=self.state_dir, data={})
        err = io.StringIO()
        with patch("docker_update_manager.cli.Config", return_value=config), \
                patch("docker_update_manager.cli.services", return_value=[]), \
                patch("docker_update_manager.cli.run") as docker, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["retention", "cleanup", "--yes"]), cli.EXIT_FATAL)
        docker.assert_not_called()
        self.assertIn("schema-10 transition", err.getvalue())
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(db_version(self.state_dir), 9)

    def test_schema9_binary_refuses_schema10_before_any_write(self):
        state = State(self.state_dir)
        service = compose_service(self.root)
        insert_fence(state, OP_1, service)
        insert_claim(state, OP_1, "image", IMAGE_A)
        before = self.db.read_bytes()
        old = schema9.State(self.state_dir)
        for call in (old.ensure_compatible, old.history,
                     lambda: old.record(service="forbidden", action="update", result="SUCCESS")):
            with self.assertRaisesRegex(RuntimeError, "unsupported core state database schema version 10"):
                call()
        with contextlib.closing(sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)) as c:
            self.assertFalse(schema9.cleanup_schema_compatible(c))
        self.assertEqual(self.db.read_bytes(), before)

    def test_unsupported_unversioned_empty_and_future_state_is_not_converted(self):
        cases = {
            "unversioned": "CREATE TABLE history(id INTEGER PRIMARY KEY)",
            "empty-version": "CREATE TABLE schema_version(version INTEGER)",
            "text-version": "CREATE TABLE schema_version(version TEXT); INSERT INTO schema_version VALUES('10')",
            "legacy": "CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(5)",
            "future": "CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(11)",
        }
        for name, script in cases.items():
            with self.subTest(name):
                root = self.root / name
                root.mkdir()
                with contextlib.closing(sqlite3.connect(root / "history.sqlite3")) as c:
                    c.executescript(script)
                before = (root / "history.sqlite3").read_bytes()
                with self.assertRaises(RuntimeError):
                    State(root).ensure_compatible()
                with self.assertRaises((ValueError, RuntimeError)):
                    upgrade_schema10(root, confirm_quiescent=True)
                self.assertEqual((root / "history.sqlite3").read_bytes(), before)

    def test_schema10_identity_mismatch_is_refused_including_long_lived_instances(self):
        state = State(self.state_dir)
        state.ensure_compatible()
        with contextlib.closing(sqlite3.connect(self.db)) as c:
            c.execute("DROP INDEX idx_completion_fence_claims_value")
            c.commit()
        for candidate in (state, State(self.state_dir)):
            with self.assertRaisesRegex(RuntimeError, "completion fence schema"):
                candidate.ensure_compatible()
        with retention.CleanupState(State(self.state_dir, require_existing=True)) as pinned, \
                self.assertRaisesRegex(RuntimeError, "not compatible"):
            pinned.protection()
        with self.assertRaises((ValueError, RuntimeError)):
            upgrade_schema10(self.state_dir, confirm_quiescent=True)

    def test_web_owned_state_schema_is_unchanged(self):
        root = self.root / "web"
        with patch.dict(os.environ, {"UPT_TESTING": "1"}):
            web = WebState(root)
            web.ensure_compatible()
        with contextlib.closing(sqlite3.connect(root / "history.sqlite3")) as c:
            self.assertEqual(c.execute("SELECT version FROM schema_version").fetchone()[0], WEB_SCHEMA_VERSION)
            names = {r[0] for r in c.execute("SELECT name FROM sqlite_master")}
        self.assertFalse({n for n in names if "completion" in n or n in {"core_schema_identity", "history"}})


class OfflineTransitionTests(Schema9Fixture):
    def test_explicit_transition_preserves_every_record_and_retains_validated_snapshot(self):
        self.make_schema9()
        rows = table_rows(self.db)
        null_protection = rows["protected_images"]
        self.assertEqual(upgrade_schema10(self.state_dir, confirm_quiescent=True), "migrated")
        self.assertEqual(db_version(self.state_dir), CORE_SCHEMA_VERSION)
        self.assertEqual(table_rows(self.db, list(rows)), rows)
        self.assertEqual(table_rows(self.db, ["protected_images"])["protected_images"], null_protection)
        self.assertEqual(self.snapshot.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.snapshot.with_suffix(".sha256").read_text(), sha(self.snapshot))
        self.assertEqual(table_rows(self.snapshot, list(rows)), rows)
        with contextlib.closing(sqlite3.connect(f"file:{self.snapshot}?mode=ro", uri=True)) as c:
            self.assertEqual(c.execute("SELECT version FROM schema_version").fetchone()[0], 9)
        state = State(self.state_dir)
        state.ensure_compatible()
        self.assertEqual(state.completion_fences(), ())
        self.assertEqual(state.bootstrap_fence("k1")["operation_id"], "op-manual")
        retained = sha(self.snapshot)
        self.assertEqual(upgrade_schema10(self.state_dir, confirm_quiescent=True), "current")
        self.assertEqual(sha(self.snapshot), retained)

    def test_chained_schema8_to9_then_explicit_schema10(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("production_schema8_state", FIXTURES / "production_schema8_state.py")
        production = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(production)
        production.State(self.state_dir).record(service="app", action="update", result="SUCCESS")
        transition(self.state_dir, confirm_quiescent=True)
        self.assertEqual(db_version(self.state_dir), 9)
        self.assertEqual(upgrade_schema10(self.state_dir, confirm_quiescent=True), "migrated")
        self.assertEqual(len(State(self.state_dir).history()), 1)
        names = sorted(p.name for p in (self.state_dir / "schema-transitions").glob("*.sqlite3"))
        self.assertEqual(names, ["schema8-before9.sqlite3", "schema9-before10.sqlite3"])

    def test_confirmation_and_both_locks_are_required(self):
        self.make_schema9()
        before = self.db.read_bytes()
        with self.assertRaisesRegex(ValueError, "quiescence"):
            upgrade_schema10(self.state_dir)
        for name in ("update.lock", "scan-worker.lock"):
            with self.subTest(name), Lock(self.state_dir / name), self.assertRaises(RuntimeError):
                upgrade_schema10(self.state_dir, confirm_quiescent=True)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertFalse(self.snapshot.exists())

    def test_active_operation_and_incompatible_evidence_are_refused(self):
        self.make_schema9()
        with schema9.State(self.state_dir).connect() as c:
            c.execute("INSERT INTO operation_runs(id,kind,service_key,service,requested_by,status,created_at) "
                      "VALUES('live','update','container/x','app','fixture','running','2000-01-01')")
        with self.assertRaisesRegex(ValueError, "active operation"):
            upgrade_schema10(self.state_dir, confirm_quiescent=True)
        with schema9.State(self.state_dir).connect() as c:
            c.execute("UPDATE operation_runs SET status='failed' WHERE id='live'")
            c.execute("CREATE TABLE completion_fences(operation_id TEXT)")
        with self.assertRaisesRegex(ValueError, "unexpected schema-10 objects"):
            upgrade_schema10(self.state_dir, confirm_quiescent=True)
        self.assertEqual(db_version(self.state_dir), 9)
        self.assertFalse(self.snapshot.exists())

    def test_unidentified_symlinked_or_wrong_version_state_is_refused(self):
        self.make_schema9()
        with contextlib.closing(sqlite3.connect(self.db)) as c:
            c.execute("DROP TRIGGER core_schema_identity_no_delete")
            c.execute("DELETE FROM core_schema_identity")
            c.commit()
        before = self.db.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "schema-9 identity"):
            upgrade_schema10(self.state_dir, confirm_quiescent=True)
        self.assertEqual(self.db.read_bytes(), before)
        link_root = self.root / "linked"
        link_root.mkdir()
        (link_root / "history.sqlite3").symlink_to(self.db)
        with self.assertRaisesRegex(ValueError, "unavailable or unsafe"):
            upgrade_schema10(link_root, confirm_quiescent=True)
        corrupt = self.root / "corrupt"
        corrupt.mkdir()
        (corrupt / "history.sqlite3").write_bytes(b"not a database" * 100)
        with self.assertRaises(sqlite3.DatabaseError):
            upgrade_schema10(corrupt, confirm_quiescent=True)

    def test_interruption_rolls_back_and_retry_resumes_without_overwriting_snapshot(self):
        self.make_schema9()
        rows = table_rows(self.db)
        for point in ("snapshot", "migrated", "validated"):
            with self.subTest(point):
                with patch.object(state_transition, "_checkpoint",
                                  side_effect=lambda name, p=point: (_ for _ in ()).throw(KeyboardInterrupt) if name == p else None), \
                        self.assertRaises(KeyboardInterrupt):
                    upgrade_schema10(self.state_dir, confirm_quiescent=True)
                self.assertEqual(db_version(self.state_dir), 9)
                with contextlib.closing(sqlite3.connect(f"file:{self.db}?mode=ro", uri=True)) as c:
                    self.assertIsNone(c.execute("SELECT 1 FROM sqlite_master WHERE name LIKE '%completion%'").fetchone())
                with self.assertRaisesRegex(RuntimeError, "schema-10 transition"):
                    State(self.state_dir).ensure_compatible()
        retained = sha(self.snapshot)
        self.assertEqual(upgrade_schema10(self.state_dir, confirm_quiescent=True), "migrated")
        self.assertEqual(sha(self.snapshot), retained)
        self.assertEqual(table_rows(self.db, list(rows)), rows)

    def test_retry_refuses_unvalidated_or_mismatched_snapshot(self):
        self.make_schema9()
        with patch.object(state_transition, "_checkpoint",
                          side_effect=lambda name: (_ for _ in ()).throw(RuntimeError("stop")) if name == "migrated" else None), \
                self.assertRaises(RuntimeError):
            upgrade_schema10(self.state_dir, confirm_quiescent=True)
        retained = sha(self.snapshot)
        schema9.State(self.state_dir).record(service="later", action="update", result="SUCCESS")
        with self.assertRaisesRegex(ValueError, "does not match"):
            upgrade_schema10(self.state_dir, confirm_quiescent=True)
        digest = self.snapshot.with_suffix(".sha256")
        digest.unlink()
        with self.assertRaisesRegex(ValueError, "cannot be validated"):
            upgrade_schema10(self.state_dir, confirm_quiescent=True)
        self.assertEqual(sha(self.snapshot), retained)
        self.assertEqual(db_version(self.state_dir), 9)

    def test_state_changed_after_snapshot_is_refused_inside_the_transaction(self):
        self.make_schema9()

        def concurrent_write(name):
            if name == "snapshot":
                with contextlib.closing(sqlite3.connect(self.db)) as c:
                    c.execute("INSERT INTO history(service,action,result) VALUES('racing','update','SUCCESS')")
                    c.commit()
        with patch.object(state_transition, "_checkpoint", side_effect=concurrent_write), \
                self.assertRaisesRegex(ValueError, "state changed during the transition"):
            upgrade_schema10(self.state_dir, confirm_quiescent=True)
        self.assertEqual(db_version(self.state_dir), 9)
        self.assertTrue(self.snapshot.exists())

    def test_downgrade_is_refused_with_diagnostics_and_changes_nothing(self):
        state = State(self.state_dir)
        insert_fence(state, OP_1, compose_service(self.root))
        before = self.db.read_bytes()
        with self.assertRaisesRegex(ValueError, "Unresolved G2 completion fences: 1"):
            refuse_schema10_downgrade(self.state_dir)
        with self.assertRaisesRegex(ValueError, "not supported"):
            transition(self.state_dir, rollback=True, confirm_quiescent=True, confirm_state_loss=True)
        with self.assertRaises(SystemExit) as exited, contextlib.redirect_stdout(io.StringIO()):
            state_transition.main(["downgrade-schema9", "--state-dir", str(self.state_dir)])
        self.assertIn("not supported", str(exited.exception))
        self.assertEqual(self.db.read_bytes(), before)
        self.assertFalse((self.state_dir / "schema-transitions").exists())


class StorageConstraintTests(Base):
    def setUp(self):
        super().setUp()
        self.state = State(self.state_dir)
        self.service = compose_service(self.root)

    def test_one_unresolved_fence_per_logical_service(self):
        insert_fence(self.state, OP_1, self.service)
        with self.assertRaises(sqlite3.IntegrityError):
            insert_fence(self.state, OP_2, self.service, lifecycle="manual")
        resolve(self.state, OP_1)
        insert_fence(self.state, OP_2, self.service, lifecycle="manual")
        self.assertEqual([f.operation_id for f in self.state.completion_fences()], [OP_2])

    def test_lifecycle_identity_and_claim_constraints(self):
        insert_fence(self.state, OP_1, self.service)
        insert_claim(self.state, OP_1, "image", IMAGE_A)
        refused = [
            ("UPDATE completion_fences SET stack='other'", ()),
            ("DELETE FROM completion_fences", ()),
            ("UPDATE completion_fence_claims SET value=?", (IMAGE_B,)),
            ("DELETE FROM completion_fence_claims", ()),
            ("INSERT INTO completion_fence_claims VALUES(?,?,?)", ("f" * 32, "image", IMAGE_B)),
            ("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "volume", "x")),
            ("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "image", IMAGE_B[:20])),
            ("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "backup", "backups/../../etc")),
            ("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "backup", "tmp/x")),
            ("INSERT INTO completion_fences VALUES(?,?,?,?,?,?,?,?,?)",
             (OP_2, "0" * 64, "s", "c", "update", "pending", "{}", NOW, NOW)),
            ("INSERT INTO completion_fences VALUES(?,?,?,?,?,?,?,?,?)",
             ("short", "0" * 64, "s", "c", "update", "active", "{}", NOW, NOW)),
        ]
        for statement, args in refused:
            with self.subTest(statement), self.assertRaises(sqlite3.IntegrityError):
                with self.state.connect() as c:
                    c.execute(statement, args)
        resolve(self.state, OP_1)
        with self.assertRaises(sqlite3.IntegrityError), self.state.connect() as c:
            c.execute("UPDATE completion_fences SET lifecycle='active'")
        with self.assertRaises(sqlite3.IntegrityError), self.state.connect() as c:
            c.execute("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "image", IMAGE_B))

    def test_independent_owners_share_an_image_and_resolution_is_owner_scoped(self):
        other = compose_service(self.root, name="worker")
        insert_fence(self.state, OP_1, self.service)
        insert_fence(self.state, OP_2, other, lifecycle="manual")
        for owner in (OP_1, OP_2):
            insert_claim(self.state, owner, "image", IMAGE_A)
        insert_claim(self.state, OP_1, "backup", "backups/one")
        resolve(self.state, OP_1)
        claims = self.state.completion_claims()
        self.assertEqual(claims, {"image": frozenset({IMAGE_A}), "backup": frozenset()})
        with self.state.read() as c:
            self.assertEqual(c.execute("SELECT count(*) FROM completion_fence_claims").fetchone()[0], 3)
        resolve(self.state, OP_2)
        self.assertEqual(self.state.completion_claims()["image"], frozenset())

    def test_no_production_code_writes_g2_tables(self):
        source = Path(completion_fence.__file__).parent
        writer = re.compile(r"(INSERT(\s+OR\s+\w+)?\s+INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)\s+completion_fence", re.I)
        offenders = [path.name for path in source.glob("*.py") if writer.search(path.read_text())]
        self.assertEqual(offenders, [])


class AdmissionTests(Base):
    def setUp(self):
        super().setUp()
        self.state = State(self.state_dir)
        self.service = compose_service(self.root)

    def test_unrelated_services_and_shared_images_are_not_blocked(self):
        insert_fence(self.state, OP_1, self.service)
        insert_claim(self.state, OP_1, "image", self.service.image_id)
        sibling = compose_service(self.root, name="worker")
        other_stack = compose_service(self.root, stack="tools")
        standalone = compose_service(self.root, name="solo")
        standalone.stack = standalone.compose_service = standalone.working_dir = None
        standalone.compose_files = []
        for service in (sibling, other_stack, standalone):
            with self.subTest(service.name):
                self.state.assert_service_unfenced(service)

    def test_active_and_manual_fences_block_identity_drift_and_aliases(self):
        project = Path(self.service.working_dir)
        drifted = {
            "exact": self.service,
            "extra override file": compose_service(self.root, files=[str(project / "compose.yml"), str(project / "override.yml")]),
            "moved project": compose_service(self.root, working_dir=self.root / "moved"),
            "project alias": compose_service(self.root, stack="alias", working_dir=project),
            "shared source": compose_service(self.root, stack="alias", working_dir=self.root / "elsewhere",
                                             files=[str(project / "compose.yml")]),
        }
        for lifecycle in ("active", "manual"):
            insert_fence(self.state, OP_1 if lifecycle == "active" else OP_2, self.service, lifecycle=lifecycle)
            for name, candidate in drifted.items():
                with self.subTest(lifecycle=lifecycle, case=name), \
                        self.assertRaisesRegex(CompletionFenceError, "completion_unresolved"):
                    self.state.assert_service_unfenced(candidate)
            partial = compose_service(self.root)
            partial.working_dir = None
            with self.assertRaisesRegex(CompletionFenceError, "completion_identity_unproven"):
                self.state.assert_completion_unfenced(partial)
            resolve(self.state, OP_1 if lifecycle == "active" else OP_2)
        self.state.assert_service_unfenced(self.service)

    def test_malformed_or_unreadable_evidence_refuses_every_service(self):
        unrelated = compose_service(self.root, stack="tools", name="other")
        good = json.loads(json.dumps({"version": 1, "working_dir": self.service.working_dir,
                                      "compose_files": self.service.compose_files}))
        cases = {
            "bad json": "{not json",
            "unknown version": json.dumps({**good, "version": 2}),
            "extra field": json.dumps({**good, "secret": "x"}),
            "relative path": json.dumps({**good, "working_dir": "relative"}),
            "identity mismatch": json.dumps({**good, "working_dir": "/other"}),
        }
        for name, evidence in cases.items():
            with self.subTest(name):
                state = State(self.root / name.replace(" ", "-"))
                insert_fence(state, OP_1, self.service, evidence=evidence)
                with self.assertRaisesRegex(CompletionFenceError, "completion_evidence_invalid") as refused:
                    state.assert_service_unfenced(unrelated)
                self.assertNotIn(self.service.working_dir, str(refused.exception))
                self.assertNotIn(OP_1, str(refused.exception))
        state = State(self.root / "lifecycle")
        insert_fence(state, OP_1, self.service)
        raw(state, ("UPDATE completion_fences SET lifecycle='paused'",))
        with self.assertRaisesRegex(CompletionFenceError, "lifecycle"):
            state.assert_completion_unfenced(unrelated)
        state = State(self.root / "claim")
        insert_fence(state, OP_1, self.service)
        raw(state, ("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "image", "sha256:short")))
        with self.assertRaisesRegex(CompletionFenceError, "claim"):
            state.completion_claims()
        state = State(self.root / "missing-table")
        state.ensure_compatible()
        with contextlib.closing(sqlite3.connect(state.db_path)) as c:
            c.execute("DROP TABLE completion_fence_claims")
            c.commit()
        with self.assertRaises((RuntimeError, sqlite3.Error)):
            State(state.root).assert_completion_unfenced(unrelated)

    def test_namespace_and_bootstrap_guards_keep_precedence(self):
        key = logical_key(self.service.stack, self.service.compose_service, self.service.working_dir,
                          self.service.compose_files)
        insert_fence(self.state, OP_1, self.service)
        with self.state.connect() as c:
            c.execute("INSERT INTO compose_bootstrap_fences VALUES(?,?,?,?,?,?)", (key, "boot", "proof", "manual", NOW, NOW))
        with self.assertRaisesRegex(ValueError, "bootstrap_unresolved"):
            self.state.assert_service_unfenced(self.service)
        with patch.object(State, "namespace_update_fence", return_value="ns"), \
                self.assertRaisesRegex(ValueError, "namespace_update_unresolved"):
            self.state.assert_service_unfenced(self.service)


class FrontDoorTests(Base):
    """Every relevant mutation entrypoint refuses before any side effect."""

    def setUp(self):
        super().setUp()
        for target in ("docker_update_manager.compose_namespace.mutation_refusal",):
            patcher = patch(target, return_value=None)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.state = State(self.state_dir)
        project = self.root / "media"
        project.mkdir()
        (project / "compose.yml").write_text(COMPOSE)
        self.service = compose_service(self.root)
        insert_fence(self.state, OP_1, self.service, lifecycle="manual")

    @contextlib.contextmanager
    def no_effects(self):
        targets = ["operations.run", "operations.run_compose_progress", "operations.backup_files",
                   "operations.atomic_write", "removal.run", "conversion.run", "compose.backup_files",
                   "compose.atomic_write", "compose_reconcile.run", "compose_bootstrap.run",
                   "compose_discard.run", "reconciliation.mark_changed"]
        spies = []
        with contextlib.ExitStack() as stack:
            for target in targets:
                try:
                    spies.append(stack.enter_context(patch("docker_update_manager." + target)))
                except AttributeError:
                    continue
            yield
        for spy in spies:
            spy.assert_not_called()

    def refuse(self, call):
        with self.no_effects(), self.assertRaises(ValueError) as refused, \
                contextlib.redirect_stdout(io.StringIO()):
            call()
        self.assertIn("completion_unresolved", str(getattr(refused.exception, "reason", "")) + str(refused.exception))

    def test_cli_and_core_service_mutations(self):
        from docker_update_manager import operations, removal
        quiet = Reporter(enabled=False)
        self.refuse(lambda: operations.do_update(self.service, self.state, yes=True, reporter=quiet))
        self.refuse(lambda: operations.do_pin(self.service, self.state, yes=True, reporter=quiet, output=lambda *_: None))
        self.refuse(lambda: operations.do_pull(self.service, reporter=quiet, state=self.state))
        self.refuse(lambda: operations.do_rollback(self.service, self.state, yes=True, reporter=quiet))
        self.refuse(lambda: operations.do_web_rollback(
            self.service, {}, self.state, sources=[], operation_id=OP_2, rollback_command=[], recovery_command=[],
            verify_before_restore=None, verify_before_recreate=None, verify_recovery_sources=None,
            verify_pre_rollback_recovery=None))
        self.refuse(lambda: operations.do_restart(self.service, state=self.state))
        pinned = compose_service(self.root, image="example/app@sha256:" + "d" * 64)
        Path(pinned.compose_files[0]).write_text(f"services:\n  app:\n    image: {pinned.image}\n")
        with patch("docker_update_manager.operations.tracking_image", return_value="example/app:latest"), \
                patch("docker_update_manager.operations.remote_manifest",
                      return_value={"digest": "sha256:" + "e" * 64, "platforms": []}):
            self.refuse(lambda: operations.do_update(pinned, self.state, yes=True, reporter=quiet,
                                                     output=lambda *_: None))
        Path(pinned.compose_files[0]).write_text(COMPOSE)
        with patch("docker_update_manager.removal._remaining_container_images", return_value=set()):
            self.refuse(lambda: removal.remove_service(self.service, self.state, images=True, yes=True, reporter=quiet))
            self.refuse(lambda: removal.remove_service(self.service, self.state, dry_run=True, reporter=quiet))

    def test_restore_compose_and_conversion_source_writes(self):
        from docker_update_manager import cli, conversion
        backup = self.state_dir / "backups" / "seed"
        backup.mkdir(parents=True)
        (backup / "compose.yml").write_text("services: {}\n")
        (backup / "metadata.json").write_text(json.dumps({"stack": "other", "service": "other", "files": [
            {"source": self.service.compose_files[0], "backup": str(backup / "compose.yml")}]}))
        for dry_run in (False, True):
            self.refuse(lambda: cli.restore(self.state, SimpleNamespace(backup="seed", dry_run=dry_run, yes=True)))
        self.assertEqual(Path(self.service.compose_files[0]).read_text(), COMPOSE)
        solo = compose_service(self.root, name="solo")
        solo.stack = solo.compose_service = solo.working_dir = None
        solo.compose_files = []
        output = Path(self.service.working_dir)
        built = ({"services": {"solo": {"image": "example/solo:latest"}}}, "", {"environment_keys": [], "service": "solo"}, {})
        with patch("docker_update_manager.conversion.build_conversion", return_value=built):
            self.refuse(lambda: conversion.generate_conversion(solo, self.state, output, yes=True))
        self.refuse(lambda: conversion.deploy_conversion(solo, self.state, output, {}, {}, yes=True))
        with self.state.connect() as c:
            c.execute("INSERT INTO history(stack,service,action,result,details,old_image,new_image) "
                      "VALUES('media','app','convert','SUCCESS',?, 'a','b')", (json.dumps({"backup_container": "kept"}),))
        retained = compose_service(self.root, name="kept")
        retained.stack = retained.compose_service = retained.working_dir = None
        retained.compose_files = []
        with patch("docker_update_manager.conversion.discover", return_value=[]), \
                patch("docker_update_manager.conversion.resolve_service", side_effect=[self.service, retained]):
            self.refuse(lambda: conversion.rollback_conversion("app", self.state, yes=True))

    def test_compose_bootstrap_reconcile_discard_and_web_plan(self):
        from docker_update_manager import compose_bootstrap, compose_discard, compose_reconcile
        from docker_update_manager.compose_drift import UNVERIFIABLE
        from docker_update_manager.webservice import ReadOnlyService
        with self.assertRaises(compose_bootstrap.BootstrapRefused) as refused:
            compose_bootstrap.make_plan(self.service, [self.service], self.state, model_reader=None, hash_reader=None,
                                        context_reader=None, mounts_reader=None, baseline_available=False)
        self.assertEqual(refused.exception.reason, "completion_unresolved")
        plan = SimpleNamespace(service=self.service, desired_model={})
        with self.no_effects(), self.assertRaises(compose_bootstrap.BootstrapExecutionFailed) as failed:
            compose_bootstrap.do_compose_bootstrap(
                plan, self.state, operation_id=OP_2, requester="t", client_ip=None, user_agent=None, revalidate=None,
                discover_current=None, verify_configuration=None, verify_context=None)
        self.assertEqual(failed.exception.reason, "completion_unresolved")
        self.refuse(lambda: compose_reconcile.do_compose_reconcile(
            self.service, self.state, plan, operation_id=OP_2, binding=None, revalidate=None,
            discover_current=None, verify_configuration=None, verify_context=None, capture_baseline=None))
        self.refuse(lambda: compose_discard.do_compose_discard(
            self.service, self.state, plan, operation_id=OP_2, binding=None, revalidate=None,
            discover_current=None, verify_configuration=None, verify_context=None))
        fake = SimpleNamespace(state=self.state, _baseline_key=ReadOnlyService._baseline_key)
        result = ReadOnlyService._compose_plan(fake, self.service, [self.service], persist=False)
        self.assertEqual((result.status, tuple(result.reasons)), (UNVERIFIABLE, ("completion_unresolved",)))


def old_history(state, image_id, *, stack="media", service="app"):
    history_id = state.record(stack=stack, service=service, action="update", old_image_id=image_id, result="SUCCESS")
    with state.connect() as c:
        c.execute("UPDATE rollback_refs SET created='2000-01-01 00:00:00' WHERE history_id=?", (history_id,))
    return history_id


class _Docker:
    def __init__(self, listing=(), in_use=()):
        self.listing, self.in_use, self.calls = list(listing), set(in_use), []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if args[:3] == ["docker", "image", "ls"]:
            return "\n".join(self.listing) + "\n"
        if args[:3] == ["docker", "image", "rm"] or args[:3] == ["docker", "image", "inspect"]:
            return ""
        if args[:3] == ["docker", "system", "df"]:
            return json.dumps({"Images": []})
        if args[:2] in (["docker", "ps"], ["docker", "rm"]):
            return ""
        raise AssertionError(f"unexpected Docker call: {args}")

    @property
    def removed(self):
        return [a[-1] for a in self.calls if a[:3] == ["docker", "image", "rm"]]


class DeletionTests(Base):
    def setUp(self):
        super().setUp()
        from test_disk_retention import Cfg
        State(self.state_dir).ensure_compatible()
        self.state = State(self.state_dir)
        self.cfg = Cfg(self.root)
        self.service = compose_service(self.root)
        self.docker = _Docker()
        for target in ("docker_update_manager.retention.run", "docker_update_manager.removal.run"):
            patcher = patch(target, self.docker)
            patcher.start()
            self.addCleanup(patcher.stop)

    def clean(self, **options):
        return retention.cleanup(self.cfg, self.state, now=datetime.now(timezone.utc), **options)

    def skipped(self, result):
        return {item.get("image") or Path(item["path"]).name: item["reason"] for item in result["skipped"]}

    def test_normal_and_forced_retention_keep_claimed_images_and_remove_unclaimed(self):
        insert_fence(self.state, OP_1, self.service)
        insert_claim(self.state, OP_1, "image", IMAGE_A)
        for options in ({}, {"service": "app", "stack": "media", "override_protection": True}, {"all_protected": True}):
            with self.subTest(options):
                old_history(self.state, IMAGE_A)
                old_history(self.state, IMAGE_B)
                preview = self.clean(dry_run=True, **options)
                self.assertEqual([p["image_id"] for p in preview["planned_images"]], [IMAGE_B])
                result = self.clean(**options)
                self.assertNotIn(IMAGE_A, self.docker.removed)
                self.assertIn(IMAGE_B, self.docker.removed)
                self.assertEqual(self.skipped(result)[IMAGE_A], "SKIPPED - UNRESOLVED RECOVERY CLAIM")
                self.docker.calls.clear()

    def test_claim_is_rechecked_at_the_final_boundary(self):
        old_history(self.state, IMAGE_A)
        insert_fence(self.state, OP_1, self.service)

        def late_claim(image_id):
            insert_claim(self.state, OP_1, "image", image_id)
            return None
        result = self.clean(revalidate=late_claim)
        self.assertEqual(self.docker.removed, [])
        self.assertEqual(self.skipped(result)[IMAGE_A], "SKIPPED - UNRESOLVED RECOVERY CLAIM")

    def test_unreadable_claims_refuse_image_and_backup_deletion(self):
        old_history(self.state, IMAGE_A)
        stale = self.state_dir / "backups" / "stale"
        stale.mkdir(parents=True)
        os.utime(stale, (0, 0))
        insert_fence(self.state, OP_1, self.service)
        raw(self.state, ("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "backup", "../outside")))
        result = self.clean()
        self.assertEqual(self.docker.removed, [])
        self.assertTrue(stale.exists())
        reasons = self.skipped(result)
        self.assertEqual(reasons[IMAGE_A], "SKIPPED - RECOVERY CLAIMS UNVERIFIABLE")
        inventory = retention.inventory(self.cfg, self.state)
        self.assertEqual([a.get("protection") for a in inventory["artifacts"] if a["path"] == str(stale)], ["unverifiable"])

    def test_dangling_cleanup_keeps_claimed_images_and_refuses_malformed_claims(self):
        from docker_update_manager import cli
        insert_fence(self.state, OP_1, self.service)
        insert_claim(self.state, OP_1, "image", IMAGE_A)
        docker = _Docker([IMAGE_A, IMAGE_B])
        out = io.StringIO()
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state_dir)}), patch.object(cli, "run", docker), \
                patch("docker_update_manager.retention.run", docker), patch.object(cli, "quick_snapshot", lambda *a, **k: None), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["cleanup", "--yes"]), 0)
        self.assertEqual(docker.removed, [IMAGE_B])
        self.assertIn(f"{IMAGE_A}  UNRESOLVED RECOVERY CLAIM", out.getvalue())
        raw(self.state, ("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "image", "sha256:short")))
        docker = _Docker([IMAGE_B, IMAGE_C])
        with patch.dict(os.environ, {"UPT_STATE_DIR": str(self.state_dir)}), patch.object(cli, "run", docker), \
                patch("docker_update_manager.retention.run", docker), patch.object(cli, "quick_snapshot", lambda *a, **k: None), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["cleanup", "--yes"]), cli.EXIT_FATAL)
        self.assertEqual(docker.removed, [])

    def test_remove_images_keeps_claimed_images(self):
        from docker_update_manager import removal
        solo = compose_service(self.root, name="solo", image_id=IMAGE_A)
        solo.stack = solo.compose_service = solo.working_dir = None
        solo.compose_files = []
        insert_fence(self.state, OP_1, self.service)
        insert_claim(self.state, OP_1, "image", IMAGE_A)
        with patch("docker_update_manager.removal.require_mutation_safe"), \
                patch("docker_update_manager.removal._remaining_container_images", return_value=set()), \
                contextlib.redirect_stdout(io.StringIO()) as preview:
            removal.remove_service(solo, self.state, images=True, dry_run=True, reporter=Reporter(enabled=False))
            result = removal.remove_service(solo, self.state, images=True, yes=True, reporter=Reporter(enabled=False),
                                            reconcile_discover=lambda: [])
        self.assertIn("unresolved recovery claim", preview.getvalue())
        self.assertEqual(self.docker.removed, [])
        self.assertIn((IMAGE_A, "UNRESOLVED RECOVERY CLAIM"), result["skipped"])

    def test_claimed_backups_survive_ttl_and_forced_retention_until_resolved(self):
        backups = self.state_dir / "backups"
        claimed, unclaimed = backups / "claimed", backups / "unclaimed"
        for path in (claimed, unclaimed):
            path.mkdir(parents=True)
            (path / "metadata.json").write_text("{}")
            os.utime(path, (0, 0))
        insert_fence(self.state, OP_1, self.service)
        insert_claim(self.state, OP_1, "backup", "backups/claimed")
        insert_claim(self.state, OP_1, "backup", "restore-bundles/missing")
        listed = {Path(a["path"]).name: a for a in retention.inventory(self.cfg, self.state)["artifacts"]}
        self.assertEqual((listed["claimed"]["expired"], listed["claimed"]["protection"]), (False, "claimed"))
        self.assertTrue(listed["unclaimed"]["expired"])
        old_history(self.state, IMAGE_B)
        self.clean(all_protected=True)
        self.assertTrue(claimed.exists())
        self.assertFalse(unclaimed.exists())
        resolve(self.state, OP_1)
        self.clean()
        self.assertFalse(claimed.exists())

    def test_symlinked_root_alias_and_substitution_are_refused_at_deletion(self):
        backups = self.state_dir / "backups"
        claimed = backups / "claimed"
        claimed.mkdir(parents=True)
        (self.state_dir / "conversion-snapshots").symlink_to(backups, target_is_directory=True)
        os.utime(claimed, (0, 0))
        insert_fence(self.state, OP_1, self.service)
        insert_claim(self.state, OP_1, "backup", "backups/claimed")
        result = self.clean()
        self.assertTrue(claimed.exists())
        protections = {a["path"]: a.get("protection") for a in retention.inventory(self.cfg, self.state)["artifacts"]}
        self.assertEqual(protections, {str(claimed): "claimed",
                                       str(self.state_dir / "conversion-snapshots" / "claimed"): "claimed"})
        self.assertEqual(result["files_removed"], 0)
        (self.state_dir / "conversion-snapshots").unlink()
        victim = backups / "victim"
        victim.mkdir()
        os.utime(victim, (0, 0))
        real = retention._backup_claim_blocker

        def substitute(state, path, expected=None, **options):
            outcome = real(state, path, expected, **options)
            if expected is None and path.name == "victim":
                victim.rename(backups / "moved-original")
                victim.mkdir()
                (victim / "planted").write_text("x")
            return outcome
        with patch.object(retention, "_backup_claim_blocker", side_effect=substitute):
            result = self.clean()
        self.assertTrue((victim / "planted").exists())
        self.assertIn(("victim", "ARTIFACT CHANGED"),
                      [(Path(item["path"]).name, item["reason"]) for item in result["skipped"] if "path" in item])

    def test_metadata_pruning_retains_g2_rows_and_null_history_protection(self):
        insert_fence(self.state, OP_1, self.service)
        insert_claim(self.state, OP_1, "image", IMAGE_A)
        insert_fence(self.state, OP_2, compose_service(self.root, name="done"))
        insert_claim(self.state, OP_2, "image", IMAGE_A)
        resolve(self.state, OP_2)
        with self.state.connect() as c:
            c.execute("INSERT INTO protected_images(image_id,reason,history_id) VALUES(?,?,NULL)", (IMAGE_C, "manual"))
        before = table_rows(self.state.db_path, ["completion_fences", "completion_fence_claims", "protected_images"])
        self.clean()
        self.state.prune_operations(retention_days=0, limit=0)
        self.assertEqual(table_rows(self.state.db_path, ["completion_fences", "completion_fence_claims", "protected_images"]),
                         before)

    def test_unclaimed_resources_keep_existing_behaviour_without_fences(self):
        old_history(self.state, IMAGE_A)
        stale = self.state_dir / "backups" / "stale"
        stale.mkdir(parents=True)
        os.utime(stale, (0, 0))
        result = self.clean()
        self.assertEqual(self.docker.removed, [IMAGE_A])
        self.assertFalse(stale.exists())
        self.assertEqual(result["skipped"], [])



SHARED = "services:\n  app:\n    image: example/app:latest\n  worker:\n    image: example/worker:latest\n"
WORKER_PINNED = "example/worker@sha256:" + "d" * 64
WORKER_TARGET = "example/worker@sha256:" + "e" * 64


class SharedSourceTests(Base):
    """A sibling's operation never rewrites a Compose source a fenced service owns.

    ``app`` and ``worker`` share ``compose.yml`` and the project ``.env``;
    ``app`` holds the unresolved fence. Docker and Compose validation are
    controlled doubles; every file is temporary.
    """

    def setUp(self):
        super().setUp()
        self.project = self.root / "media"
        self.project.mkdir()
        self.compose = self.project / "compose.yml"
        self.compose.write_text(SHARED)
        self.env = self.project / ".env"
        self.env.write_text("WORKER_IMAGE=example/worker:latest\n")
        self.state = State(self.state_dir)
        self.app = compose_service(self.root)
        self.worker = compose_service(self.root, name="worker")
        self.quiet = Reporter(enabled=False)
        self.docker = Mock(return_value="")
        for target, value in (("compose_namespace.mutation_refusal", None), ("operations.validate", None),
                              ("operations.mark_changed", None), ("operations.mark_project_inputs_changed", None)):
            patcher = patch("docker_update_manager." + target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for target in ("operations.run", "operations.run_compose_progress"):
            patcher = patch("docker_update_manager." + target, self.docker)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch("docker_update_manager.operations.discover", return_value=[self.worker])
        patcher.start()
        self.addCleanup(patcher.stop)

    def fence(self):
        if not self.state.completion_fences():
            insert_fence(self.state, OP_1, self.app, lifecycle="manual")

    def snapshot(self):
        return self.compose.read_bytes(), self.env.read_bytes()

    def history(self):
        return [(row["service"], row["action"], row["result"], row["rollback_result"]) for row in self.state.history()]

    @contextlib.contextmanager
    def refused(self, history=()):
        before = self.snapshot()
        with self.assertRaises(CompletionFenceError) as refused, contextlib.redirect_stdout(io.StringIO()):
            yield
        self.assertIn("completion_unresolved", str(refused.exception))
        self.assertNotIn(str(self.project), str(refused.exception))
        self.assertEqual(self.snapshot(), before)
        self.docker.assert_not_called()
        self.assertFalse((self.state_dir / "backups").exists())
        self.assertEqual(self.history(), list(history))

    def test_sibling_pin_cannot_rewrite_shared_compose_or_project_env(self):
        from docker_update_manager import operations
        self.fence()
        with self.refused():
            operations.do_pin(self.worker, self.state, yes=True, reporter=self.quiet, output=lambda *_: None)
        # A pin controlled through the shared project .env from a separate file.
        separate = self.project / "worker.yml"
        separate.write_text("services:\n  worker:\n    image: ${WORKER_IMAGE}\n")
        worker = compose_service(self.root, name="worker", files=[str(separate)])
        with self.refused():
            operations.do_pin(worker, self.state, yes=True, reporter=self.quiet, output=lambda *_: None)
        self.assertEqual(separate.read_text(), "services:\n  worker:\n    image: ${WORKER_IMAGE}\n")

    def test_sibling_update_that_pins_or_advances_a_pin_is_refused_before_any_effect(self):
        from docker_update_manager import operations
        self.fence()
        registry = Mock(side_effect=AssertionError("registry must not be consulted"))
        with patch("docker_update_manager.operations.remote_manifest", registry), self.refused():
            operations.do_update(self.worker, self.state, yes=True, pin=True, reporter=self.quiet,
                                 output=lambda *_: None)
        pinned = compose_service(self.root, name="worker", image=WORKER_PINNED)
        self.compose.write_text(SHARED.replace("example/worker:latest", WORKER_PINNED))
        with patch("docker_update_manager.operations.tracking_image", return_value="example/worker:latest"), \
                patch("docker_update_manager.operations.remote_manifest",
                      return_value={"digest": "sha256:" + "e" * 64, "platforms": []}), self.refused():
            operations.do_update(pinned, self.state, yes=True, reporter=self.quiet, output=lambda *_: None)

    def pinned_update(self, docker):
        from docker_update_manager import operations
        pinned = compose_service(self.root, name="worker", image=WORKER_PINNED)
        self.compose.write_text(SHARED.replace("example/worker:latest", WORKER_PINNED))
        fresh = compose_service(self.root, name="worker", image=WORKER_TARGET, image_id=IMAGE_B)
        self.docker.side_effect = docker
        with patch("docker_update_manager.operations.tracking_image", return_value="example/worker:latest"), \
                patch("docker_update_manager.operations.remote_manifest",
                      return_value={"digest": "sha256:" + "e" * 64, "platforms": []}), \
                patch("docker_update_manager.operations.discover", return_value=[fresh]), \
                contextlib.redirect_stdout(io.StringIO()):
            return operations.do_update(pinned, self.state, yes=True, no_health=True, reporter=self.quiet,
                                        output=lambda *_: None, reconcile_discover=lambda: [])

    def test_fence_appearing_during_the_pull_blocks_the_later_source_write(self):
        original = SHARED.replace("example/worker:latest", WORKER_PINNED)

        def docker(args, **_):
            if args[:2] == ["docker", "pull"]:
                self.fence()
            return ""
        with self.assertRaisesRegex(RuntimeError, "completion_unresolved"):
            self.pinned_update(docker)
        self.assertEqual(self.compose.read_text(), original)
        self.assertFalse(any("up" in call.args[0] for call in self.docker.call_args_list))
        self.assertEqual(self.history(), [("worker", "update", "FAILED", None)])

    def test_pinned_update_recovery_never_restores_over_a_fenced_source(self):
        def docker(args, **_):
            if "up" in args:
                self.fence()
                raise RuntimeError("recreation failed")
            return ""
        from docker_update_manager.operations import RecoveryRequired
        with self.assertRaises(RecoveryRequired):
            self.pinned_update(docker)
        self.assertIn("sha256:" + "e" * 64, self.compose.read_text())  # left for manual recovery, not overwritten
        self.assertEqual(sum("up" in call.args[0] for call in self.docker.call_args_list), 1)
        self.assertEqual(self.history(), [("worker", "update", "FAILED", "MANUAL RECOVERY REQUIRED")])

    def seed_rollback_point(self):
        backup = self.state_dir / "backups" / "worker-seed"
        backup.mkdir(parents=True)
        (backup / "compose.yml").write_text(SHARED.replace("worker:latest", "worker:0.9"))
        (backup / "worker.override.yml").write_text("services: {}\n")
        self.override = self.project / "worker.override.yml"
        self.override.write_text("services:\n  worker:\n    init: true\n")
        # The worker-only file comes first: no source may be written before every one is proved.
        (backup / "metadata.json").write_text(json.dumps({"stack": "media", "service": "worker", "files": [
            {"source": str(self.override), "backup": str(backup / "worker.override.yml")},
            {"source": str(self.compose), "backup": str(backup / "compose.yml")}]}))
        self.state.record(stack="media", service="worker", action="update", old_image="example/worker:0.9",
                          old_image_id=IMAGE_A, new_image="example/worker:latest", new_image_id=IMAGE_C,
                          backup=str(backup), result="SUCCESS")
        return backup

    def test_cli_rollback_cannot_restore_a_fenced_shared_source(self):
        from docker_update_manager import operations
        self.seed_rollback_point()
        self.fence()
        before = self.snapshot()
        with self.assertRaisesRegex(CompletionFenceError, "completion_unresolved"), \
                contextlib.redirect_stdout(io.StringIO()):
            operations.do_rollback(self.worker, self.state, yes=True, reporter=self.quiet,
                                   reconcile_discover=lambda: [])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.override.read_text(), "services:\n  worker:\n    init: true\n")
        self.docker.assert_not_called()
        self.assertEqual(self.history(), [("worker", "update", "SUCCESS", None)])

    def web_rollback(self, **verify):
        from docker_update_manager import operations
        from docker_update_manager.compose import compose_args
        command = compose_args(self.worker, project_name="media") + ["up", "-d", "--no-deps", "--pull", "never",
                                                                     "worker"]
        sources = [{"path": str(self.compose), "before": self.compose.read_bytes(), "restore": b"services: {}\n"}]
        callbacks = {name: verify.get(name, Mock()) for name in (
            "verify_before_restore", "verify_before_recreate", "verify_recovery_sources",
            "verify_pre_rollback_recovery")}
        row = {"id": 1, "old_image_id": IMAGE_A, "old_image": "example/worker:0.9"}
        return operations.do_web_rollback(self.worker, row, self.state, sources=sources, operation_id=OP_2,
                                          rollback_command=command, recovery_command=command,
                                          reconcile_discover=lambda: [], **callbacks)

    def test_web_rollback_cannot_restore_a_fenced_shared_source(self):
        self.fence()
        verify = Mock()
        with self.refused():
            self.web_rollback(verify_before_restore=verify)
        verify.assert_not_called()

    def test_web_rollback_rechecks_each_source_write(self):
        from docker_update_manager.operations import WebRollbackFailure
        before = self.snapshot()

        def verify(phase):
            if phase == "source-write":
                self.fence()
        with self.assertRaises(WebRollbackFailure) as failed:
            self.web_rollback(verify_before_restore=verify)
        self.assertFalse(failed.exception.manual_recovery_required)
        self.assertEqual(self.snapshot(), before)
        self.docker.assert_not_called()
        self.assertEqual(self.history(), [("worker", "rollback", "FAILED", "NO CHANGES MADE")])

    def test_web_rollback_recovery_never_restores_over_a_fenced_source(self):
        from docker_update_manager.operations import WebRollbackFailure
        identities = {"example/worker:0.9": IMAGE_A, "example/worker:latest": IMAGE_C}

        def docker(args, **_):
            if args[:3] == ["docker", "image", "inspect"]:
                return identities[args[-1]]
            if "up" in args:
                self.fence()
                raise RuntimeError("recreation failed")
            return ""
        self.docker.side_effect = docker
        with self.assertRaises(WebRollbackFailure) as failed, \
                patch("docker_update_manager.operations.discover", return_value=[self.worker]):
            self.web_rollback()
        self.assertTrue(failed.exception.manual_recovery_required)
        self.assertEqual(self.compose.read_bytes(), b"services: {}\n")  # not silently reverted
        self.assertEqual(sum("up" in call.args[0] for call in self.docker.call_args_list), 1)
        self.assertEqual(self.history(), [("worker", "rollback", "FAILED", "MANUAL RECOVERY REQUIRED")])

    def test_independent_service_and_non_writing_sibling_operations_keep_behaviour(self):
        from docker_update_manager import operations
        self.fence()
        other = compose_service(self.root, stack="tools", name="other")
        Path(other.working_dir).mkdir()
        Path(other.compose_files[0]).write_text("services:\n  other:\n    image: example/other:latest\n")
        with contextlib.redirect_stdout(io.StringIO()):
            operations.do_pin(other, self.state, yes=True, reporter=self.quiet, output=lambda *_: None)
        self.assertIn("example/other:1.0.0", Path(other.compose_files[0]).read_text())
        self.assertEqual(self.history(), [("other", "pin", "SUCCESS", None)])
        # A sibling restart and ordinary (non-pinning) update write no source.
        operations.do_restart(self.worker, state=self.state, reconcile_discover=lambda: [])
        self.assertTrue(any("restart" in call.args[0] for call in self.docker.call_args_list))
        probe = Mock(side_effect=RuntimeError("registry reached"))
        with patch("docker_update_manager.operations.remote_manifest", probe), \
                self.assertRaisesRegex(RuntimeError, "registry reached"), contextlib.redirect_stdout(io.StringIO()):
            operations.do_update(self.worker, self.state, yes=True, reporter=self.quiet, output=lambda *_: None)
        self.assertEqual(self.compose.read_text(), SHARED)


class SharedSourceComposeTests(ComposeFixture):
    """Compose discard and Apply recovery honour a fenced peer's shared source."""

    start = apply_fixtures.ComposeApplyTests.start
    execute = apply_fixtures.ComposeApplyTests.execute

    def setUp(self):
        super().setUp()
        self.compose.write_bytes(discard_fixtures.SIMPLE)
        self.service = self.make_service(self.current_hash())
        self.runtime = [self.service]
        self.fake = apply_fixtures.FakeApplyCompose(self)
        for module in ("webservice", "compose_reconcile", "compose"):
            patch(f"docker_update_manager.{module}.run", side_effect=self.fake).start()
        patch.object(self.agent, "start_refresh", return_value={"status": "checking"}).start()
        self.addCleanup(patch.stopall)
        self.status()
        self.original = self.compose.read_bytes()
        self.edit("restart: unless-stopped", "restart: always")
        self.desired = self.compose.read_bytes()
        self.peer = self.make_service(self.current_hash("redis"), container_id="b" * 64, name="redis",
                                      compose_service="redis", image="redis:7")

    def review(self, action):
        return self.agent.compose_reconcile_review(
            {"service_key": "container/" + "a" * 64, "action": action, "requested_by": "admin"})

    def fence_peer(self):
        insert_fence(self.state, OP_1, self.peer, lifecycle="manual")

    def test_discard_cannot_rewrite_a_fenced_peers_shared_source(self):
        reviewed = self.review("discard")
        self.fence_peer()
        operation = self.execute(reviewed)
        self.assertEqual(operation["status"], "blocked")
        self.assertEqual(self.compose.read_bytes(), self.desired)
        self.assertEqual(self.fake.up_calls, [])
        self.assertEqual(list((self.state.root / "compose-recoveries").glob("*")), [])  # refused before the bundle

    def test_apply_recovery_cannot_restore_over_a_fenced_peers_shared_source(self):
        def hook(number, fresh):
            if number == 1:
                self.fence_peer()
                fresh.health = "unhealthy"
        self.fake.up_hook = hook
        operation = self.execute(self.review("apply"))
        self.assertTrue(operation["result"]["manual_recovery_required"])
        self.assertFalse(operation["result"]["recovered"])
        self.assertEqual(len(self.fake.up_calls), 1)
        self.assertEqual(self.compose.read_bytes(), self.desired)

    def test_sibling_apply_that_writes_no_source_keeps_its_behaviour(self):
        self.fence_peer()
        operation = self.execute(self.review("apply"))
        self.assertEqual(operation["status"], "succeeded")
        self.assertEqual(self.compose.read_bytes(), self.desired)


class ClaimOwnerEvidenceTests(Base):
    """Retention trusts a claim only when its owning fence fully validates."""

    skipped = DeletionTests.skipped

    def setUp(self):
        super().setUp()
        from test_disk_retention import Cfg
        self.state = State(self.state_dir)
        self.cfg = Cfg(self.root)
        self.service = compose_service(self.root)
        self.docker = _Docker()
        for target in ("docker_update_manager.retention.run", "docker_update_manager.removal.run"):
            patcher = patch(target, self.docker)
            patcher.start()
            self.addCleanup(patcher.stop)

    def corrupt_cases(self):
        good = {"version": 1, "working_dir": self.service.working_dir, "compose_files": self.service.compose_files}
        other = compose_service(self.root, name="other")
        return {
            "malformed json": dict(evidence="{not json"),
            "wrong logical key": dict(key="f" * 64),
            "inconsistent compose service": dict(key=logical_key("media", "other", other.working_dir,
                                                                 other.compose_files)),
            "inconsistent stack": dict(raw="UPDATE completion_fences SET stack=''"),
            "unsupported evidence version": dict(evidence=json.dumps({**good, "version": 2})),
            "invalid lifecycle": dict(raw="UPDATE completion_fences SET lifecycle='paused'"),
            "invalid action": dict(raw="UPDATE completion_fences SET action='deploy'"),
            "invalid owner": dict(raw="UPDATE completion_fences SET operation_id='not-an-owner'"),
            "missing owner": dict(orphan=True),
        }

    def corrupt_state(self, name, case):
        state = State(self.root / name.replace(" ", "-"))
        if case.get("orphan"):
            insert_fence(state, OP_2, self.service)
            raw(state, ("DROP TRIGGER completion_fence_claims_unresolved_owner",),
                ("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "image", IMAGE_A)),
                ("INSERT INTO completion_fence_claims VALUES(?,?,?)", (OP_1, "backup", "backups/claimed")))
        else:
            insert_fence(state, OP_1, self.service, evidence=case.get("evidence"), key=case.get("key"))
            insert_claim(state, OP_1, "image", IMAGE_A)
            insert_claim(state, OP_1, "backup", "backups/claimed")
        if case.get("raw"):
            with contextlib.closing(sqlite3.connect(state.db_path)) as c:
                c.execute("PRAGMA ignore_check_constraints=ON")
                for trigger in ("completion_fences_identity_immutable", "completion_fence_claims_immutable"):
                    c.execute(f"DROP TRIGGER IF EXISTS {trigger}")
                c.execute(case["raw"])
                c.commit()
        claimed = state.root / "backups" / "claimed"
        claimed.mkdir(parents=True)
        os.utime(claimed, (0, 0))
        old_history(state, IMAGE_A)
        return state, claimed

    def test_unverifiable_owner_keeps_claimed_images_and_backups_under_all_retention_modes(self):
        for name, case in self.corrupt_cases().items():
            for options in ({}, {"service": "app", "stack": "media", "override_protection": True},
                            {"all_protected": True}):
                with self.subTest(name, options=options):
                    state, claimed = self.corrupt_state(f"{name} {len(options)}", case)
                    with self.assertRaisesRegex(CompletionFenceError, "completion_evidence_invalid"):
                        state.completion_claims()
                    self.docker.calls.clear()
                    result = retention.cleanup(self.cfg, state, now=datetime.now(timezone.utc), **options)
                    self.assertNotIn(IMAGE_A, self.docker.removed)
                    self.assertTrue(claimed.exists())
                    self.assertEqual(self.skipped(result)[IMAGE_A], "SKIPPED - RECOVERY CLAIMS UNVERIFIABLE")
                    listed = {Path(a["path"]).name: a for a in retention.inventory(self.cfg, state)["artifacts"]}
                    self.assertEqual((listed["claimed"]["expired"], listed["claimed"]["protection"]),
                                     (False, "unverifiable"))
                    self.assertNotIn(str(self.service.working_dir), json.dumps(result))

    def test_unverifiable_owner_refuses_dangling_cleanup_and_remove_images(self):
        from docker_update_manager import cli, removal
        for name, case in self.corrupt_cases().items():
            with self.subTest(name):
                state, _claimed = self.corrupt_state(name, case)
                docker = _Docker([IMAGE_A, IMAGE_B])
                err = io.StringIO()
                with patch.dict(os.environ, {"UPT_STATE_DIR": str(state.root)}), patch.object(cli, "run", docker), \
                        patch("docker_update_manager.retention.run", docker), \
                        patch.object(cli, "quick_snapshot", lambda *a, **k: None), \
                        contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    self.assertEqual(cli.main(["cleanup", "--yes"]), cli.EXIT_FATAL)
                self.assertEqual(docker.removed, [])
                self.assertNotIn(str(self.service.working_dir), err.getvalue())
                solo = compose_service(self.root, name="solo", image_id=IMAGE_A)
                solo.stack = solo.compose_service = solo.working_dir = None
                solo.compose_files = []
                self.docker.calls.clear()
                with patch("docker_update_manager.removal.require_mutation_safe"), \
                        patch("docker_update_manager.removal._remaining_container_images", return_value=set()), \
                        contextlib.redirect_stdout(io.StringIO()):
                    try:
                        result = removal.remove_service(solo, state, images=True, yes=True,
                                                        reporter=Reporter(enabled=False), reconcile_discover=lambda: [])
                    except CompletionFenceError:
                        self.assertEqual(self.docker.calls, [])  # refused before any Docker effect
                    else:
                        self.assertIn(IMAGE_A, [image for image, _reason in result["skipped"]])
                self.assertEqual(self.docker.removed, [])

    def test_valid_shared_owners_and_resolved_claims_keep_their_behaviour(self):
        insert_fence(self.state, OP_1, self.service)
        insert_claim(self.state, OP_1, "image", IMAGE_A)
        insert_fence(self.state, OP_2, compose_service(self.root, name="worker"), lifecycle="manual")
        insert_claim(self.state, OP_2, "image", IMAGE_A)
        done = "3" * 32
        insert_fence(self.state, done, compose_service(self.root, name="done"), evidence="{not json")
        insert_claim(self.state, done, "image", IMAGE_B)
        resolve(self.state, done)  # a resolved owner's evidence no longer participates
        self.assertEqual(self.state.completion_claims()["image"], frozenset({IMAGE_A}))
        old_history(self.state, IMAGE_A)
        old_history(self.state, IMAGE_B)
        result = retention.cleanup(self.cfg, self.state, now=datetime.now(timezone.utc))
        self.assertEqual(self.docker.removed, [IMAGE_B])
        self.assertEqual(self.skipped(result)[IMAGE_A], "SKIPPED - UNRESOLVED RECOVERY CLAIM")


if __name__ == "__main__":
    unittest.main()
