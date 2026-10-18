"""Binary rollback compatibility using frozen production schema/opening code."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from docker_update_manager.compose_drift import read_input
from docker_update_manager.compose_reconcile import RecoveryBundle
from docker_update_manager.compose_recovery_retention import checked_bundle, lifecycle
from docker_update_manager.state import CORE_SCHEMA_VERSION, State
from docker_update_manager.retention import cleanup, inventory
from test_disk_retention import Cfg


FIXTURE = Path(__file__).parent / "fixtures" / "production_schema8_state.py"
# Frozen production subset; changing this requires an explicit compatibility
# decision and matching provenance update, never automatic hash regeneration.
PRODUCTION_FIXTURE_SHA256 = "cb8cbbb2868cf6d88ae6a547189122bc0491678448417eba5f6f6c1b9301320c"

spec = importlib.util.spec_from_file_location("production_schema8_state", FIXTURE)
production = importlib.util.module_from_spec(spec)
spec.loader.exec_module(production)


class StateRollbackCompatibilityTests(unittest.TestCase):
    def test_frozen_production_fixture_integrity(self):
        self.assertEqual(hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), PRODUCTION_FIXTURE_SHA256,
                         "Frozen production fixture changed; an explicit compatibility decision is required")

    def test_schema8_to9_preserves_all_rows_and_retains_private_preupgrade_snapshot(self):
        from docker_update_manager.state_transition import transition
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = production.State(root)
            old.record(stack='media',service='sonarr',action='update',old_image_id='sha256:old',result='SUCCESS')
            with old.connect() as c:
                c.execute("CREATE TABLE compose_recovery_receipts(operation_id TEXT PRIMARY KEY,fingerprint TEXT NOT NULL,lifecycle TEXT NOT NULL,finished_at TEXT NOT NULL)")
                c.execute("INSERT INTO compose_recovery_receipts VALUES('retained','proof','manual','2000-01-01')")
            with old.read() as c:
                tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name!='schema_version'")]
                rows = {name:[tuple(row) for row in c.execute('SELECT * FROM '+name)] for name in tables}
            transition(root,confirm_quiescent=True)
            # The schema-10 binary's 8-to-9 action is unchanged; schema 9 is then
            # opened only by transition instances until upgrade-schema10 runs.
            with self.assertRaisesRegex(RuntimeError,'schema-10 transition'):
                State(root).ensure_compatible()
            current = State(root, quiescent_transition=True)
            for _ in range(2):
                current.ensure_compatible()
                with current.read() as c:
                    self.assertEqual(c.execute('SELECT version FROM schema_version').fetchone()[0],9)
                    for name, values in rows.items():
                        self.assertEqual([tuple(row) for row in c.execute('SELECT * FROM '+name)],values)
            snapshot = root/'schema-transitions'/'schema8-before9.sqlite3'
            self.assertEqual(snapshot.stat().st_mode & 0o777,0o600)
            with sqlite3.connect(snapshot) as c:
                self.assertEqual(c.execute('SELECT version FROM schema_version').fetchone()[0],8)
            with self.assertRaisesRegex(RuntimeError,'unsupported core state database schema version 9'):
                production.State(root).record(service='forbidden',action='update',result='SUCCESS')
            self.assertEqual(len(current.history()),1)

    def test_normal_schema8_open_refuses_without_offline_quiescence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = production.State(root)
            old.record(service='synthetic',action='update',result='SUCCESS')
            with self.assertRaisesRegex(RuntimeError,'quiescent state transition'):
                State(root).ensure_compatible()
            with old.read() as c:
                self.assertEqual(c.execute('SELECT version FROM schema_version').fetchone()[0],8)
                self.assertIsNone(c.execute("SELECT name FROM sqlite_master WHERE name='compose_bootstrap_fences'").fetchone())

    def test_transition_refuses_active_workers_operations_and_missing_confirmation(self):
        from docker_update_manager.lock import Lock
        from docker_update_manager.state_transition import transition
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = production.State(root)
            old.record(service='synthetic',action='update',result='SUCCESS')
            with self.assertRaises(ValueError): transition(root)
            for filename in ('update.lock','scan-worker.lock'):
                with Lock(root/filename), self.assertRaises(RuntimeError):
                    transition(root,confirm_quiescent=True)
            with old.connect() as c:
                c.execute("INSERT INTO operation_runs(id,kind,service_key,service,requested_by,status,created_at) VALUES('a','update','container/a','synthetic','fixture','running','2000-01-01')")
            with self.assertRaisesRegex(ValueError,'active operation'):
                transition(root,confirm_quiescent=True)
            self.assertFalse((root/'schema-transitions').exists())

    def test_binary_rollback_requires_no_fences_and_preserves_schema9_evidence(self):
        from docker_update_manager.state_transition import transition
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = production.State(root)
            old.record(service='synthetic',action='update',result='SUCCESS')
            transition(root,confirm_quiescent=True)
            state = State(root, quiescent_transition=True)
            evidence = root/'compose-recoveries'/'unpublished'
            evidence.mkdir(parents=True)
            (evidence/'private').write_text('synthetic')
            with state.connect() as c:
                c.execute("INSERT INTO compose_bootstrap_fences VALUES('logical','operation','proof','manual','2000-01-01','2000-01-01')")
            with self.assertRaisesRegex(ValueError,'unresolved bootstrap'):
                transition(root,rollback=True,confirm_quiescent=True,confirm_state_loss=True)
            with state.connect() as c:
                c.execute("UPDATE compose_bootstrap_fences SET lifecycle='resolved'")
            transition(root,rollback=True,confirm_quiescent=True,confirm_state_loss=True)
            self.assertEqual(len(production.State(root).history()),1)
            self.assertEqual((evidence/'private').read_text(),'synthetic')
            with sqlite3.connect(root/'schema-transitions'/'schema9-before-binary-rollback.sqlite3') as c:
                self.assertEqual(c.execute('SELECT version FROM schema_version').fetchone()[0],9)
                self.assertEqual(c.execute('SELECT count(*) FROM compose_bootstrap_fences').fetchone()[0],1)

    def test_unidentified_schema9_and_future_schema_are_refused_without_normalisation(self):
        for version in (9,99):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                old = production.State(root)
                old.record(service='synthetic',action='update',result='SUCCESS')
                with old.connect() as c:
                    c.execute('UPDATE schema_version SET version=?',(version,))
                with self.assertRaisesRegex(RuntimeError,'unsupported' if version == 99 else 'schema-10 transition'):
                    State(root).history()
                with sqlite3.connect(root/'history.sqlite3') as c:
                    self.assertEqual(c.execute('SELECT version FROM schema_version').fetchone()[0],version)
                    self.assertIsNone(c.execute("SELECT name FROM sqlite_master WHERE name='core_schema_identity'").fetchone())
                    self.assertEqual(c.execute('SELECT count(*) FROM history').fetchone()[0],1)

    def test_v1_bundle_remains_readable_and_archives_receipt_after_schema9_transition(self):
        from docker_update_manager.state_transition import transition, upgrade_schema10
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = production.State(root)
            old.record(service='synthetic',action='update',result='SUCCESS')
            transition(root,confirm_quiescent=True)
            self.assertEqual(upgrade_schema10(root,confirm_quiescent=True),'migrated')
            state = State(root)
            source = root/'fixture.yml'; source.write_text('synthetic')
            inputs = SimpleNamespace(files=(read_input('compose',str(source)),))
            op = 'a'*32
            state.create_operation(op,kind='compose_reconcile',service_key='container/a',service='synthetic',stack='media',
                                   requested_by='fixture',summary={'baseline_id':'b'*32})
            bundle = RecoveryBundle(root,op,inputs,SimpleNamespace(inventory=inputs),{'baseline_id':'b'*32,'evidence':'d'*64})
            state.finish_operation(op,'succeeded',message='fixture',result={'manual_recovery_required':False})
            with state.connect() as c:
                c.execute("UPDATE operation_runs SET created_at='2000-01-01',finished_at='2000-01-01' WHERE id=?",(op,))
            state.prune_operations(retention_days=1)
            with state.read() as c, checked_bundle(root,bundle.path) as checked:
                self.assertEqual(lifecycle(c,op,checked)[0],'terminal')
                self.assertEqual(c.execute('SELECT fingerprint FROM compose_recovery_receipts').fetchone()[0],bundle.manifest_fingerprint)

    def test_hardened_production_fixture_refuses_schema9_before_any_write(self):
        import sys
        fixture_root = Path(__file__).parent/'fixtures'
        sys.path.insert(0,str(fixture_root))
        try:
            import production_schema8_hardened_state as hardened
        finally:
            sys.path.remove(str(fixture_root))
        self.assertEqual(hashlib.sha256((fixture_root/'production_schema8_hardened_state.py').read_bytes()).hexdigest(),'8cc860d0933c3ee12fc61d222bbc992736ec33e05fe5bcf829c495fed53425e5')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            new = State(root); new.ensure_compatible()
            old = hardened.State(root)
            with self.assertRaisesRegex(RuntimeError,f'unsupported core state database schema version {CORE_SCHEMA_VERSION}'):
                old.ensure_compatible()
            with self.assertRaises(RuntimeError):
                old.record(service='forbidden',action='update',result='SUCCESS')
            self.assertFalse(new.history())
