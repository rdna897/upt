"""An unsupported newer core state schema must be refused before any mutation side effect.

A later core schema (for example a Phase 2B2 bootstrap fence) relies on this
schema-8 binary refusing the database before it backs up or rewrites Compose
sources, pulls images, recreates containers, writes baseline material or
starts the privileged agent. Tests assert the absence of side effects, not only
that an error eventually occurs.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import contextlib, io, json, sqlite3, tempfile, time, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from docker_update_manager.cli import EXIT_FATAL, main
from docker_update_manager.compose_baseline import BASELINE_DIR
from docker_update_manager.models import Service
from docker_update_manager.operations import do_pin, do_rollback, do_update
from docker_update_manager.progress import Reporter
from docker_update_manager.state import CORE_SCHEMA_VERSION, State
from docker_update_manager.webservice import AgentServer, ReadOnlyService, _public_service

from test_compose_reconciliation import ComposeFixture

FUTURE = CORE_SCHEMA_VERSION + 1
COMPOSE = "services:\n  grafana:\n    image: grafana/grafana:latest\n"


def set_version(state_dir, version):
    with contextlib.closing(sqlite3.connect(Path(state_dir) / "history.sqlite3")) as c, c:
        c.execute("UPDATE schema_version SET version=?", (version,))


def version(state_dir):
    with contextlib.closing(sqlite3.connect(Path(state_dir) / "history.sqlite3")) as c:
        return c.execute("SELECT version FROM schema_version").fetchone()[0]


class FutureSchemaFixture(unittest.TestCase):
    def setUp(self):
        # No namespace relation in this legacy fixture; live gates are covered
        # by test_compose_namespace's bounded Docker/Compose fixture.
        namespace = patch("docker_update_manager.compose_namespace.mutation_refusal", return_value=None)
        namespace.start()
        self.addCleanup(namespace.stop)
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.compose = self.root / "compose.yml"; self.compose.write_text(COMPOSE)
        self.state_dir = self.root / "state"
        State(self.state_dir).ensure_compatible()
        # Seed a successful update so rollback has a real rollback point.
        backup = self.state_dir / "backups" / "seed"; backup.mkdir(parents=True)
        (backup / "compose.yml").write_text("services:\n  grafana:\n    image: grafana/grafana:11.0.0\n")
        (backup / "metadata.json").write_text(json.dumps({"stack": "monitoring", "service": "grafana", "files": [
            {"source": str(self.compose), "backup": str(backup / "compose.yml")}]}))
        State(self.state_dir).record(stack="monitoring", service="grafana", action="update",
                                     old_image="grafana/grafana:11.0.0", old_image_id="sha256:" + "0" * 64,
                                     new_image="grafana/grafana:latest", backup=str(backup), result="SUCCESS")
        set_version(self.state_dir, FUTURE)
        self.backups_before = sorted(p.name for p in (self.state_dir / "backups").iterdir())
        self.db_before = (self.state_dir / "history.sqlite3").read_bytes()

    def service(self):
        return Service("grafana", "cid", "grafana/grafana:latest", "iid", "sha256:" + "a" * 64, "12.1.0", None,
                       "amd64", "running", "none", "unless-stopped", None, "monitoring", "grafana",
                       str(self.root), [str(self.compose)])

    def assert_untouched(self):
        self.assertEqual(self.compose.read_text(), COMPOSE)
        self.assertEqual(sorted(p.name for p in (self.state_dir / "backups").iterdir()), self.backups_before)
        self.assertEqual(version(self.state_dir), FUTURE)
        self.assertEqual((self.state_dir / "history.sqlite3").read_bytes(), self.db_before)
        self.assertFalse((self.state_dir / "update.lock").exists())

    @contextlib.contextmanager
    def mutation_spies(self):
        with patch("docker_update_manager.operations.run") as docker, \
             patch("docker_update_manager.operations.run_compose_progress") as compose, \
             patch("docker_update_manager.operations.remote_manifest") as remote, \
             patch("docker_update_manager.operations.validate") as validate, \
             patch("docker_update_manager.cli.run") as cli_run, \
             patch("docker_update_manager.cli.quick_snapshot") as snapshot, \
             patch("docker_update_manager.cli.retention_cleanup") as retention:
            spies = (docker, compose, remote, validate, cli_run, snapshot, retention)
            yield spies
        for spy in spies:
            spy.assert_not_called()

    def run_cli(self, *argv):
        config = Mock(state_dir=self.state_dir, data={})
        err = io.StringIO()
        with patch("docker_update_manager.cli.Config", return_value=config), \
             patch("docker_update_manager.cli.services", return_value=[self.service()]), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = main(list(argv))
        self.assertEqual(code, EXIT_FATAL)
        self.assertIn(f"unsupported core state database schema version {FUTURE}", err.getvalue())


class StatePrimitiveTests(FutureSchemaFixture):
    def test_new_and_current_databases_remain_supported(self):
        fresh = State(self.root / "fresh"); fresh.ensure_compatible(); fresh.ensure_compatible()
        self.assertEqual(version(self.root / "fresh"), CORE_SCHEMA_VERSION)
        self.assertEqual(fresh.history(), [])

    def test_future_version_is_refused_unchanged_and_instance_stays_unusable(self):
        state = State(self.state_dir)
        for _ in range(2):
            with self.assertRaisesRegex(RuntimeError, "unsupported core state database schema version"):
                state.ensure_compatible()
        with self.assertRaises(RuntimeError): state.history()
        self.assert_untouched()

    def test_long_lived_instance_rechecks_version_advanced_by_newer_binary(self):
        set_version(self.state_dir, CORE_SCHEMA_VERSION)
        state = State(self.state_dir); state.ensure_compatible()
        set_version(self.state_dir, FUTURE)
        with self.assertRaisesRegex(RuntimeError, "unsupported core state database schema version"):
            state.ensure_compatible()
        with self.assertRaises(RuntimeError): state.history()


class CliMutationBoundaryTests(FutureSchemaFixture):
    def test_pin_refuses_before_backup_or_source_write(self):
        with self.mutation_spies(), patch("docker_update_manager.operations.backup_files") as backup, \
             patch("docker_update_manager.operations.atomic_write") as write:
            self.run_cli("pin", "grafana", "--yes")
            with self.assertRaises(RuntimeError):
                do_pin(self.service(), State(self.state_dir), yes=True, reporter=Reporter(enabled=False),
                       output=lambda *_: None)
        backup.assert_not_called(); write.assert_not_called()
        self.assert_untouched()

    def test_restore_compose_refuses_before_backup_or_restore(self):
        with self.mutation_spies(), patch("docker_update_manager.compose.backup_files") as backup, \
             patch("docker_update_manager.compose.atomic_write") as write:
            self.run_cli("restore-compose", "seed", "--yes")
        backup.assert_not_called(); write.assert_not_called()
        self.assert_untouched()

    def test_update_refuses_before_pull_source_write_or_recreation(self):
        with self.mutation_spies(), patch("docker_update_manager.operations.backup_files") as backup, \
             patch("docker_update_manager.operations.atomic_write") as write:
            self.run_cli("update", "grafana", "--yes")
            with self.assertRaises(RuntimeError):
                do_update(self.service(), State(self.state_dir), yes=True, reporter=Reporter(enabled=False),
                          output=lambda *_: None)
        backup.assert_not_called(); write.assert_not_called()
        self.assert_untouched()

    def test_rollback_refuses_before_source_or_docker_mutation(self):
        with self.mutation_spies(), patch("docker_update_manager.operations.atomic_write") as write:
            self.run_cli("rollback", "grafana", "--yes")
            with self.assertRaises(RuntimeError), contextlib.redirect_stdout(io.StringIO()):
                do_rollback(self.service(), State(self.state_dir), yes=True, reporter=Reporter(enabled=False))
        write.assert_not_called()
        self.assert_untouched()

    def test_other_modifying_commands_refuse_before_lock_or_side_effects(self):
        for argv in (("pull", "grafana"), ("restart", "grafana", "--yes"), ("cleanup", "--yes"),
                     ("remove", "grafana", "--yes"), ("retention", "cleanup", "--yes")):
            with self.subTest(argv=argv), self.mutation_spies(), \
                 patch("docker_update_manager.cli.discover", return_value=[self.service()]), \
                 patch("docker_update_manager.cli.remove_service") as remove, \
                 patch("docker_update_manager.cli.Lock") as lock:
                self.run_cli(*argv)
            remove.assert_not_called(); lock.assert_not_called()
            self.assert_untouched()


class AgentBoundaryTests(FutureSchemaFixture):
    def test_long_lived_agent_mutation_starts_refuse_before_any_side_effect(self):
        for kind, action in (("update", None), ("rollback", None),
                             ("compose_reconcile", "apply"), ("compose_reconcile", "discard")):
            with self.subTest(kind=kind, action=action):
                state = State(self.root / f"agent-{kind}-{action}")
                state.ensure_compatible()
                self.assertEqual(version(state.root), CORE_SCHEMA_VERSION)
                agent = ReadOnlyService(Mock(), state)
                # An old queued operation makes premature recovery observable.
                state.create_operation("abandoned", kind="update", service_key="fixture",
                                       service="grafana", stack="monitoring", requested_by="owner", summary={})
                with state.connect() as c:
                    c.execute("UPDATE operation_runs SET created_at='2000-01-01T00:00:00+00:00'")
                confirmation_id = "a" * 43
                intent = SimpleNamespace(expires_at=time.monotonic() + 600, requested_by="owner",
                                         service_key="fixture", action=action, baseline_id=1,
                                         evidence_fingerprint="fixture",
                                         service_identity=agent._service_review_identity(_public_service(self.service())))
                intents = getattr(agent, f"_{'compose' if action else kind}_intents")
                intents[confirmation_id] = intent
                payload = {"confirmation_id": confirmation_id, "requested_by": "owner",
                           "client_ip": "127.0.0.1", "user_agent": "fixture"}
                set_version(state.root, FUTURE)

                def persistent_rows():
                    # Use an independent reader: the refused State becomes unusable.
                    with contextlib.closing(sqlite3.connect(state.db_path)) as c:
                        return {table: c.execute(f"SELECT * FROM {table} ORDER BY id").fetchall()
                                for table in ("operation_runs", "operation_events", "audit_events", "history")}

                before = persistent_rows()
                source_before = self.compose.read_bytes()
                with contextlib.ExitStack() as stack:
                    spies = [stack.enter_context(patch.object(state, method, wraps=getattr(state, method)))
                             for method in ("recover_abandoned_operations", "create_operation", "audit",
                                            "operation_event", "finish_operation")]
                    spies += [stack.enter_context(patch.object(agent, method)) for method in
                              ("_intent_candidate", "_rollback_intent_candidate", "_compose_intent_candidate",
                               "_update_worker", "_rollback_worker", "_compose_worker")]
                    spies += [stack.enter_context(patch(target)) for target in
                              ("docker_update_manager.webservice.threading.Thread",
                               "docker_update_manager.webservice.discover", "docker_update_manager.webservice.run",
                               "docker_update_manager.operations.run", "docker_update_manager.operations.atomic_write",
                               "docker_update_manager.compose.atomic_write")]
                    with self.assertRaisesRegex(RuntimeError, f"unsupported core state database schema version {FUTURE}"):
                        getattr(agent, f"start_{kind}")(payload)
                    for spy in spies:
                        spy.assert_not_called()
                self.assertEqual(persistent_rows(), before)
                self.assertEqual(self.compose.read_bytes(), source_before)
                self.assertEqual(version(state.root), FUTURE)
                self.assertEqual(agent._operation_threads, {})
                self.assertIs(intents[confirmation_id], intent)

    def test_agent_refuses_to_start_before_socket_or_health_monitor(self):
        service = SimpleNamespace(state=State(self.state_dir), start_health_monitor=Mock())
        socket_path = self.root / "agent.sock"
        with self.assertRaisesRegex(RuntimeError, "unsupported core state database schema version"):
            AgentServer(service, str(socket_path), allow_test_paths=True).serve_forever()
        self.assertFalse(socket_path.exists())
        service.start_health_monitor.assert_not_called()
        self.assert_untouched()


class PassiveCaptureBoundaryTests(ComposeFixture):
    def test_running_agent_does_not_capture_baseline_after_schema_advance(self):
        self.state.ensure_compatible()
        set_version(self.state.root, FUTURE)
        self.status()
        self.assertFalse((self.state.root / BASELINE_DIR).exists())
        self.assertEqual(version(self.state.root), FUTURE)
        with contextlib.closing(sqlite3.connect(self.state.root / "history.sqlite3")) as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM compose_baselines").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
