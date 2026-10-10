"""Frozen hardened schema-8 State overrides from b0a913a (implementation 326a890).

Exact method bodies; inherited migration schema/read/write helpers come from
production_schema8_state.py, whose pinned bytes remain unchanged.
"""
import os
import threading
import production_schema8_state as production
from production_schema8_state import *

class State(production.State):
    def __init__(self, root: Path):
        self.root = Path(root)
        self.db_path = self.root / "history.sqlite3"
        self._schema_lock = threading.Lock()
        self._schema_ready = False
        self._schema_version = None

    def _new_connection(self):
        """Open a configured connection after ensuring its containing directory."""
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        os.chmod(self.db_path, 0o600)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(self.db_path) + suffix)
            try:
                os.chmod(sidecar, 0o600)
            except FileNotFoundError:
                # SQLite may remove a sidecar while another connection closes.
                pass
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def ensure_compatible(self):
        """Establish core schema compatibility before any mutation side effect.

        Query-time initialisation is lazy, so a mutation could otherwise back up
        or rewrite sources, pull images or recreate containers before an
        unsupported newer database is noticed. Mutation front doors call this
        first. Every call re-checks the stored version, so a long-lived process
        also refuses a database advanced by a newer binary; a refusal
        leaves the instance unready and every later query fails closed too.
        """
        if self._schema_ready:
            # Cheap read-only recheck; only a changed version re-runs the gate.
            with self.read() as c:
                row = c.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is not None and int(row[0]) == self._schema_version:
                return
        self._ensure_schema(recheck=True)

    def _ensure_schema(self, recheck=False):
        """Run ordered migrations once per State instance, never on each query."""
        if self._schema_ready and not recheck:
            return
        with self._schema_lock:
            if self._schema_ready and not recheck:
                return
            self._schema_ready = False
            connection = self._new_connection()
            try:
                # WAL is configured before the migration transaction. Normal
                # reads then use deferred read transactions and never reserve
                # the single SQLite writer slot.
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("BEGIN IMMEDIATE")
                self._migrate(connection)
                version = int(connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()[0])
                connection.commit()
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(str(self.db_path) + suffix)
                    try:
                        os.chmod(sidecar, 0o600)
                    except FileNotFoundError:
                        pass
                self._schema_version = version
                self._schema_ready = True
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()

    @classmethod
    def _migrate(cls, c):
        c.execute("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)")
        row = c.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        version = int(row[0]) if row else 0
        if version < 1:
            cls._exec_schema(c, LEGACY_SCHEMA)
            c.execute("DELETE FROM schema_version")
            c.execute("INSERT INTO schema_version(version) VALUES(1)")
            version = 1
        if version < 2:
            cls._exec_schema(c, WEB_SCHEMA)
            c.execute("UPDATE schema_version SET version=2")
            version = 2
        if version < 3:
            columns = {row[1] for row in c.execute("PRAGMA table_info(scan_runs)")}
            if "heartbeat_at" not in columns:
                c.execute("ALTER TABLE scan_runs ADD COLUMN heartbeat_at TEXT")
            c.execute("UPDATE scan_runs SET heartbeat_at=COALESCE(heartbeat_at, started_at)")
            c.execute("UPDATE schema_version SET version=3")
            version = 3
        if version < 4:
            cls._migrate_scan_warnings_and_snapshot(c)
            c.execute("UPDATE schema_version SET version=4")
            version = 4
        if version < 5:
            cls._exec_schema(c, OPERATION_SCHEMA)
            c.execute("UPDATE schema_version SET version=5")
            version = 5
        if version < 6:
            cls._exec_schema(c, RUNTIME_SCHEMA)
            c.execute("UPDATE schema_version SET version=6")
            version = 6
        if version < 7:
            cls._exec_schema(c, VERIFICATION_SCHEMA)
            latest = c.execute("SELECT finished_at,payload FROM latest_scan WHERE singleton=1 AND status='complete' AND finished_at IS NOT NULL").fetchone()
            if latest:
                try:
                    services = json.loads(latest["payload"]).get("services", [])
                except (TypeError, ValueError, AttributeError):
                    services = []
                for item in services:
                    cls._save_verification(c, item, latest["finished_at"])
            cls._prune_verifications(c)
            c.execute("UPDATE schema_version SET version=7")
            version = 7
        if version < 8:
            # Additive: server-side trusted Compose baselines. No existing
            # table or row is altered.
            cls._exec_schema(c, COMPOSE_BASELINE_SCHEMA)
            c.execute("UPDATE schema_version SET version=8")
            version = 8
        if version > CORE_SCHEMA_VERSION:
            raise RuntimeError(f"unsupported core state database schema version {version}")
        cls._ensure_extensions(c)

    @staticmethod
    def _ensure_extensions(c):
        # Private additive metadata, ignored by schema-8 production binaries.
        # Initialise only after the core version passes its compatibility gate,
        # in the same transaction; never advance or downgrade the core version.
        c.execute("CREATE TABLE IF NOT EXISTS compose_recovery_receipts(operation_id TEXT PRIMARY KEY, "
                  "fingerprint TEXT NOT NULL, lifecycle TEXT NOT NULL, finished_at TEXT NOT NULL)")
