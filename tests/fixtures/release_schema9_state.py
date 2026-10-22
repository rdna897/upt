"""Frozen public schema-9 State opening code from main@468468f (pre G2-S0b).

Exact schema-9 gate semantics: the core version/identity checks of
State.ensure_compatible/_ensure_schema/_migrate and the cleanup schema check of
retention.CleanupState._require_schema. Legacy migration steps and query
helpers are inherited from the frozen schema-8 fixtures. Used only to prove a
schema-9 binary refuses schema-10 state before any write.
"""
import json
import production_schema8_hardened_state as hardened
from production_schema8_state import *

CORE_SCHEMA_VERSION = 9
CORE_SCHEMA_IDENTITY = "upt-compose-bootstrap-phase2b2-v1"
BOOTSTRAP_SCHEMA = """
CREATE TABLE core_schema_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1), identity TEXT NOT NULL);
CREATE TABLE compose_bootstrap_fences(
  logical_key TEXT NOT NULL, operation_id TEXT PRIMARY KEY, evidence TEXT NOT NULL,
  lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','manual','resolved')),
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX idx_bootstrap_unresolved ON compose_bootstrap_fences(logical_key)
  WHERE lifecycle IN ('active','manual');
"""


def cleanup_schema_compatible(c):
    """Frozen retention.CleanupState._require_schema(current=True) predicate."""
    version = c.execute("SELECT version FROM schema_version").fetchall()
    identity = [tuple(row) for row in c.execute("SELECT singleton,identity FROM core_schema_identity")] \
        if c.execute("SELECT 1 FROM sqlite_master WHERE name='core_schema_identity'").fetchone() else []
    return [tuple(row) for row in version] == [(CORE_SCHEMA_VERSION,)] and identity == [(1, CORE_SCHEMA_IDENTITY)]


class State(hardened.State):
    core_schema_identity = CORE_SCHEMA_IDENTITY

    def __init__(self, root: Path, *, quiescent_transition=False):
        super().__init__(root)
        self._quiescent_transition = quiescent_transition
        self.created_schema = False

    def ensure_compatible(self):
        if self._schema_ready:
            with self.read() as c:
                row = c.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
            if row is not None and int(row[0]) == self._schema_version:
                try:
                    with self.read() as c:
                        identity = c.execute('SELECT singleton,identity FROM core_schema_identity').fetchall()
                except sqlite3.DatabaseError:
                    self._schema_ready = False
                    raise RuntimeError('unsupported schema-9 identity') from None
                if len(identity) == 1 and tuple(identity[0]) == (1, CORE_SCHEMA_IDENTITY):
                    return
        self._ensure_schema(recheck=True)

    def _ensure_schema(self, recheck=False):
        if self._schema_ready and not recheck:
            return
        with self._schema_lock:
            if self._schema_ready and not recheck:
                return
            self._schema_ready = False
            connection = self._new_connection()
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("BEGIN IMMEDIATE")
                old = connection.execute("SELECT name FROM sqlite_master WHERE name='schema_version'").fetchone()
                version = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone() if old else None
                if version and int(version[0]) == 8 and not self._quiescent_transition:
                    raise RuntimeError("schema 8 to 9 requires the offline quiescent state transition")
                created = not version
                self._migrate(connection)
                version = int(connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()[0])
                connection.commit()
                self.created_schema = self.created_schema or created
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
        if version < 8:
            # Legacy steps are inherited unchanged from the schema-8 fixture.
            hardened.State._migrate.__func__(cls, c)
            version = int(c.execute("SELECT version FROM schema_version LIMIT 1").fetchone()[0])
        if version > CORE_SCHEMA_VERSION:
            raise RuntimeError(f"unsupported core state database schema version {version}")
        if version < 9:
            cls._exec_schema(c, BOOTSTRAP_SCHEMA)
            c.execute("INSERT INTO core_schema_identity VALUES(1,?)", (CORE_SCHEMA_IDENTITY,))
            for action in ('UPDATE', 'DELETE'):
                c.execute(f"CREATE TRIGGER core_schema_identity_no_{action.lower()} BEFORE {action} ON core_schema_identity BEGIN SELECT RAISE(ABORT,'immutable schema identity'); END")
            c.execute("UPDATE schema_version SET version=9")
        else:
            try:
                identity = c.execute("SELECT singleton,identity FROM core_schema_identity").fetchall()
                fence_columns = {row[1] for row in c.execute("PRAGMA table_info(compose_bootstrap_fences)")}
            except sqlite3.DatabaseError:
                raise RuntimeError("unsupported schema-9 identity") from None
            if (len(identity) != 1 or tuple(identity[0]) != (1, CORE_SCHEMA_IDENTITY)
                    or fence_columns != {"logical_key", "operation_id", "evidence", "lifecycle", "created_at", "updated_at"}):
                raise RuntimeError("unsupported schema-9 identity")
        c.execute("CREATE TABLE IF NOT EXISTS compose_recovery_receipts(operation_id TEXT PRIMARY KEY, "
                  "fingerprint TEXT NOT NULL, lifecycle TEXT NOT NULL, finished_at TEXT NOT NULL)")

    def record(self, **kw):
        keys = list(kw)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in kw.values()]
        with self.connect() as c:
            cur = c.execute(f"INSERT INTO history ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})", vals)
            if kw.get("old_image_id") and kw.get("result") != "BLOCKED":
                c.execute("INSERT OR REPLACE INTO protected_images(image_id,reason,history_id) VALUES(?,?,?)", (kw["old_image_id"], "rollback", cur.lastrowid))
                c.execute("INSERT OR REPLACE INTO rollback_refs(history_id,image_id) VALUES(?,?)", (cur.lastrowid, kw["old_image_id"]))
            return cur.lastrowid
