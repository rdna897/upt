from __future__ import annotations

import json
import re
import fcntl
import os
import secrets
import sqlite3
import threading
from .progress import BOOTSTRAP_STAGE_TOTAL, UPDATE_STAGE_TOTAL, RECONCILE_STAGE_TOTAL, UPDATE_RECORD_LABEL
from .sqlite_outcome import AMBIGUOUS, NOT_COMMITTED, OwnedTransaction, WriteOutcomeError, sqlite_timeout
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

LEGACY_SCHEMA = """
CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, timestamp TEXT DEFAULT CURRENT_TIMESTAMP, stack TEXT, service TEXT NOT NULL, action TEXT NOT NULL, old_image TEXT, old_image_id TEXT, old_digest TEXT, old_version TEXT, new_image TEXT, new_image_id TEXT, new_digest TEXT, new_version TEXT, backup TEXT, result TEXT NOT NULL, rollback_result TEXT, details TEXT);
CREATE TABLE IF NOT EXISTS protected_images(image_id TEXT PRIMARY KEY, reason TEXT, history_id INTEGER, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS rollback_refs(history_id INTEGER PRIMARY KEY, image_id TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP, expired INTEGER DEFAULT 0, purge_status TEXT);
CREATE INDEX IF NOT EXISTS idx_rollback_image ON rollback_refs(image_id);
CREATE TABLE IF NOT EXISTS disk_snapshots(id INTEGER PRIMARY KEY, timestamp TEXT DEFAULT CURRENT_TIMESTAMP, kind TEXT NOT NULL, metrics TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_disk_timestamp ON disk_snapshots(timestamp);
"""

WEB_SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS web_sessions(
  id TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL, absolute_expires_at TEXT NOT NULL, revoked_at TEXT,
  client_ip TEXT, user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_web_sessions_expiry ON web_sessions(expires_at, revoked_at);
CREATE TABLE IF NOT EXISTS web_credentials(
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_web_credentials_kind ON web_credentials(kind, expires_at, consumed_at);
CREATE TABLE IF NOT EXISTS audit_events(
  id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, username TEXT,
  action TEXT NOT NULL, result TEXT NOT NULL, client_ip TEXT, user_agent TEXT,
  details TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE TABLE IF NOT EXISTS scan_runs(
  id TEXT PRIMARY KEY, started_at TEXT NOT NULL, heartbeat_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL,
  total INTEGER NOT NULL DEFAULT 0, completed INTEGER NOT NULL DEFAULT 0,
  error TEXT
);
CREATE TABLE IF NOT EXISTS scan_events(
  id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  timestamp TEXT NOT NULL, kind TEXT NOT NULL, service TEXT, status TEXT,
  message TEXT, payload TEXT
);
CREATE INDEX IF NOT EXISTS idx_scan_events_run ON scan_events(run_id, id);
CREATE TABLE IF NOT EXISTS service_snapshots(
  scan_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  service_key TEXT NOT NULL, stack TEXT, service TEXT NOT NULL, payload TEXT NOT NULL,
  PRIMARY KEY(scan_id, service_key)
);
CREATE TABLE IF NOT EXISTS latest_scan(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1), scan_id TEXT NOT NULL REFERENCES scan_runs(id),
  started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, payload TEXT NOT NULL
);
"""
OPERATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_runs(
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, service_key TEXT NOT NULL,
  service TEXT NOT NULL, stack TEXT, requested_by TEXT, status TEXT NOT NULL,
  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  current_stage TEXT, summary TEXT NOT NULL DEFAULT '{}',
  error TEXT, result TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_operation_runs_status ON operation_runs(status,created_at);
CREATE INDEX IF NOT EXISTS idx_operation_runs_service ON operation_runs(stack,service,created_at);
CREATE TABLE IF NOT EXISTS operation_events(
  id INTEGER PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES operation_runs(id) ON DELETE CASCADE,
  timestamp TEXT NOT NULL, kind TEXT NOT NULL, stage TEXT, message TEXT NOT NULL,
  status TEXT, payload TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_operation_events_run ON operation_events(operation_id,id);
"""
RUNTIME_SCHEMA = """
CREATE TABLE IF NOT EXISTS runtime_snapshot(
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  captured_at TEXT,
  attempted_at TEXT NOT NULL,
  attempt_success INTEGER NOT NULL,
  failure_category TEXT,
  payload TEXT
);
"""
VERIFICATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS service_verifications(
  service_key TEXT PRIMARY KEY, identity TEXT NOT NULL, verification_id TEXT,
  checked_at TEXT, payload TEXT, failed_at TEXT, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_service_verifications_checked ON service_verifications(checked_at);
"""
COMPOSE_BASELINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS compose_baselines(
  id TEXT PRIMARY KEY, logical_key TEXT NOT NULL, stack TEXT NOT NULL, compose_service TEXT NOT NULL,
  container_id TEXT NOT NULL, runtime_hash TEXT NOT NULL, project_fingerprint TEXT NOT NULL,
  service_fingerprint TEXT NOT NULL, inventory_fingerprint TEXT NOT NULL, fingerprint TEXT NOT NULL,
  origin TEXT NOT NULL, captured_at TEXT NOT NULL, manifest TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_compose_baselines_logical ON compose_baselines(logical_key, captured_at);
"""
VERIFICATION_IDENTITY_FIELDS = (
    "container_id", "image", "image_id", "digest", "version", "architecture",
    "state", "stack", "compose_service", "working_dir", "compose_files",
    "restart_policy", "local_build", "ignored",
)
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
CURRENT_SCHEMA_VERSION = CORE_SCHEMA_VERSION  # Compatibility for existing consumers.
VERIFICATION_INVALIDATED = "Check required after service changes"
OPERATION_EVENT_LIMIT = 200
OPERATION_HISTORY_LIMIT = 500
# "blocked" is a factual pre-mutation refusal: terminal, never active.
OPERATION_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "blocked"})
COMPOSE_BASELINE_COLUMNS = (
    "id", "logical_key", "stack", "compose_service", "container_id", "runtime_hash",
    "project_fingerprint", "service_fingerprint", "inventory_fingerprint", "fingerprint",
    "origin", "captured_at", "manifest",
)


class AmbiguousHistoryError(ValueError):
    """Raised when legacy history cannot be attributed to one service stack."""


SESSION_TOMBSTONE = timedelta(hours=24)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def verification_identity(service: dict) -> str:
    return json.dumps([service.get(field) for field in VERIFICATION_IDENTITY_FIELDS], separators=(",", ":"))


class State:
    supports_service_verification = True
    core_schema_identity = CORE_SCHEMA_IDENTITY

    def __init__(self, root: Path, *, quiescent_transition=False, require_existing=False):
        self.root = Path(root)
        self.db_path = self.root / "history.sqlite3"
        self._schema_lock = threading.Lock()
        self._schema_ready = False
        self._schema_version = None
        self._quiescent_transition = quiescent_transition
        # Set once this instance initialises a database that had no schema.
        self.created_schema = False
        # Never create or initialise a database: only open and migrate one
        # that already has a schema (fail-closed safety commands).
        self._require_existing = require_existing

    def _new_connection(self, timeout=None, *, existing=False):
        """Open a configured connection after ensuring its containing directory.

        ``timeout`` bounds both the open and SQLite's busy wait (default 30 s).
        ``existing`` opens only an existing database file and never creates one.
        """
        timeout = sqlite_timeout(timeout)
        if existing or self._require_existing:
            connection = sqlite3.connect(f"{self.db_path.resolve().as_uri()}?mode=rw", uri=True, timeout=timeout)
        else:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            connection = sqlite3.connect(self.db_path, timeout=timeout)
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
        # Validated above, so the formatted value cannot carry SQL.
        connection.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
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
                if self.core_schema_identity is None:
                    return  # Web-owned authentication state has its own schema.
                # Schema identity is authority, even in a long-lived process.
                try:
                    with self.read() as c:
                        identity = c.execute('SELECT singleton,identity FROM core_schema_identity').fetchall()
                except sqlite3.DatabaseError:
                    self._schema_ready = False
                    raise RuntimeError('unsupported schema-9 identity') from None
                if len(identity) == 1 and tuple(identity[0]) == (1, CORE_SCHEMA_IDENTITY):
                    return
        self._ensure_schema(recheck=True)

    def _ensure_schema(self, recheck=False, timeout=None):
        """Run ordered migrations once per State instance, never on each query."""
        if self._schema_ready and not recheck:
            return
        with self._schema_lock:
            if self._schema_ready and not recheck:
                return
            self._schema_ready = False
            connection = self._new_connection(timeout=timeout)
            try:
                if self._require_existing:
                    self._require_schema_table(connection)
                # WAL is configured before the migration transaction. Normal
                # reads then use deferred read transactions and never reserve
                # the single SQLite writer slot.
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("BEGIN IMMEDIATE")
                if self._require_existing:
                    self._require_schema_table(connection)
                old = connection.execute("SELECT name FROM sqlite_master WHERE name='schema_version'").fetchone()
                version = connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone() if old else None
                if self.core_schema_identity is not None and version and int(version[0]) == 8 and not self._quiescent_transition:
                    raise RuntimeError("schema 8 to 9 requires the offline quiescent state transition")
                created = not version
                self._migrate(connection)
                version = int(connection.execute("SELECT version FROM schema_version LIMIT 1").fetchone()[0])
                connection.commit()
                self.created_schema = self.created_schema or created
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

    @staticmethod
    def _require_schema_table(connection):
        if not connection.execute("SELECT 1 FROM sqlite_master WHERE name='schema_version'").fetchone():
            raise RuntimeError("UPT state database is not initialised; refusing to initialise it")

    @contextmanager
    def connect(self):
        """Open an exclusive write transaction; use read() for SELECT queries."""
        self._ensure_schema()
        c = self._new_connection()
        try:
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.commit()
        except BaseException:
            c.rollback()
            raise
        finally:
            c.close()

    @contextmanager
    def write_transaction(self, *, timeout=None):
        """Opt-in write transaction whose failures are classified (G2-S0a).

        Returning normally means committed. Any ``Exception`` is re-raised as
        ``WriteOutcomeError`` carrying ``NOT_COMMITTED`` only when commit was
        never attempted and the transaction was still open, and ``AMBIGUOUS``
        otherwise. The body receives an ``OwnedTransaction``: it may execute
        statements but cannot commit, roll back or end the transaction.
        ``BaseException`` (for example ``KeyboardInterrupt``) still rolls back
        and propagates unclassified. Never hold this across Docker, Compose,
        filesystem effects or sleeps.
        """
        try:
            self._ensure_schema(timeout=timeout)
            c = self._new_connection(timeout=timeout)
        except Exception as exc:
            raise WriteOutcomeError(NOT_COMMITTED, "connect", exc) from exc
        try:
            try:
                c.execute("BEGIN IMMEDIATE")
                handle = OwnedTransaction(c)
            except Exception as exc:
                raise WriteOutcomeError(NOT_COMMITTED, "begin", exc) from exc
            try:
                yield handle
            except Exception as exc:
                bypassed = handle._release()
                # Only the original, still-open transaction is provably discarded.
                outcome = NOT_COMMITTED if c.in_transaction and not bypassed else AMBIGUOUS
                self._quiet_rollback(c)
                raise WriteOutcomeError(outcome, "body", exc) from exc
            except BaseException:
                handle._release()
                self._quiet_rollback(c)
                raise
            if handle._release() or not c.in_transaction:
                # Ended or replaced without UPT's commit (e.g. SQLite automatic
                # rollback or an out-of-band COMMIT); discard any newer transaction.
                self._quiet_rollback(c)
                exc = RuntimeError("the owned SQLite transaction ended before commit")
                raise WriteOutcomeError(AMBIGUOUS, "body", exc)
            try:
                c.commit()
            except Exception as exc:
                # A failed commit acknowledgement proves nothing either way.
                self._quiet_rollback(c)
                raise WriteOutcomeError(AMBIGUOUS, "commit", exc) from exc
            except BaseException:
                self._quiet_rollback(c)
                raise
        finally:
            try:
                c.close()
            except Exception:
                pass  # The outcome is already established; closing cannot change it.

    @staticmethod
    def _quiet_rollback(connection):
        # Rollback cannot commit; its own failure must not mask the outcome.
        try:
            connection.rollback()
        except Exception:
            pass

    @contextmanager
    def read(self, *, timeout=None):
        """Open a consistent read transaction without a writer reservation.

        ``timeout`` optionally bounds the open/busy wait (default 30 s).
        """
        self._ensure_schema(timeout=timeout)
        c = self._new_connection(timeout=timeout)
        try:
            c.execute("BEGIN")
            yield c
        finally:
            c.rollback()
            c.close()

    @contextmanager
    def read_existing(self, *, timeout=None):
        """Read transaction that never creates, initialises or migrates state.

        For fail-closed safety checks: a missing database raises instead of
        being replaced by an empty one. Callers must verify the schema.
        """
        c = self._new_connection(timeout=timeout, existing=True)
        try:
            c.execute("BEGIN")
            yield c
        finally:
            c.rollback()
            c.close()

    @contextmanager
    def scan_worker_guard(self):
        """Cross-process lease held for the entire scan worker lifetime."""
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.root / "scan-worker.lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _scan_worker_is_live(self):
        """Return whether another worker owns the cross-process lease."""
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.root / "scan-worker.lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        finally:
            os.close(fd)

    @staticmethod
    def _exec_schema(c, schema: str):
        for statement in schema.split(";"):
            statement = statement.strip()
            if statement:
                c.execute(statement)

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
        if version < 9:
            cls._exec_schema(c, BOOTSTRAP_SCHEMA)
            c.execute("INSERT INTO core_schema_identity VALUES(1,?)", (CORE_SCHEMA_IDENTITY,))
            for action in ('UPDATE','DELETE'):
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
        cls._ensure_extensions(c)

    @staticmethod
    def _ensure_extensions(c):
        # Private additive metadata, ignored by schema-8 production binaries.
        # Initialise only after the core version passes its compatibility gate,
        # in the same transaction; never advance or downgrade the core version.
        c.execute("CREATE TABLE IF NOT EXISTS compose_recovery_receipts(operation_id TEXT PRIMARY KEY, "
                  "fingerprint TEXT NOT NULL, lifecycle TEXT NOT NULL, finished_at TEXT NOT NULL)")

    @staticmethod
    def _migrate_scan_warnings_and_snapshot(c):
        columns = {row[1] for row in c.execute("PRAGMA table_info(scan_runs)")}
        if "maintenance_warning" not in columns:
            c.execute("ALTER TABLE scan_runs ADD COLUMN maintenance_warning TEXT")
        # Older versions pointed latest_scan at every terminal attempt,
        # including failed attempts whose timestamps then looked fresh.
        # Rebuild the cache pointer from a completed run when possible;
        # otherwise make its freshness explicitly unknown.
        latest = c.execute("SELECT scan_id FROM latest_scan WHERE singleton=1").fetchone()
        if latest:
            linked = c.execute("SELECT status FROM scan_runs WHERE id=?", (latest[0],)).fetchone()
            if not linked or linked[0] != "complete":
                replacement = c.execute(
                    "SELECT id,started_at,finished_at,total FROM scan_runs "
                    "WHERE status='complete' AND finished_at IS NOT NULL "
                    "ORDER BY finished_at DESC,rowid DESC"
                ).fetchall()
                rebuilt = None
                for run in replacement:
                    rows = c.execute(
                        "SELECT payload FROM service_snapshots WHERE scan_id=? ORDER BY service_key",
                        (run["id"],),
                    ).fetchall()
                    if int(run["total"] or 0) != len(rows):
                        continue
                    try:
                        services = [json.loads(row[0]) for row in rows]
                    except (TypeError, json.JSONDecodeError):
                        continue
                    rebuilt = (run, {"services": services, "count": len(services)})
                    break
                if rebuilt:
                    run, payload = rebuilt
                    c.execute(
                        "UPDATE latest_scan SET scan_id=?,started_at=?,finished_at=?,status='complete',payload=? WHERE singleton=1",
                        (run["id"], run["started_at"], run["finished_at"], json.dumps(payload, separators=(",", ":"))),
                    )
                else:
                    c.execute("UPDATE latest_scan SET finished_at=NULL,status='stale' WHERE singleton=1")

    def record(self, *, namespace_operation_id=None, **kw):
        keys = list(kw)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in kw.values()]
        with self.connect() as c:
            if namespace_operation_id:
                row = c.execute("SELECT summary FROM operation_runs WHERE id=? AND kind='update' AND status='running'",
                                (namespace_operation_id,)).fetchone()
                if (not row or kw.get('result') != 'SUCCESS'
                        or json.loads(row[0]).get('namespace_recreate_started') is not True):
                    raise ValueError('namespace update publication is not authorised')
            q = f"INSERT INTO history ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})"
            cur = c.execute(q, vals)
            if (kw.get("old_image_id") and kw.get("result") != "BLOCKED"
                    and kw.get("action") not in {"compose_reconcile", "compose_bootstrap"}):
                c.execute("INSERT OR REPLACE INTO protected_images(image_id,reason,history_id) VALUES(?,?,?)", (kw["old_image_id"], "rollback", cur.lastrowid))
                c.execute("INSERT OR REPLACE INTO rollback_refs(history_id,image_id) VALUES(?,?)", (cur.lastrowid, kw["old_image_id"]))
            if namespace_operation_id:
                result = {'updated': True, 'history_id': cur.lastrowid, 'manual_recovery_required': False}
                c.execute("UPDATE operation_runs SET status='succeeded',finished_at=?,current_stage='Complete',result=? WHERE id=?",
                          (_utc_now(), json.dumps(result), namespace_operation_id))
                c.execute("UPDATE compose_bootstrap_fences SET lifecycle='resolved',updated_at=? WHERE operation_id=?",
                          (_utc_now(), namespace_operation_id))
                # The History record is this update's durable completion point and its final
                # stage; it is committed here, before the terminal event, because the core
                # reporter can no longer persist events once the operation is terminal.
                self._insert_operation_event(c, namespace_operation_id, 'task_completed', status='completed', message='Completed',
                    stage=f'{UPDATE_STAGE_TOTAL}/{UPDATE_STAGE_TOTAL} {UPDATE_RECORD_LABEL}')
                self._insert_operation_event(c, namespace_operation_id, 'operation_completed',
                    stage='Complete', message='Namespace image update verified.', status='succeeded', payload=result)
            return cur.lastrowid

    def history(self, service=None):
        if not self.db_path.exists():
            return []
        with self.read() as c:
            q, args = "SELECT * FROM history", []
            if service:
                q += " WHERE service=?"
                args = [service]
            q += " ORDER BY id DESC"
            return [dict(x) for x in c.execute(q, args)]

    def history_for_service(self, stack, service):
        """Return history for one stack/service identity, never a namesake.

        Rows with an explicit stack are always matched exactly. A legacy NULL
        stack row is associated with a Compose service only when its retained
        UPT backup metadata proves the original stack/service identity. A
        current inventory alone is insufficient to attribute historical data.
        Unprovable legacy rows fail closed when no exact scoped history exists;
        when exact history does exist, those rows are ignored rather than merged
        or allowed to invalidate the proven identity.
        """
        if not self.db_path.exists():
            return []
        with self.read() as c:
            exact = [dict(row) for row in c.execute(
                "SELECT * FROM history WHERE stack IS ? AND service=? ORDER BY id DESC",
                (stack, service),
            )]
            legacy = [dict(row) for row in c.execute(
                "SELECT * FROM history WHERE stack IS NULL AND service=? ORDER BY id DESC",
                (service,),
            )] if stack is not None else []

        if stack is None:
            latest = None
            with self.read() as c:
                row = c.execute("SELECT status,payload FROM latest_scan WHERE singleton=1").fetchone()
                if row and row[0] == "complete": latest = row[1]
            if latest and len(self._snapshot_identities(latest, service)) > 1:
                proven = [(item, self._legacy_history_identity(item)) for item in exact]
                if any(identity is None for _, identity in proven):
                    raise AmbiguousHistoryError(
                        f"history for service {service!r} is ambiguous across stacks; refusing to select a rollback point"
                    )
                return [item for item, identity in proven if identity == (None, service)]
            return exact

        if not legacy:
            return exact
        attributed = []
        ambiguous = []
        for row in legacy:
            identity = self._legacy_history_identity(row)
            if identity is None:
                ambiguous.append(row)
                continue
            if identity == (stack, service):
                attributed.append(row)
        if ambiguous and not exact:
            raise AmbiguousHistoryError(
                f"legacy history for service {service!r} has no trustworthy stack metadata; refusing to select it"
            )
        return sorted(exact + attributed, key=lambda row: int(row["id"]), reverse=True)

    def _legacy_history_identity(self, row):
        """Read stack/service identity only from an existing UPT backup manifest."""
        backup = row.get("backup")
        if not backup:
            return None
        directory = Path(backup)
        backup_root = (self.root / "backups").resolve(strict=False)
        try:
            if directory.is_symlink(): return None
            directory = directory.resolve(strict=True)
            if not directory.is_relative_to(backup_root) or not directory.is_dir(): return None
            metadata = directory / "metadata.json"
            if metadata.is_symlink() or not metadata.is_file(): return None
            data = json.loads(metadata.read_text())
            stack, service = data.get("stack"), data.get("service")
            if not service: return None
            return stack, service
        except (OSError, TypeError, json.JSONDecodeError):
            return None

    @staticmethod
    def _snapshot_identities(payload, service):
        try:
            data = json.loads(payload) if isinstance(payload, str) else payload
        except (TypeError, json.JSONDecodeError):
            return set()
        identities = set()
        for item in (data or {}).get("services", []):
            details = item.get("service") or {}
            names = {details.get(key) for key in ("compose_service", "key", "name")}
            names.discard(None)
            if service not in names: continue
            stack = details.get("stack")
            identity = details.get("compose_service") or details.get("key") or details.get("name")
            identities.add((stack, identity))
        return identities

    def protected(self):
        if not self.db_path.exists():
            return set()
        with self.read() as c:
            return {x[0] for x in c.execute("SELECT image_id FROM protected_images")}

    def save_disk_snapshot(self, kind, metrics):
        with self.connect() as c:
            return c.execute("INSERT INTO disk_snapshots(kind,metrics) VALUES(?,?)", (kind, json.dumps(metrics, separators=(",", ":")))).lastrowid

    def compact_if_needed(self, minimum_free_bytes=1024 * 1024, minimum_free_ratio=0.20):
        if not self.db_path.exists():
            return {"compacted": False, "bytes_reclaimed": 0}
        before = self.db_path.stat().st_size
        with self.read() as c:
            page_size = c.execute("PRAGMA page_size").fetchone()[0]
            page_count = c.execute("PRAGMA page_count").fetchone()[0]
            free_pages = c.execute("PRAGMA freelist_count").fetchone()[0]
        free_bytes = page_size * free_pages
        if free_bytes < minimum_free_bytes or not page_count or free_pages / page_count < minimum_free_ratio:
            return {"compacted": False, "bytes_reclaimed": 0, "free_bytes": free_bytes}
        # VACUUM cannot run inside the write transaction opened by connect().
        # Use a short-lived autocommit connection after the free-page check.
        vacuum = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        try:
            vacuum.execute("PRAGMA busy_timeout=30000")
            vacuum.execute("VACUUM")
        finally:
            vacuum.close()
        after = self.db_path.stat().st_size
        return {"compacted": True, "bytes_reclaimed": max(0, before - after), "free_bytes": 0}

    def disk_snapshots(self, since=None, limit=None):
        if not self.db_path.exists():
            return []
        with self.read() as c:
            q, args = "SELECT * FROM disk_snapshots", []
            if since:
                q += " WHERE timestamp>=?"
                args = [since]
            q += " ORDER BY timestamp DESC"
            if limit:
                q += " LIMIT ?"
                args.append(limit)
            rows = []
            for row in c.execute(q, args):
                item = dict(row)
                item["metrics"] = json.loads(item["metrics"])
                rows.append(item)
            return rows

    # Web/auth persistence -------------------------------------------------
    def web_user(self):
        with self.read() as c:
            row = c.execute("SELECT * FROM users WHERE disabled=0 ORDER BY id LIMIT 1").fetchone()
            return dict(row) if row else None

    def create_user(self, username: str, password_hash: str):
        username = username.strip()
        if not username or len(username) > 80:
            raise ValueError("username must be between 1 and 80 characters")
        with self.connect() as c:
            if c.execute("SELECT 1 FROM users WHERE disabled=0 LIMIT 1").fetchone():
                raise ValueError("administrator already exists")
            cur = c.execute("INSERT INTO users(username,password_hash) VALUES(?,?)", (username, password_hash))
            return int(cur.lastrowid)

    def update_password(self, user_id: int, password_hash: str):
        with self.connect() as c:
            c.execute("UPDATE users SET password_hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND disabled=0", (password_hash, user_id))
            c.execute("UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (_utc_now(), user_id))

    def create_credential(self, kind: str, token_hash: str, expires_at: str):
        with self.connect() as c:
            if kind == "bootstrap" and c.execute("SELECT 1 FROM users WHERE disabled=0 LIMIT 1").fetchone():
                raise ValueError("administrator already exists; use recovery instead")
            c.execute("DELETE FROM web_credentials WHERE kind=? AND consumed_at IS NULL", (kind,))
            c.execute("INSERT INTO web_credentials(kind,token_hash,created_at,expires_at) VALUES(?,?,CURRENT_TIMESTAMP,?)", (kind, token_hash, expires_at))

    @staticmethod
    def _credential_id(c, kind: str, digest: str, now: str):
        return c.execute("SELECT id FROM web_credentials WHERE kind=? AND token_hash=? AND consumed_at IS NULL AND expires_at>? ORDER BY id DESC LIMIT 1", (kind, digest, now)).fetchone()

    def create_user_with_credential(self, digest: str, username: str, password_hash: str, now: str | None = None):
        username, now = username.strip(), now or _utc_now()
        if not username or len(username) > 80: raise ValueError("username must be between 1 and 80 characters")
        with self.connect() as c:
            if c.execute("SELECT 1 FROM users WHERE disabled=0 LIMIT 1").fetchone(): raise ValueError("administrator already exists")
            row = self._credential_id(c, "bootstrap", digest, now)
            if not row: raise ValueError("invalid or expired setup code")
            cur = c.execute("INSERT INTO users(username,password_hash) VALUES(?,?)", (username, password_hash))
            if c.execute("UPDATE web_credentials SET consumed_at=? WHERE id=? AND consumed_at IS NULL", (now, row[0])).rowcount != 1:
                raise ValueError("setup code was already used")
            return int(cur.lastrowid)

    def update_password_with_credential(self, digest: str, user_id: int, password_hash: str, now: str | None = None):
        now = now or _utc_now()
        with self.connect() as c:
            row = self._credential_id(c, "recovery", digest, now)
            if not row: raise ValueError("invalid or expired recovery code")
            if c.execute("UPDATE users SET password_hash=?,updated_at=? WHERE id=? AND disabled=0", (password_hash, now, user_id)).rowcount != 1:
                raise ValueError("administrator does not exist")
            c.execute("UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (now, user_id))
            if c.execute("UPDATE web_credentials SET consumed_at=? WHERE id=? AND consumed_at IS NULL", (now, row[0])).rowcount != 1:
                raise ValueError("recovery code was already used")

    def consume_credential(self, kind: str, token_hash: str, now: str | None = None) -> bool:
        now = now or _utc_now()
        with self.connect() as c:
            row = c.execute("SELECT id FROM web_credentials WHERE kind=? AND token_hash=? AND consumed_at IS NULL AND expires_at>? ORDER BY id DESC LIMIT 1", (kind, token_hash, now)).fetchone()
            if not row:
                return False
            c.execute("UPDATE web_credentials SET consumed_at=? WHERE id=?", (now, row[0]))
            return True

    def delete_credential(self, kind: str, token_hash: str):
        with self.connect() as c:
            c.execute("DELETE FROM web_credentials WHERE kind=? AND token_hash=? AND consumed_at IS NULL", (kind, token_hash))

    def create_session(self, user_id: int | None, csrf_token: str, expires_at: str, absolute_expires_at: str, client_ip: str | None = None, user_agent: str | None = None, session_id: str | None = None):
        sid = session_id or secrets.token_urlsafe(32)
        now = _utc_now()
        with self.connect() as c:
            c.execute("INSERT INTO web_sessions(id,user_id,csrf_token,created_at,last_seen_at,expires_at,absolute_expires_at,client_ip,user_agent) VALUES(?,?,?,?,?,?,?,?,?)", (sid, user_id, csrf_token, now, now, expires_at, absolute_expires_at, client_ip, (user_agent or "")[:300]))
        return sid

    def session(self, session_id: str):
        with self.read() as c:
            row = c.execute("SELECT s.*,u.username FROM web_sessions s LEFT JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.revoked_at IS NULL", (session_id,)).fetchone()
            return dict(row) if row else None

    def session_record(self, session_id: str):
        """Session row regardless of revocation, for rejection diagnostics only."""
        with self.read() as c:
            row = c.execute("SELECT id,user_id,revoked_at FROM web_sessions WHERE id=?", (session_id,)).fetchone()
            return dict(row) if row else None

    def touch_session(self, session_id: str, last_seen: str, expires_at: str):
        with self.connect() as c:
            c.execute("UPDATE web_sessions SET last_seen_at=?,expires_at=? WHERE id=? AND revoked_at IS NULL", (last_seen, expires_at, session_id))

    def revoke_session(self, session_id: str):
        with self.connect() as c:
            c.execute("UPDATE web_sessions SET revoked_at=? WHERE id=?", (_utc_now(), session_id))

    def revoke_other_sessions(self, user_id: int, keep_session: str | None = None):
        with self.connect() as c:
            if keep_session:
                c.execute("UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND id<>? AND revoked_at IS NULL", (_utc_now(), user_id, keep_session))
            else:
                c.execute("UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (_utc_now(), user_id))

    def prune_sessions(self, now: str | None = None):
        # Ended sessions are kept briefly so a rejected cookie can still be
        # classified (revoked vs unknown) instead of vanishing within a minute.
        now = now or _utc_now()
        cutoff = (datetime.fromisoformat(now) - SESSION_TOMBSTONE).isoformat()
        with self.connect() as c:
            return c.execute("DELETE FROM web_sessions WHERE revoked_at<=? OR expires_at<=? OR absolute_expires_at<=?", (cutoff, cutoff, cutoff)).rowcount

    def audit(self, action: str, result: str, *, user_id: int | None = None, username: str | None = None, client_ip: str | None = None, user_agent: str | None = None, details: dict | None = None):
        with self.connect() as c:
            c.execute("INSERT INTO audit_events(timestamp,user_id,username,action,result,client_ip,user_agent,details) VALUES(?,?,?,?,?,?,?,?)", (_utc_now(), user_id, username, action, result, client_ip, (user_agent or "")[:300], json.dumps(details or {}, separators=(",", ":"))))

    def audit_events(self, limit=100):
        with self.read() as c:
            rows = []
            for row in c.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (int(limit),)):
                item = dict(row)
                try:
                    item["details"] = json.loads(item.get("details") or "{}")
                except json.JSONDecodeError:
                    item["details"] = {}
                rows.append(item)
            return rows

    # Durable bounded web-operation state ---------------------------------
    def prune_operations(self, retention_days: int = 30, limit: int = OPERATION_HISTORY_LIMIT):
        """Keep operation replay state bounded without deleting active work."""
        retention_days = max(1, min(int(retention_days), 3650))
        limit = max(20, min(int(limit), 5000))
        from .compose_recovery_retention import archive_lifecycle
        with self.connect() as c:
            rows = c.execute(
                "SELECT id,summary,status,result FROM operation_runs WHERE status IN ('succeeded','failed','blocked') "
                "AND (julianday(COALESCE(finished_at,created_at)) < julianday('now', ?) "
                "OR id IN (SELECT id FROM operation_runs WHERE status IN ('succeeded','failed','blocked') "
                "ORDER BY created_at DESC LIMIT -1 OFFSET ?))",
                (f"-{retention_days} days", limit),
            ).fetchall()
            for row in rows:
                summary = json.loads(row['summary'])
                if row['status'] != 'succeeded' and summary.get('namespace_recreate_started'):
                    continue  # Durable manual-recovery fence: never expire passive trust protection.
                if summary.get('namespace_apply') is not None and (
                        json.loads(row['result'] or '{}').get('manual_recovery_required') is not False
                        or c.execute("SELECT 1 FROM compose_bootstrap_fences WHERE operation_id=? AND lifecycle IN ('active','manual')",
                                     (row[0],)).fetchone()):
                    continue  # Manual namespace Apply rows and baseline references are retained.
                archive_lifecycle(c, self.root, row[0])
                c.execute("DELETE FROM operation_runs WHERE id=?", (row[0],))

    def recover_abandoned_operations(self, minimum_age_seconds: int = 60):
        """Mark old active records interrupted; caller must hold update.lock.

        The lock is the liveness proof: a live update worker keeps the same
        cross-process lock for its entire preflight/pull/recreate/health path,
        including while Docker commands block. Age alone never releases a
        worker or allows another update to overlap it.
        """
        age = max(60, min(int(minimum_age_seconds), 3600))
        recovered = 0
        with self.read() as c:
            bootstraps = c.execute("SELECT id FROM operation_runs WHERE kind='compose_bootstrap' AND status IN ('queued','running','finalizing') AND (status!='queued' OR julianday(COALESCE(started_at,created_at)) < julianday('now', ?))", (f'-{age} seconds',)).fetchall()
        for row in bootstraps:
            recovered += bool(self.finish_bootstrap_failure(row[0]))
        with self.read() as c:
            reconciles = c.execute("SELECT id,summary FROM operation_runs WHERE kind='compose_reconcile' AND status IN ('queued','running','finalizing') AND (status!='queued' OR julianday(COALESCE(started_at,created_at)) < julianday('now', ?))", (f'-{age} seconds',)).fetchall()
        for row in reconciles:
            try:
                namespace = json.loads(row[1] or '{}').get('namespace_apply') is not None
            except (ValueError, TypeError, AttributeError):
                namespace = True  # Unreadable journal cannot become generic success/blocked.
            if namespace:
                # Never generic: marked/unprovable is manual, never replayed.
                recovered += bool(self.finish_namespace_apply(row[0], reason='interrupted'))
        with self.connect() as c:
            rows = c.execute(
                "SELECT id,requested_by,service_key,kind,summary,status FROM operation_runs "
                "WHERE status IN ('queued','running','finalizing') "
                "AND julianday(COALESCE(started_at,created_at)) < julianday('now', ?) "
                "ORDER BY created_at",
                (f"-{age} seconds",),
            ).fetchall()
            for row in rows:
                message = "Agent stopped while this update was active. Check the container and UPT History before retrying."
                status = "failed"
                result = {}
                action = "web_update"
                summary = json.loads(row['summary'] or '{}')
                if row['kind'] == 'update' and summary.get('namespace_recreate_started'):
                    message = 'Agent stopped during namespace image update; manual recovery is required.'
                    result = {'manual_recovery_required': True, 'mutation_performed': True,
                              'recovery_attempted': False}
                if row["kind"] == "compose_reconcile":
                    summary = json.loads(row["summary"] or "{}")
                    uncertain_mutation = bool(summary.get("mutation_started"))
                    status = "failed" if uncertain_mutation else "blocked"
                    action = "web_compose_reconcile"
                    message = ("Agent stopped during configuration Apply. Recovery evidence was retained; manual recovery is required."
                               if uncertain_mutation else "Agent stopped before configuration recreation. No application changes were made.")
                    discard = summary.get("action") == "discard"
                    result = {"action": "discard" if discard else "apply", "mutation_performed": uncertain_mutation,
                              "manual_recovery_required": uncertain_mutation, "recovered": False}
                    if discard:
                        from .compose_discard import classify_interrupted_discard
                        source_state = classify_interrupted_discard(self.root, row["id"], summary,
                                                                    queued=row["status"] == "queued")
                        manual = source_state not in {"pending", "not_started"}
                        status = "failed" if manual else "blocked"
                        message = {
                            "pending": "Agent stopped during Discard. The exact reviewed pending source remains present; no source changes were made.",
                            "not_started": "Agent stopped before Discard started. No source changes were made.",
                            "discarded": "Agent stopped after Discard source replacement. Verification was interrupted; manual source recovery required. UPT did not recreate the service.",
                            "unknown": "Agent stopped during Discard. Source state could not be proved; manual source recovery required. UPT did not recreate the service.",
                        }[source_state]
                        result.update(source_state=source_state,
                                      mutation_performed=True if source_state == "discarded" else None if source_state == "unknown" else False,
                                      manual_recovery_required=manual, manual_source_recovery_required=manual,
                                      source_recovered=False)
                changed = c.execute(
                    "UPDATE operation_runs SET status=?,finished_at=?,current_stage='Interrupted',error=?,result=? "
                    "WHERE id=? AND status IN ('queued','running','finalizing')",
                    (status, _utc_now(), message, json.dumps(result), row["id"]),
                ).rowcount
                if not changed:
                    continue
                if row['kind'] == 'update' and summary.get('namespace_recreate_started'):
                    c.execute("UPDATE compose_bootstrap_fences SET lifecycle='manual',updated_at=? WHERE operation_id=?",
                              (_utc_now(), row['id']))
                self._insert_operation_event(c, row["id"], "operation_blocked" if status == "blocked" else "operation_failed",
                                             stage="Interrupted", message=message, status=status, payload=result)
                c.execute(
                    "INSERT INTO audit_events(timestamp,username,action,result,details) VALUES(?,?,?,?,?)",
                    (_utc_now(), row["requested_by"], action, "interrupted",
                     json.dumps({"origin": "web", "operation_id": row["id"], "service_key": row["service_key"],
                                 **(result if row["kind"] == "compose_reconcile" else {})}, separators=(",", ":"))),
                )
                recovered += 1
        return recovered

    @staticmethod
    def _insert_operation_event(c, operation_id: str, kind: str, *, stage=None,
                                message: str, status=None, payload=None):
        clean_message = " ".join(str(message or "").split())[:300]
        clean_stage = " ".join(str(stage or "").split())[:160] or None
        clean_status = str(status)[:32] if status is not None else None
        clean_payload = json.dumps(payload if isinstance(payload, dict) else {}, separators=(",", ":"))
        if len(clean_payload) > 4096:
            raise ValueError("operation event payload is too large")
        cursor = c.execute(
            "INSERT INTO operation_events(operation_id,timestamp,kind,stage,message,status,payload) "
            "VALUES(?,?,?,?,?,?,?)",
            (operation_id, _utc_now(), str(kind)[:40], clean_stage, clean_message, clean_status, clean_payload),
        )
        c.execute(
            "DELETE FROM operation_events WHERE operation_id=? AND id NOT IN "
            "(SELECT id FROM operation_events WHERE operation_id=? ORDER BY id DESC LIMIT ?)",
            (operation_id, operation_id, OPERATION_EVENT_LIMIT),
        )
        return cursor.lastrowid

    def create_operation(self, operation_id: str, *, kind: str, service_key: str,
                         service: str, stack: str | None, requested_by: str,
                         summary: dict):
        """Atomically claim the single active web mutation slot and persist it."""
        if not operation_id or len(operation_id) > 64 or not operation_id.isascii() or not operation_id.isalnum():
            raise ValueError("invalid operation identifier")
        for value, label, limit in ((kind, "operation kind", 32), (service_key, "service identifier", 200),
                                    (service, "service name", 200), (requested_by, "requester", 80)):
            if not isinstance(value, str) or not value or len(value) > limit or any(c in value for c in "\0\r\n"):
                raise ValueError(f"invalid {label}")
        if not isinstance(summary, dict):
            raise ValueError("invalid operation summary")
        encoded_summary = json.dumps(summary, separators=(",", ":"))
        if len(encoded_summary) > 4096:
            raise ValueError("operation summary is too large")
        self.prune_operations()
        created = _utc_now()
        with self.connect() as c:
            active = c.execute(
                "SELECT id FROM operation_runs WHERE status IN ('queued','running','finalizing') "
                "ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if active:
                raise RuntimeError("another web operation is already active")
            c.execute(
                "INSERT INTO operation_runs(id,kind,service_key,service,stack,requested_by,status,created_at,summary) "
                "VALUES(?,?,?,?,?,?,'queued',?,?)",
                (operation_id, kind, service_key, service, stack, requested_by, created, encoded_summary),
            )
            self._insert_operation_event(
                c, operation_id, "operation_started", stage="Queued",
                message=f"{kind.title()} requested for {service}", status="queued",
                payload={"operation": kind, "service": service},
            )

    def set_operation_running(self, operation_id: str, stage: str = "Starting"):
        now = _utc_now()
        with self.connect() as c:
            changed = c.execute(
                "UPDATE operation_runs SET status='running',started_at=COALESCE(started_at,?),current_stage=? "
                "WHERE id=? AND status='queued'",
                (now, str(stage)[:160], operation_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("operation is no longer queued")

    def operation_event(self, operation_id: str, kind: str, *, stage=None,
                        message: str, status=None, payload=None):
        with self.connect() as c:
            row = c.execute("SELECT status FROM operation_runs WHERE id=?", (operation_id,)).fetchone()
            if not row or row[0] not in {"queued", "running", "finalizing"}:
                raise RuntimeError("operation is not active")
            event_id = self._insert_operation_event(
                c, operation_id, kind, stage=stage, message=message, status=status, payload=payload,
            )
            if stage:
                c.execute(
                    "UPDATE operation_runs SET current_stage=? WHERE id=?",
                    (str(stage)[:160], operation_id),
                )
            return event_id

    def finish_operation(self, operation_id: str, status: str, *, message: str,
                         error: str | None = None, result: dict | None = None, final_stage: str | None = None):
        """Commit the terminal state; ``final_stage`` (success only) is committed in the same
        transaction immediately before the terminal event, so a retry can never duplicate it
        and it can never outlive a terminal state that failed to commit."""
        if status not in OPERATION_TERMINAL_STATUSES:
            raise ValueError("invalid terminal operation status")
        finished = _utc_now()
        encoded_result = json.dumps(result or {}, separators=(",", ":"))
        if len(encoded_result) > 4096:
            raise ValueError("operation result is too large")
        stage = {"succeeded": "Complete", "failed": "Failed", "blocked": "Blocked"}[status]
        kind = {"succeeded": "operation_completed", "failed": "operation_failed", "blocked": "operation_blocked"}[status]
        with self.connect() as c:
            row = c.execute('SELECT kind,summary FROM operation_runs WHERE id=?', (operation_id,)).fetchone()
            if row and row[0] == 'compose_bootstrap':
                raise ValueError('bootstrap completion requires its dedicated trust publication/failure boundary')
            if row and row[0] == 'compose_reconcile' and json.loads(row[1] or '{}').get('namespace_apply') is not None:
                raise ValueError('namespace Apply completion requires its dedicated publication/failure boundary')
            changed = c.execute(
                "UPDATE operation_runs SET status=?,finished_at=?,current_stage=?,error=?,result=? "
                "WHERE id=? AND status IN ('queued','running','finalizing')",
                (status, finished, stage,
                 str(error)[:300] if error else None, encoded_result, operation_id),
            ).rowcount
            if changed != 1:
                return False
            if row and json.loads(row[1]).get('namespace_recreate_started'):
                if status != 'failed':
                    raise ValueError('namespace success requires atomic verified history publication')
                c.execute("UPDATE compose_bootstrap_fences SET lifecycle='manual',updated_at=? WHERE operation_id=?",
                          (_utc_now(), operation_id))
            if final_stage and status == "succeeded":
                self._insert_operation_event(c, operation_id, "task_completed", stage=final_stage,
                                             message="Completed", status="completed")
            self._insert_operation_event(
                c, operation_id, kind, stage=stage,
                message=message, status=status, payload=result or {},
            )
        return True

    def bootstrap_fence(self, logical_key, *, own_operation=None, allow_marked=False):
        with self.read() as c:
            row = c.execute("SELECT * FROM compose_bootstrap_fences WHERE (logical_key=? OR ? IS NULL OR logical_key LIKE 'unproven:%') AND lifecycle IN ('active','manual') AND operation_id!=?",
                            (logical_key, logical_key, own_operation if allow_marked else '')).fetchone()
        if row:
            return dict(row)
        # An unproved v2 orphan cannot become passive-adoption authority merely
        # because replay rows were lost. Material remains protected by retention.
        from .compose_baseline import _read_private
        from .compose_recovery_retention import checked_bundle, lifecycle
        import re
        import stat
        root = self.root / 'compose-recoveries'
        if root.is_symlink():
            return {'lifecycle':'manual','operation_id':'unproven'}
        for path in root.glob('*'):
            manifest = None
            if not re.fullmatch('[0-9a-f]{32}',path.name):
                continue
            try:
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    return {'lifecycle':'manual','operation_id':path.name}
                manifest = json.loads(_read_private(path/'manifest.json',256*1024))
                if isinstance(manifest,dict) and manifest.get('version') == 1:
                    continue
                if isinstance(manifest,dict) and manifest.get('version') == 3 and manifest.get('action') == 'namespace_apply':
                    # Only a fully validated v3 binding may name a logical key;
                    # any failure falls through to the global manual refusal.
                    with self.read() as c, checked_bundle(self.root,path) as bundle:
                        if logical_key is not None and bundle['binding']['logical_key'] != logical_key:
                            continue
                        if path.name == own_operation:
                            owner = c.execute("SELECT summary,status FROM operation_runs WHERE id=? AND kind='compose_reconcile'", (own_operation,)).fetchone()
                            if owner and owner['status'] == 'running':
                                summary = json.loads(owner['summary'])
                                if (not summary.get('namespace_apply_marked') and not summary.get('mutation_started')
                                        and summary.get('namespace_apply_review') == bundle['binding']['review']
                                        and summary.get('namespace_apply_evidence') in (None, bundle['fingerprint'])):
                                    continue
                        if lifecycle(c,path.name,bundle)[0] == 'terminal':
                            continue
                    return {'lifecycle':'manual','operation_id':path.name}
                if not isinstance(manifest,dict) or manifest.get('version') != 2 or manifest.get('action') != 'bootstrap':
                    return {'lifecycle':'manual','operation_id':path.name}
                binding = manifest.get('binding')
                key = binding.get('logical_key') if isinstance(binding,dict) else None
                if logical_key is not None and key is not None and key != logical_key:
                    continue
                with self.read() as c, checked_bundle(self.root,path) as bundle:
                    if path.name == own_operation:
                        owner = c.execute("SELECT summary,status FROM operation_runs WHERE id=? AND kind='compose_bootstrap'", (own_operation,)).fetchone()
                        if owner and owner['status'] == 'running':
                            summary = json.loads(owner['summary'])
                            if (allow_marked or not summary.get('recreate_may_have_started')) and summary.get('bootstrap_evidence') == bundle['fingerprint']:
                                continue
                    disposition,_finished = lifecycle(c,path.name,bundle)
                    if disposition == 'terminal':
                        continue
                return {'lifecycle':'manual','operation_id':path.name}
            except (OSError,ValueError,TypeError):
                # Unproved identified bootstrap evidence is a fence too.
                return {'lifecycle':'manual','operation_id':path.name}
        return None

    def assert_service_unfenced(self, service):
        from .compose_baseline import logical_key
        if service.stack and service.compose_service and service.working_dir and service.compose_files:
            key = logical_key(service.stack, service.compose_service, service.working_dir, service.compose_files)
            # Checked first: namespace markers share the bootstrap fence table.
            if self.namespace_update_fence(key):
                raise ValueError('namespace_update_unresolved: manual recovery is required')
            if self.bootstrap_fence(key):
                raise ValueError("bootstrap_unresolved: manual recovery is required")

    def namespace_update_fence(self, key):
        """The existing operation journal is authority, including after interruption."""
        with self.read() as c:
            rows = c.execute("SELECT id,summary FROM operation_runs WHERE kind='update' AND status!='succeeded'")
            for row in rows:
                summary = json.loads(row['summary'])
                if summary.get('namespace_recreate_started') and summary.get('namespace_logical_key') == key:
                    return row['id']
        return None

    def mark_namespace_update(self, operation_id, key, owner_fingerprint, old_image_id):
        """Commit before Compose: protect the image and fence uncertain trust atomically."""
        with self.connect() as c:
            row = c.execute("SELECT summary FROM operation_runs WHERE id=? AND kind='update' AND status='running'",
                            (operation_id,)).fetchone()
            if not row:
                raise ValueError('namespace update is not active')
            summary = json.loads(row[0])
            if summary.get('namespace_recreate_started'):
                raise ValueError('namespace update already crossed its boundary')
            # Reuse the existing logical-service fence table. Stage-1 binaries
            # already honour it, so downgrading cannot passively trust an
            # interrupted namespace image update. No schema/version change.
            now = _utc_now()
            c.execute("INSERT INTO compose_bootstrap_fences VALUES(?,?,?,'active',?,?)",
                      (key, operation_id, owner_fingerprint, now, now))
            summary.update(namespace_recreate_started=True, namespace_logical_key=key,
                           namespace_owner_fingerprint=owner_fingerprint)
            c.execute('UPDATE operation_runs SET summary=? WHERE id=?', (json.dumps(summary), operation_id))
            c.execute('INSERT OR IGNORE INTO protected_images(image_id,reason) VALUES(?,?)',
                      (old_image_id, 'namespace update manual recovery'))

    def bind_bootstrap_evidence(self, operation_id, evidence, *, logical_key, review, requester,
                                old_container_id, runtime_hash, service_fingerprint, inventory_fingerprint):
        with self.connect() as c:
            row = c.execute("SELECT summary,requested_by FROM operation_runs WHERE id=? AND kind='compose_bootstrap' AND status='running'",
                            (operation_id,)).fetchone()
            if not row:
                raise ValueError("bootstrap operation is unavailable")
            summary = json.loads(row[0])
            if (row['requested_by'] != requester or summary.get('logical_key') != logical_key
                    or summary.get('review_evidence') != review or summary.get('bootstrap_evidence')):
                raise ValueError('bootstrap evidence ownership changed')
            summary['bootstrap_evidence'] = evidence
            summary['baseline_expectation'] = {'runtime_hash':runtime_hash,'service_fingerprint':service_fingerprint,
                                                'inventory_fingerprint':inventory_fingerprint}
            summary['old_container_id'] = old_container_id
            c.execute("UPDATE operation_runs SET summary=? WHERE id=?", (json.dumps(summary), operation_id))

    def mark_bootstrap_recreate(self, operation_id, logical_key, evidence, baseline_signature):
        """Caller holds update.lock. Dispatch requires acknowledged commit."""
        now = _utc_now()
        with self.connect() as c:
            row = c.execute("SELECT summary FROM operation_runs WHERE id=? AND kind='compose_bootstrap' AND status='running'",
                            (operation_id,)).fetchone()
            if not row:
                raise ValueError("bootstrap operation is unavailable")
            summary = json.loads(row[0])
            if (summary.get('bootstrap_evidence') != evidence or summary.get('recreate_may_have_started')
                    or summary.get('logical_key') != logical_key):
                raise ValueError("bootstrap evidence changed")
            if c.execute("SELECT 1 FROM compose_bootstrap_fences WHERE (logical_key=? OR logical_key LIKE 'unproven:%') AND lifecycle IN ('active','manual')", (logical_key,)).fetchone():
                raise ValueError('bootstrap_unresolved')
            records = tuple((row['id'], row['fingerprint']) for row in c.execute("SELECT id,fingerprint FROM compose_baselines WHERE logical_key=? ORDER BY captured_at DESC,rowid DESC", (logical_key,)))
            if records != baseline_signature:
                raise ValueError('trust store changed before recreation')
            summary.update(recreate_may_have_started=True, logical_key=logical_key)
            c.execute("INSERT INTO compose_bootstrap_fences VALUES(?,?,?,'active',?,?)",
                      (logical_key, operation_id, evidence, now, now))
            c.execute("UPDATE operation_runs SET summary=?,current_stage='Recreating service to establish trust' WHERE id=?", (json.dumps(summary), operation_id))
            self._insert_operation_event(c, operation_id, "task_info", stage="Recreating service to establish trust",
                                         message="Recreation may have started; automatic configuration rollback is unavailable.",
                                         status="info")

    def publish_bootstrap_success(self, operation_id, record, proof, *, requester, client_ip, user_agent):
        """One commit publishes trust, result, history, audit and fence resolution.

        The caller validates staged material and all final proofs immediately
        before entry. No post-commit correctness check may revoke completion.
        """
        if set(record) != set(COMPOSE_BASELINE_COLUMNS):
            raise ValueError("invalid compose baseline record")
        if self.bootstrap_fence(record['logical_key'], own_operation=operation_id, allow_marked=True):
            raise ValueError('bootstrap_unresolved')
        now = _utc_now()
        result = {"action": "bootstrap", "mutation_performed": True, "recovered": False,
                  "manual_recovery_required": False, "trust_established": True,
                  "refresh_required": True, "current_service_key": "container/" + record["container_id"]}
        message = "Configuration applied; trusted baseline established"
        with self.connect() as c:
            row = c.execute("SELECT * FROM operation_runs WHERE id=? AND kind='compose_bootstrap' AND status='running'",
                            (operation_id,)).fetchone()
            fence = c.execute("SELECT * FROM compose_bootstrap_fences WHERE operation_id=? AND lifecycle='active'",
                              (operation_id,)).fetchone()
            if not row or not fence or row['requested_by'] != requester:
                raise ValueError("bootstrap ownership is unavailable")
            summary = json.loads(row['summary'])
            if (summary.get('recreate_may_have_started') is not True
                    or summary.get('bootstrap_evidence') != fence['evidence']
                    or record['logical_key'] != fence['logical_key']
                    or record['container_id'] == summary.get('old_container_id')
                    or record['origin'] != 'captured' or record['stack'] != row['stack']
                    or record['compose_service'] != row['service']
                    or summary.get('baseline_expectation') != {name:record[name] for name in ('runtime_hash','service_fingerprint','inventory_fingerprint')}):
                raise ValueError("bootstrap fence does not match")
            if c.execute("SELECT 1 FROM compose_bootstrap_fences WHERE operation_id!=? AND (logical_key=? OR logical_key LIKE 'unproven:%') AND lifecycle IN ('active','manual')", (operation_id,record['logical_key'])).fetchone():
                raise ValueError('bootstrap_unresolved')
            c.execute(f"INSERT INTO compose_baselines({','.join(COMPOSE_BASELINE_COLUMNS)}) VALUES({','.join('?' for _ in COMPOSE_BASELINE_COLUMNS)})",
                      tuple(record[name] for name in COMPOSE_BASELINE_COLUMNS))
            summary.update(new_baseline_id=record['id'], completion_proof=proof)
            self._invalidate_verification(c, row['service_key'])
            self._invalidate_verification(c, 'container/' + record['container_id'])
            details = json.dumps({"origin": "web", "operation_id": operation_id, **result})
            c.execute("INSERT INTO history(stack,service,action,result,details) VALUES(?,?,'compose_bootstrap','SUCCESS',?)",
                      (row['stack'], row['service'], details))
            c.execute("INSERT INTO audit_events(timestamp,username,action,result,client_ip,user_agent,details) VALUES(?,?,'web_compose_bootstrap','success',?,?,?)",
                      (now, requester, client_ip, user_agent, details))
            c.execute("UPDATE operation_runs SET status='succeeded',finished_at=?,current_stage=?,summary=?,result=? WHERE id=?",
                      (now, message, json.dumps(summary), json.dumps(result), operation_id))
            # Trust publication is the durable completion point and the final stage.
            self._insert_operation_event(c, operation_id, "task_completed", status="completed", message="Completed",
                                         stage=f"{BOOTSTRAP_STAGE_TOTAL}/{BOOTSTRAP_STAGE_TOTAL} Publish trusted baseline and result")
            self._insert_operation_event(c, operation_id, "operation_completed", stage=message, message=message,
                                         status="succeeded", payload=result)
            c.execute("UPDATE compose_bootstrap_fences SET lifecycle='resolved',updated_at=? WHERE operation_id=?",
                      (now, operation_id))
        return result

    def finish_bootstrap_failure(self, operation_id, *, reason='review_changed'):
        """Persistent marker/fence takes precedence over in-memory dispatch."""
        now = _utc_now()
        with self.connect() as c:
            row = c.execute("SELECT * FROM operation_runs WHERE id=? AND kind='compose_bootstrap'", (operation_id,)).fetchone()
            if not row or row['status'] in OPERATION_TERMINAL_STATUSES:
                return False
            try:
                summary = json.loads(row['summary'])
                uncertain = bool(summary.get('recreate_may_have_started'))
            except (ValueError, TypeError, AttributeError):
                summary, uncertain = {}, True
            fence = c.execute("SELECT operation_id FROM compose_bootstrap_fences WHERE operation_id=?", (operation_id,)).fetchone()
            uncertain = uncertain or bool(fence)
            # A running operation with missing/corrupt committed evidence cannot
            # license an assertion that no dispatch occurred.
            if row['status'] != 'queued' and summary.get('bootstrap_evidence'):
                from .compose_recovery_retention import checked_bundle
                try:
                    with checked_bundle(self.root, self.root / 'compose-recoveries' / operation_id) as bundle:
                        if bundle['fingerprint'] != summary['bootstrap_evidence']:
                            uncertain = True
                except (OSError, ValueError, TypeError):
                    uncertain = True
            status = 'failed' if uncertain else 'blocked'
            result = {"action": "bootstrap", "mutation_performed": None if uncertain else False,
                      "recovered": False, "manual_recovery_required": uncertain, "trust_established": False}
            if not uncertain:
                result['blocked_reason'] = reason
            message = ("Bootstrap failed/interrupted — manual recovery required" if uncertain
                       else "Blocked — no workload changes")
            if uncertain and not fence:
                c.execute("INSERT INTO compose_bootstrap_fences VALUES(?,?,?,'manual',?,?)",
                          (summary.get('logical_key') or 'unproven:'+operation_id, operation_id, summary.get('bootstrap_evidence') or 'unproven', now, now))
            c.execute("UPDATE compose_bootstrap_fences SET lifecycle='manual',updated_at=? WHERE operation_id=? AND lifecycle='active'",
                      (now, operation_id))
            c.execute("UPDATE operation_runs SET status=?,finished_at=?,current_stage=?,error=?,result=? WHERE id=?",
                      (status, now, message, message, json.dumps(result), operation_id))
            self._insert_operation_event(c, operation_id, 'operation_failed' if uncertain else 'operation_blocked',
                                         stage=message, message=message, status=status, payload=result)
            details = json.dumps({"origin": "web", "operation_id": operation_id, **result})
            c.execute("INSERT INTO history(stack,service,action,result,details) VALUES(?,?,'compose_bootstrap',?,?)",
                      (row['stack'], row['service'], status.upper(), details))
            c.execute("INSERT INTO audit_events(timestamp,username,action,result,details) VALUES(?,?,'web_compose_bootstrap',?,?)",
                      (now, row['requested_by'], status, details))
        return True

    # Namespace Stage 2 configuration Apply (v3 evidence, schema-9 fence) ------
    @staticmethod
    def _namespace_apply_row(c, operation_id):
        row = c.execute("SELECT * FROM operation_runs WHERE id=? AND kind='compose_reconcile'", (operation_id,)).fetchone()
        if not row:
            raise ValueError('namespace Apply operation is unavailable')
        summary = json.loads(row['summary'])
        if not isinstance(summary, dict) or summary.get('namespace_apply') != 3:
            raise ValueError('namespace Apply operation is unavailable')
        return row, summary

    @staticmethod
    def _namespace_apply_fence(c, operation_id, summary):
        fence = c.execute("SELECT * FROM compose_bootstrap_fences WHERE operation_id=?", (operation_id,)).fetchone()
        if (not fence or fence['lifecycle'] != 'active' or fence['evidence'] != summary.get('namespace_apply_evidence')
                or fence['logical_key'] != summary.get('namespace_apply_logical_key')
                or summary.get('namespace_apply_marked') is not True):
            raise ValueError('namespace Apply fence does not match')
        return fence

    def bind_namespace_apply_evidence(self, operation_id, evidence, *, logical_key, review, owner, requester,
                                      expectation):
        def digest(value):
            return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None
        if (not digest(evidence) or not isinstance(expectation, dict) or set(expectation) != {'desired', 'baseline'}
                or any(not isinstance(item, list) or len(item) != 3 or not all(map(digest, item))
                       for item in expectation.values())):
            raise ValueError('invalid namespace Apply evidence binding')
        with self.connect() as c:
            row, summary = self._namespace_apply_row(c, operation_id)
            if (row['status'] != 'running' or row['requested_by'] != requester
                    or summary.get('namespace_apply_logical_key') != logical_key
                    or summary.get('namespace_apply_review') != review
                    or summary.get('namespace_apply_owner') != owner
                    or summary.get('namespace_apply_evidence') or summary.get('namespace_apply_marked')
                    or summary.get('mutation_started')):
                raise ValueError('namespace Apply evidence ownership changed')
            summary.update(namespace_apply_evidence=evidence, namespace_apply_expect=expectation)
            c.execute("UPDATE operation_runs SET summary=? WHERE id=?", (json.dumps(summary), operation_id))

    def mark_namespace_apply(self, operation_id, *, logical_key, evidence):
        """One commit: ordinary marker, Stage 2 marker and the logical-service fence.

        Caller holds update.lock and dispatches only after this returns.
        """
        now = _utc_now()
        stage = 'Recreating namespace consumer'
        with self.connect() as c:
            row, summary = self._namespace_apply_row(c, operation_id)
            if (row['status'] != 'running' or summary.get('namespace_apply_marked') or summary.get('mutation_started')
                    or summary.get('namespace_apply_evidence') != evidence
                    or summary.get('namespace_apply_logical_key') != logical_key):
                raise ValueError('namespace Apply evidence changed')
            if c.execute("SELECT 1 FROM compose_bootstrap_fences WHERE (logical_key=? OR logical_key LIKE 'unproven:%') "
                         "AND lifecycle IN ('active','manual')", (logical_key,)).fetchone():
                raise ValueError('namespace_apply_unresolved')
            summary.update(mutation_started=True, namespace_apply_marked=True,
                           namespace_apply_phase='apply_recreate_may_have_started')
            c.execute("INSERT INTO compose_bootstrap_fences VALUES(?,?,?,'active',?,?)",
                      (logical_key, operation_id, evidence, now, now))
            c.execute("UPDATE operation_runs SET summary=?,current_stage=? WHERE id=?",
                      (json.dumps(summary), stage, operation_id))
            self._insert_operation_event(c, operation_id, 'task_info', stage=stage, status='info',
                                         message='Recreation may have started. The namespace owner will not be changed.')

    def namespace_apply_operation(self, operation_id):
        """Presentation only: does this fence/evidence belong to namespace Apply?"""
        if not isinstance(operation_id, str) or not re.fullmatch('[0-9a-f]{32}', operation_id):
            return False
        try:
            with self.read() as c:
                row = c.execute("SELECT summary FROM operation_runs WHERE id=? AND kind='compose_reconcile'",
                                (operation_id,)).fetchone()
            if row:
                return json.loads(row[0]).get('namespace_apply') is not None
            from .compose_baseline import _read_private
            manifest = json.loads(_read_private(self.root / 'compose-recoveries' / operation_id / 'manifest.json', 256 * 1024))
            return isinstance(manifest, dict) and manifest.get('version') == 3
        except Exception:
            return False

    def namespace_apply_marker(self, operation_id):
        """Durable read-back: 'absent', 'committed' or 'unknown' (never guessed)."""
        try:
            with self.read() as c:
                row = c.execute("SELECT summary FROM operation_runs WHERE id=?", (operation_id,)).fetchone()
                fence = c.execute("SELECT lifecycle FROM compose_bootstrap_fences WHERE operation_id=?",
                                  (operation_id,)).fetchone()
            if not row:
                return 'unknown'
            summary = json.loads(row[0])
            marked = summary.get('namespace_apply_marked') is True or summary.get('mutation_started') is True
            if not marked and not fence:
                return 'absent'
            return 'committed' if marked and fence else 'unknown'
        except Exception:
            return 'unknown'

    def record_namespace_invocation(self, operation_id, record):
        from .system import INVOCATION_CATEGORIES
        if (not isinstance(record, dict) or set(record) != {'phase', 'category', 'code'}
                or record['phase'] not in {'apply', 'recovery'} or record['category'] not in INVOCATION_CATEGORIES
                or not (record['code'] is None or (type(record['code']) is int and -255 <= record['code'] <= 255))):
            raise ValueError('invalid invocation outcome')
        with self.connect() as c:
            row, summary = self._namespace_apply_row(c, operation_id)
            self._namespace_apply_fence(c, operation_id, summary)
            invocations = summary.setdefault('namespace_apply_invocations', [])
            if (row['status'] != 'running' or len(invocations) >= 2
                    or any(item.get('phase') == record['phase'] for item in invocations)
                    or (record['phase'] == 'recovery'
                        and summary.get('namespace_apply_phase') != 'recovery_recreate_may_have_started')):
                raise ValueError('invocation outcome is not expected')
            invocations.append(dict(record))
            c.execute("UPDATE operation_runs SET summary=? WHERE id=?", (json.dumps(summary), operation_id))
        return True

    def namespace_apply_phase(self, operation_id, phase, *, failure_class=None):
        previous = {'recovery_source_transition': 'apply_recreate_may_have_started',
                    'recovery_recreate_may_have_started': 'recovery_source_transition'}[phase]
        stage = {'recovery_source_transition': 'Restoring previous configuration sources',
                 'recovery_recreate_may_have_started': 'Recovering previous configuration once'}[phase]
        with self.connect() as c:
            row, summary = self._namespace_apply_row(c, operation_id)
            self._namespace_apply_fence(c, operation_id, summary)
            invocations = summary.get('namespace_apply_invocations') or []
            if row['status'] != 'running' or summary.get('namespace_apply_phase') != previous:
                raise ValueError('namespace Apply phase is not expected')
            if phase == 'recovery_source_transition':
                if (failure_class not in {'desired_unhealthy', 'desired_start_deadline'}
                        or invocations != [{'phase': 'apply', 'category': 'completed', 'code': 0}]):
                    raise ValueError('automatic recovery is not admitted')
                summary['namespace_apply_failure_class'] = failure_class
            else:
                summary['recovery_recreate_may_have_started'] = True
            summary['namespace_apply_phase'] = phase
            c.execute("UPDATE operation_runs SET summary=?,current_stage=? WHERE id=?",
                      (json.dumps(summary), stage, operation_id))
            self._insert_operation_event(c, operation_id, 'task_info', stage=stage, status='info',
                                         message=stage + '. The image and namespace owner are unchanged.')

    def publish_namespace_apply(self, operation_id, record, proof, *, recovered, requester, client_ip, user_agent,
                                evidence):
        """One commit publishes trust, terminal result, event, history, audit,
        completion digest, verification invalidation and fence resolution."""
        if set(record) != set(COMPOSE_BASELINE_COLUMNS):
            raise ValueError("invalid compose baseline record")
        now = _utc_now()
        phase = 'recovery' if recovered else 'apply'
        with self.connect() as c:
            row, summary = self._namespace_apply_row(c, operation_id)
            fence = self._namespace_apply_fence(c, operation_id, summary)
            invocations = {item.get('phase'): item for item in summary.get('namespace_apply_invocations') or []}
            expected = (summary.get('namespace_apply_expect') or {}).get('baseline' if recovered else 'desired')
            if (row['status'] != 'running' or row['requested_by'] != requester
                    or summary.get('namespace_apply_evidence') != evidence
                    or record['logical_key'] != fence['logical_key'] or record['origin'] != 'captured'
                    or record['stack'] != row['stack'] or record['compose_service'] != row['service']
                    or 'container/' + str(record['container_id']) == row['service_key']
                    or expected != [record['runtime_hash'], record['service_fingerprint'], record['inventory_fingerprint']]
                    or invocations.get(phase) != {'phase': phase, 'category': 'completed', 'code': 0}
                    or summary.get('namespace_apply_phase') != ('recovery_recreate_may_have_started' if recovered
                                                                else 'apply_recreate_may_have_started')
                    or (not recovered and set(invocations) != {'apply'})):
                raise ValueError('namespace Apply publication does not match')
            if c.execute("SELECT 1 FROM compose_bootstrap_fences WHERE operation_id!=? AND (logical_key=? OR logical_key "
                         "LIKE 'unproven:%') AND lifecycle IN ('active','manual')",
                         (operation_id, record['logical_key'])).fetchone():
                raise ValueError('namespace_apply_unresolved')
            c.execute(f"INSERT INTO compose_baselines({','.join(COMPOSE_BASELINE_COLUMNS)}) "
                      f"VALUES({','.join('?' for _ in COMPOSE_BASELINE_COLUMNS)})",
                      tuple(record[name] for name in COMPOSE_BASELINE_COLUMNS))
            new_key = 'container/' + record['container_id']
            result = {'action': 'apply', 'mutation_performed': True, 'recovered': bool(recovered),
                      'manual_recovery_required': False, 'namespace': True, 'image_unchanged': True,
                      'owner_unchanged': True, 'current_service_key': new_key}
            if not recovered:
                result['refresh_required'] = True
            for key in (row['service_key'], new_key):
                self._invalidate_verification(c, key)
            details = json.dumps({'origin': 'web', 'operation_id': operation_id, **result})
            history = c.execute(
                "INSERT INTO history(stack,service,action,result,rollback_result,details) VALUES(?,?,'compose_reconcile',?,?,?)",
                (row['stack'], row['service'], 'FAILED' if recovered else 'SUCCESS',
                 'AUTOMATIC RECOVERY SUCCEEDED' if recovered else None, details)).lastrowid
            result['history_id'] = history
            c.execute("INSERT INTO audit_events(timestamp,username,action,result,client_ip,user_agent,details) "
                      "VALUES(?,?,'web_compose_reconcile',?,?,?,?)",
                      (now, requester, 'recovered' if recovered else 'succeeded', client_ip, user_agent,
                       json.dumps({'operation_id': operation_id, 'service_key': row['service_key'], **result})))
            message = ('Apply failed — previous configuration recovered. Desired changes remain pending.' if recovered
                       else 'Configuration applied. The image and namespace owner are unchanged.')
            summary.update(new_baseline_id=record['id'], completion_proof=proof, namespace_apply_phase='published')
            status = 'failed' if recovered else 'succeeded'
            c.execute("UPDATE operation_runs SET status=?,finished_at=?,current_stage=?,error=?,summary=?,result=? WHERE id=?",
                      (status, now, message, message if recovered else None, json.dumps(summary),
                       json.dumps(result), operation_id))
            if not recovered:
                # The publication transaction is the durable record, so its stage
                # is committed with it, immediately before the terminal event.
                self._insert_operation_event(c, operation_id, 'task_completed', status='completed', message='Completed',
                                             stage=f'{RECONCILE_STAGE_TOTAL}/{RECONCILE_STAGE_TOTAL} Publish trusted baseline and result')
            self._insert_operation_event(c, operation_id, 'operation_failed' if recovered else 'operation_completed',
                                         stage=message, message=message, status=status, payload=result)
            c.execute("UPDATE compose_bootstrap_fences SET lifecycle='resolved',updated_at=? WHERE operation_id=?",
                      (now, operation_id))
        return result

    def namespace_apply_published(self, operation_id, baseline_id, *, recovered):
        """Read durable commit state after an ambiguous publication."""
        try:
            with self.read() as c:
                row = c.execute("SELECT status,summary FROM operation_runs WHERE id=? AND kind='compose_reconcile'",
                                (operation_id,)).fetchone()
                fence = c.execute("SELECT lifecycle FROM compose_bootstrap_fences WHERE operation_id=?",
                                  (operation_id,)).fetchone()
                trusted = c.execute("SELECT 1 FROM compose_baselines WHERE id=?", (baseline_id,)).fetchone()
            summary = json.loads(row['summary'])
            return bool(row['status'] == ('failed' if recovered else 'succeeded') and trusted and fence
                        and fence[0] == 'resolved' and summary.get('new_baseline_id') == baseline_id
                        and summary.get('namespace_apply_phase') == 'published')
        except Exception:
            return False

    def finish_namespace_apply(self, operation_id, *, reason='review_changed', client_ip=None, user_agent=None,
                               observation=None):
        """Terminal failure/block from durable state, never in-memory dispatch flags.

        Marked, fenced or unprovable operations are failed/manual and keep a
        manual fence; only a definitely unmarked operation with consistent
        evidence is a factual pre-mutation block.
        """
        now = _utc_now()
        with self.connect() as c:
            row = c.execute("SELECT * FROM operation_runs WHERE id=? AND kind='compose_reconcile'", (operation_id,)).fetchone()
            if not row or row['status'] in OPERATION_TERMINAL_STATUSES:
                return False
            try:
                summary = json.loads(row['summary'])
                uncertain = (summary.get('namespace_apply') != 3
                             or bool(summary.get('namespace_apply_marked') or summary.get('mutation_started')))
            except (ValueError, TypeError, AttributeError):
                summary, uncertain = {}, True
            fence = c.execute("SELECT * FROM compose_bootstrap_fences WHERE operation_id=?", (operation_id,)).fetchone()
            uncertain = uncertain or bool(fence)
            if not uncertain and row['status'] != 'queued' and summary.get('namespace_apply_evidence'):
                from .compose_recovery_retention import checked_bundle
                try:
                    with checked_bundle(self.root, self.root / 'compose-recoveries' / operation_id) as bundle:
                        if not bundle.get('namespace_apply') or bundle['fingerprint'] != summary['namespace_apply_evidence']:
                            uncertain = True
                except (OSError, ValueError, TypeError, RecursionError):
                    uncertain = True
            if uncertain:
                status, label = 'failed', 'manual'
                result = {'action': 'apply', 'mutation_performed': None, 'possible_mutation': True, 'recovered': False,
                          'manual_recovery_required': True, 'namespace': True}
                message = ('Apply failed or was interrupted — manual recovery required. Recreation may have occurred; '
                           'evidence was retained and further trust and mutation are fenced.')
                if not fence:
                    c.execute("INSERT INTO compose_bootstrap_fences VALUES(?,?,?,'manual',?,?)",
                              (summary.get('namespace_apply_logical_key') or 'unproven:' + operation_id, operation_id,
                               summary.get('namespace_apply_evidence') or 'unproven', now, now))
                c.execute("UPDATE compose_bootstrap_fences SET lifecycle='manual',updated_at=? WHERE operation_id=? "
                          "AND lifecycle='active'", (now, operation_id))
                if isinstance(observation, dict) and summary and len(json.dumps(observation)) <= 512:
                    # Private diagnostic facts only: never projected, never authority.
                    summary['namespace_apply_observation'] = observation
                    c.execute("UPDATE operation_runs SET summary=? WHERE id=?", (json.dumps(summary), operation_id))
            else:
                status, label = 'blocked', 'blocked'
                result = {'action': 'apply', 'mutation_performed': False, 'recovered': False,
                          'manual_recovery_required': False, 'namespace': True,
                          'blocked_reason': reason if isinstance(reason, str) and len(reason) <= 64 else 'review_changed'}
                message = 'Blocked — no workload changes. Review the configuration changes again.'
            details = {'origin': 'web', 'operation_id': operation_id, **result}
            history = c.execute(
                "INSERT INTO history(stack,service,action,result,rollback_result,details) VALUES(?,?,'compose_reconcile',?,?,?)",
                (row['stack'], row['service'], status.upper(), 'MANUAL RECOVERY REQUIRED' if uncertain else None,
                 json.dumps(details))).lastrowid
            result['history_id'] = history
            c.execute("INSERT INTO audit_events(timestamp,username,action,result,client_ip,user_agent,details) "
                      "VALUES(?,?,'web_compose_reconcile',?,?,?,?)",
                      (now, row['requested_by'], label, client_ip, user_agent,
                       json.dumps({**details, 'service_key': row['service_key']})))
            c.execute("UPDATE operation_runs SET status=?,finished_at=?,current_stage=?,error=?,result=? WHERE id=?",
                      (status, now, message, message, json.dumps(result), operation_id))
            self._insert_operation_event(c, operation_id, 'operation_failed' if uncertain else 'operation_blocked',
                                         stage=message, message=message, status=status, payload=result)
        return True

    # Trusted Compose baselines (metadata only; material lives on disk) -----
    def insert_compose_baseline(self, record: dict):
        if set(record) != set(COMPOSE_BASELINE_COLUMNS):
            raise ValueError("invalid compose baseline record")
        with self.connect() as c:
            if c.execute("SELECT 1 FROM compose_bootstrap_fences WHERE (logical_key=? OR logical_key LIKE 'unproven:%') AND lifecycle IN ('active','manual')", (record['logical_key'],)).fetchone():
                raise ValueError("bootstrap_unresolved")
            c.execute(
                f"INSERT INTO compose_baselines({','.join(COMPOSE_BASELINE_COLUMNS)}) "
                f"VALUES({','.join('?' for _ in COMPOSE_BASELINE_COLUMNS)})",
                tuple(record[name] for name in COMPOSE_BASELINE_COLUMNS),
            )

    def compose_baselines(self, logical_key: str):
        with self.read() as c:
            rows = c.execute(
                "SELECT * FROM compose_baselines WHERE logical_key=? ORDER BY captured_at DESC, rowid DESC",
                (logical_key,),
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_compose_baseline(self, baseline_id: str):
        with self.connect() as c:
            return c.execute("DELETE FROM compose_baselines WHERE id=?", (baseline_id,)).rowcount

    def compose_baseline_references(self):
        """Baseline IDs named by retained operation records; never pruned."""
        referenced = set()
        with self.read() as c:
            rows = c.execute(
                "SELECT summary,result FROM operation_runs WHERE summary LIKE '%baseline_id%' OR result LIKE '%baseline_id%'"
            ).fetchall()
        for row in rows:
            for value in (row["summary"], row["result"]):
                try:
                    data = json.loads(value or "{}")
                except (TypeError, ValueError):
                    continue
                if isinstance(data, dict):
                    for name in ("baseline_id", "new_baseline_id"):
                        if isinstance(data.get(name), str):
                            referenced.add(data[name])
        return referenced | self._unresolved_namespace_evidence_baselines()

    def _unresolved_namespace_evidence_baselines(self):
        """Validated unresolved v3 evidence protects its baseline even without replay rows."""
        from .compose_recovery_retention import checked_bundle, lifecycle
        root = self.root / 'compose-recoveries'
        if root.is_symlink() or not root.is_dir():
            return set()
        referenced = set()
        with self.read() as c:
            for path in root.glob('*'):
                try:
                    with checked_bundle(self.root, path) as bundle:
                        if bundle.get('namespace_apply') and lifecycle(c, path.name, bundle)[0] != 'terminal':
                            referenced.add(bundle['baseline_id'])
                except (OSError, ValueError, TypeError, RecursionError):
                    continue
        return referenced

    def retain_compose_operation_baseline(self, operation_id, baseline_id):
        with self.connect() as c:
            row = c.execute("SELECT summary FROM operation_runs WHERE id=? AND kind='compose_reconcile'",
                            (operation_id,)).fetchone()
            if not row:
                raise ValueError("configuration operation is unavailable")
            summary = json.loads(row[0])
            summary["new_baseline_id"] = baseline_id
            c.execute("UPDATE operation_runs SET summary=? WHERE id=?", (json.dumps(summary), operation_id))

    def mark_compose_mutation_started(self, operation_id):
        """Persist an interruption safety marker immediately before invocation."""
        with self.connect() as c:
            row = c.execute("SELECT summary FROM operation_runs WHERE id=? AND kind='compose_reconcile' AND status='running'",
                            (operation_id,)).fetchone()
            if not row:
                raise ValueError("configuration operation is not active")
            summary = json.loads(row[0])
            summary["mutation_started"] = True
            c.execute("UPDATE operation_runs SET summary=? WHERE id=?", (json.dumps(summary), operation_id))

    def operation_status(self, operation_id: str, after_event_id: int = 0):
        try:
            after_event_id = max(0, min(int(after_event_id), 2**63 - 1))
        except (TypeError, ValueError):
            after_event_id = 0
        with self.read() as c:
            row = c.execute("SELECT * FROM operation_runs WHERE id=?", (operation_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            for name in ("summary", "result"):
                try:
                    item[name] = json.loads(item.get(name) or "{}")
                except (TypeError, json.JSONDecodeError):
                    item[name] = {}
            events = []
            for event in c.execute(
                "SELECT * FROM operation_events WHERE operation_id=? AND id>? ORDER BY id",
                (operation_id, after_event_id),
            ):
                value = dict(event)
                try:
                    value["payload"] = json.loads(value.get("payload") or "{}")
                except (TypeError, json.JSONDecodeError):
                    value["payload"] = {}
                events.append(value)
            last = c.execute(
                "SELECT MAX(id) FROM operation_events WHERE operation_id=?", (operation_id,)
            ).fetchone()[0]
            item["events"] = events
            item["last_event_id"] = int(last or 0)
            return item

    # Cached read-only scan persistence -----------------------------------
    def start_scan(self, run_id: str, total: int = 0):
        with self.connect() as c:
            now = _utc_now()
            c.execute("INSERT INTO scan_runs(id,started_at,heartbeat_at,status,total) VALUES(?,?,?,?,?)", (run_id, now, now, "running", int(total)))

    def set_scan_total(self, run_id: str, total: int):
        """Persist the discovered work count before publishing discovery completion."""
        total = max(0, int(total))
        with self.connect() as c:
            updated = c.execute(
                "UPDATE scan_runs SET total=?,completed=MIN(completed,?),heartbeat_at=? "
                "WHERE id=? AND status='running'",
                (total, total, _utc_now(), run_id),
            ).rowcount
            if updated != 1:
                raise RuntimeError("scan no longer owns the active lease")

    def scan_event(self, run_id: str, kind: str, *, service=None, status=None, message=None, payload=None, completed=None):
        event_payload = dict(payload) if isinstance(payload, dict) else {}
        if completed is not None:
            # Keep the authoritative cumulative count with the persisted event
            # so SSE replay and a fresh page use the same run-state value.
            completed = max(0, int(completed))
            event_payload["completed"] = completed
        with self.connect() as c:
            c.execute("INSERT INTO scan_events(run_id,timestamp,kind,service,status,message,payload) VALUES(?,?,?,?,?,?,?)", (run_id, _utc_now(), kind, service, status, message, json.dumps(event_payload, separators=(",", ":"))))
            c.execute("UPDATE scan_runs SET heartbeat_at=? WHERE id=? AND status IN ('running','finalizing')", (_utc_now(), run_id))
            if completed is not None:
                c.execute("UPDATE scan_runs SET completed=MAX(completed,?) WHERE id=? AND status IN ('running','finalizing')", (completed, run_id))

    def touch_scan(self, run_id: str):
        """Refresh the lease while bounded finalisation is still executing."""
        with self.connect() as c:
            c.execute("UPDATE scan_runs SET heartbeat_at=? WHERE id=? AND status='finalizing'", (_utc_now(), run_id))

    def finish_scan(self, run_id: str, status: str, *, error: str | None = None, services: list[dict] | None = None):
        """Compatibility helper for direct callers; the worker uses staged finalisation.

        The scan worker records each service's verification as that service's
        check completes. Direct callers have no per-service completion points,
        so their results are recorded here, before the snapshot is staged.
        """
        if services and self.supports_service_verification:
            with self.connect() as c:
                checked_at = _utc_now()
                run = c.execute("SELECT started_at FROM scan_runs WHERE id=?", (run_id,)).fetchone()
                for item in services:
                    self._save_verification(c, item, checked_at, started_at=run[0] if run else None)
                self._prune_verifications(c)
        self.stage_scan_result(run_id, status, error=error, services=services)
        self.mark_scan_terminal(run_id, status, emit_event=False)

    def stage_scan_result(self, run_id: str, status: str, *, error: str | None = None, services: list[dict] | None = None):
        """Persist result data without making the scan externally terminal.

        Partial and failed attempts remain queryable through scan_runs and
        service_snapshots, but cannot replace the last complete trustworthy
        service inventory or its captured-at timestamp.
        """
        captured = _utc_now()
        with self.connect() as c:
            updated = c.execute(
                "UPDATE scan_runs SET heartbeat_at=?,status='finalizing',error=?,completed=CASE WHEN ? IN ('complete','partial') THEN total ELSE completed END WHERE id=? AND status='running'",
                (captured, error, status, run_id),
            ).rowcount
            if updated != 1:
                raise RuntimeError("scan no longer owns the active lease")
            if services is not None:
                c.execute("DELETE FROM service_snapshots WHERE scan_id=?", (run_id,))
                seen_keys: dict[str, int] = {}
                used_keys: set[str] = set()
                for index, item in enumerate(services):
                    svc = item.get("service") or {}
                    base_key = str(svc.get("key") or svc.get("name") or f"service-{index}")
                    occurrence = seen_keys.get(base_key, 0)
                    key = base_key if occurrence == 0 else f"{base_key}#{occurrence + 1}"
                    while key in used_keys:
                        occurrence += 1
                        key = f"{base_key}#{occurrence + 1}"
                    seen_keys[base_key] = occurrence + 1
                    used_keys.add(key)
                    c.execute("INSERT INTO service_snapshots(scan_id,service_key,stack,service,payload) VALUES(?,?,?,?,?)", (run_id, key, svc.get("stack"), svc.get("compose_service") or svc.get("name") or key, json.dumps(item, separators=(",", ":"))))
                if status == "complete":
                    payload = {"services": services, "count": len(services)}
                    c.execute(
                        "INSERT INTO latest_scan(singleton,scan_id,started_at,finished_at,status,payload) "
                        "SELECT 1,id,started_at,?,'complete',? FROM scan_runs WHERE id=? "
                        "ON CONFLICT(singleton) DO UPDATE SET scan_id=excluded.scan_id,started_at=excluded.started_at,"
                        "finished_at=excluded.finished_at,status='complete',payload=excluded.payload",
                        (captured, json.dumps(payload, separators=(",", ":")), run_id),
                    )

    @staticmethod
    def _prune_verifications(c):
        # The latest historical inventory may outlive the cache retention. Keep
        # its invalidations so pruning cannot resurrect pre-mutation UPDATE facts.
        unprotected = ("NOT (checked_at IS NULL AND service_key IN "
                       "(SELECT 'container/' || json_extract(payload,'$.service.container_id') "
                       "FROM service_snapshots WHERE scan_id=(SELECT scan_id FROM latest_scan WHERE singleton=1) "
                       "AND json_extract(payload,'$.service.container_id') IS NOT NULL))")
        c.execute("DELETE FROM service_verifications WHERE " + unprotected +
                  " AND julianday(COALESCE(checked_at,failed_at)) < julianday('now','-30 days')")
        c.execute("DELETE FROM service_verifications WHERE service_key IN "
                  "(SELECT service_key FROM service_verifications WHERE " + unprotected +
                  " ORDER BY COALESCE(checked_at,failed_at) DESC LIMIT -1 OFFSET 2048)")

    @staticmethod
    def _save_verification(c, item: dict, checked_at: str, *, started_at: str | None = None):
        service = item.get("service") or {}
        key = service.get("key")
        container_id = service.get("container_id")
        if (not isinstance(key, str) or not isinstance(container_id, str)
                or key != f"container/{container_id}" or len(container_id) != 64
                or any(char not in "0123456789abcdef" for char in container_id)):
            return
        identity = verification_identity(service)
        status = item.get("status")
        old = c.execute("SELECT identity,verification_id,checked_at,failed_at,payload FROM service_verifications WHERE service_key=?", (key,)).fetchone()
        # Evidence is ordered by the time its check completed. A result older
        # than the newest recorded success or failure for this container is
        # discarded, so late or replayed results cannot replace newer evidence.
        incoming = _parse_timestamp(checked_at)
        if incoming is None:
            return
        if old:
            newest = [value for value in (_parse_timestamp(old["checked_at"]), _parse_timestamp(old["failed_at"])) if value]
            if newest and max(newest) > incoming:
                return
            started = _parse_timestamp(started_at)
            if started and newest and max(newest) > started:
                return
        if status in {"REGISTRY ERROR", "UNKNOWN"}:
            if old and old["identity"] == identity:
                previous = json.loads(old["payload"]) if old["payload"] else None
                token = None if previous and previous.get("status") == "CHECK REQUIRED" else secrets.token_urlsafe(24)
                c.execute("UPDATE service_verifications SET verification_id=?,failed_at=?,error=? WHERE service_key=?",
                          (token, checked_at, item.get("error") or "registry query failed", key))
            else:
                c.execute("INSERT OR REPLACE INTO service_verifications(service_key,identity,failed_at,error) VALUES(?,?,?,?)",
                          (key, identity, checked_at, item.get("error") or "registry query failed"))
            return
        payload = json.dumps(item, separators=(",", ":"))
        old_result = json.loads(old["payload"]) if old and old["payload"] else None
        fields = ("status", "remote_digest", "remote_version", "remote_created", "target_image", "tracking_tag")
        same = (old and old["identity"] == identity and old_result
                and all(old_result.get(field) == item.get(field) for field in fields))
        verification_id = old["verification_id"] if same else secrets.token_urlsafe(24)
        c.execute("INSERT INTO service_verifications(service_key,identity,verification_id,checked_at,payload,failed_at,error) "
                  "VALUES(?,?,?,?,?,NULL,NULL) ON CONFLICT(service_key) DO UPDATE SET "
                  "identity=excluded.identity,verification_id=excluded.verification_id,checked_at=excluded.checked_at,"
                  "payload=excluded.payload,failed_at=NULL,error=NULL",
                  (key, identity, verification_id, checked_at, payload))

    def save_verification(self, item: dict, checked_at: str | None = None, *, started_at: str | None = None):
        with self.connect() as c:
            self._save_verification(c, item, checked_at or _utc_now(), started_at=started_at)
            self._prune_verifications(c)

    def invalidate_verification(self, service_key: str):
        """Recreation makes the old container-bound evidence unusable."""
        with self.connect() as c:
            self._invalidate_verification(c, service_key)

    @staticmethod
    def _invalidate_verification(c, service_key, service=None):
        payload = json.dumps({"service": service, "status": "CHECK REQUIRED"}, separators=(",", ":")) if service else None
        c.execute("INSERT INTO service_verifications(service_key,identity,verification_id,failed_at,error,payload) "
                  "VALUES(?,?,NULL,?,?,?) ON CONFLICT(service_key) DO UPDATE SET identity=excluded.identity,"
                  "verification_id=NULL,checked_at=NULL,failed_at=excluded.failed_at,error=excluded.error,payload=excluded.payload",
                  (service_key, verification_identity(service or {}), _utc_now(), VERIFICATION_INVALIDATED, payload))

    def reconcile_runtime(self, previous_key, containers, *, current_service=None, candidate_services=(), attempted_at):
        """Publish current read-state without touching completed scans or trust."""
        with self.connect() as c:
            self._invalidate_verification(c, previous_key)
            if current_service:
                self._invalidate_verification(c, current_service["key"], current_service)
            for service in candidate_services:
                self._invalidate_verification(c, service["key"], service)
            self._save_runtime_snapshot(c, containers, captured_at=_utc_now(), attempted_at=attempted_at)

    def verification_snapshot(self):
        with self.read() as c:
            rows = c.execute("SELECT * FROM service_verifications").fetchall()
        result = []
        for row in rows:
            try:
                payload = json.loads(row["payload"]) if row["payload"] else None
            except (TypeError, ValueError):
                payload = None
            result.append({"service_key": row["service_key"], "identity": row["identity"],
                           "verification_id": row["verification_id"], "checked_at": row["checked_at"],
                           "result": payload, "failed_at": row["failed_at"], "error": row["error"],
                           "invalidated": row["error"] == VERIFICATION_INVALIDATED})
        return result

    def mark_scan_terminal(self, run_id: str, status: str, *, emit_event: bool = True, message: str | None = None):
        if status not in {"complete", "partial", "failed"}:
            raise ValueError("invalid scan terminal status")
        finished = _utc_now()
        with self.connect() as c:
            if emit_event:
                c.execute(
                    "INSERT INTO scan_events(run_id,timestamp,kind,status,message,payload) VALUES(?,?,?,?,?,?)",
                    (run_id, finished, "operation_failed" if status == "failed" else "operation_completed",
                     status, message or ("Scan failed" if status == "failed" else "Scan completed"), "{}"),
                )
            updated = c.execute(
                "UPDATE scan_runs SET finished_at=?,heartbeat_at=?,status=? WHERE id=? AND status='finalizing'",
                (finished, finished, status, run_id),
            ).rowcount
            if updated != 1:
                raise RuntimeError("scan is not awaiting finalisation")

    def add_scan_maintenance_warning(self, run_id: str, warning: str):
        """Record bounded post-scan housekeeping warnings without changing scan truth."""
        clean = " ".join(str(warning).split())[:240]
        if not clean:
            return
        with self.connect() as c:
            row = c.execute("SELECT maintenance_warning FROM scan_runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                return
            previous = row[0] or ""
            values = [item for item in previous.split(" | ") if item]
            if clean not in values:
                values.append(clean)
            c.execute("UPDATE scan_runs SET maintenance_warning=? WHERE id=?", (" | ".join(values)[:1000], run_id))

    def latest_scan(self):
        with self.read() as c:
            row = c.execute("SELECT * FROM latest_scan WHERE singleton=1").fetchone()
            if not row:
                return None
            item = dict(row)
            try:
                item["payload"] = json.loads(item["payload"])
            except json.JSONDecodeError:
                item["payload"] = {}
            return item

    def save_runtime_snapshot(self, containers, *, captured_at=None, attempted_at=None):
        """Atomically replace the one successful safe runtime snapshot."""
        from .runtime import utc_now

        captured_at = captured_at or utc_now()
        attempted_at = attempted_at or captured_at
        with self.connect() as c:
            self._save_runtime_snapshot(c, containers, captured_at=captured_at, attempted_at=attempted_at)

    @staticmethod
    def _save_runtime_snapshot(c, containers, *, captured_at, attempted_at):
        from .runtime import RUNTIME_CONTAINER_FIELDS, public_runtime_container
        previous = c.execute("SELECT attempted_at FROM runtime_snapshot WHERE singleton=1").fetchone()
        incoming = _parse_timestamp(attempted_at)
        if previous and incoming and (_parse_timestamp(previous[0]) or datetime.min.replace(tzinfo=timezone.utc)) > incoming:
            return
        safe = []
        for container in containers if isinstance(containers, list) else []:
            item = public_runtime_container(container)
            if item:
                safe.append({key: item.get(key) for key in RUNTIME_CONTAINER_FIELDS})
        payload = json.dumps({"containers": safe}, separators=(",", ":"))
        c.execute(
            "INSERT INTO runtime_snapshot(singleton,captured_at,attempted_at,attempt_success,failure_category,payload) "
            "VALUES(1,?,?,1,NULL,?) ON CONFLICT(singleton) DO UPDATE SET "
            "captured_at=excluded.captured_at,attempted_at=excluded.attempted_at,"
            "attempt_success=1,failure_category=NULL,payload=excluded.payload",
            (captured_at, attempted_at, payload),
        )

    def record_runtime_failure(self, *, attempted_at=None, failure_category="docker_unavailable"):
        """Record a failed attempt while retaining the last successful payload."""
        from .runtime import utc_now

        categories = {"docker_unavailable", "container_limit_exceeded", "invalid_docker_response", "inventory_changed", "probe_failed"}
        if failure_category not in categories:
            failure_category = "probe_failed"
        attempted_at = attempted_at or utc_now()
        with self.connect() as c:
            previous = c.execute("SELECT attempted_at FROM runtime_snapshot WHERE singleton=1").fetchone()
            incoming = _parse_timestamp(attempted_at)
            if previous and incoming and (_parse_timestamp(previous[0]) or datetime.min.replace(tzinfo=timezone.utc)) > incoming:
                return
            c.execute(
                "INSERT INTO runtime_snapshot(singleton,captured_at,attempted_at,attempt_success,failure_category,payload) "
                "VALUES(1,NULL,?,0,?,NULL) ON CONFLICT(singleton) DO UPDATE SET "
                "attempted_at=excluded.attempted_at,attempt_success=0,failure_category=excluded.failure_category",
                (attempted_at, failure_category),
            )

    def runtime_snapshot(self, *, now=None, stale_after_seconds=90):
        """Return bounded persisted runtime data with computed freshness."""
        from datetime import datetime, timezone
        from .runtime import RUNTIME_CONTAINER_FIELDS, public_runtime_container, utc_now

        with self.read() as c:
            row = c.execute("SELECT * FROM runtime_snapshot WHERE singleton=1").fetchone()
        if not row:
            return {
                "status": "never", "available": False, "stale": False,
                "captured_at": None, "last_success_at": None, "attempted_at": None,
                "attempt_success": None, "failure_category": None, "containers": [],
            }
        captured_at = row["captured_at"]
        attempted_at = row["attempted_at"]
        try:
            payload = json.loads(row["payload"] or "{}")
        except (TypeError, json.JSONDecodeError):
            payload = {}
        containers = []
        values = payload.get("containers", []) if isinstance(payload, dict) else []
        for container in values if isinstance(values, list) else []:
            safe = public_runtime_container(container)
            if safe:
                containers.append({key: safe.get(key) for key in RUNTIME_CONTAINER_FIELDS})

        attempt_success = bool(row["attempt_success"])
        stale = False
        if captured_at:
            try:
                current = datetime.fromisoformat((now or utc_now()).replace("Z", "+00:00"))
                captured = datetime.fromisoformat(captured_at.replace("Z", "+00:00"))
                if current.tzinfo is None:
                    current = current.replace(tzinfo=timezone.utc)
                if captured.tzinfo is None:
                    captured = captured.replace(tzinfo=timezone.utc)
                stale = (current - captured).total_seconds() > max(1, int(stale_after_seconds))
            except (AttributeError, TypeError, ValueError):
                stale = True
        if not attempt_success or stale:
            stale = bool(captured_at)
        status = "unavailable" if not attempt_success else ("stale" if stale else "current")
        return {
            "status": status,
            "available": status == "current",
            "stale": stale,
            "captured_at": captured_at,
            "last_success_at": captured_at,
            "attempted_at": attempted_at,
            "attempt_success": attempt_success,
            "failure_category": row["failure_category"],
            "containers": containers,
        }

    def scan_run(self, run_id: str, after_event_id: int = 0):
        with self.read() as c:
            row = c.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            events = []
            for event in c.execute("SELECT * FROM scan_events WHERE run_id=? AND id>? ORDER BY id", (run_id, max(0, int(after_event_id)))):
                ev = dict(event)
                try:
                    ev["payload"] = json.loads(ev.get("payload") or "{}")
                except json.JSONDecodeError:
                    ev["payload"] = {}
                events.append(ev)
            item["events"] = events
            return item

    def scan_run_summary(self, run_id: str | None = None, event_limit: int = 6):
        """Return one scan attempt and a bounded event tail for page reattach."""
        with self.read() as c:
            if run_id:
                row = c.execute("SELECT * FROM scan_runs WHERE id=?", (run_id,)).fetchone()
            else:
                row = c.execute("SELECT * FROM scan_runs ORDER BY rowid DESC LIMIT 1").fetchone()
            if not row:
                return None
            item = dict(row)
            limit = max(1, min(20, int(event_limit)))
            rows = list(c.execute(
                "SELECT * FROM scan_events WHERE run_id=? ORDER BY id DESC LIMIT ?",
                (item["id"], limit),
            ))
            events = []
            for event in reversed(rows):
                value = dict(event)
                try:
                    value["payload"] = json.loads(value.get("payload") or "{}")
                except json.JSONDecodeError:
                    value["payload"] = {}
                events.append(value)
            item["events"] = events
            item["last_event_id"] = events[-1]["id"] if events else 0
            if item["status"] == "partial":
                item["diagnostics"] = [
                    {"service": event["service"] or "Service", "status": event["status"] or "UNKNOWN",
                     "message": event["message"] or "Result could not be verified"}
                    for event in c.execute(
                        "SELECT service,status,message FROM scan_events WHERE run_id=? "
                        "AND kind IN ('task_failed','task_completed') AND status IN ('REGISTRY ERROR','UNKNOWN') "
                        "ORDER BY id DESC LIMIT 5", (item["id"],)
                    )
                ]
            return item

    def latest_scan_run(self, event_limit: int = 6):
        """Return the newest scan attempt and a bounded event tail for reattach."""
        return self.scan_run_summary(event_limit=event_limit)

    def claim_scan(self, run_id: str, stale_after_seconds: int = 600):
        now = datetime.now(timezone.utc)
        with self.connect() as c:
            rows = c.execute("SELECT * FROM scan_runs WHERE status IN ('running','finalizing') ORDER BY started_at DESC").fetchall()
            for row in rows:
                try: started = datetime.fromisoformat(row["heartbeat_at"] or row["started_at"])
                except (TypeError, ValueError): started = now
                if (now - started).total_seconds() > stale_after_seconds:
                    if self._scan_worker_is_live():
                        return {"run_id": row["id"], "status": row["status"], "existing": True}
                    c.execute("UPDATE scan_runs SET status='failed',finished_at=?,error=? WHERE id=?", (_utc_now(), "scan lease expired after agent restart", row["id"]))
                else:
                    return {"run_id": row["id"], "status": row["status"], "existing": True}
            now_text = _utc_now()
            c.execute("INSERT INTO scan_runs(id,started_at,heartbeat_at,status,total) VALUES(?,?,?,?,?)", (run_id, now_text, now_text, "running", 0))
            return {"run_id": run_id, "status": "running", "existing": False}

    def recover_stale_scans(self, stale_after_seconds: int = 600):
        now = datetime.now(timezone.utc); recovered = 0
        with self.connect() as c:
            rows = c.execute("SELECT id,started_at,heartbeat_at FROM scan_runs WHERE status IN ('running','finalizing')").fetchall()
            for row in rows:
                try: started = datetime.fromisoformat(row["heartbeat_at"] or row["started_at"])
                except (TypeError, ValueError): continue
                if (now - started).total_seconds() > stale_after_seconds:
                    if self._scan_worker_is_live():
                        continue
                    c.execute("UPDATE scan_runs SET status='failed',finished_at=?,error=? WHERE id=?", (_utc_now(), "scan lease expired after agent restart", row["id"]))
                    recovered += 1
        return recovered

    def active_scan(self):
        with self.read() as c:
            row = c.execute("SELECT * FROM scan_runs WHERE status IN ('running','finalizing') ORDER BY started_at DESC LIMIT 1").fetchone()
            return dict(row) if row else None

    def web_prune(self, audit_days=365, scan_days=30):
        with self.connect() as c:
            if self.supports_service_verification:
                self._prune_verifications(c)
            c.execute("DELETE FROM audit_events WHERE timestamp < datetime('now', ?)", (f"-{int(audit_days)} days",))
            c.execute("DELETE FROM scan_events WHERE timestamp < datetime('now', ?)", (f"-{int(scan_days)} days",))
            c.execute("DELETE FROM scan_runs WHERE status NOT IN ('running','finalizing') AND started_at < datetime('now', ?) AND id NOT IN (SELECT scan_id FROM latest_scan)", (f"-{int(scan_days)} days",))
