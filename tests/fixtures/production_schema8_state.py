from __future__ import annotations


import json


import fcntl


import os


import secrets


import sqlite3


import threading


from contextlib import contextmanager


from datetime import datetime, timezone


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


CORE_SCHEMA_VERSION = 8


CURRENT_SCHEMA_VERSION = CORE_SCHEMA_VERSION  # Compatibility for existing consumers.


OPERATION_EVENT_LIMIT = 200


OPERATION_HISTORY_LIMIT = 500


OPERATION_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "blocked"})


COMPOSE_BASELINE_COLUMNS = (
    "id", "logical_key", "stack", "compose_service", "container_id", "runtime_hash",
    "project_fingerprint", "service_fingerprint", "inventory_fingerprint", "fingerprint",
    "origin", "captured_at", "manifest",
)


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
    def __init__(self, root: Path):
        self.root = Path(root)
        self.db_path = self.root / "history.sqlite3"
        self._schema_lock = threading.Lock()
        self._schema_ready = False


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


    def _ensure_schema(self):
        """Run ordered migrations once per State instance, never on each query."""
        if self._schema_ready:
            return
        with self._schema_lock:
            if self._schema_ready:
                return
            connection = self._new_connection()
            try:
                # WAL is configured before the migration transaction. Normal
                # reads then use deferred read transactions and never reserve
                # the single SQLite writer slot.
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("BEGIN IMMEDIATE")
                self._migrate(connection)
                connection.commit()
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(str(self.db_path) + suffix)
                    try:
                        os.chmod(sidecar, 0o600)
                    except FileNotFoundError:
                        pass
                self._schema_ready = True
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()


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
    def read(self):
        """Open a consistent read transaction without a writer reservation."""
        self._ensure_schema()
        c = self._new_connection()
        try:
            c.execute("BEGIN")
            yield c
        finally:
            c.rollback()
            c.close()


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


    def record(self, **kw):
        keys = list(kw)
        vals = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in kw.values()]
        with self.connect() as c:
            q = f"INSERT INTO history ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})"
            cur = c.execute(q, vals)
            if kw.get("old_image_id") and kw.get("result") != "BLOCKED":
                c.execute("INSERT OR REPLACE INTO protected_images(image_id,reason,history_id) VALUES(?,?,?)", (kw["old_image_id"], "rollback", cur.lastrowid))
                c.execute("INSERT OR REPLACE INTO rollback_refs(history_id,image_id) VALUES(?,?)", (cur.lastrowid, kw["old_image_id"]))
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


    def protected(self):
        if not self.db_path.exists():
            return set()
        with self.read() as c:
            return {x[0] for x in c.execute("SELECT image_id FROM protected_images")}


    @staticmethod
    def _prune_verifications(c):
        c.execute("DELETE FROM service_verifications WHERE julianday(COALESCE(checked_at,failed_at)) < julianday('now','-30 days')")
        c.execute("DELETE FROM service_verifications WHERE service_key IN "
                  "(SELECT service_key FROM service_verifications ORDER BY COALESCE(checked_at,failed_at) DESC LIMIT -1 OFFSET 2048)")


    @staticmethod
    def _save_verification(c, item: dict, checked_at: str):
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
        if status in {"REGISTRY ERROR", "UNKNOWN"}:
            if old and old["identity"] == identity:
                c.execute("UPDATE service_verifications SET verification_id=?,failed_at=?,error=? WHERE service_key=?",
                          (secrets.token_urlsafe(24), checked_at, item.get("error") or "registry query failed", key))
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

    def prune_operations(self, retention_days: int = 30, limit: int = OPERATION_HISTORY_LIMIT):
        """Keep operation replay state bounded without deleting active work."""
        retention_days = max(1, min(int(retention_days), 3650))
        limit = max(20, min(int(limit), 5000))
        with self.connect() as c:
            c.execute(
                "DELETE FROM operation_runs WHERE status IN ('succeeded','failed','blocked') "
                "AND julianday(COALESCE(finished_at,created_at)) < julianday('now', ?)",
                (f"-{retention_days} days",),
            )
            c.execute(
                "DELETE FROM operation_runs WHERE id IN (SELECT id FROM operation_runs "
                "WHERE status IN ('succeeded','failed','blocked') ORDER BY created_at DESC "
                "LIMIT -1 OFFSET ?)",
                (limit,),
            )
