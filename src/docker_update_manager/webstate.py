from __future__ import annotations

import os
from pathlib import Path

from .state import State, WEB_SCHEMA

WEB_SCHEMA_VERSION = 4

MANAGED_WEB_ROOT = Path("/var/lib/docker-update-manager-web")


def validate_web_root(root: Path) -> Path:
    """Validate a web state directory without creating any filesystem entry."""
    root = Path(root)
    if not root.is_absolute():
        raise ValueError("web state directory must be an absolute local path")
    resolved = root.resolve(strict=False)
    managed = MANAGED_WEB_ROOT.resolve(strict=False)
    test_path = os.getenv("UPT_TESTING") == "1" and str(resolved).startswith("/tmp/")
    if (resolved == Path("/") or resolved.parent == resolved or
            (resolved != managed and not str(resolved).startswith(str(managed) + "/") and not test_path)):
        raise ValueError("web state directory must be under /var/lib/docker-update-manager-web")
    current = root
    while True:
        if current.exists() and current.is_symlink():
            raise ValueError("web state directory cannot contain symlinks")
        if current == current.parent:
            break
        current = current.parent
    return root


def _reject_unsafe_file(path: Path, root: Path) -> None:
    """Refuse symlinked or escaping state files before they are opened."""
    if path.is_symlink():
        raise ValueError(f"refusing symlinked web state file: {path}")
    if not path.exists():
        return
    resolved_root = Path(root).resolve(strict=False)
    resolved = path.resolve(strict=False)
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise ValueError(f"web state file escapes the managed directory: {path}")
    if not path.is_file():
        raise ValueError(f"refusing unsafe web state file: {path}")


def validate_web_files(root: Path) -> Path:
    """Validate the state root and every file UPT will open inside it."""
    root = validate_web_root(root)
    db_path = Path(root) / "history.sqlite3"
    for candidate in (db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm"), Path(root) / "web.lock"):
        _reject_unsafe_file(candidate, root)
    return root


class WebState(State):
    """Web-owned SQLite state; deliberately contains no Docker/history tables."""
    supports_service_verification = False
    core_schema_identity = None

    def _new_connection(self):
        # Validate before the open, then re-check the file SQLite created so a
        # swapped path cannot redirect reads or writes outside the managed tree.
        validate_web_files(self.root)
        connection = super()._new_connection()
        try:
            _reject_unsafe_file(self.db_path, self.root)
        except BaseException:
            connection.close()
            raise
        return connection

    @classmethod
    def _migrate(cls, c):
        c.execute("CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL)")
        row = c.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        version = int(row[0]) if row else 0
        if version < 2:
            cls._exec_schema(c, WEB_SCHEMA)
            version = 2
        if version < 3:
            columns = {row[1] for row in c.execute("PRAGMA table_info(scan_runs)")}
            if "heartbeat_at" not in columns:
                c.execute("ALTER TABLE scan_runs ADD COLUMN heartbeat_at TEXT")
            c.execute("UPDATE scan_runs SET heartbeat_at=COALESCE(heartbeat_at, started_at)")
            version = 3
        if version < 4:
            cls._migrate_scan_warnings_and_snapshot(c)
            version = 4
        if version != 0:
            c.execute("DELETE FROM schema_version")
            c.execute("INSERT INTO schema_version(version) VALUES(?)", (version,))
        if version > WEB_SCHEMA_VERSION:
            raise RuntimeError(f"unsupported web state database schema version {version}")
