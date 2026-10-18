"""Offline schema transitions and explicitly confirmed binary-rollback recovery.

Stop all UPT admission/processes (including scheduled CLI invocations) before
calling this tool. update.lock serialises the transition but cannot by itself
prove that an old binary is quiescent. No Docker commands are invoked.

Actions:
  upgrade                 schema 8 to 9 (unchanged), retaining a schema-8 snapshot
  restore-schema8-backup  schema 9 only; explicitly discards post-upgrade state
  upgrade-schema10        schema 9 to 10 (G2 completion fences), retaining a
                          validated schema-9 snapshot; never discards state
  downgrade-schema9       always refused: no state-preserving 10 to 9 exists
"""
from __future__ import annotations
import argparse
import hashlib
import os
import sqlite3
import tempfile
from contextlib import ExitStack, closing
from pathlib import Path

from . import completion_fence
from .compose_baseline import _read_private, _write_private
from .lock import Lock
from .state import CORE_SCHEMA_VERSION, SCHEMA9_VERSION, State

SCHEMA10_SNAPSHOT = 'schema9-before10.sqlite3'
_ACTIVE_OPERATION = "SELECT 1 FROM operation_runs WHERE status IN ('queued','running','finalizing')"


def _version(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('state backup is unavailable or unsafe')
    with sqlite3.connect(f'file:{path}?mode=ro', uri=True) as c:
        if c.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('state integrity check failed')
        return int(c.execute('SELECT version FROM schema_version LIMIT 1').fetchone()[0])


def _digest(path):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as source:
        while True:
            part = source.read(256*1024)
            if not part:
                return digest.hexdigest()
            digest.update(part)


def _snapshot(source, target):
    if target.exists() or target.is_symlink():
        raise ValueError('a retained transition snapshot already exists; preserve and review it')
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    try:
        with sqlite3.connect(f'file:{source}?mode=ro', uri=True) as src, sqlite3.connect(target) as dst:
            src.backup(dst)
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _write_private(target.with_suffix('.sha256'), _digest(target).encode())
        fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        # An incomplete snapshot is deliberately retained and never trusted.
        raise


def transition(root, *, rollback=False, confirm_quiescent=False, confirm_state_loss=False):
    if not confirm_quiescent or rollback and not confirm_state_loss:
        raise ValueError('explicit offline quiescence confirmation and rollback state-loss acknowledgement are required')
    root = Path(root).absolute()
    if root.resolve() != root or not root.is_dir():
        raise ValueError('unsafe state root')
    state = State(root, quiescent_transition=True)
    stored_version = _version(state.db_path)
    if stored_version == CORE_SCHEMA_VERSION:
        raise ValueError(_SCHEMA10_DOWNGRADE_REFUSAL if rollback else 'state is already at schema 10')
    if stored_version != (9 if rollback else 8):
        raise ValueError('unexpected state schema for offline transition')
    with ExitStack() as stack:
        stack.enter_context(Lock(root / 'update.lock', no_follow=True))
        stack.enter_context(Lock(root / 'scan-worker.lock', no_follow=True))
        # Admission must already be stopped by the operator; persisted active
        # work must be resolved with the matching binary before transition.
        with sqlite3.connect(f'file:{state.db_path}?mode=ro', uri=True) as c:
            if c.execute("SELECT 1 FROM operation_runs WHERE status IN ('queued','running','finalizing')").fetchone():
                raise ValueError('an active operation prevents the state transition')
            if rollback:
                if c.execute("SELECT 1 FROM compose_bootstrap_fences WHERE lifecycle IN ('active','manual')").fetchone():
                    raise ValueError('an unresolved bootstrap prevents binary rollback')
        backup_root = root / 'schema-transitions'
        if backup_root.is_symlink():
            raise ValueError('unsafe transition storage')
        backup_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(backup_root, 0o700)
        old = backup_root / 'schema8-before9.sqlite3'
        if not rollback:
            if _version(state.db_path) != 8:
                raise ValueError('transition requires schema 8')
            _snapshot(state.db_path, old)
            if _version(old) != 8:
                raise ValueError('schema-8 backup did not validate')
            state.ensure_compatible()
            return
        state.ensure_compatible()
        if state.bootstrap_fence(None):
            raise ValueError('unresolved or unproved bootstrap evidence prevents binary rollback')
        if _version(old) != 8 or _read_private(old.with_suffix('.sha256'),64).decode() != _digest(old):
            raise ValueError('a validated retained schema-8 backup is required')
        _snapshot(state.db_path, backup_root / 'schema9-before-binary-rollback.sqlite3')
        # Preserve all schema-9 evidence directories. Only the explicitly
        # acknowledged pre-upgrade database snapshot is restored.
        fd, name = tempfile.mkstemp(prefix='.schema8-restore-', dir=root)
        os.close(fd)
        staged = Path(name)
        with sqlite3.connect(f'file:{old}?mode=ro', uri=True) as src, sqlite3.connect(staged) as dst:
            src.backup(dst)
        with sqlite3.connect(state.db_path) as current:
            if current.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] != 0:
                raise ValueError('state is not quiescent; checkpoint refused')
        for suffix in ('-wal', '-shm'):
            Path(str(state.db_path) + suffix).unlink(missing_ok=True)
        fd = os.open(staged, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(staged, state.db_path)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


_SCHEMA10_DOWNGRADE_REFUSAL = (
    'state-preserving schema 10 to 9 downgrade is not supported. The retained schema-9 snapshot is not '
    'restored because it would discard post-upgrade History, rollback points and G2 recovery claims. '
    'Keep a schema-10 binary and use forward recovery; a schema-9 binary refuses this database before '
    'any state or Docker change.')


def _safe_root(root):
    root = Path(root).absolute()
    if root.resolve() != root or not root.is_dir():
        raise ValueError('unsafe state root')
    return root


def _transition_storage(root):
    backup_root = root / 'schema-transitions'
    if backup_root.is_symlink():
        raise ValueError('unsafe transition storage')
    backup_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(backup_root, 0o700)
    return backup_root


def _logical_digest(c, names=None):
    """Digest of every non-G2 schema object and its rows (except the version), order-independent."""
    objects = sorted((row[0], row[1], row[2], row[3]) for row in c.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
    objects = [item for item in objects if not item[1].startswith(('completion_', 'idx_completion_'))
               and (names is None or item[1] in names)]
    digest = hashlib.sha256()
    for kind, name, table, sql in objects:
        digest.update(repr((kind, name, table, sql)).encode())
        # The version row is checked separately; it is the one intended change.
        if kind == 'table' and name != 'schema_version':
            quoted = '"' + name.replace('"', '""') + '"'
            for row in sorted(repr(tuple(row)) for row in c.execute('SELECT * FROM ' + quoted)):
                digest.update(row.encode() + b'\n')
    return frozenset(item[1] for item in objects), digest.hexdigest()


def _strict_version(path):
    """Integrity-checked version that must be exactly one integer row."""
    if path.is_symlink() or not path.is_file():
        raise ValueError('state backup is unavailable or unsafe')
    with closing(sqlite3.connect(f'file:{path}?mode=ro', uri=True)) as c:
        if c.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('state integrity check failed')
        if not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone():
            raise ValueError('state database is unversioned; refusing to convert it')
        _version_row = c.execute('SELECT version FROM schema_version').fetchall()
    if len(_version_row) != 1 or type(_version_row[0][0]) is not int:
        raise ValueError('state database version is invalid; refusing to convert it')
    return _version_row[0][0]


def _readonly(path):
    return closing(sqlite3.connect(f'file:{path}?mode=ro', uri=True))


def _verify_snapshot(snapshot, expected):
    """A retained snapshot is trusted only if it exactly matches current state."""
    if snapshot.is_symlink() or not snapshot.is_file() or snapshot.stat().st_mode & 0o077:
        raise ValueError('a retained transition snapshot is unsafe; preserve and review it')
    try:
        recorded = _read_private(snapshot.with_suffix('.sha256'), 64).decode()
    except Exception:
        raise ValueError('a retained transition snapshot cannot be validated; preserve and review it') from None
    if recorded != _digest(snapshot) or _version(snapshot) != SCHEMA9_VERSION:
        raise ValueError('a retained transition snapshot failed validation; preserve and review it')
    with _readonly(snapshot) as c:
        if _logical_digest(c) != expected:
            raise ValueError('the retained schema-9 snapshot does not match current state; preserve and review it')


def _checkpoint(_name):
    """Deterministic fault-injection seam for interruption tests."""


def upgrade_schema10(root, *, confirm_quiescent=False):
    """Explicit offline schema 9 to 10 transition; returns 'migrated' or 'current'.

    Order: both locks; verify file, integrity, version, schema-9 identity and
    quiescence; take or re-validate the private snapshot; then one IMMEDIATE
    transaction that re-proves the unchanged state, adds the G2 tables and
    proves every pre-existing object and row is unchanged before COMMIT. Any
    failure rolls back to schema 9 and retains the snapshot. A retry resumes
    only when the retained snapshot exactly matches current state.
    """
    if not confirm_quiescent:
        raise ValueError('explicit offline quiescence confirmation is required')
    root = _safe_root(root)
    db = root / 'history.sqlite3'
    with ExitStack() as stack:
        stack.enter_context(Lock(root / 'update.lock', no_follow=True))
        stack.enter_context(Lock(root / 'scan-worker.lock', no_follow=True))
        stored = _strict_version(db)
        if stored == CORE_SCHEMA_VERSION:
            # Repeat invocation: prove the committed schema; convert nothing.
            State(root, require_existing=True).ensure_compatible()
            return 'current'
        if stored != SCHEMA9_VERSION:
            raise ValueError('the schema-10 transition requires a schema-9 state database')
        with _readonly(db) as c:
            State._validate_schema9_identity(c)
            if c.execute("SELECT 1 FROM sqlite_master WHERE name LIKE '%completion%'").fetchone():
                raise ValueError('unexpected schema-10 objects in schema-9 state; refusing to migrate')
            if c.execute(_ACTIVE_OPERATION).fetchone():
                raise ValueError('an active operation prevents the state transition')
            if c.execute('PRAGMA foreign_key_check').fetchone():
                raise ValueError('state foreign-key integrity check failed')
            before = _logical_digest(c)
        snapshot = _transition_storage(root) / SCHEMA10_SNAPSHOT
        if not (snapshot.exists() or snapshot.is_symlink()):
            _snapshot(db, snapshot)
        _verify_snapshot(snapshot, before)
        _checkpoint('snapshot')
        c = sqlite3.connect(f'file:{db}?mode=rw', uri=True, isolation_level=None)
        try:
            c.execute('PRAGMA foreign_keys=ON')
            c.execute('BEGIN IMMEDIATE')
            if (c.execute('SELECT version FROM schema_version').fetchall() != [(SCHEMA9_VERSION,)]
                    or _logical_digest(c) != before):
                raise ValueError('state changed during the transition; nothing was migrated')
            State._migrate(c, target=CORE_SCHEMA_VERSION)
            _checkpoint('migrated')
            if (c.execute('SELECT version FROM schema_version').fetchall() != [(CORE_SCHEMA_VERSION,)]
                    or not completion_fence.schema_matches(c)
                    or _logical_digest(c, before[0]) != before
                    or c.execute('PRAGMA foreign_key_check').fetchone()
                    or c.execute('PRAGMA integrity_check').fetchone()[0] != 'ok'):
                raise ValueError('schema-10 validation failed; nothing was migrated')
            _checkpoint('validated')
            c.execute('COMMIT')
        except BaseException:
            if c.in_transaction:
                c.execute('ROLLBACK')
            raise
        finally:
            c.close()
        State(root, require_existing=True).ensure_compatible()
        return 'migrated'


def refuse_schema10_downgrade(root):
    """Diagnose (read-only) and refuse: no state-preserving 10 to 9 transition exists."""
    root = _safe_root(root)
    stored = _strict_version(root / 'history.sqlite3')
    if stored != CORE_SCHEMA_VERSION:
        raise ValueError(f'state is at schema {stored}, not schema 10; nothing to downgrade')
    try:
        with _readonly(root / 'history.sqlite3') as c:
            unresolved = len(completion_fence.unresolved_fences(c))
        detail = f' Unresolved G2 completion fences: {unresolved}.'
    except (sqlite3.Error, ValueError):
        detail = ' G2 recovery evidence could not be verified.'
    raise ValueError(_SCHEMA10_DOWNGRADE_REFUSAL + detail)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('action', choices=['upgrade', 'restore-schema8-backup', 'upgrade-schema10', 'downgrade-schema9'])
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--confirm-quiescent', action='store_true', help='Confirm all UPT admission and processes are stopped.')
    parser.add_argument('--confirm-state-loss', action='store_true', help='Accept loss of all post-upgrade database state (restore-schema8-backup only).')
    args = parser.parse_args(argv)
    try:
        _run(args)
    except (ValueError, RuntimeError, OSError, sqlite3.Error) as exc:
        raise SystemExit(f'Error: {exc}') from None


def _run(args):
    if args.action == 'upgrade-schema10':
        outcome = upgrade_schema10(args.state_dir, confirm_quiescent=args.confirm_quiescent)
        print('State is already at schema 10; nothing was changed.' if outcome == 'current' else
              'Offline schema-10 transition completed. The validated schema-9 snapshot is retained privately.')
        return
    if args.action == 'downgrade-schema9':
        refuse_schema10_downgrade(args.state_dir)
    transition(args.state_dir, rollback=args.action != 'upgrade', confirm_quiescent=args.confirm_quiescent,
               confirm_state_loss=args.confirm_state_loss)
    print('Offline state transition completed. Retained snapshots and Compose evidence remain private.')


if __name__ == '__main__':
    main()
