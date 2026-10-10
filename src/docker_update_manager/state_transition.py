"""Offline schema transition and explicitly confirmed binary-rollback recovery.

Stop all UPT admission/processes (including scheduled CLI invocations) before
calling this tool. update.lock serialises the transition but cannot by itself
prove that an old binary is quiescent. No Docker commands are invoked.
"""
from __future__ import annotations
import argparse
import hashlib
import os
import sqlite3
import tempfile
from contextlib import ExitStack
from pathlib import Path

from .compose_baseline import _read_private, _write_private
from .lock import Lock
from .state import State


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['upgrade', 'restore-schema8-backup'])
    parser.add_argument('--state-dir', type=Path, required=True)
    parser.add_argument('--confirm-quiescent', action='store_true', help='Confirm all UPT admission and processes are stopped.')
    parser.add_argument('--confirm-state-loss', action='store_true', help='Accept loss of all post-upgrade database state.')
    args = parser.parse_args(argv)
    transition(args.state_dir, rollback=args.action != 'upgrade', confirm_quiescent=args.confirm_quiescent,
               confirm_state_loss=args.confirm_state_loss)
    print('Offline state transition completed. Retained snapshots and Compose evidence remain private.')


if __name__ == '__main__':
    main()
