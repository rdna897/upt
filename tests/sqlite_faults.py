"""Deterministic SQLite fault injection at the ``State`` connection boundary.

Characterisation tests use this to make one real ``State`` write fail where a
production SQLite failure would surface, without replacing ``State`` methods:

* ``before_commit`` - the matching statement raises inside the write
  transaction, so ``State.connect`` rolls it back and nothing is persisted.
  A busy timeout at ``BEGIN IMMEDIATE`` has the same caller-visible outcome;
  the fault is placed on the statement because only it identifies which
  ``State`` write is being targeted.
* ``after_commit`` - the matching statement executes, the transaction really
  commits, then the commit acknowledgement raises (an ambiguous commit).
* ``unavailable`` - the matching statement raises and, from then on, every new
  connection fails until the context exits (persistent unavailability).
* ``read_failure`` - the matching statement (normally a ``SELECT`` chosen with
  ``select_from``) raises without persisting anything: a failed
  reconciliation read. ``times`` bounds how many reads fail.

Every connection's requested per-call timeout is recorded in
``fault.connection_timeouts`` (``None`` means the 30 s default), so tests can
prove a deadline reached each SQLite step.

Statements are matched by a predicate over ``(sql, row)``, where ``row`` maps
the column names of an ``INSERT`` to its parameters (``{"params": ...}`` for
other SQL). Only ``Connection.execute`` is intercepted, and an ``INSERT`` whose
values are not all placeholders cannot be matched by column (``history_insert``
fails loudly rather than mismatching it).
"""

import re
import sqlite3
from contextlib import contextmanager
from unittest.mock import patch

_INSERT = re.compile(r"\s*INSERT\s+(?:OR\s+\w+\s+)?INTO\s+(\w+)\s*\(([^)]*)\)", re.IGNORECASE)


def history_insert(**expected):
    """Match an ``INSERT INTO history`` whose named columns equal ``expected``."""
    def match(sql, row):
        found = _INSERT.match(sql)
        if not found or found.group(1) != "history":
            return False
        if "unmapped" in row:
            raise AssertionError("history_insert supports placeholder-only INSERTs: " + sql[:80])
        return all(row.get(key) == value for key, value in expected.items())
    return match


def select_from(table):
    """Match a ``SELECT`` whose first ``FROM`` names ``table``."""
    pattern = re.compile(r"\s*SELECT\b.*?\bFROM\s+" + re.escape(table) + r"\b", re.IGNORECASE | re.DOTALL)

    def match(sql, row):
        return bool(pattern.match(sql))
    return match


def terminal_operation_update(status):
    """Match ``finish_operation``'s terminal ``UPDATE operation_runs`` for ``status``."""
    def match(sql, row):
        return (sql.lstrip().startswith("UPDATE operation_runs SET status=?,finished_at=?")
                and bool(row.get("params")) and row["params"][0] == status)
    return match


class _Connection:
    """Delegate to a real sqlite3 connection, failing only the selected write."""

    def __init__(self, real, fault):
        self._real = real
        self._fault = fault
        self._ambiguous = False

    def __getattr__(self, name):
        return getattr(self._real, name)

    def execute(self, sql, params=()):
        found = _INSERT.match(sql)
        row = {"params": tuple(params)}
        if found:
            columns = [name.strip() for name in found.group(2).split(",")]
            row = dict(zip(columns, params)) if len(columns) == len(params) else {"unmapped": sql}
        if self._fault.remaining and self._fault.match(sql, row):
            self._fault.remaining -= 1
            self._fault.hits.append(row)
            if self._fault.mode == "after_commit":
                self._ambiguous = True
            else:
                if self._fault.mode == "unavailable":
                    self._fault.unavailable = True
                raise sqlite3.OperationalError(self._fault.message)
        return self._real.execute(sql, params)

    def commit(self):
        self._real.commit()
        if self._ambiguous:
            self._ambiguous = False
            raise sqlite3.OperationalError(self._fault.message)


class SqliteFault:
    def __init__(self, match, mode, times, message):
        if mode not in {"before_commit", "after_commit", "unavailable", "read_failure"}:
            raise ValueError(mode)
        self.match = match
        self.mode = mode
        self.remaining = times
        self.message = message
        self.hits = []
        self.unavailable = False
        self.connection_timeouts = []


@contextmanager
def sqlite_fault(state, match, *, mode="before_commit", times=1, message=None):
    """Inject one SQLite failure into ``state``'s connections for the block.

    Only the targeted ``State`` instance is affected; reads made after the
    block see exactly what was durably committed.
    """
    fault = SqliteFault(match, mode, times, message or {
        "before_commit": "database is locked",
        "after_commit": "disk I/O error",
        "unavailable": "unable to open database file",
        "read_failure": "disk I/O error"}[mode])
    original = state._new_connection

    def new_connection(timeout=None, **options):
        fault.connection_timeouts.append(timeout)
        if fault.unavailable:
            raise sqlite3.OperationalError(fault.message)
        return _Connection(original(timeout=timeout, **options), fault)

    with patch.object(state, "_new_connection", side_effect=new_connection):
        yield fault
