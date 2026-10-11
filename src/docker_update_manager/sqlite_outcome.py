"""Storage-independent SQLite completion primitives (G2-S0a).

These primitives let a future completion publisher tell an established
non-commit apart from an unknown commit outcome, and bound every SQLite step
by one monotonic deadline. They are opt-in: existing ``State.connect`` and
``State.read`` callers keep their exception types and 30 s defaults.

Outcome rules (deliberately conservative):

* ``NOT_COMMITTED`` is reported only when ``commit()`` was never attempted and
  the write transaction was still open when the failure surfaced, so the
  rollback provably discards it.
* ``AMBIGUOUS`` covers every failure in or after ``commit()`` and any case
  where the transaction ended without UPT's commit (for example an automatic
  SQLite rollback after ``SQLITE_FULL``/``SQLITE_IOERR``). A SQLite error is
  never treated as proof that nothing was committed; the caller must verify
  by a successful read before writing again.
"""
from __future__ import annotations

import math
import re
import time

NOT_COMMITTED = "not_committed"
AMBIGUOUS = "ambiguous"

DEFAULT_SQLITE_TIMEOUT = 30.0
MAX_SQLITE_TIMEOUT = DEFAULT_SQLITE_TIMEOUT

# Statements that could end, split or nest the owned transaction.
_TRANSACTION_CONTROL = frozenset({"BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE",
                                  "ATTACH", "DETACH", "VACUUM"})
_LEADING_NOISE = re.compile(r"\s+|--[^\n]*(?:\n|$)|/\*.*?(?:\*/|$)", re.DOTALL)
_FIRST_WORD = re.compile(r"[A-Za-z]+")


class TransactionOwnershipError(RuntimeError):
    """A transaction body tried to control or outlive the transaction it was lent."""


class _UnavailableAttribute(TransactionOwnershipError, AttributeError):
    """Refused attribute; still an ``AttributeError`` so ``hasattr`` keeps working."""


class DeadlineExceeded(RuntimeError):
    """No further SQLite step may start: the monotonic deadline has passed."""


class WriteOutcomeError(Exception):
    """A classified write-transaction failure.

    ``outcome`` is ``NOT_COMMITTED`` or ``AMBIGUOUS``; ``phase`` is where it
    failed (``connect``, ``begin``, ``body``, ``commit``); ``cause`` is the
    original exception, also chained as ``__cause__``.
    """

    def __init__(self, outcome, phase, cause):
        if outcome not in {NOT_COMMITTED, AMBIGUOUS}:
            raise ValueError(f"invalid write outcome: {outcome!r}")
        super().__init__(f"SQLite write {outcome} during {phase}: {type(cause).__name__}")
        self.outcome = outcome
        self.phase = phase
        self.cause = cause


def sqlite_timeout(value=None) -> float:
    """Validate a per-call connection/busy timeout in seconds; ``None`` is the 30 s default."""
    if value is None:
        return DEFAULT_SQLITE_TIMEOUT
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("SQLite timeout must be a number of seconds")
    value = float(value)
    if not math.isfinite(value) or value <= 0 or value > MAX_SQLITE_TIMEOUT:
        raise ValueError(f"SQLite timeout must be greater than 0 and at most {MAX_SQLITE_TIMEOUT:g} seconds")
    return value


class Deadline:
    """One monotonic budget shared by every SQLite step of a completion.

    ``step_timeout()`` gives the next step ``min(remaining, cap)`` as its
    connection/busy timeout and refuses to start a step once the budget is
    spent. A statement already executing is not interrupted.
    """

    def __init__(self, seconds, *, clock=time.monotonic):
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ValueError("deadline must be a number of seconds")
        seconds = float(seconds)
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError("deadline must be a positive, finite number of seconds")
        self._clock = clock
        self._expires_at = clock() + seconds

    def remaining(self) -> float:
        return max(0.0, self._expires_at - self._clock())

    def expired(self) -> bool:
        return self.remaining() <= 0

    def step_timeout(self, cap=MAX_SQLITE_TIMEOUT) -> float:
        cap = sqlite_timeout(cap)
        remaining = self.remaining()
        if remaining <= 0:
            raise DeadlineExceeded("SQLite completion deadline exhausted")
        return min(remaining, cap)


def _leading_keyword(sql) -> str:
    text = str(sql)
    position = 0
    while True:
        noise = _LEADING_NOISE.match(text, position)
        if not noise or noise.end() == position:
            break
        position = noise.end()
    word = _FIRST_WORD.match(text, position)
    return word.group(0).upper() if word else ""


class OwnedTransaction:
    """The only view of a write connection lent to a transaction body.

    It exposes statement execution and nothing that can commit, roll back,
    open a raw cursor or run an implicit-commit script. Each statement first
    proves the owned transaction is still open, so Python's implicit ``BEGIN``
    cannot silently start a second transaction after an automatic rollback.
    """

    __slots__ = ("_connection", "_open")

    def __init__(self, connection):
        self._connection = connection
        self._open = True

    def _checked(self, sql):
        if not self._open:
            raise TransactionOwnershipError("transaction handle used after its transaction ended")
        if _leading_keyword(sql) in _TRANSACTION_CONTROL:
            raise TransactionOwnershipError("transaction control is owned by State.write_transaction")
        if not self._connection.in_transaction:
            raise TransactionOwnershipError("the owned SQLite transaction is no longer open")

    def execute(self, sql, parameters=()):
        self._checked(sql)
        return self._connection.execute(sql, parameters)

    def executemany(self, sql, parameters):
        self._checked(sql)
        return self._connection.executemany(sql, parameters)

    @property
    def in_transaction(self):
        return self._open and self._connection.in_transaction

    def _release(self):
        self._open = False

    def __getattr__(self, name):
        raise _UnavailableAttribute(f"{name!r} is not available inside State.write_transaction")
