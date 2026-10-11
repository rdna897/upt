"""G2-S0a storage-independent SQLite completion primitives.

Commit-outcome classification, per-call timeouts and the monotonic deadline
are exercised inside real ``State`` transactions on temporary databases, with
faults injected by ``sqlite_faults``. No Docker, Compose or registry boundary
is reached. Existing ``State.connect``/``State.read`` behaviour is pinned so
these opt-in primitives cannot silently change current callers.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import math
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("UPT_TESTING", "1")  # WebState accepts temporary roots only in tests

from docker_update_manager.sqlite_outcome import (
    AMBIGUOUS, NOT_COMMITTED, Deadline, DeadlineExceeded, TransactionOwnershipError, WriteOutcomeError,
    sqlite_timeout,
)
from docker_update_manager.state import State
from docker_update_manager.webstate import WebState
from sqlite_faults import history_insert, select_from, sqlite_fault

KEY = "c" * 32


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class _StateFixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.state = State(Path(temp.name) / "state")
        self.state.ensure_compatible()

    def insert(self, c, result="SUCCESS"):
        c.execute("INSERT INTO history (stack,service,action,result,details) VALUES (?,?,?,?,?)",
                  ("stack", "app", "update", result, '{"completion_id":"%s"}' % KEY))

    def rows(self):
        # Independent connection: only what was durably committed is visible.
        with sqlite3.connect(self.state.db_path) as c:
            return c.execute("SELECT result FROM history WHERE details LIKE ?", (f"%{KEY}%",)).fetchall()

    def outcome(self, **kwargs):
        with self.assertRaises(WriteOutcomeError) as caught:
            with self.state.write_transaction(**kwargs) as c:
                self.insert(c)
        return caught.exception


class TimeoutAndDeadlineTests(_StateFixture):
    def test_timeout_validation_is_bounded(self):
        self.assertEqual(sqlite_timeout(None), 30.0)
        self.assertEqual(sqlite_timeout(0.25), 0.25)
        self.assertEqual(sqlite_timeout(30), 30.0)
        for bad in (0, -1, 30.001, math.nan, math.inf, True, "5"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sqlite_timeout(bad)

    def busy_timeout(self, context):
        with context as c:
            return c.execute("PRAGMA busy_timeout").fetchone()[0]

    def test_defaults_unchanged_and_per_call_timeout_reaches_sqlite(self):
        self.assertEqual(self.busy_timeout(self.state.connect()), 30000)
        self.assertEqual(self.busy_timeout(self.state.read()), 30000)
        self.assertEqual(self.busy_timeout(self.state.read(timeout=0.25)), 250)
        self.assertEqual(self.busy_timeout(self.state.write_transaction(timeout=1.5)), 1500)
        with self.assertRaises(ValueError):
            with self.state.read(timeout=31):
                pass

    def test_invalid_write_timeout_is_classified_not_committed(self):
        error = self.outcome(timeout=0)
        self.assertEqual((error.outcome, error.phase), (NOT_COMMITTED, "connect"))
        self.assertIsInstance(error.cause, ValueError)
        self.assertEqual(self.rows(), [])

    def test_web_state_accepts_per_call_timeout(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        web = WebState(Path(temp.name) / "web")
        self.assertEqual(self.busy_timeout(web.read(timeout=0.5)), 500)

    def test_deadline_caps_steps_and_refuses_after_expiry(self):
        clock = FakeClock()
        deadline = Deadline(60, clock=clock)
        self.assertEqual(deadline.step_timeout(), 30.0)
        clock.now += 45
        self.assertEqual(deadline.remaining(), 15.0)
        self.assertEqual(deadline.step_timeout(), 15.0)
        self.assertEqual(deadline.step_timeout(cap=2), 2.0)
        clock.now += 15
        self.assertTrue(deadline.expired())
        with self.assertRaises(DeadlineExceeded):
            deadline.step_timeout()
        for bad in (0, -1, math.inf, math.nan, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                Deadline(bad, clock=clock)

    def test_busy_writer_fails_within_step_timeout_without_writing(self):
        holder = sqlite3.connect(self.state.db_path, timeout=0)
        self.addCleanup(holder.close)
        holder.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        error = self.outcome(timeout=0.2)
        elapsed = time.monotonic() - started
        holder.rollback()
        self.assertEqual((error.outcome, error.phase), (NOT_COMMITTED, "begin"))
        self.assertIsInstance(error.cause, sqlite3.OperationalError)
        self.assertGreaterEqual(elapsed, 0.15)
        self.assertLess(elapsed, 10)  # far below the 30 s default
        self.assertEqual(self.rows(), [])


class CommitClassificationTests(_StateFixture):
    def test_success_commits_exactly_once(self):
        with self.state.write_transaction() as c:
            self.insert(c)
        self.assertEqual(self.rows(), [("SUCCESS",)])

    def test_statement_failure_before_commit_is_not_committed(self):
        with sqlite_fault(self.state, history_insert(result="SUCCESS")) as fault:
            error = self.outcome(timeout=5)
        self.assertEqual((error.outcome, error.phase), (NOT_COMMITTED, "body"))
        self.assertIsInstance(error.cause, sqlite3.OperationalError)
        self.assertIs(error.__cause__, error.cause)
        self.assertEqual((len(fault.hits), fault.connection_timeouts), (1, [5]))
        self.assertEqual(self.rows(), [])

    def test_non_sqlite_body_error_rolls_back_and_keeps_its_type(self):
        with self.assertRaises(WriteOutcomeError) as caught:
            with self.state.write_transaction() as c:
                self.insert(c)
                raise ValueError("publication is not authorised")
        self.assertEqual(caught.exception.outcome, NOT_COMMITTED)
        self.assertIsInstance(caught.exception.cause, ValueError)
        self.assertEqual(self.rows(), [])

    def test_failed_commit_acknowledgement_is_ambiguous_even_though_committed(self):
        with sqlite_fault(self.state, history_insert(result="SUCCESS"), mode="after_commit"):
            error = self.outcome()
        self.assertEqual((error.outcome, error.phase), (AMBIGUOUS, "commit"))
        # The SQLite error did not mean "not committed": the row is durable.
        self.assertEqual(self.rows(), [("SUCCESS",)])

    def test_persistent_unavailability(self):
        with sqlite_fault(self.state, history_insert(result="SUCCESS"), mode="unavailable"):
            first = self.outcome()
            second = self.outcome()
            with self.assertRaises(sqlite3.OperationalError):
                with self.state.read() as c:
                    c.execute("SELECT 1")
        self.assertEqual((first.outcome, first.phase), (NOT_COMMITTED, "body"))
        self.assertEqual((second.outcome, second.phase), (NOT_COMMITTED, "connect"))
        self.assertEqual(self.rows(), [])

    def test_lost_transaction_is_ambiguous_and_refuses_further_statements(self):
        # Simulates SQLite's automatic rollback (SQLITE_FULL/IOERR) mid-body.
        with self.assertRaises(WriteOutcomeError) as caught:
            with self.state.write_transaction() as c:
                c._connection.rollback()
                self.insert(c)  # would otherwise implicitly BEGIN a new transaction
        self.assertEqual(caught.exception.outcome, AMBIGUOUS)
        self.assertIsInstance(caught.exception.cause, TransactionOwnershipError)
        with self.assertRaises(WriteOutcomeError) as caught:
            with self.state.write_transaction() as c:
                c._connection.rollback()
        self.assertEqual((caught.exception.outcome, caught.exception.phase), (AMBIGUOUS, "body"))
        self.assertEqual(self.rows(), [])

    def test_keyboard_interrupt_rolls_back_and_propagates_unchanged(self):
        with self.assertRaises(KeyboardInterrupt):
            with self.state.write_transaction() as c:
                self.insert(c)
                raise KeyboardInterrupt
        self.assertEqual(self.rows(), [])


class TransactionOwnershipTests(_StateFixture):
    def assert_refused(self, action):
        with self.assertRaises(WriteOutcomeError) as caught:
            with self.state.write_transaction() as c:
                self.insert(c)
                action(c)
        self.assertEqual(caught.exception.outcome, NOT_COMMITTED)
        self.assertIsInstance(caught.exception.cause, TransactionOwnershipError)
        self.assertEqual(self.rows(), [])  # the earlier insert was rolled back

    def test_body_cannot_end_or_escape_the_transaction(self):
        for name, action in (
            ("commit", lambda c: c.commit()),
            ("rollback", lambda c: c.rollback()),
            ("executescript", lambda c: c.executescript("SELECT 1")),
            ("cursor", lambda c: c.cursor()),
            ("close", lambda c: c.close()),
            ("COMMIT", lambda c: c.execute("COMMIT")),
            ("commented end", lambda c: c.execute("  -- note\n /* x */ end")),
            ("savepoint", lambda c: c.execute("SAVEPOINT s")),
            ("executemany release", lambda c: c.executemany("RELEASE s", [()])),
            ("attach", lambda c: c.execute("ATTACH ':memory:' AS other")),
        ):
            with self.subTest(name):
                self.assert_refused(action)

    def test_handle_is_unusable_after_the_transaction(self):
        with self.state.write_transaction() as c:
            self.insert(c)
        with self.assertRaises(TransactionOwnershipError):
            c.execute("SELECT 1")
        self.assertFalse(c.in_transaction)
        self.assertFalse(hasattr(c, "commit"))
        self.assertEqual(self.rows(), [("SUCCESS",)])


class LegacyBehaviourTests(_StateFixture):
    def test_connect_still_raises_raw_sqlite_errors(self):
        for mode, expected in (("before_commit", []), ("after_commit", [("SUCCESS",)])):
            with self.subTest(mode):
                with sqlite3.connect(self.state.db_path) as c:
                    c.execute("DELETE FROM history")
                with sqlite_fault(self.state, history_insert(result="SUCCESS"), mode=mode) as fault:
                    with self.assertRaises(sqlite3.OperationalError):
                        with self.state.connect() as c:
                            self.insert(c)
                self.assertEqual(self.rows(), expected)
                self.assertEqual(fault.connection_timeouts, [None])


class ReconciliationCompositionTests(_StateFixture):
    """The primitives compose into the P5 rule: never insert again after an
    ambiguous commit until a successful read has established absence."""

    def find(self, deadline):
        with self.state.read(timeout=deadline.step_timeout()) as c:
            return c.execute("SELECT result FROM history WHERE details LIKE ?", (f"%{KEY}%",)).fetchall()

    def publish(self, deadline, clock):
        inserts = 0
        while True:
            try:
                with self.state.write_transaction(timeout=deadline.step_timeout()) as c:
                    inserts += 1
                    self.insert(c)
                return "committed", inserts
            except DeadlineExceeded:
                return "not_committed", inserts
            except WriteOutcomeError as error:
                if error.outcome == NOT_COMMITTED:
                    continue
            while True:  # ambiguous: reads only, within the deadline
                try:
                    found = self.find(deadline)
                except DeadlineExceeded:
                    return "ambiguous", inserts
                except sqlite3.OperationalError:
                    clock.now += 10  # a failed read consumes budget
                    continue
                if found:
                    return "committed", inserts
                break

    def test_ambiguous_commit_then_failed_reads_never_duplicates(self):
        clock = FakeClock()
        deadline = Deadline(60, clock=clock)
        with sqlite_fault(self.state, history_insert(result="SUCCESS"), mode="after_commit"):
            with sqlite_fault(self.state, select_from("history"), mode="read_failure", times=10) as reads:
                outcome, inserts = self.publish(deadline, clock)
        self.assertEqual((outcome, inserts), ("ambiguous", 1))
        self.assertEqual(len(reads.hits), 6)  # 60 s budget, 10 s per failed read
        self.assertTrue(all(0 < value <= 30 for value in reads.connection_timeouts))
        self.assertEqual(self.rows(), [("SUCCESS",)])

    def test_ambiguous_commit_resolved_by_a_later_successful_read(self):
        clock = FakeClock()
        with sqlite_fault(self.state, history_insert(result="SUCCESS"), mode="after_commit"):
            with sqlite_fault(self.state, select_from("history"), mode="read_failure", times=2):
                outcome, inserts = self.publish(Deadline(60, clock=clock), clock)
        self.assertEqual((outcome, inserts), ("committed", 1))
        self.assertEqual(self.rows(), [("SUCCESS",)])

    def test_established_non_commit_permits_exactly_one_retry(self):
        clock = FakeClock()
        with sqlite_fault(self.state, history_insert(result="SUCCESS")):
            outcome, inserts = self.publish(Deadline(60, clock=clock), clock)
        self.assertEqual((outcome, inserts), ("committed", 2))
        self.assertEqual(self.rows(), [("SUCCESS",)])

    def test_expired_deadline_starts_no_sqlite_step(self):
        clock = FakeClock()
        deadline = Deadline(1, clock=clock)
        clock.now += 1
        with sqlite_fault(self.state, history_insert(result="SUCCESS")) as fault:
            outcome, inserts = self.publish(deadline, clock)
        self.assertEqual((outcome, inserts, fault.connection_timeouts), ("not_committed", 0, []))
        self.assertEqual(self.rows(), [])


if __name__ == "__main__":
    unittest.main()
