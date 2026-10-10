"""Targeted verification real-worker regressions: races and safety."""

import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py

import itertools
import os
import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("UPT_TESTING", "1")

from docker_update_manager.config import Config
from docker_update_manager.models import ScanResult, Service
from docker_update_manager.reconciliation import public_service
from docker_update_manager.state import State
from docker_update_manager.webservice import ReadOnlyService


class TargetedVerificationWorkerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = State(self.root / "state")
        self.agent = ReadOnlyService(Config(path=str(self.root / "config.yml")), self.state)
        self.service = Service(
            name="fixture", container_id="a" * 64, image="example.invalid/fixture:latest",
            image_id="sha256:" + "1" * 64, digest="sha256:" + "2" * 64,
            version="1.0", created=None, architecture="amd64", state="running",
            health="healthy", restart_policy="always", started_at=None,
            stack="synthetic-stack", compose_service="fixture", working_dir=str(self.root),
            compose_files=[str(self.root / "compose.yml")],
        )
        self.key = "container/" + self.service.container_id
        # Capture the actual Thread objects before Thread.start(), including
        # workers that finish before start_refresh() returns to its caller.
        self._started_refresh_threads = []
        original_thread_start = threading.Thread.start

        def capture_thread_start(thread):
            if thread.name.startswith("upt-refresh-"):
                self._started_refresh_threads.append(thread)
            return original_thread_start(thread)

        tracker = patch.object(threading.Thread, "start", capture_thread_start)
        tracker.start()
        self.addCleanup(tracker.stop)

    def _start_thread(self, *, after_reconcile=False):
        result = self.agent.start_refresh(self.key, after_reconcile=after_reconcile)
        self.assertEqual(result["status"], "checking")
        self.assertTrue(self._started_refresh_threads, "no real refresh thread started")
        return self._started_refresh_threads[-1]

    def _join(self, thread):
        thread.join(5)
        self.assertFalse(thread.is_alive(), "refresh worker was not joined")

    def _join_all_started(self):
        # Joining the first worker can reveal its follow-up, which is created
        # in the old worker's finally block. Include it before removing guards.
        for _ in range(4):
            observed = tuple(self._started_refresh_threads)
            for thread in observed:
                self._join(thread)
            if tuple(self._started_refresh_threads) == observed:
                return
        self.fail("refresh workers kept spawning unexpected follow-up threads")

    def _assert_empty(self):
        with self.agent._lock:
            self.assertEqual(self.agent._refresh_threads, {})
            self.assertEqual(self.agent._refresh_started_at, {})
            self.assertEqual(self.agent._refresh_again, set())

    def test_invalidation_during_first_discover_queues_exactly_one_followup(self):
        entered, release = threading.Event(), threading.Event()
        checked_threads = []
        timestamps = []
        base = datetime.now(timezone.utc) - timedelta(minutes=1)
        ticks = itertools.count(1)
        clock_tick = lambda *_: base + timedelta(milliseconds=next(ticks))
        discovery_count = []

        def discover_services(_config):
            discovery_count.append(1)
            if len(discovery_count) == 1:
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("timed out inside first discovery")
            return [self.service]

        def check_service(service, _state):
            checked_threads.append(threading.current_thread())
            return ScanResult(service, "UPDATE" if len(checked_threads) == 1 else "CURRENT",
                              "sha256:" + "3" * 64)

        save = self.state.save_verification

        def saved(data, *, started_at=None):
            timestamps.append((started_at, self.agent._refresh_started_at.get(self.key)))
            return save(data, started_at=started_at)

        first = None
        with patch("docker_update_manager.webservice.datetime", wraps=datetime) as clock, \
             patch("docker_update_manager.state._utc_now", side_effect=lambda: clock_tick().isoformat()), \
             patch("docker_update_manager.webservice.discover", side_effect=discover_services) as discovery, \
             patch("docker_update_manager.webservice.scan_service_with_tracking", side_effect=check_service) as checked, \
             patch.object(self.state, "save_verification", side_effect=saved), \
             patch("subprocess.run", side_effect=AssertionError("live subprocess")) as run, \
             patch("subprocess.Popen", side_effect=AssertionError("live Popen")) as popen, \
             patch("urllib.request.urlopen", side_effect=AssertionError("live network")) as network:
            clock.now.side_effect = clock_tick
            try:
                first = self._start_thread()
                self.assertTrue(entered.wait(3), "first discovery never started")
                with self.agent._lock:
                    published = self.agent._refresh_started_at[self.key]
                self.state.reconcile_runtime(
                    self.key, [public_service(self.service)],
                    current_service=public_service(self.service),
                    attempted_at=base.isoformat(),
                )
                self.assertEqual(self.agent.start_refresh(self.key, after_reconcile=True)["existing"], True)
                self.assertEqual(self.agent.start_refresh(self.key, after_reconcile=True)["existing"], True)
                self.assertEqual(self.agent._refresh_again, {self.key})
            finally:
                release.set()
                if first is not None:
                    self._join_all_started()
            self._assert_empty()
            self.assertEqual(discovery.call_count, 4)
            self.assertEqual(checked.call_count, 2)
            self.assertEqual(len(timestamps), 2)
            self.assertEqual(timestamps[0], (published, published))
            self.assertEqual(timestamps[1][0], timestamps[1][1])
            self.assertNotEqual(timestamps[1][0], published)
            # start_refresh also reads wall time for verification freshness;
            # assert the stored attempt timestamps instead of total clock calls.
            run.assert_not_called()
            popen.assert_not_called()
            network.assert_not_called()

        record = self.agent.verification_snapshot()["records"][0]
        self.assertEqual(record["result"]["status"], "CURRENT")
        self.assertTrue(record["fresh"])
        self.assertFalse(record["invalidated"])

    def test_missing_or_replaced_container_never_retries_or_publishes(self):
        changed = replace(self.service, image_id="sha256:" + "f" * 64)
        for scenario, responses, expected_checks in (
            ("absent", [[]], 0),
            ("ambiguous", [[self.service, self.service]], 0),
            ("replaced", [[self.service], [changed]], 1),
            ("disappeared", [[self.service], []], 1),
        ):
            with self.subTest(scenario=scenario):
                # Each scenario has isolated state, preserving the public call path.
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                state = State(Path(tmp.name) / "state")
                agent = ReadOnlyService(self.agent.config, state)
                with patch("docker_update_manager.webservice.discover", side_effect=responses) as discovery, \
                     patch("docker_update_manager.webservice.scan_service_with_tracking",
                           return_value=ScanResult(self.service, "UPDATE", "sha256:" + "3" * 64)) as checked, \
                     patch("subprocess.run", side_effect=AssertionError("live subprocess")) as run, \
                     patch("subprocess.Popen", side_effect=AssertionError("live Popen")) as popen, \
                     patch("urllib.request.urlopen", side_effect=AssertionError("live network")) as network:
                    self.assertEqual(agent.start_refresh(self.key)["status"], "checking")
                    self._join_all_started()
                    self.assertEqual(discovery.call_count, 1 if expected_checks == 0 else 2)
                    self.assertEqual(checked.call_count, expected_checks)
                    self.assertEqual(agent._refresh_threads, {})
                    self.assertEqual(agent._refresh_started_at, {})
                    self.assertEqual(agent._refresh_again, set())
                    run.assert_not_called()
                    popen.assert_not_called()
                    network.assert_not_called()
                self.assertEqual(state.verification_snapshot(), [])
                self.assertEqual(agent.verification_snapshot()["records"], [])
                with self.assertRaises(ValueError):
                    agent.update_review({"service_key": self.key, "requested_by": "admin",
                                         "verification_id": "untrusted"})

    def test_discovery_and_save_exceptions_reach_original_facade_logger(self):
        for failure in ("first_discover", "second_discover", "save"):
            with self.subTest(failure=failure):
                tmp = tempfile.TemporaryDirectory()
                self.addCleanup(tmp.cleanup)
                state = State(Path(tmp.name) / "state")
                agent = ReadOnlyService(self.agent.config, state)
                called = []

                def discovery(_config):
                    called.append(1)
                    if failure == "first_discover" or (failure == "second_discover" and len(called) == 2):
                        raise RuntimeError("token=redaction-sentinel discovery failure")
                    return [self.service]

                def save(*_args, **_kwargs):
                    raise RuntimeError("token=redaction-sentinel disk failure")

                with patch("docker_update_manager.webservice.discover", side_effect=discovery), \
                     patch("docker_update_manager.webservice.scan_service_with_tracking",
                           return_value=ScanResult(self.service, "UPDATE", "sha256:" + "3" * 64)), \
                     patch.object(state, "save_verification", side_effect=save), \
                     patch("subprocess.run", side_effect=AssertionError("live subprocess")) as run, \
                     patch("subprocess.Popen", side_effect=AssertionError("live Popen")) as popen, \
                     patch("urllib.request.urlopen", side_effect=AssertionError("live network")) as network, \
                     self.assertLogs("docker_update_manager.webservice", level="WARNING") as logs:
                    self.assertEqual(agent.start_refresh(self.key)["status"], "checking")
                    self._join_all_started()
                    self.assertEqual(agent._refresh_threads, {})
                    self.assertEqual(agent._refresh_started_at, {})
                    self.assertEqual(agent._refresh_again, set())
                    run.assert_not_called()
                    popen.assert_not_called()
                    network.assert_not_called()
                self.assertTrue(any("Service verification failed for" in msg for msg in logs.output))
                self.assertNotIn("redaction-sentinel", str(logs.output))
                self.assertEqual(state.verification_snapshot(), [])
                # Discover/save failures do not create a cooldown. Do not
                # accidentally allow this retry to contact live Docker.
                with patch("docker_update_manager.webservice.discover", return_value=[]), \
                     patch("subprocess.run", side_effect=AssertionError("live subprocess")) as guarded:
                    self.assertEqual(agent.start_refresh(self.key, after_reconcile=False)["status"], "checking")
                    self._join_all_started()
                    guarded.assert_not_called()
                self.assertEqual(agent._refresh_threads, {})

    def test_registry_projection_exception_remains_safe_registry_error(self):
        with patch("docker_update_manager.webservice.discover", return_value=[self.service]), \
             patch("docker_update_manager.webservice.scan_service_with_tracking",
                   return_value=ScanResult(self.service, "UPDATE", "sha256:" + "3" * 64)), \
             patch("docker_update_manager.webservice._public_result",
                   side_effect=RuntimeError("token=redaction-sentinel")) as projection, \
             patch("subprocess.run", side_effect=AssertionError("live subprocess")) as run, \
             patch("subprocess.Popen", side_effect=AssertionError("live Popen")) as popen, \
             patch("urllib.request.urlopen", side_effect=AssertionError("live network")) as network:
            first = self._start_thread()
            self._join(first)
            self._assert_empty()
            projection.assert_called_once()
            run.assert_not_called()
            popen.assert_not_called()
            network.assert_not_called()
        record = self.agent.verification_snapshot()["records"][0]
        # _safe_error deliberately classifies a token-bearing exception as
        # authentication failure without exposing the exception's contents.
        self.assertEqual(record["error"], "registry authentication failed")
        self.assertNotIn("redaction-sentinel", str(record))
        self.assertEqual(self.agent.refresh_status(self.key)["status"], "failed")
        self.assertEqual(self.agent.start_refresh(self.key)["status"], "retry_later")

    def test_wait_for_scan_only_retries_when_scan_is_active(self):
        calls = []

        def active_scan():
            calls.append(True)
            # start_refresh's original admission guard evaluates active_scan
            # once even for after_reconcile=True. The real worker must then
            # see a scan once and a clear scan once, with no extra loop.
            if len(calls) > 3:
                raise AssertionError("unexpected extra active_scan call")
            return len(calls) == 2

        with patch.object(self.state, "active_scan", side_effect=active_scan), \
             patch("docker_update_manager.webservice.discover", return_value=[]) as discovery, \
             patch("docker_update_manager.webservice.time.sleep") as sleep, \
             patch("subprocess.run", side_effect=AssertionError("live subprocess")) as run:
            first = self._start_thread(after_reconcile=True)
            self._join(first)
            self.assertEqual(len(calls), 3)
            sleep.assert_called_once_with(.2)
            discovery.assert_called_once_with(self.agent.config)
            run.assert_not_called()
            self._assert_empty()

    def test_failed_followup_start_clears_pending_retry(self):
        triggered = []

        def discovery(_config):
            with self.agent._lock:
                self.agent._refresh_again.add(self.key)
            return []

        original = self.agent.start_refresh

        def start(service_key, *, after_reconcile=False):
            if after_reconcile:
                triggered.append(service_key)
                raise RuntimeError("follow-up unavailable")
            return original(service_key, after_reconcile=after_reconcile)

        with patch.object(self.agent, "start_refresh", side_effect=start), \
             patch("docker_update_manager.webservice.discover", side_effect=discovery), \
             patch("subprocess.run", side_effect=AssertionError("live subprocess")) as run, \
             self.assertLogs("docker_update_manager.webservice", level="WARNING") as logged:
            first = self._start_thread()
            self._join(first)
            self._assert_empty()
            self.assertEqual(triggered, [self.key])
            self.assertTrue(any("Post-mutation targeted verification needs retry" in item
                                for item in logged.output))
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
