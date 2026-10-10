"""Focused runtime collector, persistence, and view-merge regressions."""

import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import json
import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest import mock

from docker_update_manager.config import Config
from docker_update_manager.runtime import (
    MAX_RUNTIME_CONTAINERS,
    RUNTIME_INSPECT_TEMPLATE,
    RuntimeProbeError,
    collect_runtime_containers,
    healthcheck_label,
    public_runtime_container,
)
from docker_update_manager.state import State
from docker_update_manager.system import CommandError
from docker_update_manager.webservice import READ_ONLY_OPERATIONS, ReadOnlyService
from docker_update_manager.release_identity import inventory_identity
from docker_update_manager.webviews import attention_items, merge_service_items, runtime_attention, runtime_summary


def container(container_id, *, name="api", stack="media", service="api", state="running",
              healthcheck="healthy", ignored=False, **overrides):
    value = {
        "container_id": container_id,
        "name": name,
        "image": "registry.example/api:1.2.3",
        "stack": stack,
        "compose_service": service,
        "state": state,
        "healthcheck": healthcheck,
        "restart_count": 0,
        "restart_policy": "unless-stopped",
        "started_at": "2026-09-27T09:00:00Z",
        "finished_at": None,
        "exit_code": 0,
        "oom_killed": False,
        "health_failing_streak": 0,
        "health_last_started_at": "2026-09-27T14:00:00Z",
        "health_last_finished_at": "2026-09-27T14:00:01Z",
        "health_last_exit_code": 0,
        "ignored": ignored,
    }
    value.update(overrides)
    return value


def inspect_line(value, *, docker_state=None):
    healthcheck = value["healthcheck"]
    if docker_state is None:
        if value["healthcheck"] == "none":
            health_failing_streak = None
            health_check = None
        else:
            health_failing_streak = value.get("health_failing_streak")
            health_check = {
                "started_at": value.get("health_last_started_at"),
                "finished_at": value.get("health_last_finished_at"),
                "exit_code": value.get("health_last_exit_code"),
            }
    else:
        health = docker_state.get("Health")
        if "Health" not in docker_state:
            healthcheck = "none"
            health_failing_streak = None
            health_check = None
        elif isinstance(health, dict):
            healthcheck = health.get("Status") or "unknown"
            health_failing_streak = health.get("FailingStreak")
            logs = health.get("Log")
            latest = logs[-1] if isinstance(logs, list) and logs else None
            health_check = ({
                "started_at": latest.get("Start"),
                "finished_at": latest.get("End"),
                "exit_code": latest.get("ExitCode"),
            } if isinstance(latest, dict) else None)
        else:
            healthcheck = "unknown"
            health_failing_streak = None
            health_check = None
    return json.dumps({
        "container_id": value["container_id"],
        "name": "/" + value["name"],
        "image": value.get("image"),
        "stack": value.get("stack"),
        "compose_service": value.get("compose_service"),
        "state": value["state"],
        "healthcheck": healthcheck,
        "restart_count": value["restart_count"],
        "restart_policy": value["restart_policy"],
        "started_at": value.get("started_at"),
        "finished_at": value.get("finished_at"),
        "exit_code": value.get("exit_code"),
        "oom_killed": value["oom_killed"],
        "health_failing_streak": health_failing_streak,
        "health_check": health_check,
    })


class RuntimeCollectorTests(unittest.TestCase):
    def test_all_states_use_one_list_and_one_safe_batched_inspect(self):
        running = container("a" * 64)
        stopped = container("b" * 64, name="worker", service="worker", state="exited",
                            healthcheck="none", finished_at="2026-09-27T13:20:00Z", exit_code=137,
                            oom_killed=True, restart_count=3)
        calls = []

        def runner(args, *, timeout):
            calls.append((args, timeout))
            if args[1] == "ps":
                self.assertIn("--all", args)
                self.assertIn("--last", args)
                return running["container_id"] + "\n" + stopped["container_id"] + "\n"
            self.assertEqual(args[1], "inspect")
            self.assertIn("--format", args)
            self.assertIn("--type", args)
            self.assertEqual(args[-2:], [running["container_id"], stopped["container_id"]])
            return inspect_line(running) + "\n" + inspect_line(stopped) + "\n"

        values = collect_runtime_containers(runner=runner)
        self.assertEqual(len(calls), 2)
        self.assertEqual({item["state"] for item in values}, {"running", "exited"})
        stopped_result = next(item for item in values if item["state"] == "exited")
        self.assertTrue(stopped_result["oom_killed"])
        self.assertEqual(stopped_result["exit_code"], 137)
        self.assertEqual(stopped_result["restart_count"], 3)
        self.assertEqual(stopped_result["healthcheck"], "none")
        self.assertIsNone(stopped_result["health_last_exit_code"])
        self.assertNotIn("image inspect", " ".join(calls[1][0]))
        self.assertNotIn("registry", " ".join(calls[1][0]))

    def test_empty_inventory_skips_inspect_and_limit_fails_closed(self):
        calls = []

        def empty_runner(args, *, timeout):
            calls.append(args)
            return ""

        self.assertEqual(collect_runtime_containers(runner=empty_runner), [])
        self.assertEqual(len(calls), 1)

        ids = [f"{index:064x}" for index in range(1, MAX_RUNTIME_CONTAINERS + 2)]

        calls = []

        def full_runner(args, *, timeout):
            calls.append(args[1])
            return "\n".join(ids)

        with self.assertRaises(RuntimeProbeError) as caught:
            collect_runtime_containers(runner=full_runner)
        self.assertEqual(caught.exception.category, "container_limit_exceeded")
        self.assertEqual(calls, ["ps"])

    def test_safe_projection_mapping_and_privacy_allowlist(self):
        raw = container("c" * 64, state="running", healthcheck="none", restart_count=2)
        raw.update({
            "environment": ["PASSWORD=fixture-secret"],
            "labels": {"private.token": "fixture-secret", "com.docker.compose.project": "media"},
            "mounts": ["/host/private:/container"],
            "state_error": "private daemon detail",
            "health_output": "response with fixture-secret",
        })
        safe = public_runtime_container(raw)
        encoded = json.dumps(safe)
        for private in ("fixture-secret", "private daemon detail", "/host/private", "health_output", "environment", "labels"):
            self.assertNotIn(private, encoded)
        self.assertEqual(healthcheck_label(safe), "Running · No healthcheck")
        self.assertNotEqual(safe["healthcheck"], "healthy")
        template = RUNTIME_INSPECT_TEMPLATE
        for forbidden in (".Config.Env", ".State.Error", ".Output", ".Mounts", ".HostConfig.Binds", ".Config.Labels}}"):
            self.assertNotIn(forbidden, template)
        for bounded in ('printf "%.255s" .Name', 'printf "%.512s" .Config.Image',
                        'printf "%.128s" .'):
            self.assertIn(bounded, template)
        self.assertIn('"com.docker.compose.project"', template)
        self.assertIn('"com.docker.compose.service"', template)
        self.assertIn('"health_check":', template)
        self.assertNotIn('"health_checks":', template)
        self.assertIn("$last = .", template)
        self.assertIn('{{$health := index .State "Health"}}', template)
        self.assertIn('index $health "Status"', template)
        self.assertIn('index $health "FailingStreak"', template)
        self.assertIn('index $health "Log"', template)
        self.assertNotIn(".State.Health", template)

    def test_optional_health_fields_cover_absent_statuses_and_empty_logs(self):
        stopped_id = "1" * 64
        no_health_state = {"Status": "exited"}
        self.assertNotIn("Health", no_health_state)
        healthy_id, unhealthy_id, starting_id = "2" * 64, "3" * 64, "4" * 64
        secret_output = "health output fixture secret"
        scenarios = [
            (container(stopped_id, name="stopped", state="exited", healthcheck="none"), no_health_state,
             "none", None, None),
            (container(healthy_id, name="healthy"), {
                "Status": "running", "Health": {"Status": "healthy", "FailingStreak": 0,
                    "Log": [{"Start": "2026-09-27T13:59:00Z", "End": "2026-09-27T13:59:01Z", "ExitCode": 1, "Output": secret_output},
                            {"Start": "2026-09-27T14:00:00Z", "End": "2026-09-27T14:00:01Z", "ExitCode": 0, "Output": secret_output}]},
            }, "healthy", 0, ("2026-09-27T14:00:00Z", "2026-09-27T14:00:01Z", 0)),
            (container(unhealthy_id, name="unhealthy", healthcheck="unhealthy", health_failing_streak=3), {
                "Status": "running", "Health": {"Status": "unhealthy", "FailingStreak": 3,
                    "Log": [{"Start": "2026-09-27T14:00:00Z", "End": "2026-09-27T14:00:01Z", "ExitCode": 1, "Output": secret_output}]},
            }, "unhealthy", 3, ("2026-09-27T14:00:00Z", "2026-09-27T14:00:01Z", 1)),
            (container(starting_id, name="starting", healthcheck="starting"), {
                "Status": "running", "Health": {"Status": "starting", "FailingStreak": 0, "Log": []},
            }, "starting", 0, None),
            (container("5" * 64, name="empty-log"), {
                "Status": "running", "Health": {"Status": "healthy", "FailingStreak": 0, "Log": []},
            }, "healthy", 0, None),
            (container("6" * 64, name="missing-log"), {
                "Status": "running", "Health": {"Status": "healthy", "FailingStreak": 0},
            }, "healthy", 0, None),
        ]
        ids = [item[0]["container_id"] for item in scenarios]
        by_id = {item[0]["container_id"]: (item[0], item[1]) for item in scenarios}

        def runner(args, *, timeout):
            if args[1] == "ps":
                return "\n".join(ids)
            return "\n".join(inspect_line(value, docker_state=state) for value, state in
                              (by_id[cid] for cid in ids))

        collected = collect_runtime_containers(runner=runner)
        values = {item["container_id"]: item for item in collected}
        for fixture, _docker_state, expected_health, expected_streak, expected_log in scenarios:
            with self.subTest(name=fixture["name"]):
                item = values[fixture["container_id"]]
                self.assertEqual(item["healthcheck"], expected_health)
                self.assertEqual(item["health_failing_streak"], expected_streak)
                actual_log = (item["health_last_started_at"], item["health_last_finished_at"],
                              item["health_last_exit_code"])
                self.assertEqual(actual_log, expected_log or (None, None, None))

        encoded = json.dumps(collected)
        self.assertNotIn(secret_output, encoded)
        self.assertNotIn("Output", encoded)
        with tempfile.TemporaryDirectory() as tmp:
            state = State(Path(tmp) / "state")
            state.save_runtime_snapshot(collected)
            with state.read() as connection:
                persisted = connection.execute("SELECT payload FROM runtime_snapshot").fetchone()[0]
            self.assertNotIn(secret_output, persisted)
            self.assertNotIn('"Output"', persisted)

    def test_health_and_container_state_mapping_keeps_states_distinct(self):
        cases = [
            ("running", "healthy", "Running · Healthy", None),
            ("running", "none", "Running · No healthcheck", None),
            ("running", "unhealthy", "Running · Unhealthy", (0, "Unhealthy")),
            ("running", "starting", "Running · Starting", None),
            ("restarting", "none", "No healthcheck", (1, "Restarting")),
            ("exited", "none", "No healthcheck", (1, "Exited")),
            ("paused", "none", "No healthcheck", (1, "Paused")),
            ("dead", "none", "No healthcheck", (0, "Dead")),
            ("created", "none", "No healthcheck", (1, "Created")),
        ]
        for index, (state, health, label, attention) in enumerate(cases, start=1):
            item = public_runtime_container(container(f"{index:064x}", state=state, healthcheck=health))
            with self.subTest(state=state, health=health):
                self.assertEqual(healthcheck_label(item), label)
                self.assertEqual(runtime_attention(item), attention)
                self.assertEqual(item["state"], state)
                self.assertEqual(item["healthcheck"], health)
        self.assertEqual(runtime_attention(container("f" * 64, state="exited", oom_killed=True)), (0, "OOM-killed"))

    def test_config_ignored_policy_is_attached_without_copying_labels(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.yml"
            config_path.write_text("exclude:\n  services: [worker]\n")
            config = Config(path=str(config_path))
            item = container("d" * 64, name="worker", service="worker", state="paused")

            def runner(args, *, timeout):
                return item["container_id"] + "\n" if args[1] == "ps" else inspect_line(item) + "\n"

            found = collect_runtime_containers(config, runner=runner)
            self.assertTrue(found[0]["ignored"])
            self.assertEqual(set(found[0]), {
                "key", "container_id", "name", "stack", "compose_service", "image", "state", "healthcheck",
                "restart_count", "restart_policy", "started_at", "finished_at", "exit_code", "oom_killed",
                "health_failing_streak", "health_last_started_at", "health_last_finished_at",
                "health_last_exit_code", "ignored",
            })

    def test_registry_runtime_collection_failure_is_safe_and_bounded(self):
        def failed(*_args, **_kwargs):
            raise RuntimeError("credential=fixture-secret host=/private/path")

        with self.assertRaises(RuntimeProbeError) as caught:
            collect_runtime_containers(runner=failed)
        self.assertEqual(caught.exception.category, "probe_failed")
        self.assertNotIn("fixture-secret", str(caught.exception))

    def test_command_failure_preserves_only_bounded_diagnostic_metadata(self):
        container_id = "7" * 64

        def runner(args, *, timeout):
            if args[1] == "ps":
                return container_id
            raise CommandError(args, "stderr fixture-secret container=" + container_id, code=1)

        with self.assertRaises(RuntimeProbeError) as caught:
            collect_runtime_containers(runner=runner)
        failure = caught.exception
        self.assertEqual(failure.category, "probe_failed")
        self.assertEqual(failure.stage, "inspect")
        self.assertEqual(failure.failure_class, "CommandError")
        self.assertEqual(failure.exit_code, 1)
        self.assertEqual(str(failure), "probe_failed")
        self.assertNotIn("fixture-secret", repr(failure.__dict__))
        self.assertNotIn(container_id, repr(failure.__dict__))

    def test_disappearing_container_is_relisted_once_and_recovered(self):
        replacement = container("b" * 64, name="api-new")
        calls = []

        def runner(args, *, timeout):
            calls.append(args[1])
            if args[1] == "ps":
                return ("a" if calls.count("ps") == 1 else "b") * 64 + "\n"
            if calls.count("inspect") == 1:
                raise RuntimeError("Error: No such container: " + "a" * 12)
            return inspect_line(replacement) + "\n"

        found = collect_runtime_containers(runner=runner)
        self.assertEqual([item["container_id"] for item in found], ["b" * 64])
        self.assertEqual(calls, ["ps", "inspect", "ps", "inspect"])

    def test_repeated_inventory_churn_stops_after_one_retry(self):
        calls = []

        def runner(args, *, timeout):
            calls.append(args[1])
            if args[1] == "ps":
                return ("a" if calls.count("ps") == 1 else "b") * 64 + "\n"
            raise RuntimeError("No such container")

        with self.assertRaises(RuntimeProbeError) as caught:
            collect_runtime_containers(runner=runner)
        self.assertEqual(caught.exception.category, "inventory_changed")
        self.assertEqual(calls, ["ps", "inspect", "ps", "inspect"])
        self.assertEqual(calls.count("ps"), 2)
        self.assertEqual(calls.count("inspect"), 2)

    def test_only_daemon_access_failure_is_classified_unavailable(self):
        for fail_at in ("ps", "inspect"):
            calls = []

            def daemon_down(args, *, timeout):
                calls.append(args[1])
                if args[1] == fail_at:
                    raise RuntimeError("Cannot connect to the Docker daemon at unix:///run/docker.sock")
                return "a" * 64 + "\n"

            with self.subTest(fail_at=fail_at), self.assertRaises(RuntimeProbeError) as caught:
                collect_runtime_containers(runner=daemon_down)
            self.assertEqual(caught.exception.category, "docker_unavailable")
            self.assertEqual(calls, ["ps"] if fail_at == "ps" else ["ps", "inspect"])

    def test_cli_and_probe_timeouts_are_not_misreported_as_daemon_unavailable(self):
        for failure in (FileNotFoundError("docker executable missing"), TimeoutError("Docker command timed out")):
            with self.subTest(failure=type(failure).__name__):
                def failed(*_args, **_kwargs):
                    raise failure

                with self.assertRaises(RuntimeProbeError) as caught:
                    collect_runtime_containers(runner=failed)
                self.assertEqual(caught.exception.category, "probe_failed")

        calls = []

        for failure in (TimeoutError("inspect command timed out"), RuntimeError("generic inspect command failure"),
                        PermissionError("permission denied reading Docker socket")):
            calls.clear()

            def inspect_failed(args, *, timeout):
                calls.append(args[1])
                if args[1] == "ps":
                    return "a" * 64 + "\n"
                raise failure

            with self.subTest(failure=type(failure).__name__), self.assertRaises(RuntimeProbeError) as caught:
                collect_runtime_containers(runner=inspect_failed)
            self.assertEqual(caught.exception.category, "probe_failed")
            self.assertEqual(calls, ["ps", "inspect"])

    def test_malformed_inspect_response_is_invalid_and_is_not_retried(self):
        for response in ("{not valid json\n", json.dumps({"unexpected": "shape"}), b"not text"):
            calls = []

            def malformed(args, *, timeout):
                calls.append(args[1])
                return "a" * 64 + "\n" if args[1] == "ps" else response

            with self.subTest(response=type(response).__name__), self.assertRaises(RuntimeProbeError) as caught:
                collect_runtime_containers(runner=malformed)
            self.assertEqual(caught.exception.category, "invalid_docker_response")
            self.assertEqual(calls, ["ps", "inspect"])

    def test_inspect_id_set_mismatch_is_retried_once(self):
        calls = []
        replacement = container("b" * 64, name="replacement")

        def runner(args, *, timeout):
            calls.append(args[1])
            if args[1] == "ps":
                return ("a" if calls.count("ps") == 1 else "b") * 64 + "\n"
            return inspect_line(replacement) + "\n"

        self.assertEqual(collect_runtime_containers(runner=runner)[0]["container_id"], replacement["container_id"])
        self.assertEqual(calls, ["ps", "inspect", "ps", "inspect"])

    def test_inspect_text_no_such_object_is_retried_once(self):
        calls = []
        item = container("a" * 64)

        def runner(args, *, timeout):
            calls.append(args[1])
            if args[1] == "ps":
                return item["container_id"] + "\n"
            if calls.count("inspect") == 1:
                return "Error: No such object: " + item["container_id"]
            return inspect_line(item) + "\n"

        self.assertEqual(collect_runtime_containers(runner=runner)[0]["container_id"], item["container_id"])
        self.assertEqual(calls, ["ps", "inspect", "ps", "inspect"])


class RuntimePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = State(Path(self.temp.name) / "state")

    def test_latest_success_freshness_failure_retention_and_recovery(self):
        captured = "2026-09-27T14:00:00+00:00"
        self.state.save_runtime_snapshot([container("e" * 64)], captured_at=captured)
        current = self.state.runtime_snapshot(now="2026-09-27T14:01:00+00:00")
        self.assertEqual(current["status"], "current")
        self.assertTrue(current["available"])
        self.assertEqual(current["containers"][0]["container_id"], "e" * 64)

        categories = ("docker_unavailable", "inventory_changed", "probe_failed",
                      "invalid_docker_response", "container_limit_exceeded")
        for category in categories:
            with self.subTest(category=category):
                self.state.record_runtime_failure(
                    attempted_at="2026-09-27T14:02:00+00:00", failure_category=category,
                )
                failed = self.state.runtime_snapshot(now="2026-09-27T14:02:01+00:00")
                self.assertEqual(failed["status"], "unavailable")
                self.assertFalse(failed["available"])
                self.assertTrue(failed["stale"])
                self.assertEqual(failed["failure_category"], category)
                self.assertEqual(failed["captured_at"], captured)
                self.assertEqual(failed["last_success_at"], captured)
                self.assertEqual(failed["attempted_at"], "2026-09-27T14:02:00+00:00")
                self.assertEqual(failed["containers"][0]["container_id"], "e" * 64)

        stale = self.state.runtime_snapshot(now="2026-09-27T14:02:00+00:00", stale_after_seconds=90)
        self.assertTrue(stale["stale"])
        self.assertEqual(stale["status"], "unavailable")

        self.state.save_runtime_snapshot([container("f" * 64, healthcheck="none")],
                                         captured_at="2026-09-27T14:03:00+00:00")
        recovered = self.state.runtime_snapshot(now="2026-09-27T14:03:10+00:00")
        self.assertEqual(recovered["status"], "current")
        self.assertIsNone(recovered["failure_category"])
        self.assertEqual(recovered["containers"][0]["healthcheck"], "none")

        too_old = self.state.runtime_snapshot(now="2026-09-27T14:05:00+00:00")
        self.assertEqual(too_old["status"], "stale")
        self.assertTrue(too_old["stale"])

    def test_never_checked_state_and_database_privacy(self):
        never = self.state.runtime_snapshot(now="2026-09-27T14:00:00+00:00")
        self.assertEqual(never["status"], "never")
        self.state.save_runtime_snapshot([container("1" * 64)])
        with self.state.read() as connection:
            raw = connection.execute("SELECT payload FROM runtime_snapshot").fetchone()[0]
            version = connection.execute("SELECT version FROM schema_version").fetchone()[0]
        self.assertEqual(version, 9)
        for forbidden in ("environment", "labels", "mounts", "health_output", "State.Error"):
            self.assertNotIn(forbidden, raw)


class RuntimeViewMergeTests(unittest.TestCase):
    def test_trusted_scan_channel_is_displayed_only_for_exact_runtime_identity(self):
        original = "a" * 64
        target_image = "registry.example/api:1.2.4@sha256:" + "2" * 64
        scan = {"status": "complete", "finished_at": "2026-09-27T14:00:00+00:00",
                "payload": {"services": [{"service": {
                    "key": "container/" + original, "container_id": original,
                    "name": "api", "stack": "media", "compose_service": "api",
                    "image": "registry.example/api@sha256:" + "1" * 64,
                }, "status": "PINNED UPDATE", "tracking_tag": "1.2.4", "target_image": target_image}]}}
        exact = merge_service_items(scan, {"status": "current", "containers": [container(original)]})
        self.assertEqual(exact[0]["tracking_tag"], "1.2.4")
        # Finding 6: the bounded, server-projected target identity is retained
        # for an exact scan/runtime identity so Services can show the target tag.
        self.assertEqual(exact[0]["target_image"], target_image)
        self.assertEqual(inventory_identity(exact[0]), "Target tag 1.2.4")
        replaced = merge_service_items(scan, {"status": "current", "containers": [container("b" * 64)]})
        self.assertEqual(replaced[0]["status"], "CHECK REQUIRED")
        self.assertIsNone(replaced[0]["tracking_tag"])
        self.assertIsNone(replaced[0]["target_image"])

    def test_runtime_summary_never_counts_no_healthcheck_as_healthy(self):
        summary = runtime_summary({"containers": [
            container("2" * 64, healthcheck="healthy"),
            container("3" * 64, name="plain", service="plain", healthcheck="none"),
            container("4" * 64, name="bad", service="bad", healthcheck="unhealthy"),
        ]})
        self.assertEqual(summary["running"], 3)
        self.assertEqual(summary["healthy"], 1)
        self.assertEqual(summary["no_healthcheck"], 1)
        self.assertEqual(summary["unhealthy"], 1)
        self.assertEqual(summary["attention"], 1)

    def test_starting_healthcheck_is_factual_summary_only(self):
        summary = runtime_summary({"containers": [
            container("1" * 64, healthcheck="starting"),
        ]})
        self.assertEqual(summary["starting"], 1)
        self.assertEqual(summary["healthy"], 0)
        self.assertEqual(summary["unhealthy"], 0)
        self.assertEqual(summary["attention"], 0)

    def test_duplicate_compose_names_merge_by_container_id_and_attention_deduplicates(self):
        scan = {
            "status": "complete", "finished_at": "2026-09-27T14:00:00+00:00",
            "payload": {"services": [
                {"service": {"key": "container/" + "5" * 64, "container_id": "5" * 64, "name": "web", "stack": "a", "compose_service": "web", "image": "repo/web:1", "state": "running"}, "status": "UPDATE", "remote_version": "2"},
                {"service": {"key": "container/" + "6" * 64, "container_id": "6" * 64, "name": "web", "stack": "b", "compose_service": "web", "image": "repo/web:1", "state": "running"}, "status": "CURRENT"},
                {"service": {"key": "container/" + "7" * 64, "container_id": "7" * 64, "name": "registry", "stack": "a", "compose_service": "registry", "state": "running"}, "status": "REGISTRY ERROR"},
            ]},
        }
        runtime = {"status": "current", "stale": False, "containers": [
            container("5" * 64, name="web", stack="a", service="web", healthcheck="unhealthy"),
            container("6" * 64, name="web", stack="b", service="web", healthcheck="healthy"),
            container("7" * 64, name="registry", stack="a", service="registry"),
            container("8" * 64, name="worker", stack="c", service="worker", state="exited", healthcheck="none", oom_killed=True),
        ]}
        merged = merge_service_items(scan, runtime)
        self.assertEqual(len(merged), 4)
        update_and_runtime = next(item for item in merged if item["service"].get("container_id") == "5" * 64)
        self.assertEqual(update_and_runtime["status"], "UPDATE")
        self.assertEqual(update_and_runtime["runtime"]["healthcheck"], "unhealthy")
        runtime_only = next(item for item in merged if item["service"].get("container_id") == "8" * 64)
        self.assertEqual(runtime_only["status"], "NOT SCANNED")
        self.assertTrue(runtime_only["runtime_only"])
        self.assertNotIn("working_dir", runtime_only["service"])

        attention = attention_items(merged, runtime, limit=20)
        self.assertEqual(len(attention), 3)
        self.assertEqual(attention[0]["runtime_issue"], "Unhealthy")
        self.assertTrue(attention[0]["maintenance_attention"])
        self.assertEqual(attention[1]["runtime_issue"], "OOM-killed")
        self.assertEqual(attention[2]["status"], "REGISTRY ERROR")

    def test_current_runtime_exclusion_survives_an_older_scan_record(self):
        container_id = "a" * 64
        scan = {
            "status": "complete", "finished_at": "2026-09-27T14:00:00+00:00",
            "payload": {"services": [{"service": {
                "key": "container/" + container_id, "container_id": container_id,
                "name": "worker", "stack": "media", "compose_service": "worker",
                "image": "registry.example/worker:1", "ignored": False,
            }, "status": "UPDATE"}]},
        }
        merged = merge_service_items(scan, {"status": "current", "containers": [
            container(container_id, name="worker", service="worker", ignored=True),
        ]})
        self.assertTrue(merged[0]["service"]["ignored"])

    @staticmethod
    def _identity_scan(*services):
        return {"status": "complete", "finished_at": "2026-09-27T14:00:00Z",
                "payload": {"services": list(services)}}

    @staticmethod
    def _scanned(container_id, *, name="api", stack="media", compose_service="api", status="UPDATE"):
        return {"service": {
            "key": "container/" + container_id, "container_id": container_id,
            "name": name, "stack": stack, "compose_service": compose_service,
            "image": "registry.example/old:1", "version": "1", "state": "running",
            "working_dir": "/opt/private-compose", "compose_files": ["/opt/private-compose/compose.yml"],
            "local_build": False, "digest": "sha256:" + "1" * 64,
        }, "status": status, "remote_version": "2", "remote_digest": "sha256:" + "2" * 64,
            "target_image": "registry.example/new:2"}

    def test_exact_id_is_strongest_match(self):
        original = "a" * 64
        merged = merge_service_items(
            self._identity_scan(self._scanned(original)),
            {"status": "current", "containers": [container(original, healthcheck="unhealthy")]},
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["service"]["container_id"], original)
        self.assertEqual(merged[0]["status"], "UPDATE")
        self.assertEqual(merged[0]["runtime"]["healthcheck"], "unhealthy")
        self.assertFalse(merged[0]["runtime_missing"])
        self.assertFalse(merged[0].get("runtime_reconciled", False))

    def test_unique_current_compose_recreation_discards_old_mutation_authority(self):
        old_id, new_id = "a" * 64, "b" * 64
        merged = merge_service_items(
            self._identity_scan(self._scanned(old_id)),
            {"status": "current", "containers": [container(new_id, name="api-new", healthcheck="starting")]},
        )
        self.assertEqual(len(merged), 1)
        replacement = merged[0]
        self.assertEqual(replacement["service"]["container_id"], new_id)
        self.assertEqual(replacement["runtime"]["container_id"], new_id)
        self.assertEqual(replacement["status"], "CHECK REQUIRED")
        self.assertTrue(replacement["runtime_reconciled"])
        self.assertFalse(replacement["runtime_missing"])
        self.assertIsNone(replacement["remote_version"])
        self.assertIsNone(replacement["remote_digest"])
        for forbidden in ("working_dir", "compose_files", "digest", "version", "target_image", "local_build"):
            self.assertNotIn(forbidden, replacement["service"])
        attention = attention_items(merged, {"status": "current"}, limit=4)
        self.assertEqual(len(attention), 1)
        self.assertEqual(attention[0]["attention_rank"], 1)

    def test_duplicate_service_names_in_different_stacks_reconcile_independently(self):
        scanned = self._identity_scan(
            self._scanned("a" * 64, stack="alpha"),
            self._scanned("c" * 64, stack="beta"),
        )
        runtime = {"status": "current", "containers": [
            container("b" * 64, name="api-alpha", stack="alpha", service="api"),
            container("d" * 64, name="api-beta", stack="beta", service="api"),
        ]}
        merged = merge_service_items(scanned, runtime)
        self.assertEqual(len(merged), 2)
        self.assertEqual({item["service"]["container_id"] for item in merged}, {"b" * 64, "d" * 64})
        self.assertTrue(all(item["runtime_reconciled"] for item in merged))

    def test_ambiguous_scaled_identities_are_never_guessed(self):
        scan = self._identity_scan(self._scanned("a" * 64))
        runtime = {"status": "current", "containers": [
            container("b" * 64), container("c" * 64, name="api_2"),
        ]}
        merged = merge_service_items(scan, runtime)
        self.assertEqual(len(merged), 3)
        old = next(item for item in merged if item["service"]["container_id"] == "a" * 64)
        self.assertTrue(old["runtime_missing"])
        self.assertTrue(all(item.get("runtime_only") for item in merged if item["service"]["container_id"] != "a" * 64))

        two_scanned = self._identity_scan(self._scanned("a" * 64), self._scanned("d" * 64))
        ambiguous_scan = merge_service_items(two_scanned, {"status": "current", "containers": [container("e" * 64)]})
        self.assertEqual(len(ambiguous_scan), 3)
        self.assertEqual(sum(bool(item.get("runtime_reconciled")) for item in ambiguous_scan), 0)

    def test_removed_current_container_is_explicit_and_stale_absence_is_not_inferred(self):
        scan = self._identity_scan(self._scanned("a" * 64, status="CURRENT"))
        current = merge_service_items(scan, {"status": "current", "containers": []})
        self.assertTrue(current[0]["runtime_missing"])
        attention = attention_items(current, {"status": "current"})
        self.assertEqual(attention[0]["runtime_issue"], "Not present in current Docker runtime")

        stale = merge_service_items(scan, {"status": "unavailable", "stale": True, "containers": []})
        self.assertFalse(stale[0]["runtime_missing"])
        self.assertIsNone(stale[0]["runtime"])

    def test_stale_runtime_issues_are_marked_last_known(self):
        item = {"service": {"key": "container/9" + "9" * 63, "container_id": "9" * 64, "name": "old", "stack": None},
                "status": "NOT SCANNED", "runtime": container("9" * 64, state="exited", healthcheck="none"),
                "runtime_stale": True, "runtime_only": True}
        attention = attention_items([item], {"status": "unavailable", "stale": True}, limit=3)
        self.assertEqual(attention[0]["runtime_issue_label"], "Last known · Exited")


class RuntimeAgentBoundaryTests(unittest.TestCase):
    def test_runtime_snapshot_is_cached_read_only_agent_operation(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = State(Path(tmp) / "state")
            expected = container("a" * 64)
            state.save_runtime_snapshot([expected])
            service = ReadOnlyService(Config(path=str(Path(tmp) / "missing.yml")), state)
            with mock.patch("docker_update_manager.webservice.collect_runtime_containers", side_effect=AssertionError("Docker probe from request")):
                self.assertIn("runtime_snapshot", READ_ONLY_OPERATIONS)
                response = service.handle("runtime_snapshot")
            self.assertEqual(response["containers"][0]["container_id"], "a" * 64)

    def test_one_background_monitor_owns_immediate_runtime_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = ReadOnlyService(Config(path=str(Path(tmp) / "missing.yml")), State(Path(tmp) / "state"))
            refreshed = Event()
            service._docker_health = mock.Mock(return_value={"ok": True, "version": "fixture"})
            service._refresh_runtime_snapshot = mock.Mock(side_effect=refreshed.set)
            service.start_health_monitor(interval_seconds=30)
            thread = service._health_thread
            service.start_health_monitor(interval_seconds=30)
            self.assertIs(service._health_thread, thread)
            self.assertTrue(refreshed.wait(2))
            service.stop_health_monitor()
            self.assertEqual(service._refresh_runtime_snapshot.call_count, 1)

    def test_runtime_probe_and_persistence_logs_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = State(Path(tmp) / "state")
            service = ReadOnlyService(Config(path=str(Path(tmp) / "missing.yml")), state)
            probe_failure = RuntimeProbeError(
                "probe_failed", stage="inspect", failure_class="CommandError", exit_code=1,
            )
            probe_failure.__context__ = CommandError(
                ["docker", "inspect", "secret-container-id"],
                "raw stderr PASSWORD=fixture-secret /private/mount",
            )
            with mock.patch("docker_update_manager.webservice.collect_runtime_containers", side_effect=probe_failure):
                with mock.patch.object(state, "record_runtime_failure", side_effect=OSError("SQLite path /private/state")):
                    with self.assertLogs("docker_update_manager.webservice", level="WARNING") as captured:
                        service._refresh_runtime_snapshot()
            output = "\n".join(captured.output)
            self.assertIn("stage=inspect category=probe_failed failure_class=CommandError exit_code=1", output)
            self.assertIn("Runtime failure persistence failed stage=persist", output)
            for private in ("fixture-secret", "/private", "raw stderr", "secret-container-id", "password"):
                self.assertNotIn(private.lower(), output.lower())

            with mock.patch("docker_update_manager.webservice.collect_runtime_containers", return_value=[]):
                with mock.patch.object(state, "save_runtime_snapshot", side_effect=OSError("SQLite path /private/state")):
                    with self.assertLogs("docker_update_manager.webservice", level="WARNING") as captured:
                        service._refresh_runtime_snapshot()
            output = "\n".join(captured.output)
            self.assertIn("Runtime snapshot persistence failed stage=persist failure_class=OSError", output)
            self.assertNotIn("/private", output)


if __name__ == "__main__":
    unittest.main()
