"""Bounded, privacy-filtered Docker container runtime collection."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from types import SimpleNamespace

from .system import run

RUNTIME_INTERVAL_SECONDS = 30
RUNTIME_STALE_AFTER_SECONDS = 90
MAX_RUNTIME_CONTAINERS = 512
_CONTAINER_ID = re.compile(r"^[a-fA-F0-9]{12,64}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SAFE_POLICY = re.compile(r"^[A-Za-z0-9_.:-]{0,64}$")
_SAFE_TIMESTAMP = re.compile(r"^[0-9TtZz:+.\-]{0,64}$")
_SAFE_STATE = re.compile(r"^[a-z0-9_-]{1,32}$")
_SAFE_FAILURE_CLASS = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_RUNTIME_FAILURE_CATEGORIES = frozenset({
    "docker_unavailable", "inventory_changed", "probe_failed",
    "invalid_docker_response", "container_limit_exceeded",
})
_RUNTIME_FAILURE_STAGES = frozenset({"list", "inspect", "parse", "reconcile", "collect"})

# Docker renders only these allowlisted fields. In particular, this template
# never asks the CLI to serialize Config.Env, Config.Labels, State.Error,
# State.Health.Log[].Output, HostConfig.Binds, or Mounts.
RUNTIME_INSPECT_TEMPLATE = r'''{{$health := index .State "Health"}}{"container_id":{{json .Id}},"name":{{json (printf "%.255s" .Name)}},"image":{{json (printf "%.512s" .Config.Image)}},"state":{{json (printf "%.32s" .State.Status)}},"healthcheck":{{if $health}}{{if index $health "Status"}}{{json (printf "%.32s" (index $health "Status"))}}{{else}}"unknown"{{end}}{{else}}"none"{{end}},"restart_count":{{json .RestartCount}},"restart_policy":{{json (printf "%.64s" .HostConfig.RestartPolicy.Name)}},"started_at":{{json (printf "%.64s" .State.StartedAt)}},"finished_at":{{json (printf "%.64s" .State.FinishedAt)}},"exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}},"health_failing_streak":{{if $health}}{{json (index $health "FailingStreak")}}{{else}}null{{end}},"health_check":{{if $health}}{{$logs := index $health "Log"}}{{if $logs}}{{$last := index $logs 0}}{{range $logs}}{{$last = .}}{{end}}{"started_at":{{with index $last "Start"}}{{json (printf "%.64s" .)}}{{else}}null{{end}},"finished_at":{{with index $last "End"}}{{json (printf "%.64s" .)}}{{else}}null{{end}},"exit_code":{{json (index $last "ExitCode")}}}{{else}}null{{end}}{{else}}null{{end}},"stack":{{with index .Config.Labels "com.docker.compose.project"}}{{json (printf "%.128s" .)}}{{else}}null{{end}},"compose_service":{{with index .Config.Labels "com.docker.compose.service"}}{{json (printf "%.128s" .)}}{{else}}null{{end}}}'''

RUNTIME_CONTAINER_FIELDS = (
    "key", "container_id", "name", "stack", "compose_service", "image",
    "state", "healthcheck", "restart_count", "restart_policy", "started_at",
    "finished_at", "exit_code", "oom_killed", "health_failing_streak",
    "health_last_started_at", "health_last_finished_at", "health_last_exit_code",
    "ignored",
)


class RuntimeProbeError(RuntimeError):
    """A safe, stable category for a failed local Docker runtime probe."""

    def __init__(self, category: str, *, stage="collect", failure_class="RuntimeProbeError", exit_code=None):
        self.category = category if category in _RUNTIME_FAILURE_CATEGORIES else "probe_failed"
        self.stage = stage if stage in _RUNTIME_FAILURE_STAGES else "collect"
        candidate_class = str(failure_class)
        self.failure_class = candidate_class if _SAFE_FAILURE_CLASS.fullmatch(candidate_class) else "UnknownError"
        self.exit_code = exit_code if type(exit_code) is int and -255 <= exit_code <= 255 else None
        super().__init__(self.category)


def _runtime_probe_error(category: str, stage: str, error: Exception | None = None, *, failure_class=None):
    candidate_class = failure_class or (type(error).__name__ if error is not None else "RuntimeProbeError")
    exit_code = None
    if error is not None:
        for attribute in ("code", "returncode", "exit_code"):
            try:
                candidate_code = getattr(error, attribute, None)
            except Exception:
                continue
            if type(candidate_code) is int and -255 <= candidate_code <= 255:
                exit_code = candidate_code
                break
    return RuntimeProbeError(category, stage=stage, failure_class=candidate_class, exit_code=exit_code)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _text(value, limit: int, pattern: re.Pattern | None = None) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > limit or any(ord(char) < 32 or ord(char) == 127 for char in value):
        return None
    if pattern is not None and not pattern.fullmatch(value):
        return None
    return value


def _integer(value, *, minimum=0, maximum=2**31 - 1) -> int | None:
    if type(value) is not int or value < minimum or value > maximum:
        return None
    return value


def _timestamp(value) -> str | None:
    value = _text(value, 64, _SAFE_TIMESTAMP)
    return None if value and value.startswith("0001-01-01") else value


def public_runtime_container(value: dict) -> dict:
    """Rebuild a container record from the strict safe runtime field list."""
    if not isinstance(value, dict):
        return {}
    container_id = _text(value.get("container_id"), 64, _CONTAINER_ID)
    if not container_id:
        return {}
    name = _text(str(value.get("name") or "").lstrip("/"), 255, _SAFE_NAME) or container_id[:12]
    image = _text(value.get("image"), 512)
    if image and any(char.isspace() for char in image):
        image = None
    stack = _text(value.get("stack"), 128, _SAFE_LABEL)
    compose_service = _text(value.get("compose_service"), 128, _SAFE_LABEL)
    state = _text(value.get("state"), 32, _SAFE_STATE) or "unknown"
    healthcheck = _text(value.get("healthcheck"), 32, _SAFE_STATE) or "unknown"
    if healthcheck not in {"healthy", "unhealthy", "starting", "none", "unknown"}:
        healthcheck = "unknown"
    latest_check = value.get("health_check")
    if not isinstance(latest_check, dict):
        checks = value.get("health_checks")
        latest_check = checks[-1] if isinstance(checks, list) and checks and isinstance(checks[-1], dict) else {}
    result = {
        "key": f"container/{container_id}",
        "container_id": container_id,
        "name": name,
        "stack": stack,
        "compose_service": compose_service,
        "image": image,
        "state": state,
        "healthcheck": healthcheck,
        "restart_count": _integer(value.get("restart_count")),
        "restart_policy": _text(value.get("restart_policy"), 64, _SAFE_POLICY) or "no",
        "started_at": _timestamp(value.get("started_at")),
        "finished_at": _timestamp(value.get("finished_at")),
        "exit_code": _integer(value.get("exit_code"), minimum=-1),
        "oom_killed": value.get("oom_killed") if type(value.get("oom_killed")) is bool else False,
        "health_failing_streak": _integer(value.get("health_failing_streak")),
        "health_last_started_at": _timestamp(latest_check.get("started_at", value.get("health_last_started_at"))),
        "health_last_finished_at": _timestamp(latest_check.get("finished_at", value.get("health_last_finished_at"))),
        "health_last_exit_code": _integer(latest_check.get("exit_code", value.get("health_last_exit_code")), minimum=-1),
        "ignored": value.get("ignored") if type(value.get("ignored")) is bool else False,
    }
    return result


def _daemon_unavailable(error: Exception) -> bool:
    message = str(error).lower()
    # A permission denial says the local probe could not access Docker; it does
    # not establish that the daemon itself is unavailable.
    if any(marker in message for marker in ("permission denied", "operation not permitted", "access is denied")):
        return False
    return any(marker in message for marker in (
        "cannot connect to the docker daemon", "is the docker daemon running",
        "error during connect", "failed to connect to docker", "cannot connect to docker.sock",
        "could not connect to docker.sock", "dial unix",
    ))


def _missing_inspected_object(message: str) -> bool:
    """Recognise Docker's explicit inspect response for an object that vanished."""
    return re.search(r"\bno such (?:container|object)\b", message, re.IGNORECASE) is not None


def _listed_ids(runner) -> list[str]:
    try:
        listed = runner(
            ["docker", "ps", "--all", "--quiet", "--no-trunc", "--last", str(MAX_RUNTIME_CONTAINERS + 1)],
            timeout=10,
        )
    except Exception as exc:
        category = "docker_unavailable" if _daemon_unavailable(exc) else "probe_failed"
        raise _runtime_probe_error(category, "list", exc) from None
    if not isinstance(listed, str):
        raise _runtime_probe_error("invalid_docker_response", "parse", failure_class="InvalidDockerResponse")
    ids = list(dict.fromkeys(line.strip() for line in listed.splitlines() if line.strip()))
    if len(ids) > MAX_RUNTIME_CONTAINERS:
        raise _runtime_probe_error("container_limit_exceeded", "list", failure_class="ContainerLimitExceeded")
    if any(not _CONTAINER_ID.fullmatch(container_id) for container_id in ids):
        raise _runtime_probe_error("invalid_docker_response", "parse", failure_class="InvalidContainerId")
    return ids


def _inspect_inventory(ids: list[str], config, runner) -> list[dict]:
    try:
        output = runner(
            ["docker", "inspect", "--type", "container", "--format", RUNTIME_INSPECT_TEMPLATE, *ids],
            timeout=20,
        )
    except Exception as exc:
        if _daemon_unavailable(exc):
            raise _runtime_probe_error("docker_unavailable", "inspect", exc) from None
        if _missing_inspected_object(str(exc)):
            # This is positive evidence that the listed object disappeared.
            raise _runtime_probe_error("inventory_changed", "inspect", exc) from None
        raise _runtime_probe_error("probe_failed", "inspect", exc) from None
    if not isinstance(output, str):
        raise _runtime_probe_error("invalid_docker_response", "parse", failure_class="InvalidDockerResponse")
    if _missing_inspected_object(output):
        raise _runtime_probe_error("inventory_changed", "inspect", failure_class="MissingObjectResponse")
    try:
        inspected = [json.loads(line) for line in output.splitlines() if line.strip()]
    except json.JSONDecodeError as exc:
        raise _runtime_probe_error("invalid_docker_response", "parse", exc) from None
    result = []
    seen = set()
    duplicate_id = False
    for item in inspected:
        if not isinstance(item, dict):
            raise _runtime_probe_error("invalid_docker_response", "parse", failure_class="InvalidDockerResponse")
        name = _text(str(item.get("name") or "").lstrip("/"), 255, _SAFE_NAME)
        compose_service = _text(item.get("compose_service"), 128, _SAFE_LABEL)
        stack = _text(item.get("stack"), 128, _SAFE_LABEL)
        service = SimpleNamespace(
            key=compose_service or name or "unknown",
            image=item.get("image") if isinstance(item.get("image"), str) else "",
            stack=stack,
        )
        try:
            ignored = bool(config and config.ignored(service))
        except Exception:
            # An exclusion lookup must not make Docker inventory incomplete.
            ignored = False
        item["ignored"] = ignored
        safe = public_runtime_container(item)
        if not safe:
            raise _runtime_probe_error("invalid_docker_response", "parse", failure_class="InvalidDockerResponse")
        if safe["container_id"] in seen:
            duplicate_id = True
        seen.add(safe["container_id"])
        result.append(safe)
    if duplicate_id or seen != set(ids) or len(result) != len(ids):
        raise _runtime_probe_error("inventory_changed", "reconcile", failure_class="InventoryMismatch")
    return sorted(result, key=lambda item: ((item.get("stack") or "~standalone"), item["name"].lower(), item["container_id"]))


def collect_runtime_containers(config=None, runner=run) -> list[dict]:
    """Collect a coherent inventory with at most one list/inspect retry.

    Each attempt uses one bounded `docker ps --all` and, for a non-empty
    inventory, one allowlisted batched inspect. Only positive inventory churn
    is retried once; all other failure categories are returned without retry.
    """
    for attempt in range(2):
        ids = _listed_ids(runner)
        if not ids:
            return []
        try:
            return _inspect_inventory(ids, config, runner)
        except RuntimeProbeError as exc:
            if attempt == 0 and exc.category == "inventory_changed":
                continue
            raise
    raise RuntimeProbeError("inventory_changed")


def healthcheck_label(container: dict) -> str:
    """Return factual healthcheck text without promoting missing checks."""
    state = str(container.get("state") or "unknown").lower()
    health = str(container.get("healthcheck") or "unknown").lower()
    if state == "running" and health == "none":
        return "Running · No healthcheck"
    if health == "none":
        return "No healthcheck"
    return f"{state.title()} · {health.title()}"
