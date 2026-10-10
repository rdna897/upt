"""Pure server-side merges for independent scan and runtime view models."""

from __future__ import annotations

from .registry import LOCAL_DIGEST_UNVERIFIED

from .runtime import public_runtime_container

_ERROR_ATTENTION = {"REGISTRY ERROR", "UNKNOWN", "ARCH UNSUPPORTED", "UNTRACKED DIGEST", "CHECK REQUIRED"}
_UPDATE_ATTENTION = {"UPDATE", "DIGEST CHANGED", "PINNED UPDATE"}
_MAINTENANCE_LABELS = {
    "NOT SCANNED": "Not scanned",
    "CHECK REQUIRED": "Check required",
    "REGISTRY ERROR": "Registry error",
    "ARCH UNSUPPORTED": "Architecture unsupported",
    "UNTRACKED DIGEST": "Tracking unavailable",
    "DIGEST CHANGED": "Digest changed",
    "PINNED UPDATE": "Pinned update",
}
_RUNTIME_FAILURE_MESSAGES = {
    "docker_unavailable": "Docker runtime unavailable",
    "inventory_changed": "Docker inventory changed during the runtime check",
    "probe_failed": "The Docker runtime check could not be completed",
    "invalid_docker_response": "Docker returned an invalid runtime response",
    "container_limit_exceeded": "The Docker runtime inventory exceeds UPT's monitoring limit",
}


SCAN_SERVICE_EVENT_KINDS = ("task_started", "task_completed", "task_failed")
SCAN_PROGRESS_RECENT_LIMIT = 4


def scan_progress_projection(events: list[dict] | None, label=lambda status: status) -> dict:
    """Project persisted scan events into one progress row per checked service.

    Presentation only: persisted events, their IDs and the SSE cursor are not
    changed. `static/app.js` (`projectScanEvent`/`visibleScanRows`) applies
    the same rules to live events so a reload and a live stream render the same
    rows in the same order.

    - Rows are keyed by the run-local `payload.index` plus the event's service
      key, so two services that share a Compose name remain separate rows.
    - `task_started` creates/activates a row; `task_completed`/`task_failed`
      finalise the same row. A finished row never returns to active, and events
      at or below the last applied event ID are ignored (replay safety).
    - Global events (operation, discovery, finalisation, warnings) only change
      the headline stage; they never become service rows.
    - Visible rows: every active row, then the most recent finished rows.
    """
    rows: dict[str, dict] = {}
    stage = None
    cursor = 0
    ordered = sorted((event for event in (events or []) if isinstance(event, dict)),
                     key=lambda event: _event_id(event))
    for event in ordered:
        event_id = _event_id(event)
        if event_id <= cursor:
            continue
        cursor = event_id
        kind = event.get("kind")
        service = event.get("service")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        status = event.get("status")
        message = event.get("message")
        if kind in SCAN_SERVICE_EVENT_KINDS and isinstance(service, str) and service:
            index = payload.get("index")
            key = f"{index}:{service}" if isinstance(index, int) else service
            row = rows.get(key)
            if kind == "task_started":
                if row and row["state"] != "active":
                    continue
                row = {"key": key, "name": service, "state": "active", "status": None,
                       "message": None, "event_id": event_id}
                stage = f"Checking {service}…"
            else:
                row = {"key": key, "name": service, "event_id": event_id,
                       "state": "failed" if kind == "task_failed" else "complete",
                       "status": status, "message": message}
                stage = f"{service}: {_scan_state_label(row, label)}"
            rows[key] = row
            continue
        if kind == "discovery_completed":
            total = payload.get("total", payload.get("count")) or 0
            stage = f"Discovered {total} services. Checking registries…"
        elif message:
            stage = label(status) if status and str(message).strip().upper() == str(status).strip().upper() else message
        elif status:
            stage = label(status)
    for row in rows.values():
        row["label"] = _scan_state_label(row, label)
        row["detail"] = (row["message"] if row["state"] == "failed" and row.get("message")
                         and str(row["message"]).strip().upper() != str(row.get("status") or "").strip().upper()
                         else None)
    return {"rows": list(rows.values()), "visible": visible_scan_rows(rows.values()),
            "stage": stage, "cursor": cursor}


def visible_scan_rows(rows) -> list[dict]:
    rows = list(rows)
    active = sorted((row for row in rows if row["state"] == "active"), key=lambda row: -row["event_id"])
    finished = sorted((row for row in rows if row["state"] != "active"), key=lambda row: -row["event_id"])
    return active + finished[:SCAN_PROGRESS_RECENT_LIMIT]


def _event_id(event: dict) -> int:
    try:
        return int(event.get("id") or 0)
    except (TypeError, ValueError):
        return 0


def _scan_state_label(row: dict, label) -> str:
    if row["state"] == "active":
        return "Checking registry…"
    if row.get("status"):
        return label(row["status"])
    return row.get("message") or ("Failed" if row["state"] == "failed" else "Checked")


def runtime_failure_message(snapshot: dict | None) -> str:
    """Map a bounded probe category to factual operator-facing copy."""
    category = (snapshot or {}).get("failure_category")
    return _RUNTIME_FAILURE_MESSAGES.get(category, _RUNTIME_FAILURE_MESSAGES["probe_failed"])


def runtime_is_stale(snapshot: dict | None) -> bool:
    return bool(snapshot and (snapshot.get("stale") or snapshot.get("status") in {"stale", "unavailable"}))


def runtime_summary(snapshot: dict | None) -> dict:
    containers = [public_runtime_container(item) for item in (snapshot or {}).get("containers", [])]
    containers = [item for item in containers if item]
    running = [item for item in containers if item.get("state") == "running"]
    healthy = sum(item.get("healthcheck") == "healthy" for item in running)
    no_healthcheck = sum(item.get("healthcheck") == "none" for item in running)
    starting = sum(item.get("healthcheck") == "starting" for item in running)
    unhealthy = sum(item.get("healthcheck") == "unhealthy" for item in containers)
    restarting = sum(item.get("state") == "restarting" for item in containers)
    non_running = sum(item.get("state") != "running" for item in containers)
    attention = sum(runtime_attention(item) is not None for item in containers)
    return {
        "total": len(containers), "running": len(running), "healthy": healthy,
        "no_healthcheck": no_healthcheck, "starting": starting, "unhealthy": unhealthy,
        "restarting": restarting, "non_running": non_running,
        "attention": attention,
    }


def runtime_attention(container: dict | None, *, runtime_missing=False, runtime_reconciled=False) -> tuple[int, str] | None:
    """Return the documented factual attention rank and label, if any."""
    if runtime_missing:
        return 1, "Not present in current Docker runtime"
    if not container:
        if runtime_reconciled:
            return 1, "Changed since inventory scan"
        return None
    state = str(container.get("state") or "unknown").lower()
    health = str(container.get("healthcheck") or "unknown").lower()
    if container.get("oom_killed") is True:
        return 0, "OOM-killed"
    if health == "unhealthy":
        return 0, "Unhealthy"
    if state == "dead":
        return 0, "Dead"
    if state == "restarting":
        return 1, "Restarting"
    if state != "running":
        return 1, state.replace("_", " ").title()
    return None


def merge_service_items(scan_snapshot: dict | None, runtime_snapshot: dict | None,
                        verifications: dict | None = None) -> list[dict]:
    """Merge exact IDs, then conservatively display unique current Compose replacements."""
    scan_trustworthy = bool(
        scan_snapshot and scan_snapshot.get("status") == "complete" and scan_snapshot.get("finished_at")
    )
    scanned = (scan_snapshot or {}).get("payload", {}).get("services", []) if scan_trustworthy else []
    containers = [public_runtime_container(item) for item in (runtime_snapshot or {}).get("containers", [])]
    containers = [item for item in containers if item]
    by_id = {item["container_id"]: item for item in containers}
    matched = set()
    scan_rows = []
    scan_identity_counts = {}
    runtime_identity_groups = {}
    current = bool(runtime_snapshot and runtime_snapshot.get("status") == "current" and not runtime_is_stale(runtime_snapshot))
    for entry in scanned:
        if not isinstance(entry, dict):
            continue
        service = dict(entry.get("service") or {})
        identity = _compose_identity(service)
        if identity:
            scan_identity_counts[identity] = scan_identity_counts.get(identity, 0) + 1
        scan_rows.append((entry, service, identity))
    for runtime in containers:
        identity = _compose_identity(runtime)
        if identity:
            runtime_identity_groups.setdefault(identity, []).append(runtime)

    result = []
    stale = runtime_is_stale(runtime_snapshot)

    # Exact full-ID matches are authoritative and are reserved before any
    # Compose-label display reconciliation is considered.
    for entry, service, _identity in scan_rows:
        container_id = service.get("container_id")
        runtime = by_id.get(container_id) if isinstance(container_id, str) else None
        if runtime:
            matched.add(container_id)
            # The runtime monitor applies the current exclusion policy more
            # frequently than a potentially older completed registry scan.
            service["ignored"] = bool(service.get("ignored") or runtime.get("ignored"))
        row = {
            "service": service,
            "status": entry.get("status") or "UNKNOWN",
            "remote_version": entry.get("remote_version"),
            "remote_digest": entry.get("remote_digest"),
            "target_image": entry.get("target_image"),
            "tracking_tag": entry.get("tracking_tag"),
            "error": entry.get("error"),
            "runtime": runtime,
            "runtime_stale": stale if runtime else False,
            "runtime_only": False,
            "runtime_missing": bool(current and container_id and not runtime),
        }
        if container_id:
            row["_scan_container_id"] = container_id
        row["_scan_service_key"] = service.get("key")
        result.append(row)

    # A replacement may be shown as the same logical service only when both
    # sides prove a one-to-one Compose identity. It receives no scan-owned
    # update, rollback, digest, or Compose-write metadata; its update facts
    # come only from its own service verification (CHECK REQUIRED until then).
    for row in result:
        if not row.get("runtime_missing"):
            continue
        service = row["service"]
        identity = _compose_identity(service)
        candidates = runtime_identity_groups.get(identity, []) if identity else []
        if (not current or not identity or scan_identity_counts.get(identity) != 1
                or len(candidates) != 1 or candidates[0]["container_id"] in matched):
            continue
        replacement = candidates[0]
        matched.add(replacement["container_id"])
        row["service"] = _runtime_service(replacement)
        row["status"] = "CHECK REQUIRED"
        row["remote_version"] = None
        row["remote_digest"] = None
        row["target_image"] = None
        row["tracking_tag"] = None
        row["error"] = None
        row["runtime"] = replacement
        row["runtime_stale"] = False
        row["runtime_only"] = False
        row["runtime_missing"] = False
        row["runtime_reconciled"] = True

    for runtime in containers:
        if runtime["container_id"] in matched:
            continue
        service = _runtime_service(runtime)
        result.append({
            "service": service, "status": "NOT SCANNED", "remote_version": None,
            "remote_digest": None, "target_image": None, "error": None, "runtime": runtime,
            "runtime_stale": stale, "runtime_only": True,
            "runtime_missing": False, "runtime_reconciled": False,
        })
    if verifications is not None and not verifications.get("_error"):
        _apply_verifications(result, verifications)
    result.sort(key=lambda item: (
        (item["service"].get("stack") or "").lower(),
        (item["service"].get("name") or item["service"].get("key") or "").lower(),
        item["service"].get("container_id") or "",
    ))
    return result


_KEEP_WITHOUT_VERIFICATION = {"NOT SCANNED", "CHECK REQUIRED", "IGNORED", "LOCAL BUILD", "UNTRACKED DIGEST"}


def _apply_verifications(rows: list[dict], verifications: dict) -> None:
    """Project per-service update evidence onto rows with a current container.

    Source rules:
    - evidence applies only to the exact current container ID (a container's
      image, image ID and Compose labels are fixed when it is created);
    - fresh evidence supersedes the global snapshot's update facts, and a newer
      global scan has already superseded older evidence in the agent store;
    - stale or failed evidence is shown as last known with CHECK REQUIRED;
    - a current container with no applicable evidence keeps no update target;
    - rows without a current container keep their historical scan facts, which
      never carry a verification ID and therefore cannot authorise review.
    If verification state is unavailable the caller skips this projection and
    no row gains a verification ID, so update review stays closed.
    """
    records = {entry.get("service_key"): entry for entry in verifications.get("records", [])
               if isinstance(entry, dict)}
    for row in rows:
        runtime = row.get("runtime")
        identity = runtime or row["service"]
        key = "container/" + identity["container_id"] if identity.get("container_id") else identity.get("key")
        record = records.get(key)
        verified = (record or {}).get("result") or {}
        verified_service = verified.get("service") or {}
        if record and (record.get("invalidated") or (not runtime and not record.get("checked_at") and record.get("failed_at"))):
            row["status"] = "CHECK REQUIRED"
            row["remote_digest"] = row["remote_version"] = row["target_image"] = row["tracking_tag"] = None
            row["error"] = None
            if runtime and verified_service.get("container_id") == runtime.get("container_id"):
                row["service"] = dict(verified_service)
            continue
        if not runtime:
            continue
        # UNKNOWN invalidates verification like other failed checks. Preserve
        # its curated missing-identity reason instead of calling it a registry
        # failure or presenting historical update evidence as current.
        if record and not verified and record.get("failed_at"):
            row["last_known_status"] = row.get("status") if row.get("status") not in _KEEP_WITHOUT_VERIFICATION else None
            row["status"] = "UNKNOWN" if record.get("error") == LOCAL_DIGEST_UNVERIFIED else "REGISTRY ERROR"
            row["error"] = record.get("error")
            row["remote_digest"] = row["remote_version"] = row["target_image"] = None
            row["verification_failed_at"] = record.get("failed_at")
            continue
        if not record or verified_service.get("container_id") != runtime.get("container_id"):
            if row.get("status") not in _KEEP_WITHOUT_VERIFICATION:
                row["last_known_status"] = row["status"]
                row["status"] = "CHECK REQUIRED"
                row["remote_digest"] = row["remote_version"] = row["target_image"] = None
            continue
        row["service"] = dict(verified_service)
        row["service"]["ignored"] = bool(verified_service.get("ignored") or runtime.get("ignored"))
        row["runtime_only"] = row["runtime_reconciled"] = row["runtime_missing"] = False
        for field in ("status", "remote_digest", "remote_version", "remote_created",
                      "target_image", "tracking_tag", "error"):
            row[field] = verified.get(field)
        row["verification_id"] = record.get("verification_id")
        row["checked_at"] = record.get("checked_at")
        row["verification_fresh"] = bool(record.get("fresh"))
        row["verification_failed_at"] = record.get("failed_at")
        if not record.get("fresh"):
            row["last_known_status"] = row.get("status")
            row["status"] = "UNKNOWN" if record.get("error") == LOCAL_DIGEST_UNVERIFIED else "CHECK REQUIRED"
            row["error"] = record.get("error") or row.get("error")
            if row["status"] == "UNKNOWN":
                row["remote_digest"] = row["remote_version"] = row["target_image"] = None


def _compose_identity(service: dict | None) -> tuple[str, str] | None:
    if not isinstance(service, dict):
        return None
    stack, compose_service = service.get("stack"), service.get("compose_service")
    if not isinstance(stack, str) or not stack or not isinstance(compose_service, str) or not compose_service:
        return None
    return stack, compose_service


def _runtime_service(runtime: dict) -> dict:
    return {
        "key": runtime["key"], "container_id": runtime["container_id"],
        "name": runtime["name"], "stack": runtime.get("stack"),
        "compose_service": runtime.get("compose_service"), "image": runtime.get("image"),
        "ignored": runtime.get("ignored", False),
    }


def find_service_item(items: list[dict], service_key: str) -> dict | None:
    """Resolve current runtime keys and old scan keys for reconciled display rows."""
    for item in items:
        service = item.get("service") or {}
        if (service.get("key") == service_key or item.get("_scan_service_key") == service_key
                or item.get("_scan_container_id") == service_key.removeprefix("container/")):
            return item
    names = [item for item in items if (item.get("service") or {}).get("name") == service_key]
    if len(names) == 1:
        return names[0]
    return None


def attention_items(items: list[dict], runtime_snapshot: dict | None, limit: int = 8) -> list[dict]:
    """Return one combined row per service, ordered by runtime then maintenance facts."""
    stale = runtime_is_stale(runtime_snapshot)
    attention = []
    for item in items:
        runtime_issue = runtime_attention(
            item.get("runtime"), runtime_missing=item.get("runtime_missing", False),
            runtime_reconciled=item.get("runtime_reconciled", False),
        )
        status = item.get("status")
        maintenance_issue = status in _ERROR_ATTENTION or status in _UPDATE_ATTENTION
        if not runtime_issue and not maintenance_issue:
            continue
        identity_issue = item.get("runtime_missing") or item.get("runtime_reconciled")
        rank = runtime_issue[0] if runtime_issue else (1 if identity_issue else (2 if status in _ERROR_ATTENTION else 3))
        row = dict(item)
        row["runtime_issue"] = runtime_issue[1] if runtime_issue else None
        row["runtime_issue_label"] = (
            f"Last known · {runtime_issue[1]}" if runtime_issue and stale else (runtime_issue[1] if runtime_issue else None)
        )
        row["maintenance_attention"] = maintenance_issue
        row["maintenance_label"] = _MAINTENANCE_LABELS.get(status, status)
        row["attention_rank"] = rank
        attention.append(row)
    attention.sort(key=lambda item: (
        item["attention_rank"],
        (item["service"].get("stack") or "").lower(),
        (item["service"].get("name") or item["service"].get("key") or "").lower(),
        item["service"].get("container_id") or "",
    ))
    return attention[:max(0, int(limit))]
