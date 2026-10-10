"""Internal full-scan implementation, invoked by the existing agent facade.

This module never imports Docker/registry functions or webservice: the facade
passes its currently-bound, test-patchable functions for each scan invocation,
and its logger so diagnostics keep their established logger name.
Scan thread scheduling, leases and locking remain in ReadOnlyService.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone


def record_service_verification(data, *, state, safe_identifier, logger, started_at=None):
    """Record one checked service at the moment its check completes.

    This is independent of the overall scan outcome: a partial or failed
    run still updates (or marks failed) exactly the services it checked,
    while the complete inventory snapshot remains governed by staging.
    """
    try:
        state.save_verification(data, started_at=started_at)
    except Exception:
        service = (data.get("service") or {}).get("key")
        logger.warning(
            "Service verification could not be recorded for %s", safe_identifier(service))


def run_full_scan(run_id: str, *, config, state, web_settings, discover_services,
                  check_service, public_result, public_service, safe_error, safe_identifier, logger):
    results = []
    try:
        state.scan_event(run_id, "discovery_started", message="Discovering running services")
        started_at = datetime.now(timezone.utc).isoformat()
        found = discover_services(config)
        state.set_scan_total(run_id, len(found))
        state.scan_event(
            run_id, "discovery_completed",
            message=f"Discovered {len(found)} services",
            payload={"count": len(found), "total": len(found)}, completed=0,
        )
        for index, service in enumerate(found, 1):
            state.scan_event(run_id, "task_started", service=service.key, message="Checking registry", payload={"index": index, "total": len(found)}, completed=index - 1)
            try:
                result = check_service(service, state)
                data = public_result(result, state)
                results.append(data)
                record_service_verification(data, state=state, safe_identifier=safe_identifier, logger=logger,
                                            started_at=started_at)
                state.scan_event(run_id, "task_completed", service=service.key, status=data["status"], message=data["status"], payload={"index": index, "total": len(found), "tracking_issue": data.get("tracking_issue")}, completed=index)
            except Exception as exc:
                message = safe_error(exc)
                data = {"service": public_service(service), "status": "REGISTRY ERROR", "error": message, "remote_digest": None, "remote_version": None, "remote_created": None}
                results.append(data)
                record_service_verification(data, state=state, safe_identifier=safe_identifier, logger=logger,
                                            started_at=started_at)
                state.scan_event(run_id, "task_failed", service=service.key, status="REGISTRY ERROR", message=message, payload={"index": index, "total": len(found)}, completed=index)
        failed = sum(1 for item in results if item.get("status") in {"REGISTRY ERROR", "UNKNOWN"})
        status = "partial" if failed else "complete"
        scan_error = f"{failed} service result(s) could not be verified" if failed else None
        state.stage_scan_result(run_id, status, error=scan_error, services=results)
    except Exception as exc:
        message = safe_error(exc)
        try:
            state.stage_scan_result(run_id, "failed", error=message, services=results)
        except Exception:
            logger.exception("Could not persist failed scan state")
            try:
                state.stage_scan_result(run_id, "failed", error=message, services=[])
            except Exception:
                logger.warning("Could not persist minimal failed scan state")
        try:
            state.audit("scan", "failed", details={"run_id": run_id, "error": message})
        except Exception:
            logger.warning("Could not persist failed scan audit record")
        try:
            state.mark_scan_terminal(run_id, "failed", message=message)
        except Exception:
            logger.warning("Could not persist failed scan terminal event")
            try:
                state.mark_scan_terminal(run_id, "failed", emit_event=False)
            except Exception:
                logger.warning("Failed scan no longer owns the terminal transition")
    else:
        # The trustworthy inventory may be cached first, but the attempt
        # stays active until every bounded finalisation step has finished.
        keepalive_stop = threading.Event()

        def keepalive():
            while not keepalive_stop.wait(15):
                try:
                    state.touch_scan(run_id)
                except Exception:
                    logger.warning("Could not refresh finalising scan lease")

        keepalive_thread = threading.Thread(target=keepalive, name=f"upt-finalize-{run_id[:8]}", daemon=True)
        keepalive_thread.start()

        def housekeeping(label, action):
            try:
                action()
            except Exception:
                logger.warning("Post-scan %s failed", label)
                warning = f"Post-scan {label} did not complete"
                try:
                    state.add_scan_maintenance_warning(run_id, warning)
                except Exception:
                    logger.warning("Could not persist scan maintenance warning")
                try:
                    state.scan_event(run_id, "task_warning", status="warning", message=warning)
                except Exception:
                    pass

        try:
            housekeeping("progress reporting", lambda: state.scan_event(run_id, "finalization_started", message="Saving scan and completing housekeeping"))
            housekeeping("audit logging", lambda: state.audit("scan", status, details={"run_id": run_id, "services": len(results), "failures": failed}))
            housekeeping("retention cleanup", lambda: state.web_prune(audit_days=int(web_settings.get("audit_retention_days", 365)), scan_days=int(web_settings.get("scan_retention_days", 30))))
            housekeeping("database compaction", lambda: state.compact_if_needed(minimum_free_bytes=4 * 1024 * 1024))
            try:
                state.mark_scan_terminal(run_id, status, message=f"Scan completed with {len(results)} services")
            except Exception:
                logger.warning("Could not persist completed scan terminal event")
                try:
                    state.add_scan_maintenance_warning(run_id, "Completed scan progress could not be fully saved")
                except Exception:
                    pass
                try:
                    state.mark_scan_terminal(run_id, status, emit_event=False)
                except Exception:
                    logger.warning("Scan no longer owns the terminal transition")
        finally:
            keepalive_stop.set()
            keepalive_thread.join(timeout=1)

