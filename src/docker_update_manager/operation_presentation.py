"""Bounded, display-only operation facts shared by HTML and terminal SSE."""

from .release_identity import display_repository, display_version, short_digest

# ``refresh_required`` is an immutable commit-time fact: this operation reset
# the service's update verification, so a targeted refresh is needed. UPT tries
# to queue it after the commit, but that attempt is asynchronous, may fail, and is
# never recorded in the result, so this wording must hold whether or not it did.
REFRESH_NOTICE = ("A targeted refresh is required. UPT normally queues it automatically; "
                  "if the service still shows Check required, use Check for updates.")


def operation_presentation(operation: dict) -> dict:
    status = operation.get("status")
    result = operation.get("result") or {}
    rollback = operation.get("kind") == "rollback"
    bootstrap = operation.get("kind") == "compose_bootstrap"
    compose = bootstrap or operation.get("kind") == "compose_reconcile"
    discard = compose and (result.get("action") or (operation.get("summary") or {}).get("action")) == "discard"
    name = "Discard" if discard else "Apply" if compose else "Rollback" if rollback else "Update"
    recovered = bool(result.get("recovered"))
    manual = bool(result.get("manual_recovery_required"))
    unchanged = status == "succeeded" and not rollback and not compose and result.get("updated") is False

    view = {"status_label": {"queued": "Queued", "running": "Running"}.get(status, str(status or "Unknown").title()),
            "stage": operation.get("current_stage") or "Queued",
            "outcome": "pending",
            "alert": None, "alert_class": None, "alert_role": None, "error": status == "failed",
            "badge_class": "status-info" if status == "running" else "status-neutral", "result_facts": []}
    if status == "succeeded":
        view.update(status_label="No change needed" if unchanged else "Completed",
                    outcome="no-change" if unchanged else "success",
                    stage="No image change needed" if unchanged else f"{name} complete",
                    alert=("No image change was required; the service already matches its tracked digest."
                           if unchanged else "Rollback completed successfully. Volumes and application data were preserved."
                           if rollback else "Update completed successfully."),
                    alert_class="alert-info" if unchanged else "alert-success",
                    alert_role="status", badge_class="status-success")
        if compose:
            view.update(status_label="Applied successfully", stage="Configuration applied successfully",
                        alert="Configuration applied successfully. The service image is unchanged; no image was pulled.")
    elif status == "blocked":
        # A factual pre-mutation refusal: nothing was pulled, written or
        # recreated, so this is neither a failure nor a recovery event.
        view.update(status_label="Blocked · no changes made", outcome="blocked",
                    stage=f"{name} blocked",
                    alert="No changes were made. " + (operation.get("error") or
                                                     f"UPT refused this {name.lower()} before changing anything."),
                    alert_class="alert-warning", alert_role="status", badge_class="status-warning")
    elif status == "failed":
        view.update(status_label="Manual recovery required" if manual else "Failed · recovered" if recovered else "Failed",
                    outcome="manual" if manual else "recovered" if recovered else "failure",
                    stage="Manual recovery required" if manual else f"{name} failed · service recovered" if recovered else f"{name} failed",
                    alert=(operation.get("error") or "The operation did not complete.") +
                          (" Check the retained recovery details in UPT History before retrying." if manual else
                           " The original service was recovered automatically." if recovered else
                           " Check UPT History for recovery details."),
                    alert_class="alert-danger" if manual or not recovered else "alert-warning",
                    alert_role="alert", badge_class="status-danger" if manual or not recovered else "status-warning")
        if compose and recovered:
            view.update(status_label="Apply failed · recovered", stage="Previous configuration recovered",
                        alert="Apply failed; the previous configuration was recovered. Desired changes remain pending on disk.")
        elif compose and manual:
            view.update(alert="Apply failed. Manual recovery is required. Trusted baseline and desired configuration evidence were retained in UPT History.")

    if compose and result.get("namespace") is True and not discard:
        # Namespace consumer Apply: image and owner unchanged; configuration-only recovery.
        if status == "succeeded":
            view.update(alert="Configuration applied. The image is unchanged and no image was pulled; "
                              "the namespace owner was unchanged at every proved checkpoint."
                              + (" " + REFRESH_NOTICE if result.get("refresh_required") else ""))
        elif status == "blocked":
            view.update(status_label="Blocked — no workload changes", stage="Apply blocked",
                        alert="Blocked — no workload changes. Review the configuration changes again.")
        elif status == "failed" and recovered:
            view.update(alert="Apply failed — previous configuration recovered. The image and namespace owner are "
                              "unchanged. Desired changes remain pending; retry requires a fresh review. Application "
                              "data and database changes are not rolled back.")
        elif status == "failed":
            view.update(status_label="Manual recovery required", outcome="manual", stage="Manual recovery required",
                        alert_class="alert-danger", alert_role="alert", badge_class="status-danger",
                        alert="Apply failed or was interrupted — manual recovery required. Recreation may have "
                              "occurred. Evidence was retained and further trust and mutation for this service are fenced.")

    if discard:
        if status in {"queued", "running"}:
            view["stage"] = "Discarding configuration changes"
        elif status == "succeeded":
            view.update(status_label="Pending configuration changes discarded",
                        stage="Pending configuration changes discarded",
                        alert="Pending source changes discarded. The running service and image are unchanged; UPT did not recreate or restart the service.")
        elif status == "blocked":
            view.update(status_label="Blocked — no source changes made", stage="Discard blocked",
                        alert="No source changes were made. Refresh and review the pending changes again.")
        elif status == "failed":
            view.update(status_label="Manual source recovery required" if manual else "Discard failed — pending source restored" if recovered else "Discard failed",
                        stage="Manual source recovery required" if manual else "Pending source restored" if recovered else "Discard failed",
                        alert=("Manual source recovery required. Pending source evidence was retained."
                               if manual else "Discard failed; the original pending source was restored."
                               if recovered else "Discard failed. Check UPT History for source recovery details.")
                              + " UPT did not recreate or restart the running service.")

    if bootstrap:
        if status in {'queued','running'}:
            view['stage'] = (operation.get('current_stage') or 'Revalidate trust bootstrap') if status == 'running' else 'Queued trust bootstrap'
        elif status == 'succeeded':
            view.update(status_label='Configuration applied; trusted baseline established',
                        stage='Configuration applied; trusted baseline established',
                        alert='The reviewed configuration is trusted. The service image is unchanged; no image was pulled.' + (' ' + REFRESH_NOTICE if result.get('refresh_required') else ''))
        elif status == 'blocked':
            view.update(status_label='Blocked — no workload changes',stage='Blocked — no workload changes',
                        alert='UPT blocked trust bootstrap before workload mutation. Refresh and review again.')
        else:
            view.update(status_label='Bootstrap failed/interrupted — manual recovery required',
                        stage='Manual recovery required',outcome='manual',alert_class='alert-danger',alert_role='alert',
                        alert='Bootstrap failed or was interrupted. Recreation may have occurred. Automatic configuration rollback is unavailable. Private diagnostic evidence was retained; manual recovery is required. Further automatic trust capture and mutation are fenced.')

    if status != "succeeded":
        return view  # A failed deployment has no proven deployed/restored image.

    if compose:
        return view

    release = display_version(result.get("version"), result.get("image"))
    repository = display_repository(result.get("image"))
    digest = short_digest(result.get("digest"))
    if repository:
        view["result_facts"].append({"label": "Image", "value": repository})
    if release.value:
        view["result_facts"].append({"label": "Image tag" if release.source == "tag" else "Published version",
                                     "value": release.value})
    if digest:
        view["result_facts"].append({"label": "Digest", "value": digest})
    return view
