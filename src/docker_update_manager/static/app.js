(() => {
  let statusLabels = {};
  try {
    statusLabels = JSON.parse(document.body.dataset.statusLabels || "{}");
  } catch (_) {
    statusLabels = {};
  }
  const displayStatus = value => statusLabels[String(value || "").toUpperCase()]
    || String(value || "Unknown").replace(/_/g, " ").toLowerCase()
      .replace(/\b\w/g, letter => letter.toUpperCase());

  const localTimestampText = value => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return null;
    const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (seconds < 45) return "Just now";
    if (seconds < 3600) return Math.max(1, Math.floor(seconds / 60)) + " min ago";
    if (seconds < 86400) return Math.max(1, Math.floor(seconds / 3600)) + " hr ago";
    const today = new Date();
    const localDate = (left, right) => left.getFullYear() === right.getFullYear()
      && left.getMonth() === right.getMonth() && left.getDate() === right.getDate();
    if (localDate(date, today)) {
      return "Today, " + new Intl.DateTimeFormat(undefined, {hour: "2-digit", minute: "2-digit"}).format(date);
    }
    return new Intl.DateTimeFormat(undefined, {day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"}).format(date);
  };

  document.querySelectorAll("time[data-local-time][datetime]").forEach(element => {
    const parsed = new Date(element.dateTime);
    const formatted = localTimestampText(element.dateTime);
    if (!formatted || Number.isNaN(parsed.getTime())) return;
    element.textContent = formatted;
    element.title = parsed.toLocaleString(undefined, {dateStyle: "medium", timeStyle: "long"});
  });

  document.querySelectorAll("time[data-local-date][datetime]").forEach(element => {
    const parsed = new Date(element.dateTime);
    if (Number.isNaN(parsed.getTime())) return;
    element.textContent = parsed.toLocaleString(undefined, {dateStyle: "medium", timeStyle: "short"});
  });

  // Service Detail targeted check. The control's copy depends on the state
  // rendered by the server (fresh, stale/missing, failed); the request is the
  // same explicit single-service refresh in every state.
  const refreshPanel = document.querySelector("[data-service-refresh]");
  if (refreshPanel) {
    const key = refreshPanel.dataset.serviceKey || "";
    const path = key.split("/").map(encodeURIComponent).join("/");
    const action = refreshPanel.querySelector("[data-refresh-action]");
    const button = refreshPanel.querySelector("[data-refresh-button]");
    const status = refreshPanel.querySelector("[data-refresh-status]");
    const csrf = refreshPanel.querySelector("[data-refresh-csrf]")?.value || "";
    let busy = false;
    const showStatus = (text, checking) => {
      if (!status) return;
      const children = [];
      if (checking) {
        const spinner = document.createElement("span");
        spinner.className = "refresh-spinner";
        spinner.setAttribute("aria-hidden", "true");
        children.push(spinner);
      }
      children.push(document.createTextNode(text));
      status.replaceChildren(...children);
      status.hidden = false;
    };
    const setChecking = checking => {
      refreshPanel.classList.toggle("is-checking", checking);
      if (action) action.hidden = checking;
      if (button) button.disabled = checking;
    };
    const stopWith = text => {
      setChecking(false);
      showStatus(text, false);
    };
    const check = async () => {
      if (busy || !path) return;
      busy = true;
      setChecking(true);
      showStatus("Checking update information…", true);
      try {
        const body = new URLSearchParams({csrf});
        const started = await fetch("/services/" + path + "/refresh", {
          method: "POST", body, credentials: "same-origin", headers: {"Content-Type": "application/x-www-form-urlencoded"}
        });
        if (!started.ok) throw new Error("service check unavailable");
        const state = await started.json();
        if (state.status === "current") { window.location.reload(); return; }
        if (state.status === "scan_active") { stopWith("An inventory scan is running; check again when it finishes."); return; }
        if (state.status === "retry_later") { stopWith("The last check failed moments ago. Retry in a minute."); return; }
        for (let attempt = 0; attempt < 60; attempt += 1) {
          await new Promise(resolve => window.setTimeout(resolve, 1500));
          const response = await fetch("/api/services/" + path + "/refresh", {credentials: "same-origin", cache: "no-store"});
          if (!response.ok) throw new Error("service check unavailable");
          const result = await response.json();
          if (result.status === "checking") continue;
          if (result.record?.fresh || result.status === "failed") { window.location.reload(); return; }
          stopWith("The service changed during the check. Review its current runtime details and retry.");
          return;
        }
        stopWith("The check is still running. Revisit this page shortly.");
      } catch (_) {
        stopWith("Update information could not be checked. Try again.");
      } finally {
        busy = false;
      }
    };
    if (button) button.addEventListener("click", check);
    if (refreshPanel.dataset.auto === "true") check();
  }

  // Prevent duplicate submissions of mutating/auth forms. The submit event
  // fires only after native validation passes, so required fields and the
  // explicit confirmation checkbox still gate submission.
  const busyForms = document.querySelectorAll("form[data-busy-form]");
  busyForms.forEach(busyForm => {
    busyForm.addEventListener("submit", event => {
      if (busyForm.dataset.busy === "true") {
        event.preventDefault();
        return;
      }
      busyForm.dataset.busy = "true";
      const submit = busyForm.querySelector("button[type=submit]");
      if (!submit) return;
      submit.dataset.idleLabel = submit.textContent;
      submit.setAttribute("aria-busy", "true");
      submit.classList.add("is-busy");
      if (submit.dataset.busyLabel) submit.textContent = submit.dataset.busyLabel;
      // Disable after the browser has captured the submission.
      window.setTimeout(() => { submit.disabled = true; }, 0);
    });
  });
  window.addEventListener("pageshow", event => {
    if (!event.persisted) return;
    busyForms.forEach(busyForm => {
      delete busyForm.dataset.busy;
      const submit = busyForm.querySelector("button[type=submit]");
      if (!submit) return;
      submit.disabled = false;
      submit.removeAttribute("aria-busy");
      submit.classList.remove("is-busy");
      if (submit.dataset.idleLabel) submit.textContent = submit.dataset.idleLabel;
    });
  });

  const progressPanel = document.querySelector("[data-scan-progress]");
  const scanStatus = document.querySelector("[data-scan-status]");
  const eventList = progressPanel && progressPanel.querySelector("[data-scan-events]");
  const stageLabel = progressPanel && progressPanel.querySelector("[data-scan-stage]");
  const countLabel = progressPanel && progressPanel.querySelector("[data-scan-count]");
  const progressBar = progressPanel && progressPanel.querySelector("[data-scan-bar]");
  const connectionLabel = progressPanel && progressPanel.querySelector("[data-scan-connection]");
  const activeStreams = new Map();

  // One projection model for scan progress. It mirrors
  // webviews.scan_progress_projection so a reloaded page and a live stream
  // show the same service rows in the same order. Persisted events and the
  // SSE cursor are untouched; only presentation is derived here.
  const SCAN_SERVICE_KINDS = new Set(["task_started", "task_completed", "task_failed"]);
  const SCAN_RECENT_LIMIT = 4;
  const scanRows = new Map();
  if (progressPanel && progressPanel.dataset.scanRows) {
    try {
      for (const row of JSON.parse(progressPanel.dataset.scanRows)) {
        if (row && row.key) scanRows.set(row.key, row);
      }
    } catch (_) {
      scanRows.clear();
    }
  }
  const sameText = (left, right) => String(left || "").trim().toUpperCase() === String(right || "").trim().toUpperCase();
  const scanRowLabel = row => {
    if (row.state === "active") return "Checking registry…";
    if (row.status) return displayStatus(row.status);
    return row.message || (row.state === "failed" ? "Failed" : "Checked");
  };
  const visibleScanRows = () => {
    const rows = [...scanRows.values()];
    const active = rows.filter(row => row.state === "active").sort((a, b) => b.event_id - a.event_id);
    const finished = rows.filter(row => row.state !== "active").sort((a, b) => b.event_id - a.event_id);
    return active.concat(finished.slice(0, SCAN_RECENT_LIMIT));
  };
  const renderScanRows = () => {
    if (!eventList) return;
    eventList.replaceChildren(...visibleScanRows().map(row => {
      const item = document.createElement("li");
      item.className = "scan-service-row";
      item.dataset.rowKey = row.key;
      item.dataset.state = row.state;
      if (row.detail) item.title = row.detail;
      const name = document.createElement("span");
      name.className = "scan-service-name";
      name.textContent = row.name;
      const state = document.createElement("span");
      state.className = "scan-service-state";
      state.textContent = row.label;
      item.append(name, state);
      return item;
    }));
  };
  // Returns the headline stage for the event, or null when the event is
  // ignored (a replayed or regressing service event).
  const projectScanEvent = (eventData, eventId) => {
    const payload = eventData.payload || {};
    const service = eventData.service;
    if (SCAN_SERVICE_KINDS.has(eventData.kind) && typeof service === "string" && service) {
      const key = Number.isInteger(payload.index) ? payload.index + ":" + service : service;
      const existing = scanRows.get(key);
      let row;
      if (eventData.kind === "task_started") {
        if (existing && existing.state !== "active") return null;
        row = {key, name: service, state: "active", status: null, message: null, event_id: eventId};
      } else {
        row = {key, name: service, event_id: eventId, state: eventData.kind === "task_failed" ? "failed" : "complete",
               status: eventData.status || null, message: eventData.message || null};
      }
      row.label = scanRowLabel(row);
      row.detail = row.state === "failed" && row.message && !sameText(row.message, row.status) ? row.message : null;
      scanRows.set(key, row);
      return row.state === "active" ? "Checking " + service + "…" : service + ": " + row.label;
    }
    if (eventData.kind === "discovery_completed") {
      return "Discovered " + (Number(payload.total ?? payload.count) || 0) + " services. Checking registries…";
    }
    if (eventData.message) {
      return eventData.status && sameText(eventData.message, eventData.status) ? displayStatus(eventData.status) : eventData.message;
    }
    return eventData.status ? displayStatus(eventData.status) : null;
  };

  const setScanCounts = (completed, total) => {
    const done = Number.isFinite(Number(completed)) ? Number(completed) : 0;
    const count = Number.isFinite(Number(total)) ? Number(total) : 0;
    if (countLabel) countLabel.textContent = done + " / " + (count || "discovering");
    if (!progressBar) return;
    if (count > 0) {
      progressBar.hidden = false;
      progressBar.max = count;
      progressBar.value = Math.min(done, count);
    } else {
      progressBar.hidden = true;
    }
    if (progressPanel) {
      progressPanel.dataset.completed = String(done);
      progressPanel.dataset.total = String(count);
    }
  };

  const addScanEvent = eventData => {
    const eventId = Number.parseInt(eventData.id, 10);
    if (!Number.isFinite(eventId)) return;
    // Replayed or out-of-order events never duplicate or regress a row.
    if (eventId <= (Number.parseInt(progressPanel.dataset.cursor, 10) || 0)) return;
    progressPanel.dataset.cursor = String(eventId);

    const payload = eventData.payload || {};
    const eventCompleted = eventData.completed ?? payload.completed;
    if (eventData.kind === "discovery_completed") {
      setScanCounts(eventCompleted ?? 0, Number(payload.total ?? payload.count) || 0);
    } else if (payload.total !== undefined) {
      setScanCounts(eventCompleted ?? progressPanel.dataset.completed, payload.total);
    } else if (eventCompleted !== undefined) {
      setScanCounts(eventCompleted, progressPanel.dataset.total);
    }
    const stage = projectScanEvent(eventData, eventId);
    if (stage && stageLabel) stageLabel.textContent = stage;
    renderScanRows();
  };

  const watchScan = (runId, initialCursor = 0) => {
    if (!progressPanel || !runId || typeof EventSource === "undefined") return;
    if (activeStreams.has(runId)) return activeStreams.get(runId);
    progressPanel.hidden = false;
    progressPanel.dataset.runId = runId;
    if (scanStatus) scanStatus.textContent = " Scan is running on the server.";
    const cursor = Number.parseInt(initialCursor, 10) || 0;
    const stream = new EventSource("/scan/" + encodeURIComponent(runId) + "/events?after=" + cursor);
    activeStreams.set(runId, stream);
    const closeStream = () => {
      stream.close();
      if (activeStreams.get(runId) === stream) activeStreams.delete(runId);
    };
    stream.addEventListener("scan-event", event => {
      try {
        addScanEvent(JSON.parse(event.data));
        if (connectionLabel) connectionLabel.textContent = "Connected · scan continues on the server if this page closes.";
      } catch (_) {
        if (connectionLabel) connectionLabel.textContent = "Received an unreadable progress update.";
      }
    });
    stream.addEventListener("scan-warning", event => {
      try {
        const warning = JSON.parse(event.data);
        if (connectionLabel) connectionLabel.textContent = warning.message || "Agent temporarily unavailable; reconnecting.";
      } catch (_) {
        if (connectionLabel) connectionLabel.textContent = "Agent temporarily unavailable; reconnecting.";
      }
    });
    const finishScan = fallbackStatus => event => {
      let result = {};
      try {
        result = JSON.parse(event.data);
      } catch (_) {
        result.status = fallbackStatus;
      }
      const status = result.status || fallbackStatus;
      const labels = {
        complete: "Scan complete",
        partial: "Scan finished with registry errors",
        failed: "Scan failed",
      };
      closeStream();
      if (scanStatus) {
        scanStatus.textContent = " " + (labels[status] || "Scan ended") + ". Refreshing saved results…";
      }
      if (stageLabel) {
        stageLabel.textContent = result.error || labels[status] || "Scan ended";
      }
      if (connectionLabel && result.error) connectionLabel.textContent = result.error;
      if (connectionLabel && result.maintenance_warning) connectionLabel.textContent = "Scan saved with housekeeping warning: " + result.maintenance_warning;
      window.setTimeout(() => window.location.reload(), 500);
    };
    stream.addEventListener("scan-complete", finishScan("complete"));
    stream.addEventListener("scan-partial", finishScan("partial"));
    stream.addEventListener("scan-failed", finishScan("failed"));
    stream.addEventListener("scan-auth-expired", event => {
      closeStream();
      if (stageLabel) stageLabel.textContent = "Scan continues on the server; sign in again to resume viewing progress.";
      if (scanStatus) scanStatus.textContent = " Your session expired or was revoked.";
      if (connectionLabel) {
        const link = document.createElement("a");
        link.href = "/login?notice=session-expired";
        link.textContent = "Sign in again";
        connectionLabel.replaceChildren(document.createTextNode("Progress stream closed. "), link);
      }
    });
    stream.addEventListener("scan-not-found", event => {
      closeStream();
      if (stageLabel) stageLabel.textContent = "This scan is no longer available.";
      if (scanStatus) scanStatus.textContent = " Start a new scan to view current progress.";
      if (connectionLabel) connectionLabel.textContent = "The server no longer has this scan's event history.";
    });
    stream.onerror = () => {
      // Keep EventSource open so its automatic retry resumes from the last
      // persisted event id after a transient network interruption.
      if (connectionLabel) connectionLabel.textContent = "Connection interrupted · browser will retry automatically.";
      if (scanStatus) scanStatus.textContent = " Reconnecting to the active scan…";
    };
  };

  if (progressPanel && progressPanel.dataset.runId) {
    watchScan(progressPanel.dataset.runId, progressPanel.dataset.cursor);
  }

  const form = document.querySelector("[data-scan-form]");
  const setScanButton = (button, text) => {
    const label = button.querySelector("[data-scan-label]");
    if (label) label.textContent = text;
    else button.textContent = text;
  };
  if (form) {
    form.addEventListener("submit", async event => {
      event.preventDefault();
      const button = form.querySelector("button");
      if (button) {
        button.disabled = true;
        setScanButton(button, "Starting scan…");
      }
      if (scanStatus) scanStatus.textContent = " Connecting to the read-only agent…";
      try {
        const response = await fetch(form.action, {
          method: "POST",
          body: new FormData(form),
          headers: {"X-Requested-With": "fetch"},
          credentials: "same-origin",
        });
        const data = await response.json();
        if (!response.ok || !data.run_id) {
          throw new Error(data.error || "The scan could not be started.");
        }
        const continuingCurrentRun = Boolean(data.existing)
          && progressPanel.dataset.runId === data.run_id;
        progressPanel.hidden = false;
        progressPanel.dataset.status = "running";
        if (!continuingCurrentRun) {
          scanRows.clear();
          renderScanRows();
          progressPanel.dataset.cursor = "0";
          setScanCounts(0, 0);
          if (stageLabel) stageLabel.textContent = "Discovering running services…";
          if (connectionLabel) connectionLabel.textContent = "Connected · scan continues on the server if this page closes.";
        }
        if (button) {
          button.disabled = true;
          setScanButton(button, "Scan in progress");
        }
        watchScan(data.run_id, continuingCurrentRun ? progressPanel.dataset.cursor : 0);
      } catch (error) {
        if (scanStatus) scanStatus.textContent = " " + (error.message || "Unable to start the scan.");
        if (button) {
          button.disabled = false;
          setScanButton(button, "Scan now");
        }
      }
    });
  }
})();
