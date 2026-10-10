(() => {
  const panel = document.querySelector("[data-operation-progress]");
  if (!panel || typeof EventSource === "undefined") return;
  const status = document.querySelector("[data-operation-status]");
  const stage = panel.querySelector("[data-operation-stage]");
  const stageDetail = panel.querySelector("[data-operation-stage-detail]");
  const connection = panel.querySelector("[data-operation-connection]");
  const list = panel.querySelector("[data-operation-events]");
  const seen = new Set(Array.from(list.querySelectorAll("[data-event-id]"), row => row.dataset.eventId));
  const activeStages = new Map(Array.from(list.querySelectorAll('[data-stage-active="true"][data-stage-key]'), row => [row.dataset.stageKey, row]));
  const progressKinds = new Set(["task_started", "task_progress", "task_completed", "task_failed"]);
  const operationId = panel.dataset.operationId;
  const initialStatus = panel.dataset.status;
  const terminalStatuses = ["succeeded", "failed", "blocked"];
  if (!operationId || terminalStatuses.includes(initialStatus)) return;

  let cursor = Number.parseInt(panel.dataset.cursor || "0", 10) || 0;
  const stream = new EventSource("/operations/" + encodeURIComponent(operationId) + "/events?after=" + cursor);
  const close = () => stream.close();
  const meter = panel.querySelector("[data-operation-meter]");
  const stepLabel = panel.querySelector("[data-operation-step]");
  const log = panel.querySelector("[data-operation-log]");
  const logCount = panel.querySelector("[data-operation-log-count]");
  // Step counts come only from explicit "n/N" core stage labels.
  const stageStep = label => {
    const match = /^\[?(\d{1,2})\/(\d{1,2})\]?\s/.exec(typeof label === "string" ? label : "");
    if (!match) return null;
    const step = Number(match[1]); const total = Number(match[2]);
    return step > 0 && step <= total ? { step, total } : null;
  };
  const showStep = (label, completed) => {
    const parsed = stageStep(label);
    if (!parsed || !meter) return;
    meter.removeAttribute("data-indeterminate");
    meter.max = parsed.total;
    meter.value = completed ? parsed.step : parsed.step - 1;
    if (stepLabel) { stepLabel.hidden = false; stepLabel.textContent = "Step " + parsed.step + " of " + parsed.total; }
  };
  const updateLogCount = () => {
    if (logCount) logCount.textContent = list.children.length + (list.children.length === 1 ? " event" : " events");
  };
  const span = (className, text) => {
    const element = document.createElement("span");
    element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  };
  // The server computes the marker role once (operation_event_role); the
  // fallback only covers a payload that lacks it and mirrors the same rules.
  const roleOf = item => {
    if (item.presentation && item.presentation.role) return item.presentation.role;
    if (["operation_completed", "operation_failed", "operation_blocked"].includes(item.kind)) return "terminal";
    if (["operation_started", "task_info", "task_running"].includes(item.kind) || ["queued", "info"].includes(item.status)) return "info";
    return item.kind === "task_warning" ? "warning" : "stage";
  };
  const newRow = item => {
    const row = document.createElement("li");
    const icon = span("op-step-icon");
    icon.setAttribute("aria-hidden", "true");
    row.append(icon, span("op-step-name", item.stage || item.kind || "Update"));
    row.dataset.eventStatus = item.status || "";
    row.dataset.eventRole = roleOf(item);
    // Same attributes the server renders, so live and reloaded rows are identical.
    if (item.id !== undefined) row.dataset.eventId = String(item.id);
    row.dataset.stageKey = typeof item.stage === "string" ? item.stage.trim() : "";
    row.dataset.stageActive = "false";
    if (row.dataset.eventRole !== "terminal") {
      if (item.message) row.append(span("op-step-message", item.message));
    } else {
      row.dataset.terminalEvent = "true";
    }
    return row;
  };
  const updateRow = (row, item, id, active) => {
    if (id) row.dataset.eventId = id;
    row.dataset.eventStatus = item.status || "";
    row.dataset.stageKey = item.stage || "";
    row.dataset.stageActive = active ? "true" : "false";
    row.querySelector(".op-step-name").textContent = item.stage || item.kind || "Update";
    row.dataset.eventRole = roleOf(item);
    let message = row.querySelector(".op-step-message");
    if (!message && item.message && row.dataset.eventRole !== "terminal") { message = span("op-step-message"); row.append(message); }
    if (message) message.textContent = item.message || "";
  };
  const addRow = row => {
    list.append(row);
    while (list.children.length > 200) list.firstElementChild.remove();
    updateLogCount();
  };
  const appendEvent = item => {
    const id = item.id === undefined ? "" : String(item.id);
    if (id) {
      cursor = Math.max(cursor, Number.parseInt(id, 10) || 0);
      panel.dataset.cursor = String(cursor);
      if (seen.has(id)) return;
      seen.add(id);
    }
    if (stage && item.stage) stage.textContent = item.stage;
    if (item.stage) showStep(item.stage, item.status === "completed");
    if (stageDetail && item.message) stageDetail.textContent = item.message;
    if (!list) return;
    const key = typeof item.stage === "string" ? item.stage.trim() : "";
    if (key && progressKinds.has(item.kind)) {
      const active = item.status === "running" && item.kind !== "task_failed";
      let row = activeStages.get(key);
      if (row && !row.isConnected) row = null;
      if (!row) {
        row = newRow(item);
        addRow(row);
      }
      updateRow(row, item, id, active);
      if (active) activeStages.set(key, row);
      else activeStages.delete(key);
      return;
    }
    addRow(newRow(item));
  };
  stream.addEventListener("operation-event", event => {
    try {
      appendEvent(JSON.parse(event.data));
      if (connection) connection.textContent = "Connected · progress is saved on the server.";
    } catch (_) {
      if (connection) connection.textContent = "Received an unreadable progress update; saved status remains available.";
    }
  });
  stream.addEventListener("operation-warning", event => {
    try { if (connection) connection.textContent = JSON.parse(event.data).message || "Agent temporarily unavailable; reconnecting."; }
    catch (_) { if (connection) connection.textContent = "Agent temporarily unavailable; reconnecting."; }
  });
  const finish = expectedStatus => event => {
    let result = {};
    try { result = JSON.parse(event.data); } catch (_) { result.status = expectedStatus; }
    const isRollback = panel.dataset.kind === "rollback" || result.kind === "rollback";
    const view = result.presentation;
    if (!view || result.status !== expectedStatus) {
      // A partial terminal payload cannot safely replace the saved server view.
      window.location.reload();
      return;
    }
    const successful = expectedStatus === "succeeded";
    close();
    activeStages.forEach(row => { row.dataset.stageActive = "false"; });
    activeStages.clear();
    panel.dataset.status = expectedStatus;
    panel.dataset.outcome = view.outcome;
    if (/^container\/[a-f0-9]{64}$/.test(result.result?.current_service_key || "")) {
      document.querySelectorAll("[data-operation-service-link]").forEach((link) => {
        link.href = "/services/" + result.result.current_service_key;
      });
    }
    if (status) {
      status.textContent = view.status_label;
      status.className = "badge " + view.badge_class;
    }
    if (stage) stage.textContent = view.stage;
    if (stageDetail) stageDetail.textContent = "Operation result saved in UPT History.";
    if (connection) connection.hidden = true;
    if (meter) meter.hidden = true;
    if (stepLabel) stepLabel.hidden = true;
    // The transient stage log collapses into the final state once complete.
    if (log) log.open = false;
    const message = document.createElement("div");
    message.className = "alert " + view.alert_class;
    message.setAttribute("role", view.alert_role);
    if (view.error) message.dataset.operationError = "";
    message.textContent = view.alert;
    panel.querySelector(".operation-terminal-result")?.remove();
    message.classList.add("operation-terminal-result");
    const resultSection = panel.querySelector(".operation-result");
    panel.querySelector(".operation-body").insertBefore(message, resultSection || log);
    if (successful && result.result) {
      panel.querySelector(".operation-result")?.remove();
      const data = result.result;
      const rows = view.result_facts || [];
      if (rows.length) {
        const section = document.createElement("section");
        section.className = "operation-result";
        section.setAttribute("aria-label", isRollback ? "Rollback image result" : "Update image result");
        const heading = document.createElement("h3");
        heading.textContent = isRollback ? "Restored image" : "Deployed image";
        const list = document.createElement("dl");
        list.className = "kv-grid operation-result-facts";
        for (const {label, value} of rows) {
          const row = document.createElement("div");
          const term = document.createElement("dt"); term.textContent = label;
          const definition = document.createElement("dd"); definition.textContent = value;
          row.append(term, definition);
          list.append(row);
        }
        const disclosure = document.createElement("details");
        disclosure.className = "identity-disclosure";
        const summary = document.createElement("summary");
        summary.textContent = "Show exact image reference and digest";
        const exact = document.createElement("dl");
        exact.className = "exact-identity-facts";
        const exactRows = [["Image reference", data.image], ["Exact digest", data.digest]]
          .filter(([, value]) => value);
        for (const [label, value] of exactRows) {
          const row = document.createElement("div");
          const term = document.createElement("dt"); term.textContent = label;
          const definition = document.createElement("dd");
          const code = document.createElement("code");
          code.className = "technical-value";
          code.textContent = value;
          definition.append(code);
          row.append(term, definition);
          exact.append(row);
        }
        disclosure.append(summary, exact);
        section.append(heading, list, disclosure);
        panel.querySelector(".operation-body").insertBefore(section, log);
      }
    }
  };
  stream.addEventListener("operation-complete", finish("succeeded"));
  stream.addEventListener("operation-failed", finish("failed"));
  stream.addEventListener("operation-blocked", finish("blocked"));
  stream.addEventListener("operation-auth-expired", () => {
    close();
    if (connection) {
      const link = document.createElement("a");
      link.href = "/login?notice=session-expired";
      link.textContent = "Sign in again";
      connection.replaceChildren(document.createTextNode("Progress stream closed. "), link);
    }
  });
  stream.addEventListener("operation-not-found", () => {
    close();
    if (connection) connection.textContent = "This operation is no longer available.";
  });
  stream.onerror = () => {
    if (connection) connection.textContent = "Connection interrupted · browser will retry from the last saved event.";
  };
})();
