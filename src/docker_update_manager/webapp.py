from __future__ import annotations

import ipaddress
import asyncio
import json
import logging
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .agent import AgentClient, AgentNotFound, AgentUnavailable
from .component_version import VERSION_MISMATCH, VERSION_MISMATCH_MESSAGE, ComponentVersionMismatch, version_agreement
from .compose_discard import DiscardRefused
from .auth import DUMMY_PASSWORD_HASH, RateLimiter, hash_password, new_token, safe_equal, token_hash, utc_after, verify_password
from .compose_drift import STATUSES as COMPOSE_STATUSES, ComposePreflightRefused
from .config import WebConfig, session_policy, session_policy_warnings
from .runtime import public_runtime_container
from .release_identity import display_channel, display_repository, display_version, exact_digest_reference, inventory_identity, short_digest, update_identity
from .operation_presentation import operation_presentation
from .state import State
from .webviews import attention_items, find_service_item, merge_service_items, runtime_failure_message, runtime_is_stale, runtime_summary, scan_progress_projection
from .webstate import WebState, validate_web_files

BASE = Path(__file__).resolve().parent

# Bound the forwarded chain we are willing to parse so a hostile client cannot
# force unbounded work through a very long X-Forwarded-For value.
MAX_FORWARDED_HOPS = 20
SESSION_TOUCH_INTERVAL = timedelta(minutes=5)
SESSION_AUDIT_THROTTLE_SECONDS = 60
# Lax, not Strict: a Strict cookie is withheld on cross-site-initiated
# navigations (a link tapped in Messages/Notes/mail), so the server saw no
# session, issued an anonymous browser-session cookie and that Set-Cookie
# replaced the persistent authenticated cookie in the browser. All mutating
# routes are POST + CSRF token + Origin check, which Lax still protects.
SESSION_COOKIE_SAMESITE = "lax"
log = logging.getLogger("upt.web")


def _duration_label(minutes: int) -> str:
    for unit, size in (("day", 1440), ("hour", 60)):
        if minutes % size == 0:
            count = minutes // size
            return f"{count} {unit}{'' if count == 1 else 's'}"
    return f"{minutes} minutes"
STATUS_LABELS = {
    "CURRENT": "Up to date",
    "UPDATE": "Update available",
    "PINNED": "Pinned",
    "PINNED UPDATE": "Pinned update",
    "DIGEST CHANGED": "Digest changed",
    "UNTRACKED DIGEST": "Tracking unavailable",
    "REGISTRY ERROR": "Registry error",
    "ARCH UNSUPPORTED": "Architecture unsupported",
    "UNKNOWN": "Unknown",
    "LOCAL BUILD": "Local build",
    "IGNORED": "Ignored",
    "NOT SCANNED": "Not scanned",
    "CHECK REQUIRED": "Check required",
}
_OPERATION_PROGRESS_KINDS = frozenset({"task_started", "task_progress", "task_completed", "task_failed"})
_OPERATION_TERMINAL_KINDS = frozenset({"operation_completed", "operation_failed", "operation_blocked"})
_OPERATION_INFO_KINDS = frozenset({"operation_started", "task_info", "task_running"})


def operation_event_role(event):
    """Marker role of one persisted event: the single source for live and reloaded views.

    ``info`` events (queued, running/transition markers, explanations) are
    neutral facts, never steps; only ``stage`` rows can be incomplete.
    """
    kind = event.get("kind")
    if kind in _OPERATION_TERMINAL_KINDS: return "terminal"
    if kind in _OPERATION_INFO_KINDS or event.get("status") in {"queued", "info"}: return "info"
    if kind == "task_warning": return "warning"
    return "stage"


def operation_timeline(events, terminal=False):
    """Project persisted events into one row per active logical stage.

    This is presentation-only: operation status, event ids, SSE cursors and the
    audit/event stream remain untouched. Warnings and terminal/rollback events
    stay as their own rows; only routine updates and a stage failure can
    replace an active row with the same exact stage identity. Terminal views
    clear active presentation without changing the recorded event status.
    """
    timeline = []
    active = {}
    for event in events or []:
        row = dict(event)
        row["_timeline_role"] = operation_event_role(row)
        stage = row.get("stage")
        key = stage.strip() if isinstance(stage, str) else ""
        kind = row.get("kind")
        status = row.get("status")
        if kind in _OPERATION_PROGRESS_KINDS and key:
            row["_timeline_active"] = status == "running" and kind != "task_failed"
            if key in active:
                index = active[key]
                timeline[index] = row
            else:
                index = len(timeline)
                timeline.append(row)
            if row["_timeline_active"]:
                active[key] = index
            else:
                active.pop(key, None)
        else:
            row["_timeline_active"] = False
            timeline.append(row)
    if terminal:
        for row in timeline:
            row["_timeline_active"] = False
    return timeline
UPDATE_STATUSES = {"UPDATE", "DIGEST CHANGED", "PINNED UPDATE"}
_STAGE_STEP = re.compile(r"^\[?(\d{1,2})/(\d{1,2})\]?\s")


def stage_step(label):
    """Return the real ``(step, total)`` encoded in a core stage label, else None.

    Presentation-only: progress is shown as a step count only when the core
    reporter emitted an explicit ``n/N`` stage label; nothing is estimated.
    """
    match = _STAGE_STEP.match(label) if isinstance(label, str) else None
    if not match:
        return None
    step, total = int(match.group(1)), int(match.group(2))
    return (step, total) if 0 < step <= total else None


def relative_time(value, *, now=None) -> str:
    """Render stored ISO timestamps compactly without changing their UTC value."""
    if not value:
        return "Unknown"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed = parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return str(value)
    now = now or datetime.now(timezone.utc)
    seconds = max(0, int((now - parsed).total_seconds()))
    if seconds < 45:
        return "Just now"
    if seconds < 3600:
        minutes = max(1, seconds // 60)
        return f"{minutes} min ago"
    if parsed.date() == now.astimezone(timezone.utc).date():
        return f"Today, {parsed:%H:%M} UTC"
    if seconds < 86400:
        hours = max(1, seconds // 3600)
        return f"{hours} hr ago"
    if seconds < 7 * 86400:
        return f"{seconds // 86400} days ago"
    return parsed.strftime("%d %b, %H:%M UTC")


def utc_timestamp(value) -> str:
    """Normalize stored timestamp text to an explicit UTC ISO-8601 value."""
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        return str(value)


def _public_service_items(items):
    return [{key: value for key, value in item.items() if not key.startswith("_")} for item in items]


def parse_trusted_networks(values) -> list:
    """Parse configured trusted proxy addresses/networks, ignoring invalid entries."""
    networks = []
    for raw in values or []:
        try:
            network = ipaddress.ip_network(str(raw), strict=False)
        except ValueError:
            continue
        # A catch-all network would make every peer trusted and turn
        # X-Forwarded-For into caller-controlled identity; refuse it.
        if network.prefixlen == 0:
            continue
        networks.append(network)
    return networks


def _as_address(value):
    try:
        address = ipaddress.ip_address(str(value).strip())
    except (ValueError, AttributeError):
        return None
    # A dual-stack socket may report a local IPv4 peer as ::ffff:127.0.0.1;
    # normalise so it can match an IPv4 trusted_proxies entry.
    return getattr(address, "ipv4_mapped", None) or address


def effective_client_ip(peer: str, forwarded_for: str, networks: list) -> str:
    """Resolve the effective client address from the direct peer and X-Forwarded-For.

    The direct socket peer is authoritative. Forwarded values are consulted
    only when that peer is a configured trusted proxy. The chain is then walked
    from the right (closest hop) towards the client and stops at the first
    address that is not a trusted proxy, so client-supplied leading entries
    cannot spoof the audit or throttle identity. Malformed entries are ignored
    and the direct peer is retained when nothing trustworthy remains.
    """
    peer_address = _as_address(peer)

    def trusted(address) -> bool:
        return address is not None and any(address in network for network in networks)

    if peer_address is None or not trusted(peer_address):
        return str(peer) if peer else "unknown"
    # Keep the nearest hops: the right-most entry is written by the nearest
    # proxy, so padding the header with extra leading values can never discard
    # the address that proxy actually observed.
    raw_hops = str(forwarded_for or "").split(",")[-MAX_FORWARDED_HOPS:]
    current = peer_address
    for raw in reversed(raw_hops):
        if not trusted(current):
            break
        address = _as_address(raw)
        if address is None:
            # An unparseable hop means the chain is not trustworthy; keep the
            # last address proven to come from a trusted proxy.
            break
        current = address
    return str(current)


def forwarded_proto_is_https(peer: str, forwarded_proto: str, networks: list, direct_secure: bool) -> bool:
    """Trust X-Forwarded-Proto only from a configured proxy, using the nearest hop."""
    peer_address = _as_address(peer)
    if peer_address is None or not any(peer_address in network for network in networks):
        return direct_secure
    values = [value.strip().lower() for value in str(forwarded_proto or "").split(",") if value.strip()]
    if not values:
        return direct_secure
    # The nearest trusted proxy writes the right-most value; earlier entries may
    # originate from the client.
    return values[-1] == "https"


class WebApplication:
    def __init__(self, config: WebConfig, state: State, agent=None):
        self.config = config
        self.state = state or WebState(validate_web_files(config.web_state_dir))
        socket_path = config.data.get("web", {}).get("socket", "/run/docker-update-manager/agent.sock")
        self._last_prune = 0.0
        self._session_reject_seen: dict = {}
        for warning in session_policy_warnings(config.data.get("web", {})):
            log.warning(warning)
        self.agent = agent or AgentClient(socket_path)
        self.templates = Jinja2Templates(directory=str(BASE / "templates"))
        self.templates.env.filters["relative_time"] = relative_time
        self.templates.env.filters["utc_timestamp"] = utc_timestamp
        self.templates.env.filters["status_class"] = self._status_class
        self.templates.env.filters["status_label"] = self._status_label
        self.templates.env.filters["operation_timeline"] = operation_timeline
        self.templates.env.filters["runtime_failure_message"] = runtime_failure_message
        self.templates.env.globals.update(
            release_identity=display_version,
            inventory_identity=inventory_identity,
            update_identity=update_identity,
            stage_step=stage_step,
            display_channel=display_channel,
            display_repository=display_repository,
            exact_digest_reference=exact_digest_reference,
            short_digest=short_digest,
            operation_presentation=operation_presentation,
            scan_progress_projection=lambda events: scan_progress_projection(events, self._status_label),
        )
        self.login_limiter = RateLimiter()
        self.app = FastAPI(title="UPT", docs_url=None, redoc_url=None)
        self._mount()

    def _mount(self):
        app = self.app
        app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")
        app.middleware("http")(self._security_middleware)
        app.get("/", response_class=HTMLResponse)(self.overview)
        app.get("/setup", response_class=HTMLResponse)(self.setup_get)
        app.post("/setup", response_class=HTMLResponse)(self.setup_post)
        app.get("/login", response_class=HTMLResponse)(self.login_get)
        app.post("/login", response_class=HTMLResponse)(self.login_post)
        app.post("/logout")(self.logout)
        app.get("/updates", response_class=HTMLResponse)(self.updates)
        app.get("/services", response_class=HTMLResponse)(self.services)
        app.get("/services/{service_key:path}", response_class=HTMLResponse)(self.service_detail)
        app.get("/history", response_class=HTMLResponse)(self.history)
        app.get("/settings", response_class=HTMLResponse)(self.settings)
        app.post("/settings/password", response_class=HTMLResponse)(self.change_password)
        app.post("/scan")(self.start_scan)
        app.post("/services/{service_key:path}/refresh")(self.refresh_service)
        app.get("/api/services/{service_key:path}/refresh")(self.api_refresh_service)
        app.get("/scan/{run_id}/events")(self.scan_events)
        app.post("/operations/update")(self.start_update)
        app.post("/operations/rollback")(self.start_rollback)
        app.post("/compose/bootstrap/review", response_class=HTMLResponse)(self.review_compose_bootstrap)
        app.post("/operations/compose-bootstrap")(self.start_compose_bootstrap)
        app.post("/compose/apply/review", response_class=HTMLResponse)(self.review_compose_apply)
        app.post("/compose/discard/review", response_class=HTMLResponse)(self.review_compose_discard)
        app.post("/operations/compose-reconcile")(self.start_compose_apply)
        app.get("/operations/{operation_id}/events")(self.operation_events)
        app.get("/operations/{operation_id}", response_class=HTMLResponse)(self.operation_detail)
        app.get("/api/health")(self.api_health)
        app.get("/api/overview")(self.api_overview)
        app.get("/api/runtime")(self.api_runtime)
        app.get("/api/services")(self.api_services)
        app.get("/api/services/{service_key:path}")(self.api_service)
        app.get("/api/scan/{run_id}")(self.api_scan)
        app.get("/api/scan")(self.api_scan_active)
        app.get("/api/operations/{operation_id}")(self.api_operation)

    @staticmethod
    def _status_class(status):
        value = str(status or "unknown").lower().replace(" ", "-")
        if value in {"update", "digest-changed", "pinned-update"}:
            return "status-info"
        if value in {"untracked-digest", "warning", "blocked"}:
            return "status-warning"
        if value in {"running"}:
            return "status-info"
        if value in {"starting", "restarting", "paused", "created"}:
            return "status-warning"
        if value in {"current", "pinned", "complete", "healthy", "succeeded", "success"}:
            return "status-success"
        if value in {"registry-error", "arch-unsupported", "failed", "failure", "denied", "unhealthy", "oom-killed", "dead", "exited"}:
            return "status-danger"
        return "status-neutral"

    @staticmethod
    def _status_label(status):
        value = str(status or "UNKNOWN").upper()
        return STATUS_LABELS.get(value, value.replace("_", " ").title())

    @property
    def settings_data(self):
        return self.config.data.get("web", {})

    def _maybe_prune(self):
        now = time.monotonic()
        if now - self._last_prune > 60:
            self._last_prune = now
            try: self.state.prune_sessions()
            except Exception: pass

    @property
    def _trusted_networks(self) -> list:
        return parse_trusted_networks(self.settings_data.get("trusted_proxies", []))

    def _trusted_proxy(self, request: Request) -> bool:
        peer = request.client.host if request.client else ""
        address = _as_address(peer)
        return address is not None and any(address in network for network in self._trusted_networks)

    def _request_context(self, request: Request):
        peer = request.client.host if request.client else ""
        networks = self._trusted_networks
        client_ip = effective_client_ip(peer, request.headers.get("x-forwarded-for", ""), networks)
        secure = forwarded_proto_is_https(
            peer, request.headers.get("x-forwarded-proto", ""), networks, request.url.scheme == "https")
        return client_ip, secure

    @staticmethod
    def _normalise_host(value: str) -> str:
        value = (value or "").strip().lower().rstrip(".")
        if value.startswith("["):
            end = value.find("]")
            return value[1:end] if end > 0 else value.strip("[]")
        # A single colon denotes an optional host:port suffix; multiple
        # colons are an IPv6 literal without brackets.
        return value.rsplit(":", 1)[0] if value.count(":") == 1 else value

    async def _security_middleware(self, request: Request, call_next):
        host = self._normalise_host(request.headers.get("host", ""))
        allowed = {self._normalise_host(str(x)) for x in self.settings_data.get("allowed_hosts", [])}
        if allowed and host not in allowed:
            return JSONResponse({"error": "host is not allowed"}, status_code=400)
        response = await call_next(request)
        _, secure = self._request_context(request)
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        if secure: response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @staticmethod
    def _session_cookie_expiry(session):
        """Remaining browser lifetime bounded by the server absolute expiry.

        Anonymous pre-auth CSRF sessions and unknown sessions keep a
        browser-session cookie; only a real authenticated session becomes
        persistent. The returned browser expiry is never later than the
        server-side ``absolute_expires_at`` so refreshes cannot extend it.
        """
        if not session or not session.get("user_id"):
            return None
        raw = session.get("absolute_expires_at")
        if not raw:
            return None
        try:
            absolute = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        if absolute.tzinfo is None:
            absolute = absolute.replace(tzinfo=timezone.utc)
        remaining = (absolute - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            return None
        return absolute, max(1, int(remaining))

    def _cookie(self, response, request, session_id: str, secure: bool, session=None):
        # Authenticated sessions get a persistent cookie bounded by the fixed
        # server-side absolute expiry. Anonymous CSRF sessions keep a
        # browser-session cookie. The server still enforces idle and absolute
        # lifetimes; the browser lifetime never exceeds the absolute deadline.
        lifetime = self._session_cookie_expiry(session)
        if lifetime is None:
            response.set_cookie("upt_session", session_id, httponly=True, secure=secure, samesite=SESSION_COOKIE_SAMESITE, path="/")
            return
        expires, max_age = lifetime
        response.set_cookie("upt_session", session_id, httponly=True, secure=secure, samesite=SESSION_COOKIE_SAMESITE,
                            path="/", max_age=max_age, expires=expires)

    def _session_policy_view(self):
        policy = session_policy(self.settings_data)
        return {**policy, "idle_label": _duration_label(policy["idle_minutes"]),
                "absolute_label": _duration_label(policy["absolute_hours"] * 60)}

    def _session_idle_minutes(self):
        return session_policy(self.settings_data)["idle_minutes"]

    def _session_absolute_hours(self):
        return session_policy(self.settings_data)["absolute_hours"]

    def _session(self, request: Request, *, create=True):
        cached = getattr(request.state, "upt_session", None)
        if cached is not None:
            sid, session = cached
            if session or not create:
                return sid, session
        else:
            sid = request.cookies.get("upt_session")
            session = self.state.session(sid) if sid else None
            # Why a presented/absent cookie did not yield a session. Never
            # contains the token; used for audit and operator diagnostics.
            if not sid:
                request.state.upt_session_reason = "cookie_missing"
            elif not session:
                request.state.upt_session_reason = "explicitly_revoked" if self.state.session_record(sid) else "unknown_session"
        now = datetime.now(timezone.utc)
        if session:
            try:
                if datetime.fromisoformat(session["absolute_expires_at"]) <= now:
                    request.state.upt_session_reason = "absolute_expired"
                    self.state.revoke_session(sid); session = None
                elif datetime.fromisoformat(session["expires_at"]) <= now:
                    request.state.upt_session_reason = "idle_expired"
                    self.state.revoke_session(sid); session = None
            except (TypeError, ValueError):
                request.state.upt_session_reason = "unknown_session"
                self.state.revoke_session(sid); session = None
        if session:
            idle = self._session_idle_minutes()
            touch_interval = min(SESSION_TOUCH_INTERVAL, timedelta(minutes=idle) / 2)
            try:
                last_seen = datetime.fromisoformat(session.get("last_seen_at", "").replace("Z", "+00:00"))
                should_touch = now - last_seen >= touch_interval
            except (TypeError, ValueError):
                should_touch = True
            if should_touch:
                absolute = datetime.fromisoformat(session["absolute_expires_at"].replace("Z", "+00:00"))
                new_expiry = min(now + timedelta(minutes=idle), absolute).replace(microsecond=0).isoformat()
                touched_at = now.replace(microsecond=0).isoformat()
                self.state.touch_session(sid, touched_at, new_expiry)
                session["last_seen_at"] = touched_at
                session["expires_at"] = new_expiry
            self._maybe_prune()
            request.state.upt_session = (sid, session)
            return sid, session
        if not create:
            # Preserve an invalid cookie's identifier so the caller can show a
            # specific expired/revoked-session notice rather than treating it
            # like an ordinary first visit.
            request.state.upt_session = (sid, None)
            return sid, None
        idle = self._session_idle_minutes()
        absolute = self._session_absolute_hours()
        csrf_token = new_token()
        absolute_expiry = utc_after(hours=absolute)
        idle_expiry = min(datetime.fromisoformat(utc_after(minutes=idle)), datetime.fromisoformat(absolute_expiry)).isoformat()
        sid = self.state.create_session(None, csrf_token, idle_expiry, absolute_expiry, self._request_context(request)[0], request.headers.get("user-agent"))
        session = {"id": sid, "csrf_token": csrf_token, "user_id": None, "username": None,
                   "last_seen_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                   "expires_at": idle_expiry, "absolute_expires_at": absolute_expiry}
        self._maybe_prune()
        request.state.upt_session = (sid, session)
        return sid, session

    def _csrf(self, request: Request, session, token: str | None = None):
        origin = request.headers.get("origin")
        if origin:
            expected = f"{'https' if self._request_context(request)[1] else 'http'}://{request.headers.get('host', request.url.netloc)}"
            if origin.rstrip("/") != expected.rstrip("/"):
                raise PermissionError("request origin is not trusted")
        token = token or request.headers.get("x-csrf-token")
        if not token:
            try:
                form = getattr(request.state, "form_data", None)
                token = form.get("csrf") if form else None
            except Exception: token = None
        if not safe_equal(token, session.get("csrf_token") if session else None):
            raise PermissionError("invalid request token")

    def _audit_session_rejection(self, request: Request, reason: str):
        """Record why a presented session cookie was refused, throttled per client and reason."""
        ip = self._request_context(request)[0]
        key, now = (ip, reason), time.monotonic()
        if now - self._session_reject_seen.get(key, float("-inf")) < SESSION_AUDIT_THROTTLE_SECONDS:
            return
        if len(self._session_reject_seen) >= 256:
            self._session_reject_seen.clear()
        self._session_reject_seen[key] = now
        try:
            self.state.audit("session_rejected", reason, client_ip=ip, user_agent=request.headers.get("user-agent"))
        except Exception:
            pass

    def _user_required(self, request: Request):
        # Protected routes inspect existing sessions only. Anonymous sessions are
        # created solely by the setup/login flows that need CSRF state.
        sid, session = self._session(request, create=False)
        if not session:
            if sid:
                request.state.auth_notice = "session-expired"
                self._audit_session_rejection(request, getattr(request.state, "upt_session_reason", "unknown_session"))
            return sid, session, RedirectResponse("/login?notice=session-expired" if sid else "/login", status_code=303)
        if not session.get("user_id"):
            # Anonymous CSRF sessions used by setup/login are not expired
            # authenticated sessions and should not receive alarming copy.
            return sid, session, RedirectResponse("/login", status_code=303)
        return sid, session, None

    def _render(self, request, template, **context):
        sid, session = self._session(request, create=False)
        if isinstance(context.get("health"), dict):
            context.setdefault("component_versions", version_agreement(context["health"]))
        context.update({"version": __version__, "session": session, "session_policy": self._session_policy_view(),
                        "csrf": session.get("csrf_token") if session else "",
                        "status_labels": STATUS_LABELS})
        response = self.templates.TemplateResponse(request=request, name=template, context=context)
        if sid:
            self._cookie(response, request, sid, self._request_context(request)[1], session)
        return response

    def _agent(self, op, payload=None):
        try:
            return self.agent.call(op, payload or {})
        except AgentUnavailable:
            return {"_error": "The read-only UPT agent is unavailable.", "_error_type": "agent_unavailable"}
        except AgentNotFound:
            message = ("This scan is no longer available. Start a new scan to view current progress."
                       if op == "scan_status" else "The requested service is not present in the cached scan.")
            return {"_error": message, "_error_type": "not_found"}
        except PermissionError:
            return {"_error": "The requested read-only operation is unavailable.", "_error_type": "operation_unavailable"}
        except Exception:
            return {"_error": "The read-only service could not complete this request.", "_error_type": "service_error"}

    def _scan_state(self):
        """Latest scan attempt; an active run carries its full event history.

        The summary RPC returns only a short event tail. Progress rows are a
        projection of every service event in the run, so an active run's events
        are read through the existing bounded `scan_status` run query. This is
        read-only and does not change persisted events or cursors.
        """
        scan = self._agent("scan_status")
        if scan.get("status") in {"running", "finalizing"} and scan.get("id"):
            full = self._agent("scan_status", {"run_id": scan["id"]})
            if not full.get("_error") and isinstance(full.get("events"), list):
                scan = {**scan, "events": full["events"]}
        return scan

    def _auth_page(self, request, template, **context):
        sid, session = self._session(request)
        response = self.templates.TemplateResponse(request=request, name=template, context={"version": __version__, "csrf": session.get("csrf_token") if session else "", **context})
        self._cookie(response, request, sid, self._request_context(request)[1], session)
        return response

    async def setup_get(self, request: Request):
        if self.state.web_user(): return RedirectResponse("/login", status_code=303)
        return self._auth_page(request, "setup.html", error=None)

    async def setup_post(self, request: Request, bootstrap: str = Form(""), username: str = Form(""), password: str = Form(""), password_confirm: str = Form(""), csrf: str = Form("")):
        sid, session = self._session(request)
        try: self._csrf(request, session or {}, csrf)
        except PermissionError: return self._auth_page(request, "setup.html", error="This form expired. Refresh and try again.")
        if self.state.web_user(): return RedirectResponse("/login", status_code=303)
        if password != password_confirm: return self._auth_page(request, "setup.html", error="Passwords do not match.")
        try:
            password_digest = hash_password(password)
            user_id = self.state.create_user_with_credential(token_hash(bootstrap), username, password_digest)
        except Exception:
            return self._auth_page(request, "setup.html", error="Setup code or account details are invalid.")
        self.state.audit("bootstrap", "success", user_id=user_id, username=username, client_ip=self._request_context(request)[0])
        return RedirectResponse("/login?notice=setup", status_code=303)

    async def login_get(self, request: Request):
        if not self.state.web_user(): return RedirectResponse("/setup", status_code=303)
        notices = {
            "setup": "Setup is complete. Sign in with your new account.",
            "password": "Your password was changed. Sign in again with the new password.",
            "logout": "You have been signed out.",
            "session-expired": "Your session expired or was revoked. Sign in again.",
        }
        notice = notices.get(request.query_params.get("notice", ""))
        return self._auth_page(request, "login.html", error=None, notice=notice)

    async def login_post(self, request: Request, username: str = Form(""), password: str = Form(""), csrf: str = Form("")):
        sid, session = self._session(request)
        ip = self._request_context(request)[0]
        try: self._csrf(request, session or {}, csrf)
        except PermissionError: return self._auth_page(request, "login.html", error="This form expired. Refresh and try again.")
        if not self.login_limiter.allowed(ip):
            self.state.audit("login", "rate_limited", client_ip=ip)
            return self._auth_page(request, "login.html", error="Sign-in is temporarily unavailable. Try again shortly.")
        user = self.state.web_user()
        username_matches = bool(user and safe_equal(user.get("username"), username))
        encoded_hash = user.get("password_hash", "") if username_matches else DUMMY_PASSWORD_HASH
        password_matches = verify_password(encoded_hash, password)
        if not username_matches or not password_matches:
            self.login_limiter.failed(ip); self.state.audit("login", "failure", client_ip=ip)
            return self._auth_page(request, "login.html", error="Invalid username or password.")
        self.login_limiter.success(ip)
        if sid: self.state.revoke_session(sid)
        absolute_expiry = utc_after(hours=self._session_absolute_hours())
        idle_expiry = min(datetime.fromisoformat(utc_after(minutes=self._session_idle_minutes())),
                          datetime.fromisoformat(absolute_expiry)).isoformat()
        new_sid = self.state.create_session(user["id"], new_token(), idle_expiry, absolute_expiry, ip, request.headers.get("user-agent"))
        self.state.audit("login", "success", user_id=user["id"], username=user["username"], client_ip=ip)
        response = RedirectResponse("/", status_code=303)
        self._cookie(response, request, new_sid, self._request_context(request)[1],
                     {"user_id": user["id"], "absolute_expires_at": absolute_expiry})
        return response

    async def logout(self, request: Request):
        sid, session = self._session(request, create=False)
        if session:
            try:
                form = await request.form(); self._csrf(request, session, form.get("csrf"))
            except Exception: return JSONResponse({"error": "invalid request token"}, status_code=403)
            self.state.revoke_session(sid); self.state.audit("logout", "success", user_id=session.get("user_id"), username=session.get("username"), client_ip=self._request_context(request)[0])
        response = RedirectResponse("/login?notice=logout", status_code=303); response.delete_cookie("upt_session", path="/"); return response

    async def overview(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect: return redirect
        snapshot = self._agent("snapshot")
        runtime = self._agent("runtime_snapshot")
        verifications = self._agent("verification_snapshot")
        health = self._agent("health")
        scan = self._scan_state()
        trustworthy = snapshot.get("status") == "complete" and bool(snapshot.get("finished_at"))
        items = merge_service_items(snapshot, runtime, verifications)
        attention = attention_items(items, runtime, limit=10000)
        return self._render(
            request, "overview.html", active="overview", snapshot=snapshot,
            health=health, scan=scan, snapshot_available=not snapshot.get("_error"),
            snapshot_trustworthy=trustworthy, runtime=runtime,
            runtime_available=not runtime.get("_error") and runtime.get("status") == "current",
            runtime_stale=runtime_is_stale(runtime), runtime_summary=runtime_summary(runtime),
            merged_items=items, attention_items=attention[:8], attention_count=len(attention),
        )

    def _service_items(self, snapshot):
        return (snapshot or {}).get("payload", {}).get("services", [])

    async def services(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect: return redirect
        snapshot = self._agent("snapshot")
        runtime = self._agent("runtime_snapshot")
        all_items = merge_service_items(snapshot, runtime, self._agent("verification_snapshot"))
        items = list(all_items)
        scan = self._agent("scan_status")
        q = request.query_params.get("q", "").strip().lower(); stack = request.query_params.get("stack", ""); status = request.query_params.get("status", "")
        if q: items = [x for x in items if q in json.dumps({"service": x.get("service", {}), "runtime": x.get("runtime")}).lower()]
        if stack: items = [x for x in items if (x.get("service") or {}).get("stack") == stack]
        if status: items = [x for x in items if x.get("status") == status]
        stacks=sorted({(x.get("service") or {}).get("stack") for x in all_items if (x.get("service") or {}).get("stack")})
        statuses=sorted({x.get("status") for x in all_items if x.get("status")})
        trustworthy = snapshot.get("status") == "complete" and bool(snapshot.get("finished_at"))
        return self._render(request, "services.html", active="services", snapshot=snapshot,
                            snapshot_available=not snapshot.get("_error"),
                            snapshot_trustworthy=trustworthy,
                            scan=scan, runtime=runtime, runtime_available=not runtime.get("_error") and runtime.get("status") == "current",
                            runtime_stale=runtime_is_stale(runtime), runtime_summary=runtime_summary(runtime),
                            inventory_available=trustworthy or bool(runtime.get("captured_at")), items=items,
                            stacks=stacks, statuses=statuses, q=q, stack=stack, status=status)

    async def updates(self, request: Request):
        """Read-only, update-focused projection of the same merged inventory."""
        sid, session, redirect = self._user_required(request)
        if redirect: return redirect
        snapshot = self._agent("snapshot")
        runtime = self._agent("runtime_snapshot")
        verifications = self._agent("verification_snapshot")
        scan = self._scan_state()
        trustworthy = snapshot.get("status") == "complete" and bool(snapshot.get("finished_at"))
        merged = merge_service_items(snapshot, runtime, verifications)
        evidence_available = trustworthy or any(item.get("verification_id") or item.get("verification_failed_at")
                                                for item in merged)
        groups = {"update": [], "undetermined": [], "current": [], "excluded": []}
        for item in merged if evidence_available else []:
            identity = update_identity(item)
            entry = {"item": item, "identity": identity}
            if identity["state"] in ("update", "undetermined"):
                groups[identity["state"]].append(entry)
            elif identity["state"] in ("current", "pinned"):
                groups["current"].append(entry)
            elif identity["state"] == "skipped":
                groups["excluded"].append(entry)
            else:
                groups["undetermined"].append(entry)
        return self._render(request, "updates.html", active="updates", snapshot=snapshot,
                            snapshot_available=not snapshot.get("_error"), snapshot_trustworthy=trustworthy,
                            scan=scan, runtime=runtime, groups=groups,
                            evidence_available=evidence_available)

    @staticmethod
    def _runtime_container(runtime_snapshot, service_key):
        if not isinstance(service_key, str) or not service_key.startswith("container/"):
            return None
        for value in (runtime_snapshot or {}).get("containers", []):
            container = public_runtime_container(value)
            if container and container.get("key") == service_key:
                return container
        return None

    def _compose_status(self, service, result):
        """Fetch the agent's allowlisted Compose status for one Compose container.

        Returns None for non-Compose or absent containers and an
        "unavailable" marker when the agent cannot answer. Display only:
        update review is independently refused by the agent.
        """
        container_id = service.get("container_id")
        if (not container_id or not service.get("stack") or not service.get("compose_service")
                or result.get("runtime_missing")):
            return None
        try:
            data = self.agent.call("compose_status", {"service_key": f"container/{container_id}"})
        except Exception:
            return {"status": "unavailable"}
        if not isinstance(data, dict) or data.get("status") not in COMPOSE_STATUSES:
            return {"status": "unavailable"}
        return data

    async def service_detail(self, request: Request, service_key: str):
        sid, session, redirect = self._user_required(request)
        if redirect: return redirect
        runtime = self._agent("runtime_snapshot")
        snapshot = self._agent("snapshot")
        verifications = self._agent("verification_snapshot")
        merged_item = find_service_item(merge_service_items(snapshot, runtime, verifications), service_key)
        result = dict(merged_item) if merged_item else None
        if result:
            result.pop("_scan_container_id", None)
            result.pop("_scan_service_key", None)
        if not result and any(isinstance(item, dict) and item.get("_error") for item in (snapshot, runtime)):
            response = self._render(request, "error.html", active="services", title="Service details unavailable",
                                    message="The read-only service could not complete this request.")
            response.status_code = 503
            return response
        if not result:
            response = self._render(request, "error.html", active="services", title="Service not found", message="This service is not present in the current inventory.")
            response.status_code = 404
            return response
        service = result.get("service") or {}
        if "runtime" not in result and service.get("container_id"):
            result["runtime"] = self._runtime_container(runtime, f"container/{service['container_id']}")
        runtime_record = result.get("runtime")
        if runtime_record:
            service["ignored"] = bool(service.get("ignored") or runtime_record.get("ignored"))
        result["runtime_stale"] = runtime_is_stale(runtime)
        pinned_update = result.get("status") == "PINNED UPDATE"
        compose_status = self._compose_status(service, result)
        compose_blocks_update = bool(compose_status and compose_status.get("update_blocked"))
        can_update = bool(
            not result.get("runtime_missing") and result.get("verification_fresh")
            and result.get("verification_id")
            and result.get("status") in UPDATE_STATUSES and service.get("container_id")
            and service.get("state") == "running" and service.get("stack")
            and service.get("compose_service") and service.get("working_dir")
            and service.get("compose_files") and not service.get("local_build")
            and not service.get("ignored")
            and (not pinned_update or result.get("target_image"))
        )
        confirmation_id = None
        update_unavailable_reason = None
        if can_update and compose_blocks_update:
            # Display layer only; the agent's update_review preflight
            # independently refuses the same condition.
            can_update = False
            update_unavailable_reason = (
                "Image update blocked until the pending Compose configuration changes are applied or reverted."
                if compose_status.get("status") == "drifted" else
                "Image update blocked because UPT could not verify this service's Compose configuration.")
        if can_update:
            try:
                reviewed = self.agent.call("update_review", {
                    "service_key": service.get("key"),
                    "requested_by": str(session.get("username") or "")[:80],
                    "verification_id": result.get("verification_id"),
                })
                candidate = reviewed.get("confirmation_id") if isinstance(reviewed, dict) else None
                if not isinstance(candidate, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", candidate):
                    raise ValueError("invalid review reference")
                confirmation_id = candidate
            except ComposePreflightRefused as exc:
                can_update = False
                update_unavailable_reason = exc.public_message
            except ComponentVersionMismatch:
                can_update = False
                update_unavailable_reason = VERSION_MISMATCH_MESSAGE
            except Exception:
                can_update = False
                update_unavailable_reason = "UPT could not bind this page to a verified image target. Refresh this service and review again."
        can_review_rollback=bool(
            not result.get("runtime_missing") and result.get("runtime")
            and service.get("container_id") and (result["runtime"] or {}).get("state")=="running"
            and service.get("stack") and service.get("compose_service") and not service.get("ignored")
        )
        rollback_confirmation_id=None; rollback_target=None; rollback_unavailable_reason=None
        if can_review_rollback:
            try:
                reviewed=self.agent.call("rollback_review",{
                    "service_key":service.get("key"),
                    "requested_by":str(session.get("username") or "")[:80],
                })
                candidate=reviewed.get("confirmation_id") if isinstance(reviewed,dict) else None
                target=reviewed.get("rollback") if isinstance(reviewed,dict) else None
                if (not isinstance(candidate,str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}",candidate)
                        or not isinstance(target,dict)):
                    raise ValueError("invalid rollback review response")
                rollback_confirmation_id=candidate; rollback_target=target
            except ComponentVersionMismatch:
                rollback_unavailable_reason=VERSION_MISMATCH_MESSAGE
            except Exception:
                rollback_unavailable_reason="A verified, unexpired rollback point is not currently available for this service."
        return self._render(request, "service.html", active="services", result=result,
                            runtime=runtime, runtime_record=runtime_record,
                            runtime_available=not runtime.get("_error") and runtime.get("status") == "current",
                            can_update=can_update, confirmation_id=confirmation_id,
                            update_unavailable_reason=update_unavailable_reason,
                            compose_status=compose_status,
                            can_review_rollback=bool(rollback_confirmation_id),
                            rollback_confirmation_id=rollback_confirmation_id,
                            rollback_target=rollback_target,
                            rollback_unavailable_reason=rollback_unavailable_reason)

    async def history(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect: return redirect
        result = self._agent("audit_recent", {"limit": 100})
        local = self.state.audit_events(100)
        remote = (result or {}).get("events", [])
        events = sorted(local + remote, key=lambda item: item.get("timestamp", ""), reverse=True)[:100]
        return self._render(request, "history.html", active="history", events=events, error=(result or {}).get("_error"))

    async def settings(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect: return redirect
        return self._render(request, "settings.html", active="settings", user=self.state.web_user(), health=self._agent("health"), message=None, error=None)

    async def change_password(self, request: Request, current_password: str = Form(""), new_password: str = Form(""), new_password_confirm: str = Form(""), csrf: str = Form("")):
        sid, session, redirect = self._user_required(request)
        if redirect: return redirect
        try: self._csrf(request, session, csrf)
        except PermissionError: return self._render(request, "settings.html", active="settings", user=self.state.web_user(), health=self._agent("health"), error="This form expired. Refresh and try again.", message=None)
        user=self.state.web_user()
        if not verify_password(user.get("password_hash", ""), current_password) or new_password != new_password_confirm:
            self.state.audit("password_change", "failure", user_id=user["id"], username=user["username"], client_ip=self._request_context(request)[0])
            return self._render(request, "settings.html", active="settings", user=user, health=self._agent("health"), error="Current password or new password is invalid.", message=None)
        try: hashed=hash_password(new_password)
        except Exception as exc: return self._render(request, "settings.html", active="settings", user=user, health=self._agent("health"), error=str(exc), message=None)
        self.state.update_password(user["id"], hashed); self.state.audit("password_change", "success", user_id=user["id"], username=user["username"], client_ip=self._request_context(request)[0])
        response=RedirectResponse("/login?notice=password", status_code=303); response.delete_cookie("upt_session", path="/"); return response

    async def start_scan(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect: return redirect
        try:
            form = await request.form(); self._csrf(request, session, form.get("csrf"))
        except Exception: return JSONResponse({"error": "invalid request token"}, status_code=403)
        try:
            result = self.agent.call("scan_start", {})
        except AgentUnavailable:
            return JSONResponse({"error": "The read-only UPT agent is unavailable."}, status_code=503)
        except Exception:
            return JSONResponse({"error": "The read-only agent could not start a scan."}, status_code=503)
        self.state.audit("scan", "started", user_id=session.get("user_id"), username=session.get("username"), client_ip=self._request_context(request)[0])
        return JSONResponse(result, status_code=202)

    async def refresh_service(self, request: Request, service_key: str):
        sid, session, redirect = self._user_required(request)
        if redirect: return JSONResponse({"error": "authentication required"}, status_code=401)
        try:
            form = await request.form()
            if len(list(form.multi_items())) != 1 or "csrf" not in form:
                raise PermissionError("invalid form")
            self._csrf(request, session, form.get("csrf"))
        except Exception:
            return JSONResponse({"error": "invalid request token"}, status_code=403)
        try:
            result = self.agent.call("refresh_start", {"service_key": service_key})
        except ValueError:
            return JSONResponse({"error": "invalid service identifier"}, status_code=400)
        except Exception:
            return JSONResponse({"error": "service check unavailable"}, status_code=503)
        return JSONResponse(result, status_code=202 if result.get("status") == "checking" else 200,
                            headers={"Cache-Control": "no-store"})

    async def api_refresh_service(self, request: Request, service_key: str):
        sid, session, redirect = self._user_required(request)
        if redirect: return JSONResponse({"error": "authentication required"}, status_code=401)
        try:
            result = self.agent.call("refresh_status", {"service_key": service_key})
        except ValueError:
            return JSONResponse({"error": "invalid service identifier"}, status_code=400)
        except Exception:
            return JSONResponse({"error": "service check unavailable"}, status_code=503)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})

    async def start_update(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect:
            return redirect
        try:
            form = await request.form()
            pairs = list(form.multi_items())
            if len(pairs) != 3 or {key for key, _ in pairs} != {"csrf", "confirmation_id", "confirm_update"}:
                return JSONResponse({"error": "invalid update request"}, status_code=400)
            self._csrf(request, session, form.get("csrf"))
        except Exception:
            return JSONResponse({"error": "invalid request token"}, status_code=403)
        confirmation_id = form.get("confirmation_id")
        if form.get("confirm_update") != "yes" or not isinstance(confirmation_id, str):
            return JSONResponse({"error": "confirm the single-service update before continuing"}, status_code=400)
        client_ip, _ = self._request_context(request)
        payload = {
            "confirmation_id": confirmation_id,
            "requested_by": str(session.get("username") or "")[:80],
            "client_ip": client_ip[:64],
            "user_agent": str(request.headers.get("user-agent", ""))[:300],
        }
        try:
            result = self.agent.call("update_start", payload)
        except AgentUnavailable:
            return JSONResponse({"error": "The UPT agent is unavailable; no update was started."}, status_code=503)
        except ComponentVersionMismatch:
            return self._version_mismatch_response()
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=409)
        except RuntimeError as exc:
            message = str(exc)
            if "active" in message or "modifying" in message or "eligible" in message or "update" in message or "Compose" in message:
                return JSONResponse({"error": message}, status_code=409)
            return JSONResponse({"error": "The agent could not safely start this update."}, status_code=503)
        except Exception:
            return JSONResponse({"error": "The agent could not safely start this update."}, status_code=503)
        operation_id = result.get("operation_id") if isinstance(result, dict) else None
        if not isinstance(operation_id, str) or not re.fullmatch(r"[a-f0-9]{32}", operation_id):
            return JSONResponse({"error": "The agent returned an invalid operation reference."}, status_code=503)
        return RedirectResponse(f"/operations/{operation_id}", status_code=303)

    async def start_rollback(self,request:Request):
        sid,session,redirect=self._user_required(request)
        if redirect: return redirect
        try:
            form=await request.form(); pairs=list(form.multi_items())
            if len(pairs)!=3 or {key for key,_ in pairs}!={"csrf","confirmation_id","confirm_rollback"}:
                return JSONResponse({"error":"invalid rollback request"},status_code=400)
            self._csrf(request,session,form.get("csrf"))
        except Exception:
            return JSONResponse({"error":"invalid request token"},status_code=403)
        confirmation_id=form.get("confirmation_id")
        if form.get("confirm_rollback")!="yes" or not isinstance(confirmation_id,str):
            return JSONResponse({"error":"confirm the single-service rollback before continuing"},status_code=400)
        client_ip,_=self._request_context(request)
        payload={"confirmation_id":confirmation_id,
                 "requested_by":str(session.get("username") or "")[:80],
                 "client_ip":client_ip[:64],
                 "user_agent":str(request.headers.get("user-agent",""))[:300]}
        try: result=self.agent.call("rollback_start",payload)
        except AgentUnavailable:
            return JSONResponse({"error":"The UPT agent is unavailable; no rollback was started."},status_code=503)
        except ComponentVersionMismatch:
            return self._version_mismatch_response()
        except ValueError as exc: return JSONResponse({"error":str(exc)},status_code=409)
        except RuntimeError as exc:
            message=str(exc)
            if "active" in message or "rollback" in message or "Compose" in message or "service" in message:
                return JSONResponse({"error":message},status_code=409)
            return JSONResponse({"error":"The agent could not safely start this rollback."},status_code=503)
        except Exception:
            return JSONResponse({"error":"The agent could not safely start this rollback."},status_code=503)
        operation_id=result.get("operation_id") if isinstance(result,dict) else None
        if not isinstance(operation_id,str) or not re.fullmatch(r"[a-f0-9]{32}",operation_id):
            return JSONResponse({"error":"The agent returned an invalid operation reference."},status_code=503)
        return RedirectResponse(f"/operations/{operation_id}",status_code=303)

    async def review_compose_bootstrap(self, request: Request):
        return await self._review_compose(request, "bootstrap")

    async def review_compose_apply(self, request: Request):
        return await self._review_compose(request, "apply")

    async def review_compose_discard(self, request: Request):
        return await self._review_compose(request, "discard")

    @staticmethod
    def _bootstrap_observations_valid(observations):
        """Display-only facts: a few short label/value strings, nothing else."""
        return (isinstance(observations, list) and len(observations) <= 6
                and all(isinstance(item, dict) and set(item) == {"label", "value"}
                        and all(isinstance(item[key], str) and 0 < len(item[key]) <= 200 for key in item)
                        for item in observations))

    @staticmethod
    def _namespace_review_valid(namespace, action):
        """Optional Apply-only display fact: a safe owner service name, nothing else."""
        if namespace is None:
            return True
        return (action == "apply" and isinstance(namespace, dict)
                and set(namespace) == {"owner", "owner_unchanged", "configuration_only_recovery"}
                and isinstance(namespace["owner"], str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", namespace["owner"]) is not None
                and namespace["owner_unchanged"] is True and namespace["configuration_only_recovery"] is True)

    async def _review_compose(self, request: Request, action):
        sid, session, redirect = self._user_required(request)
        if redirect:
            return redirect
        try:
            form = await request.form()
            pairs = list(form.multi_items())
            if len(pairs) != 3 or {key for key, _ in pairs} != {"csrf", "service_key", "action"} or form.get("action") != action:
                return JSONResponse({"error": "invalid configuration review request"}, status_code=400)
            self._csrf(request, session, form.get("csrf"))
        except Exception:
            return JSONResponse({"error": "invalid request token"}, status_code=403)
        try:
            review_payload = {"service_key":form.get("service_key"), "requested_by":str(session.get("username") or "")[:80]}
            if action != 'bootstrap':
                review_payload['action'] = action
            reviewed = self.agent.call('compose_bootstrap_review' if action == 'bootstrap' else 'compose_reconcile_review', review_payload)
            confirmation_id = reviewed.get("confirmation_id")
            review = reviewed.get("review")
            if (not isinstance(confirmation_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", confirmation_id)
                    or not isinstance(review, dict) or review.get("image_unchanged") is not True
                    or review.get("service_recreated") is not (action != "discard")
                    or review.get("automatic_recovery") is not (action != "bootstrap")
                    or (action == "bootstrap" and (review.get("action") != "bootstrap" or review.get("previous_source_known") is not False
                                                   or not self._bootstrap_observations_valid(review.get("observations"))))
                    or (action == "discard" and review.get("action") != "discard")
                    or not self._namespace_review_valid(review.get("namespace"), action)):
                raise ValueError("invalid review response")
        except ComponentVersionMismatch:
            response = self._render(request, "error.html", active="services", title="Upgrade incomplete",
                                    message=VERSION_MISMATCH_MESSAGE + " No source changes were made.")
            response.status_code = 409
            return response
        except DiscardRefused as exc:
            response = self._render(request, "error.html", active="services", title="Discard unavailable",
                                    message=exc.public_message + " No source changes were made. Refresh and review again.")
            response.status_code = 409
            return response
        except Exception:
            response = self._render(request, "error.html", active="services", title=action.title() + " unavailable",
                                    message="UPT could not verify the current configuration and recovery evidence. Refresh the service and review again.")
            response.status_code = 409
            return response
        return self._render(request, "compose_bootstrap.html" if action == "bootstrap" else "compose_apply.html", active="services", review=review,
                            service_key=form.get("service_key"), confirmation_id=confirmation_id, compose_action=action)

    async def start_compose_bootstrap(self, request: Request):
        return await self._start_compose(request, bootstrap=True)

    async def start_compose_apply(self, request: Request):
        return await self._start_compose(request)

    async def _start_compose(self, request: Request, *, bootstrap=False):
        sid, session, redirect = self._user_required(request)
        if redirect:
            return redirect
        ack_field = "acknowledge_no_rollback" if bootstrap else "confirm_apply"
        try:
            form = await request.form()
            pairs = list(form.multi_items())
            if len(pairs) != 3 or {key for key, _ in pairs} != {"csrf", "confirmation_id", ack_field}:
                return JSONResponse({"error": "invalid configuration confirmation request"}, status_code=400)
            self._csrf(request, session, form.get("csrf"))
        except Exception:
            return JSONResponse({"error": "invalid request token"}, status_code=403)
        if form.get(ack_field) != "yes" or not isinstance(form.get("confirmation_id"), str):
            return JSONResponse({"error": "confirm the reviewed configuration action before continuing"}, status_code=400)
        client_ip, _ = self._request_context(request)
        try:
            start_payload = {
                "confirmation_id": form["confirmation_id"], "requested_by": str(session.get("username") or "")[:80],
                "client_ip": client_ip[:64], "user_agent": str(request.headers.get("user-agent", ""))[:300]}
            if bootstrap:
                start_payload['acknowledge_no_rollback'] = True
            result = self.agent.call('compose_bootstrap_start' if bootstrap else 'compose_reconcile_start', start_payload)
        except ComponentVersionMismatch:
            return self._version_mismatch_response()
        except (ValueError, RuntimeError):
            return JSONResponse({"error": "Configuration action could not start safely. Refresh and review again."}, status_code=409)
        except Exception:
            return JSONResponse({"error": "The UPT agent is unavailable; no configuration action was started."}, status_code=503)
        operation_id = result.get("operation_id") if isinstance(result, dict) else None
        if not self._valid_operation_id(operation_id):
            return JSONResponse({"error": "invalid operation reference"}, status_code=503)
        return RedirectResponse(f"/operations/{operation_id}", status_code=303)

    @staticmethod
    def _version_mismatch_response():
        # Distinct bounded reason so clients never confuse a partial upgrade
        # with authentication failure or agent unavailability.
        return JSONResponse({"error": VERSION_MISMATCH_MESSAGE, "reason": VERSION_MISMATCH}, status_code=409)

    @staticmethod
    def _valid_operation_id(operation_id):
        return isinstance(operation_id, str) and re.fullmatch(r"[a-f0-9]{32}", operation_id) is not None

    async def operation_detail(self, request: Request, operation_id: str):
        sid, session, redirect = self._user_required(request)
        if redirect:
            return redirect
        if not self._valid_operation_id(operation_id):
            response = self._render(request, "error.html", active="history", title="Operation not found", message="This operation is not available.")
            response.status_code = 404
            return response
        try:
            operation = await asyncio.to_thread(self.agent.call, "operation_status",
                                                {"operation_id": operation_id, "after_event_id": 0})
        except AgentNotFound:
            operation = None
        except Exception:
            response = self._render(request, "error.html", active="history", title="Operation unavailable", message="The UPT agent could not load this operation.")
            response.status_code = 503
            return response
        if not operation:
            response = self._render(request, "error.html", active="history", title="Operation not found", message="This operation is not available.")
            response.status_code = 404
            return response
        return self._render(request, "operation.html", active="history", operation=operation)

    async def operation_events(self, request: Request, operation_id: str):
        sid, session, redirect = self._user_required(request)
        if redirect:
            async def expired_stream():
                yield 'event: operation-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
            return StreamingResponse(expired_stream(), media_type="text/event-stream",
                                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})
        if not self._valid_operation_id(operation_id):
            return JSONResponse({"error": "operation not found"}, status_code=404)
        user_id = session.get("user_id")

        async def session_is_valid():
            try:
                current = await asyncio.to_thread(self.state.session, sid)
                if not current or current.get("user_id") != user_id:
                    return False
                now = datetime.now(timezone.utc)
                idle = datetime.fromisoformat(current["expires_at"].replace("Z", "+00:00"))
                absolute = datetime.fromisoformat(current["absolute_expires_at"].replace("Z", "+00:00"))
                return idle > now and absolute > now
            except Exception:
                return False

        def cursor_value():
            raw = request.headers.get("last-event-id") or request.query_params.get("after", "0")
            try:
                return max(0, min(int(raw), 2**63 - 1))
            except (TypeError, ValueError):
                return 0

        async def events():
            cursor = cursor_value()
            yield "retry: 3000\n\n"
            while not await request.is_disconnected():
                if not await session_is_valid():
                    yield 'event: operation-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                    return
                try:
                    operation = await asyncio.to_thread(
                        self.agent.call, "operation_status",
                        {"operation_id": operation_id, "after_event_id": cursor},
                    )
                except AgentNotFound:
                    yield 'event: operation-not-found\ndata: {"message":"This operation is no longer available."}\n\n'
                    return
                except Exception:
                    if not await session_is_valid():
                        yield 'event: operation-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                        return
                    yield 'event: operation-warning\ndata: {"message":"UPT agent temporarily unavailable; reconnecting."}\n\n'
                    await asyncio.sleep(2)
                    continue
                for event in operation.get("events", []):
                    if not await session_is_valid():
                        yield 'event: operation-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                        return
                    try:
                        event_id = int(event.get("id"))
                    except (TypeError, ValueError):
                        continue
                    if event_id <= cursor:
                        continue
                    cursor = event_id
                    event = {**event, "presentation": {"role": operation_event_role(event)}}
                    yield f"id: {cursor}\nevent: operation-event\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
                if operation.get("status") in {"succeeded", "failed", "blocked"}:
                    if not await session_is_valid():
                        yield 'event: operation-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                        return
                    event_name = {"succeeded": "operation-complete", "failed": "operation-failed",
                                  "blocked": "operation-blocked"}[operation["status"]]
                    terminal = {**operation, "presentation": operation_presentation(operation)}
                    yield f"event: {event_name}\ndata: {json.dumps(terminal, separators=(',', ':'))}\n\n"
                    return
                yield ": keep-alive\n\n"
                await asyncio.sleep(1)

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})

    async def scan_events(self, request: Request, run_id: str):
        sid, session, redirect = self._user_required(request)
        if redirect:
            async def expired_stream():
                yield 'event: scan-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
            return StreamingResponse(
                expired_stream(), media_type="text/event-stream",
                headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
            )
        user_id = session.get("user_id")

        async def session_is_valid():
            """Recheck revocation/expiry without touching or extending the session."""
            try:
                current = await asyncio.to_thread(self.state.session, sid)
                if not current or current.get("user_id") != user_id:
                    return False
                now = datetime.now(timezone.utc)
                idle = datetime.fromisoformat(current["expires_at"].replace("Z", "+00:00"))
                absolute = datetime.fromisoformat(current["absolute_expires_at"].replace("Z", "+00:00"))
                return idle > now and absolute > now
            except Exception:
                # Fail closed: a long-lived stream must not outlive a session
                # merely because its revocation check could not be performed.
                return False

        def event_cursor():
            raw = request.headers.get("last-event-id") or request.query_params.get("after", "0")
            try:
                return max(0, min(int(raw), 2**63 - 1))
            except (TypeError, ValueError):
                return 0

        async def events():
            cursor = event_cursor()
            yield "retry: 3000\n\n"
            while not await request.is_disconnected():
                if not await session_is_valid():
                    yield 'event: scan-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                    return
                try:
                    state = await asyncio.to_thread(
                        self.agent.call,
                        "scan_status",
                        {"run_id": run_id, "after_event_id": cursor},
                    )
                except AgentNotFound:
                    if not await session_is_valid():
                        yield 'event: scan-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                        return
                    yield 'event: scan-not-found\ndata: {"message":"This scan is no longer available. Start a new scan to view current progress."}\n\n'
                    return
                except Exception:
                    if not await session_is_valid():
                        yield 'event: scan-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                        return
                    # Keep the stream alive through temporary agent/socket
                    # disruption. EventSource will also reconnect itself if
                    # the transport closes; the persisted cursor prevents a
                    # full replay when it does.
                    yield "event: scan-warning\ndata: {\"message\":\"Agent temporarily unavailable; reconnecting.\"}\n\n"
                    await asyncio.sleep(2)
                    continue
                if not await session_is_valid():
                    yield 'event: scan-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                    return
                for event in state.get("events", []):
                    if not await session_is_valid():
                        yield 'event: scan-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                        return
                    event_id = event.get("id")
                    try:
                        event_id = int(event_id)
                    except (TypeError, ValueError):
                        continue
                    if event_id <= cursor:
                        continue
                    cursor = event_id
                    payload = json.dumps(event, separators=(",", ":"))
                    yield f"id: {cursor}\nevent: scan-event\ndata: {payload}\n\n"
                if state.get("status") not in {"running", "finalizing"}:
                    if not await session_is_valid():
                        yield 'event: scan-auth-expired\ndata: {"message":"Your session expired or was revoked. Sign in again."}\n\n'
                        return
                    payload = json.dumps(state, separators=(",", ":"))
                    event_name = {
                        "complete": "scan-complete",
                        "partial": "scan-partial",
                    }.get(state.get("status"), "scan-failed")
                    yield f"event: {event_name}\ndata: {payload}\n\n"
                    return
                yield ": keep-alive\n\n"
                await asyncio.sleep(1)

        return StreamingResponse(
            events(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
        )

    async def api_health(self, request: Request):
        result = self._agent("health")
        if result.get("_error"): return JSONResponse({"ok": False, "agent": "unavailable"}, status_code=503)
        return JSONResponse({"ok": True, "agent": "reachable"})

    async def api_overview(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect: return JSONResponse({"error": "authentication required"}, status_code=401)
        snapshot = self._agent("snapshot")
        runtime = self._agent("runtime_snapshot")
        verifications = self._agent("verification_snapshot")
        return JSONResponse({"snapshot": snapshot, "latest_attempt": self._agent("scan_status"),
                             "health": self._agent("health"), "runtime": runtime,
                             "services": _public_service_items(merge_service_items(snapshot, runtime, verifications))})

    async def api_runtime(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect: return JSONResponse({"error": "authentication required"}, status_code=401)
        return JSONResponse(self._agent("runtime_snapshot"))

    async def api_services(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect: return JSONResponse({"error": "authentication required"}, status_code=401)
        snapshot = self._agent("snapshot")
        runtime = self._agent("runtime_snapshot")
        verifications = self._agent("verification_snapshot")
        return JSONResponse({**snapshot, "runtime": runtime,
                             "items": _public_service_items(merge_service_items(snapshot, runtime, verifications))})

    async def api_service(self, request: Request, service_key: str):
        sid, session, redirect = self._user_required(request)
        if redirect: return JSONResponse({"error": "authentication required"}, status_code=401)
        runtime = self._agent("runtime_snapshot")
        snapshot = self._agent("snapshot")
        merged_item = find_service_item(merge_service_items(snapshot, runtime, self._agent("verification_snapshot")), service_key)
        if not merged_item:
            return JSONResponse({"error": "service not found"}, status_code=404)
        result = dict(merged_item)
        result.pop("_scan_container_id", None)
        result.pop("_scan_service_key", None)
        service = result.get("service") or {}
        if not result.get("runtime") and service.get("container_id"):
            result["runtime"] = self._runtime_container(runtime, f"container/{service['container_id']}")
        if result.get("runtime"):
            service["ignored"] = bool(service.get("ignored") or result["runtime"].get("ignored"))
        result["runtime_stale"] = runtime_is_stale(runtime)
        result.pop("_scan_container_id", None)
        return JSONResponse(result)

    async def api_scan(self, request: Request, run_id: str):
        sid, session, redirect = self._user_required(request)
        if redirect: return JSONResponse({"error": "authentication required"}, status_code=401)
        try:
            after_event_id = max(0, int(request.query_params.get("after", "0")))
        except ValueError:
            after_event_id = 0
        result = self._agent("scan_status", {"run_id": run_id, "after_event_id": after_event_id})
        if result.get("_error"):
            status = 404 if result.get("_error_type") == "not_found" else 503
            return JSONResponse({"error": result["_error"]}, status_code=status)
        return JSONResponse(result)

    async def api_scan_active(self, request: Request):
        sid, session, redirect = self._user_required(request)
        if redirect:
            return JSONResponse({"error": "authentication required"}, status_code=401)
        return JSONResponse(self._agent("scan_status", {}))

    async def api_operation(self, request: Request, operation_id: str):
        sid, session, redirect = self._user_required(request)
        if redirect:
            return JSONResponse({"error": "authentication required"}, status_code=401)
        if not self._valid_operation_id(operation_id):
            return JSONResponse({"error": "operation not found"}, status_code=404)
        try:
            after = max(0, min(int(request.query_params.get("after", "0")), 2**63 - 1))
        except ValueError:
            after = 0
        try:
            result = await asyncio.to_thread(self.agent.call, "operation_status",
                                             {"operation_id": operation_id, "after_event_id": after})
        except AgentNotFound:
            return JSONResponse({"error": "operation not found"}, status_code=404)
        except AgentUnavailable:
            return JSONResponse({"error": "agent unavailable"}, status_code=503)
        except Exception:
            return JSONResponse({"error": "operation status unavailable"}, status_code=503)
        return JSONResponse(result, headers={"Cache-Control": "no-store"})


def create_app(config: WebConfig | None = None, state: State | None = None, agent=None):
    config = config or WebConfig()
    return WebApplication(config, state, agent=agent).app
