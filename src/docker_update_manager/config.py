from __future__ import annotations
import copy
import os
from pathlib import Path
import yaml

DEFAULTS = {"auto_pin_after_update": False, "health_timeout": 90, "conversion_root": "/root",
            "retention": {"recovery_days": 7, "compose_backups_days": 7, "rollback_images_days": 7,
                          "operational_logs_days": 7, "temporary_files_days": 7, "disk_history_days": 30,
                          "audit_history_days": 365, "resolved_rollback_metadata_days": 30},
            "exclude": {"services": [], "images": [], "stacks": []}, "services": {}}

WEB_DEFAULTS = {"web": {"listen": "127.0.0.1", "port": 8787,
                "socket": "/run/docker-update-manager/agent.sock",
                "state_dir": "/var/lib/docker-update-manager-web", "trusted_proxies": [],
                "allowed_hosts": ["localhost", "127.0.0.1", "[::1]", "testserver"],
                "allow_insecure_http": False, "state_owner": "docker-update-manager-web",
                "session_idle_minutes": 43200, "session_absolute_hours": 720,
                "bootstrap_minutes": 15, "scan_retention_days": 30, "audit_retention_days": 365,
                "verification_freshness_hours": 6}}


def _read_config_text(path: Path) -> str:
    """Read a configuration file, converting OS errors into a curated message."""
    try:
        return path.read_text()
    except OSError as exc:
        raise ValueError(f"cannot read configuration file {path}: {exc.strerror or exc}") from None


def _config_exists(path: Path) -> bool:
    """Return True when the path exists, without leaking a raw OSError.

    ``Path.exists()`` raises ``PermissionError`` on some supported Python
    versions when a parent directory is unreadable. Configuration discovery must
    report that condition as a clear, curated error instead of a traceback.
    """
    try:
        return path.exists()
    except OSError as exc:
        raise ValueError(f"cannot access configuration file {path}: {exc.strerror or exc}") from None


class Config:
    def __init__(self, path: str | None = None):
        self.path = Path(path or os.getenv("UPT_CONFIG") or os.getenv("DUM_CONFIG", "/etc/docker-update-manager/config.yml"))
        self.data = copy.deepcopy(DEFAULTS)
        if _config_exists(self.path):
            loaded = yaml.safe_load(_read_config_text(self.path)) or {}
            if not isinstance(loaded, dict): raise ValueError("configuration root must be a mapping")
            if "web" in loaded:
                import sys
                print("warning: ignoring legacy web: settings in config.yml; web.yml is authoritative", file=sys.stderr)
                loaded = {key: value for key, value in loaded.items() if key != "web"}
            self.data = _merge(DEFAULTS, loaded)
    @property
    def state_dir(self): return Path(os.getenv("UPT_STATE_DIR") or os.getenv("DUM_STATE_DIR", "/var/lib/docker-update-manager"))
    @property
    def log_dir(self): return Path(os.getenv("UPT_LOG_DIR") or os.getenv("DUM_LOG_DIR", "/var/log/docker-update-manager"))
    def ignored(self, service) -> bool:
        ex = self.data.get("exclude", {})
        return service.key in ex.get("services", []) or service.image in ex.get("images", []) or service.stack in ex.get("stacks", []) or self.data.get("services", {}).get(service.key, {}).get("policy") == "ignore"
    def redacted(self):
        sensitive = ("token", "password", "passwd", "secret", "credential", "authorization",
                     "api_key", "apikey", "api-key", "webhook")
        def walk(x):
            if isinstance(x, dict): return {k: ("<redacted>" if any(s in k.lower() for s in sensitive) else walk(v)) for k,v in x.items()}
            if isinstance(x, list): return [walk(v) for v in x]
            return x
        return walk(self.data)

class WebConfig:
    """Authoritative configuration for the web/agent trust boundary."""
    def __init__(self, path: str | None = None):
        self.path = Path(path or os.getenv("UPT_WEB_CONFIG", "/etc/docker-update-manager/web.yml"))
        self.data = copy.deepcopy(WEB_DEFAULTS)
        if _config_exists(self.path):
            loaded = yaml.safe_load(_read_config_text(self.path)) or {}
            if not isinstance(loaded, dict): raise ValueError("web configuration root must be a mapping")
            unknown = set(loaded) - {"web"}
            if unknown: raise ValueError(f"unsupported web configuration keys: {chr(44).join(sorted(unknown))}")
            self.data = _merge(WEB_DEFAULTS, loaded)
    @property
    def settings(self): return self.data["web"]
    @property
    def socket_path(self): return Path(self.settings["socket"])
    @property
    def web_state_dir(self): return Path(os.getenv("UPT_WEB_STATE_DIR") or os.getenv("DUM_WEB_STATE_DIR") or self.settings["state_dir"])

SESSION_IDLE_MINUTES_DEFAULT = 43200
SESSION_ABSOLUTE_HOURS_DEFAULT = 720


def session_policy(settings: dict) -> dict:
    """The single authoritative parser for the effective web session lifetime.

    Every consumer (session creation, idle refresh, Settings, startup and
    installer warnings) must use this. Numeric values are clamped to at least 1;
    missing or non-numeric values fall back to the 30-day defaults. The idle
    window can never exceed the absolute lifetime, so ``idle_minutes`` is the
    value actually applied to a new session.
    """
    def _int(key, default):
        try:
            return max(1, int(settings.get(key, default)))
        except (TypeError, ValueError):
            return default
    absolute = _int("session_absolute_hours", SESSION_ABSOLUTE_HOURS_DEFAULT)
    idle = min(_int("session_idle_minutes", SESSION_IDLE_MINUTES_DEFAULT), absolute * 60)
    return {"idle_minutes": idle, "absolute_hours": absolute,
            "shorter_than_default": idle < SESSION_IDLE_MINUTES_DEFAULT or absolute < SESSION_ABSOLUTE_HOURS_DEFAULT}


def session_policy_warnings(settings: dict) -> list[str]:
    """Operator-owned overrides are honoured, never rewritten; this only reports them."""
    policy = session_policy(settings)
    if not policy["shorter_than_default"]:
        return []
    return [f"web session lifetime is shorter than the documented 30-day defaults "
            f"(session_idle_minutes={policy['idle_minutes']}, session_absolute_hours={policy['absolute_hours']}; "
            f"defaults are {SESSION_IDLE_MINUTES_DEFAULT} and {SESSION_ABSOLUTE_HOURS_DEFAULT}). "
            f"Edit web.yml to change it; the installer does not overwrite an existing web.yml."]


def _merge(a, b):
    """Deep-merge mappings without sharing nested containers with the defaults."""
    out = {key: copy.deepcopy(value) for key, value in a.items()}
    for key, value in b.items():
        out[key] = _merge(out[key], value) if isinstance(value, dict) and isinstance(out.get(key), dict) else copy.deepcopy(value)
    return out
