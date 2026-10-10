"""Compose drift status, configuration-input inventory and redacted diffs.

This module is presentation-independent and never executes Docker. Callers
resolve Compose models/hashes with their own bounded runners and pass the
results here. Nothing returned by compute_diff() contains raw Compose source,
resolved environment values or other free-form model values; every
browser-visible string comes from an explicit allowlisted formatter.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass, field

import yaml

IN_SYNC = "in_sync"
DRIFTED = "drifted"
UNVERIFIABLE = "unverifiable"
UNSUPPORTED = "unsupported"
STATUSES = frozenset({IN_SYNC, DRIFTED, UNVERIFIABLE, UNSUPPORTED})
# Web image updates require a complete, reproducible input inventory.
UPDATE_ALLOWED_STATUSES = frozenset({IN_SYNC})

MAX_INPUT_FILES = 32
MAX_INPUT_BYTES = 1024 * 1024
MAX_TOTAL_INPUT_BYTES = 16 * 1024 * 1024
MAX_LIST_ITEMS = 20

# Bounded reason codes. Messages are fixed server copy, never derived from
# exception text, paths or Compose values.
REASONS = {
    "namespace_owner_unproven": "UPT could not prove the namespace owner and its execution context.",
    "namespace_owner_changed": "The namespace owner or consumer changed during verification.",
    "namespace_owner_replaced": "The consumer references a different namespace owner container.",
    "namespace_stale": "The consumer network namespace is no longer proven fresh.",
    "namespace_owner_unhealthy": "The namespace owner is not ready under the declared health condition.",
    "namespace_owner_has_dependents": "Namespace consumers depend on this container. UPT cannot mutate the namespace owner.",
    "namespace_unsupported_compose": "Namespace consumer mutation is unavailable pending separate Compose qualification and review.",
    "namespace_update_unresolved": "A namespace image update requires manual recovery before UPT can establish trust or mutate this service.",
    "bootstrap_unresolved": "Bootstrap verification was interrupted or failed. Manual recovery is required; automatic capture and mutation are fenced.",
    "namespace_apply_unresolved": "A namespace configuration Apply requires manual recovery before UPT can establish trust or mutate this service.",
    "namespace_apply_unqualified": "This Docker/Compose runtime is not qualified for namespace configuration Apply and recovery.",
    "namespace_env_file_unsupported": "Namespace configuration Apply does not support an env_file on the selected service.",
    "namespace_change_unqualified": "This configuration change is outside the namespace changes UPT has qualified for Apply (environment, labels, bounded command/entrypoint, restart policy, json-file logging, read-only bind).",
    "namespace_relationship_changed": "The namespace owner relationship would change. Owner, network mode and dependency settings cannot be applied.",
    "namespace_baseline_unproven": "UPT could not reproduce the trusted namespace consumer configuration from its retained inputs.",
    "trust_store_unavailable": "UPT could not read its trusted configuration store. Apply is unavailable.",
    # unverifiable
    "service_not_found": "The container is no longer present in the Docker runtime.",
    "not_compose_service": "This container is not managed by a discoverable Compose project.",
    "service_not_running": "The container is not running, so its configuration identity cannot be compared.",
    "runtime_hash_missing": "The container has no valid Compose configuration identity label.",
    "compose_model_unavailable": "Docker Compose could not resolve this project's configuration.",
    "compose_hash_unavailable": "Docker Compose could not report this service's configuration identity.",
    "service_missing_from_model": "The Compose project on disk no longer defines this service.",
    "hash_excluded_fields": "The service uses build, pull-policy, profile or scale settings that the Compose configuration identity does not cover.",
    "sources_changed_during_check": "The Compose configuration changed while UPT was checking it. Check again.",
    "runtime_changed_during_check": "The container changed while UPT was checking it. Check again.",
    # drifted
    "config_hash_differs": "The Compose configuration on disk differs from the configuration used to create this container.",
    "replica_hash_differs": "A running replica of this service was created from a different Compose configuration.",
    "image_differs": "The Compose image reference differs from the image this container is running.",
    # inventory: drift detectable, trusted baseline unsupported
    "compose_include": "The project uses Compose include files.",
    "compose_extends_file": "A service extends a definition from another file.",
    "label_file": "A service reads labels from a label file.",
    "external_secret_or_config": "The project uses file-backed, environment-backed or external Compose secrets or configs.",
    "interpolated_input_path": "An env_file path uses variable interpolation.",
    "unsupported_yaml": "A Compose file uses YAML features UPT cannot inspect safely.",
    "input_limit": "The configuration inputs exceed UPT's baseline size limits.",
    "input_not_regular_file": "A configuration input is a symbolic link or not a regular file.",
    "source_unreadable": "A configuration input could not be read safely.",
    "env_file_unlisted": "Docker Compose reported an env_file UPT could not match to its inventory.",
    "interpolation_unproven": "Interpolation may depend on an uncaptured process environment value.",
    "shell_environment_inheritance": "A service inherits an uncaptured process environment value.",
    "project_identity": "The current Compose project name does not match the running service's project.",
    "project_identity_unavailable": "The Compose project identity could not be verified.",
    "network_unproven": "The selected service's Compose network cannot be proven to match its running network.",
    "named_volume_unproven": "The selected service uses a Compose volume that UPT cannot verify against the running service.",
    "service_resource_unproven": "The selected service uses a Compose project resource that UPT cannot verify against the running service.",
    "multiple_replicas": "UPT cannot verify one execution context for all replicas of this service.",
    "no_trusted_baseline": "UPT has no trusted running configuration for this exact container. Apply is unavailable.",
    "project_unproven": "The project includes configuration outside the supported single-service recovery scope.",
    "inventory_unsupported": "UPT cannot reproduce every configuration input safely.",
    "image_change": "Image changes cannot be applied as configuration changes.",
    "project_changes": "Other services or project definitions changed. Single-service Apply is unavailable.",
    "service_ineligible": "The selected service is not eligible for configuration Apply.",
    "input_inventory_changed": "The configuration input inventory changed. Recovery requires the same files and presence state.",
    "service_change_unproven": "UPT could not prove a configuration-only service change.",
    "recovery_source_not_writable": "UPT cannot safely replace the configuration inputs required for automatic recovery.",
    "local_image_changed": "The local image reference no longer resolves to the running image. Apply is unavailable.",
    "runtime_mounts_unproven": "UPT could not prove that the running service has only the supported configuration's bind mounts.",
}
UNVERIFIABLE_REASONS = frozenset({
    "service_not_found", "not_compose_service", "service_not_running", "runtime_hash_missing", "compose_model_unavailable",
    "compose_hash_unavailable", "service_missing_from_model", "hash_excluded_fields",
    "sources_changed_during_check", "runtime_changed_during_check",
})
DRIFT_REASONS = frozenset({"config_hash_differs", "replica_hash_differs", "image_differs"})
INVENTORY_REASONS = frozenset(REASONS) - UNVERIFIABLE_REASONS - DRIFT_REASONS

PREFLIGHT_MESSAGES = {
    DRIFTED: ("Compose configuration changes are pending for this service. Image updates are blocked until "
              "the running service matches its Compose configuration; review the pending changes on the service page."),
    UNVERIFIABLE: ("UPT could not verify this service's Compose configuration. Image updates are blocked until "
                   "its Configuration status can be verified."),
    UNSUPPORTED: ("UPT cannot verify all Compose configuration inputs for this service. "
                  "Image updates are blocked until the inputs are supported and verified."),
}


class ComposePreflightRefused(ValueError):
    """Structured, browser-safe refusal raised before an update review exists."""

    def __init__(self, status: str, reason: str):
        self.status = status if status in (IN_SYNC, DRIFTED, UNVERIFIABLE, UNSUPPORTED) else UNVERIFIABLE
        self.reason = reason if reason in REASONS else "compose_hash_unavailable"
        self.public_message = (REASONS[self.reason] + " Image updates are blocked until it can be verified."
                               if self.status == IN_SYNC else PREFLIGHT_MESSAGES[self.status])
        super().__init__(self.public_message)


def fingerprint(value) -> str:
    """Stable SHA-256 over canonical JSON; used for models, inventories and diffs."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def project_outside_service(model: dict, service_name: str) -> dict:
    """The project model with the selected service removed (project-level identity)."""
    other = {key: value for key, value in model.items() if key != "services"}
    other["services"] = {name: value for name, value in (model.get("services") or {}).items() if name != service_name}
    return other


def observed_service_model(model: dict, service_name: str) -> dict:
    """Store the selected model; retain only digests of unrelated project data.

    These digests describe what was seen on disk at capture time. They do not
    prove that unrelated desired configuration was ever applied.
    """
    result = {}
    for name, value in model.items():
        if name == "services":
            result[name] = {key: (entry if key == service_name else fingerprint(entry))
                            for key, entry in value.items()}
        elif name in {"networks", "volumes", "secrets", "configs"} and isinstance(value, dict):
            result[name] = {key: fingerprint(entry) for key, entry in value.items()}
        else:
            result[name] = fingerprint(value)
    return result


def hash_excluded_fields_present(service_model: dict) -> bool:
    deploy = service_model.get("deploy") or {}
    return bool(service_model.get("build") or service_model.get("scale") is not None
                or service_model.get("pull_policy") is not None or service_model.get("profiles")
                or (isinstance(deploy, dict) and deploy.get("replicas") is not None))


# ---------------------------------------------------------------------------
# Configuration-input inventory
# ---------------------------------------------------------------------------

class InputReadError(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class InputFile:
    role: str  # compose | project_env | env_file
    path: str
    present: bool
    sha256: str | None
    size: int
    content: bytes = field(default=b"", repr=False, compare=False)

    def identity(self):
        return [self.role, self.path, self.present, self.sha256, self.size]


@dataclass(frozen=True)
class Inventory:
    files: tuple
    unsupported: tuple

    @property
    def supported(self) -> bool:
        return not self.unsupported

    @property
    def fingerprint(self) -> str:
        return fingerprint([item.identity() for item in self.files])

    def by_path(self):
        return {item.path: item for item in self.files}


def read_input(role: str, path: str, *, optional: bool = False) -> InputFile:
    """Read one configuration input without following a final symbolic link.

    FIFOs, devices, directories and oversized files are refused; a missing
    optional input is recorded as absent so that its later appearance is a
    detectable inventory change.
    """
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if optional:
            return InputFile(role, path, False, None, 0)
        raise InputReadError("source_unreadable") from None
    except OSError as exc:
        if exc.errno in (getattr(os, "ELOOP", 40), 40):
            raise InputReadError("input_not_regular_file") from None
        raise InputReadError("source_unreadable") from None
    chunks = []
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise InputReadError("input_not_regular_file")
        if info.st_size > MAX_INPUT_BYTES:
            raise InputReadError("input_limit")
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_INPUT_BYTES:
                raise InputReadError("input_limit")
            chunks.append(chunk)
    except InputReadError:
        raise
    except OSError:
        raise InputReadError("source_unreadable") from None
    finally:
        os.close(descriptor)
    content = b"".join(chunks)
    return InputFile(role, path, True, hashlib.sha256(content).hexdigest(), len(content), content)


def live_reader(role, path, optional):
    return read_input(role, path, optional=optional)


def _env_file_refs(value):
    """Return (path, required) pairs from a Compose env_file value, else raise."""
    if value is None:
        return []
    if isinstance(value, str):
        return [(value, True)]
    if isinstance(value, list):
        refs = []
        for item in value:
            if isinstance(item, str):
                refs.append((item, True))
            elif isinstance(item, dict) and isinstance(item.get("path"), str):
                required = item.get("required", True)
                if not isinstance(required, bool):
                    raise InputReadError("unsupported_yaml")
                refs.append((item["path"], required))
            else:
                raise InputReadError("unsupported_yaml")
        return refs
    raise InputReadError("unsupported_yaml")


def _scan_document(document, unsupported: set, env_refs: dict):
    if document is None:
        return
    if not isinstance(document, dict):
        unsupported.add("unsupported_yaml")
        return
    if "include" in document:
        unsupported.add("compose_include")
    for section in ("secrets", "configs"):
        entries = document.get(section)
        if entries is None:
            continue
        if not isinstance(entries, dict):
            unsupported.add("unsupported_yaml")
            continue
        for entry in entries.values():
            # Only inline content is fully represented by the Compose model.
            if not isinstance(entry, dict) or set(entry) - {"content", "name", "labels"} or "content" not in entry:
                unsupported.add("external_secret_or_config")
    services = document.get("services")
    if services is None:
        return
    if not isinstance(services, dict):
        unsupported.add("unsupported_yaml")
        return
    for node in services.values():
        if node is None:
            continue
        if not isinstance(node, dict):
            unsupported.add("unsupported_yaml")
            continue
        extends = node.get("extends")
        if isinstance(extends, dict) and "file" in extends:
            unsupported.add("compose_extends_file")
        elif extends is not None and not isinstance(extends, (str, dict)):
            unsupported.add("unsupported_yaml")
        if "label_file" in node:
            unsupported.add("label_file")
        environment = node.get("environment")
        if ((isinstance(environment, dict) and any(value is None for value in environment.values()))
                or (isinstance(environment, list) and any(isinstance(value, str) and "=" not in value
                                                          for value in environment))):
            unsupported.add("shell_environment_inheritance")
        try:
            refs = _env_file_refs(node.get("env_file"))
        except InputReadError as exc:
            unsupported.add(exc.reason)
            continue
        for path, required in refs:
            env_refs[path] = env_refs.get(path, False) or required


_INTERPOLATION = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*))")


def _interpolation_proven(files) -> bool:
    """Fail closed if Compose could read uncaptured shell interpolation inputs.

    Compose gives the process environment precedence over the project .env.
    The inventory holds file bytes, never the process environment; even an
    identical current shell value cannot establish future reproducibility.
    Ambiguous dollar syntax and Compose control variables are unsupported.
    """
    if any(name.startswith("COMPOSE_") for name in os.environ):
        return False
    for item in files:
        if not item.present:
            continue
        try:
            source = item.content.decode("utf-8")
        except UnicodeDecodeError:
            return False
        names = {match.group(1) or match.group(2) for match in _INTERPOLATION.finditer(source)}
        if names & os.environ.keys():
            return False
        if "$" in _INTERPOLATION.sub("", source):
            return False
    return True


def build_inventory(compose_files, working_dir, reader=live_reader, model=None) -> Inventory:
    """Enumerate every file input the selected Compose project reads.

    Supported inputs are the discovered Compose files, the project .env file
    and service env_file entries. Anything else that can influence the
    effective model (includes, extends from other files, label files,
    non-inline secrets/configs, custom YAML tags) makes the inventory
    unsupported: drift remains detectable, but no trusted baseline is claimed.
    """
    files, unsupported, env_refs = [], set(), {}
    working_dir = os.path.abspath(str(working_dir))
    try:
        for path in compose_files:
            item = reader("compose", os.path.abspath(str(path)), False)
            files.append(item)
            try:
                document = yaml.safe_load(item.content.decode("utf-8"))
            except (yaml.YAMLError, UnicodeDecodeError):
                unsupported.add("unsupported_yaml")
                continue
            _scan_document(document, unsupported, env_refs)
        files.append(reader("project_env", os.path.join(working_dir, ".env"), True))
        for reference in sorted(env_refs):
            if "$" in reference or reference.startswith("~"):
                unsupported.add("interpolated_input_path")
                continue
            path = reference if os.path.isabs(reference) else os.path.join(working_dir, reference)
            files.append(reader("env_file", os.path.normpath(path), not env_refs[reference]))
    except InputReadError as exc:
        unsupported.add(exc.reason)
    unique = {}
    for item in files:
        # An env_file that is also the project .env is one physical input.
        unique.setdefault(item.path, item)
    files = list(unique.values())
    if len(files) > MAX_INPUT_FILES or sum(item.size for item in files) > MAX_TOTAL_INPUT_BYTES:
        unsupported.add("input_limit")
    if not _interpolation_proven(files):
        unsupported.add("interpolation_unproven")
    if isinstance(model, dict):
        listed = {item.path for item in files if item.role in {"env_file", "project_env"}}
        for service in (model.get("services") or {}).values():
            if not isinstance(service, dict) or not service.get("env_file"):
                continue
            try:
                refs = _env_file_refs(service.get("env_file"))
            except InputReadError:
                unsupported.add("env_file_unlisted")
                continue
            for path, _required in refs:
                resolved = os.path.normpath(path if os.path.isabs(path) else os.path.join(working_dir, path))
                if resolved not in listed:
                    unsupported.add("env_file_unlisted")
    return Inventory(tuple(files), tuple(sorted(unsupported)))


# ---------------------------------------------------------------------------
# Redacted drift projection
# ---------------------------------------------------------------------------

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_FIELD = re.compile(r"^[a-z][a-z_]{0,39}$")
_IMAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,254}$")
_RESTART = re.compile(r"^(no|always|unless-stopped|on-failure(:\d{1,4})?)$")
_USER = re.compile(r"^[A-Za-z0-9_.-]{1,32}(:[A-Za-z0-9_.-]{1,32})?$")
_CAPABILITY = re.compile(r"^[A-Z][A-Z0-9_]{0,39}$")
_SIMPLE_QUANTITY = re.compile(r"^[0-9]{1,15}(\.[0-9]{1,6})?[A-Za-z]{0,3}$")
_CONTAINER_PATH = re.compile(r"^/[A-Za-z0-9_./@+-]{0,159}$")
_NETWORK_MODE = re.compile(r"^(bridge|host|none|default|(service|container):[A-Za-z0-9][A-Za-z0-9_.-]{0,63})$")

FIELD_LABELS = {
    "image": "Image", "restart": "Restart policy", "environment": "Environment", "labels": "Labels",
    "ports": "Ports", "volumes": "Mounts", "networks": "Networks", "network_mode": "Network mode",
    "depends_on": "Dependencies", "cap_add": "Added capabilities", "cap_drop": "Dropped capabilities",
    "privileged": "Privileged mode", "read_only": "Read-only root filesystem", "init": "Init process",
    "tty": "TTY", "stdin_open": "Interactive stdin", "user": "User", "mem_limit": "Memory limit",
    "memswap_limit": "Memory+swap limit", "cpus": "CPU limit", "cpu_shares": "CPU shares",
    "pids_limit": "Process limit", "shm_size": "Shared memory size", "command": "Command",
    "entrypoint": "Entrypoint", "healthcheck": "Healthcheck", "security_opt": "Security options",
    "devices": "Devices", "deploy": "Deploy settings", "logging": "Logging", "secrets": "Secrets",
    "configs": "Configs", "extra_hosts": "Extra hosts", "dns": "DNS", "sysctls": "Kernel parameters",
    "ulimits": "Resource limits (ulimits)", "working_dir": "Working directory", "hostname": "Hostname",
    "container_name": "Container name", "stop_signal": "Stop signal", "stop_grace_period": "Stop grace period",
    "group_add": "Additional groups", "tmpfs": "tmpfs mounts", "expose": "Exposed ports",
}
_VALUE_FIELDS = {
    "image": _IMAGE, "restart": _RESTART, "user": _USER, "network_mode": _NETWORK_MODE,
    "mem_limit": _SIMPLE_QUANTITY, "memswap_limit": _SIMPLE_QUANTITY, "cpus": _SIMPLE_QUANTITY,
    "cpu_shares": _SIMPLE_QUANTITY, "pids_limit": _SIMPLE_QUANTITY, "shm_size": _SIMPLE_QUANTITY,
}
_BOOL_FIELDS = {"privileged", "read_only", "init", "tty", "stdin_open"}


def _bounded(values):
    values = sorted(values)
    return values[:MAX_LIST_ITEMS], max(0, len(values) - MAX_LIST_ITEMS)


def _safe_value(pattern, value):
    if value is None:
        return "not set"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        value = str(value)
    if isinstance(value, str) and pattern.fullmatch(value):
        return value
    return None


def _count_summary(added, removed, changed):
    parts = []
    for count, word in ((len(added), "added"), (len(removed), "removed"), (len(changed), "changed")):
        if count:
            parts.append(f"{count} {word}")
    return ", ".join(parts) or "changed"


def _entry(field_name, *, summary, old=None, new=None, added=(), removed=(), changed=(), hidden=0):
    entry = {"field": field_name, "label": FIELD_LABELS.get(field_name, field_name.replace("_", " ").capitalize()),
             "summary": summary}
    if old is not None or new is not None:
        entry["old"], entry["new"] = old, new
    for key, items in (("added", added), ("removed", removed), ("changed", changed)):
        if items:
            entry[key] = list(items)
    if hidden:
        entry["hidden"] = hidden
    return entry


def _key_changes(old_map, new_map, pattern):
    """Compare mappings by key only; values are never projected."""
    added = [key for key in new_map if key not in old_map]
    removed = [key for key in old_map if key not in new_map]
    changed = [key for key in new_map if key in old_map and new_map[key] != old_map[key]]
    keep = lambda keys: [key for key in keys if isinstance(key, str) and pattern.fullmatch(key)]
    (a, ha), (r, hr), (c, hc) = _bounded(keep(added)), _bounded(keep(removed)), _bounded(keep(changed))
    hidden = len(added) + len(removed) + len(changed) - len(a) - len(r) - len(c)
    return added, removed, changed, a, r, c, hidden


def _as_mapping(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        result = {}
        for item in value:
            key, _, rest = str(item).partition("=")
            result[key] = rest
        return result
    return {}


def _port_text(port):
    if not isinstance(port, dict):
        return None
    try:
        target = int(port.get("target"))
    except (TypeError, ValueError):
        return None
    protocol = port.get("protocol") or "tcp"
    if protocol not in {"tcp", "udp", "sctp"} or not 0 < target < 65536:
        return None
    published = port.get("published")
    published = "" if published in (None, "") else str(published)
    if published and not re.fullmatch(r"\d{1,5}(-\d{1,5})?", published):
        return None
    host_ip = port.get("host_ip") or ""
    if host_ip:
        try:
            host_ip = str(ipaddress.ip_address(host_ip))
        except ValueError:
            return None
        host_ip = f"[{host_ip}]:" if ":" in host_ip else f"{host_ip}:"
    return f"{host_ip}{published}{':' if published else ''}{target}/{protocol}"


def _mount_key(mount):
    if not isinstance(mount, dict):
        return None
    kind, target = mount.get("type"), mount.get("target")
    if (kind not in {"bind", "volume", "tmpfs", "npipe", "cluster", "image"}
            or not isinstance(target, str) or not _CONTAINER_PATH.fullmatch(target)):
        return None
    return f"{kind} {target}{' (read-only)' if mount.get('read_only') else ''}"


def _mount_option_changes(old, new):
    def by_key(items):
        return {key: item for item in items for key in [_mount_key(item)] if key}
    old_map, new_map = by_key(old), by_key(new)
    return [key.split(" ", 1)[1] for key in new_map if key in old_map and old_map[key] != new_map[key]]


def _list_diff(field_name, old, new, formatter, detect_changed=None):
    old_items = [formatter(item) for item in old]
    new_items = [formatter(item) for item in new]
    old_set = {item for item in old_items if item}
    new_set = {item for item in new_items if item}
    added, removed = sorted(new_set - old_set), sorted(old_set - new_set)
    changed = detect_changed(old, new) if detect_changed else []
    if not (added or removed or changed):
        # Differences exist only in entries UPT cannot format safely.
        return _entry(field_name, summary="settings changed")
    (a, ha), (r, hr), (c, hc) = _bounded(added), _bounded(removed), _bounded(changed)
    return _entry(field_name, summary=_count_summary(added, removed, changed), added=a, removed=r, changed=c,
                  hidden=ha + hr + hc)


def _service_field_entry(name, old, new):
    if name in _VALUE_FIELDS:
        pattern = _VALUE_FIELDS[name]
        old_text, new_text = _safe_value(pattern, old), _safe_value(pattern, new)
        if old_text is not None and new_text is not None:
            return _entry(name, summary=f"{old_text} → {new_text}", old=old_text, new=new_text)
        return _entry(name, summary="changed")
    if name in _BOOL_FIELDS and isinstance(old, (bool, type(None))) and isinstance(new, (bool, type(None))):
        old_text, new_text = ("yes" if old else "no"), ("yes" if new else "no")
        return _entry(name, summary=f"{old_text} → {new_text}", old=old_text, new=new_text)
    if name in {"environment", "labels"}:
        added, removed, changed, a, r, c, hidden = _key_changes(_as_mapping(old), _as_mapping(new), _NAME)
        return _entry(name, summary=_count_summary(added, removed, changed), added=a, removed=r, changed=c, hidden=hidden)
    if name in {"networks", "depends_on"}:
        keys = lambda value: value if isinstance(value, dict) else ({str(item): None for item in value} if isinstance(value, list) else {})
        added, removed, changed, a, r, c, hidden = _key_changes(keys(old), keys(new), _SERVICE_NAME)
        return _entry(name, summary=_count_summary(added, removed, changed), added=a, removed=r, changed=c, hidden=hidden)
    as_list = lambda value: value if isinstance(value, list) else []
    if name in {"cap_add", "cap_drop"}:
        return _list_diff(name, as_list(old), as_list(new),
                          lambda item: item if isinstance(item, str) and _CAPABILITY.fullmatch(item) else None)
    if name == "ports":
        return _list_diff(name, as_list(old), as_list(new), _port_text)
    if name == "volumes":
        return _list_diff(name, as_list(old), as_list(new), _mount_key, _mount_option_changes)
    # command/entrypoint/healthcheck/logging/devices/security options and any
    # other field may carry secrets or host paths: report only that it changed.
    if not _FIELD.fullmatch(name):
        return _entry("other", summary="changed")
    return _entry(name, summary="changed")


def service_changes(old: dict, new: dict) -> list:
    old, new = old or {}, new or {}
    entries, other = [], 0
    for name in sorted(set(old) | set(new), key=str):
        if old.get(name) == new.get(name):
            continue
        entry = _service_field_entry(str(name), old.get(name), new.get(name))
        if entry["field"] == "other":
            other += 1
            continue
        entries.append(entry)
    if other:
        entries.append({"field": "other", "label": "Other settings", "summary": f"{other} changed"})
    return entries


def project_changes(old: dict, new: dict, service_name: str, *, observed=False) -> list:
    """Project-level differences outside the selected service (names only)."""
    old, new = old or {}, new or {}
    entries = []
    old_services = {key: value for key, value in (old.get("services") or {}).items() if key != service_name}
    new_services = {key: value for key, value in (new.get("services") or {}).items() if key != service_name}
    for label, old_map, new_map, field_name in (
            ("Other services", old_services, new_services, "services"),
            ("Project networks", old.get("networks") or {}, new.get("networks") or {}, "networks"),
            ("Project volumes", old.get("volumes") or {}, new.get("volumes") or {}, "volumes"),
            ("Project secrets", old.get("secrets") or {}, new.get("secrets") or {}, "secrets"),
            ("Project configs", old.get("configs") or {}, new.get("configs") or {}, "configs")):
        if not isinstance(old_map, dict) or not isinstance(new_map, dict):
            entries.append({"field": f"project_{field_name}", "label": label, "summary": "changed"})
            continue
        if observed:
            new_map = {key: fingerprint(value) for key, value in new_map.items()}
        added, removed, changed, a, r, c, hidden = _key_changes(old_map, new_map, _SERVICE_NAME)
        if not (added or removed or changed):
            continue
        entry = {"field": f"project_{field_name}", "label": label, "summary": _count_summary(added, removed, changed)}
        for key, items in (("added", a), ("removed", r), ("changed", c)):
            if items:
                entry[key] = items
        if hidden:
            entry["hidden"] = hidden
        entries.append(entry)
    other_keys = (set(old) | set(new)) - {"services", "networks", "volumes", "secrets", "configs"}
    if any(old.get(key) != (fingerprint(new.get(key)) if observed and key in new else new.get(key))
           for key in other_keys):
        entries.append({"field": "project_other", "label": "Project settings", "summary": "changed"})
    return entries


@dataclass(frozen=True)
class DriftDiff:
    service: list
    project: list
    image_change: bool
    scope: str  # service | project
    fingerprint: str


def compute_diff(baseline_model: dict, desired_model: dict, service_name: str, baseline_fingerprint: str,
                 *, project_observed=False) -> DriftDiff:
    old_service = (baseline_model.get("services") or {}).get(service_name) or {}
    new_service = (desired_model.get("services") or {}).get(service_name) or {}
    service = service_changes(old_service, new_service)
    project = project_changes(baseline_model, desired_model, service_name, observed=project_observed)
    image_change = old_service.get("image") != new_service.get("image")
    projection = {"service": service, "project": project}
    digest = fingerprint({"baseline": baseline_fingerprint, "desired": fingerprint(desired_model),
                          "projection": projection})
    return DriftDiff(service, project, image_change, "project" if project else "service", digest)
