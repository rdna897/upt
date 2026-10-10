from __future__ import annotations

import json
import socket
from pathlib import Path

from ._version import __version__
from .component_version import MATCH, TRANSPORT_VERSION_FIELD, ComponentVersionMismatch, version_agreement
from .compose_drift import ComposePreflightRefused
from .compose_discard import DiscardRefused
from .webservice import AGENT_OPERATIONS, VERSION_GATED_OPERATIONS


class AgentUnavailable(RuntimeError):
    pass


class AgentNotFound(RuntimeError):
    """A requested cached object does not exist; distinct from agent failure."""


class AgentClient:
    def __init__(self, socket_path: str | Path, timeout: float = 10.0):
        self.socket_path, self.timeout = str(socket_path), timeout

    def call(self, operation: str, payload: dict | None = None):
        if operation not in AGENT_OPERATIONS:
            raise PermissionError("operation is not available through the bounded agent")
        payload = payload or {}
        if TRANSPORT_VERSION_FIELD in payload:
            raise PermissionError("operation payload contains a reserved transport field")
        if operation in VERSION_GATED_OPERATIONS:
            # Central web-side mutation admission: every browser-triggered
            # mutation reaches the agent through this call. Re-check on each
            # mutation rather than caching, so a restart of either component
            # is observed immediately.
            agreement = version_agreement(self._request("health", {}))
            if agreement["status"] != MATCH:
                raise ComponentVersionMismatch(agreement["status"])
            # Mutation-time assertion closing the probe/mutation race: see
            # TRANSPORT_VERSION_FIELD. A new dict leaves the caller's untouched.
            payload = {**payload, TRANSPORT_VERSION_FIELD: __version__}
        return self._request(operation, payload)

    def _request(self, operation: str, payload: dict):
        request = {"operation": operation, "payload": payload, "client_version": __version__}
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall((json.dumps(request, separators=(",", ":")) + "\n").encode("utf-8"))
                file = sock.makefile("rb")
                response = json.loads(file.readline().decode("utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise AgentUnavailable("UPT agent is unavailable") from exc
        if not response.get("ok"):
            kind = response.get("type")
            message = response.get("error") or "agent request failed"
            if kind == "PermissionError": raise PermissionError(message)
            if kind == "AgentNotFound": raise AgentNotFound(message)
            if kind == "ComposePreflightRefused":
                # Rebuilt from bounded status/reason codes; the message is
                # fixed server copy, never the transported text.
                raise ComposePreflightRefused(response.get("status"), response.get("reason"))
            if kind == "ComponentVersionMismatch":
                raise ComponentVersionMismatch()
            if kind == "DiscardRefused":
                raise DiscardRefused(response.get("reason"))
            if kind == "ValueError": raise ValueError(message)
            raise RuntimeError(message)
        return response.get("data")
