"""Web/agent product-version agreement (deployment integrity).

`upt-web` and `upt-agent` are one release unit. A differing or unknown agent
version means a partially upgraded/stale installation: read-only diagnostics
stay available, but mutation admission fails closed. This check is separate
from schema, evidence-format and capability compatibility; it never replaces
them and never infers compatibility from them.
"""
from __future__ import annotations

import re

from ._version import __version__

VERSION_MISMATCH = "version_mismatch"
VERSION_MISMATCH_MESSAGE = "UPT web and agent versions do not match. Complete the UPT upgrade before making changes."

# Agreement states. Only MATCH admits mutation; UNKNOWN (missing/malformed
# agent version) is treated exactly like MISMATCH.
MATCH, MISMATCH, UNKNOWN, UNAVAILABLE = "match", "mismatch", "unknown", "unavailable"

# Reserved web<->agent transport field carried inside the payload of every
# version-gated request. Owned by AgentClient/AgentServer only: callers may never
# supply it and the agent strips it before operation handlers run. Pre-0.4 agents
# ignore top-level request fields but pass the payload unchanged to handlers whose
# strict `_exact_payload` allowlists reject this unknown key, so a mutation that
# reaches a stale agent after a passing health probe fails closed.
TRANSPORT_VERSION_FIELD = "_upt_client_version"

_VERSION_RE = re.compile(r"[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}(?:[-+][0-9A-Za-z.+-]{1,32})?")


class ComponentVersionMismatch(Exception):
    """Mutation refused because web and agent product versions differ.

    Deliberately not a PermissionError/RuntimeError subclass so it cannot be
    confused with authentication failure, agent unavailability or schema
    incompatibility by existing handlers.
    """

    reason = VERSION_MISMATCH
    public_message = VERSION_MISMATCH_MESSAGE

    def __init__(self, status: str = MISMATCH):
        super().__init__(VERSION_MISMATCH_MESSAGE)
        self.status = status if status in {MISMATCH, UNKNOWN, UNAVAILABLE} else MISMATCH


def reported_version(value) -> str | None:
    """Return a bounded product-version string, or None when absent/malformed."""
    if isinstance(value, str) and _VERSION_RE.fullmatch(value):
        return value
    return None


def version_agreement(agent_health) -> dict:
    """Compare this process's product version with an agent health response."""
    if not isinstance(agent_health, dict) or agent_health.get("_error") or agent_health.get("ok") is not True:
        return {"web": __version__, "agent": None, "status": UNAVAILABLE}
    agent = reported_version(agent_health.get("version"))
    if agent is None:
        status = UNKNOWN
    else:
        status = MATCH if agent == __version__ else MISMATCH
    return {"web": __version__, "agent": agent, "status": status}
