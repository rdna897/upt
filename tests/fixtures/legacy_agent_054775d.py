"""Frozen pre-0.4 agent request path (main 54775dff74bf42fa71a13fc667c6b9045e33ad63).

Legacy compatibility regression fixture for the web/agent version gate. It
reproduces, verbatim in behaviour, how a 0.3.1-reporting agent parsed a request
line and dispatched a mutation: top-level fields other than `operation` and
`payload` are ignored, the payload is passed unchanged to the operation handler,
and every version-gated handler begins with its strict `_exact_payload`
allowlist. Error-message projection is simplified; the parse, authorisation,
dispatch and validation order is unchanged. Do not update this file to follow
current code; it represents an already-deployed old agent.
"""
import json

LEGACY_MUTATION_OPERATIONS = frozenset({"update_review", "update_start", "rollback_review", "rollback_start", "operation_status",
                                        "compose_reconcile_review", "compose_reconcile_start", "compose_bootstrap_review", "compose_bootstrap_start"})

# First statement of each legacy handler (webservice.py @ 54775df).
LEGACY_EXACT_PAYLOADS = {
    "update_review": {"service_key", "requested_by", "verification_id"},
    "update_start": {"confirmation_id", "requested_by", "client_ip", "user_agent"},
    "rollback_review": {"service_key", "requested_by"},
    "rollback_start": {"confirmation_id", "requested_by", "client_ip", "user_agent"},
    "compose_reconcile_review": {"service_key", "action", "requested_by"},
    "compose_reconcile_start": {"confirmation_id", "requested_by", "client_ip", "user_agent"},
    "compose_bootstrap_review": {"service_key", "requested_by"},
    "compose_bootstrap_start": {"confirmation_id", "acknowledge_no_rollback", "requested_by", "client_ip", "user_agent"},
}


class LegacyAgentAuthorizationError(PermissionError):
    pass


class LegacyService:
    """Legacy `ReadOnlyService.handle` dispatch with recorded mutation side effects."""

    def __init__(self, version="0.3.1"):
        self.version, self.side_effects = version, []

    @staticmethod
    def _exact_payload(payload, names):
        if set(payload) != set(names):
            raise ValueError("invalid operation request")

    def handle(self, operation, payload=None):
        payload = payload or {}
        if operation == "health":
            # Legacy health carried no product version field.
            return {"ok": True, "service": "upt-agent", "docker": {"ok": True}}
        if operation in LEGACY_EXACT_PAYLOADS:
            self._exact_payload(payload, LEGACY_EXACT_PAYLOADS[operation])
            self.side_effects.append((operation, dict(payload)))
            return {"operation_id": "a" * 32, "confirmation_id": "C" * 43}
        raise LegacyAgentAuthorizationError("operation is not available through the bounded agent")


class LegacyAgentServer:
    def __init__(self, service, allowed_mutation_uid):
        self.service, self.allowed_mutation_uid = service, allowed_mutation_uid

    def handle_line(self, line: bytes, *, peer_uid=None) -> bytes:
        operation = None
        try:
            if not line or len(line) > 65536 or not line.endswith(b"\n"):
                raise ValueError("invalid request framing")
            request = json.loads(line.decode("utf-8"))
            if not isinstance(request, dict): raise ValueError("invalid request")
            operation, payload = request.get("operation"), request.get("payload", {})
            if not isinstance(operation, str) or not isinstance(payload, dict): raise ValueError("invalid request")
            if operation in LEGACY_MUTATION_OPERATIONS and (self.allowed_mutation_uid is None or peer_uid != self.allowed_mutation_uid):
                raise LegacyAgentAuthorizationError("mutation requests are restricted to the configured web service identity")
            response = {"ok": True, "data": self.service.handle(operation, payload)}
        except Exception as exc:
            if isinstance(exc, LegacyAgentAuthorizationError):
                response = {"ok": False, "error": str(exc), "type": "PermissionError"}
            elif (operation in {"compose_reconcile_review", "compose_reconcile_start"}
                  and isinstance(exc, (ValueError, RuntimeError))):
                response = {"ok": False, "error": "Configuration action could not be reviewed or started safely. Refresh and review again.",
                            "type": "ValueError"}
            else:
                response = {"ok": False, "error": "invalid operation request", "type": exc.__class__.__name__}
        return (json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8")
