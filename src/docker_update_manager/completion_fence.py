"""G2 schema-10 recovery fences and claims: storage and inert, read-only guards.

Policy: docs/implementation/g2-s0-recovery-fence-design.md (Option B, D3/D3b/
D3c/D10). S0b deliberately contains no production writer: nothing in UPT
creates, arms, enriches, releases or resolves a G2 fence. Admission and
deletion paths only *read* these tables.

Every reader validates strictly. A malformed, unknown or unreadable record
raises CompletionFenceError (or the underlying sqlite3.Error); callers must
treat that as a refusal, never as an empty protection set.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from dataclasses import dataclass

UNRESOLVED = ("active", "manual")
ACTIONS = ("update", "pinned_update", "rollback", "web_rollback")
CLAIM_KINDS = ("image", "backup")
# Backup claims name one direct child of a managed recovery root.
BACKUP_CLAIM_ROOTS = ("backups", "conversion-file-backups", "conversion-snapshots", "restore-bundles")
EVIDENCE_VERSION = 1
MAX_EVIDENCE_BYTES = 64 * 1024
MAX_COMPOSE_FILES = 32
MAX_PATH = 4096
MAX_NAME = 255

_OPERATION_ID = re.compile(r"[0-9a-f]{32}")
_LOGICAL_KEY = re.compile(r"[0-9a-f]{64}")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
_BACKUP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}")

# Statements are executed one at a time: trigger bodies contain semicolons.
# The exact stored SQL is part of the schema-10 compatibility identity, so any
# edit here is a schema change that needs its own migration.
COMPLETION_SCHEMA = (
    "CREATE TABLE completion_fences("
    "operation_id TEXT NOT NULL PRIMARY KEY CHECK(typeof(operation_id)='text' AND length(operation_id)=32 "
    "AND operation_id NOT GLOB '*[^0-9a-f]*'), "
    "logical_key TEXT NOT NULL CHECK(typeof(logical_key)='text' AND length(logical_key)=64 "
    "AND logical_key NOT GLOB '*[^0-9a-f]*'), "
    "stack TEXT NOT NULL CHECK(typeof(stack)='text' AND length(stack) BETWEEN 1 AND 255), "
    "compose_service TEXT NOT NULL CHECK(typeof(compose_service)='text' AND length(compose_service) BETWEEN 1 AND 255), "
    "action TEXT NOT NULL CHECK(action IN ('update','pinned_update','rollback','web_rollback')), "
    "lifecycle TEXT NOT NULL CHECK(lifecycle IN ('active','manual','resolved')), "
    "evidence TEXT NOT NULL CHECK(typeof(evidence)='text' AND length(evidence) BETWEEN 2 AND 65536), "
    "created_at TEXT NOT NULL CHECK(typeof(created_at)='text' AND length(created_at) BETWEEN 1 AND 64), "
    "updated_at TEXT NOT NULL CHECK(typeof(updated_at)='text' AND length(updated_at) BETWEEN 1 AND 64))",
    # At most one unresolved G2 fence per logical service.
    "CREATE UNIQUE INDEX idx_completion_fences_unresolved ON completion_fences(logical_key) "
    "WHERE lifecycle IN ('active','manual')",
    "CREATE INDEX idx_completion_fences_service ON completion_fences(stack,compose_service) "
    "WHERE lifecycle IN ('active','manual')",
    "CREATE TABLE completion_fence_claims("
    "operation_id TEXT NOT NULL REFERENCES completion_fences(operation_id) ON UPDATE RESTRICT ON DELETE RESTRICT, "
    "kind TEXT NOT NULL CHECK(kind IN ('image','backup')), "
    "value TEXT NOT NULL CHECK(typeof(value)='text' AND ("
    "(kind='image' AND length(value)=71 AND substr(value,1,7)='sha256:' AND substr(value,8) NOT GLOB '*[^0-9a-f]*') "
    "OR (kind='backup' AND length(value) BETWEEN 3 AND 512 AND instr(value,'..')=0 AND value NOT GLOB '*/*/*' "
    "AND (value GLOB 'backups/?*' OR value GLOB 'conversion-file-backups/?*' "
    "OR value GLOB 'conversion-snapshots/?*' OR value GLOB 'restore-bundles/?*')))), "
    "PRIMARY KEY(operation_id,kind,value)) WITHOUT ROWID",
    # Many independent owners may claim the same image or backup.
    "CREATE INDEX idx_completion_fence_claims_value ON completion_fence_claims(kind,value)",
    "CREATE TRIGGER completion_fences_identity_immutable BEFORE UPDATE OF "
    "operation_id,logical_key,stack,compose_service,action,created_at ON completion_fences "
    "BEGIN SELECT RAISE(ABORT,'completion fence identity is immutable'); END",
    "CREATE TRIGGER completion_fences_resolved_final BEFORE UPDATE OF lifecycle ON completion_fences "
    "WHEN OLD.lifecycle='resolved' AND NEW.lifecycle<>'resolved' "
    "BEGIN SELECT RAISE(ABORT,'a resolved completion fence cannot be reopened'); END",
    "CREATE TRIGGER completion_fences_unresolved_retained BEFORE DELETE ON completion_fences "
    "WHEN OLD.lifecycle IN ('active','manual') "
    "BEGIN SELECT RAISE(ABORT,'an unresolved completion fence cannot be deleted'); END",
    "CREATE TRIGGER completion_fence_claims_immutable BEFORE UPDATE ON completion_fence_claims "
    "BEGIN SELECT RAISE(ABORT,'completion claims are immutable'); END",
    "CREATE TRIGGER completion_fence_claims_unresolved_owner BEFORE INSERT ON completion_fence_claims "
    "WHEN COALESCE((SELECT lifecycle FROM completion_fences WHERE operation_id=NEW.operation_id),'') "
    "NOT IN ('active','manual') "
    "BEGIN SELECT RAISE(ABORT,'claims require an unresolved owner'); END",
    "CREATE TRIGGER completion_fence_claims_retained BEFORE DELETE ON completion_fence_claims "
    "WHEN COALESCE((SELECT lifecycle FROM completion_fences WHERE operation_id=OLD.operation_id),'resolved') "
    "<>'resolved' "
    "BEGIN SELECT RAISE(ABORT,'claims of an unresolved completion fence cannot be deleted'); END",
)
COMPLETION_TABLES = ("completion_fences", "completion_fence_claims")
_SCHEMA_QUERY = ("SELECT type,name,tbl_name,sql FROM sqlite_master "
                 "WHERE tbl_name IN ('completion_fences','completion_fence_claims') "
                 "OR name LIKE '%completion%' ORDER BY type,name")
_expected_schema = None


class CompletionFenceError(ValueError):
    """G2 recovery evidence is unresolved, unproven or cannot be verified."""


@dataclass(frozen=True)
class Fence:
    operation_id: str
    logical_key: str
    stack: str
    compose_service: str
    action: str
    lifecycle: str
    working_dir: str
    compose_files: tuple


def create_schema(c):
    for statement in COMPLETION_SCHEMA:
        c.execute(statement)


def expected_schema():
    """The exact sqlite_master rows this binary creates for schema 10."""
    global _expected_schema
    if _expected_schema is None:
        with sqlite3.connect(":memory:") as memory:
            create_schema(memory)
            _expected_schema = tuple(tuple(row) for row in memory.execute(_SCHEMA_QUERY))
        memory.close()
    return _expected_schema


def schema_matches(c):
    return tuple(tuple(row) for row in c.execute(_SCHEMA_QUERY)) == expected_schema()


def _invalid(detail):
    # Fixed text only: never project evidence, paths or identities.
    return CompletionFenceError(f"completion_evidence_invalid: G2 recovery evidence is malformed ({detail}); "
                                "refusing until it is diagnosed")


def _name(value):
    return isinstance(value, str) and 0 < len(value) <= MAX_NAME and "\x00" not in value


def _absolute_path(value):
    return (isinstance(value, str) and 0 < len(value) <= MAX_PATH and "\x00" not in value
            and os.path.isabs(value) and os.path.abspath(value) == value)


def _evidence(text):
    if not isinstance(text, str) or len(text.encode("utf-8", "surrogatepass")) > MAX_EVIDENCE_BYTES:
        raise _invalid("evidence size")
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise _invalid("evidence encoding") from None
    if not isinstance(data, dict) or set(data) != {"version", "working_dir", "compose_files"}:
        raise _invalid("evidence fields")
    if type(data["version"]) is not int or data["version"] != EVIDENCE_VERSION:
        raise _invalid("evidence version")
    files = data["compose_files"]
    if (not _absolute_path(data["working_dir"]) or not isinstance(files, list)
            or not 0 < len(files) <= MAX_COMPOSE_FILES or not all(_absolute_path(item) for item in files)
            or len(set(files)) != len(files)):
        raise _invalid("evidence identity")
    return data["working_dir"], tuple(files)


def _fence(row):
    from .compose_baseline import logical_key
    operation_id, key, stack, compose_service, action, lifecycle, evidence, created, updated = tuple(row)
    if not (isinstance(operation_id, str) and _OPERATION_ID.fullmatch(operation_id)):
        raise _invalid("owner")
    if lifecycle not in UNRESOLVED:
        raise _invalid("lifecycle")
    if action not in ACTIONS:
        raise _invalid("action")
    if not (isinstance(key, str) and _LOGICAL_KEY.fullmatch(key)) or not _name(stack) or not _name(compose_service):
        raise _invalid("logical service identity")
    if not (isinstance(created, str) and created and isinstance(updated, str) and updated):
        raise _invalid("timestamps")
    working_dir, files = _evidence(evidence)
    # The stored key must be exactly reproducible from the stable identity.
    if logical_key(stack, compose_service, working_dir, files) != key:
        raise _invalid("logical service identity")
    return Fence(operation_id, key, stack, compose_service, action, lifecycle, working_dir, files)


def unresolved_fences(c):
    """Every unresolved (or unrecognised-lifecycle) fence, strictly validated."""
    rows = c.execute(
        "SELECT operation_id,logical_key,stack,compose_service,action,lifecycle,evidence,created_at,updated_at "
        "FROM completion_fences WHERE lifecycle IS NOT 'resolved' ORDER BY operation_id").fetchall()
    fences = tuple(_fence(row) for row in rows)
    if len({fence.logical_key for fence in fences}) != len(fences):
        raise _invalid("duplicate unresolved logical service")
    return fences


def valid_claim(kind, value):
    if kind == "image":
        return isinstance(value, str) and bool(_IMAGE_ID.fullmatch(value))
    if kind == "backup" and isinstance(value, str) and value.count("/") == 1:
        root, name = value.split("/")
        return root in BACKUP_CLAIM_ROOTS and bool(_BACKUP_NAME.fullmatch(name)) and ".." not in name
    return False


def unresolved_claims(c):
    """Claims of unresolved owners by kind; orphaned or malformed claims refuse."""
    claims = {kind: set() for kind in CLAIM_KINDS}
    rows = c.execute(
        "SELECT cl.operation_id,cl.kind,cl.value,f.lifecycle FROM completion_fence_claims cl "
        "LEFT JOIN completion_fences f ON f.operation_id=cl.operation_id "
        "WHERE f.lifecycle IS NOT 'resolved'").fetchall()
    for operation_id, kind, value, lifecycle in (tuple(row) for row in rows):
        if not (isinstance(operation_id, str) and _OPERATION_ID.fullmatch(operation_id)) or lifecycle not in UNRESOLVED:
            raise _invalid("claim owner")
        if not valid_claim(kind, value):
            raise _invalid("claim")
        claims[kind].add(value)
    return {kind: frozenset(values) for kind, values in claims.items()}


def _identity(service):
    files = getattr(service, "compose_files", None) or ()
    return (getattr(service, "stack", None), getattr(service, "compose_service", None),
            getattr(service, "working_dir", None), [str(item) for item in files])


def service_refusal(fences, service):
    """Why ``service`` may not be mutated under ``fences``, or None.

    A fence covers its exact logical service and, to resist identity drift
    (changed file lists, moved projects, project-name aliases), any service
    with the same (stack, Compose service) or the same Compose service in the
    same project directory or Compose source. Sharing only an image never
    blocks. Incomplete Compose identity cannot be proved unrelated.
    """
    if not fences:
        return None
    stack, compose_service, working_dir, files = _identity(service)
    if not stack and not compose_service:
        return None  # A standalone container has no Compose identity a fence can own.
    if not (stack and compose_service and working_dir and files):
        return ("completion_identity_unproven: Compose service identity is incomplete while an unresolved "
                "update/rollback completion requires manual recovery")
    from .compose_baseline import logical_key
    key = logical_key(stack, compose_service, working_dir, files)
    directory = os.path.abspath(str(working_dir))
    sources = {os.path.abspath(item) for item in files}
    for fence in fences:
        if (fence.logical_key == key or (fence.stack, fence.compose_service) == (stack, compose_service)
                or (fence.compose_service == compose_service
                    and (fence.working_dir == directory or sources.intersection(fence.compose_files)))):
            return "completion_unresolved: an unresolved update/rollback completion requires manual recovery"
    return None


def source_refusal(fences, paths, *, stack=None, compose_service=None):
    """Why rewriting Compose ``paths`` would mutate a fenced service, or None."""
    sources = {os.path.abspath(str(item)) for item in paths}
    for fence in fences:
        if (sources.intersection(fence.compose_files)
                or (stack and compose_service and (fence.stack, fence.compose_service) == (stack, compose_service))):
            return "completion_unresolved: an unresolved update/rollback completion requires manual recovery"
    return None
