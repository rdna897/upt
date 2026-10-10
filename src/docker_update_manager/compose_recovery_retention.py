"""Private, flat Compose recovery artifacts; never follow recorded source paths."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .compose_drift import InputFile, fingerprint

ID = re.compile(r"[0-9a-f]{32}")
HASH = re.compile(r"[0-9a-f]{64}")


def _private(info, directory=False):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or (not directory and info.st_nlink != 1)):
        raise ValueError("unsafe recovery artifact")


def _read(fd, name, limit):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        info = os.fstat(descriptor)
        _private(info)
        if info.st_size > limit:
            raise ValueError("oversized recovery artifact")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != info.st_size or len(content) > limit:
            raise ValueError("changed recovery artifact")
        return content, info
    finally:
        os.close(descriptor)


@contextmanager
def checked_bundle(state_root, path):
    """Open each directory without symlinks, validate bounded flat material."""
    state_root = Path(state_root).absolute()
    path = Path(path).absolute()
    root = state_root / "compose-recoveries"
    if path.parent != root or not ID.fullmatch(path.name):
        raise ValueError("outside recovery root")
    descriptors = []
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(fd)
        for part in root.parts[1:]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        _private(os.fstat(fd), True)
        _private(os.fstat(descriptors[-2]), True)
        root_fd = fd
        fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        descriptors.append(fd)
        bundle_info = os.fstat(fd)
        _private(bundle_info, True)
        content, manifest_info = _read(fd, "manifest.json", 256 * 1024)
        manifest = json.loads(content)
        bootstrap = isinstance(manifest, dict) and type(manifest.get('version')) is int and manifest['version'] == 2
        namespace = isinstance(manifest, dict) and type(manifest.get('version')) is int and manifest['version'] == 3
        if namespace:
            binding = manifest.get('binding')
            if (set(manifest) != {'version', 'action', 'binding', 'files', 'proof_sha256'}
                    or manifest.get('action') != 'namespace_apply' or not isinstance(binding, dict)
                    or set(binding) != {'operation_id', 'logical_key', 'requester', 'baseline_id',
                                        'baseline_fingerprint', 'review', 'owner'}
                    or binding['operation_id'] != path.name or not ID.fullmatch(str(binding['baseline_id']))
                    or any(not isinstance(binding[name], str) or not HASH.fullmatch(binding[name])
                           for name in ('logical_key', 'baseline_fingerprint', 'review', 'owner'))
                    or not isinstance(binding['requester'], str) or not 1 <= len(binding['requester']) <= 80
                    or not isinstance(manifest['proof_sha256'], str) or not HASH.fullmatch(manifest['proof_sha256'])):
                raise ValueError('malformed namespace Apply manifest')
        elif bootstrap:
            binding = manifest.get('binding')
            if (set(manifest) != {'version', 'action', 'binding', 'files', 'proof_sha256'}
                    or manifest.get('action') != 'bootstrap' or not isinstance(binding, dict)
                    or set(binding) != {'operation_id', 'logical_key', 'evidence', 'requester', 'old_trusted_source_available'}
                    or binding['operation_id'] != path.name or not HASH.fullmatch(str(binding['logical_key']))
                    or not HASH.fullmatch(str(binding['evidence'])) or binding['old_trusted_source_available'] is not False
                    or not isinstance(binding['requester'], str) or not 1 <= len(binding['requester']) <= 80
                    or not HASH.fullmatch(str(manifest['proof_sha256']))):
                raise ValueError('malformed bootstrap manifest')
        elif (not isinstance(manifest, dict) or set(manifest) != {"version", "binding", "files"}
                or type(manifest["version"]) is not int or manifest["version"] != 1 or not isinstance(manifest["binding"], dict)
                or set(manifest["binding"]) != {"baseline_id", "evidence"}
                or not ID.fullmatch(str(manifest["binding"]["baseline_id"]))
                or not HASH.fullmatch(str(manifest["binding"]["evidence"]))):
            raise ValueError("malformed recovery manifest")
        if not isinstance(manifest['files'], list) or not 1 <= len(manifest['files']) <= (32 if bootstrap else 64):
            raise ValueError('malformed recovery inventory')
        files = {"manifest.json": manifest_info}
        size = len(content)
        if namespace:
            from .namespace_apply import PROOF_LIMIT, validate_proof
            proof, proof_info = _read(fd, 'proof.json', PROOF_LIMIT)
            if hashlib.sha256(proof).hexdigest() != manifest['proof_sha256']:
                raise ValueError('changed namespace Apply proof')
            parsed = json.loads(proof)
            validate_proof(parsed)  # Closed nested schema: a valid checksum is not enough.
            if (parsed['logical_key'] != binding['logical_key'] or parsed['review'] != binding['review']
                    or not isinstance(parsed['baseline'], dict) or parsed['baseline'].get('id') != binding['baseline_id']
                    or parsed['baseline'].get('fingerprint') != binding['baseline_fingerprint']
                    or fingerprint(parsed['owner']) != binding['owner']):
                raise ValueError('malformed namespace Apply proof')
            files['proof.json'] = proof_info
            size += len(proof)
        if bootstrap:
            proof, proof_info = _read(fd, 'proof.json', 8 * 1024 * 1024)
            if hashlib.sha256(proof).hexdigest() != manifest['proof_sha256']:
                raise ValueError('changed bootstrap proof')
            parsed = json.loads(proof)
            if not isinstance(parsed, dict) or set(parsed) != {'model', 'selected', 'peers', 'context', 'desired_hash', 'runtime_hash'}:
                raise ValueError('malformed bootstrap proof')
            files['proof.json'] = proof_info
            size += len(proof)
        inputs = {"desired": [], "baseline": []}
        totals = {"desired": 0, "baseline": 0}
        layouts = {"desired": [], "baseline": []}
        for item in manifest["files"]:
            if (not isinstance(item, dict) or set(item) != {"kind", "role", "path", "present", "sha256", "size", "stored"}
                    or item["kind"] not in totals or item["role"] not in {"compose", "project_env", "env_file"}
                    or not isinstance(item["path"], str) or not item["path"].startswith("/")
                    or len(item["path"]) > 4096 or "\x00" in item["path"]
                    or type(item["present"]) is not bool or type(item["size"]) is not int
                    or not 0 <= item["size"] <= 1024 * 1024):
                raise ValueError("malformed recovery input")
            kind = item["kind"]
            if bootstrap and kind != 'desired':
                raise ValueError('bootstrap has no baseline inventory')
            index = len(layouts[kind])
            if index >= 32:
                raise ValueError("oversized recovery inventory")
            layouts[kind].append((item["role"], item["path"], item["present"]))
            if not item["present"]:
                if item["stored"] is not None or item["size"] != 0 or item["sha256"] is not None:
                    raise ValueError("malformed absent input")
                inputs[kind].append(InputFile(item["role"], item["path"], False, None, 0))
                continue
            name = item["stored"]
            if (not isinstance(name, str) or not re.fullmatch(item["kind"] + r"-[0-9]{2}", name)
                    or name != f"{kind}-{index:02d}" or name in files or not HASH.fullmatch(str(item["sha256"]))):
                raise ValueError("unsafe stored input")
            data, info = _read(fd, name, 1024 * 1024)
            totals[item["kind"]] += len(data)
            if (len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]
                    or totals[item["kind"]] > 16 * 1024 * 1024):
                raise ValueError("changed recovery input")
            inputs[kind].append(InputFile(item["role"], item["path"], True, item["sha256"], item["size"], data))
            files[name] = info
            size += len(data)
        if ((not bootstrap and layouts["desired"] != layouts["baseline"]) or not layouts["desired"]
                or len(set(layouts["desired"])) != len(layouts["desired"])
                or not any(role == "compose" and present for role, _, present in layouts["desired"])):
            raise ValueError("incomplete recovery inventory")
        if set(os.listdir(fd)) != set(files):
            raise ValueError("unexpected recovery material")
        yield {"binding": manifest["binding"], "inputs": inputs, "fingerprint": fingerprint(manifest), "baseline_id": manifest["binding"].get("baseline_id"), "bootstrap": bootstrap,
               "namespace_apply": namespace,
               "size": size, "created": bundle_info.st_mtime, "files": files,
               "fd": fd, "root_fd": root_fd, "info": bundle_info,
               "parent_fd": descriptors[-3], "root_info": os.fstat(root_fd)}
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _namespace_lifecycle(connection, operation_id, bundle, row):
    """Active/manual fences take precedence over any terminal receipt."""
    fence = connection.execute("SELECT lifecycle,evidence,logical_key FROM compose_bootstrap_fences WHERE operation_id=?",
                               (operation_id,)).fetchone()
    if fence and fence[0] in {'active', 'manual'}:
        return fence[0], row[4] if row else None
    binding = bundle['binding']
    if row:
        kind, status, result, summary, finished = row
        try:
            result, summary = json.loads(result), json.loads(summary)
            evidence = summary.get('namespace_apply_evidence')
            if (kind != 'compose_reconcile' or summary.get('namespace_apply') != 3
                    or summary.get('namespace_apply_review') != binding['review']
                    or summary.get('namespace_apply_logical_key') != binding['logical_key']
                    or summary.get('namespace_apply_owner') != binding['owner']
                    or summary.get('baseline_id') != binding['baseline_id']
                    or evidence not in (None, bundle['fingerprint'])):
                return 'unproven', None
            if status in {'queued', 'running', 'finalizing'}:
                return 'active', None
            if result.get('manual_recovery_required') is not False:
                return 'manual', finished
            marked = summary.get('namespace_apply_marked') is True or summary.get('mutation_started') is True
            if status == 'blocked' and not marked and not fence:
                return 'terminal', finished  # Proved pre-marker block: no mutation fence.
            if (marked and evidence == bundle['fingerprint'] and fence and fence[0] == 'resolved'
                    and fence[1] == bundle['fingerprint'] and fence[2] == binding['logical_key']
                    and (status == 'succeeded' or status == 'failed' and result.get('recovered') is True)):
                return 'terminal', finished
        except (ValueError, TypeError, AttributeError):
            pass
        return 'unproven', None
    receipt = connection.execute("SELECT fingerprint,lifecycle,finished_at FROM compose_recovery_receipts WHERE operation_id=?", (operation_id,)).fetchone()
    if receipt and receipt[0] == bundle["fingerprint"] and receipt[1] in {"terminal", "manual"}:
        if receipt[1] == 'terminal' and fence and (fence[0] != 'resolved' or fence[1] != bundle['fingerprint']):
            return 'unproven', None
        return receipt[1], receipt[2]
    return 'unproven', None


def lifecycle(connection, operation_id, bundle):
    """Live state takes precedence; a pruning receipt proves safe orphan state."""
    row = connection.execute("SELECT kind,status,result,summary,finished_at FROM operation_runs WHERE id=?", (operation_id,)).fetchone()
    if bundle.get('namespace_apply'):
        return _namespace_lifecycle(connection, operation_id, bundle, row)
    if bundle.get('bootstrap'):
        fence = connection.execute("SELECT lifecycle,evidence,logical_key FROM compose_bootstrap_fences WHERE operation_id=?", (operation_id,)).fetchone()
        if fence and fence[0] in {'active', 'manual'}:
            return fence[0], row[4] if row else None
        if row:
            kind, status, result, summary, finished = row
            try:
                result, summary = json.loads(result), json.loads(summary)
                if kind != 'compose_bootstrap' or summary.get('bootstrap_evidence') != bundle['fingerprint']:
                    return 'unproven', None
                if result.get('manual_recovery_required') is True:
                    return 'manual', finished
                if status in {'queued','running','finalizing'}:
                    return 'active', None
                if (status in {'succeeded','blocked'} and result.get('manual_recovery_required') is False
                        and (status == 'blocked' or fence and fence[0] == 'resolved' and fence[1] == bundle['fingerprint'])):
                    return 'terminal', finished
            except (ValueError, TypeError, AttributeError):
                pass
            return 'unproven', None
    if row and not bundle.get("bootstrap"):
        kind, status, result, summary, finished = row
        if kind != "compose_reconcile":
            return "unproven", None
        try:
            result, summary = json.loads(result), json.loads(summary)
            if summary.get("baseline_id") != bundle["baseline_id"]:
                return "unproven", None
            if status in {"queued", "running", "finalizing"}:
                return "active", None
            if result.get("manual_recovery_required") is True:
                return "manual", finished
            if (result.get("manual_recovery_required") is False and
                    (status in {"succeeded", "blocked"} or
                     status == "failed" and result.get("recovered") is True)):
                return "terminal", finished
        except (TypeError, ValueError, AttributeError):
            pass
        return "unproven", None
    receipt = connection.execute("SELECT fingerprint,lifecycle,finished_at FROM compose_recovery_receipts WHERE operation_id=?", (operation_id,)).fetchone()
    if receipt and receipt[0] == bundle["fingerprint"] and receipt[1] in {"terminal", "manual"}:
        return receipt[1], receipt[2]
    return "unproven", None


def archive_lifecycle(connection, state_root, operation_id):
    """Called in the same write transaction as operation pruning."""
    try:
        with checked_bundle(state_root, Path(state_root) / "compose-recoveries" / operation_id) as bundle:
            status, finished = lifecycle(connection, operation_id, bundle)
            if status in {"terminal", "manual"} and finished:
                connection.execute("INSERT OR IGNORE INTO compose_recovery_receipts VALUES(?,?,?,?)",
                                   (operation_id, bundle["fingerprint"], status, finished))
    except (OSError, ValueError, TypeError, RecursionError):
        # Missing, malformed or unproved orphan material remains protected.
        pass


def remove_bundle(path, bundle):
    """Delete only validated flat files via pinned descriptors; no traversal."""
    root_fd, fd = bundle["root_fd"], bundle["fd"]
    _private(os.fstat(bundle["parent_fd"]), True)
    _private(os.fstat(fd), True)
    if set(os.listdir(fd)) != set(bundle["files"]):
        raise ValueError("changed recovery material")
    current_root = os.stat("compose-recoveries", dir_fd=bundle["parent_fd"], follow_symlinks=False)
    _private(current_root, True)
    if (current_root.st_dev, current_root.st_ino) != (bundle["root_info"].st_dev, bundle["root_info"].st_ino):
        raise ValueError("changed recovery root")
    current = os.stat(Path(path).name, dir_fd=root_fd, follow_symlinks=False)
    _private(current, True)
    if (current.st_dev, current.st_ino) != (bundle["info"].st_dev, bundle["info"].st_ino):
        raise ValueError("changed recovery directory")
    for name, before in bundle["files"].items():
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)
        _private(current)
        if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError("changed recovery material")
    for name in bundle["files"]:
        os.unlink(name, dir_fd=fd)
    os.rmdir(Path(path).name, dir_fd=root_fd)
