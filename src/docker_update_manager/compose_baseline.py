"""Durable, bounded, server-side trusted Compose baselines.

A baseline is the captured configuration-input bytes plus the selected service
model proven by the running container hash. Other project model entries are
stored only as digests of the desired state observed at capture time.
Metadata lives in the core SQLite state; material lives under
<state root>/compose-baselines/<id>/ with directories mode 0700 and files mode
0600. Nothing here is ever returned to a browser: callers project only the
bounded public facts they need.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .compose_drift import InputFile, Inventory, fingerprint, observed_service_model

BASELINE_DIR = "compose-baselines"
KEEP_PER_SERVICE = 4  # one current baseline plus three previous
ORIGINS = frozenset({"captured", "adopted_backup", "reproduced"})
MAX_MODEL_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
_ID = re.compile(r"^[0-9a-f]{32}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


class BaselineIntegrityError(Exception):
    """Stored baseline material is missing, altered or unsafe; never trusted."""


def logical_key(stack, compose_service, working_dir, compose_files) -> str:
    return fingerprint(["compose-service-v1", stack, compose_service, os.path.abspath(str(working_dir)),
                        [os.path.abspath(str(path)) for path in compose_files]])


def _record_fingerprint(values: dict) -> str:
    return fingerprint({name: values[name] for name in (
        "logical_key", "stack", "compose_service", "container_id", "runtime_hash",
        "project_fingerprint", "service_fingerprint", "inventory_fingerprint")})


@dataclass(frozen=True)
class Baseline:
    id: str
    logical_key: str
    stack: str
    compose_service: str
    container_id: str
    runtime_hash: str
    project_fingerprint: str
    service_fingerprint: str
    inventory_fingerprint: str
    fingerprint: str
    origin: str
    captured_at: str
    manifest: dict

    @classmethod
    def from_row(cls, row: dict):
        try:
            manifest = json.loads(row["manifest"])
        except (TypeError, ValueError):
            manifest = {}
        return cls(**{**{key: row[key] for key in row if key != "manifest"}, "manifest": manifest})


@dataclass(frozen=True)
class LoadedBaseline:
    record: Baseline
    model: dict
    inputs: tuple  # InputFile with content

    @property
    def inventory(self) -> Inventory:
        return Inventory(self.inputs, ())

    @property
    def project_trusted(self) -> bool:
        # Neither v1's full desired model nor v2's digests prove project runtime.
        return False

    @property
    def project_observed(self) -> bool:
        return self.record.manifest.get("version") == 2


def _write_private(path: Path, content: bytes):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def _read_private(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise BaselineIntegrityError("baseline material is unavailable") from None
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid()
                or info.st_size > limit):
            raise BaselineIntegrityError("baseline material is unsafe")
        chunks, total = [], 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise BaselineIntegrityError("baseline material is unsafe")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


class BaselineStore:
    def __init__(self, state):
        self.state = state

    @property
    def root(self) -> Path:
        return Path(self.state.root) / BASELINE_DIR

    def _ensure_root(self) -> Path:
        root = self.root
        Path(self.state.root).mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.is_symlink():
            raise BaselineIntegrityError("baseline storage is a symbolic link")
        root.mkdir(exist_ok=True, mode=0o700)
        os.chmod(root, 0o700)
        return root

    def records(self, key: str):
        return [Baseline.from_row(row) for row in self.state.compose_baselines(key)]

    def save(self, *, protected=(), **values) -> Baseline:
        record = self.prepare(**values)
        encoded = {**record.__dict__, "manifest": json.dumps(record.manifest, sort_keys=True, separators=(",", ":"))}
        try:
            self.state.insert_compose_baseline(encoded)
        except BaseException:
            shutil.rmtree(self.root / record.id, ignore_errors=True)
            raise
        self.prune(record.logical_key, protected=protected)
        return record

    def prepare(self, *, key, stack, compose_service, container_id, runtime_hash, model, inventory: Inventory,
                origin, captured_at) -> Baseline:
        """Fsync and verify material without publishing any trusted row."""
        if origin not in ORIGINS or not inventory.supported or not _HASH.fullmatch(str(runtime_hash)):
            raise ValueError("baseline evidence is incomplete")
        service_model = (model.get("services") or {}).get(compose_service)
        if not isinstance(service_model, dict):
            raise ValueError("baseline evidence is incomplete")
        for item in inventory.files:
            if item.present and hashlib.sha256(item.content).hexdigest() != item.sha256:
                raise ValueError("baseline evidence is incomplete")
        baseline_id = secrets.token_hex(16)
        model = observed_service_model(model, compose_service)
        model_bytes = json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
        if len(model_bytes) > MAX_MODEL_BYTES:
            raise ValueError("baseline model exceeds the storage limit")
        files = []
        for index, item in enumerate(inventory.files):
            files.append({"role": item.role, "path": item.path, "present": item.present, "sha256": item.sha256,
                          "size": item.size, "stored": f"inputs/{index:02d}" if item.present else None})
        manifest = {"version": 2, "trust_scope": "selected_service", "files": files,
                    "model_sha256": hashlib.sha256(model_bytes).hexdigest()}
        values = {"id": baseline_id, "logical_key": key, "stack": stack, "compose_service": compose_service,
                  "container_id": container_id, "runtime_hash": runtime_hash,
                  "project_fingerprint": fingerprint(model), "service_fingerprint": fingerprint(service_model),
                  "inventory_fingerprint": inventory.fingerprint, "origin": origin, "captured_at": captured_at}
        values["fingerprint"] = _record_fingerprint(values)
        values["manifest"] = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
        root = self._ensure_root()
        staging = root / f".tmp-{baseline_id}"
        final = root / baseline_id
        staging.mkdir(mode=0o700)
        promoted = False
        try:
            (staging / "inputs").mkdir(mode=0o700)
            for item, entry in zip(inventory.files, files):
                if entry["stored"]:
                    _write_private(staging / entry["stored"], item.content)
            _write_private(staging / "model.json", model_bytes)
            _write_private(staging / "manifest.json", values["manifest"].encode())
            for directory in (staging / "inputs", staging):
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            os.replace(staging, final)
            promoted = True
            descriptor = os.open(root, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            # Only a directory this call promoted may be removed; final may pre-exist.
            if promoted:
                self._remove_private_directory(final)
            raise
        record = Baseline.from_row(values)
        try:
            self.load(record)
        except BaseException:
            self._remove_private_directory(final)
            raise
        return record

    def _remove_private_directory(self, directory: Path) -> None:
        """Best-effort removal of one UPT-owned baseline directory; never follows a symlink."""
        try:
            info = os.lstat(directory)
            if stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and directory.parent == self.root:
                shutil.rmtree(directory, ignore_errors=True)
        except OSError:
            pass

    def discard_unpublished(self, record: Baseline) -> bool:
        """Remove prepared material only when the database proves no trusted row exists.

        A matching row, or any failure to read publication state, retains the material.
        """
        try:
            if not _ID.fullmatch(str(record.id)):
                return False
            with self.state.read() as c:
                if c.execute("SELECT 1 FROM compose_baselines WHERE id=?", (record.id,)).fetchone():
                    return False
            self._remove_private_directory(self.root / record.id)
            return True
        except Exception:
            return False

    def load(self, record: Baseline) -> LoadedBaseline:
        """Return verified baseline material or raise BaselineIntegrityError."""
        if not _ID.fullmatch(str(record.id)) or _record_fingerprint(record.__dict__) != record.fingerprint:
            raise BaselineIntegrityError("baseline record is inconsistent")
        directory = self.root / record.id
        try:
            info = os.lstat(directory)
        except OSError:
            raise BaselineIntegrityError("baseline material is unavailable") from None
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise BaselineIntegrityError("baseline directory is unsafe")
        try:
            manifest = json.loads(_read_private(directory / "manifest.json", MAX_MANIFEST_BYTES))
        except ValueError:
            raise BaselineIntegrityError("baseline manifest is invalid") from None
        if (manifest != record.manifest or manifest.get("version") not in {1, 2}
                or (manifest.get("version") == 2 and manifest.get("trust_scope") != "selected_service")
                or not isinstance(manifest.get("files"), list)):
            raise BaselineIntegrityError("baseline manifest does not match its record")
        model_bytes = _read_private(directory / "model.json", MAX_MODEL_BYTES)
        if hashlib.sha256(model_bytes).hexdigest() != manifest.get("model_sha256"):
            raise BaselineIntegrityError("baseline model was altered")
        try:
            model = json.loads(model_bytes)
        except ValueError:
            raise BaselineIntegrityError("baseline model is invalid") from None
        if not isinstance(model, dict) or fingerprint(model) != record.project_fingerprint:
            raise BaselineIntegrityError("baseline model does not match its record")
        service_model = (model.get("services") or {}).get(record.compose_service)
        if not isinstance(service_model, dict) or fingerprint(service_model) != record.service_fingerprint:
            raise BaselineIntegrityError("baseline service model does not match its record")
        inputs = []
        for entry in manifest["files"]:
            if not isinstance(entry, dict):
                raise BaselineIntegrityError("baseline manifest is invalid")
            if entry.get("present"):
                stored = entry.get("stored")
                if not isinstance(stored, str) or not re.fullmatch(r"inputs/\d{2}", stored):
                    raise BaselineIntegrityError("baseline manifest is invalid")
                content = _read_private(directory / stored, 1024 * 1024)
                if hashlib.sha256(content).hexdigest() != entry.get("sha256") or len(content) != entry.get("size"):
                    raise BaselineIntegrityError("baseline input was altered")
                inputs.append(InputFile(entry["role"], entry["path"], True, entry["sha256"], entry["size"], content))
            else:
                inputs.append(InputFile(entry.get("role"), entry.get("path"), False, None, 0))
        if Inventory(tuple(inputs), ()).fingerprint != record.inventory_fingerprint:
            raise BaselineIntegrityError("baseline inventory does not match its record")
        return LoadedBaseline(record, model, tuple(inputs))

    def prune(self, key: str, *, protected=()):
        """Keep one current plus a small previous set; never prune referenced baselines."""
        protected = self.state.compose_baseline_references() | set(protected)
        root = self.root
        for record in self.records(key)[KEEP_PER_SERVICE:]:
            if record.id in protected or not _ID.fullmatch(record.id):
                continue
            self.state.delete_compose_baseline(record.id)
            directory = root / record.id
            if not directory.is_symlink() and directory.is_dir():
                shutil.rmtree(directory, ignore_errors=True)
        # Staging directories from an interrupted capture are never trusted.
        try:
            for staging in root.glob(".tmp-*"):
                if (not staging.is_symlink() and staging.is_dir()
                        and time.time() - staging.stat().st_mtime > 3600):
                    shutil.rmtree(staging, ignore_errors=True)
        except OSError:
            pass
