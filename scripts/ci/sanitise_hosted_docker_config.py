#!/usr/bin/env python3
"""Fail-closed removal of the Docker client config that GitHub-hosted images pre-provision.

The ubuntu-24.04 hosted image ships ``~/.docker/config.json`` containing a
registry ``auths`` entry. UPT forbids Docker credentials on test workers
(``runner_smoke.py``), so hosted jobs must remove that file first. This step
removes it only when it has *exactly* the shape the hosted image is known to
provide, and refuses (leaving everything in place for the unchanged smoke check
to reject) when anything else is found: Docker contexts, credential helpers,
other files, missing, extra or unknown keys or registries, empty values,
symlinks or unreadable content.

Values are never read into diagnostics. Messages are fixed strings so no
credential, registry name, filename or path can reach logs, and unexpected
filesystem or parser errors are converted into fixed refusals rather than
tracebacks. The directory is opened once without following symlinks and every
later operation is relative to that handle; the file is read through a handle
opened with ``O_NOFOLLOW`` and is only unlinked if the name still refers to the
inode that was validated. Standard library only; runs on Python 3.10+.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from typing import Mapping

HOSTED = "github-hosted"
# Shape observed on the ubuntu-24.04 hosted image: only config.json, whose JSON is
# exactly {"auths": {<Docker Hub>: {"auth": <non-empty string>}}}.
CONFIG_NAME = "config.json"
EXPECTED_FILES = [CONFIG_NAME]
EXPECTED_TOP_LEVEL = frozenset({"auths"})
EXPECTED_REGISTRIES = frozenset({"https://index.docker.io/v1/"})
EXPECTED_ENTRY_FIELDS = frozenset({"auth"})
MAX_CONFIG_BYTES = 65536
FORBIDDEN_ENV = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
# O_NONBLOCK so a planted FIFO cannot hang the job; it is rejected by the S_ISREG check.
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


class Refusal(ValueError):
    """Raised with a fixed diagnostic; never includes configuration content."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise Refusal(reason)


def _reject_duplicate_keys(pairs):
    keys = [key for key, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def _read_bounded(descriptor: int) -> bytes:
    chunks, total = [], 0
    while True:
        chunk = os.read(descriptor, MAX_CONFIG_BYTES + 1 - total)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        _require(total <= MAX_CONFIG_BYTES, "Docker client config is unexpectedly large")


def _validate(raw: bytes) -> None:
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (ValueError, RecursionError):
        raise Refusal("Docker client config is unreadable or not JSON") from None
    shape = "Docker client config does not match the expected hosted-image structure"
    _require(isinstance(data, dict) and set(data) == EXPECTED_TOP_LEVEL, shape)
    auths = data["auths"]
    _require(isinstance(auths, dict) and set(auths) == EXPECTED_REGISTRIES, shape)
    for entry in auths.values():
        _require(isinstance(entry, dict) and set(entry) == EXPECTED_ENTRY_FIELDS, shape)
        _require(isinstance(entry["auth"], str) and entry["auth"] != "", shape)


def _open_docker_directory(home: str) -> int | None:
    """Return a handle for ``~/.docker`` (never following a symlink), or None if absent."""
    try:
        return os.open(os.path.join(home, ".docker"), _DIR_FLAGS)
    except FileNotFoundError:
        return None
    except OSError:
        raise Refusal("Docker client directory is unexpected or inaccessible") from None


def _same_regular_file(descriptor: int, directory: int) -> bool:
    opened = os.fstat(descriptor)
    named = os.stat(CONFIG_NAME, dir_fd=directory, follow_symlinks=False)
    return stat.S_ISREG(named.st_mode) and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)


def sanitise(env: Mapping[str, str], home: str | None = None) -> str:
    """Validate then remove the hosted image's Docker client config.

    Returns ``"removed"`` or ``"absent"``; raises :class:`Refusal` otherwise.
    """
    _require(env.get("GITHUB_ACTIONS") == "true", "GitHub Actions metadata required")
    _require(env.get("RUNNER_ENVIRONMENT") == HOSTED, "only GitHub-hosted runners are sanitised")
    _require(not any(env.get(name) for name in FORBIDDEN_ENV), "Docker connection overrides forbidden")
    home_dir = home if home is not None else env.get("HOME", "")
    _require(os.path.isabs(home_dir), "home directory is not an absolute path")
    directory = _open_docker_directory(home_dir)
    if directory is None:
        return "absent"
    descriptor = None
    try:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            raise Refusal("Docker client directory could not be listed") from None
        _require(names == EXPECTED_FILES, "Docker client directory has unexpected contents")
        try:
            descriptor = os.open(CONFIG_NAME, _FILE_FLAGS, dir_fd=directory)
        except OSError:
            raise Refusal("Docker client config could not be opened as a regular file") from None
        try:
            info = os.fstat(descriptor)
            _require(stat.S_ISREG(info.st_mode), "Docker client config is not a regular file")
            _require(info.st_size <= MAX_CONFIG_BYTES, "Docker client config is unexpectedly large")
            raw = _read_bounded(descriptor)
        except OSError:
            raise Refusal("Docker client config could not be read") from None
        _validate(raw)
        try:
            _require(_same_regular_file(descriptor, directory), "Docker client config changed during validation")
            os.unlink(CONFIG_NAME, dir_fd=directory)
        except OSError:
            raise Refusal("Docker client config could not be removed") from None
        try:
            os.stat(CONFIG_NAME, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return "removed"
        except OSError:
            pass
        raise Refusal("Docker client config could not be removed")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def main(env: Mapping[str, str] | None = None) -> int:
    environment = os.environ if env is None else env
    try:
        result = sanitise(environment)
    except Refusal as exc:
        print(f"Hosted Docker config sanitisation refused: {exc}", file=sys.stderr)
        return 1
    except Exception:  # fail closed without a traceback that could carry paths
        print("Hosted Docker config sanitisation refused: unexpected error", file=sys.stderr)
        return 1
    print(f"Hosted Docker client config {result}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
