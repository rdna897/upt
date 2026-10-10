#!/usr/bin/env python3
"""Check the actual CI worker before installing or executing tests.

Runner routing is not access control: revoke private runner registrations before
publication. This script deliberately never imports application or test modules.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Mapping


ROOT = Path(__file__).resolve().parents[2]


def expected_environment(event: Mapping, env: Mapping[str, str]) -> str:
    private = event.get("repository", {}).get("private") is True
    same_repository = (
        env.get("GITHUB_EVENT_NAME") != "pull_request"
        or event.get("pull_request", {}).get("head", {}).get("repo", {}).get("full_name")
        == env.get("GITHUB_REPOSITORY")
    )
    if private and same_repository and env.get("UPT_CI_HOSTED") != "true":
        return "self-hosted"
    return "github-hosted"


def verify(event: Mapping, env: Mapping[str, str], *, require_test_bootstrap: bool,
           root: Path = ROOT) -> str:
    expected = expected_environment(event, env)

    def require(condition: bool, reason: str) -> None:
        if not condition:
            raise ValueError(reason)  # Fixed diagnostics; never include environment values.

    require(env.get("GITHUB_ACTIONS") == "true", "GitHub Actions metadata required")
    require(env.get("RUNNER_ENVIRONMENT") == expected, "runner environment mismatch")
    require(env.get("RUNNER_OS") == "Linux" and env.get("RUNNER_ARCH") == "X64"
            and platform.machine() == "x86_64", "unsupported operating system or architecture")
    release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            release[key] = value.strip('"')
    wanted = ("ubuntu", "24.04") if expected == "github-hosted" else ("debian", "13")
    require((release.get("ID"), release.get("VERSION_ID")) == wanted, "unsupported runner image")
    require(sys.version_info >= (3, 10), "Python 3.10 or newer required")
    for tool in ("git", "curl", "python3"):
        require(shutil.which(tool) is not None, "required runner tool missing")
    require(not any(env.get(name) for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG")),
            "Docker connection overrides forbidden")
    docker_config = Path(env.get("HOME", "")) / ".docker"
    require(not (docker_config / "config.json").exists()
            and not (docker_config / "contexts").exists(), "Docker credentials or contexts forbidden")
    if expected == "self-hosted":
        require(not Path("/var/run/docker.sock").is_socket(), "private runner Docker socket forbidden")
        require(not any(shutil.which(tool) for tool in ("docker", "docker-compose")),
                "private runner Docker executables forbidden")
    if require_test_bootstrap:
        require(all((root / name).is_file() for name in
                    ("scripts/run_tests.py", "tests/_upt_isolation.py")),
                "tests require the approved isolation bootstrap")
    return expected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-test-bootstrap", action="store_true")
    args = parser.parse_args()
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        environment = verify(event, os.environ, require_test_bootstrap=args.require_test_bootstrap)
    except (OSError, KeyError, ValueError, TypeError, AttributeError) as exc:
        # Parsing and filesystem errors can contain paths or payloads.
        reason = str(exc) if type(exc) is ValueError and not isinstance(exc, json.JSONDecodeError) else "invalid runner metadata"
        print("Runner smoke failed: " + reason, file=sys.stderr)
        return 1
    print("Runner smoke passed: " + environment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
