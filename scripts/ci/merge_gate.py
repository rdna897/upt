#!/usr/bin/env python3
"""Fail-closed UPT merge gate and CI run summary.

The gate succeeds only when this workflow run executed the complete suite
(Python 3.10 and 3.13 unit tests plus Chromium) and every required job
succeeded. Skipped, cancelled, failed or targeted-only runs never pass, because
GitHub treats a skipped required job as successful. Timing collection is
best-effort and can never change the gate decision.

Standard library only; runs on Python 3.10+.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import datetime

# Prefix of the single machine-readable evidence line in the merge-gate job log,
# consumed by scripts/ci/verify_merge_ready.py. Contains commit/branch identities
# only, never tokens or environment contents.
EVIDENCE_MARKER = "UPT_MERGE_GATE_EVIDENCE "

REQUIRED_JOBS = ("runner-smoke", "plan", "unit-tests", "browser-tests")
FULL_PYTHON_VERSIONS = ["3.10", "3.13"]


def decide(*, results: dict[str, str], plan_full: str, python_versions: str,
           event: str, draft: bool) -> tuple[bool, list[str]]:
    """Return (passed, explanation lines). Pure function; inputs are workflow strings."""
    notes: list[str] = []
    full_required = event != "pull_request" or not draft
    notes.append("Full validation required for merge: " + ("yes" if full_required else
                 "draft PR; the gate passes only if this run executed the full suite"))
    passed = True
    if plan_full != "true":
        passed = False
        notes.append("Full suite was not selected for this run (targeted/docs CI only).")
    try:
        versions = json.loads(python_versions or "null")
    except ValueError:
        versions = None
    if plan_full == "true" and versions != FULL_PYTHON_VERSIONS:
        passed = False
        notes.append(f"Python matrix {python_versions!r} is not the full matrix {FULL_PYTHON_VERSIONS}.")
    for job in REQUIRED_JOBS:
        result = results.get(job) or "missing"
        if result != "success":
            passed = False
        notes.append(f"`{job}`: {result}")
    notes.append("Merge gate: " + ("PASSED - complete suite succeeded" if passed else "FAILED"))
    return passed, notes


def evidence(env, *, passed: bool) -> dict:
    return {
        "passed": passed,
        "mode": env.get("PLAN_MODE", ""),
        "event": env.get("GITHUB_EVENT_NAME", ""),
        "head_sha": env.get("PR_HEAD_SHA") or env.get("GITHUB_SHA", ""),
        "base_ref": env.get("PR_BASE_REF", ""),
        "base_sha": env.get("PR_BASE_SHA", ""),
        "tested_sha": env.get("GITHUB_SHA", ""),
    }


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _fmt(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "n/a"
    seconds = int(round(seconds))
    return f"{seconds // 60}m {seconds % 60:02d}s"


def timing_table(jobs: list[dict]) -> list[str]:
    lines = ["| Job | Result | Queued | Executed | Runner |", "|---|---|---|---|---|"]
    for job in jobs:
        created, started, completed = (_parse(job.get(k)) for k in ("created_at", "started_at", "completed_at"))
        queued = (started - created).total_seconds() if created and started else None
        ran = (completed - started).total_seconds() if started and completed else None
        lines.append(f"| {job.get('name')} | {job.get('conclusion') or job.get('status')} | "
                     f"{_fmt(queued)} | {_fmt(ran)} | {job.get('runner_name') or '-'} |")
    return lines


def _api(path: str) -> dict:
    url = f"{os.environ['GITHUB_API_URL']}/repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{path}"
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310 - fixed GitHub API URL
        return json.load(response)


def run_timings() -> list[str]:
    run_id = os.environ["GITHUB_RUN_ID"]
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
    jobs = _api(f"{run_id}/attempts/{attempt}/jobs?per_page=100").get("jobs", [])
    lines = timing_table(jobs)
    created = _parse(_api(run_id).get("created_at"))
    finished = [_parse(j.get("completed_at")) for j in jobs if j.get("completed_at")]
    if created and finished:
        lines += ["", f"Run created to last completed job: {_fmt((max(finished) - created).total_seconds())} "
                  "(excludes this gate job)."]
    return lines


def main() -> int:
    env = os.environ
    results = json.loads(env.get("NEEDS_JSON", "{}"))
    job_results = {name: (data or {}).get("result", "missing") for name, data in results.items()}
    passed, notes = decide(
        results=job_results,
        plan_full=env.get("PLAN_FULL", ""),
        python_versions=env.get("PLAN_PYTHON_VERSIONS", ""),
        event=env.get("GITHUB_EVENT_NAME", ""),
        draft=env.get("PR_DRAFT", "false") == "true",
    )
    lines = ["## UPT merge gate", ""]
    lines.append(f"- **Event**: `{env.get('GITHUB_EVENT_NAME', '')}`; **plan mode**: `{env.get('PLAN_MODE', 'unknown')}`")
    lines.append(f"- **Tested commit** (`GITHUB_SHA`): `{env.get('GITHUB_SHA', '')}`")
    if env.get("PR_HEAD_SHA"):
        lines.append(f"- **PR head commit**: `{env['PR_HEAD_SHA']}`")
        lines.append(f"- **Integration base**: `{env.get('PR_BASE_REF', '')}` @ `{env.get('PR_BASE_SHA', '')}`")
    if env.get("PLAN_TEST_MODULES"):
        lines.append(f"- **Targeted modules**: {env['PLAN_TEST_MODULES']}")
    lines += [f"- {note}" for note in notes]
    lines += ["", "### Job timings", ""]
    try:
        lines += run_timings()
    except Exception as exc:  # Timing is observability only; never affects the gate.
        lines.append(f"Timings unavailable: {type(exc).__name__}")
    summary = "\n".join(lines) + "\n"
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(summary)
    print(summary)
    print(EVIDENCE_MARKER + json.dumps(evidence(env, passed=passed), sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
