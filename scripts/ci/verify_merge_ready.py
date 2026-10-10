#!/usr/bin/env python3
"""Read-only pre-merge check for a UPT pull request.

Branch protection is unavailable on this repository's GitHub plan, so nothing
stops a merge through the web UI or ``gh pr merge``. Run this before any UPT
merge:

    python3 scripts/ci/verify_merge_ready.py <pr-number> [--repo owner/name]

It exits 0 only when the latest applicable ``tests`` workflow run for the PR's
*current* head and *current* base-branch tip completed a full validation that
the merge-gate job attested. Missing, stale, running, failed, ambiguous or
inconsistent evidence exits 1 with reasons. It never merges or writes anything.
There is deliberately no override flag. It uses the caller's existing ``gh``
authentication and prints no credentials.

Standard library only; runs on Python 3.10+.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Callable

WORKFLOW_FILE = "tests.yml"
EVIDENCE_MARKER = "UPT_MERGE_GATE_EVIDENCE "  # emitted by scripts/ci/merge_gate.py
GATE_JOB = "merge-gate"
REQUIRED_JOBS = ("runner-smoke", "plan", "unit-tests (3.10)", "unit-tests (3.13)", "browser-tests", GATE_JOB)
SELF_VALIDATING_PREFIXES = (".github/", "scripts/ci/")

Gh = Callable[[list[str]], str]


class NotReady(Exception):
    pass


def run_gh(args: list[str]) -> str:
    result = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        # gh error text never contains the token; keep it short anyway.
        raise NotReady(f"gh {args[0]} failed: {result.stderr.strip()[:300] or 'exit ' + str(result.returncode)}")
    return result.stdout


def gh_json(gh: Gh, path: str) -> dict:
    try:
        return json.loads(gh(["api", path]))
    except ValueError as exc:
        raise NotReady(f"unparseable GitHub response for {path}") from exc


def is_noop_run(jobs: list[dict]) -> bool:
    """A metadata-only "edited" run: every job skipped, including runner-smoke.

    runner-smoke is skipped only for such edits, so no validating run matches.
    (GitHub shows a skipped job's templated name unevaluated, so the gate name
    is not a reliable signal.)
    """
    return (bool(jobs) and all(j.get("conclusion") == "skipped" for j in jobs)
            and any(j.get("name") == "runner-smoke" for j in jobs))


def parse_evidence(log: str) -> dict:
    found = [line.split(EVIDENCE_MARKER, 1)[1] for line in log.splitlines() if EVIDENCE_MARKER in line]
    if len(found) != 1:
        raise NotReady(f"merge-gate log has {len(found)} evidence lines (expected exactly 1)")
    try:
        data = json.loads(found[0])
    except ValueError as exc:
        raise NotReady("merge-gate evidence line is not valid JSON") from exc
    if not isinstance(data, dict):
        raise NotReady("merge-gate evidence is not an object")
    return data


def verify(pr_number: int, repo: str, gh: Gh = run_gh) -> tuple[list[str], list[str]]:
    """Return (facts, warnings) when merge-ready; raise NotReady otherwise."""
    pr = gh_json(gh, f"repos/{repo}/pulls/{pr_number}")
    if pr.get("state") != "open" or pr.get("merged"):
        raise NotReady(f"PR #{pr_number} is not open (state={pr.get('state')}, merged={pr.get('merged')})")
    if pr.get("draft") is not False:
        raise NotReady(f"PR #{pr_number} is a draft; mark it ready and let full CI run")
    head_sha = (pr.get("head") or {}).get("sha")
    head_ref = (pr.get("head") or {}).get("ref")
    base_ref = (pr.get("base") or {}).get("ref")
    if not (head_sha and head_ref and base_ref):
        raise NotReady("PR head SHA, head branch or base branch is unknown")
    base_tip = (gh_json(gh, f"repos/{repo}/git/ref/heads/{base_ref}").get("object") or {}).get("sha")
    if not base_tip:
        raise NotReady(f"cannot resolve current tip of base branch {base_ref!r}")

    runs = gh_json(gh, f"repos/{repo}/actions/workflows/{WORKFLOW_FILE}/runs"
                       f"?event=pull_request&head_sha={head_sha}&per_page=100").get("workflow_runs")
    if not isinstance(runs, list):
        raise NotReady("workflow run list missing from GitHub response")
    runs = [r for r in runs if r.get("head_sha") == head_sha and r.get("head_branch") == head_ref]
    runs.sort(key=lambda r: (r.get("created_at") or "", r.get("id") or 0), reverse=True)
    if not runs:
        raise NotReady(f"no '{WORKFLOW_FILE}' pull_request run exists for head {head_sha[:12]}")

    for run in runs:  # newest first; the latest applicable run decides
        run_id = run.get("id")
        if run.get("status") != "completed":
            raise NotReady(f"run {run_id} for the current head is still {run.get('status')}; wait for it")
        jobs = gh_json(gh, f"repos/{repo}/actions/runs/{run_id}/jobs?filter=latest&per_page=100").get("jobs")
        if not isinstance(jobs, list):
            raise NotReady(f"job list missing for run {run_id}")
        if is_noop_run(jobs):
            continue  # title/body edit: carries no validation either way
        return _check_run(run, jobs, repo=repo, gh=gh, head_sha=head_sha,
                          base_ref=base_ref, base_tip=base_tip, pr_number=pr_number)
    raise NotReady(f"no validating run exists for head {head_sha[:12]} (only metadata-edit runs)")


def _check_run(run, jobs, *, repo, gh, head_sha, base_ref, base_tip, pr_number):
    run_id = run.get("id")
    if run.get("conclusion") != "success":
        raise NotReady(f"latest applicable run {run_id} concluded {run.get('conclusion')}")
    by_name: dict[str, list[dict]] = {}
    for job in jobs:
        by_name.setdefault(job.get("name"), []).append(job)
    problems = []
    for name in REQUIRED_JOBS:
        matches = by_name.get(name, [])
        if len(matches) != 1:
            problems.append(f"{name}: {'missing' if not matches else 'ambiguous'}")
        elif matches[0].get("conclusion") != "success":
            problems.append(f"{name}: {matches[0].get('conclusion') or matches[0].get('status')}")
    if problems:
        raise NotReady(f"run {run_id} is not a passing full validation: " + "; ".join(problems))

    gate_job = by_name[GATE_JOB][0]
    log = gh(["run", "view", str(run_id), "--repo", repo, "--job", str(gate_job.get("id")), "--log"])
    ev = parse_evidence(log)
    expected = {"passed": True, "mode": "full", "event": "pull_request", "head_sha": head_sha,
                "base_ref": base_ref, "base_sha": base_tip}
    mismatches = [f"{key}: run has {ev.get(key)!r}, need {want!r}"
                  for key, want in expected.items() if ev.get(key) != want]
    if mismatches:
        hint = ""
        if any(m.startswith(("base_ref", "base_sha")) for m in mismatches):
            hint = (" (the base branch changed or advanced since validation; re-run full CI, e.g. "
                    f"`gh pr ready {pr_number} --undo && gh pr ready {pr_number}`)")
        raise NotReady(f"run {run_id} evidence does not match the PR's current state: "
                       + "; ".join(mismatches) + hint)

    facts = [f"PR #{pr_number}: open, ready for review",
             f"head {head_sha}",
             f"base {base_ref} @ {base_tip}",
             f"validated by run {run_id} ({run.get('html_url', '')}), tested merge commit {ev.get('tested_sha')}",
             "runner-smoke, plan, unit-tests (3.10), unit-tests (3.13), browser-tests, merge-gate: success"]
    warnings = []
    files = gh(["api", "--paginate", f"repos/{repo}/pulls/{pr_number}/files", "--jq", ".[].filename"]).split()
    ci_files = sorted(f for f in files if f.startswith(SELF_VALIDATING_PREFIXES))
    if ci_files:
        warnings.append("this PR changes its own CI definition, so its evidence came from the PR's version of "
                        "the workflow; review these files by hand: " + ", ".join(ci_files))
    return facts, warnings


def main(argv: list[str] | None = None, gh: Gh = run_gh) -> int:
    parser = argparse.ArgumentParser(description="Read-only UPT pre-merge validation check.")
    parser.add_argument("pr", type=int, help="pull request number")
    parser.add_argument("--repo", help="owner/name (default: current gh repository)")
    args = parser.parse_args(argv)
    try:
        repo = args.repo or gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]).strip()
        if not repo:
            raise NotReady("cannot determine repository")
        facts, warnings = verify(args.pr, repo, gh)
    except NotReady as exc:
        print(f"NOT READY: {exc}")
        return 1
    except Exception as exc:  # Unexpected data or tooling failure: fail closed.
        print(f"NOT READY: verification error ({type(exc).__name__}: {exc})")
        return 1
    print("READY: full validation matches the current head and base")
    for fact in facts:
        print(f"  - {fact}")
    for warning in warnings:
        print(f"WARNING: {warning}")
    print("Note: this check is advisory; GitHub does not enforce it on this repository.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
