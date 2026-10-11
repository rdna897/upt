#!/usr/bin/env python3
"""Risk-aware CI test selection for UPT pull requests.

Classifies the files a pull request changes (relative to the Git merge-base with
its base branch) through the explicit RULES map below and decides which test
modules a draft-PR "fast" run needs. Anything cross-cutting, security-sensitive,
infrastructure-related or unclassified escalates to the full suite, and any
selector failure also falls back to full validation (fail closed).

Fast selection is advisory only: merging still requires the full suite via the
merge-gate job (see docs/ci.md). Standard library only; runs on Python 3.10+.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field

FULL_PYTHON_VERSIONS = ("3.10", "3.13")
FAST_PYTHON_VERSIONS = ("3.13",)
BROWSER_TEST_MODULE = "test_web_browser"


@dataclass(frozen=True)
class Suite:
    """What a class of change requires. ``full`` overrides everything else."""

    reason: str
    tests: tuple[str, ...] = ()
    browser: bool = False
    full: bool = False
    docs_only: bool = False


def _full(reason: str) -> Suite:
    return Suite(reason=reason, full=True)


# Test-module groups. Membership is checked by tests/test_ci_selection.py:
# every test module that directly imports a narrowly mapped source module must
# be selected for it, and every name must be a real tests/<name>.py file.
REGISTRY_TESTS = (
    "test_core", "test_discovery", "test_pin_history_image", "test_progress",
    "test_service_verification",
)
VERIFICATION_TESTS = (
    "test_service_verification", "test_web_closure_scan", "test_discovery",
    "test_post_mutation_reconciliation", "test_same_project_baseline_reconciliation",
)
COMPOSE_TESTS = (
    "test_compose_apply", "test_compose_bootstrap", "test_compose_discard",
    "test_compose_namespace", "test_compose_namespace_apply",
    "test_compose_namespace_update", "test_compose_reconciliation",
    "test_compose_recovery_retention", "test_conversion",
    "test_post_mutation_reconciliation", "test_same_project_baseline_reconciliation",
    "test_schema_compatibility_boundary", "test_state_rollback_compatibility",
    "test_web_operations", "test_web_rollback", "test_core", "test_pin_history_image",
    "test_sqlite_completion_characterisation",
)
WEB_TESTS = (
    "test_web_closure_auth", "test_web_closure_http", "test_web_closure_scan",
    "test_web_closure_ui_deploy", "test_web_foundation", "test_web_operations",
    "test_web_redesign", "test_web_remediation", "test_web_rollback",
    "test_web_runtime", "test_web_session_persistence", "test_web_ux_hardening",
    "test_compose_apply", "test_compose_bootstrap", "test_compose_namespace_apply",
    "test_compose_reconciliation", "test_compose_discard",
    "test_post_mutation_reconciliation", "test_runtime_health",
    "test_service_verification", "test_release_identity", "test_version_contract",
)
CLI_TESTS = (
    "test_core", "test_discovery", "test_pin_history_image", "test_progress",
    "test_compose_namespace", "test_schema_compatibility_boundary",
    "test_version_contract", "test_disk_retention",
)

SRC = "src/docker_update_manager/"

# Ordered (glob, Suite) rules; the first match wins. fnmatch "*" also matches
# "/", so "docs/*" covers nested paths. Anything unmatched escalates to full.
RULES: tuple[tuple[str, Suite], ...] = (
    # CI selection, workflow, dependency and test infrastructure.
    (".github/*", _full("CI workflow or GitHub configuration")),
    ("scripts/ci/*", _full("CI selector or merge-gate logic")),
    ("tests/test_ci_*.py", _full("CI selector tests")),
    ("pyproject.toml", _full("packaging or dependency metadata")),
    ("requirements*.txt", _full("dependency pins")),
    (".gitignore", _full("repository packaging/ignore rules")),
    ("tests/progress_assertions.py", _full("shared test helper")),
    ("tests/fixtures/*", _full("shared test fixtures")),
    ("scripts/*", _full("operator tooling without targeted coverage")),

    # Deployment artefacts: installation permissions, service identities,
    # privileged execution, filesystem access and network-exposure defaults.
    ("install.sh", _full("installer permissions and privileged setup")),
    ("systemd/*", _full("systemd service identity, privileges and filesystem access")),
    ("config/*.example.yml", _full("security-relevant example configuration defaults")),

    # Shared orchestration, state, security and recovery: always full.
    (SRC + "state.py", _full("persistent state and history")),
    (SRC + "state_transition.py", _full("persistent state transitions")),
    (SRC + "sqlite_outcome.py", _full("persistent state transaction outcome primitives")),
    (SRC + "lock.py", _full("exclusive operation locking")),
    (SRC + "auth.py", _full("authentication")),
    (SRC + "webstate.py", _full("web sessions and authorisation state")),
    (SRC + "agent.py", _full("privileged agent boundary")),
    (SRC + "webcli.py", _full("web/agent service entry points and privileges")),
    (SRC + "webservice.py", _full("shared web/agent orchestration")),
    (SRC + "operations.py", _full("shared update/pin/rollback orchestration")),
    (SRC + "reconciliation.py", _full("post-mutation recovery and reconciliation")),
    (SRC + "compose_recovery_retention.py", _full("recovery retention")),
    (SRC + "compose_discard.py", _full("Compose drift discard/recovery")),
    (SRC + "namespace_apply.py", _full("namespace apply with recovery")),
    (SRC + "retention.py", _full("image retention and rollback-point protection")),
    (SRC + "removal.py", _full("destructive removal")),
    (SRC + "runtime.py", _full("runtime health gating")),
    (SRC + "docker.py", _full("Docker command execution")),
    (SRC + "system.py", _full("subprocess execution and host helpers")),
    (SRC + "models.py", _full("shared data contracts")),
    (SRC + "config.py", _full("configuration loading")),
    (SRC + "progress.py", _full("shared semantic operation events")),
    (SRC + "_version.py", _full("release identity")),
    (SRC + "__init__.py", _full("package identity")),
    (SRC + "component_version.py", _full("cross-component version reporting")),

    # Narrow, risk-mapped areas.
    (SRC + "registry.py", Suite("registry/version resolution", REGISTRY_TESTS)),
    (SRC + "scan_worker.py", Suite("targeted verification and scan worker", VERIFICATION_TESTS)),
    (SRC + "compose.py", Suite("Compose", COMPOSE_TESTS)),
    (SRC + "compose_*.py", Suite("Compose", COMPOSE_TESTS)),
    (SRC + "namespace_change_catalog.py", Suite("Compose namespace", COMPOSE_TESTS)),
    (SRC + "namespace_update.py", Suite("Compose namespace", COMPOSE_TESTS)),
    (SRC + "conversion.py", Suite("Compose conversion", COMPOSE_TESTS)),
    (SRC + "templates/*", Suite("web templates", WEB_TESTS, browser=True)),
    (SRC + "static/*", Suite("web static assets", WEB_TESTS, browser=True)),
    (SRC + "webapp.py", Suite("web application/routes", WEB_TESTS, browser=True)),
    (SRC + "webviews.py", Suite("web view models", WEB_TESTS, browser=True)),
    (SRC + "operation_presentation.py", Suite("operation presentation", WEB_TESTS, browser=True)),
    (SRC + "release_identity.py", Suite("release identity presentation", WEB_TESTS, browser=True)),
    (SRC + "cli.py", Suite("CLI", CLI_TESTS)),
    (SRC + "diskcli.py", Suite("disk CLI", CLI_TESTS)),
    (SRC + "diskdiag.py", Suite("disk diagnostics", ("test_disk_retention",) + CLI_TESTS)),
    ("bin/*", Suite("CLI launcher", CLI_TESTS)),

    # Non-Python files that tests read directly are not documentation-only.
    ("README.md", Suite("README (asserted by web deploy tests)",
                        ("test_web_closure_http", "test_web_closure_ui_deploy"))),
    ("docs/deployment.md", Suite("deployment security notes (asserted by tests)",
                                ("test_web_closure_http", "test_web_closure_ui_deploy"))),
    ("docs/versioning.md", Suite("versioning policy (asserted by tests)", ("test_version_contract",))),

    # Test modules: run the changed module itself.
    ("tests/test_web_browser.py", Suite("browser test module", browser=True)),
    ("tests/capture_*.py", Suite("screenshot capture harness", browser=True)),

    # Documentation only.
    ("docs/*", Suite("documentation", docs_only=True)),
    ("AGENTS.md", Suite("documentation", docs_only=True)),
    ("SECURITY.md", Suite("documentation", docs_only=True)),
    ("THIRD_PARTY_NOTICES.md", Suite("documentation", docs_only=True)),
)


@dataclass
class Plan:
    full: bool = False
    tests: set[str] = field(default_factory=set)
    browser: bool = False
    reasons: list[tuple[str, str, str]] = field(default_factory=list)  # (path, outcome, reason)
    escalations: list[str] = field(default_factory=list)
    changed_tests: set[str] = field(default_factory=set)

    @property
    def mode(self) -> str:
        if self.full:
            return "full"
        if self.tests or self.browser:
            return "targeted"
        return "docs"

    def escalate(self, reason: str) -> None:
        self.full = True
        self.escalations.append(reason)

    def outputs(self) -> dict[str, str]:
        full = self.full
        versions = FULL_PYTHON_VERSIONS if full else FAST_PYTHON_VERSIONS
        return {
            "mode": self.mode,
            "full": str(full).lower(),
            "run_unit": str(full or bool(self.tests)).lower(),
            "run_browser": str(full or self.browser).lower(),
            "python_versions": json.dumps(list(versions)),
            "test_modules": "" if full else " ".join(sorted(self.tests)),
        }


def match_rule(path: str) -> Suite | None:
    for pattern, suite in RULES:
        if fnmatch.fnmatchcase(path, pattern):
            return suite
    return None


def classify(changes: list[tuple[str, list[str]]], tests_dir: str = "tests") -> Plan:
    """Build a plan from ``(status, paths)`` entries of ``git diff --name-status``."""
    plan = Plan()
    if not changes:
        plan.escalate("no changed files detected; cannot prove a narrower selection")
        return plan
    for status, paths in changes:
        kind = status[:1]
        if kind not in "AMDRCT" or not paths:
            plan.escalate(f"unrecognised change status {status!r}")
            plan.reasons.append((" ".join(paths), "full", f"unrecognised status {status}"))
            continue
        for path in paths:
            _classify_path(plan, kind, path, tests_dir)
    if plan.changed_tests and not plan.full:
        try:
            dependents = test_dependents(plan.changed_tests, tests_dir)
        except (OSError, SyntaxError, ValueError) as exc:
            plan.escalate(f"cannot resolve test-module fixture imports: {exc}")
            return plan
        for module in sorted(dependents - plan.changed_tests):
            plan.reasons.append((f"tests/{module}.py", "targeted", "imports a changed test module's fixtures"))
        plan.browser = plan.browser or BROWSER_TEST_MODULE in dependents
        plan.tests.update(dependents - {BROWSER_TEST_MODULE})
    return plan


def test_dependents(changed: set[str], tests_dir: str) -> set[str]:
    """Changed test modules plus every test module that (transitively) imports them.

    Several suites import fixtures from other test modules, so editing one must
    also run the modules built on it. Computed from the AST, so it cannot drift.
    """
    local = {name[:-3] for name in os.listdir(tests_dir) if name.endswith(".py")}
    importers: dict[str, set[str]] = {}
    for name in local:
        with open(os.path.join(tests_dir, name + ".py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                targets = {node.module.split(".")[0]}
            elif isinstance(node, ast.Import):
                targets = {alias.name.split(".")[0] for alias in node.names}
            else:
                continue
            for target in targets & local:
                importers.setdefault(target, set()).add(name)
    result, pending = set(changed), list(changed)
    while pending:
        for importer in importers.get(pending.pop(), ()):
            if importer not in result:
                result.add(importer)
                pending.append(importer)
    return {name for name in result if name.startswith("test_")}


def _classify_path(plan: Plan, kind: str, path: str, tests_dir: str) -> None:
    module = _test_module(path)
    if module is not None and (kind == "D" or not os.path.isfile(os.path.join(tests_dir, module + ".py"))):
        # A deleted or renamed-away test module cannot be run and reduces coverage.
        plan.escalate(f"{path}: test module removed or renamed")
        plan.reasons.append((path, "full", "test module removed or renamed"))
        return
    suite = match_rule(path)
    if module is not None:
        plan.changed_tests.add(module)
    if suite is None and module is not None:
        plan.tests.add(module)
        plan.reasons.append((path, "targeted", "changed test module"))
        return
    if suite is None:
        plan.escalate(f"{path}: unclassified file")
        plan.reasons.append((path, "full", "unclassified file (fail closed)"))
        return
    if suite.full:
        plan.escalate(f"{path}: {suite.reason}")
        plan.reasons.append((path, "full", suite.reason))
        return
    if suite.docs_only:
        plan.reasons.append((path, "docs", suite.reason))
        return
    plan.tests.update(suite.tests)
    plan.browser = plan.browser or suite.browser
    label = suite.reason + (" + Chromium" if suite.browser else "")
    plan.reasons.append((path, "targeted", label))


def _test_module(path: str) -> str | None:
    head, _, name = path.rpartition("/")
    if head == "tests" and name.startswith("test_") and name.endswith(".py"):
        return name[:-3]
    return None


def parse_name_status(text: str) -> list[tuple[str, list[str]]]:
    changes = []
    for line in text.splitlines():
        if not line.strip():
            continue
        status, *paths = line.split("\t")
        changes.append((status, paths))
    return changes


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def changed_files(base: str, head: str) -> tuple[str, list[tuple[str, list[str]]]]:
    merge_base = git("merge-base", base, head).strip()
    if not merge_base:
        raise RuntimeError("git merge-base returned no commit")
    diff = git("diff", "--no-color", "--name-status", "-M", merge_base, head)
    return merge_base, parse_name_status(diff)


def render_summary(plan: Plan, *, context: dict[str, str]) -> str:
    out = plan.outputs()
    lines = ["## UPT CI plan", ""]
    for key in ("event", "mode_reason", "base_ref", "head_sha", "tested_sha", "merge_base"):
        if context.get(key):
            lines.append(f"- **{key.replace('_', ' ')}**: `{context[key]}`")
    lines.append(f"- **selected mode**: `{out['mode']}` (full validation {'required' if plan.full else 'not selected'})")
    lines.append(f"- **Python versions**: {', '.join(json.loads(out['python_versions'])) if out['run_unit'] == 'true' else 'none'}")
    lines.append(f"- **Chromium suite**: {'run' if out['run_browser'] == 'true' else 'skipped (no browser-facing change)'}")
    if plan.full:
        lines.append("- **Python test modules**: complete suite (`unittest discover`)")
    elif plan.tests:
        lines.append(f"- **Python test modules** ({len(plan.tests)}): " + ", ".join(f"`{t}`" for t in sorted(plan.tests)))
    else:
        lines.append("- **Python test modules**: skipped (documentation-only change)")
    if plan.escalations:
        lines += ["", "### Full-validation escalations", ""]
        lines += [f"- {e}" for e in plan.escalations[:50]]
    if plan.reasons:
        lines += ["", "### Changed files", "", "| File | Outcome | Reason |", "|---|---|---|"]
        for path, outcome, reason in plan.reasons[:200]:
            lines.append(f"| `{path}` | {outcome} | {reason} |")
        if len(plan.reasons) > 200:
            lines.append(f"| … | | {len(plan.reasons) - 200} more |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="PR base commit")
    parser.add_argument("--head", help="PR head commit")
    parser.add_argument("--force-full", metavar="REASON", help="require full validation regardless of changes")
    parser.add_argument("--tested-sha", default="", help="commit actually checked out for tests")
    parser.add_argument("--event", default="")
    parser.add_argument("--base-ref", default="", help="PR base branch name (display only)")
    args = parser.parse_args(argv)

    context = {"event": args.event, "base_ref": args.base_ref,
               "head_sha": args.head or "", "tested_sha": args.tested_sha}
    plan = Plan()
    try:
        if args.base and args.head:
            context["merge_base"], changes = changed_files(args.base, args.head)
            plan = classify(changes)
        elif not args.force_full:
            raise RuntimeError("--base and --head are required unless --force-full is given")
    except Exception as exc:  # Any selector failure must fail closed.
        plan = Plan()
        plan.escalate(f"selector could not classify changes: {exc}")
    if args.force_full:
        plan.escalate(args.force_full)
        context["mode_reason"] = args.force_full

    outputs = plan.outputs()
    summary = render_summary(plan, context=context)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            for key, value in outputs.items():
                fh.write(f"{key}={value}\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(summary)
    json.dump(outputs, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
