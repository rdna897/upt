"""Regression tests for risk-aware CI selection and the fail-closed merge gate."""

import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import ast
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SRC = ROOT / "src" / "docker_update_manager"


def _load(name):
    path = ROOT / "scripts" / "ci" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"upt_ci_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(module)
    return module


select = _load("select_tests")
gate = _load("merge_gate")
verify = _load("verify_merge_ready")
runner_smoke = _load("runner_smoke")


def plan_for(*lines):
    return select.classify(select.parse_name_status("\n".join(lines)), tests_dir=str(TESTS))


def direct_test_importers(module):
    """Test modules that import or patch ``docker_update_manager.<module>`` directly."""
    importers = set()
    for path in TESTS.glob("test_*.py"):
        text = path.read_text(encoding="utf-8")
        names = set(re.findall(r"docker_update_manager\.(\w+)", text))
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.ImportFrom) and node.module == "docker_update_manager":
                names.update(alias.name for alias in node.names)
        if module in names:
            importers.add(path.stem)
    return importers


class DependencyMapIntegrityTests(unittest.TestCase):
    def test_every_source_file_is_explicitly_classified(self):
        for path in sorted(SRC.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                rel = path.relative_to(ROOT).as_posix()
                self.assertIsNotNone(select.match_rule(rel), f"{rel} is not in the CI dependency map")

    def test_every_mapped_test_module_exists(self):
        for pattern, suite in select.RULES:
            for name in suite.tests:
                self.assertTrue((TESTS / f"{name}.py").is_file(), f"{pattern} maps to missing {name}")

    def test_narrow_source_rules_select_every_direct_test_importer(self):
        # Grounds the hand-written map in real imports: a test that imports a
        # narrowly mapped module must run when that module changes. Chromium is
        # governed by the explicit browser flag instead.
        for path in sorted(SRC.glob("*.py")):
            suite = select.match_rule(path.relative_to(ROOT).as_posix())
            if suite.full:
                continue
            expected = direct_test_importers(path.stem) - {select.BROWSER_TEST_MODULE}
            missing = expected - set(suite.tests)
            self.assertFalse(missing, f"{path.name} rule misses direct importers {sorted(missing)}")

    def test_files_read_by_tests_are_never_documentation_only(self):
        corpus = "\n".join(p.read_text(encoding="utf-8") for p in TESTS.glob("*.py")
                            if p.name != Path(__file__).name)
        for path in sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").rglob("*.md")):
            rel = path.relative_to(ROOT).as_posix()
            suite = select.match_rule(rel)
            if suite is not None and suite.docs_only:
                self.assertFalse(rel in corpus, f"{rel} is read by tests but classified docs-only")
                if "/" not in rel:
                    self.assertNotRegex(corpus, rf"[\"'/]{re.escape(rel)}[\"']",
                                        f"{rel} is read by tests but classified docs-only")


class SelectionScenarioTests(unittest.TestCase):
    def assertFull(self, plan, fragment):
        self.assertEqual(plan.mode, "full")
        out = plan.outputs()
        self.assertEqual((out["full"], out["run_unit"], out["run_browser"]), ("true", "true", "true"))
        self.assertEqual(json.loads(out["python_versions"]), ["3.10", "3.13"])
        self.assertEqual(out["test_modules"], "")
        self.assertTrue(any(fragment in e for e in plan.escalations), plan.escalations)

    def test_documentation_only_skips_python_and_browser(self):
        plan = plan_for("M\tdocs/agent-efficiency.md", "A\tdocs/screenshots/x/new.png", "M\tAGENTS.md")
        out = plan.outputs()
        self.assertEqual(out["mode"], "docs")
        self.assertEqual((out["run_unit"], out["run_browser"]), ("false", "false"))

    def test_docs_read_by_tests_run_those_tests(self):
        self.assertEqual(plan_for("M\tREADME.md").tests, {"test_web_closure_http", "test_web_closure_ui_deploy"})
        self.assertEqual(plan_for("M\tdocs/deployment.md").tests, {"test_web_closure_http", "test_web_closure_ui_deploy"})
        self.assertEqual(plan_for("M\tdocs/versioning.md").tests, {"test_version_contract"})

    def test_template_change_runs_web_tests_and_chromium_on_313_only(self):
        plan = plan_for("M\tsrc/docker_update_manager/templates/base.html")
        out = plan.outputs()
        self.assertEqual(out["mode"], "targeted")
        self.assertEqual(out["run_browser"], "true")
        self.assertEqual(json.loads(out["python_versions"]), ["3.13"])
        self.assertIn("test_web_closure_http", plan.tests)

    def test_registry_change_runs_registry_and_verification_without_chromium(self):
        plan = plan_for("M\tsrc/docker_update_manager/registry.py")
        self.assertEqual(plan.mode, "targeted")
        self.assertFalse(plan.browser)
        self.assertTrue({"test_core", "test_service_verification"} <= plan.tests)

    def test_scan_worker_change_runs_scan_refresh_reconciliation_verification(self):
        plan = plan_for("M\tsrc/docker_update_manager/scan_worker.py")
        self.assertTrue({"test_service_verification", "test_web_closure_scan",
                         "test_post_mutation_reconciliation"} <= plan.tests)

    def test_compose_change_runs_compose_reconciliation_and_operation_tests(self):
        plan = plan_for("M\tsrc/docker_update_manager/compose_reconcile.py")
        self.assertEqual(plan.mode, "targeted")
        self.assertTrue({"test_compose_reconciliation", "test_compose_apply",
                         "test_same_project_baseline_reconciliation", "test_web_operations"} <= plan.tests)

    def test_cli_change_runs_cli_and_packaging_tests(self):
        plan = plan_for("M\tsrc/docker_update_manager/cli.py")
        self.assertTrue({"test_core", "test_version_contract"} <= plan.tests)
        self.assertFalse(plan.browser)

    def test_security_state_and_orchestration_changes_escalate(self):
        for path in ("auth.py", "webstate.py", "state.py", "lock.py", "agent.py",
                     "webservice.py", "operations.py", "reconciliation.py", "retention.py"):
            with self.subTest(path=path):
                self.assertFull(plan_for(f"M\tsrc/docker_update_manager/{path}"), path)

    def test_privileged_installation_and_deployment_files_escalate(self):
        for path in ("install.sh", "systemd/upt-agent.service.example", "systemd/upt-web.service.example",
                     "systemd/upt-agent.compose-writes.conf.example", "systemd/upt-web.sysusers.example",
                     "config/web.example.yml", "config/config.example.yml"):
            with self.subTest(path=path):
                self.assertFull(plan_for(f"M\t{path}"), path)
        # Escalation wins even alongside an otherwise docs-only change.
        self.assertFull(plan_for("M\tdocs/roadmap.md", "A\tsystemd/new.conf"), "systemd")

    def test_dependency_ci_and_test_infrastructure_changes_escalate(self):
        for path in ("pyproject.toml", "requirements.txt", ".github/workflows/tests.yml",
                     "scripts/ci/select_tests.py", "scripts/ci/verify_merge_ready.py",
                     "tests/test_ci_selection.py",
                     "tests/progress_assertions.py", "tests/fixtures/production_schema8_state.py"):
            with self.subTest(path=path):
                self.assertFull(plan_for(f"M\t{path}"), path)

    def test_unknown_files_fail_closed(self):
        self.assertFull(plan_for("A\tnew_top_level.cfg"), "unclassified")
        self.assertFull(plan_for("A\tsrc/docker_update_manager/brand_new.py"), "unclassified")
        self.assertFull(plan_for("A\ttests/helper_without_rule.py"), "unclassified")

    def test_renames_classify_both_sides(self):
        self.assertFull(plan_for("R100\tsrc/docker_update_manager/registry.py\tsrc/docker_update_manager/registry2.py"),
                        "unclassified")
        self.assertFull(plan_for("R090\ttests/test_core.py\ttests/test_core_moved.py"), "renamed")
        moved = plan_for("R100\tdocs/old.md\tdocs/new.md")
        self.assertEqual(moved.mode, "docs")

    def test_deleted_test_module_escalates(self):
        self.assertFull(plan_for("D\ttests/test_conversion.py"), "removed")
        self.assertFull(plan_for("D\ttests/test_web_browser.py"), "removed")

    def test_changed_test_module_runs_itself_and_fixture_importers(self):
        self.assertEqual(plan_for("M\ttests/test_conversion.py").tests, {"test_conversion"})
        # test_compose_namespace_apply imports test_compose_namespace_update,
        # which imports test_compose_namespace.
        self.assertEqual(plan_for("M\ttests/test_compose_namespace.py").tests,
                         {"test_compose_namespace", "test_compose_namespace_update",
                          "test_compose_namespace_apply", "test_same_project_baseline_reconciliation"})
        # test_compose_reconciliation imports the browser fixture agent.
        browser = plan_for("M\ttests/test_web_browser.py")
        self.assertTrue(browser.browser)
        self.assertTrue({"test_compose_reconciliation", "test_compose_apply"} <= browser.tests)
        self.assertNotIn("test_web_browser", browser.tests)
        self.assertTrue(plan_for("M\ttests/test_web_runtime.py").tests >= {"test_web_redesign"})

    def test_mixed_change_unions_and_any_full_rule_wins(self):
        mixed = plan_for("M\tdocs/roadmap.md", "M\tsrc/docker_update_manager/registry.py",
                         "M\tsrc/docker_update_manager/static/app.css")
        self.assertEqual(mixed.mode, "targeted")
        self.assertTrue(mixed.browser)
        self.assertFull(plan_for("M\tsrc/docker_update_manager/registry.py",
                                 "M\tsrc/docker_update_manager/models.py"), "models.py")

    def test_empty_or_unrecognised_diff_escalates(self):
        self.assertFull(select.classify([]), "no changed files")
        self.assertFull(plan_for("X\tsomething"), "unrecognised")
        self.assertFull(plan_for("U\tsrc/docker_update_manager/cli.py"), "unrecognised")


class SelectorCommandTests(unittest.TestCase):
    def run_main(self, *argv):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            env = {"GITHUB_OUTPUT": str(output), "GITHUB_STEP_SUMMARY": str(Path(tmp) / "summary")}
            with patch.dict(os.environ, env), redirect_stdout(io.StringIO()):
                self.assertEqual(select.main(list(argv)), 0)
            pairs = dict(line.split("=", 1) for line in output.read_text().splitlines())
            return pairs, (Path(tmp) / "summary").read_text()

    def test_git_failure_fails_closed_to_full(self):
        def broken(*_args):
            raise RuntimeError("bad object")
        with patch.object(select, "git", broken):
            out, summary = self.run_main("--base", "deadbeef", "--head", "HEAD")
        self.assertEqual((out["mode"], out["full"]), ("full", "true"))
        self.assertIn("selector could not classify changes", summary)

    def test_missing_refs_without_force_fails_closed(self):
        out, _ = self.run_main("--event", "pull_request")
        self.assertEqual(out["full"], "true")

    def test_force_full_overrides_narrow_diff_and_reports_selection(self):
        with patch.object(select, "changed_files",
                          lambda base, head: ("abc123", [("M", ["docs/roadmap.md"])])):
            out, summary = self.run_main("--base", "b", "--head", "h", "--tested-sha", "m1",
                                         "--force-full", "pull request is ready for review")
        self.assertEqual(out["mode"], "full")
        self.assertIn("ready for review", summary)
        self.assertIn("`m1`", summary)
        self.assertIn("docs/roadmap.md", summary)


class MergeGateTests(unittest.TestCase):
    ALL_OK = {job: "success" for job in gate.REQUIRED_JOBS}
    FULL = '["3.10", "3.13"]'

    def decide(self, results=None, plan_full="true", versions=FULL, event="pull_request", draft=False):
        return gate.decide(results=results or dict(self.ALL_OK), plan_full=plan_full,
                           python_versions=versions, event=event, draft=draft)[0]

    def test_passes_only_when_complete_suite_succeeded(self):
        self.assertTrue(self.decide())
        self.assertTrue(self.decide(event="push"))
        self.assertTrue(self.decide(event="schedule"))

    def test_draft_targeted_run_never_passes(self):
        results = dict(self.ALL_OK, **{"browser-tests": "skipped"})
        self.assertFalse(self.decide(results, plan_full="false", versions='["3.13"]', draft=True))
        self.assertFalse(self.decide(plan_full="false", versions='["3.13"]', draft=True))

    def test_skipped_cancelled_failed_or_missing_jobs_fail(self):
        for job in gate.REQUIRED_JOBS:
            for result in ("skipped", "cancelled", "failure", ""):
                with self.subTest(job=job, result=result):
                    self.assertFalse(self.decide(dict(self.ALL_OK, **{job: result})))
        missing = dict(self.ALL_OK)
        del missing["browser-tests"]
        self.assertFalse(self.decide(missing))

    def test_ready_pr_with_non_full_plan_fails(self):
        self.assertFalse(self.decide(plan_full="false"))
        self.assertFalse(self.decide(plan_full=""))

    def test_incomplete_python_matrix_fails(self):
        for versions in ('["3.13"]', "", "not json", '["3.10"]'):
            with self.subTest(versions=versions):
                self.assertFalse(self.decide(versions=versions))

    def test_timing_table_reports_queue_and_execution(self):
        rows = gate.timing_table([{"name": "plan", "conclusion": "success", "runner_name": "r1",
                                   "created_at": "2026-01-01T00:00:00Z",
                                   "started_at": "2026-01-01T00:01:05Z",
                                   "completed_at": "2026-01-01T00:01:35Z"}])
        self.assertIn("| plan | success | 1m 05s | 0m 30s | r1 |", rows)


class WorkflowInvariantTests(unittest.TestCase):
    TEXT = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")

    def test_runner_labels_and_screenshot_isolation_preserved(self):
        self.assertEqual(self.TEXT.count("runs-on: >-"), 5)
        self.assertEqual(self.TEXT.count("|| '[\"ubuntu-24.04\"]'"), 5)
        self.assertIn("UPT_SCREENSHOT_DIR: ${{ runner.temp }}/upt-browser-screenshots-", self.TEXT)
        self.assertEqual(self.TEXT.count("python3 scripts/ci/runner_smoke.py --require-test-bootstrap"), 3)
        self.assertIn("playwright install --with-deps chromium", self.TEXT)
        self.assertIn(".venv/bin/python scripts/run_tests.py discover -s tests -v", self.TEXT)
        self.assertIn('PYTHONPATH=tests .venv/bin/python scripts/run_tests.py -v "${modules[@]}"', self.TEXT)
        self.assertIn(".venv/bin/python scripts/run_tests.py discover -s tests -p 'test_web_browser.py' -v", self.TEXT)
        self.assertNotIn("-m unittest", self.TEXT)
        self.assertNotIn("runner_args", self.TEXT)

    def test_actions_are_pinned_and_checkout_does_not_persist_credentials(self):
        import yaml
        workflow = yaml.safe_load(self.TEXT)
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"@[0-9a-f]{40}$")
                    if step["uses"].startswith("actions/checkout@"):
                        self.assertIs(step["with"]["persist-credentials"], False)
        self.assertNotIn("pull_request_target", workflow.get("on", workflow.get(True)))

    def test_merge_gate_always_runs_and_cancellation_is_pr_scoped(self):
        gate_block = self.TEXT.split("  merge-gate:", 1)[1]
        self.assertIn("needs: [runner-smoke, plan, unit-tests, browser-tests]", gate_block)
        # always() keeps the gate running after failed/cancelled/skipped needs;
        # event-specific behaviour is evaluated in WorkflowEventConditionTests.
        self.assertIn("if: ${{ always() && !(", gate_block)
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' && !(", self.TEXT)
        self.assertIn("format('run-{0}', github.run_id)", self.TEXT)

    def test_permissions_stay_minimal(self):
        self.assertNotRegex(self.TEXT, r":\s*write\b")
        self.assertEqual(re.findall(r"^\s+(\w+): (read|write)\b", self.TEXT, re.M),
                         [("contents", "read"), ("contents", "read"), ("actions", "read")])



    def test_evidence_records_head_and_integration_base_without_environment_contents(self):
        env = {"PLAN_MODE": "full", "GITHUB_EVENT_NAME": "pull_request", "PR_HEAD_SHA": "h1",
               "PR_BASE_REF": "main", "PR_BASE_SHA": "b1", "GITHUB_SHA": "m1", "GITHUB_TOKEN": "ghs_secret"}
        ev = gate.evidence(env, passed=True)
        self.assertEqual(ev, {"passed": True, "mode": "full", "event": "pull_request", "head_sha": "h1",
                              "base_ref": "main", "base_sha": "b1", "tested_sha": "m1"})
        self.assertNotIn("ghs_secret", json.dumps(ev))
        self.assertEqual(gate.EVIDENCE_MARKER, verify.EVIDENCE_MARKER)


def gh_expr(expression, ctx, variables=None):
    """Evaluate the GitHub expression subset used by tests.yml against ``ctx``.

    Supports property access (missing -> None), ==, !, &&, || (value-returning,
    like GitHub), parentheses, string literals, format() and always().
    """
    py = re.sub(r"!(?!=)", " not ", expression).replace("&&", " and ").replace("||", " or ")

    class Ctx(dict):
        def __getattr__(self, name):
            value = self.get(name)
            return Ctx(value or {}) if value is None or isinstance(value, dict) else value

    def fmt(template, *args):
        return template.format(*args)

    return eval(py, {"__builtins__": {}}, {"github": Ctx(ctx), "vars": Ctx(variables or {}),
                "true": True, "false": False, "fromJSON": json.loads,
                "format": fmt, "always": lambda: True})


class RunnerRoutingTests(unittest.TestCase):
    def test_all_events_route_from_repository_metadata_and_match_smoke(self):
        import yaml
        workflow = yaml.safe_load(WorkflowInvariantTests.TEXT)
        for event_name in ("push", "schedule", "workflow_dispatch", "pull_request"):
            for private in (True, False):
                for hosted in ("", "true"):
                    for fork in (True, False):
                        for draft in (True, False):
                            ctx = {"repository": "owner/repo", "event_name": event_name,
                                   "event": {"repository": {"private": private},
                                             "pull_request": {"draft": draft, "head": {"repo": {
                                                 "full_name": "fork/repo" if fork else "owner/repo"}}}}}
                            expected_private = private and hosted != "true" and (event_name != "pull_request" or not fork)
                            expected = ["self-hosted", "linux", "x64", "upt-ci"] if expected_private else ["ubuntu-24.04"]
                            with self.subTest(event=event_name, private=private, hosted=hosted, fork=fork, draft=draft):
                                for job in workflow["jobs"].values():
                                    expr = job["runs-on"].strip()[3:-2]
                                    self.assertEqual(gh_expr(expr, ctx, {"UPT_CI_HOSTED": hosted}), expected)
                                env = {"GITHUB_EVENT_NAME": event_name, "GITHUB_REPOSITORY": "owner/repo", "UPT_CI_HOSTED": hosted}
                                self.assertEqual(runner_smoke.expected_environment(ctx["event"], env),
                                                 "self-hosted" if expected_private else "github-hosted")

    def test_missing_visibility_never_selects_private_runners(self):
        import yaml
        workflow = yaml.safe_load(WorkflowInvariantTests.TEXT)
        for event in ({}, {"repository": {}}, {"repository": {"private": "true"}}):
            for job in workflow["jobs"].values():
                self.assertEqual(gh_expr(job["runs-on"].strip()[3:-2],
                                        {"event": event, "event_name": "push"}), ["ubuntu-24.04"])


class RunnerSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.event = {"repository": {"private": False}}
        self.env = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "owner/repo",
                    "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "HOME": str(self.root)}
        self.release = "ID=ubuntu\nVERSION_ID=\"24.04\"\n"
        self.patchers = [patch.object(runner_smoke.platform, "machine", return_value="x86_64"),
                         patch.object(runner_smoke.shutil, "which", side_effect=lambda name: None if name.startswith("docker") else "/usr/bin/tool"),
                         patch.object(Path, "read_text", side_effect=lambda *a, **k: self.release),
                         patch.object(Path, "is_socket", return_value=False)]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def check(self, require=True):
        return runner_smoke.verify(self.event, self.env, require_test_bootstrap=require, root=self.root)

    def add_bootstrap(self):
        for name in ("scripts/run_tests.py", "tests/_upt_isolation.py"):
            path = self.root / name
            path.parent.mkdir(exist_ok=True)
            path.write_text("raise AssertionError('bootstrap must not be imported by smoke')")

    def test_hosted_missing_bootstrap_refuses_before_import_or_execution(self):
        with self.assertRaisesRegex(ValueError, "approved isolation bootstrap"):
            self.check()
        self.add_bootstrap()
        self.assertEqual(self.check(), "github-hosted")
        (self.root / "tests/_upt_isolation.py").unlink()
        with self.assertRaisesRegex(ValueError, "approved isolation bootstrap"):
            self.check()

    def test_infrastructure_only_check_does_not_require_test_bootstrap(self):
        self.assertEqual(self.check(require=False), "github-hosted")

    def test_public_job_cannot_accept_private_worker_or_unsupported_image(self):
        self.env["RUNNER_ENVIRONMENT"] = "self-hosted"
        with self.assertRaisesRegex(ValueError, "environment mismatch"):
            self.check(False)
        self.env["RUNNER_ENVIRONMENT"] = "github-hosted"
        self.release = "ID=debian\nVERSION_ID=13\n"
        with self.assertRaisesRegex(ValueError, "unsupported runner image"):
            self.check(False)
        self.release = "ID=ubuntu\nVERSION_ID=22.04\n"
        with self.assertRaisesRegex(ValueError, "unsupported runner image"):
            self.check(False)

    def test_private_debian_requires_bootstrap_and_no_docker_socket_or_executable(self):
        self.event["repository"]["private"] = True
        self.env["RUNNER_ENVIRONMENT"] = "self-hosted"
        self.release = "ID=debian\nVERSION_ID=13\n"
        with self.assertRaisesRegex(ValueError, "approved isolation bootstrap"):
            self.check()
        self.add_bootstrap()
        self.assertEqual(self.check(), "self-hosted")
        (self.root / "scripts/run_tests.py").unlink()
        with self.assertRaisesRegex(ValueError, "approved isolation bootstrap"):
            self.check()
        self.add_bootstrap()
        with patch.object(Path, "is_socket", return_value=True):
            with self.assertRaisesRegex(ValueError, "Docker socket forbidden"):
                self.check()
        with patch.object(runner_smoke.shutil, "which", return_value="/usr/bin/tool"):
            with self.assertRaisesRegex(ValueError, "Docker executables forbidden"):
                self.check()

    def test_connection_overrides_and_credentials_are_rejected_without_values(self):
        sentinel = "private-infrastructure-sentinel"
        for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"):
            with self.subTest(name=name):
                self.env[name] = sentinel
                with self.assertRaisesRegex(ValueError, "connection overrides forbidden") as error:
                    self.check(False)
                self.assertNotIn(sentinel, str(error.exception))
                del self.env[name]
        (self.root / ".docker").mkdir()
        (self.root / ".docker/config.json").write_text(sentinel)
        with self.assertRaisesRegex(ValueError, "credentials or contexts forbidden") as error:
            self.check(False)
        self.assertNotIn(sentinel, str(error.exception))

    def test_missing_tools_or_unsupported_architecture_fail(self):
        with patch.object(runner_smoke.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "tool missing"):
                self.check(False)
        self.env["RUNNER_ARCH"] = "ARM64"
        with self.assertRaisesRegex(ValueError, "architecture"):
            self.check(False)


class WorkflowEventConditionTests(unittest.TestCase):
    WORKFLOW = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")

    def scenario(self, event_name, action=None, changes=None, number=43, run_id=999):
        event = {"pull_request": {"number": number, "draft": True}} if event_name == "pull_request" else {}
        if action:
            event["action"] = action
        if changes is not None:
            event["changes"] = changes
        return {"event_name": event_name, "event": event, "workflow": "tests", "run_id": run_id}

    def evaluate(self, ctx):
        import yaml  # test dependency (see test_compose_namespace_apply)
        wf = yaml.safe_load(self.WORKFLOW)

        def ev(value):
            # Substitute each ${{ }} span; a whole-string expression keeps its type.
            parts = re.split(r"\$\{\{(.*?)\}\}", str(value), flags=re.S)
            if len(parts) == 3 and not parts[0].strip() and not parts[2].strip():
                return gh_expr(parts[1], ctx)
            return "".join(str(gh_expr(p, ctx)) if i % 2 else p for i, p in enumerate(parts))

        gate_job = wf["jobs"]["merge-gate"]
        return {"group": ev(wf["concurrency"]["group"]).strip(),
                "cancel": bool(ev(wf["concurrency"]["cancel-in-progress"])),
                "runs": bool(ev(wf["jobs"]["runner-smoke"]["if"])),
                "gate_runs": bool(ev(gate_job["if"])),
                "gate_name": ev(gate_job["name"])}

    def test_edited_is_a_subscribed_pull_request_type(self):
        self.assertRegex(self.WORKFLOW, r"types: \[[^\]]*\bedited\b[^\]]*\]")

    def test_title_or_body_edit_runs_nothing_cancels_nothing_and_never_names_merge_gate(self):
        for changes in ({"title": {"from": "old"}}, {"body": {"from": "old"}}, {}):
            with self.subTest(changes=changes):
                out = self.evaluate(self.scenario("pull_request", "edited", changes))
                self.assertFalse(out["runs"])
                self.assertFalse(out["gate_runs"])
                self.assertFalse(out["cancel"])
                self.assertEqual(out["group"], "tests-run-999")
                self.assertNotEqual(out["gate_name"], "merge-gate")
                self.assertTrue(out["gate_name"].startswith("merge-gate-skipped"))
        # GitHub displays a skipped job's templated name unevaluated; that raw
        # text must not be "merge-gate" either.
        import yaml
        raw = str(yaml.safe_load(self.WORKFLOW)["jobs"]["merge-gate"]["name"])
        self.assertNotEqual(raw.strip(), "merge-gate")

    def test_base_branch_edit_revalidates_in_the_pr_group(self):
        changes = {"base": {"ref": {"from": "old-base"}, "sha": {"from": "abc"}}}
        out = self.evaluate(self.scenario("pull_request", "edited", changes))
        self.assertEqual(out, {"group": "tests-pr-43", "cancel": True, "runs": True,
                               "gate_runs": True, "gate_name": "merge-gate"})

    def test_commits_and_state_changes_keep_pr_scoped_cancellation(self):
        for action in ("opened", "synchronize", "reopened", "ready_for_review", "converted_to_draft"):
            with self.subTest(action=action):
                out = self.evaluate(self.scenario("pull_request", action))
                self.assertEqual(out, {"group": "tests-pr-43", "cancel": True, "runs": True,
                                       "gate_runs": True, "gate_name": "merge-gate"})

    def test_main_nightly_and_manual_runs_are_never_cancelled(self):
        for event in ("push", "schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                out = self.evaluate(self.scenario(event))
                self.assertEqual(out, {"group": "tests-run-999", "cancel": False, "runs": True,
                                       "gate_runs": True, "gate_name": "merge-gate"})

    def test_plan_passes_new_base_and_ready_prs_force_full(self):
        plan = self.WORKFLOW.split("  plan:", 1)[1].split("  unit-tests:", 1)[0]
        self.assertIn("BASE_SHA: ${{ github.event.pull_request.base.sha }}", plan)
        self.assertIn('args+=(--base "$BASE_SHA" --head "$HEAD_SHA")', plan)
        self.assertIn('if [ "$DRAFT" != true ]; then', plan)
        gate_block = self.WORKFLOW.split("  merge-gate:", 1)[1]
        self.assertIn("PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}", gate_block)
        self.assertIn("PR_BASE_REF: ${{ github.event.pull_request.base.ref }}", gate_block)


class FakeGitHub:
    """Minimal stand-in for ``gh`` keyed by API path / run-view job id."""

    REPO = "o/r"
    HEAD = "h" * 40
    BASE = "b" * 40

    def __init__(self):
        self.pr = {"state": "open", "merged": False, "draft": False,
                   "head": {"sha": self.HEAD, "ref": "feature"}, "base": {"ref": "main", "sha": self.BASE}}
        self.base_tip = self.BASE
        self.runs = [self.make_run(100, "2026-10-08T10:00:00Z")]
        self.jobs = {100: self.full_jobs(100)}
        self.logs = {1006: self.log(passed=True)}
        self.files = ["src/docker_update_manager/registry.py"]
        self.calls = []

    def make_run(self, run_id, created, status="completed", conclusion="success", head=None):
        return {"id": run_id, "created_at": created, "status": status, "conclusion": conclusion,
                "head_sha": head or self.HEAD, "head_branch": "feature", "html_url": f"https://x/{run_id}"}

    @staticmethod
    def full_jobs(run_id, **overrides):
        jobs = []
        for i, name in enumerate(verify.REQUIRED_JOBS, start=1):
            jobs.append({"id": run_id * 10 + i, "name": name, "status": "completed",
                         "conclusion": overrides.get(name, "success")})
        return jobs

    def log(self, **changes):
        ev = {"passed": True, "mode": "full", "event": "pull_request", "head_sha": self.HEAD,
              "base_ref": "main", "base_sha": self.BASE, "tested_sha": "m" * 40}
        ev.update(changes)
        return f"merge-gate\tstep\t2026-10-08T10:10:00Z {verify.EVIDENCE_MARKER}{json.dumps(ev)}\n"

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "run":
            assert args[:2] == ["run", "view"] and args[3:6] == ["--repo", self.REPO, "--job"] \
                and args[7:] == ["--log"], args
            return self.logs.get(int(args[6]), "")
        assert args[0] == "api", args
        if args[1] == "--paginate":
            return "\n".join(self.files)
        path = args[1]
        if path == f"repos/{self.REPO}/pulls/43":
            return json.dumps(self.pr)
        if path == f"repos/{self.REPO}/git/ref/heads/{self.pr['base']['ref']}":
            return json.dumps({"object": {"sha": self.base_tip}})
        if path.startswith(f"repos/{self.REPO}/actions/workflows/tests.yml/runs?"):
            assert f"head_sha={self.pr['head']['sha']}" in path, path
            return json.dumps({"workflow_runs": self.runs})
        match = re.fullmatch(rf"repos/{self.REPO}/actions/runs/(\d+)/jobs\?filter=latest&per_page=100", path)
        if match:
            return json.dumps({"jobs": self.jobs[int(match.group(1))]})
        raise AssertionError(f"unexpected gh call {args}")


class VerifyMergeReadyTests(unittest.TestCase):
    def check(self, fake):
        with redirect_stdout(io.StringIO()) as out:
            code = verify.main(["43", "--repo", FakeGitHub.REPO], gh=fake)
        return code, out.getvalue()

    def assertNotReady(self, fake, fragment):
        code, out = self.check(fake)
        self.assertEqual(code, 1, out)
        self.assertIn("NOT READY", out)
        self.assertIn(fragment, out)

    def test_ready_when_latest_full_run_matches_current_head_and_base(self):
        fake = FakeGitHub()
        code, out = self.check(fake)
        self.assertEqual(code, 0, out)
        self.assertIn("READY", out)
        self.assertIn("not enforce", out)
        self.assertNotIn("WARNING", out)
        # Read-only: only GET-style "api" and "run view --log" calls.
        for call in fake.calls:
            self.assertNotIn("merge", " ".join(call[:2]))
            self.assertFalse({"-X", "--method", "-f", "-F", "--field", "--raw-field", "--input"} & set(call))

    def test_draft_closed_or_merged_pr_is_rejected(self):
        fake = FakeGitHub()
        fake.pr["draft"] = True
        self.assertNotReady(fake, "draft")
        fake = FakeGitHub()
        fake.pr["state"] = "closed"
        self.assertNotReady(fake, "not open")
        fake = FakeGitHub()
        fake.pr["merged"] = True
        self.assertNotReady(fake, "not open")

    def test_stale_evidence_from_an_earlier_head_is_rejected(self):
        fake = FakeGitHub()
        fake.runs = [fake.make_run(100, "2026-10-08T10:00:00Z", head="0" * 40)]
        self.assertNotReady(fake, "no 'tests.yml' pull_request run exists")
        fake = FakeGitHub()
        fake.logs[1006] = fake.log(head_sha="0" * 40)
        self.assertNotReady(fake, "head_sha")

    def test_base_changed_or_advanced_since_validation_is_rejected(self):
        fake = FakeGitHub()
        fake.pr["base"]["ref"] = "other-base"
        fake.base_tip = "c" * 40
        self.assertNotReady(fake, "base_ref")
        fake = FakeGitHub()
        fake.base_tip = "c" * 40  # same branch, new commits
        self.assertNotReady(fake, "base branch changed or advanced")

    def test_incomplete_later_run_blocks_even_with_earlier_success(self):
        for status in ("queued", "in_progress", "waiting"):
            with self.subTest(status=status):
                fake = FakeGitHub()
                fake.runs.insert(0, fake.make_run(101, "2026-10-08T11:00:00Z", status=status, conclusion=None))
                self.assertNotReady(fake, "still " + status)

    def test_later_failed_or_cancelled_run_invalidates_earlier_success(self):
        for conclusion in ("failure", "cancelled", "timed_out"):
            with self.subTest(conclusion=conclusion):
                fake = FakeGitHub()
                fake.runs.insert(0, fake.make_run(101, "2026-10-08T11:00:00Z", conclusion=conclusion))
                fake.jobs[101] = fake.full_jobs(101, **{"unit-tests (3.10)": "failure"})
                self.assertNotReady(fake, f"concluded {conclusion}")

    def test_later_targeted_draft_run_invalidates_earlier_full_success(self):
        fake = FakeGitHub()
        fake.runs.insert(0, fake.make_run(101, "2026-10-08T11:00:00Z", conclusion="failure"))
        fake.jobs[101] = fake.full_jobs(101, **{"browser-tests": "skipped", "merge-gate": "failure"})
        self.assertNotReady(fake, "concluded failure")

    def test_failed_skipped_missing_or_ambiguous_required_job_is_rejected(self):
        for job in verify.REQUIRED_JOBS:
            for conclusion in ("failure", "skipped", "cancelled"):
                with self.subTest(job=job, conclusion=conclusion):
                    fake = FakeGitHub()
                    fake.jobs[100] = fake.full_jobs(100, **{job: conclusion})
                    self.assertNotReady(fake, f"{job}: {conclusion}")
        fake = FakeGitHub()
        fake.jobs[100] = [j for j in fake.jobs[100] if j["name"] != "unit-tests (3.10)"]
        self.assertNotReady(fake, "unit-tests (3.10): missing")
        fake = FakeGitHub()
        fake.jobs[100].append(dict(fake.jobs[100][0], id=9999))
        self.assertNotReady(fake, "ambiguous")

    def test_gate_evidence_must_be_present_unique_full_and_passed(self):
        cases = [("", "0 evidence lines"),
                 (FakeGitHub().log() * 2, "2 evidence lines"),
                 (FakeGitHub().log(mode="targeted"), "mode"),
                 (FakeGitHub().log(passed=False), "passed"),
                 (FakeGitHub().log(event="push"), "event"),
                 (f"{verify.EVIDENCE_MARKER}{{not json", "not valid JSON")]
        for log, fragment in cases:
            with self.subTest(fragment=fragment):
                fake = FakeGitHub()
                fake.logs[1006] = log
                self.assertNotReady(fake, fragment)

    def test_metadata_edit_runs_are_ignored_but_never_count_as_evidence(self):
        fake = FakeGitHub()
        fake.runs.insert(0, fake.make_run(101, "2026-10-08T11:00:00Z", conclusion="success"))
        # As observed live: GitHub shows the skipped gate's raw name expression.
        fake.jobs[101] = [{"id": 1010 + i, "name": name, "conclusion": "skipped"} for i, name in enumerate(
            ("runner-smoke", "plan", "unit-tests", "browser-tests",
             "(github.event.action == 'edited' && !github.event.changes.base) && "
             "'merge-gate-skipped (PR metadata edit)' || 'merge-gate'"))]
        self.assertEqual(self.check(fake)[0], 0)
        fake.runs = fake.runs[:1]
        self.assertNotReady(fake, "only metadata-edit runs")

    def test_run_with_smoke_executed_is_never_treated_as_metadata_edit(self):
        fake = FakeGitHub()
        fake.runs.insert(0, fake.make_run(101, "2026-10-08T11:00:00Z", conclusion="failure"))
        fake.jobs[101] = [{"id": 1011, "name": "runner-smoke", "conclusion": "failure"},
                          {"id": 1012, "name": "plan", "conclusion": "skipped"},
                          {"id": 1013, "name": "merge-gate", "conclusion": "failure"}]
        self.assertNotReady(fake, "concluded failure")

    def test_gh_failure_or_malformed_response_fails_closed(self):
        def broken(args):
            raise verify.NotReady("gh api failed: HTTP 502")
        code, out = self.check(broken)
        self.assertEqual(code, 1)
        self.assertIn("HTTP 502", out)
        fake = FakeGitHub()
        fake.pr = {"state": "open", "merged": False, "draft": False}
        self.assertNotReady(fake, "unknown")

    def test_pr_changing_its_own_ci_is_flagged(self):
        fake = FakeGitHub()
        fake.files = [".github/workflows/tests.yml", "scripts/ci/merge_gate.py", "docs/ci.md"]
        code, out = self.check(fake)
        self.assertEqual(code, 0)
        self.assertIn("WARNING", out)
        self.assertIn(".github/workflows/tests.yml", out)

    def test_no_bypass_option_exists(self):
        with redirect_stdout(io.StringIO()), patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                verify.main(["43", "--force"], gh=FakeGitHub())


if __name__ == "__main__":
    unittest.main()
