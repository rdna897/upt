"""Regression tests for the plan job's checkout on persistent runners.

A private runner reuses its workspace between jobs. The merge-gate job uses a sparse
checkout, which makes actions/checkout fetch with ``--filter=blob:none`` and leaves the
workspace a blobless partial clone. A later plan job then fetches without a filter, but
Git keeps applying the configured one, so blobs that only the *base* side of the PR diff
needs are never downloaded. ``persist-credentials: false`` has already removed the token
when ``git diff --check`` runs, so the lazy fetch fails with
``could not fetch <blob> from promisor remote``.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))


def checkout_steps(job):
    return [step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")]


class PlanCheckoutWorkflowTests(unittest.TestCase):
    def test_plan_checks_out_into_a_dedicated_complete_directory(self):
        plan = WORKFLOW["jobs"]["plan"]
        (checkout,) = checkout_steps(plan)
        options = checkout["with"]
        path = options["path"]
        self.assertTrue(path and not Path(path).is_absolute() and ".." not in Path(path).parts)
        self.assertNotEqual(path, ".")
        self.assertEqual(options["fetch-depth"], 0)
        self.assertEqual(plan["defaults"]["run"]["working-directory"], path)
        for forbidden in ("filter", "sparse-checkout", "token", "ref", "repository"):
            self.assertNotIn(forbidden, options)

    def test_plan_run_steps_use_the_dedicated_directory(self):
        plan = WORKFLOW["jobs"]["plan"]
        for step in plan["steps"]:
            if "run" in step:
                self.assertNotIn("working-directory", step, step.get("name"))
        names = [step.get("name") for step in plan["steps"] if "run" in step]
        self.assertIn("Lightweight change validation", names)
        diff_step = next(step for step in plan["steps"] if step.get("name") == "Lightweight change validation")
        self.assertIn('git diff --check "$(git merge-base "$BASE_SHA" "$HEAD_SHA")" "$HEAD_SHA"', diff_step["run"])

    def test_every_checkout_still_withholds_credentials_and_only_merge_gate_is_sparse(self):
        for name, job in WORKFLOW["jobs"].items():
            for checkout in checkout_steps(job):
                self.assertIs(checkout["with"]["persist-credentials"], False, name)
                if name != "merge-gate":
                    self.assertNotIn("sparse-checkout", checkout["with"], name)
                    self.assertNotIn("filter", checkout["with"], name)


@unittest.skipUnless(shutil.which("git"), "git is required")
class PartialCloneMechanismTests(unittest.TestCase):
    """Reproduce the failing workspace state locally and show the dedicated checkout avoids it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="upt-checkout-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        home = self.base / "home"
        home.mkdir()
        self.env = {"PATH": os.environ["PATH"], "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        self.origin = self.base / "origin.git"
        self.url = self.origin.as_uri()
        work = self.base / "seed"
        self.git("init", "-q", "-b", "main", str(work))
        (work / "scripts" / "ci").mkdir(parents=True)
        (work / "scripts" / "ci" / "gate.py").write_text("print('gate')\n", encoding="utf-8")
        (work / "docs").mkdir()
        self.commit(work, "docs/page.md", "base version of the document\n", "old")
        self.commit(work, "docs/page.md", "base version of the document\n", "base")
        self.base_sha = self.git("rev-parse", "HEAD", cwd=work).stdout.strip()
        self.commit(work, "docs/page.md", "head version of the document\n", "head")
        self.head_sha = self.git("rev-parse", "HEAD", cwd=work).stdout.strip()
        self.git("clone", "-q", "--bare", str(work), str(self.origin))
        self.git("config", "uploadpack.allowFilter", "true", cwd=self.origin)
        self.git("config", "uploadpack.allowAnySHA1InWant", "true", cwd=self.origin)

    def git(self, *args, cwd=None, check=True):
        result = subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True, text=True, check=False)
        if check and result.returncode:
            self.fail(f"git {args[0]} failed: {result.stderr.strip()[:300]}")
        return result

    def commit(self, work, name, text, message):
        (work / name).write_text(text + message + "\n", encoding="utf-8")
        self.git("add", "-A", cwd=work)
        self.git("commit", "-q", "-m", message, cwd=work)

    def merge_gate_style_checkout(self, workspace):
        """What actions/checkout leaves behind for a sparse job: shallow, blob:none, promisor."""
        self.git("init", "-q", str(workspace))
        self.git("remote", "add", "origin", self.url, cwd=workspace)
        old = self.git("rev-parse", "main~2", cwd=self.origin).stdout.strip()
        self.git("fetch", "-q", "--no-tags", "--filter=blob:none", "--depth=1", "origin",
                 f"+{old}:refs/remotes/pull/1/merge", cwd=workspace)
        self.git("sparse-checkout", "set", "--cone", "scripts/ci", cwd=workspace)
        self.git("checkout", "-q", "--force", "refs/remotes/pull/1/merge", cwd=workspace)

    def plan_style_fetch_and_checkout(self, workspace):
        """The plan job's fetch (no filter) and checkout; credentials are never persisted."""
        self.git("sparse-checkout", "disable", cwd=workspace, check=False)
        shallow = (workspace / ".git" / "shallow").exists()
        self.git("fetch", "-q", "--prune", *(["--unshallow"] if shallow else []), "origin",
                 "+refs/heads/*:refs/remotes/origin/*", cwd=workspace)
        self.git("checkout", "-q", "--force", self.head_sha, cwd=workspace)

    def diff_check_offline(self, workspace):
        """`git diff --check` as the workflow runs it, with the remote unreachable (no credentials)."""
        hidden = self.origin.with_name("origin.hidden")
        self.origin.rename(hidden)
        try:
            return self.git("diff", "--check", self.git("merge-base", self.base_sha, self.head_sha, cwd=workspace).stdout.strip(),
                            self.head_sha, cwd=workspace, check=False)
        finally:
            hidden.rename(self.origin)

    def test_reused_blobless_workspace_cannot_diff_the_base_side_offline(self):
        workspace = self.base / "reused"
        self.merge_gate_style_checkout(workspace)
        self.assertEqual(self.git("config", "remote.origin.promisor", cwd=workspace).stdout.strip(), "true")
        self.assertEqual(self.git("config", "remote.origin.partialclonefilter", cwd=workspace).stdout.strip(), "blob:none")
        self.plan_style_fetch_and_checkout(workspace)  # an unfiltered fetch does not repair it
        self.assertEqual(self.git("config", "remote.origin.partialclonefilter", cwd=workspace).stdout.strip(), "blob:none")
        result = self.diff_check_offline(workspace)
        self.assertEqual(result.returncode, 128)
        self.assertIn("from promisor remote", result.stderr)

    def test_dedicated_directory_under_the_same_contaminated_workspace_diffs_offline(self):
        workspace = self.base / "reused"
        self.merge_gate_style_checkout(workspace)
        dedicated = workspace / "plan-checkout"
        self.git("init", "-q", str(dedicated))
        self.git("remote", "add", "origin", self.url, cwd=dedicated)
        self.plan_style_fetch_and_checkout(dedicated)
        self.assertEqual(self.git("config", "--get", "remote.origin.promisor", cwd=dedicated, check=False).returncode, 1)
        result = self.diff_check_offline(dedicated)
        self.assertEqual((result.returncode, result.stderr), (0, ""))

    def test_the_next_jobs_clean_removes_the_dedicated_directory(self):
        workspace = self.base / "reused"
        self.merge_gate_style_checkout(workspace)
        dedicated = workspace / "plan-checkout"
        self.git("init", "-q", str(dedicated))
        self.git("clean", "-ffdx", cwd=workspace)  # actions/checkout runs this on a reused workspace
        self.assertFalse(dedicated.exists())


if __name__ == "__main__":
    unittest.main()
