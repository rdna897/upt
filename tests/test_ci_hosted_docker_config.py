"""Tests for the fail-closed hosted Docker client-config sanitiser and its workflow wiring."""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import contextlib
import errno
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "sanitise_hosted_docker_config.py"
SPEC = importlib.util.spec_from_file_location("sanitise_hosted_docker_config", SCRIPT)
sanitiser = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sanitiser  # dataclass-free, but keeps tracebacks and pickling sane
SPEC.loader.exec_module(sanitiser)

SENTINEL = "sentinel-secret-7c1e5a"
HOSTED_ENV = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
EXPECTED = {"auths": {"https://index.docker.io/v1/": {"auth": SENTINEL}}}


class SanitiserTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="upt-hosted-docker-")
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.docker = self.home / ".docker"
        self.config = self.docker / "config.json"

    def write(self, data, raw=None):
        self.docker.mkdir(exist_ok=True)
        if raw is None:
            raw = json.dumps(data)
        self.config.write_bytes(raw if isinstance(raw, bytes) else raw.encode("utf-8"))

    def run_main(self, env=None):
        merged = dict(HOSTED_ENV, HOME=str(self.home), **(env or {}))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sanitiser.main(merged)
        return code, out.getvalue() + err.getvalue()

    def assertRefused(self, reason_fragment=None, env=None):
        code, output = self.run_main(env)
        self.assertEqual(code, 1)
        self.assertIn("refused", output)
        if reason_fragment:
            self.assertIn(reason_fragment, output)
        self.assertRedacted(output)
        return output

    def assertRedacted(self, output):
        for forbidden in (SENTINEL, str(self.home), "config.json", ".docker", "index.docker.io",
                          "example.invalid", "Traceback", "errno", "Errno"):
            self.assertNotIn(forbidden, output)

    def failing(self, target, name, **kwargs):
        error = OSError(errno.EACCES, f"{SENTINEL} {self.home}/.docker/config.json", str(self.config))
        return mock.patch.object(target, name, side_effect=error, **kwargs)

    # --- accepted shape -------------------------------------------------------------------

    def test_expected_hosted_shape_is_removed_and_nothing_is_printed(self):
        self.write(EXPECTED)
        code, output = self.run_main()
        self.assertEqual((code, output), (0, "Hosted Docker client config removed.\n"))
        self.assertFalse(self.config.exists())
        self.assertTrue(self.docker.is_dir())

    def test_absent_docker_directory_is_a_no_op(self):
        self.assertEqual(self.run_main(), (0, "Hosted Docker client config absent.\n"))
        self.assertFalse(self.docker.exists())

    # --- environment ----------------------------------------------------------------------

    def test_refuses_outside_github_hosted_environment(self):
        self.write(EXPECTED)
        for env in ({"RUNNER_ENVIRONMENT": "self-hosted"}, {"RUNNER_ENVIRONMENT": ""}, {"GITHUB_ACTIONS": ""}):
            with self.subTest(env=env):
                self.assertRefused(env=env)
                self.assertTrue(self.config.exists())

    def test_refuses_docker_connection_overrides(self):
        self.write(EXPECTED)
        for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG"):
            with self.subTest(name=name):
                self.assertRefused("overrides forbidden", env={name: SENTINEL})
                self.assertTrue(self.config.exists())

    def test_refuses_missing_or_relative_home_without_touching_the_working_directory(self):
        previous = os.getcwd()
        self.addCleanup(os.chdir, previous)
        os.chdir(self.home)
        self.write(EXPECTED)  # a relative ".docker" would resolve here
        for home in ("", ".", "relative/path"):
            with self.subTest(home=home):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = sanitiser.main(dict(HOSTED_ENV, HOME=home))
                self.assertEqual(code, 1)
                self.assertTrue(self.config.exists())
        env = dict(HOSTED_ENV)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(sanitiser.main(env), 1)

    # --- exact structure ------------------------------------------------------------------

    def test_refuses_every_structure_other_than_the_exact_hosted_shape(self):
        hub = "https://index.docker.io/v1/"
        cases = {
            "empty object": {},
            "missing auths": {"credsStore": "desktop"},
            "empty auths": {"auths": {}},
            "empty registry entry": {"auths": {hub: {}}},
            "missing auth field": {"auths": {hub: {"email": SENTINEL}}},
            "empty auth string": {"auths": {hub: {"auth": ""}}},
            "null auth": {"auths": {hub: {"auth": None}}},
            "non-string auth": {"auths": {hub: {"auth": [SENTINEL]}}},
            "numeric auth": {"auths": {hub: {"auth": 7}}},
            "credential store": {**EXPECTED, "credsStore": "desktop"},
            "credential helpers": {**EXPECTED, "credHelpers": {"example.invalid": "helper"}},
            "current context": {**EXPECTED, "currentContext": "remote"},
            "http headers": {**EXPECTED, "HttpHeaders": {"X-Token": SENTINEL}},
            "extra top-level key": {**EXPECTED, "other": 1},
            "unexpected registry only": {"auths": {f"{SENTINEL}.example.invalid": {"auth": SENTINEL}}},
            "extra registry": {"auths": {hub: {"auth": SENTINEL}, "ghcr.example.invalid": {"auth": SENTINEL}}},
            "identity token field": {"auths": {hub: {"auth": SENTINEL, "identitytoken": SENTINEL}}},
            "extra entry field": {"auths": {hub: {"auth": SENTINEL, "email": "x"}}},
            "non-mapping entry": {"auths": {hub: SENTINEL}},
            "auths not a mapping": {"auths": [SENTINEL]},
            "not an object": [SENTINEL],
            "scalar": SENTINEL,
            "null": None,
        }
        for name, payload in cases.items():
            with self.subTest(case=name):
                self.write(payload)
                self.assertRefused("expected hosted-image structure" if name not in ("null", "scalar") else None)
                self.assertTrue(self.config.exists(), "refusal must leave the file for the smoke check")

    def test_refuses_invalid_encoded_duplicate_and_deeply_nested_json(self):
        hub = "https://index.docker.io/v1/"
        raws = {
            "invalid json": "{ not json " + SENTINEL,
            "empty file": "",
            "not utf-8": b'{"auths": {"\xff\xfe": {"auth": "x"}}}',
            "duplicate key": '{"auths": {"%s": {"auth": "a"}}, "auths": {"%s": {"auth": "b"}}}' % (hub, hub),
            "duplicate entry key": '{"auths": {"%s": {"auth": "a", "auth": "b"}}}' % hub,
            "deeply nested": "[" * 30000 + "]" * 30000,
        }
        for name, raw in raws.items():
            with self.subTest(case=name):
                self.write(None, raw=raw)
                self.assertRefused("unreadable")
                self.assertTrue(self.config.exists())

    def test_refuses_oversized_config_without_reading_it_all(self):
        padding = "x" * (sanitiser.MAX_CONFIG_BYTES + 1)
        self.write(None, raw=json.dumps({"auths": {"https://index.docker.io/v1/": {"auth": padding}}}))
        self.assertRefused("large")
        self.assertTrue(self.config.exists())
        with mock.patch.object(sanitiser.os, "fstat", wraps=os.fstat) as fstat:
            fstat.side_effect = lambda fd: type("S", (), {"st_mode": stat.S_IFREG | 0o600, "st_size": 1})()
            self.assertRefused("large")  # the bounded read, not st_size, enforces the cap
        self.assertTrue(self.config.exists())

    # --- filesystem shape -----------------------------------------------------------------

    def test_refuses_symlinked_and_non_regular_config(self):
        self.write(EXPECTED)
        self.config.unlink()
        target = self.home / "target.json"
        target.write_text(json.dumps(EXPECTED), encoding="utf-8")
        os.symlink(target, self.config)
        self.assertRefused("regular file")
        self.assertTrue(target.exists() and os.path.islink(self.config))
        self.config.unlink()
        os.symlink(self.home / "missing-target", self.config)  # dangling
        self.assertRefused("regular file")
        self.config.unlink()
        os.mkfifo(self.config)
        self.assertRefused("regular file")
        self.assertTrue(stat.S_ISFIFO(os.lstat(self.config).st_mode))
        self.config.unlink()
        self.config.mkdir()
        self.assertRefused("regular file")

    def test_refuses_extra_files_contexts_and_empty_directory(self):
        self.write(EXPECTED)
        (self.docker / "contexts").mkdir()
        self.assertRefused("unexpected contents")
        (self.docker / "contexts").rmdir()
        (self.docker / "extra").write_text(SENTINEL, encoding="utf-8")
        self.assertRefused("unexpected contents")
        self.assertTrue(self.config.exists())
        (self.docker / "extra").unlink()
        self.config.unlink()
        self.assertRefused("unexpected contents")  # empty directory is not the hosted shape

    def test_refuses_symlinked_and_non_directory_docker_path(self):
        real = self.home / "real-docker"
        real.mkdir()
        (real / "config.json").write_text(json.dumps(EXPECTED), encoding="utf-8")
        os.symlink(real, self.docker)
        self.assertRefused("unexpected")
        self.assertTrue((real / "config.json").exists())
        self.docker.unlink()
        os.symlink(self.home / "missing-dir", self.docker)  # dangling
        self.assertRefused("unexpected")
        self.docker.unlink()
        self.docker.write_text(SENTINEL, encoding="utf-8")
        self.assertRefused("unexpected")
        self.assertEqual(self.docker.read_text(encoding="utf-8"), SENTINEL)

    # --- filesystem failures --------------------------------------------------------------

    def test_filesystem_failures_are_refused_with_fixed_redacted_messages_and_leave_the_file(self):
        cases = (
            ("open directory", sanitiser.os, "open", "inaccessible"),
            ("list directory", sanitiser.os, "listdir", "could not be listed"),
            ("inspect file", sanitiser.os, "fstat", "could not be read"),
            ("read file", sanitiser.os, "read", "could not be read"),
            ("unlink file", sanitiser.os, "unlink", "could not be removed"),
        )
        for label, target, name, fragment in cases:
            with self.subTest(operation=label):
                self.write(EXPECTED)
                with self.failing(target, name):
                    self.assertRefused(fragment)
                self.assertTrue(self.config.exists(), "validation or removal failure must not delete the file")

    def test_failure_opening_the_config_and_rechecking_the_name_is_refused(self):
        self.write(EXPECTED)
        real_open = os.open

        def open_config_fails(path, flags, *args, **kwargs):
            if path == "config.json":
                raise OSError(errno.EIO, f"{SENTINEL} {self.home}", str(self.config))
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(sanitiser.os, "open", side_effect=open_config_fails):
            self.assertRefused("regular file")
        self.assertTrue(self.config.exists())
        real_stat = os.stat

        def recheck_fails(path, *args, **kwargs):
            if path == "config.json":
                raise OSError(errno.EIO, f"{SENTINEL} {self.home}", str(self.config))
            return real_stat(path, *args, **kwargs)

        with mock.patch.object(sanitiser.os, "stat", side_effect=recheck_fails):
            self.assertRefused("could not be removed")
        self.assertTrue(self.config.exists())

    def test_unlink_that_does_not_remove_the_file_is_refused(self):
        self.write(EXPECTED)
        with mock.patch.object(sanitiser.os, "unlink"):
            self.assertRefused("could not be removed")
        self.assertTrue(self.config.exists())

    def test_unexpected_exceptions_fail_closed_without_a_traceback(self):
        self.write(EXPECTED)
        with mock.patch.object(sanitiser, "_validate", side_effect=RuntimeError(f"{SENTINEL} {self.home}")):
            output = self.assertRefused("unexpected error")
        self.assertTrue(self.config.exists())
        self.assertNotIn(SENTINEL, output)

    def test_file_replaced_after_validation_is_not_removed(self):
        self.write(EXPECTED)
        validate = sanitiser._validate

        def validate_then_swap(raw):
            validate(raw)
            self.config.unlink()  # the validated inode stays open, so it cannot be reused
            self.write({"auths": {"https://index.docker.io/v1/": {"auth": "other"}}, "credsStore": "x"})

        with mock.patch.object(sanitiser, "_validate", side_effect=validate_then_swap):
            self.assertRefused("changed during validation")
        self.assertTrue(self.config.exists(), "the replacement file must be left for the smoke check")
        self.assertIn("credsStore", self.config.read_text(encoding="utf-8"))

    def test_subprocess_refusal_has_no_traceback_and_no_values(self):
        self.write({**EXPECTED, "credsStore": SENTINEL})
        result = subprocess.run(
            [sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True, timeout=30, check=False,
            env={**HOSTED_ENV, "HOME": str(self.home), "PATH": os.environ.get("PATH", "")})
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.count("\n"), 1)
        self.assertRedacted(result.stderr)
        self.assertTrue(self.config.exists())
        self.config.write_text(json.dumps(EXPECTED), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True, timeout=30, check=False,
            env={**HOSTED_ENV, "HOME": str(self.home), "PATH": os.environ.get("PATH", "")})
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "Hosted Docker client config removed.\n", ""))
        self.assertFalse(self.config.exists())


class WorkflowWiringTests(unittest.TestCase):
    TEXT = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")

    def test_every_smoke_check_is_preceded_by_the_hosted_only_sanitiser(self):
        import yaml
        workflow = yaml.safe_load(self.TEXT)
        smoke_steps = 0
        for name, job in workflow["jobs"].items():
            steps = job["steps"]
            for index, step in enumerate(steps):
                if "scripts/ci/runner_smoke.py" in step.get("run", ""):
                    smoke_steps += 1
                    previous = steps[index - 1]
                    self.assertEqual(previous.get("run"), "python3 scripts/ci/sanitise_hosted_docker_config.py", name)
                    self.assertEqual(previous.get("if"), "runner.environment == 'github-hosted'", name)
                    self.assertNotIn("continue-on-error", previous, name)
                    self.assertNotIn("env", previous, name)
        self.assertEqual(smoke_steps, 5)
        self.assertEqual(self.TEXT.count("sanitise_hosted_docker_config.py"), 5)

    def test_sanitiser_is_the_only_runner_environment_conditional_step_and_has_no_shell_fallback(self):
        self.assertEqual(len(re.findall(r"if: runner\.environment == 'github-hosted'", self.TEXT)), 5)
        self.assertNotRegex(self.TEXT, r"sanitise_hosted_docker_config\.py\s*(\|\||;|&&)")
        self.assertNotIn("rm -f -- \"$HOME/.docker", self.TEXT)

    def test_script_file_is_not_world_writable(self):
        path = ROOT / "scripts" / "ci" / "sanitise_hosted_docker_config.py"
        self.assertEqual(path.stat().st_mode & stat.S_IWOTH, 0)


if __name__ == "__main__":
    unittest.main()
