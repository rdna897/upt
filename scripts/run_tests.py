#!/usr/bin/env python3
"""Guarded unittest entry point for UPT.

Accepts exactly the arguments of ``python -m unittest`` (``discover ...`` or
test names) and installs Docker and worker isolation before unittest imports
any test module. Every test module is statically checked first: its first
statement must be ``import _upt_isolation``, so no module-level code can run
before the guard, and the same import fails loudly when the runner is
bypassed. Run from the repository root, for example::

    python scripts/run_tests.py discover -s tests -v
    PYTHONPATH=tests python scripts/run_tests.py -v test_core

Screenshot harnesses that reuse test fixtures run under the same guard::

    PYTHONPATH=src:tests python scripts/run_tests.py --script tests/capture_web_ui_final.py
"""

import ast
import fnmatch
import importlib.machinery
import importlib.util
import os
import runpy
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD_PATH = os.path.join(REPO, "tests", "_upt_isolation.py")
GUARD_IMPORT = "_upt_isolation"
PREFLIGHT_EXIT = 2


def _emulate_module_invocation():
    """Give sys.path the shape ``python -m unittest`` would.

    Script mode puts this script's directory first; ``-m`` puts the current
    directory there instead. Under ``-P``/PYTHONSAFEPATH (3.11+), neither
    invocation adds an unsafe entry; explicit PYTHONPATH entries stay intact.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if getattr(sys.flags, "safe_path", False):
        return
    if sys.path and os.path.abspath(sys.path[0] or os.curdir) == script_dir:
        sys.path[0] = os.getcwd()


def preflight_source(source, name):
    """Return an error message when ``source`` may run code before the guard."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None  # unittest reports the import error itself; nothing has run.
    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        body = body[1:]
    first = body[0] if body else None
    if not (isinstance(first, ast.Import) and len(first.names) == 1
            and first.names[0].name == GUARD_IMPORT and first.names[0].asname is None):
        return f"{name}: the first statement must be 'import {GUARD_IMPORT}'"
    return None


def _check_file(path, name, errors):
    try:
        with open(path, encoding="utf-8") as handle:
            source = handle.read()
    except OSError:
        errors.append("test module could not be read for isolation preflight")
        return
    error = preflight_source(source, name)
    if error:
        errors.append(error)


def _discovery_files(start, pattern):
    original_start = start
    start = os.path.abspath(start)
    if os.path.isfile(start):
        return
    if not os.path.isdir(start):
        # unittest also accepts an importable package as the start directory.
        candidates = list(_named_files([original_start]))
        yield from candidates
        if candidates and os.path.basename(candidates[-1][0]) == "__init__.py":
            start = os.path.dirname(candidates[-1][0])
        else:
            return
    for directory, subdirs, files in os.walk(start):
        # unittest only descends into packages below the start directory.
        subdirs[:] = sorted(d for d in subdirs if os.path.isfile(os.path.join(directory, d, "__init__.py")))
        if "__init__.py" in files:
            yield os.path.join(directory, "__init__.py"), "test-package"
        for name in sorted(files):
            if name.endswith(".py") and fnmatch.fnmatch(name, pattern):
                yield os.path.join(directory, name), name[:-3]


def _named_files(names):
    for name in names:
        if name.endswith(".py") and os.path.isfile(name):
            yield name, os.path.basename(name)[:-3]
            name = os.path.relpath(name, os.getcwd())[:-3].replace(os.sep, ".")
        search_path = None
        parts = name.split(".")
        for index in range(len(parts)):
            module = ".".join(parts[:index + 1])
            # PathFinder does not import a parent package, unlike util.find_spec.
            spec = importlib.machinery.PathFinder.find_spec(module, search_path)
            if spec is None:
                break  # Remaining components may be a class/test method.
            if spec.origin and spec.origin.endswith(".py"):
                yield spec.origin, module
            search_path = spec.submodule_search_locations
            if search_path is None:
                break


class GuardedTestProgram(unittest.TestProgram):
    """unittest's own CLI with a static preflight before any test import."""

    def createTests(self, from_discovery=False, Loader=None):  # noqa: N802 - unittest API
        if from_discovery:
            files = _discovery_files(self.start, self.pattern)
        else:
            files = _named_files(self.testNames or ())
        errors = []
        # Imported repository test fixtures must also satisfy the bootstrap.
        for path, name in [*_discovery_files(os.path.join(REPO, "tests"), "test*.py"), *files]:
            _check_file(path, name, errors)
        if errors:
            sys.stderr.write("UPT test isolation preflight failed; no test module was imported:\n")
            for error in errors:
                sys.stderr.write(f"  {error}\n")
            sys.exit(PREFLIGHT_EXIT)
        super().createTests(from_discovery=from_discovery, Loader=Loader)


def load_guard():
    spec = importlib.util.spec_from_file_location(GUARD_IMPORT, GUARD_PATH)
    module = importlib.util.module_from_spec(spec)
    module._LOAD_MODE = "runner"
    sys.modules[GUARD_IMPORT] = module
    spec.loader.exec_module(module)
    return module


def run_script(args, guard):
    """Run one harness script as ``__main__`` with the guard already installed."""
    if not args or not os.path.isfile(args[0]):
        sys.stderr.write("usage: run_tests.py --script <path/to/script.py> [args...]\n")
        return PREFLIGHT_EXIT
    path = os.path.abspath(args[0])
    errors = []
    _check_file(path, os.path.basename(path)[:-3], errors)
    if errors:
        sys.stderr.write("UPT test isolation preflight failed; the script was not run:\n  " + errors[0] + "\n")
        return PREFLIGHT_EXIT
    sys.argv = [path, *args[1:]]
    sys.path.insert(0, os.path.dirname(path))
    class CaptureScript(unittest.TestCase):
        def id(self):
            return "capture-script"

        def runTest(self):
            try:
                runpy.run_path(path, run_name="__main__")
            except SystemExit as exc:
                if exc.code not in (None, 0):
                    raise

    result = guard.GuardedTextTestRunner().run(unittest.TestSuite([CaptureScript()]))
    return 0 if result.wasSuccessful() else 1


def main(argv=None):
    _emulate_module_invocation()
    guard = load_guard()
    try:
        guard.install()
    except ImportError as exc:
        sys.stderr.write(f"UPT test isolation could not be installed ({type(exc).__name__}); "
                         "is docker_update_manager importable (PYTHONPATH=src or an installed venv)?\n")
        return PREFLIGHT_EXIT
    if not guard.guard_active():
        sys.stderr.write("UPT test isolation is not active; refusing to run tests.\n")
        return PREFLIGHT_EXIT
    args = sys.argv[1:] if argv is None else list(argv)
    if args[:1] == ["--script"]:
        return run_script(args[1:], guard)
    GuardedTestProgram(module=None, argv=["python -m unittest", *args],
                       testRunner=guard.GuardedTextTestRunner)
    return 0  # unreachable: TestProgram exits


if __name__ == "__main__":
    sys.exit(main())
