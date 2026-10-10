"""Fail-closed isolation for UPT's unittest suite.

``scripts/run_tests.py`` loads this module and calls :func:`install` before
unittest discovers or imports any test module. Every test module imports it as
its first statement; a plain ``import`` outside the runner raises, so tests
cannot run silently unguarded.

The guard enforces two things:

* No test may execute Docker. ``docker_update_manager.system.subprocess`` is
  replaced by a proxy, so every ``run``/``invoke``/``run_compose_progress``
  alias is covered at call time, and a ``docker`` shim on ``PATH`` covers child
  processes. Refusals are recorded in a ledger before the exception is raised,
  so product code that swallows the exception cannot turn a violation into a
  pass.
* No UPT worker may outlive the test (or class/module fixture) that started
  it. Threads are stamped with their owner when they start; violations are
  attributed to that owner, never to whichever test happens to be running. A
  surviving UPT worker fails its owner and stops the run.

Diagnostics contain only the owner ID, a safe thread label, the boundary and
allowlisted executable/operation constants -- never argv, paths, environment
or process output.
"""

import atexit
import contextlib
import itertools
import json
import os
import re
import shutil
import stat
import subprocess as _real_subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import unittest.suite

OWNER_ENV = "UPT_TEST_ISOLATION_OWNER"
JOIN_SECONDS = 5.0
SESSION_OWNER = "session"
SHIM_EXIT_CODE = 125

DOCKER_EXECUTABLES = {"docker": "docker", "docker-compose": "docker-compose"}
# Exact leading-token sequences after the executable; anything else is
# "unclassified". The emitted value is always the constant, never the input.
OPERATIONS = (
    ("buildx", "imagetools", "inspect"),
    ("image", "inspect"), ("image", "rm"), ("image", "tag"), ("system", "df"),
    ("compose", "config"), ("compose", "up"), ("compose", "ps"),
    ("ps",), ("inspect",), ("pull",),
)
THREAD_PREFIXES = (
    "upt-refresh", "upt-scan", "upt-finalize", "upt-runtime-health", "upt-project-refresh",
    "upt-rollback", "upt-update", "upt-compose",
)
_EXECUTABLE_LABELS = frozenset({"docker", "docker compose", "docker-compose"})
_OPERATION_LABELS = frozenset(" ".join(operation) for operation in OPERATIONS)
BOUNDARIES = {"run": "run", "invoke": "invoke", "run_compose_progress": "Popen"}


class BootstrapMissing(ImportError):
    """Raised when a test module is imported outside ``scripts/run_tests.py``."""


class UnexpectedDockerInvocation(Exception):
    """A test reached a real Docker executable.

    Deliberately not an ``OSError``: ``system.run`` would otherwise wrap it in a
    ``CommandError`` that carries the argv.
    """


class IsolationFailure(AssertionError):
    """An owner (test or fixture scope) violated isolation."""


def classify(argv):
    """Return (executable category, operation) as allowlisted constants, or None."""
    if not argv:
        return None
    category = docker_category(argv[0])
    if category is None:
        return None
    rest = tuple(str(token) for token in argv[1:])
    if category == "docker" and rest[:1] == ("compose",):
        category = "docker compose"
    operation = "unclassified"
    for candidate in OPERATIONS:
        if rest[:len(candidate)] == candidate:
            operation = " ".join(candidate)
            break
    return category, operation


def docker_category(program):
    try:
        name = os.fsdecode(program)
    except TypeError:
        return None
    names = {os.path.basename(name)}
    resolved = name if os.sep in name else shutil.which(name)
    if resolved:
        names.add(os.path.basename(os.path.realpath(resolved)))
    for candidate in names:
        if candidate in DOCKER_EXECUTABLES:
            return DOCKER_EXECUTABLES[candidate]
    return None


def thread_label(thread):
    if thread is threading.main_thread():
        return "main"
    name = thread.name or ""
    for prefix in THREAD_PREFIXES:
        if name == prefix or name.startswith(prefix + "-"):
            return prefix
    stamp = getattr(thread, "_upt_isolation_stamp", None)
    return "thread#" + str(stamp.ordinal if stamp else "?")


class _Stamp:
    __slots__ = ("state", "owner", "ordinal", "upt", "quarantined", "termination")

    def __init__(self, state, owner, ordinal, upt):
        self.state, self.owner, self.ordinal, self.upt = state, owner, ordinal, upt
        self.quarantined = False
        self.termination = "started"


class _State:
    """Ledger and ownership for one guarded run (or one self-test sandbox)."""

    def __init__(self, join_seconds=JOIN_SECONDS, ledger=None):
        self.lock = threading.RLock()
        self.join_seconds = join_seconds
        self.ledger = ledger
        self.ledger_offset = 0
        self.owners = [SESSION_OWNER]
        self.violations = []
        self.leaks = []
        self.reported = set()
        self.ordinals = itertools.count(1)
        self.session_result = None
        self.stopped = False
        self.threads = []
        self.owner_tokens = {}
        self.token_owners = {}

    def token(self, owner):
        with self.lock:
            if owner not in self.owner_tokens:
                token = "owner-" + str(len(self.owner_tokens) + 1)
                self.owner_tokens[owner] = token
                self.token_owners[token] = owner
            return self.owner_tokens[owner]

    @property
    def owner(self):
        return self.owners[-1]

    def push(self, owner):
        self.owners.append(owner)
        os.environ[OWNER_ENV] = self.token(owner)

    def pop(self):
        self.owners.pop()
        os.environ[OWNER_ENV] = self.token(self.owner)

    def record(self, owner, label, boundary, category, operation):
        with self.lock:
            entry = {"owner": owner, "thread": label, "boundary": boundary,
                     "executable": category, "operation": operation}
            self.violations.append(entry)
            return entry

    def drain_ledger(self):
        if not self.ledger or not os.path.exists(self.ledger):
            return
        with self.lock, open(self.ledger, "rb") as handle:
            handle.seek(self.ledger_offset)
            data = handle.read()
            complete = data.rfind(b"\n") + 1
            self.ledger_offset += complete
        for line in data[:complete].splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                entry = {}
            if not isinstance(entry, dict):
                entry = {}
            token = entry.get("owner")
            owner = self.token_owners.get(token, "unattributed") if isinstance(token, str) else "unattributed"
            executable = entry.get("executable")
            operation = entry.get("operation")
            self.record(owner,
                        "child-process", "child-process",
                        executable if isinstance(executable, str) and executable in _EXECUTABLE_LABELS else "docker",
                        operation if isinstance(operation, str) and operation in _OPERATION_LABELS else "unclassified")

    def owned_workers(self, owner):
        workers = []
        with self.lock:
            threads = list(self.threads)
        for thread in threads:
            stamp = getattr(thread, "_upt_isolation_stamp", None)
            if stamp and stamp.state is self and stamp.owner == owner:
                if not thread.is_alive():
                    stamp.termination = "terminated"
                elif stamp.upt:
                    workers.append(thread)
        return workers

    def verify(self, owner):
        """Join the owner's UPT workers (bounded) and return its new failures."""
        deadline = time.monotonic() + self.join_seconds
        workers = self.owned_workers(owner)
        while workers:
            for thread in workers:
                thread.join(max(0.0, deadline - time.monotonic()))
            # A finishing parent can spawn another worker during its join.
            workers = self.owned_workers(owner)
            if time.monotonic() >= deadline:
                break
        survivors = workers
        for thread in survivors:
            thread._upt_isolation_stamp.quarantined = True
            thread._upt_isolation_stamp.termination = "surviving"
        self.drain_ledger()
        lines = []
        with self.lock:
            for index, entry in enumerate(self.violations):
                if entry["owner"] == owner and index not in self.reported:
                    self.reported.add(index)
                    lines.append(describe(entry))
            for thread in survivors:
                leak = {"owner": owner, "thread": thread_label(thread)}
                self.leaks.append(leak)
                lines.append("UPT worker survived bounded teardown [test={owner}, thread={thread}]; "
                             "test run stopped".format(**leak))
        return lines, bool(survivors)

    def unreported(self):
        self.drain_ledger()
        with self.lock:
            pending = [(i, e) for i, e in enumerate(self.violations) if i not in self.reported]
            self.reported.update(i for i, _ in pending)
        return [describe(entry, late=True) for _, entry in pending]

    def stop(self, *results):
        self.stopped = True
        for result in results + (self.session_result,):
            if result is not None:
                result.stop()


def describe(entry, late=False):
    return ("UPT test isolation refused {kind}Docker invocation [test={owner}, thread={thread}, "
            "boundary={boundary}, executable={executable}, operation={operation}]").format(
        kind="a late " if late else "an unexpected ", **entry)


_STATE = None
_ORIGINALS = {}


def active_state():
    return _STATE


def installed():
    return _STATE is not None


def _calling_owner():
    thread = threading.current_thread()
    stamp = getattr(thread, "_upt_isolation_stamp", None)
    if stamp is not None:
        return stamp.state, stamp.owner, stamp
    # Low-level/pre-existing threads have no owning test. Never charge their
    # calls to whichever test is currently running on the main thread.
    owner = _STATE.owner if thread is threading.main_thread() else "unattributed"
    return _STATE, owner, stamp


def _boundary(default):
    frame = sys._getframe(3)
    while frame is not None:
        if frame.f_globals.get("__name__") == "docker_update_manager.system":
            return BOUNDARIES.get(frame.f_code.co_name, default)
        frame = frame.f_back
    return default


def _argv(args, kwargs):
    program = args[0] if args else kwargs.get("args")
    if isinstance(program, (str, bytes, os.PathLike)):
        argv = [program]
        if kwargs.get("shell") and isinstance(program, str):
            argv = program.split()
    else:
        argv = list(program or ())
    return argv


def _guard(boundary, args, kwargs):
    state, owner, stamp = _calling_owner()
    argv = _argv(args, kwargs)
    classified = classify(argv) or (kwargs.get("executable") and classify([kwargs["executable"]]))
    if stamp is not None and stamp.quarantined:
        classified = classified or ("other", "unclassified")
    if classified:
        entry = state.record(owner, thread_label(threading.current_thread()), _boundary(boundary), *classified)
        raise UnexpectedDockerInvocation(describe(entry))
    env = kwargs.get("env")
    kwargs["env"] = dict(os.environ if env is None else env, **{OWNER_ENV: state.token(owner)})


class _GuardedSubprocess(types.ModuleType):
    """``subprocess`` stand-in installed only into docker_update_manager.system."""

    def __init__(self):
        super().__init__("subprocess", _real_subprocess.__doc__)

    def __getattr__(self, name):
        return getattr(_real_subprocess, name)

    def run(self, *args, **kwargs):
        _guard("run", args, kwargs)
        return _real_subprocess.run(*args, **kwargs)

    def Popen(self, *args, **kwargs):  # noqa: N802 - mirrors subprocess.Popen
        _guard("Popen", args, kwargs)
        return _real_subprocess.Popen(*args, **kwargs)

    def call(self, *args, **kwargs):
        _guard("run", args, kwargs)
        return _real_subprocess.call(*args, **kwargs)

    def check_call(self, *args, **kwargs):
        _guard("run", args, kwargs)
        return _real_subprocess.check_call(*args, **kwargs)

    def check_output(self, *args, **kwargs):
        _guard("run", args, kwargs)
        return _real_subprocess.check_output(*args, **kwargs)


def _is_upt_thread(thread):
    if (thread.name or "").startswith("upt-"):
        return True
    target = getattr(thread, "_target", None)
    module = getattr(target, "__module__", None) or type(thread).__module__
    return str(module).startswith("docker_update_manager")


def _stamping_start(self):
    state = _STATE
    if state is not None and getattr(self, "_upt_isolation_stamp", None) is None:
        parent = getattr(threading.current_thread(), "_upt_isolation_stamp", None)
        if parent is not None:
            owner_state, owner = parent.state, parent.owner
        else:
            owner_state, owner, _ = _calling_owner()
        self._upt_isolation_stamp = _Stamp(owner_state, owner, next(owner_state.ordinals),
                                          _is_upt_thread(self) or bool(parent and parent.upt))
        with owner_state.lock:
            owner_state.threads.append(self)
    return _ORIGINALS["start"](self)


def _guarded_thread_exception(args):
    if isinstance(args.exc_value, UnexpectedDockerInvocation):
        # The normal hook prints source lines and full thread names, either of
        # which can contain a secret. The owner ledger supplies the failure.
        sys.stderr.write("UnexpectedDockerInvocation: " + str(args.exc_value) + "\n")
    else:
        _ORIGINALS["thread_exception"](args)


def _fail(lines):
    raise IsolationFailure("\n".join(lines))


def _guarded_suite_run(self, result, debug=False):
    """unittest's suite lifecycle, checking stop after each fixture transition.

    Stock unittest checks shouldStop only at the top of the loop, so a leak
    discovered in tearDownClass could otherwise still run the next test.
    """
    top_level = not getattr(result, "_testRunEntered", False)
    if top_level:
        result._testRunEntered = True
    try:
        for index, test in enumerate(self):
            if result.shouldStop:
                break
            if unittest.suite._isnotsuite(test):
                self._tearDownPreviousClass(test, result)
                if result.shouldStop:
                    break
                self._handleModuleFixture(test, result)
                if result.shouldStop:
                    break
                self._handleClassSetUp(test, result)
                result._previousTestClass = test.__class__
                if result.shouldStop:
                    break
                if (getattr(test.__class__, "_classSetupFailed", False)
                        or getattr(result, "_moduleSetUpFailed", False)):
                    continue
            if debug:
                test.debug()
            else:
                test(result)
            if self._cleanup:
                self._removeTestAtIndex(index)
    finally:
        if top_level:
            self._tearDownPreviousClass(None, result)
            self._handleModuleTearDown(result)
            result._testRunEntered = False
    return result


def _guarded_test_run(self, result=None):
    state = _STATE
    if state is None:
        return _ORIGINALS["test_run"](self, result)
    owner = self.id()
    outcome = {"checked": False, "leaked": False}

    def check():
        outcome["checked"] = True
        lines, leaked = state.verify(owner)
        outcome["leaked"] = leaked
        if lines:
            _fail(lines)

    # Registered first, so it runs after every fixture cleanup (LIFO), while
    # the test's own patches have already been stopped by those cleanups.
    self.addCleanup(check)
    state.push(owner)
    try:
        return _ORIGINALS["test_run"](self, result)
    finally:
        state.pop()
        if not outcome["checked"]:
            lines, leaked = state.verify(owner)
            outcome["leaked"] = leaked
            if lines and result is not None:
                try:
                    _fail(lines)
                except IsolationFailure:
                    result.addError(self, sys.exc_info())
        if outcome["leaked"]:
            state.stop(result)


def _verify_scope(owner, result):
    state = _STATE
    lines, leaked = state.verify(owner)
    if lines:
        try:
            _fail(lines)
        except IsolationFailure:
            result.addError(unittest.suite._ErrorHolder("upt-isolation ({})".format(owner)), sys.exc_info())
    if leaked:
        state.stop(result)


def _class_owner(cls):
    return "class:{}.{}".format(cls.__module__, cls.__qualname__)


def _handle_class_setup(self, test, result):
    if _STATE is None:
        return _ORIGINALS["class_setup"](self, test, result)
    _STATE.push(_class_owner(test.__class__))
    try:
        return _ORIGINALS["class_setup"](self, test, result)
    finally:
        _STATE.pop()
        if getattr(test.__class__, "_classSetupFailed", False):
            _verify_scope(_class_owner(test.__class__), result)


def _teardown_previous_class(self, test, result):
    previous = getattr(result, "_previousTestClass", None)
    current = test.__class__ if test is not None else None
    if _STATE is None or previous is None or previous == current:
        return _ORIGINALS["class_teardown"](self, test, result)
    owner = _class_owner(previous)
    _STATE.push(owner)
    try:
        return _ORIGINALS["class_teardown"](self, test, result)
    finally:
        _STATE.pop()
        _verify_scope(owner, result)


def _handle_module_fixture(self, test, result):
    if _STATE is None:
        return _ORIGINALS["module_fixture"](self, test, result)
    _STATE.push("module:" + test.__class__.__module__)
    try:
        return _ORIGINALS["module_fixture"](self, test, result)
    finally:
        _STATE.pop()
        if getattr(result, "_moduleSetUpFailed", False):
            _verify_scope("module:" + test.__class__.__module__, result)


def _handle_module_teardown(self, result):
    previous = self._get_previous_module(result)
    if _STATE is None or previous is None:
        return _ORIGINALS["module_teardown"](self, result)
    owner = "module:" + previous
    _STATE.push(owner)
    try:
        return _ORIGINALS["module_teardown"](self, result)
    finally:
        _STATE.pop()
        _verify_scope(owner, result)


def _write_shims(directory, ledger):
    guard = os.path.abspath(__file__)
    for name, category in DOCKER_EXECUTABLES.items():
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "#!{python} -I\n"
                "import importlib.util, sys\n"
                "spec = importlib.util.spec_from_file_location('_upt_isolation_shim', {guard!r})\n"
                "module = importlib.util.module_from_spec(spec)\n"
                "module._LOAD_MODE = 'shim'\n"
                "spec.loader.exec_module(module)\n"
                "sys.exit(module.shim_main({category!r}, {ledger!r}, sys.argv[1:]))\n".format(
                    python=sys.executable, guard=guard, category=category, ledger=ledger))
        os.chmod(path, stat.S_IRWXU)


def shim_main(category, ledger, args):
    """Entry point of the PATH shim: record a redacted entry and refuse."""
    owner = os.environ.get(OWNER_ENV, "")
    classified = classify([category, *args]) or (category, "unclassified")
    entry = {"owner": owner if re.fullmatch(r"owner-[0-9]{1,12}", owner) else "unattributed",
             "executable": classified[0], "operation": classified[1]}
    descriptor = os.open(ledger, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(descriptor, (json.dumps(entry) + "\n").encode())
    finally:
        os.close(descriptor)
    sys.stderr.write("docker execution is blocked by UPT test isolation\n")
    return SHIM_EXIT_CODE


def _make_shim_dir():
    directory = tempfile.mkdtemp(prefix="upt-test-isolation-")
    ledger = os.path.join(directory, "ledger.jsonl")
    _write_shims(directory, ledger)
    return directory, ledger


def install(join_seconds=JOIN_SECONDS):
    """Install every isolation layer. Called once by scripts/run_tests.py."""
    global _STATE
    if _STATE is not None:
        return _STATE
    import docker_update_manager.system as system

    directory, ledger = _make_shim_dir()
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    os.environ["PATH"] = directory + os.pathsep + os.environ.get("PATH", "")
    _STATE = _State(join_seconds=join_seconds, ledger=ledger)
    _STATE.shim_dir = directory
    os.environ[OWNER_ENV] = _STATE.token(SESSION_OWNER)
    system.subprocess = _GuardedSubprocess()
    suite = unittest.suite.TestSuite
    _ORIGINALS.update(start=threading.Thread.start, test_run=unittest.TestCase.run,
                      suite_run=suite.run,
                      thread_exception=threading.excepthook,
                      class_setup=suite._handleClassSetUp, class_teardown=suite._tearDownPreviousClass,
                      module_fixture=suite._handleModuleFixture, module_teardown=suite._handleModuleTearDown)
    threading.Thread.start = _stamping_start
    threading.excepthook = _guarded_thread_exception
    unittest.TestCase.run = _guarded_test_run
    suite.run = _guarded_suite_run
    suite._handleClassSetUp = _handle_class_setup
    suite._tearDownPreviousClass = _teardown_previous_class
    suite._handleModuleFixture = _handle_module_fixture
    suite._handleModuleTearDown = _handle_module_teardown
    return _STATE


def guard_active():
    """True when every in-process layer is in place."""
    if _STATE is None:
        return False
    system = sys.modules.get("docker_update_manager.system")
    return (isinstance(getattr(system, "subprocess", None), _GuardedSubprocess)
            and threading.Thread.start is _stamping_start
            and threading.excepthook is _guarded_thread_exception
            and unittest.TestCase.run is _guarded_test_run
            and unittest.TestSuite.run is _guarded_suite_run
            and unittest.TestSuite._handleClassSetUp is _handle_class_setup
            and unittest.TestSuite._tearDownPreviousClass is _teardown_previous_class
            and unittest.TestSuite._handleModuleFixture is _handle_module_fixture
            and unittest.TestSuite._handleModuleTearDown is _handle_module_teardown)


@contextlib.contextmanager
def sandbox(join_seconds=0.0, shim=False):
    """Run guard self-tests against a private ledger and owner stack.

    Threads stamped inside the sandbox stay accountable to it; the caller must
    release and join them before the sandbox exits, or the outer test fails.
    """
    global _STATE
    outer, outer_env, outer_path = _STATE, os.environ.get(OWNER_ENV), os.environ.get("PATH", "")
    directory = None
    ledger = None
    if shim:
        directory, ledger = _make_shim_dir()
        os.environ["PATH"] = directory + os.pathsep + outer_path
    inner = _State(join_seconds=join_seconds, ledger=ledger)
    inner.shim_dir = directory
    _STATE = inner
    try:
        yield inner
    finally:
        _STATE = outer
        os.environ["PATH"] = outer_path
        if outer_env is None:
            os.environ.pop(OWNER_ENV, None)
        else:
            os.environ[OWNER_ENV] = outer_env
        if directory:
            shutil.rmtree(directory, ignore_errors=True)
        survivors = [t for t in threading.enumerate()
                     if getattr(getattr(t, "_upt_isolation_stamp", None), "state", None) is inner
                     and t._upt_isolation_stamp.upt and t.is_alive()]
        for thread in survivors:
            thread.join(JOIN_SECONDS)
        survivors = [thread for thread in survivors if thread.is_alive()]
        if survivors:
            for thread in survivors:
                thread._upt_isolation_stamp.quarantined = True
                thread._upt_isolation_stamp.termination = "surviving"
                if outer is not None:
                    outer.leaks.append({"owner": outer.owner, "thread": thread_label(thread)})
            if outer is not None:
                outer.stop()
            raise IsolationFailure("guard self-test left a sandbox UPT worker running")


class GuardedTextTestResult(unittest.TextTestResult):
    """Reports session-level isolation failures and refuses a green run after any."""

    def _exc_info_to_string(self, err, test):
        if isinstance(err[1], (IsolationFailure, UnexpectedDockerInvocation)):
            return "{}: {}\n".format(type(err[1]).__name__, err[1])
        return super()._exc_info_to_string(err, test)

    def startTestRun(self):
        if _STATE is not None:
            _STATE.session_result = self
            _verify_scope(SESSION_OWNER, self)
            _verify_scope("unattributed", self)
        super().startTestRun()

    def stopTestRun(self):
        if _STATE is not None:
            lines, leaked = _STATE.verify(SESSION_OWNER)
            unattributed, unowned_leak = _STATE.verify("unattributed")
            lines += unattributed
            leaked = leaked or unowned_leak
            lines += _STATE.unreported()
            if lines:
                try:
                    _fail(lines)
                except IsolationFailure:
                    self.addError(unittest.suite._ErrorHolder("upt-isolation (session)"), sys.exc_info())
            if leaked:
                _STATE.stopped = True
            if _STATE.stopped:
                self.stream.writeln("UPT test isolation stopped the run after a surviving UPT worker.")
        super().stopTestRun()

    def wasSuccessful(self):
        return super().wasSuccessful() and not (_STATE is not None and (_STATE.stopped or _STATE.leaks))


class GuardedTextTestRunner(unittest.TextTestRunner):
    resultclass = GuardedTextTestResult


if globals().get("_LOAD_MODE") not in ("runner", "shim"):
    try:
        install()
    except ImportError:
        pass
    raise BootstrapMissing(
        "UPT tests must run through scripts/run_tests.py, which installs Docker and worker isolation "
        "before discovery (for example: python scripts/run_tests.py discover -s tests).")
