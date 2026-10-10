"""Synthetic isolation regressions: never execute a real Docker binary."""
import _upt_isolation
import _thread
import contextlib
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

from docker_update_manager import system
# Captured before the self-test sandbox; the system global must still guard it.
from docker_update_manager.system import run as imported_run

isolation = _upt_isolation
ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / 'scripts/run_tests.py'
SECRET = 'isolation-sentinel-9fd846a'


class GuardTests(unittest.TestCase):
    def run_inner(self, tests):
        stream = io.StringIO()
        result = isolation.GuardedTextTestRunner(stream=stream, verbosity=2).run(unittest.TestSuite(tests))
        return result, stream.getvalue()

    def case(self, function, name='test_scenario'):
        return type('Scenario', (unittest.TestCase,), {name: function})(name)

    def worker(self, target, name='upt-refresh-private', **kwargs):
        thread = threading.Thread(target=target, name=name, daemon=True, **kwargs)
        self.assertIsNone(thread.start())
        return thread

    def test_guard_active_and_bootstrap_convention(self):
        self.assertTrue(isolation.guard_active())
        spec = importlib.util.spec_from_file_location('runner_source', RUNNER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for path in sorted((ROOT / 'tests').glob('test_*.py')):
            self.assertIsNone(module.preflight_source(path.read_text(), path.stem))

    def test_all_boundaries_aliases_absolute_paths_and_swallowed_refusals(self):
        for boundary in ('run', 'invoke', 'progress', 'alias'):
            with self.subTest(boundary=boundary), isolation.sandbox():
                def scenario(_):
                    for program in ('docker', '/untrusted/' + SECRET + '/docker', 'docker-compose'):
                        args = [program, 'login', '-p', SECRET]
                        try:
                            if boundary == 'invoke':
                                self.assertEqual(system.invoke(args, phase='test').category, 'unknown')
                            elif boundary == 'progress':
                                system.run_compose_progress(args, None, 'fixture')
                            else:
                                (imported_run if boundary == 'alias' else system.run)(args)
                        except isolation.UnexpectedDockerInvocation as exc:
                            self.assertNotIn(SECRET, str(exc))
                            self.assertFalse(hasattr(exc, 'args_run'))
                with patch.object(subprocess, 'Popen', side_effect=AssertionError('process spawned')):
                    result, output = self.run_inner([self.case(scenario)])
                self.assertFalse(result.wasSuccessful())
                self.assertNotIn(SECRET, output)
                self.assertIn('Docker invocation', output)
                self.assertEqual(len(isolation.active_state().violations), 3)

    def test_executable_override_and_symlink_cannot_bypass(self):
        with tempfile.TemporaryDirectory() as directory, isolation.sandbox():
            alias = Path(directory) / 'alias'
            alias.symlink_to('/untrusted/docker')
            def scenario(_):
                for args, kwargs in (([str(alias)], {}), (['harmless'], {'executable': '/untrusted/docker'})):
                    with self.assertRaises(isolation.UnexpectedDockerInvocation):
                        system.subprocess.run(args, **kwargs)
            result, _ = self.run_inner([self.case(scenario)])
            self.assertFalse(result.wasSuccessful())

    def test_aliases_captured_while_boundary_is_unpatched_are_guarded_later(self):
        with patch.object(system, 'subprocess', subprocess):
            run, invoke, progress = system.run, system.invoke, system.run_compose_progress
        with isolation.sandbox() as state:
            def scenario(_):
                for call in (lambda: run(['docker', 'ps']),
                             lambda: invoke(['docker', 'ps'], phase='test'),
                             lambda: progress(['docker', 'compose', 'up'], None, 'fixture')):
                    try: call()
                    except isolation.UnexpectedDockerInvocation: pass
            with patch.object(subprocess, 'Popen', side_effect=AssertionError('process spawned')):
                result, _ = self.run_inner([self.case(scenario)])
            self.assertFalse(result.wasSuccessful())
            self.assertEqual([item['boundary'] for item in state.violations], ['run', 'invoke', 'Popen'])

    def test_worker_created_during_parent_join_is_also_enforced(self):
        parent_gate, child_gate = threading.Event(), threading.Event()
        workers = []
        with isolation.sandbox(join_seconds=1):
            def parent():
                parent_gate.wait()
                workers.append(self.worker(child_gate.wait, name='generic-descendant'))
            def scenario(_):
                thread = self.worker(parent)
                workers.append(thread)
                original_join = thread.join
                def join(timeout):
                    parent_gate.set()
                    original_join(timeout)
                thread.join = join
            try:
                result, output = self.run_inner([self.case(scenario)])
                self.assertFalse(result.wasSuccessful())
                self.assertTrue(result.shouldStop)
                self.assertIn('survived bounded teardown', output)
                self.assertEqual(len(workers), 2)
                self.assertFalse(workers[0].is_alive())
            finally:
                parent_gate.set()
                child_gate.set()
                for thread in workers: thread.join(1)

    def test_non_docker_subprocess_outcomes_preserved(self):
        self.assertEqual(system.run([sys.executable, '-c', 'print(42)']).strip(), '42')
        for code, expected in (('pass', ('completed', 0)), ('raise SystemExit(7)', ('completed', 7)),
                               ('import os,signal; os.kill(os.getpid(),signal.SIGTERM)', ('signal', -15))):
            outcome = system.invoke([sys.executable, '-c', code], phase='test')
            self.assertEqual((outcome.category, outcome.returncode), expected)
        self.assertEqual(system.invoke(['/does-not-exist/upt-test'], phase='test').category, 'launch_error')
        self.assertEqual(system.invoke([sys.executable, '-c', 'import time; time.sleep(10)'],
                                       phase='test', timeout=.01).category, 'timeout')
        with self.assertRaises(system.CommandError):
            system.run(['/does-not-exist/upt-test'])

    def test_completed_worker_and_fixture_cleanup_pass(self):
        for cleanup in (False, True):
            with self.subTest(cleanup=cleanup), isolation.sandbox(join_seconds=1):
                gate = threading.Event()
                def scenario(case):
                    worker = self.worker(lambda: gate.wait(2))
                    if cleanup:
                        case.addCleanup(worker.join, 1)
                        case.addCleanup(gate.set)
                    else:
                        gate.set()
                        worker.join(1)
                    self.assertTrue(hasattr(worker, '_upt_isolation_stamp'))
                result, _ = self.run_inner([self.case(scenario)])
                self.assertTrue(result.wasSuccessful())

    def test_surviving_worker_fails_owner_and_stops_next_test(self):
        gate = threading.Event()
        workers, ran = [], []
        with isolation.sandbox() as state:
            def first(_):
                workers.append(self.worker(lambda: gate.wait(2), name='upt-refresh-' + SECRET))
            first_case = self.case(first, 'test_first')
            try:
                result, output = self.run_inner([first_case, self.case(lambda _: ran.append(True), 'test_next')])
                self.assertFalse(result.wasSuccessful())
                self.assertTrue(result.shouldStop)
                self.assertEqual(result.testsRun, 1)
                self.assertEqual(ran, [])
                self.assertIn(first_case.id(), output)
                self.assertIn('test run stopped', output)
                self.assertNotIn(SECRET, output)
                self.assertEqual(state.leaks[0]['owner'], first_case.id())
            finally:
                gate.set()
                for thread in workers: thread.join(1)

    def test_late_worker_and_descendant_keep_original_owner(self):
        gate = threading.Event()
        workers = []
        with isolation.sandbox() as state:
            def call():
                system.invoke(['docker', '--context', SECRET, 'ps'], phase='test')
            def worker():
                gate.wait(2)
                child = self.worker(call, name='generic-descendant')
                child.join(1)
            owner = self.case(lambda _: workers.append(self.worker(worker)), 'test_owner')
            try:
                result, _ = self.run_inner([owner])
                self.assertFalse(result.wasSuccessful())
                # Simulate a later scope; the suite itself must already be stopped.
                state.push('later-test')
                try:
                    gate.set()
                    workers[0].join(1)
                finally:
                    state.pop()
                self.assertEqual(state.violations[0]['owner'], owner.id())
                self.assertEqual(state.unreported()[0].count('later-test'), 0)
            finally:
                gate.set()
                for thread in workers: thread.join(1)

    def test_swallowed_worker_exception_fails_owning_test_and_is_redacted(self):
        with isolation.sandbox(join_seconds=1) as state:
            def scenario(_):
                thread = self.worker(lambda: system.invoke(['docker', 'run', '-e', SECRET], phase='test'),
                                     name='upt-refresh-' + SECRET)
                thread.join(1)
            case = self.case(scenario)
            logs, stdout = io.StringIO(), io.StringIO()
            handler = logging.StreamHandler(logs)
            logging.getLogger().addHandler(handler)
            try:
                with contextlib.redirect_stdout(stdout):
                    result, output = self.run_inner([case])
            finally:
                logging.getLogger().removeHandler(handler)
            self.assertFalse(result.wasSuccessful())
            self.assertEqual(state.violations[0]['owner'], case.id())
            self.assertNotIn(SECRET, output + logs.getvalue() + stdout.getvalue() + json.dumps(state.violations))

    def test_nested_tests_restore_owner_even_on_failure(self):
        with isolation.sandbox() as state:
            seen = []
            def inner(_):
                seen.append(state.owner)
                raise RuntimeError('intentional inner failure')
            nested = self.case(inner, 'test_inner')
            def outer(case):
                seen.append(state.owner)
                inner_result = unittest.TestResult()
                nested.run(inner_result)
                self.assertFalse(inner_result.wasSuccessful())
                seen.append(state.owner)
            outer_case = self.case(outer, 'test_outer')
            result, _ = self.run_inner([outer_case])
            self.assertTrue(result.wasSuccessful())
            self.assertEqual(seen, [outer_case.id(), nested.id(), outer_case.id()])
            self.assertEqual(state.owner, isolation.SESSION_OWNER)

    def test_sequential_violation_does_not_contaminate_clean_test(self):
        with isolation.sandbox():
            ran = []
            def refuse(_):
                system.invoke(['docker', 'ps'], phase='test')
            first = self.case(refuse, 'test_first')
            second = self.case(lambda _: ran.append(True), 'test_second')
            result, output = self.run_inner([first, second])
            self.assertEqual(result.testsRun, 2)
            self.assertEqual(ran, [True])
            self.assertFalse(result.wasSuccessful())
            self.assertEqual(len(result.errors + result.failures), 1)
            self.assertEqual((result.errors + result.failures)[0][0], first)

    def test_unstamped_thread_violation_is_not_charged_to_current_test(self):
        done = threading.Event()
        with isolation.sandbox() as state:
            def call():
                try:
                    system.invoke(['docker', 'ps'], phase='test')
                    descendant = self.worker(lambda: system.invoke(['docker', 'ps'], phase='descendant'))
                    descendant.join(1)
                finally:
                    done.set()
            def scenario(_):
                _thread.start_new_thread(call, ())
                self.assertTrue(done.wait(2))
            case = self.case(scenario, 'test_current')
            result, output = self.run_inner([case])
            self.assertFalse(result.wasSuccessful())
            self.assertEqual([entry['owner'] for entry in state.violations], ['unattributed', 'unattributed'])
            self.assertIn('test=unattributed', output)
            self.assertTrue(all(error[0] is not case for error in result.errors + result.failures))

    def test_framework_workers_are_tracked_without_leak_false_positives(self):
        for name in ('playwright-dispatcher', 'asyncio-portal', 'anyio-worker', 'starlette-fixture'):
            gate = threading.Event()
            workers = []
            with self.subTest(name=name), isolation.sandbox():
                try:
                    result, _ = self.run_inner([self.case(lambda _: workers.append(self.worker(
                        lambda: gate.wait(2), name=name)))])
                    self.assertTrue(result.wasSuccessful())
                    self.assertFalse(workers[0]._upt_isolation_stamp.upt)
                finally:
                    gate.set()
                    for thread in workers: thread.join(1)

    def test_class_and_module_fixture_scopes_and_stop_transitions(self):
        for scope in ('class', 'module'):
            for phase in ('setup', 'teardown'):
                for leak in (False, True):
                    with self.subTest(scope=scope, phase=phase, leak=leak), isolation.sandbox() as state:
                        gate, workers, ran = threading.Event(), [], []
                        module = types.ModuleType('synthetic_isolation_fixture')
                        def fixture(*_):
                            if leak:
                                workers.append(self.worker(lambda: gate.wait(2)))
                            else:
                                system.invoke(['docker', 'ps'], phase='fixture')
                        attrs = {'__module__': module.__name__, 'test_body': lambda _: ran.append('body')}
                        if scope == 'class':
                            attrs['setUpClass' if phase == 'setup' else 'tearDownClass'] = classmethod(fixture)
                        else:
                            setattr(module, 'setUpModule' if phase == 'setup' else 'tearDownModule', fixture)
                        cls = type('Fixture', (unittest.TestCase,), attrs)
                        # Setup-owned workers may live until their fixture teardown.
                        if leak and phase == 'setup':
                            def failed_setup(*_):
                                fixture()
                                raise RuntimeError('intentional fixture failure')
                            if scope == 'class': cls.setUpClass = classmethod(failed_setup)
                            else: module.setUpModule = failed_setup
                        following = self.case(lambda _: ran.append('next'), 'test_next')
                        try:
                            with patch.dict(sys.modules, {module.__name__: module}):
                                result, output = self.run_inner([cls('test_body'), following])
                            self.assertFalse(result.wasSuccessful())
                            owner = ('class:' + module.__name__ + '.Fixture' if scope == 'class'
                                     else 'module:' + module.__name__)
                            self.assertIn(owner, output)
                            if leak:
                                self.assertTrue(result.shouldStop)
                                self.assertNotIn('next', ran)
                            else:
                                self.assertEqual(state.violations[0]['owner'], owner)
                        finally:
                            gate.set()
                            for thread in workers: thread.join(1)

    def test_fixture_worker_stopped_at_own_cleanup_boundary(self):
        with isolation.sandbox(join_seconds=1):
            gate, workers = threading.Event(), []
            def setup(cls):
                workers.append(self.worker(lambda: gate.wait(2)))
                cls.addClassCleanup(workers[0].join, 1)
                cls.addClassCleanup(gate.set)
            cls = type('CleanFixture', (unittest.TestCase,),
                       {'setUpClass': classmethod(setup), 'test_body': lambda _: None})
            result, _ = self.run_inner([cls('test_body')])
            self.assertTrue(result.wasSuccessful())

    def test_module_worker_released_by_module_cleanup_passes(self):
        gate, workers = threading.Event(), []
        with isolation.sandbox(join_seconds=1):
            module = types.ModuleType('synthetic_clean_module')
            def setup():
                workers.append(self.worker(lambda: gate.wait(2)))
                unittest.addModuleCleanup(workers[0].join, 1)
                unittest.addModuleCleanup(gate.set)
            module.setUpModule = setup
            cls = type('CleanFixture', (unittest.TestCase,),
                       {'__module__': module.__name__, 'test_body': lambda _: None})
            try:
                with patch.dict(sys.modules, {module.__name__: module}):
                    result, _ = self.run_inner([cls('test_body')])
                self.assertTrue(result.wasSuccessful())
                self.assertFalse(workers[0].is_alive())
            finally:
                gate.set()
                for thread in workers: thread.join(1)

    def test_import_owned_worker_stops_suite_before_first_test(self):
        gate, ran = threading.Event(), []
        with isolation.sandbox() as state:
            worker = self.worker(lambda: gate.wait(2))
            try:
                result, output = self.run_inner([self.case(lambda _: ran.append(True))])
                self.assertFalse(result.wasSuccessful())
                self.assertEqual(ran, [])
                self.assertIn('test=session', output)
                self.assertEqual(state.leaks[0]['owner'], isolation.SESSION_OWNER)
            finally:
                gate.set()
                worker.join(1)

    def test_surviving_sandbox_worker_also_stops_its_outer_suite(self):
        gate, workers, ran = threading.Event(), [], []
        with isolation.sandbox() as outer, patch.object(isolation, 'JOIN_SECONDS', 0):
            def first(_):
                with isolation.sandbox():
                    workers.append(self.worker(gate.wait))
            try:
                case = self.case(first, 'test_sandbox_owner')
                result, output = self.run_inner([case, self.case(lambda _: ran.append(True), 'test_next')])
                self.assertFalse(result.wasSuccessful())
                self.assertTrue(result.shouldStop)
                self.assertEqual(ran, [])
                self.assertEqual(outer.leaks[0]['owner'], case.id())
                self.assertIn('sandbox UPT worker running', output)
            finally:
                gate.set()
                for thread in workers: thread.join(1)

    def test_child_shim_records_owner_and_redacts_all_inputs(self):
        with isolation.sandbox(shim=True) as state:
            def scenario(_):
                code = 'import subprocess; subprocess.run(["docker", "login", "-p", %r])' % SECRET
                child = system.subprocess.run([sys.executable, '-c', code], capture_output=True, text=True)
                self.assertNotIn(SECRET, child.stdout + child.stderr)
                text = Path(state.ledger).read_text()
                self.assertNotIn(SECRET, text)
            case = self.case(scenario)
            result, output = self.run_inner([case])
            self.assertFalse(result.wasSuccessful())
            self.assertEqual(state.violations[0]['owner'], case.id())
            self.assertIn('child-process', output)
            self.assertNotIn(SECRET, output)

    def test_raw_exception_source_and_logging_cannot_expose_arguments(self):
        with isolation.sandbox():
            def scenario(_):
                system.run(['docker', 'login', '-p', 'isolation-sentinel-9fd846a'])
            result, output = self.run_inner([self.case(scenario)])
            self.assertFalse(result.wasSuccessful())
            self.assertNotIn(SECRET, output)
            self.assertIn('UnexpectedDockerInvocation', output)

    def test_main_and_worker_redaction_matrix_including_uncaught_thread_errors(self):
        commands = (['docker', 'login', '-p', SECRET], ['docker', '--context', SECRET, 'ps'],
                    ['docker', 'compose', '--env-file', '/tmp/' + SECRET + '/.env', 'up'],
                    ['docker', 'run', '-e', 'TOKEN=' + SECRET])
        for worker in (False, True):
            with self.subTest(worker=worker), isolation.sandbox(join_seconds=1) as state:
                exceptions = io.StringIO()
                def scenario(_):
                    def calls():
                        for args in commands:
                            for operation in (lambda: system.run(args),
                                              lambda: system.invoke(args, phase='test'),
                                              lambda: system.run_compose_progress(args, None, 'fixture')):
                                try: operation()
                                except isolation.UnexpectedDockerInvocation: pass
                        # Exercise the standard thread-exception reporting path.
                        if worker:
                            system.run(['docker', 'login', '-p', 'isolation-sentinel-9fd846a'])
                    if worker:
                        thread = self.worker(calls, name='upt-refresh-' + SECRET)
                        thread.join(1)
                    else:
                        calls()
                with contextlib.redirect_stderr(exceptions):
                    result, output = self.run_inner([self.case(scenario)])
                self.assertFalse(result.wasSuccessful())
                self.assertNotIn(SECRET, output + exceptions.getvalue() + json.dumps(state.violations))
                self.assertTrue(all(entry['operation'] == 'unclassified' for entry in state.violations))


class RunnerTests(unittest.TestCase):
    def child_run(self, source, arguments=None, guarded=True, safe_path=False, package=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            if package:
                folder = root / 'test_package'
                folder.mkdir()
                (folder / '__init__.py').write_text(source)
                (folder / 'test_synthetic.py').write_text('import _upt_isolation\n')
            else:
                (root / 'test_synthetic.py').write_text(source)
            marker = root / 'spawned'
            # Absolute-path probes are safe even if a guard regression spawns.
            docker = root / 'docker'
            docker.write_text('#!/bin/sh\n: > "' + str(marker) + '"\nexit 91\n')
            docker.chmod(0o700)
            env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(ROOT / 'src'), str(ROOT / 'tests'), directory)),
                       PATH=directory + os.pathsep + os.environ['PATH'])
            command = [sys.executable]
            if safe_path: command.append('-P')
            command += [str(RUNNER)] if guarded else ['-m', 'unittest']
            command += arguments or ['discover', '-s', directory, '-v']
            result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)
            self.assertFalse(marker.exists(), 'a recording Docker probe was spawned')
            return result

    def test_missing_bootstrap_and_import_time_docker_are_rejected_before_import(self):
        source = 'from docker_update_manager.system import run\ntry: run(["docker", "ps"])\nexcept Exception: pass\n'
        result = self.child_run(source)
        self.assertEqual(result.returncode, 2)
        self.assertIn('preflight failed', result.stderr)
        self.assertIn('test_synthetic', result.stderr)

    def test_import_time_swallowed_docker_fails_session(self):
        for program in ('"docker"', '__import__("os").path.join(__import__("os").environ["PYTHONPATH"].split(__import__("os").pathsep)[-1], "docker")'):
            source = ('import _upt_isolation\nfrom docker_update_manager.system import invoke\n'
                      'invoke([' + program + ', "login", "-p", ' + repr(SECRET) + '], phase="import")\n')
            result = self.child_run(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('test=session', result.stderr)
            self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_plain_unittest_fails_loudly(self):
        result = self.child_run('import _upt_isolation\n', guarded=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must run through scripts/run_tests.py', result.stderr)

    def test_discovery_targeted_skips_and_safe_path(self):
        source = ('import _upt_isolation\nimport unittest\nclass Synthetic(unittest.TestCase):\n'
                  ' def test_pass(self): pass\n @unittest.skip("synthetic skip")\n def test_skip(self): pass\n')
        for arguments in (None, ['-v', 'test_synthetic'], ['-v', 'test_synthetic.Synthetic.test_pass']):
            for safe in (False, True) if sys.version_info >= (3, 11) else (False,):
                result = self.child_run(source, arguments, safe_path=safe)
                self.assertEqual(result.returncode, 0, result.stderr)
                if not arguments or arguments[-1] == 'test_synthetic':
                    self.assertIn('skipped=1', result.stderr)

    def test_safe_path_preserves_explicit_script_directory_on_pythonpath(self):
        if sys.version_info < (3, 11):
            return  # This interpreter has no -P option.
        source = ('import importlib.util, sys\n'
                  'spec = importlib.util.spec_from_file_location("runner", ' + repr(str(RUNNER)) + ')\n'
                  'runner = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(runner)\n'
                  'before = list(sys.path)\nrunner._emulate_module_invocation()\n'
                  'assert sys.path == before, "explicit PYTHONPATH changed"\n')
        env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(ROOT / 'scripts'), str(ROOT / 'src'))))
        result = subprocess.run([sys.executable, '-P', '-c', source], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_targeted_and_discovery_package_init_preflight_without_import(self):
        for arguments in (None, ['-v', 'test_package.test_synthetic']):
            result = self.child_run('raise RuntimeError("package imported unsafely")\n', arguments, package=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('RuntimeError', result.stderr)

    def test_script_mode_checks_ledger_even_after_successful_system_exit(self):
        source = ('import _upt_isolation\nfrom docker_update_manager.system import invoke\n'
                  'invoke(["docker", "ps"], phase="script")\nraise SystemExit(0)\n')
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'capture.py'
            script.write_text(source)
            env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
            result = subprocess.run([sys.executable, str(RUNNER), '--script', str(script)],
                                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('test=capture-script', result.stderr)

    def test_single_product_subprocess_boundary_remains_true(self):
        import ast
        for path in sorted((ROOT / 'src/docker_update_manager').rglob('*.py')):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == 'subprocess': self.assertEqual(path.name, 'system.py')
                if isinstance(node, ast.ImportFrom) and node.module == 'subprocess':
                    self.assertEqual(path.name, 'system.py')
                if isinstance(node, ast.Call):
                    self.assertFalse(any(k.arg == 'shell' and isinstance(k.value, ast.Constant)
                                         and k.value.value is True for k in node.keywords))
                    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        self.assertNotIn((node.func.value.id, node.func.attr), (('os', 'system'), ('os', 'popen')))
