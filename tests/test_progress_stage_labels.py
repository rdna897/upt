"""Static guard for the stage model in every module that emits numbered stages.

A numbered stage is one row: if a stage is announced as running, it must finish
under the identical static label, otherwise the running row never closes.
Within one function every literal total must agree.
"""
import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import ast
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "src" / "docker_update_manager"
MODULES = ("operations.py", "compose_reconcile.py", "compose_discard.py", "compose_bootstrap.py", "conversion.py", "removal.py")


def stage_calls(tree):
    """Yield (function, number, total_node, label_node, is_running) for each literal-numbered stage.

    ``reporter.stage(n, total, label, state)`` and the local ``stage(n, label[, running])``
    helpers in the Compose workflows (which supply the total themselves) are both covered.
    """
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(function):
            if not (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, int)):
                continue
            keywords = {k.arg: k.value for k in node.keywords}
            if isinstance(node.func, ast.Attribute) and node.func.attr == "stage" and len(node.args) >= 3:
                state = keywords.get("state", node.args[3] if len(node.args) >= 4 else None)
                yield function.name, node.args[0].value, node.args[1], node.args[2], is_running(state)
            elif isinstance(node.func, ast.Name) and node.func.id == "stage" and len(node.args) >= 2:
                # Local helpers mark "running" by a third argument (True, "running" or a progress message).
                state = keywords.get("state", node.args[2] if len(node.args) >= 3 else None)
                running = state is not None and not (isinstance(state, ast.Constant) and state.value in {False, None, "completed"})
                yield function.name, node.args[0].value, None, node.args[1], running


def resolve_total(tree, function_name, node):
    """Literal value of a stage total given as a constant, a local ``total = ...`` or a progress constant."""
    from docker_update_manager import progress
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        for function in ast.walk(tree):
            if isinstance(function, ast.FunctionDef) and function.name == function_name:
                for stmt in ast.walk(function):
                    if isinstance(stmt, ast.Assign) and any(isinstance(x, ast.Name) and x.id == node.id for x in stmt.targets):
                        return resolve_total(tree, function_name, stmt.value)
        return getattr(progress, node.id, None)
    return None


def is_running(state):
    return isinstance(state, ast.Constant) and state.value in {"running", True}


class StageLabelTests(unittest.TestCase):
    def test_running_stages_finish_under_the_same_static_label(self):
        problems = []
        for module in MODULES:
            tree = ast.parse((SOURCE / module).read_text())
            labels = {}
            running_numbers = set()
            for function, number, _total, label_node, is_running_stage in stage_calls(tree):
                label = ast.unparse(label_node)
                labels.setdefault((function, number), set()).add(label)
                if is_running_stage:
                    running_numbers.add((function, number))
            for key in running_numbers:
                if len(labels[key]) != 1 or not next(iter(labels[key])).startswith(("'", '"')):
                    problems.append((module, key, sorted(labels[key])))
        self.assertEqual(problems, [])

    def test_a_function_never_mixes_stage_totals_and_numbers_fit_the_total(self):
        problems = []
        for module in MODULES:
            tree = ast.parse((SOURCE / module).read_text())
            totals, highest = {}, {}
            for function, number, total, _label, _running in stage_calls(tree):
                value = resolve_total(tree, function, total)
                if value is None:
                    continue
                totals.setdefault(function, set()).add(value)
                highest[function] = max(highest.get(function, 0), number)
            problems += [(module, function, sorted(values)) for function, values in totals.items() if len(values) != 1]
            problems += [(module, function, "number exceeds total") for function, values in totals.items()
                         if highest[function] > max(values)]
        self.assertEqual(problems, [])

    def test_declared_workflow_totals_are_the_documented_ones(self):
        from docker_update_manager import progress
        self.assertEqual((progress.RECONCILE_STAGE_TOTAL, progress.DISCARD_STAGE_TOTAL, progress.UPDATE_STAGE_TOTAL), (8, 5, 8))
        # Totals passed by name must be resolvable, so the checks above cannot silently skip them.
        for module in ("operations.py", "compose_reconcile.py"):
            tree = ast.parse((SOURCE / module).read_text())
            for function, _number, total, _label, _running in stage_calls(tree):
                if total is not None:
                    self.assertIsNotNone(resolve_total(tree, function, total), (module, function, ast.unparse(total)))

    def test_compose_apply_and_bootstrap_cores_emit_only_stages_one_to_seven(self):
        for module, function_name in (("compose_reconcile.py", "do_compose_reconcile"),
                                      ("compose_bootstrap.py", "do_compose_bootstrap")):
            tree = ast.parse((SOURCE / module).read_text())
            numbers = {number for function, number, *_ in stage_calls(tree) if function == function_name}
            self.assertEqual(numbers, set(range(1, 8)), f"{module}: stage 8 is the committer's durable record")


if __name__ == "__main__":
    unittest.main()
