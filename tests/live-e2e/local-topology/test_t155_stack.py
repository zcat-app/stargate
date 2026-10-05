# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""T155: the stack harness's exit code must mean "every mandatory check ran and
passed" (Constitution VII: SKIP or an unrun check is never PASS).

The tests execute t155_stack.py's real `if __name__ == "__main__":` block.
The module body is executed under another name in a temporary directory, the
phase functions are replaced by stand-ins that record results, and the
entrypoint block is then executed in that namespace. No Docker, network or
repository file is touched.
"""

import ast
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path

SOURCE = Path(__file__).with_name("t155_stack.py")
MODES = {None: [], "resumption": ["--only", "resumption"], "traffic": ["--only", "traffic"]}
# main_focused records this one only on its resumption branch.
ENTRY_ONLY = "laptop still admitted after the CP rotation"


class FakeSubprocess:
    """Stands in for the module's `subprocess` during the entrypoint: records
    the cleanup call and can make it fail."""

    def __init__(self, fail=None, returncode=0):
        self.calls = []
        self.fail = fail
        self.returncode = returncode

    def run(self, argv, **kwargs):
        self.calls.append(list(map(str, argv)))
        if self.fail is not None:
            raise self.fail
        return types.SimpleNamespace(returncode=self.returncode, stdout="", stderr="")


class Harness:
    def __init__(self, mode):
        self.mode = mode
        self.tmp = tempfile.TemporaryDirectory(prefix="t155-stack-test-")
        tree = ast.parse(SOURCE.read_text(), str(SOURCE))
        entry = [n for n in tree.body if isinstance(n, ast.If) and "__name__" in ast.unparse(n.test)]
        assert len(entry) == 1, "expected exactly one __main__ block"
        self.entry = compile(ast.Module(body=entry[0].body, type_ignores=[]), str(SOURCE), "exec")
        tree.body.remove(entry[0])
        self.ns = {"__name__": "t155_stack_under_test", "__file__": str(SOURCE)}
        argv, cwd = sys.argv, os.getcwd()
        try:
            sys.argv = ["t155_stack.py", *MODES[mode]]
            os.chdir(self.tmp.name)
            exec(compile(tree, str(SOURCE), "exec"), self.ns)
        finally:
            sys.argv = argv
            os.chdir(cwd)
        self.ns["log"] = lambda msg: None
        self.subprocess = FakeSubprocess()
        self.ns["subprocess"] = self.subprocess

    def close(self):
        self.tmp.cleanup()

    def record(self, name, ok=True):
        self.ns["check"](name, ok)

    def run(self, phase):
        """Run the entrypoint with `phase` as the selected mode's main; return
        (exit code, results written to results.json)."""
        self.ns["main"] = self.ns["main_focused"] = lambda: phase(self)
        code = None
        try:
            exec(self.entry, self.ns)
        except SystemExit as exc:
            code = exc.code
        results_file = Path(self.ns["EV"]) / "results.json"
        results = json.loads(results_file.read_text()) if results_file.is_file() else None
        return code, results

    def mandatory(self):
        return self.ns["MANDATORY"][self.mode]

    def complete(self, skip=None, fail=None):
        for name, need in self.mandatory().items():
            if name == skip:
                continue
            for _ in range(need):
                self.record(name, name != fail)


def one_pass_then(exc):
    def phase(h):
        h.record("scripts/stargate init on clean volumes")
        if exc is not None:
            raise exc
    return phase


class EntrypointTests(unittest.TestCase):
    def harness(self, mode):
        h = Harness(mode)
        self.addCleanup(h.close)
        return h

    def assert_unsuccessful(self, h, code, results, needle):
        self.assertNotIn(code, (0, None), "an incomplete run must not exit 0")
        self.assertIsNotNone(results, "results.json must still be written")
        failed = [r for r in results if r["result"] != "PASS"]
        self.assertTrue(any(needle in (r["check"] + " " + r["detail"]).lower() for r in failed),
                        f"no explicit {needle!r} record among {failed}")
        self.assertTrue(any("down" in call for call in h.subprocess.calls), "cleanup must still run")

    def test_interrupt_after_one_pass_is_incomplete(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                code, results = h.run(one_pass_then(KeyboardInterrupt()))
                self.assert_unsuccessful(h, code, results, "incomplete")
                self.assertTrue(any("KeyboardInterrupt" in r["detail"] for r in results))

    def test_system_exit_zero_inside_a_phase_is_incomplete(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                code, results = h.run(one_pass_then(SystemExit(0)))
                self.assert_unsuccessful(h, code, results, "incomplete")

    def test_early_return_is_incomplete(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                code, results = h.run(one_pass_then(None))
                self.assert_unsuccessful(h, code, results, "incomplete")

    def test_ordinary_exception_is_a_recorded_failure(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                code, results = h.run(one_pass_then(RuntimeError("boom")))
                self.assert_unsuccessful(h, code, results, "harness error")

    def test_one_missing_mandatory_check_is_incomplete(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                last = list(h.mandatory())[-1]
                code, results = h.run(lambda hh, last=last: hh.complete(skip=last))
                self.assert_unsuccessful(h, code, results, "incomplete")
                self.assertTrue(any(last in r["detail"] for r in results if r["result"] != "PASS"))

    def test_too_few_repetitions_of_a_repeated_check_is_incomplete(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                repeated = [n for n, need in h.mandatory().items() if need > 1]
                if not repeated:
                    continue

                def phase(hh, name=repeated[0]):
                    hh.complete(skip=name)
                    hh.record(name)
                code, results = h.run(phase)
                self.assert_unsuccessful(h, code, results, "incomplete")

    def test_a_failed_mandatory_check_fails_the_run(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                first = list(h.mandatory())[0]
                code, results = h.run(lambda hh, first=first: hh.complete(fail=first))
                self.assertNotIn(code, (0, None))
                self.assertTrue(any(r["check"] == first and r["result"] == "FAIL" for r in results))

    def test_normal_completion_exits_zero(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                code, results = h.run(lambda hh: hh.complete())
                self.assertEqual(code, 0)
                self.assertTrue(results and all(r["result"] == "PASS" for r in results))
                self.assertEqual(len(results), sum(h.mandatory().values()), "success adds no result of its own")
                self.assertTrue(any("down" in call for call in h.subprocess.calls))

    def test_failed_cleanup_cannot_turn_into_success(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                h.subprocess.fail = RuntimeError("compose down failed")
                code, _ = h.run(lambda hh: hh.complete())
                self.assertNotIn(code, (0, None))
                h.subprocess.fail = KeyboardInterrupt()
                h.ns["RESULTS"].clear()
                code, _ = h.run(lambda hh: hh.complete())
                self.assertNotIn(code, (0, None))

    def test_nonzero_cleanup_exit_is_a_recorded_failure(self):
        for mode in MODES:
            with self.subTest(mode=mode or "full"):
                h = self.harness(mode)
                h.subprocess.returncode = 1
                code, results = h.run(lambda hh: hh.complete())
                self.assertNotIn(code, (0, None), "a failed compose down must not exit 0")
                failed = [r for r in results if r["result"] != "PASS"]
                self.assertEqual(len(failed), 1, failed)
                self.assertIn("cleanup", failed[0]["check"])
                self.assertIn("exit 1", failed[0]["detail"])
                # Control: the same complete run with a clean teardown succeeds.
                h = self.harness(mode)
                code, results = h.run(lambda hh: hh.complete())
                self.assertEqual(code, 0)


def calls_outside_functions(source):
    """check()/require() calls at module level outside the __main__ block: such
    a call would be recorded in every mode without being declared mandatory."""
    tree = ast.parse(source)
    found = []
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(stmt, ast.If) and "__name__" in ast.unparse(stmt.test):
            continue
        found += [ast.unparse(n) for n in ast.walk(stmt)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("check", "require")]
    return found


def source_check_names():
    """Literal check()/require() names per top-level function, read from the
    source, with the wire-row f-string expanded."""
    tree = ast.parse(SOURCE.read_text(), str(SOURCE))
    per_function = {}
    for fn in (n for n in tree.body if isinstance(n, ast.FunctionDef)):
        names = set()
        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in ("check", "require") and node.args):
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                names.add(arg.value)
            elif isinstance(arg, ast.JoinedStr):
                text = ast.unparse(arg)
                assert text == "f'wire runtime row R{n} PASS (not SKIP)'", f"unknown dynamic check name {text}"
                names.update(f"wire runtime row R{n} PASS (not SKIP)" for n in range(1, 10))
            else:
                # `check(name, ...)` inside traffic_publication_phase's require()
                assert isinstance(arg, ast.Name) and arg.id == "name", ast.unparse(node)
        if names:
            per_function[fn.name] = names
    return per_function


class MandatoryListTests(unittest.TestCase):
    """The declared mandatory names must be exactly the checks the source can
    record in each mode, so a new or renamed check cannot be left out."""

    def test_declaration_matches_the_check_calls_in_the_source(self):
        src = source_check_names()
        self.assertEqual(set(src), {"main", "main_focused", "traffic_publication_phase", "resumption_phase"})
        focused = src["main_focused"] - {ENTRY_ONLY}
        expected = {
            None: src["main"] | src["traffic_publication_phase"] | src["resumption_phase"],
            "resumption": focused | src["resumption_phase"] | {ENTRY_ONLY},
            "traffic": focused | src["traffic_publication_phase"],
        }
        h = Harness(None)
        self.addCleanup(h.close)
        declared = h.ns["MANDATORY"]
        self.assertEqual(set(declared), set(expected))
        for mode, names in expected.items():
            with self.subTest(mode=mode or "full"):
                self.assertEqual(set(declared[mode]), names)
                self.assertTrue(all(isinstance(n, int) and n >= 1 for n in declared[mode].values()))

    def test_no_check_is_recorded_outside_a_function(self):
        # Positive controls: the detector sees a module-level and a nested call.
        self.assertEqual(calls_outside_functions('check("new step", True)\n'), ["check('new step', True)"])
        self.assertEqual(len(calls_outside_functions('for n in (1, 2):\n    require("x", n)\n')), 1)
        self.assertEqual(calls_outside_functions('def f():\n    check("x", True)\n'), [])
        self.assertEqual(calls_outside_functions(SOURCE.read_text()), [])
        # Only plain functions may hold checks, so source_check_names sees them all.
        tree = ast.parse(SOURCE.read_text())
        self.assertFalse([n for n in tree.body if isinstance(n, (ast.ClassDef, ast.AsyncFunctionDef))])

    def test_entrypoint_results_are_not_mandatory_names(self):
        h = Harness(None)
        self.addCleanup(h.close)
        code, results = h.run(one_pass_then(KeyboardInterrupt()))
        added = {r["check"] for r in results} - {"scripts/stargate init on clean volumes"}
        for mode in MODES:
            self.assertFalse(added & set(h.ns["MANDATORY"][mode]))


if __name__ == "__main__":
    unittest.main()
