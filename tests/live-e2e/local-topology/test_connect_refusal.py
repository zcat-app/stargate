# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from connect_refusal import validate_trace

CONTROL = 'stargate-proxy-42 [000] 1.0: t173_connect: path="/run/stargate-tor/tor-socks.sock" task="stargate-proxy"'
SOURCE = Path(__file__).with_name('connect_refusal.py').resolve()
REFUSAL = 'optimized Python (-O/PYTHONOPTIMIZE)'
UNSAFE = 'UNSAFE_OPTIMIZED_ACCEPTANCE'

def run_fixed_child(args, *, optimize_env=False):
    # Keep child output on a bounded regular file; RLIMIT_FSIZE does not bound pipes.
    runs = target_runs_dir(Path(__file__).resolve().parents[3])
    with tempfile.TemporaryDirectory(prefix='t189-optimized-', dir=runs) as directory:
        output_path = Path(directory) / 'child-output'
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'PYTHONIOENCODING': 'utf-8'}
        if optimize_env:
            env['PYTHONOPTIMIZE'] = '1'
        with output_path.open('wb') as output:
            result = subprocess.run(
                ['/usr/bin/timeout', '--kill-after=1s', '5s', '/usr/bin/prlimit',
                 '--fsize=65536', '--', sys.executable, *args],
                stdout=output, stderr=subprocess.STDOUT, check=False, timeout=7, env=env,
            )
        data = output_path.read_bytes()
        if len(data) > 65536:
            raise AssertionError('child output exceeded 65536 bytes')
        return result.returncode, data.decode('utf-8', errors='replace')

def target_runs_dir(repo_root):
    runs = Path(repo_root) / 'target' / 'runs'
    runs.mkdir(parents=True, exist_ok=True)
    return runs

class FreshCheckoutFixtureTests(unittest.TestCase):
    def test_target_runs_is_created_for_a_fresh_checkout(self):
        with tempfile.TemporaryDirectory(prefix='t189-fresh-checkout-') as checkout:
            runs = target_runs_dir(Path(checkout))
            self.assertTrue(runs.is_dir())
            self.assertEqual(runs, Path(checkout) / 'target' / 'runs')

class TraceVerdictTests(unittest.TestCase):
    def test_optimized_python_refuses_before_accepting_forbidden_trace(self):
        code = (
            'import importlib.util; '
            f'spec=importlib.util.spec_from_file_location("t189_fixture", {str(SOURCE)!r}); '
            'module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); '
            f'module.validate_trace({CONTROL!r}, {CONTROL!r}, [0], 0); '
            f'print({UNSAFE!r})'
        )
        codepoint, output = run_fixed_child(['-O', '-B', '-c', code])
        self.assertNotEqual(codepoint, 0, f'optimized validator accepted forbidden trace: {output}')
        self.assertNotIn(UNSAFE, output)
        self.assertIn(REFUSAL, output)

    def test_optimized_python_entrypoints_refuse_and_normal_trace_still_passes(self):
        code = (
            'import importlib.util; '
            f'spec=importlib.util.spec_from_file_location("t189_fixture", {str(SOURCE)!r}); '
            'module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); '
            f'module.validate_trace({CONTROL!r}, {CONTROL!r}, [0], 0); '
            f'print({UNSAFE!r})'
        )
        for args, optimize_env in ((['-O', '-B', '-c', code], False), (['-B', '-c', code], True),
                                   (['-O', '-B', str(SOURCE)], False)):
            with self.subTest(args=args, optimize_env=optimize_env):
                result, output = run_fixed_child(args, optimize_env=optimize_env)
                self.assertNotEqual(result, 0, output)
                self.assertIn(REFUSAL, output)
                self.assertNotIn(UNSAFE, output)
        normal_code = (
            'import importlib.util; '
            f'spec=importlib.util.spec_from_file_location("t189_fixture", {str(SOURCE)!r}); '
            'module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); '
            f'module.validate_trace("", {CONTROL!r}, [0], 0); print("NORMAL_TRACE_ACCEPTED")'
        )
        result, output = run_fixed_child(['-B', '-c', normal_code])
        self.assertEqual(result, 0, output)
        self.assertIn('NORMAL_TRACE_ACCEPTED', output)

    def test_real_control_and_no_refused_dial(self):
        validate_trace('', CONTROL, [0, 0], 0)

    def test_disconnected_or_wrong_endpoint_cannot_prove_refusal(self):
        for control in ('', CONTROL.replace('tor-socks.sock', 'control.sock')):
            with self.assertRaises(AssertionError):
                validate_trace('', control, [0], 0)

    def test_any_refused_dial_invalidates_result(self):
        with self.assertRaises(AssertionError):
            validate_trace(CONTROL, CONTROL, [0], 0)

    def test_lost_or_missing_trace_accounting_invalidates_result(self):
        for overruns, missed in (([], 0), ([1], 0), ([0], 1)):
            with self.assertRaises(AssertionError):
                validate_trace('', CONTROL, overruns, missed)

    def test_failed_path_fetch_invalidates_result(self):
        with self.assertRaises(AssertionError):
            validate_trace(CONTROL.replace('/run/stargate-tor/tor-socks.sock', '(fault)'), CONTROL, [0], 0)
