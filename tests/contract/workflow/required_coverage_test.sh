#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T139: exercise real entrypoints in isolated repositories; never mutate this checkout.
set -euo pipefail
python3 - "$(git rev-parse --show-toplevel)" <<'PY'
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE = Path(sys.argv.pop())
MODULES = ('data-plane', 'proto', 'tests/contract',
           'tests/internal/loginvariants', 'tests/integration')


class Coverage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='stargate-t139-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ, GOWORK='auto', GOTOOLCHAIN='local',
                        GOPROXY='off', GOSUMDB='off', STARGATE_TEST_TAGS='',
                        STARGATE_SKIP_CP='0', STARGATE_SKIP_GROUND='0',
                        STARGATE_VERIFY_REPRO='0')
        self.env.pop('STARGATE_VERIFY_LOG', None)
        self.run_cmd('git', 'init', '-q', '-b', '001-fixture')
        self.run_cmd('git', 'config', 'user.email', 'fixture@example.invalid')
        self.run_cmd('git', 'config', 'user.name', 'T139 fixture')
        self.run_cmd('git', 'config', 'commit.gpgsign', 'false')
        self.write('.gitignore', 'target/\n')

    def write(self, name, content, mode=0o644):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(mode)
        return path

    def copy(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE / name, path)

    def run_cmd(self, *cmd):
        return subprocess.run(cmd, cwd=self.root, env=self.env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def commit(self):
        paths = self.run_cmd('git', 'ls-files', '--others', '--exclude-standard').stdout.splitlines()
        if paths:
            self.run_cmd('git', 'add', '--', *paths)
        result = self.run_cmd('git', 'commit', '-qm', 'fixture')
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_required_runner_modes(self):
        self.copy('scripts/verify.sh')
        runners = {
            'scripts/check-license-headers.sh': 'license-headers',
            'scripts/ground-check.sh': 'ground-check',
            'scripts/go-workspace-gate.py': 'go-workspace',
            'extension/run-tests.sh': 'extension-tests',
            'control-plane/mvnw': 'mvnw-verify',
        }
        self.write('control-plane/App.java', '// fixture substrate\n')
        self.write('extension/app.js', '// fixture substrate\n')
        for path in runners:
            self.write(path, 'raise SystemExit(7)\n' if path.endswith('.py')
                       else '#!/bin/sh\nexit 7\n', 0o755)
        self.commit()
        for path, gate in runners.items():
            with self.subTest(runner=path):
                (self.root / path).chmod(0o644)
                result = self.run_cmd('bash', 'scripts/verify.sh')
                self.assertIn(f'[FAIL] {gate}', result.stdout)
                self.assertNotIn(f'[SKIP] {gate}', result.stdout)
                (self.root / path).chmod(0o755)
            with self.subTest(missing_runner=path):
                runner = self.root / path
                content = runner.read_text()
                runner.unlink()
                result = self.run_cmd('bash', 'scripts/verify.sh')
                self.write(path, content, 0o755)
                self.assertIn(f'[FAIL] {gate}', result.stdout)

        # A scaffold with no JavaScript or Java sources genuinely has no
        # language tests yet; a missing runner alone is not that condition.
        for path in ('extension/app.js', 'extension/run-tests.sh', 'control-plane/App.java'):
            (self.root / path).unlink()
        result = self.run_cmd('bash', 'scripts/verify.sh')
        self.assertIn('[SKIP] extension-tests', result.stdout)
        self.assertIn('[SKIP] control-plane', result.stdout)

    def workspace(self):
        for idx, mod in enumerate(MODULES):
            self.write(f'{mod}/go.mod', f'module example.invalid/m{idx}\n\ngo 1.26\n')
            self.write(f'{mod}/sample_test.go', 'package sample\nimport "testing"\n'
                       'func TestControl(t *testing.T) {}\n')
        self.workfile(MODULES)

    def workfile(self, modules):
        self.write('go.work', 'go 1.26\nuse (\n' +
                   ''.join(f'./{m}\n' for m in modules) + ')\n')

    def gate(self):
        return self.run_cmd('python3', str(SOURCE / 'scripts/go-workspace-gate.py'), str(self.root))

    def test_each_required_module_omission(self):
        self.workspace()
        for missing in MODULES:
            with self.subTest(module=missing):
                self.workfile([m for m in MODULES if m != missing])
                result = self.gate()
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(missing, result.stdout)
        (self.root / 'go.work').unlink()
        self.assertNotEqual(self.gate().returncode, 0)

    def test_extra_module_and_failure_diagnostics(self):
        self.workspace()
        self.write('extra/go.mod', 'module example.invalid/extra\n\ngo 1.26\n')
        test = self.write('extra/extra_test.go', 'package extra\nimport "testing"\n'
                          'func TestDiagnostic(t *testing.T) { t.Fatal("T139 diagnostic marker") }\n')
        self.workfile([*MODULES, 'extra'])
        result = self.gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('TestDiagnostic', result.stdout)
        self.assertIn('T139 diagnostic marker', result.stdout)
        test.write_text('package extra\nimport "testing"\nfunc TestPositive(t *testing.T) {}\n')
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('PASS  go:extra:', result.stdout)

    def test_absent_substrate(self):
        result = self.gate()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('SKIP', result.stdout)

    def driver(self, privacy=True, budget=8):
        self.copy('scripts/run-task.sh')
        self.copy('scripts/review-matrix.json')
        self.write('scripts/verify.sh', '#!/bin/bash\necho "RESULT: GREEN"\n')
        self.write('scripts/regen-status.sh', '#!/bin/bash\nexit 0\n')
        self.write('.specify/feature.json', '{"feature_directory":"specs/001-fixture"}\n')
        self.ticket = 'specs/001-fixture/tickets/T999-fixture.md'
        self.write(self.ticket, f'---\nid: T999\ntitle: fixture\nstatus: in-review\n'
                   f'privacy_critical: {str(privacy).lower()}\nfiles_budget: {budget}\n'
                   'round_cap: 2\nreviews: {}\n---\n## Context\nFixture.\n')
        self.write('tracked.txt', 'before\n')
        self.commit()
        self.before = self.run_cmd('git', 'rev-parse', 'HEAD').stdout
        self.write('tracked.txt', 'after\n')
        self.run_cmd('git', 'add', 'tracked.txt')
        self.write('target/runs/T999.start-sha', self.before)

    def drive(self):
        return self.run_cmd('bash', 'scripts/run-task.sh', 'T999')

    def review_manifest(self, snapshot, files):
        lines = [f'SNAPSHOT: {snapshot}', 'ROUND: 1', 'GATE: review']
        for name in files:
            data = (self.root / 'target/runs' / name).read_bytes()
            lines.append(f'{hashlib.sha256(data).hexdigest()}  {name}')
        self.write('target/runs/T999.review-set', '\n'.join(lines) + '\n')

    def reviewer_verdict(self, name, verdict, reviewer, tool, model, effort,
                         snapshot):
        body = (f'VERDICT: {verdict}\nREVIEWER: {reviewer}\nTOOL: {tool}\n'
                f'MODEL: {model}\nEFFORT: {effort}\nSNAPSHOT: {snapshot}\nROUND: 1\n'
                'SUMMARY: fixture\nFINDINGS: none\n')
        self.write('target/runs/' + name, body)

    def gate_approve(self, verdict='APPROVE'):
        result = self.drive()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('REVIEW', result.stdout)
        self.assertNotIn('REDTEAM', result.stdout)
        snapshot = (self.root / 'target/runs/T999.review-snapshot').read_text().strip()
        files = ('T999.review-glm.verdict', 'T999.review-astra.verdict')
        self.reviewer_verdict(files[0], verdict, 'glm', 'opencode',
                              'zai-coding-plan/glm-5.3', 'xhigh', snapshot)
        self.reviewer_verdict(files[1], verdict, 'astra', 'codex',
                              'gpt-6-astra', 'xhigh', snapshot)
        self.review_manifest(snapshot, files)
        return files

    def code_approve(self):
        self.gate_approve()

    def assert_refused(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.before, self.run_cmd('git', 'rev-parse', 'HEAD').stdout)
        self.assertFalse((self.root / 'target/runs/T999.review-glm.verdict').exists(), result.stdout)

    def test_untracked_blocks_review(self):
        self.driver()
        self.write('new-source.go', 'package source\n')
        result = self.drive()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('new-source.go', result.stdout)

    def test_untracked_after_review_invalidates(self):
        self.setUp()
        self.driver()
        self.gate_approve()
        self.write('new-source.go', 'package source\n')
        self.assert_refused(self.drive())
        self.write('new-source.go', 'package changed\n')
        self.assert_refused(self.drive())

    def test_tracked_change_after_review_invalidates(self):
        self.driver(privacy=False)
        self.gate_approve()
        self.write('tracked.txt', 'changed after review\n')
        self.run_cmd('git', 'add', 'tracked.txt')
        self.assert_refused(self.drive())

    def test_staged_sources_and_ignored_artifacts_work(self):
        self.driver()
        self.write('new-source.go', 'package source\n')
        self.run_cmd('git', 'add', 'new-source.go')
        self.gate_approve()
        self.write('target/build-output', 'ignored generated output\n')
        result = self.drive()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('status: done', (self.root / self.ticket).read_text())
        self.assertNotEqual(self.before, self.run_cmd('git', 'rev-parse', 'HEAD').stdout)

    def test_all_paths_budget(self):
        self.driver(budget=1)
        self.write('specs/new-document.md', 'Counts toward scope.\n')
        self.run_cmd('git', 'add', 'specs/new-document.md')
        result = self.drive()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('budget', result.stdout.lower())

    def test_delayed_reviewer_cannot_authorize_new_candidate(self):
        self.driver(privacy=False)
        self.assertEqual(self.drive().returncode, 0)
        snapshot_a = (self.root / 'target/runs/T999.review-snapshot').read_text().strip()
        self.write('tracked.txt', 'candidate B\n')
        self.run_cmd('git', 'add', 'tracked.txt')
        self.assertEqual(self.drive().returncode, 0)
        snapshot_b = (self.root / 'target/runs/T999.review-snapshot').read_text().strip()
        self.assertNotEqual(snapshot_a, snapshot_b)
        # Reviewer A finishes only after the new handoff for B was issued: a
        # complete set bound to the stale snapshot cannot authorize B.
        files = ('T999.review-glm.verdict', 'T999.review-astra.verdict')
        self.reviewer_verdict(files[0], 'APPROVE', 'glm', 'opencode',
                              'zai-coding-plan/glm-5.3', 'xhigh', snapshot_a)
        self.reviewer_verdict(files[1], 'APPROVE', 'astra', 'codex',
                              'gpt-6-astra', 'xhigh', snapshot_a)
        self.review_manifest(snapshot_a, files)
        self.assert_refused(self.drive())
        self.gate_approve()
        result = self.drive()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('status: done', (self.root / self.ticket).read_text())
        self.assertEqual(self.run_cmd('git', 'show', 'HEAD:tracked.txt').stdout, 'candidate B\n')

    def test_gate_rejects_invalid_snapshot_and_round(self):
        for field in ('SNAPSHOT', 'ROUND'):
            for fault in ('missing', 'duplicate', 'wrong'):
                with self.subTest(field=field, fault=fault):
                    self.setUp()
                    self.driver(privacy=False)
                    self.gate_approve()
                    path = self.root / 'target/runs/T999.review-glm.verdict'
                    lines = path.read_text().splitlines()
                    original = next(line for line in lines if line.startswith(field + ':'))
                    if fault == 'missing':
                        lines.remove(original)
                    elif fault == 'duplicate':
                        lines.append(original)
                    else:
                        lines[lines.index(original)] = field + ': ' + ('2' if field == 'ROUND' else '0' * 64)
                    path.write_text('\n'.join(lines) + '\n')
                    self.review_manifest(
                        (self.root / 'target/runs/T999.review-snapshot').read_text().strip(),
                        ('T999.review-glm.verdict', 'T999.review-astra.verdict'))
                    self.assert_refused(self.drive())

    def test_authoritative_docs_require_isolated_review_launcher(self):
        for name in ('.specify/memory/review-loop.md',
                     '.specify/memory/autopilot.md', 'CONTRIBUTING.md'):
            with self.subTest(path=name):
                text = (SOURCE / name).read_text()
                self.assertIn('scripts/review-task.sh', text)
                self.assertIn('one GLM', text)
                self.assertIn('one Codex', text)


unittest.main(verbosity=2)
PY
