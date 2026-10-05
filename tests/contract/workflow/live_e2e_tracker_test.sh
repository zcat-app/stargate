#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T155 Acceptance 4: the live-e2e tracker must exist, carry the required
# sections, name only commands that exist, track the real-browser Direct-fallback
# probe and the release-cadence checks, and never record an unrun check as PASS
# (Constitution VII: SKIP is not PASS; workflow.md "Live end-to-end verification").
set -euo pipefail
python3 - "$(git rev-parse --show-toplevel)" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
readme = root / 'specs/001-tor-route/live-e2e/README.md'
errors = []

if not readme.is_file():
    print('FAIL: specs/001-tor-route/live-e2e/README.md is missing (T155 Acceptance 4)',
          file=sys.stderr)
    sys.exit(1)
text = readme.read_text()


def need(label, pattern, flags=re.I | re.S):
    if not re.search(pattern, text, flags):
        errors.append(f'missing: {label}')


# Required content named by Acceptance 4.
need('prerequisites section', r'^## .*environment.*disposable host', re.I | re.M)
need('foundation checks table', r'^## 1\. Foundation checks', re.I | re.M)
need('evidence index with a snapshot hash',
     r'## Evidence index.*snapshot\.\*\*\s+executable content is commit `[0-9a-f]{40}`')
need('preserve/reset semantics', r'### Preserve / reset.*reset every run.*preserve across runs')
need('transport-relevant vs invisible classification',
     r'transport-relevant \(live only\).*transport-invisible \(stays in contract tests\)')
need('real-browser hardening/token-failure probe with packet attribution',
     r'real-browser hardening / token-failure probe.*direct fallback.*packet attribution')
need('SKIP is never PASS rule', r'never recorded as pass|never pass', re.I)
for ticket in ('T186', 'T188', 'T034a', 'T034f', 'T070a'):
    need(f'{ticket} named', rf'\b{ticket}\b')
need('browser launch / session restore obligation',
     r'browser launch and session restore.*run before every release')
# The evidence snapshot must name a real commit, not any 40-hex string.
snap = re.search(r'executable content is commit `([0-9a-f]{40})`', text, re.I)
if snap and subprocess.run(['git', '-C', str(root), 'cat-file', '-e', snap.group(1) + '^{commit}'],
                           capture_output=True).returncode != 0:
    errors.append(f'evidence snapshot {snap.group(1)} is not a commit in this repository')
decisions = set(re.findall(r'\*\*D-live-(\d+)', text))
if len(decisions) < 3:
    errors.append(f'D-live-N decisions log needs at least 3 entries, found {len(decisions)}')

# Every repository path the tracker tells an operator to run must exist.
for path in sorted(set(re.findall(
        r'(?:tests/(?:live-e2e|contract|integration)/[\w./-]+\.(?:py|sh|go)|extension/package\.sh|scripts/verify\.sh)',
        text))):
    if not (root / path).is_file():
        errors.append(f'command path does not exist: {path}')

# An unrun release-cadence check must not carry a PASS status, and a check
# definition row (F-n) is not a result. An R-n row may name PASS only in the
# exact negation "never recorded as PASS"; any other PASS/PASSED/GREEN/OK, or a
# "passed"/"green" in any case, in an R-n or F-n row is an error (a nearby "not"
# elsewhere in the row is no excuse). Lower-case "pass" stays usable as a noun.
for line in text.splitlines():
    if not re.match(r'\|\s*[RF]-?\d+\s*\|', line):
        continue
    rest = line.replace('never recorded as PASS', '')
    if re.search(r'\b(PASS|OK)\b', rest) or re.search(r'\b(passed|green)\b', rest, re.I):
        errors.append(f'check row claims a result: {line[:80]}')

if errors:
    print('FAIL: live-e2e tracker (T155 Acceptance 4):', file=sys.stderr)
    for e in errors:
        print(f'  - {e}', file=sys.stderr)
    sys.exit(1)
print('OK: live-e2e tracker sections, commands, probe tracking and no unrun PASS')
PY
