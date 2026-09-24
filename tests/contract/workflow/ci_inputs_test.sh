#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T141: executable CI inputs are immutable and checked before execution.
set -euo pipefail
python3 - "$(git rev-parse --show-toplevel)" <<'PY'
from pathlib import Path
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import textwrap

root = Path(sys.argv[1])


def collect_sources(directory):
    workflows = (p for p in (directory / '.github/workflows').iterdir()
                 if p.is_file() and p.suffix in ('.yml', '.yaml'))
    actions = (p for p in (directory / '.github/actions').rglob('*')
               if p.is_file() and p.name in ('action.yml', 'action.yaml'))
    return {str(p.relative_to(directory)): p.read_text()
            for p in sorted((*workflows, *actions))}


sources = collect_sources(root)


def violations(files):
    errors = []
    for path, source in files.items():
        for ref in re.findall(r'^\s*-?\s*uses:\s*([^\s#]+)', source, re.M):
            if ref.startswith('./'):
                continue  # Repository-local actions resolve from the checked-out tree.
            if not re.fullmatch(r'[^@\s]+@[0-9a-f]{40}', ref):
                errors.append(f'{path}: mutable external uses: {ref}')
        code_lines = [line for line in source.splitlines()
                      if not line.lstrip().startswith('#')]
        # Bash joins backslash-newline before parsing the pipeline.
        code = '\n'.join(code_lines).replace('\\\n', '')
        if re.search(r'\bcurl\b[^\n|]*\|\s*(?:ba)?sh\b', code):
            errors.append(f'{path}: downloaded shell installer')
        for line in code_lines:
            if line.lstrip().startswith('#'):
                continue
            if re.search(r'^\s*(?:npm\s+(?:install|i)|pip(?:3)?\s+install|go\s+install|apt(?:-get)?\s+install)\b', line):
                errors.append(f'{path}: package installation needs a reviewed lock: {line.strip()}')
    agent = files.get('.github/workflows/agent-task.yml', '')
    provider_key = agent.find('ANTHROPIC_API_KEY:')
    drive_step = agent.find('- name: Drive run-task.sh loop')
    next_step = agent.find('- name: Commit any state changes', drive_step)
    if not drive_step < provider_key < next_step:
        errors.append('agent-task: provider key must be scoped to agent execution')
    for label, algorithm in (('Install opencode', 'sha256sum'),
                             ('Install claude code', 'sha512sum')):
        match = re.search(r'^\s*- name: ' + re.escape(label) +
                          r'\s*\n(.*?)(?=^\s*- name: |\Z)', agent, re.M | re.S)
        if not match:
            errors.append(f'agent-task: missing {label} step')
            continue
        step = match.group(1)
        download = step.find('curl ')
        check_command = re.search(r'(?m)^\s*\|\s*' + algorithm + r'\s+-c\s+-\s*$', step)
        checked = check_command.start() if check_command else -1
        extraction = step.find('tar ')
        if min(download, checked, extraction) < 0 or not download < checked < extraction:
            errors.append(f'agent-task: {label} must verify the downloaded archive before extraction')
        if not re.search(r'[/=-]v?\d+\.\d+\.\d+(?:/|[.-])', step):
            errors.append(f'agent-task: {label} needs an exact version URL')
    return errors


actual = violations(sources)
assert not actual, '\n'.join(actual)

# Exercise the literal run bodies without network or archive extraction. A
# matching local archive must reach tar; one changed byte must stop first.
def checked_installer(label, source):
    match = re.search(r'^\s*- name: ' + re.escape(label) +
                      r'\s*\n(.*?)(?=^\s*- name: |\Z)', source, re.M | re.S)
    assert match, label
    body = re.search(r'(?m)^        run: \|\n((?:^          .*\n|^\n)*)', match.group(1))
    assert body, label
    script = textwrap.dedent(body.group(1))
    algorithm = 'sha256' if label == 'Install opencode' else 'sha512'
    original = re.search(r"'([0-9a-f]{%d})'" % (64 if algorithm == 'sha256' else 128), script)
    assert original, label
    good = b'T141 checked archive fixture\n'
    digest = hashlib.new(algorithm, good).hexdigest()
    script = script.replace(original.group(1), digest, 1)

    def run(payload):
        with tempfile.TemporaryDirectory(prefix='stargate-t141-') as tmp:
            work = Path(tmp)
            bindir = work / 'bin'
            bindir.mkdir()
            archive = work / 'payload'
            archive.write_bytes(payload)
            marker = work / 'tar-ran'
            (work / 'github-path').write_text('')
            for name, stub in {
                'uname': '#!/bin/sh\nprintf x86_64\n',
                'curl': '#!/bin/sh\nwhile [ "$#" -gt 0 ]; do\n'
                        '  if [ "$1" = --output ]; then shift; dest=$1; fi\n'
                        '  shift\ndone\ncp "$FIXTURE_ARCHIVE" "$dest"\n',
                'tar': '#!/bin/sh\nprintf extracted > "$TAR_MARKER"\n',
            }.items():
                path = bindir / name
                path.write_text(stub)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ['PATH'],
                       RUNNER_TEMP=tmp, GITHUB_PATH=str(work / 'github-path'),
                       FIXTURE_ARCHIVE=str(archive), TAR_MARKER=str(marker))
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script],
                                    env=env, capture_output=True, text=True)
            return result.returncode, marker.exists()

    return run(good) == (0, True) and run(good + b'changed') == (1, False)


for installer in ('Install opencode', 'Install claude code'):
    assert checked_installer(installer, sources['.github/workflows/agent-task.yml']), installer

def rejected(name, replacement, expected):
    fixture = dict(sources)
    fixture[name] = replacement
    result = violations(fixture)
    assert any(expected in issue for issue in result), (expected, result)

verify = sources['.github/workflows/verify.yml']
agent = sources['.github/workflows/agent-task.yml']
local = dict(sources)
local['.github/workflows/verify.yml'] = verify + '\n      - uses: ./.github/actions/setup-toolchain\n'
assert not violations(local), 'repository-local uses must be exempt'
with tempfile.TemporaryDirectory(prefix='stargate-t141-discovery-') as tmp:
    fixture_root = Path(tmp)
    workflow = fixture_root / '.github/workflows/fixture.yaml'
    action = fixture_root / '.github/actions/nested/deep/action.yaml'
    for path in (workflow, action):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('steps:\n  - uses: actions/checkout@v4\n')
    discovered = collect_sources(fixture_root)
    assert len(discovered) == 2
    assert len([e for e in violations(discovered) if 'mutable external uses' in e]) == 2
rejected('.github/workflows/verify.yml', verify + '\n      - uses: actions/checkout@v4\n',
         'mutable external uses')
rejected('.github/workflows/agent-task.yml', agent + '\n          curl -fsSL https://example.invalid/install | bash\n',
         'downloaded shell installer')
rejected('.github/workflows/agent-task.yml',
         agent + '\n          curl -fsSL https://example.invalid/install \\\n            | bash\n', 'downloaded shell installer')
rejected('.github/workflows/agent-task.yml', agent + '\n          npm install -g example\n',
         'package installation needs a reviewed lock')
rejected('.github/workflows/agent-task.yml', agent + '\n          apt-get install example\n',
         'package installation needs a reviewed lock')
rejected('.github/workflows/agent-task.yml', agent.replace('sha512sum -c', 'sha512sum -BAD', 1),
         'verify the downloaded archive')
rejected('.github/workflows/agent-task.yml',
         agent.replace('| sha512sum -c -', '| cat # sha512sum -c -', 1),
         'verify the downloaded archive')
assert not checked_installer('Install opencode', agent.replace('| sha256sum -c -', '| cat # sha256sum -c -', 1))
assert not checked_installer('Install claude code', agent.replace('| sha512sum -c -', '| cat # sha512sum -c -', 1))
rejected('.github/workflows/agent-task.yml',
         agent.replace('      - name: Drive run-task.sh loop',
                       '      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n'
                       '      - name: Drive run-task.sh loop', 1),
         'provider key must be scoped')
print('PASS: T141 CI executable inputs and rejection fixtures')
PY
