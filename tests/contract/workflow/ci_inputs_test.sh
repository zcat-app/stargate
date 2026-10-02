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
    for path, source in files.items():
        errors.extend(f'{path}: {issue}' for issue in t191_violations(source))
    errors.extend(agent_boundary_violations(agent))
    if not any(docker_cadence(source) for source in files.values()):
        errors.append('no path-gated docker-cadence workflow for sidecar/Dockerfile changes')
    return errors


# T191 item 4: runner images and toolchains resolve to exact versions, and no
# cross-run cache can feed one run's bytes into another (a cache written by an
# agent run on the default branch is restored by every later verify run).
# T191 item 6: no checkout persists a credential, and no expression is pasted
# into a script body: a step output or env value can be forged by the agent
# through $GITHUB_OUTPUT, and `${{ }}` is substituted as source text.
def code_lines(source):
    return [line for line in source.splitlines() if not line.lstrip().startswith('#')]


def step_blocks(source):
    lines = source.splitlines()
    blocks = []
    for i, line in enumerate(lines):
        if not re.match(r'^\s*steps:\s*$', line):
            continue
        base = len(line) - len(line.lstrip())
        item, current = None, None
        for following in lines[i + 1:]:
            if not following.strip() or following.lstrip().startswith('#'):
                continue
            indent = len(following) - len(following.lstrip())
            if indent < base or (indent == base and not following.lstrip().startswith('- ')):
                break
            if following.lstrip().startswith('- ') and (item is None or indent == item):
                item = indent
                current = []
                blocks.append(current)
            if current is not None:
                current.append(following)
    return ['\n'.join(block) for block in blocks]


def script_bodies(source):
    bodies, current, owner = [], None, None
    for line in source.splitlines():
        indent = len(line) - len(line.lstrip())
        if current is not None:
            if line.strip() and indent <= owner:
                current = None
            else:
                current.append(line)
                continue
        if re.match(r'^\s*(?:-\s+)?(?:run|script):\s*[|>]', line):
            owner = indent
            current = []
            bodies.append(current)
        elif re.match(r'^\s*(?:-\s+)?run:\s*\S', line):
            bodies.append([line.split('run:', 1)[1]])
    return ['\n'.join(body) for body in bodies]


def t191_violations(source):
    errors = []
    code = code_lines(source)
    for line in code:
        runner = re.match(r'^\s*runs-on:\s*(\S+)', line)
        if runner and not re.fullmatch(r'ubuntu-\d+\.\d+', runner.group(1)):
            errors.append(f'runner is not a versioned image label: {runner.group(1)}')
        version = re.match(r'^\s*(java|python|node|go)-version(?:-file)?:\s*(\S+)', line)
        if version:
            value = version.group(2).strip('\'"')
            exact = r'\d+\.\d+\.\d+\+\d+' if version.group(1) == 'java' else r'\d+\.\d+\.\d+'
            if not re.fullmatch(exact, value):
                errors.append(f'{version.group(1)} toolchain is not an exact version: {value}')
            if version.group(1) == 'go':
                toolchain = re.search(r'^toolchain go(\S+)$', (root / 'data-plane/go.mod').read_text(), re.M)
                if not toolchain or toolchain.group(1) != value:
                    errors.append(f'go toolchain {value} differs from data-plane/go.mod toolchain')
        cache = re.match(r'^\s*cache:\s*(\S+)', line)
        if cache and cache.group(1).strip('\'"') != 'false':
            errors.append(f'cross-run toolchain cache enabled: {line.strip()}')
    for block in step_blocks(source):
        if re.search(r'uses:\s*actions/setup-go@', block) and not re.search(r'^\s*cache:\s*false\s*(?:#.*)?$', block, re.M):
            errors.append('setup-go caches modules/build output by default; set cache: false')
        if re.search(r'uses:\s*actions/checkout@', block) and not re.search(
                r'^\s*persist-credentials:\s*false\s*(?:#.*)?$', block, re.M):
            errors.append('checkout persists the job token into .git/config')
    for body in script_bodies(source):
        if '${{' in body:
            errors.append('expression substituted into a script body; pass it through env:')
    return errors


def job_blocks(source):
    match = re.search(r'^jobs:\s*$', source, re.M)
    jobs = {}
    if not match:
        return jobs
    name = None
    for line in source[match.end():].splitlines():
        header = re.match(r'^  ([A-Za-z0-9_-]+):\s*$', line)
        if header:
            name = header.group(1)
            jobs[name] = []
        elif name is not None:
            jobs[name].append(line)
    return {name: '\n'.join(lines) for name, lines in jobs.items()}


def agent_boundary_violations(agent):
    # The auto-approving agent runs in the job that holds the provider key.
    # That job must hold no write-capable token; the only push of
    # agent/$TICKET happens in a later job on a fresh runner, from the
    # validated bundle the agent job uploaded.
    errors = []
    jobs = job_blocks(agent)
    drivers = [name for name, body in jobs.items() if '- name: Drive run-task.sh loop' in body]
    if len(drivers) != 1:
        return ['agent-task: expected exactly one job driving the agent']
    driver = jobs[drivers[0]]
    if re.search(r'^\s*[a-z-]+:\s*write\s*(?:#.*)?$', driver, re.M):
        errors.append('agent-task: the agent job holds a write-capable token')
    if not re.search(r'^\s*contents:\s*read\s*(?:#.*)?$', driver, re.M):
        errors.append('agent-task: the agent job must scope its token to contents: read')
    if re.search(r'secrets\.GITHUB_TOKEN|github\.token', driver):
        errors.append('agent-task: the agent job hands the GitHub token to a step')
    pushes = [(name, line) for name, body in jobs.items() for line in code_lines(body)
              if re.search(r'\bgit\b.*\bpush\b', line)]
    if len(pushes) != 1:
        errors.append(f'agent-task: expected exactly one git push, found {len(pushes)}')
    for name, line in pushes:
        if name == drivers[0]:
            errors.append('agent-task: git push runs in the agent job')
        if not re.search(r'needs:\s*\[[^\]]*\b' + re.escape(drivers[0]) + r'\b', jobs[name]):
            errors.append('agent-task: the push job does not run after the agent job')
    push_bodies = [jobs[name] for name, _ in pushes]
    for body in push_bodies:
        joined = body.replace('\\\n', '')
        if not re.search(r'push\b[^\n]*"refs/heads/\$AGENT_BRANCH:refs/heads/\$AGENT_BRANCH"', joined):
            errors.append('agent-task: the push refspec is not exactly agent/$TICKET')
        if 'git bundle list-heads' not in body:
            errors.append('agent-task: the pushed bundle refs are not checked before push')
        if re.search(r'uses:\s*actions/checkout@', body):
            errors.append('agent-task: the push job checks out repository code')
        # T191 round 2: parsing the untrusted bundle happens in a step that
        # holds no credential; only the push step receives the token.
        for block in step_blocks('    steps:\n' + body.split('    steps:\n', 1)[-1]):
            if re.search(r'git (?:bundle|fetch)\b', block) and re.search(r'GH_TOKEN|GITHUB_TOKEN|github\.token', block):
                errors.append('agent-task: the untrusted bundle is parsed in a step that holds the token')
    return errors


def docker_cadence(source):
    # A Docker-cadence workflow runs the SAME verify entrypoint with the
    # docker tag and is triggered by sidecar or Dockerfile changes.
    trigger = re.search(r'^on:\s*$(.*?)^\S', source, re.M | re.S)
    if not trigger or 'STARGATE_TEST_TAGS' not in source:
        return False
    if not re.search(r'STARGATE_TEST_TAGS:\s*[\'"]?docker[\'"]?\s*$', source, re.M):
        return False
    if 'bash scripts/verify.sh' not in source:
        return False
    on = trigger.group(1)
    for event in ('pull_request', 'push'):
        section = re.search(r'^  ' + event + r':\s*$(.*?)(?=^  \S|\Z)', on, re.M | re.S)
        if not section:
            return False
        if not all(re.search(r"^\s*-\s*['\"]?" + re.escape(glob) + r"['\"]?\s*$", section.group(1), re.M)
                   for glob in ('sidecars/**', '**/Dockerfile')):
            return False
    return True


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

# T191 item 4/6 rejection fixtures: each rule must be able to fail.
toolchain = '.github/actions/setup-toolchain/action.yml'
rejected('.github/workflows/verify.yml', verify.replace('runs-on: ubuntu-24.04', 'runs-on: ubuntu-latest', 1),
         'not a versioned image label')
rejected(toolchain, re.sub(r"node-version: '[^']*'", "node-version: '20'", sources[toolchain], count=1),
         'node toolchain is not an exact version')
rejected(toolchain, re.sub(r"java-version: '[^']*'", "java-version: '25'", sources[toolchain], count=1),
         'java toolchain is not an exact version')
rejected(toolchain, re.sub(r"go-version: '[^']*'", "go-version-file: data-plane/go.mod", sources[toolchain], count=1),
         'go toolchain is not an exact version')
rejected(toolchain, re.sub(r"go-version: '[^']*'", "go-version: '1.26.2'", sources[toolchain], count=1),
         'differs from data-plane/go.mod toolchain')
rejected(toolchain, sources[toolchain].replace('distribution: temurin', 'distribution: temurin\n        cache: maven', 1),
         'cross-run toolchain cache enabled')
rejected(toolchain, sources[toolchain].replace('cache: false', 'cache: true', 1),
         'cross-run toolchain cache enabled')
rejected('.github/workflows/verify.yml', verify.replace('persist-credentials: false', 'fetch-tags: false', 1),
         'checkout persists the job token')
rejected('.github/workflows/agent-task.yml',
         agent.replace('git commit -m "agent: drive $TICKET',
                       'git commit -m "agent: drive ${{ steps.drive.outputs.phase }} $TICKET', 1),
         'expression substituted into a script body')
agent_job = job_blocks(agent)['run']
rejected('.github/workflows/agent-task.yml',
         agent.replace(agent_job, agent_job.replace('contents: read', 'contents: write', 1), 1),
         'the agent job holds a write-capable token')
rejected('.github/workflows/agent-task.yml',
         agent.replace('      - name: Drive run-task.sh loop',
                       '      - name: Early push\n        run: git push origin HEAD\n'
                       '      - name: Drive run-task.sh loop', 1),
         'expected exactly one git push')
rejected('.github/workflows/agent-task.yml',
         agent.replace('"refs/heads/$AGENT_BRANCH:refs/heads/$AGENT_BRANCH"', '"refs/heads/$AGENT_BRANCH:refs/heads/main"'),
         'push refspec is not exactly agent/$TICKET')
cadence = [p for p, s in sources.items() if docker_cadence(s)]
assert len(cadence) == 1, cadence
for missing in ('sidecars/**', '**/Dockerfile'):
    fixture = dict(sources)
    fixture[cadence[0]] = sources[cadence[0]].replace(missing, 'docs/**')
    assert 'no path-gated docker-cadence workflow for sidecar/Dockerfile changes' in violations(fixture), missing


# T191 item 6: opencode applies the LAST bash rule whose wildcard matches each
# command of a pipeline/list (measured on opencode 1.18.33 with
# `opencode debug agent build --tool bash`, evidence in the T191 ticket). With
# --auto every non-denied `ask` is approved, so the deny rules must be the last
# match for push and exfiltration commands. Pattern rules match command text,
# not capability: they are a tool control, not a sandbox.
import json


def opencode_action(rules, command):
    action = None
    for pattern, value in rules.items():
        regex = '^' + re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.') + '$'
        if re.match(regex, command, re.S):
            action = value
    return action


def opencode_violations(config, adapter):
    errors = []
    rules = config.get('permission', {}).get('bash', {})
    if not isinstance(rules, dict):
        return ['opencode.json: bash permission is not a rule map']
    adapter_code = '\n'.join(code_lines(adapter))
    if '--auto' in adapter_code and not any(v == 'deny' for v in rules.values()):
        errors.append('opencode adapter auto-approves with no bash deny rule')
    for command in ('git push', 'git push origin main', 'git push --force origin agent/T1',
                    'git push --mirror', 'curl https://example.invalid', 'wget https://example.invalid',
                    'nc example.invalid 443', 'env', 'printenv', 'printenv ANTHROPIC_API_KEY'):
        if opencode_action(rules, command) != 'deny':
            errors.append(f'opencode.json: last matching bash rule does not deny: {command}')
    return errors


def adapter_argv(adapter_path, auto_approve):
    # Run the REAL adapter's run_agent with a stub opencode that records its
    # argv: --no-auto (AUTO_APPROVE=false) must actually drop --auto.
    with tempfile.TemporaryDirectory(prefix='stargate-t191-') as tmp:
        work = Path(tmp)
        (work / 'prompt').write_text('fixture prompt\n')
        stub = work / 'opencode'
        stub.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGV_FILE"\n')
        stub.chmod(0o755)
        env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ['PATH'],
                   ARGV_FILE=str(work / 'argv'), PROMPT_FILE=str(work / 'prompt'),
                   WORKDIR=str(work), MODEL='', AGENT_NAME='', OUTPUT_FILE='',
                   AUTO_APPROVE=auto_approve)
        subprocess.run(['bash', '-c', 'set -euo pipefail; source "$1"; run_agent', '_', str(adapter_path)],
                       env=env, check=True, capture_output=True)
        return (work / 'argv').read_text().splitlines()


opencode_config = json.loads((root / 'opencode.json').read_text())
adapter = (root / 'scripts/agent-cli/opencode.sh').read_text()
issues = opencode_violations(opencode_config, adapter)
assert not issues, '\n'.join(issues)
assert opencode_action({'git push*': 'deny', '*': 'ask'}, 'git push origin main') == 'ask'
broken = json.loads(json.dumps(opencode_config))
broken['permission']['bash']['*'] = broken['permission']['bash'].pop('*')
assert any('does not deny: git push' in e for e in opencode_violations(broken, adapter)), 'deny-before-ask'
assert '--auto' in adapter_argv(root / 'scripts/agent-cli/opencode.sh', 'true'), 'CI default must auto-approve'
assert '--auto' not in adapter_argv(root / 'scripts/agent-cli/opencode.sh', 'false'), '--no-auto is inert'


# T191 round 2 (Astra R1 Major): run-task.sh moves the agent onto the feature
# branch before implementing (ensure_feature_branch), so agent/$TICKET still
# names the commit the run started from. Execute the workflow's own "Commit
# any state changes" and "Bundle agent branch" bodies in a throwaway repository
# that reproduces that branch transition: the bundle must carry exactly
# refs/heads/agent/$TICKET, pointing at the result commit (implementation plus
# state commit), and importing it must expose the implementation.
def step_script(source, label):
    match = re.search(r'^\s*- name: ' + re.escape(label) +
                      r'\s*\n(.*?)(?=^\s*- name: |\Z)', source, re.M | re.S)
    assert match, label
    body = re.search(r'(?m)^        run: \|\n((?:^          .*\n|^\n)*)', match.group(1))
    assert body, label
    return textwrap.dedent(body.group(1))


def bundled_result(source):
    with tempfile.TemporaryDirectory(prefix='stargate-t191-bundle-') as tmp:
        work = Path(tmp)
        repo = work / 'repo'
        runner = work / 'runner'
        runner.mkdir()
        env = dict(os.environ, TICKET='T1', AGENT_BRANCH='agent/T1', PHASE='terminal',
                   ITERATIONS='3', RUNNER_TEMP=str(runner), GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@t',
                   GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@t', GIT_CONFIG_NOSYSTEM='1',
                   GIT_CONFIG_GLOBAL=os.devnull)

        def git(*args, cwd=repo):
            return subprocess.run(['git', *args], cwd=cwd, env=env, check=True,
                                  capture_output=True, text=True).stdout.strip()

        repo.mkdir()
        git('init', '-q', '-b', 'main')
        (repo / 'README').write_text('base\n')
        git('add', 'README')
        git('commit', '-q', '-m', 'base')
        git('checkout', '-q', '-b', 'agent/T1')            # workflow "Create agent branch"
        git('checkout', '-q', '-b', '001-feature', 'main')  # run-task.sh ensure_feature_branch
        (repo / 'impl.txt').write_text('implementation\n')
        git('add', 'impl.txt')
        git('commit', '-q', '-m', 'Implement T1')
        (repo / 'state.txt').write_text('status: done\n')  # left for the state commit
        for label in ('Commit any state changes', 'Bundle agent branch'):
            subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', step_script(source, label)],
                           cwd=repo, env=env, check=True, capture_output=True)
        result = git('rev-parse', 'HEAD')
        bundle = runner / 'agent-result' / 'branch.bundle'
        heads = git('bundle', 'list-heads', str(bundle)).splitlines()
        imported = work / 'imported'
        git('clone', '-q', '--branch', 'agent/T1', str(bundle), str(imported), cwd=work)
        exposed = (imported / 'impl.txt').exists() and (imported / 'state.txt').exists()
        return heads, result, exposed


heads, result, exposed = bundled_result(agent)
assert heads == [f'{result} refs/heads/agent/T1'], (heads, result)
assert exposed, 'bundled agent branch lacks the implementation and state commits'
print('PASS: T141/T191 CI executable inputs, credential boundary, opencode deny rules and rejection fixtures')
PY
