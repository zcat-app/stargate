#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T185 (Constitution IV): every artifact the control-plane build resolves
# (dependencies, plugins, processors, extensions, POMs) must match a committed
# SHA-256 before it is used. A version string is not verification.
#
# Static half: the Maven Resolver trusted-checksums config and strict checksums
# are committed in control-plane/.mvn/maven.config, the Docker build copies it
# in before `mvn`, no build entrypoint overrides it, the lock is well formed, and
# no plugin version floats on repository metadata (which the lock cannot cover).
#
# Hermetic half: each case runs the real reactor offline against a scratch copy.
# The head local repository holds one tampered artifact, or the case removes one
# line from the copied lock. The developer's local repository is attached as a
# read-only chained tail (maven.repo.local.tail) and is never modified. Every case must fail
# with the resolver's checksum error before any class is compiled.
# scripts/verify.sh runs the Maven gate before the contract tests, so the tail
# already holds the locked artifacts; a missing one is a FAIL, not a SKIP.
set -euo pipefail

if [ "${STARGATE_SKIP_CP:-0}" = "1" ]; then
  echo "SKIP: STARGATE_SKIP_CP=1 (control-plane gate disabled)"
  exit 0
fi

python3 - "$(git rev-parse --show-toplevel)" <<'PY'
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

root = pathlib.Path(sys.argv[1])
cp = root / 'control-plane'
config = cp / '.mvn/maven.config'
lock = cp / '.mvn/checksums/checksums.sha256'
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


# --- static: committed resolver policy ---------------------------------------
REQUIRED = [
    '--strict-checksums',
    '-Daether.trustedChecksumsSource.summaryFile=true',
    '-Daether.trustedChecksumsSource.summaryFile.basedir=${session.rootDirectory}/.mvn/checksums',
    '-Daether.trustedChecksumsSource.summaryFile.originAware=false',
    '-Daether.artifactResolver.postProcessor.trustedChecksums=true',
    '-Daether.artifactResolver.postProcessor.trustedChecksums.checksumAlgorithms=SHA-256',
    '-Daether.artifactResolver.postProcessor.trustedChecksums.failIfMissing=true',
]
config_lines = config.read_text().split() if config.is_file() else []
for line in REQUIRED:
    check(line in config_lines, f'maven.config lacks {line}')
# Record mode rewrites the lock instead of enforcing it; it is a refresh-only flag.
check(not any('record' in line or 'snapshots' in line for line in config_lines),
      'maven.config must not enable record mode or change snapshot handling')

dockerfile = (cp / 'Dockerfile').read_text()
instructions = [line.strip() for line in dockerfile.splitlines()
                if line.strip() and not line.lstrip().startswith('#')]
copy_at = next((i for i, line in enumerate(instructions)
                if re.match(r'COPY\s+control-plane/\.mvn\s', line)), None)
runs = [i for i, line in enumerate(instructions) if re.match(r'RUN\s+mvn\b', line)]
check(copy_at is not None and runs and all(copy_at < i for i in runs),
      'Dockerfile must COPY control-plane/.mvn before every RUN mvn')
# A settings file (-s/--settings, -gs/--global-settings) can carry resolver
# properties too, so it counts as an override like an inline -Daether.*.
# Any -s/-gs token matches, attached forms included (-sfile.xml); Maven has
# no other short option with that prefix.
OVERRIDE = re.compile(r'aether\.|lax-checksums|(^|\s)-c(\s|$)|maven\.repo\.local|(^|\s)-o(\s|$)|--offline'
                      r'|(^|\s)-g?s|--(global-)?settings')
for name, text in (('Dockerfile', dockerfile), ('verify.sh', (root / 'scripts/verify.sh').read_text())):
    for line in text.splitlines():
        invocation = re.search(r'(?:^|[\s;&|(])(?:\S*/)?mvnw?(\s.*|$)', line)
        if invocation and not line.lstrip().startswith('#'):
            # Only the Maven arguments: `sh -c '... mvnw ...'` wraps it legitimately.
            check(not OVERRIDE.search(invocation.group(1)),
                  f'{name} overrides the resolver policy: {line.strip()}')

entries = {}
LINE = re.compile(r'^([0-9a-f]{64})  (\S+)$')
for number, line in enumerate(lock.read_text().splitlines() if lock.is_file() else [], 1):
    match = LINE.match(line)
    check(match is not None, f'lock line {number} is not "<sha256>  <path>"')
    if match:
        check(match.group(2) not in entries, f'lock lists {match.group(2)} twice')
        entries[match.group(2)] = match.group(1)
ANCHORS = [
    'io/quarkus/platform/quarkus-bom/3.33.1/quarkus-bom-3.33.1.pom',
    'io/quarkus/platform/quarkus-maven-plugin/3.33.1/quarkus-maven-plugin-3.33.1.jar',
    'org/apache/maven/plugins/maven-compiler-plugin/3.15.0/maven-compiler-plugin-3.15.0.jar',
    'com/google/errorprone/error_prone_core/2.50.0/error_prone_core-2.50.0.jar',
    'com/uber/nullaway/nullaway/0.14.1/nullaway-0.14.1.jar',
    'io/github/zlika/reproducible-build-maven-plugin/0.17/reproducible-build-maven-plugin-0.17.jar',
    'io/smallrye/jandex-maven-plugin/3.6.0/jandex-maven-plugin-3.6.0.jar',
]
for anchor in ANCHORS:
    check(anchor in entries, f'lock does not cover {anchor}')

# The Dockerfile's base images are multi-arch (amd64 + arm64), and some
# artifacts are selected by the build host's OS/arch (Maven <os> profile
# activation, the gRPC codegen's protoc classifier). The hermetic cases below
# resolve only the host's closure, so every supported Linux platform's
# selected native must be locked explicitly, or an arm64 build fails closed.
PLATFORM_SELECTED = (
    'com/aayushatharva/brotli4j/native-linux-{brotli}/1.16.0/native-linux-{brotli}-1.16.0.jar',
    'com/aayushatharva/brotli4j/native-linux-{brotli}/1.16.0/native-linux-{brotli}-1.16.0.pom',
    'com/google/protobuf/protoc/4.33.2/protoc-4.33.2-linux-{protoc}.exe',
    'io/grpc/protoc-gen-grpc-java/1.79.0/protoc-gen-grpc-java-1.79.0-linux-{protoc}.exe',
)
for template in PLATFORM_SELECTED:
    for brotli, protoc in (('x86_64', 'x86_64'), ('aarch64', 'aarch_64')):
        path = template.format(brotli=brotli, protoc=protoc)
        check(path in entries, f'lock does not cover the {brotli} platform artifact {path}')

# No amd64 build (verify.sh, the hermetic cases, the default image build)
# resolves these arm64-only entries, so a corrupted digest would pass every
# amd64 gate and only break arm64 builds. They were recorded under strict
# Central checksums by aarch64 profile-activation emulation and are not
# build-confirmed (T185 Acceptance 1). This second, reviewed copy makes any
# later change to them fail here, not first on an arm64 host.
# A lock refresh that changes them must update these values in the same review.
ARM64_ONLY = {
    'com/aayushatharva/brotli4j/native-linux-aarch64/1.16.0/native-linux-aarch64-1.16.0.jar':
        '0f4cf2ea3dfb361daa3393f4dc345fabfb1a99e31d8b0bb6ed91dac56a38c11a',
    'com/aayushatharva/brotli4j/native-linux-aarch64/1.16.0/native-linux-aarch64-1.16.0.pom':
        '5e77f056fc2efbac4c75532b060aea5b3836a18dbdd17a444e9a1f0d5d3043b5',
}
for path, digest in ARM64_ONLY.items():
    check(entries.get(path) == digest,
          f'arm64-only lock entry {path} is {entries.get(path)}, reviewed value {digest}')

# The pinned jandex version must be the locked one; a metadata-resolved
# version would let an upstream release change what executes.
pom = (cp / 'pom.xml').read_text()
check(re.search(r'<artifactId>jandex-maven-plugin</artifactId>\s*<version>3\.6\.0</version>', pom),
      'root pom.xml must pin io.smallrye:jandex-maven-plugin at the locked 3.6.0')

# --- hermetic: tampered and unlisted artifacts fail before compilation --------
runnable = shutil.which('java') is not None
if not runnable:
    failures.append('java is required for the hermetic lock cases')
tail = pathlib.Path(os.environ.get('HOME', '/nonexistent')) / '.m2/repository'
POM = 'io/quarkus/platform/quarkus-bom/3.33.1/quarkus-bom-3.33.1.pom'
PLUGIN = 'org/apache/maven/plugins/maven-compiler-plugin/3.15.0/maven-compiler-plugin-3.15.0.jar'
PROCESSOR = 'com/google/errorprone/error_prone_core/2.50.0/error_prone_core-2.50.0.jar'
for rel in (POM, PLUGIN, PROCESSOR):
    if not (tail / rel).is_file():
        runnable = False
        failures.append(f'{tail / rel} absent: run the mvnw-verify gate first')


def tree_copy(work):
    ignore = shutil.ignore_patterns('target')
    shutil.copytree(cp, work / 'control-plane', ignore=ignore, symlinks=True)
    shutil.copytree(root / 'proto', work / 'proto', ignore=ignore)
    return work / 'control-plane'


def plant(head, rel, tamper):
    # The tracking file travels with the artifact so the enhanced local repo
    # serves the head copy offline instead of falling through to the tail.
    target = head / rel
    target.parent.mkdir(parents=True)
    shutil.copy2(tail / rel, target)
    tracking = (tail / rel).parent / '_remote.repositories'
    if tracking.is_file():
        shutil.copy2(tracking, target.parent / tracking.name)
    tamper(target)


def append_comment(path):
    # Still a well-formed POM: only the committed hash can tell.
    with open(path, 'a') as handle:
        handle.write('\n<!-- stargate T185 tamper -->\n')


def add_entry(path):
    # Still a loadable jar: only the committed hash can tell.
    with zipfile.ZipFile(path, 'a') as archive:
        archive.writestr('META-INF/stargate-t185-tamper.txt', 'tampered\n')


def drop_lock_line(rel):
    def edit(copy):
        path = copy / '.mvn/checksums/checksums.sha256'
        if not path.is_file():
            return
        kept = [line for line in path.read_text().splitlines() if not line.endswith('  ' + rel)]
        path.write_text('\n'.join(kept) + '\n')
    return edit


CASES = [
    ('tampered import POM', lambda head: plant(head, POM, append_comment), None,
     'io.quarkus.platform:quarkus-bom:pom:3.33.1 trusted checksum mismatch'),
    ('tampered plugin jar', lambda head: plant(head, PLUGIN, add_entry), None,
     'org.apache.maven.plugins:maven-compiler-plugin:jar:3.15.0 trusted checksum mismatch'),
    ('unlisted processor jar', lambda head: None, drop_lock_line(PROCESSOR),
     'Missing from summaryFile trusted checksum(s) [SHA-256] for artifact '
     'com.google.errorprone:error_prone_core:jar:2.50.0'),
]

if runnable:
    env = {k: v for k, v in os.environ.items() if k not in ('MAVEN_ARGS', 'MAVEN_OPTS', 'MAVEN_CONFIG')}
    for name, prepare_head, prepare_copy, expected in CASES:
        with tempfile.TemporaryDirectory(prefix='stargate-t185-') as tmp:
            work = pathlib.Path(tmp)
            copy = tree_copy(work)
            head = work / 'head'
            head.mkdir()
            prepare_head(head)
            if prepare_copy:
                prepare_copy(copy)
            result = subprocess.run(
                ['sh', 'mvnw', '-B', '-ntp', '-o', f'-Dmaven.repo.local={head}',
                 f'-Dmaven.repo.local.tail={tail}', '-DskipTests', 'package'],
                cwd=copy, env=env, capture_output=True, text=True, timeout=1800)
            output = result.stdout + result.stderr
            classes = list(copy.glob('*/target/classes/**/*.class'))
            if result.returncode == 0:
                failures.append(f'{name}: build SUCCEEDED with the {name} (accepted, not verified)')
            elif expected not in output:
                tail_lines = '\n    '.join(output.splitlines()[-8:])
                failures.append(f'{name}: build failed without "{expected}":\n    {tail_lines}')
            if classes and result.returncode != 0:
                failures.append(f'{name}: {len(classes)} classes compiled before the check failed')

if failures:
    for message in failures:
        print(f'FAIL: {message} (T185)', file=sys.stderr)
    sys.exit(1)
print('PASS: control-plane Maven artifacts are verified against the committed SHA-256 lock (T185)')
PY
