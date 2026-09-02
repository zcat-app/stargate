#!/bin/sh
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# extension/run-tests.sh — discovery runner for extension JS unit tests
# (T034b). verify.sh Gate 2b executes this; CI installs Node 20 through
# .github/actions/setup-toolchain per the research.md §10 CI pin.
#
# Discovers every *.test.js under extension/ (excluding the dist/ build
# output) and runs each directly with node — a file that drives node:test
# reports results and exits non-zero on failure without the --test flag,
# which keeps the runner identical across the Node 18–24 lines. No
# third-party deps, no package.json (research.md §10).
#
# Future extension test files (T034c popup, T034d firstparty, T034e
# options) are picked up automatically by the discovery pattern — no
# per-task runner amendments.

set -u

cd "$(dirname "$0")" || exit 1

if ! command -v node >/dev/null 2>&1; then
  echo "run-tests.sh: node not found on PATH — extension tests require Node (20 LTS pinned, research.md §10)" >&2
  exit 1
fi

NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')

if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "run-tests.sh: node $(node --version) is too old — node:test requires >= 18; the CI pin is Node 20 LTS (research.md §10)" >&2
  exit 1
fi

if [ "$NODE_MAJOR" -lt 20 ]; then
  echo "run-tests.sh: WARNING: node $(node --version) is below the Node 20 LTS CI pin (research.md §10) — running anyway; CI is the authoritative gate" >&2
fi

TEST_FILES=$(find . -name '*.test.js' -type f -not -path './dist/*' | sort)

if [ -z "$TEST_FILES" ]; then
  echo "run-tests.sh: no *.test.js found under extension/ — nothing to run" >&2
  exit 0
fi

rc=0
for f in $TEST_FILES; do
  echo "run-tests.sh: node $f"
  node "$f" || rc=1
done
exit $rc
