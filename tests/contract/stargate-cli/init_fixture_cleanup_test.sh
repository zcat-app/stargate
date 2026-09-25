#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T146: a forced fixture failure must release its own projects, not a peer's.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo 'SKIP: Docker daemon unavailable (fixture cleanup needs a daemon).'
  exit 0
fi

probe="$(mktemp -d)"
suffix="t146-$$-$(date +%s)"
foreign="${suffix}-foreign"
volume="${foreign}_sentinel"
trap 'docker volume rm "$volume" >/dev/null 2>&1 || true; rm -rf "$probe"' EXIT
docker volume create --label "com.docker.compose.project=$foreign" "$volume" >/dev/null

if T146_FIXTURE_SUFFIX="$suffix" T146_FORCE_FAILURE=1 \
    bash tests/contract/stargate-cli/init_docker_test.sh >"$probe/out" 2>&1; then
  echo 'FAIL: injected fixture failure returned success' >&2
  exit 1
fi
grep -q 'T146 injected failure after project A provisioning' "$probe/out" || {
  cat "$probe/out" >&2
  echo 'FAIL: fixture did not reach the forced failure' >&2
  exit 1
}
for project in "t088isoa-$suffix" "t088isob-$suffix"; do
  [ -z "$(docker volume ls --filter "label=com.docker.compose.project=$project" -q)" ] || {
    echo "FAIL: owned volumes leaked for $project" >&2; exit 1;
  }
  [ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ] || {
    echo "FAIL: owned containers leaked for $project" >&2; exit 1;
  }
done
docker volume inspect "$volume" >/dev/null 2>&1 || {
  echo 'FAIL: fixture cleanup removed a foreign volume' >&2
  exit 1
}
echo 'PASS: forced fixture failure cleaned owned resources and preserved a foreign volume'
