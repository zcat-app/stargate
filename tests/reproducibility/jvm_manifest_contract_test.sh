#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# Contract for the production manifest in jvm_test.sh. Keep the extraction
# narrow so this test exercises the exact comparator function without running
# its Maven build harness.

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PRODUCTION="$REPO_ROOT/tests/reproducibility/jvm_test.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

manifest_definition="$(sed -n '/^manifest() {$/,/^}$/p' "$PRODUCTION")"
[ -n "$manifest_definition" ] || {
  echo 'FAIL: production manifest() definition was not found' >&2
  exit 1
}
# shellcheck disable=SC1090
source <(printf '%s\n' "$manifest_definition")

fixture="$WORK/build"
metadata='./control-plane/runtime/target/quarkus-artifact.properties'
fast_jar='./control-plane/runtime/target/quarkus-app/quarkus-artifact.properties'
retained='./control-plane/runtime/target/quarkus-app/quarkus/generated-bytecode.jar'
mkdir -p "$fixture/control-plane/runtime/target/quarkus-app/quarkus"
printf 'metadata.library-dir=/tmp/build-a\n' > "$fixture/$metadata"
printf 'fast-jar-properties=retained\n' > "$fixture/$fast_jar"
printf 'artifact bytes\n' > "$fixture/$retained"

first_manifest="$(manifest "$fixture")"
if grep -Fq "  $metadata" <<<"$first_manifest"; then
  echo "FAIL: exact unshipped metadata is included: $metadata" >&2
  exit 1
fi
grep -Fq "  $fast_jar" <<<"$first_manifest" || {
  echo "FAIL: identically named fast-jar file was excluded: $fast_jar" >&2
  exit 1
}

printf 'changed artifact bytes\n' > "$fixture/$retained"
second_manifest="$(manifest "$fixture")"
if [ "$first_manifest" = "$second_manifest" ]; then
  echo "FAIL: retained artifact byte change did not change manifest: $retained" >&2
  exit 1
fi

echo 'OK: exact root metadata excluded; fast-jar same-name file retained; retained bytes affect manifest'
