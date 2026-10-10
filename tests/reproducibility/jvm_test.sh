#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/reproducibility/jvm_test.sh — T098.
#
# Gates the byte-reproducibility claim for the JVM control-plane build
# (arch §12.2, Constitution Principle VI): two clean `mvnw package` builds
# of the same source bytes must produce byte-identical build outputs even
# when the source copies carry different mtimes — nothing about the build
# host may leak into the JVM artifacts (jars, classes, the Quarkus
# fast-jar layout).
#
# Copied inputs: control-plane/ AND proto/ as repo-root siblings. The api
# module's GrpcCodeGen reads ../../proto/stargate/v1 relative to its
# basedir (api/pom.xml), so a copy without proto/ builds a hollow api jar
# (codegen silently produces nothing, compile has nothing to compile) and
# the gate would compare an empty artifact. The anti-hollow guards below
# re-assert that the api jar actually contains the generated stubs.
#
# Falsification case: source trees with identical bytes but deliberately
# different mtimes (tree A: 2024, tree B: 2031), perturbed per-file.
# Comparing two builds that share one source mtime set would reconfirm
# whatever the toolchain does instead of testing reproducibility, so the
# perturbation is the point of the test.
#
# Scope: the JVM tier only. Native-image is best-effort by the
# Constitution (Principle VI) and is built with -Pnative outside this
# test; any unavoidable native variation belongs in BUILD-DIFFS.md.
#
# Unit tests are NOT executed here on purpose (-DskipTests): the gated
# property is packaging determinism, and test execution is Gate 3's job
# (scripts/verify.sh `mvnw verify`). Running the Quarkus test suite twice
# per reproducibility check would triple the runtime for zero added
# falsification power over the byte comparison.
#
# Compared: every file under */target/ except maven-status/ (compiler
# bookkeeping), quarkus-grpc*.sh (protoc invocation scratch left in the
# module target root by quarkus-grpc codegen: random per-build name, embeds
# host paths — JVM home, local ~/.m2 — and is never packaged into any jar;
# verified against api-*.jar and quarkus-run.jar), and the exact
# ./control-plane/runtime/target/quarkus-artifact.properties path. That file
# records metadata.library-dir as an absolute temporary build root and is not
# shipped: the release Dockerfile copies runtime/target/quarkus-app only, and
# no build/runtime consumer reads the separate target-root file. Both JVM
# comparators omit this exact path; identically named files under quarkus-app
# and all other shipped outputs remain byte-compared.
#
# Release cadence: opt-in via STARGATE_VERIFY_REPRO=1 (scripts/verify.sh
# Gate 5). CI wiring for PRs touching control-plane/ is T076.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

command -v java >/dev/null 2>&1 || { echo "SKIP: java not available"; exit 0; }
command -v sha256sum >/dev/null 2>&1 || { echo "SKIP: sha256sum not available"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not available"; exit 0; }
[ -x control-plane/mvnw ] || { echo "SKIP: control-plane/mvnw absent"; exit 0; }
[ -d proto/stargate/v1 ] || { echo "SKIP: proto/stargate/v1 absent"; exit 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() {
  echo "FAIL: $1 (T098)" >&2
  shift
  local line
  for line in "$@"; do echo "  $line" >&2; done
  exit 1
}

# --- two clean copies, perturbed differently --------------------------------
# Siblings under each tree root so api/pom.xml's ../../proto reference
# resolves inside the copy, never back at the live repo.
for tree in a b; do
  mkdir -p "$WORK/$tree"
  cp -a control-plane proto "$WORK/$tree/"
done

# Drop any build outputs from the copies: the gate is a *clean* build, not
# a re-verification of a stale target/ tree.
find "$WORK/a" "$WORK/b" -type d -name target -prune -exec rm -rf {} + 2>/dev/null

perturb() {
  local dir="$1" base_epoch="$2" i=0 f
  base_epoch="$(date -d "$base_epoch" +%s)"
  while IFS= read -r f; do
    i=$((i + 1))
    touch -d "@$((base_epoch + i))" "$dir/$f"
  done < <(cd "$dir" && find . -type f | LC_ALL=C sort)
}
perturb "$WORK/a" "2024-03-01 00:00:00 UTC"
perturb "$WORK/b" "2031-11-05 00:00:00 UTC"

# --- build both trees --------------------------------------------------------
for tree in a b; do
  (cd "$WORK/$tree/control-plane" && ./mvnw -B -ntp clean package -DskipTests) \
    > "$WORK/$tree.log" 2>&1 \
    || fail "mvnw clean package failed in copy $tree" "$(tail -20 "$WORK/$tree.log")"
done

# --- harness sanity: the gate is only meaningful if real artifacts were built
# One jar per module (5), and the api jar must carry the gRPC stubs — a copy
# that lost proto/ builds an empty api jar and this gate goes hollow.
n_jars="$(find "$WORK/a" -path '*/target/*' -type f -name '*.jar' | wc -l | tr -d ' ')"
[ "$n_jars" -ge 5 ] \
  || fail "copy a produced only $n_jars jars — harness bug, gate would be hollow"
api_jar="$(echo "$WORK/a/control-plane/api/target/api-"*.jar)"
n_stubs="$(python3 -c "
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as zf:
    print(sum(1 for n in zf.namelist()
              if n.startswith('stargate/v1/') and n.endswith('.class')))
" "$api_jar")"
[ "$n_stubs" -ge 10 ] \
  || fail "copy a's api jar carries only $n_stubs stub classes — proto inputs were missing, gate would be hollow"

# --- the byte-identity gate --------------------------------------------------
manifest() {
  (cd "$1" && find . -path '*/target/*' -type f \
    -not -path '*/target/maven-status/*' -not -name 'quarkus-grpc*.sh' \
    -not -path './control-plane/runtime/target/quarkus-artifact.properties' \
    -print0 | LC_ALL=C sort -z | xargs -0 sha256sum)
}
manifest "$WORK/a" > "$WORK/a.sha"
manifest "$WORK/b" > "$WORK/b.sha"

if ! diff -u "$WORK/a.sha" "$WORK/b.sha" > "$WORK/diff.txt" 2>&1; then
  n_files="$(wc -l < "$WORK/a.sha" | tr -d ' ')"
  fail "two clean builds from identical source bytes produced different outputs" \
    "$n_files build outputs compared; differing paths:" \
    "$(grep -E '^[+-][0-9a-f]{64}' "$WORK/diff.txt" | awk '{print $NF}' | sort -u | head -10 | sed 's/^/    /')" \
    "full hashes in $WORK/diff.txt (build logs: $WORK/*.log)"
fi

echo "OK: JVM build byte-reproducible across mtime perturbation" \
  "($(wc -l < "$WORK/a.sha" | tr -d ' ') build outputs identical, $n_stubs api stub classes)"
