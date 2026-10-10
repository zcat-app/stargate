#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T075: exercise Gate 5's real selection block, its Docker-cadence wiring,
# and T075's named-resource cleanup/failure behavior without doing Docker
# builds. The real two-build comparison is run separately on the local daemon.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
verify="$repo_root/scripts/verify.sh"
workflow="$repo_root/.github/workflows/docker-cadence.yml"
repro_script="$repo_root/tests/reproducibility/data_plane_test.sh"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/stargate-t075-contract.XXXXXX")"
trap 'rm -rf -- "$scratch"' EXIT
errors=()
bail() { errors+=("$*"); }

for path in "$verify" "$workflow" "$repro_script"; do
  [ -f "$path" ] || { echo "FAIL: missing $path" >&2; exit 1; }
done

# Isolate and execute the production Gate 5 block with fixture scripts. This
# keeps the test focused: no Go, Maven, extension, or unrelated contract gate.
awk '/^# === Gate 5:/{copy=1} /^# === Summary/{copy=0} copy {print}' "$verify" > "$scratch/gate5.sh"
[ -s "$scratch/gate5.sh" ] || { echo "FAIL: could not extract Gate 5 block" >&2; exit 1; }
mkdir -p "$scratch/repo/tests/reproducibility"
cat > "$scratch/repo/tests/reproducibility/a_test.sh" <<'EOF'
#!/usr/bin/env bash
echo "fixture-ran:a"
EOF
cat > "$scratch/repo/tests/reproducibility/b_test.sh" <<'EOF'
#!/usr/bin/env bash
echo "fixture-ran:b"
EOF
cat > "$scratch/repo/tests/reproducibility/fail_test.sh" <<'EOF'
#!/usr/bin/env bash
echo "fixture-ran:fail"
exit 7
EOF
chmod +x "$scratch/repo/tests/reproducibility/"*.sh

cat > "$scratch/harness.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
declare -a G_NAME=() G_STATE=() G_NOTE=()
FAILED=0
say() { printf '%s\n' "$*"; }
record() {
  G_NAME+=("$1"); G_STATE+=("$2"); G_NOTE+=("${3:-}")
  [ "$2" = FAIL ] && FAILED=1
  say "[$2] $1 ${3:+— $3}"
}
run_cmd() {
  local name="$1" out rc=0
  shift; [ "${1:-}" = -- ] && shift
  out="$("$@" 2>&1)" || rc=$?
  printf '%s\n' "$out"
  if [ "$rc" -ne 0 ]; then record "$name" FAIL "exit $rc"
  elif printf '%s\n' "$out" | grep -q '^SKIP:'; then record "$name" SKIP "self-reported skip"
  else record "$name" PASS
  fi
}
EOF
cat "$scratch/gate5.sh" >> "$scratch/harness.sh"
cat >> "$scratch/harness.sh" <<'EOF'
if [ "$FAILED" -eq 0 ]; then echo 'RESULT: GREEN'; exit 0; fi
echo 'RESULT: RED'; exit 1
EOF
chmod +x "$scratch/harness.sh"

run_gate() {
  local name="$1"; shift
  (cd "$scratch/repo" && env -u STARGATE_VERIFY_REPRO -u STARGATE_VERIFY_REPRO_ONLY "$@" bash "$scratch/harness.sh") > "$scratch/$name.out" 2>&1 || :
}

run_gate default_off STARGATE_VERIFY_REPRO=0
grep -q 'release-cadence; set STARGATE_VERIFY_REPRO=1' "$scratch/default_off.out" \
  || bail "Gate 5 default-off behavior changed"
! grep -q 'fixture-ran:' "$scratch/default_off.out" || bail "default-off Gate 5 ran a fixture"

run_gate all_scripts STARGATE_VERIFY_REPRO=1
grep -q 'fixture-ran:a' "$scratch/all_scripts.out" || bail "unset selector omitted fixture a"
grep -q 'fixture-ran:b' "$scratch/all_scripts.out" || bail "unset selector omitted fixture b"
grep -q 'fixture-ran:fail' "$scratch/all_scripts.out" || bail "unset selector omitted fixture failure script"
grep -q 'RESULT: RED' "$scratch/all_scripts.out" || bail "unset selector did not record fixture failure as RED"

run_gate selected STARGATE_VERIFY_REPRO=1 STARGATE_VERIFY_REPRO_ONLY=a_test.sh
grep -q 'fixture-ran:a' "$scratch/selected.out" || bail "exact selector did not run selected fixture"
! grep -qE 'fixture-ran:(b|fail)' "$scratch/selected.out" || bail "exact selector ran sibling fixture"
grep -q 'sibling reproducibility gates excluded (not a release-wide reproducibility pass)' "$scratch/selected.out" \
  || bail "selected Gate 5 output overstates coverage or omits sibling exclusion"
grep -q 'RESULT: GREEN' "$scratch/selected.out" || bail "selected passing fixture did not report green"

for selector_case in empty path glob unknown; do
  case "$selector_case" in
    empty) selector='' ;;
    path) selector='tests/reproducibility/a_test.sh' ;;
    glob) selector='*_test.sh' ;;
    unknown) selector='missing_test.sh' ;;
  esac
  run_gate "invalid_$selector_case" STARGATE_VERIFY_REPRO=1 "STARGATE_VERIFY_REPRO_ONLY=$selector"
  grep -q '\[FAIL\] reproducibility-selection' "$scratch/invalid_$selector_case.out" \
    || bail "$selector_case selector did not fail closed"
  ! grep -q 'fixture-ran:' "$scratch/invalid_$selector_case.out" \
    || bail "$selector_case selector ran a fixture"
done

run_gate selector_without_gate STARGATE_VERIFY_REPRO=0 STARGATE_VERIFY_REPRO_ONLY=a_test.sh
grep -q '\[FAIL\] reproducibility-selection' "$scratch/selector_without_gate.out" \
  || bail "selector with disabled Gate 5 did not fail closed"

run_gate selected_failure STARGATE_VERIFY_REPRO=1 STARGATE_VERIFY_REPRO_ONLY=fail_test.sh
grep -q 'fixture-ran:fail' "$scratch/selected_failure.out" || bail "selected failing script did not run"
grep -q 'RESULT: RED' "$scratch/selected_failure.out" || bail "selected script failure was not recorded RED"

# Workflow contract: same entrypoint only, exact selector, and complete path
# coverage for every source copied into the builder plus the selector wiring.
python3 - "$workflow" <<'PY' || bail "Docker-cadence workflow wiring or path filters are incomplete"
from pathlib import Path
import re, sys

text = Path(sys.argv[1]).read_text()
required_paths = (
    "data-plane/**", "proto/**", ".dockerignore",
    "tests/reproducibility/data_plane_test.sh",
    "tests/contract/workflow/data_plane_repro_gate_test.sh",
    "scripts/verify.sh", ".github/workflows/docker-cadence.yml",
)
for event in ("push:", "pull_request:"):
    block = re.search(r"(?ms)^  " + re.escape(event[:-1]) + r":\n(.*?)(?=^  [a-z_]+:|^permissions:)", text)
    if not block:
        raise SystemExit(f"missing {event} path trigger")
    missing = [p for p in required_paths if f"'{p}'" not in block.group(1)]
    if missing:
        raise SystemExit(f"{event} missing path filters: {missing}")
if len(re.findall(r"(?m)^\s*run:\s*\|\s*$", text)) != 1 or not re.search(r"(?m)^\s+bash scripts/verify\.sh\s*$", text):
    raise SystemExit("workflow must keep scripts/verify.sh as its only run entrypoint")
if not re.search(r"(?m)^\s+STARGATE_VERIFY_REPRO: '1'\s*$", text):
    raise SystemExit("workflow must enable Gate 5")
if not re.search(r"(?m)^\s+STARGATE_VERIFY_REPRO_ONLY: data_plane_test\.sh\s*$", text):
    raise SystemExit("workflow must select only data_plane_test.sh")
PY

# Exercise the actual reproducibility script behind a fake Docker executable.
# Each invocation receives its own TMPDIR and sentinel; cleanup may remove
# only that run's named Docker objects and its generated temp directory.
mkdir -p "$scratch/fake-bin"
cat > "$scratch/fake-bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$FAKE_DOCKER_LOG"
printf '\n' >> "$FAKE_DOCKER_LOG"
case "${1:-}" in
  info)
    if [ "${2:-}" = --format ]; then printf 'linux/amd64\n'; fi
    ;;
  build)
    count_file="$FAKE_DOCKER_STATE/build-count"
    count=0; [ ! -f "$count_file" ] || read -r count < "$count_file"
    count=$((count + 1)); printf '%s\n' "$count" > "$count_file"
    printf '%s\n' "$@" > "$FAKE_DOCKER_STATE/build-args-$count"
    tag=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --tag ]; then tag="$2"; break; fi
      shift
    done
    if [ -z "$tag" ]; then echo 'fake docker: build omitted --tag' >&2; exit 91; fi
    if [ "$FAKE_DOCKER_SCENARIO" = build_failure ] && [ "$count" -eq 2 ]; then exit 23; fi
    printf '%s\n' "$tag" >> "$FAKE_DOCKER_STATE/acquired-images"
    ;;
  create)
    container=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --name ]; then container="$2"; break; fi
      shift
    done
    [ -n "$container" ] || { echo 'fake docker: create omitted --name' >&2; exit 92; }
    printf '%s\n' "$container" >> "$FAKE_DOCKER_STATE/acquired-containers"
    ;;
  cp)
    source="$2"; dest="$3"
    case "$FAKE_DOCKER_SCENARIO" in
      missing_output) exit 24 ;;
      empty_output) : > "$dest" ;;
      mismatch)
        case "$source" in *-one:*) printf 'first-binary' > "$dest" ;; *) printf 'second-binary' > "$dest" ;; esac
        ;;
      *) printf 'same-binary' > "$dest" ;;
    esac
    ;;
  rm)
    shift
    [ "${1:-}" != -f ] || shift
    for container in "$@"; do
      printf 'container %s\n' "$container" >> "$FAKE_DOCKER_STATE/removal-attempts"
      if [ -f "$FAKE_DOCKER_STATE/acquired-containers" ] \
        && grep -Fxq "$container" "$FAKE_DOCKER_STATE/acquired-containers" \
        && { [ ! -f "$FAKE_DOCKER_STATE/removed-containers" ] \
          || ! grep -Fxq "$container" "$FAKE_DOCKER_STATE/removed-containers"; }; then
        printf '%s\n' "$container" >> "$FAKE_DOCKER_STATE/removed-containers"
      fi
    done
    ;;
  image)
    [ "${2:-}" = rm ] || exit 93
    shift 2
    [ "${1:-}" != -f ] || shift
    for image in "$@"; do
      printf 'image %s\n' "$image" >> "$FAKE_DOCKER_STATE/removal-attempts"
      if [ -f "$FAKE_DOCKER_STATE/acquired-images" ] \
        && grep -Fxq "$image" "$FAKE_DOCKER_STATE/acquired-images" \
        && { [ ! -f "$FAKE_DOCKER_STATE/removed-images" ] \
          || ! grep -Fxq "$image" "$FAKE_DOCKER_STATE/removed-images"; }; then
        printf '%s\n' "$image" >> "$FAKE_DOCKER_STATE/removed-images"
      fi
    done
    ;;
  *) echo "unexpected docker invocation: $*" >&2; exit 90 ;;
esac
EOF
chmod +x "$scratch/fake-bin/docker"

assert_build_args() {
  local state="$1" expected_builds="$2" count_file="$state/build-count" count=0 ordinal
  [ ! -f "$count_file" ] || read -r count < "$count_file"
  [ "$count" -eq "$expected_builds" ] || {
    echo "FAIL: expected $expected_builds docker build calls, got $count" >&2
    return 1
  }
  for ((ordinal = 1; ordinal <= count; ordinal++)); do
    local -a args=()
    mapfile -t args < "$state/build-args-$ordinal"
    if [ "${#args[@]}" -ne 9 ] \
      || [ "${args[0]:-}" != build ] \
      || [ "${args[1]:-}" != --no-cache ] \
      || [ "${args[2]:-}" != --target ] \
      || [ "${args[3]:-}" != builder ] \
      || [ "${args[4]:-}" != --file ] \
      || [ "${args[5]:-}" != data-plane/Dockerfile ] \
      || [ "${args[6]:-}" != --tag ] \
      || [ "${args[8]:-}" != . ]; then
      echo "FAIL: docker build $ordinal arguments differ from the T075 contract" >&2
      return 1
    fi
    local expected_suffix=two
    [ "$ordinal" -ne 1 ] || expected_suffix=one
    case "${args[7]}" in
      stargate-t075:*-"$expected_suffix") ;;
      *) echo "FAIL: docker build $ordinal tag is not invocation-scoped: ${args[7]}" >&2; return 1 ;;
    esac
  done
}

assert_owned_resources_removed() {
  local state="$1" name resource_id="" resource ids="$scratch/resource-ids"
  : > "$ids"
  for name in "$state"/acquired-images "$state"/acquired-containers "$state"/removal-attempts; do
    [ ! -f "$name" ] || while IFS= read -r item; do
      case "$item" in
        *' '*) resource="${item#* }" ;;
        *) resource="$item" ;;
      esac
      case "$resource" in
        stargate-t075:*-one|stargate-t075:*-two)
          resource_id="${resource#stargate-t075:}"; resource_id="${resource_id%-one}"; resource_id="${resource_id%-two}"
          printf '%s\n' "$resource_id" >> "$ids"
          ;;
        stargate-t075-*-one|stargate-t075-*-two)
          resource_id="${resource#stargate-t075-}"; resource_id="${resource_id%-one}"; resource_id="${resource_id%-two}"
          printf '%s\n' "$resource_id" >> "$ids"
          ;;
        *) echo "FAIL: Docker resource escaped the T075 invocation namespace: $item" >&2; return 1 ;;
      esac
    done < "$name"
  done
  [ "$(sort -u "$ids" | wc -l | tr -d ' ')" -le 1 ] || {
    echo 'FAIL: one fake-Docker run used more than one resource id' >&2
    return 1
  }
  for resource in images containers; do
    local acquired="$state/acquired-$resource" removed="$state/removed-$resource"
    : > "$scratch/acquired.sorted"; : > "$scratch/removed.sorted"
    [ ! -f "$acquired" ] || sort -u "$acquired" > "$scratch/acquired.sorted"
    [ ! -f "$removed" ] || sort -u "$removed" > "$scratch/removed.sorted"
    if ! diff -u "$scratch/acquired.sorted" "$scratch/removed.sorted"; then
      echo "FAIL: acquired $resource were not all removed exactly once" >&2
      return 1
    fi
  done
}

run_fake_docker() {
  local scenario="$1" expected_rc="$2"
  local state="$scratch/docker-$scenario" tmp="$scratch/tmp-$scenario"
  mkdir -p "$state" "$tmp"
  printf 'keep-me\n' > "$tmp/unowned-sentinel"
  : > "$scratch/docker-$scenario.log"
  local rc=0
  PATH="$scratch/fake-bin:$PATH" TMPDIR="$tmp" \
    FAKE_DOCKER_SCENARIO="$scenario" FAKE_DOCKER_STATE="$state" \
    FAKE_DOCKER_LOG="$scratch/docker-$scenario.log" \
    bash "$repro_script" > "$scratch/docker-$scenario.out" 2>&1 || rc=$?
  [ "$rc" -eq "$expected_rc" ] || bail "$scenario returned $rc; expected $expected_rc"
  case "$scenario" in
    green|mismatch) expected_builds=2 ;;
    build_failure) expected_builds=2 ;;
    *) expected_builds=1 ;;
  esac
  assert_build_args "$state" "$expected_builds" || bail "$scenario Docker build argv assertion failed"
  assert_owned_resources_removed "$state" || bail "$scenario acquired-resource cleanup assertion failed"
  [ -f "$tmp/unowned-sentinel" ] || bail "$scenario cleanup deleted an unowned TMPDIR file"
  [ "$(find "$tmp" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" = 1 ] \
    || bail "$scenario left a task temp directory behind"
}

run_fake_docker green 0
grep -q '^PASS:' "$scratch/docker-green.out" || bail "fake-Docker equal outputs did not pass"
run_fake_docker mismatch 1
grep -q 'outputs differ' "$scratch/docker-mismatch.out" || bail "mismatched output did not fail at cmp"
run_fake_docker missing_output 24
run_fake_docker empty_output 1
grep -q 'missing or empty' "$scratch/docker-empty_output.out" || bail "empty output did not fail explicitly"
run_fake_docker build_failure 23

# Mutation probe: a copy of the production script with --no-cache removed
# must be rejected by the same recorded-argv assertion above.
sed 's/docker build --no-cache --target builder/docker build --target builder/' \
  "$repro_script" > "$scratch/mutated-data-plane_test.sh"
chmod +x "$scratch/mutated-data-plane_test.sh"
state="$scratch/docker-mutated"
tmp="$scratch/tmp-mutated"
mkdir -p "$state" "$tmp"
: > "$scratch/docker-mutated.log"
PATH="$scratch/fake-bin:$PATH" TMPDIR="$tmp" FAKE_DOCKER_SCENARIO=green \
  FAKE_DOCKER_STATE="$state" FAKE_DOCKER_LOG="$scratch/docker-mutated.log" \
  bash "$scratch/mutated-data-plane_test.sh" > "$scratch/docker-mutated.out" 2>&1 \
  || bail "the controlled --no-cache mutation prevented test execution"
if assert_build_args "$state" 2 > "$scratch/mutation-assert.out" 2>&1; then
  bail "the build-argument contract did not detect the --no-cache mutation"
fi
assert_owned_resources_removed "$state" || bail "mutation-probe resources were not cleaned up"

if [ "${#errors[@]}" -gt 0 ]; then
  printf 'FAIL: data_plane_repro_gate_test.sh — %d assertion(s) failed:\n' "${#errors[@]}" >&2
  printf '  - %s\n' "${errors[@]}" >&2
  exit 1
fi
echo "PASS: data_plane_repro_gate_test.sh — Gate 5 selection, workflow inputs, and bounded Docker failure cleanup."
