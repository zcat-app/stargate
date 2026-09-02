#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# verify_skip_convention_test.sh — T108 regression probe.
#
# Falsifies the claim that got T108 filed: "a repro gate that skipped still
# summarizes as PASS". Three assertions carry the ticket:
#
#   1. WIRED    — verify.sh's run_cmd implements the sentinel: exit 0 plus
#                 a line starting "SKIP:" records SKIP; a nonzero exit
#                 records FAIL even with "SKIP:" in the output.
#                 (§Acceptance #1)
#   2. ADOPTED  — each of the three tests/reproducibility/ scripts, run
#                 with every gate tool hidden from PATH, exits 0 and emits
#                 the "SKIP:" sentinel. The scripts pre-date the convention
#                 (T098 review context), so their adoption is proven here
#                 rather than re-edited. (§Acceptance #2)
#   3. RECORDED — a harness built from verify.sh's OWN helper block and
#                 summary code drives fixture gates: a self-skipping gate
#                 lands SKIP (never PASS) and stays out of the PASS count;
#                 a gate that prints "SKIP:" but exits nonzero lands FAIL;
#                 a bash syntax error (exit 2) lands FAIL — the case that
#                 makes a sentinel convention mandatory over an exit-code
#                 one. (§Acceptance #3 — the run summary reflects skips.)
#
# HERMETIC: throwaway sandbox + shim PATH; no network, no docker builds.
# The repro runs skip at their first tool probe (~ms). Self-skip if bash
# or git is absent.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
VERIFY_SH="$REPO_ROOT/scripts/verify.sh"

command -v bash >/dev/null 2>&1 || { echo "SKIP: bash not installed"; exit 0; }
command -v git  >/dev/null 2>&1 || { echo "SKIP: git not installed";  exit 0; }
[ -f "$VERIFY_SH" ] || { echo "FAIL: $VERIFY_SH missing" >&2; exit 1; }

errs=()
bail() { errs+=("$*"); }

# --- 1. WIRED: run_cmd must implement both sentinel branches ---------------
grep -qE "grep -q '\^SKIP:'" "$VERIFY_SH" \
  || bail "run_cmd does not detect the ^SKIP: sentinel (§Acceptance #1)"
grep -qE 'record "\$name" SKIP' "$VERIFY_SH" \
  || bail "run_cmd has no SKIP record branch (§Acceptance #1)"
grep -qE 'run_cmd "repro:' "$VERIFY_SH" \
  || bail "Gate 5 no longer routes repro gates through run_cmd (§Acceptance #3)"

# --- 2. ADOPTED: repro scripts emit the sentinel with tools hidden ---------
SANDBOX="$(mktemp -d -t stargate-t108-XXXXXX)"
cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT

SHIM="$SANDBOX/bin"
mkdir "$SHIM"
# The only tools a repro script can reach before its first tool probe:
# bash (the interpreter), git (cd to toplevel), and mktemp + rm for the tor
# script's pre-probe sandbox and EXIT trap. Everything else stays hidden —
# hiding them IS the scenario under test (§Acceptance #3).
for tool in bash git mktemp rm; do
  ln -s "$(command -v "$tool")" "$SHIM/$tool" || bail "shim: cannot link $tool"
done

for t in jvm_test.sh extension_test.sh tor_sidecar_manifest_test.sh; do
  script="$REPO_ROOT/tests/reproducibility/$t"
  [ -f "$script" ] || { bail "missing repro script: $t"; continue; }
  out="$(PATH="$SHIM" bash "$script" 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] \
    || bail "$t exited $rc with tools hidden (want 0 + SKIP: sentinel)"
  printf '%s\n' "$out" | grep -q '^SKIP:' \
    || bail "$t emitted no SKIP: sentinel with tools hidden (output: $out)"
done

# --- 3. RECORDED: verify.sh's own helper + summary code, fixture gates -----
# The helper block lives entirely before the Gate 1 section header; the
# summary block from its header to EOF. If a future edit moves either
# anchor, extraction comes up empty and this probe FAILS (fail-closed).
awk '/^# === Gate 1:/{exit} {print}' "$VERIFY_SH" > "$SANDBOX/head.sh"
awk '/^# === Summary/{found=1} found {print}' "$VERIFY_SH" > "$SANDBOX/tail.sh"
[ -s "$SANDBOX/head.sh" ] || bail "harness head extraction empty — Gate 1 anchor moved in verify.sh"
[ -s "$SANDBOX/tail.sh" ] || bail "harness tail extraction empty — Summary anchor moved in verify.sh"

build_harness() {  # build_harness <out> <fixture-lines-file>
  cat "$SANDBOX/head.sh" > "$1"
  cat "$2" >> "$1"
  cat "$SANDBOX/tail.sh" >> "$1"
}

# GREEN scenario: one passing gate + one self-skipping gate. The skip must
# be counted separately and excluded from PASS, and must not turn the run
# red (§Acceptance #1: "the PASS count must not include skipped gates").
cat > "$SANDBOX/green-fixtures.sh" <<'EOF'
run_cmd "fixture:pass" -- true
run_cmd "fixture:skip" -- bash -c 'echo "SKIP: tool not available"; exit 0'
EOF
build_harness "$SANDBOX/green.sh" "$SANDBOX/green-fixtures.sh"
STARGATE_VERIFY_LOG="$SANDBOX/green.log" \
  bash "$SANDBOX/green.sh" > "$SANDBOX/green.out" 2>&1
green_rc=$?
[ "$green_rc" -eq 0 ] \
  || bail "GREEN harness exited $green_rc — a skip must not fail the run"
grep -q '^RESULT: GREEN' "$SANDBOX/green.out" \
  || bail "GREEN harness did not report GREEN"
grep -qE '\[SKIP\] fixture:skip — tool not available' "$SANDBOX/green.out" \
  || bail "self-skipping fixture not recorded SKIP with its sentinel note"
grep -qE '\[PASS\] fixture:skip' "$SANDBOX/green.out" \
  && bail "self-skipping fixture recorded PASS (the T108 bug, live)"
grep -q 'PASS=1  SKIP=1  FAIL=0' "$SANDBOX/green.out" \
  || bail "summary does not count the skip separately from PASS"

# RED scenario: the skip stays SKIP while every failure mode lands FAIL —
# including a gate that prints the sentinel but exits nonzero (the sentinel
# must never mask a fail) and a bash syntax error (exit 2 — why the
# convention is a sentinel and not an exit code).
cat > "$SANDBOX/red-fixtures.sh" <<'EOF'
run_cmd "fixture:skip" -- bash -c 'echo "SKIP: tool not available"; exit 0'
run_cmd "fixture:fail" -- false
run_cmd "fixture:liar" -- bash -c 'echo "SKIP: not really"; exit 1'
run_cmd "fixture:syntax" -- bash -c 'fi'
EOF
build_harness "$SANDBOX/red.sh" "$SANDBOX/red-fixtures.sh"
STARGATE_VERIFY_LOG="$SANDBOX/red.log" \
  bash "$SANDBOX/red.sh" > "$SANDBOX/red.out" 2>&1
red_rc=$?
[ "$red_rc" -eq 1 ] \
  || bail "RED harness exited $red_rc — failing fixtures must turn the run red"
grep -q '^RESULT: RED' "$SANDBOX/red.out" \
  || bail "RED harness did not report RED"
grep -qE '\[SKIP\] fixture:skip' "$SANDBOX/red.out" \
  || bail "skip fixture regressed to a non-SKIP state in the red run"
grep -qE '\[FAIL\] fixture:liar' "$SANDBOX/red.out" \
  || bail "a nonzero exit with SKIP: output was not recorded FAIL (sentinel masking)"
grep -qE '\[FAIL\] fixture:syntax' "$SANDBOX/red.out" \
  || bail "bash syntax error (exit 2) was not recorded FAIL (exit-code convention trap)"
grep -q 'PASS=0  SKIP=1  FAIL=3' "$SANDBOX/red.out" \
  || bail "red-run summary counts wrong (want PASS=0 SKIP=1 FAIL=3)"

# --- report ---------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  printf 'FAIL: verify_skip_convention_test.sh — %d assertion(s) failed:\n' "${#errs[@]}" >&2
  for e in "${errs[@]}"; do printf '  - %s\n' "$e" >&2; done
  printf '\n--- green harness output ---\n%s\n' "$(cat "$SANDBOX/green.out" 2>/dev/null)" >&2
  printf '\n--- red harness output ---\n%s\n' "$(cat "$SANDBOX/red.out" 2>/dev/null)" >&2
  exit 1
fi

echo "PASS: verify_skip_convention_test.sh — wired + adopted + recorded (T108 §A1–#3)."
exit 0
