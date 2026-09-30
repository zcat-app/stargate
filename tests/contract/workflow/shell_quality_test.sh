#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# shell_quality_test.sh — hermetic regression guard for the shell-quality
# gate added in T103. Falsifies the four claims that gate makes:
#
#   1. WIRED   — scripts/verify.sh records a "shell-quality" gate that
#                invokes `bash -n` AND a ShellCheck scoped to the four A4
#                categories (SC2012, SC2015, SC2148, SC2164). A verify.sh
#                that drops either is a regression (§Acceptance #1, #2, #5).
#   2. CLEAN   — running the SAME bash -n + scoped ShellCheck against the
#                current scripts/ tree finds zero issues. If a future edit
#                reintroduces an A4-category defect, this assertion fails
#                (§Acceptance #3 — the regression line).
#   3. DISCOVERS — a shell file added under scripts/ is picked up
#                automatically by the gate's enumeration rule, with no gate
#                edit (§Acceptance #4 — the load-bearing discovery claim).
#                T193: that includes an extension-less entrypoint under
#                scripts/subcommands/ (T187's `status` was silently ungated),
#                and the real tree's gate run covers scripts/subcommands/status.
#   4. SCOPE   — scripts/subcommands/.keep (a non-shell placeholder) is
#                NOT enumerated, and each of the four A4 codes is individually
#                flaggable by the scoped ShellCheck invocation (§Acceptance #2
#                — the scope is real, not a no-op).
#
# CLEAN and DISCOVERS run verify.sh's OWN Gate 1c block (T193), extracted
# between its section anchors like verify_skip_convention_test.sh does, so
# this test cannot drift from the gate: T103's hand-copied discovery rule did
# drift silently when T187 added an extension-less subcommand.
#
# Self-skip if bash or shellcheck is absent (CI has both).
# HERMETIC: throwaway sandbox for the discovery/scope fixtures; no network.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
VERIFY_SH="$REPO_ROOT/scripts/verify.sh"

command -v bash       >/dev/null 2>&1 || { echo "SKIP: bash not installed"; exit 0; }
command -v shellcheck >/dev/null 2>&1 || { echo "SKIP: shellcheck not installed"; exit 0; }
command -v git        >/dev/null 2>&1 || { echo "SKIP: git not installed"; exit 0; }
[ -f "$VERIFY_SH" ] || { echo "FAIL: $VERIFY_SH missing" >&2; exit 1; }

errs=()
bail() { errs+=("$*"); }

# The exact gate invocation verify.sh must run. Centralised so the test and
# the gate cannot drift apart: changing the scope here is intentional, and
# the wiring grep below forces verify.sh to follow.
A4_CODES='SC2012,SC2015,SC2148,SC2164'

# --- 1. WIRED: verify.sh reports the gate and the scoped checks ------------
grep -qE 'record[[:space:]]+"shell-quality"' "$VERIFY_SH" \
  || bail "verify.sh does not record a 'shell-quality' gate (§Acceptance #5)"
grep -qE 'bash[[:space:]]+-n' "$VERIFY_SH" \
  || bail "verify.sh does not invoke 'bash -n' (§Acceptance #1)"
# The four A4 codes must appear by name in the gate's shellcheck invocation.
for code in SC2012 SC2015 SC2148 SC2164; do
  grep -qE "shellcheck.*-i.*${code}" "$VERIFY_SH" \
    || bail "verify.sh does not scope shellcheck to ${code} (§Acceptance #2 — A4 set)"
done
grep -qE 'scripts/subcommands/\.keep' "$VERIFY_SH" \
  || bail "verify.sh does not exclude scripts/subcommands/.keep (scope hygene)"

SANDBOX="$(mktemp -d -t stargate-t103-XXXXXX)"
cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT

# The gate harness: verify.sh's helper block (everything before Gate 1) plus
# its Gate 1c block (from its header to Gate 2's). An anchor that moves
# empties the extraction and this test FAILS (fail-closed).
awk '/^# === Gate 1:/{exit} {print}' "$VERIFY_SH" > "$SANDBOX/gate.sh"
awk '/^# === Gate 1c:/{f=1} /^# === Gate 2:/{f=0} f {print}' "$VERIFY_SH" > "$SANDBOX/gate1c.sh"
[ -s "$SANDBOX/gate.sh" ] || bail "harness head extraction empty — Gate 1 anchor moved in verify.sh"
grep -q 'record "shell-quality"' "$SANDBOX/gate1c.sh" \
  || bail "Gate 1c extraction has no shell-quality gate — anchor moved in verify.sh"
cat "$SANDBOX/gate1c.sh" >> "$SANDBOX/gate.sh"

# run_gate <repo> <tag> — run the real gate with <repo> as the toplevel.
# Sets GATE_OUT (the gate's one-line result) and GATE_FILES (the entrypoints it
# logged as checked, sorted).
run_gate() {
  local log="$SANDBOX/$2.log"
  GATE_OUT="$(cd "$1" && STARGATE_VERIFY_LOG="$log" bash "$SANDBOX/gate.sh" 2>&1 \
    | grep -m1 'shell-quality')"
  GATE_FILES="$(sed -n 's/^shell-quality entrypoint: //p' "$log" 2>/dev/null | sort)"
}
has_file() { printf '%s\n' "$GATE_FILES" | grep -qxF -- "$1"; }

# --- 2. CLEAN: the gate passes the current scripts/ tree --------------------
# A future edit that reintroduces an A4-category defect (or a syntax error)
# in any discovered entrypoint turns this red (§Acceptance #3).
run_gate "$REPO_ROOT" real
printf '%s\n' "$GATE_OUT" | grep -qE '\[PASS\] shell-quality' \
  || bail "shell-quality gate is not PASS on the current tree: $GATE_OUT"
[ -n "$GATE_FILES" ] \
  || bail "gate logged zero checked entrypoints under scripts/ (enumeration regressed)"
# T193 §Acceptance #5: the operator entrypoints are really covered.
for want in scripts/stargate scripts/subcommands/init scripts/subcommands/status; do
  has_file "$want" || bail "real-tree gate run did not check $want (got: $GATE_FILES)"
done

# --- 3 + 4. DISCOVERS + SCOPE: hermetic sandbox ----------------------------
REPO="$SANDBOX/repo"
mkdir -p "$REPO/scripts/agent-cli" "$REPO/scripts/subcommands"
git -C "$REPO" init -q
git -C "$REPO" config user.email t103@stargate.test
git -C "$REPO" config user.name "T103 test"

# Tracked shell fixtures the gate must discover.
printf '#!/usr/bin/env bash\necho existing\n'  > "$REPO/scripts/existing.sh"
printf '#!/usr/bin/env bash\necho adapter\n'   > "$REPO/scripts/agent-cli/adapter.sh"
printf '#!/usr/bin/env bash\n# explicit non-.sh entrypoint\n' > "$REPO/scripts/stargate"
# T193: an extension-less subcommand the gate was never told about by name.
printf '#!/usr/bin/env bash\necho newcmd\n'    > "$REPO/scripts/subcommands/newcmd"
# A non-shell placeholder that shares the subcommands/ dir — must NOT be
# enumerated (ShellCheck would SC2148 it: no shebang, so the PASS below also
# proves the exclusion is real).
printf 'placeholder\n'                        > "$REPO/scripts/subcommands/.keep"
git -C "$REPO" add -A
git -C "$REPO" commit -q -m fixtures

run_gate "$REPO" fixtures
printf '%s\n' "$GATE_OUT" | grep -qE '\[PASS\] shell-quality' \
  || bail "gate is not PASS on clean fixtures (is .keep enumerated?): $GATE_OUT"
for want in scripts/agent-cli/adapter.sh scripts/existing.sh scripts/stargate \
            scripts/subcommands/newcmd; do
  has_file "$want" || bail "discovery missed '$want' (got: $GATE_FILES)"
done
has_file scripts/subcommands/.keep \
  && bail "discovery picked up scripts/subcommands/.keep (not a shell file)"

# §Acceptance #4: a NEWLY added shell file is auto-discovered — no gate edit.
printf '#!/usr/bin/env bash\necho new\n' > "$REPO/scripts/newly_added.sh"
git -C "$REPO" add scripts/newly_added.sh
run_gate "$REPO" added
has_file scripts/newly_added.sh \
  || bail "newly-added shell file not auto-discovered (§Acceptance #4 regression)"

# T193 §Acceptance #1/#2: a broken extension-less subcommand FAILS the gate —
# the regression that let T187's `status` ship without bash -n/ShellCheck.
printf '#!/usr/bin/env bash\nif then\n' > "$REPO/scripts/subcommands/broken"
git -C "$REPO" add scripts/subcommands/broken
run_gate "$REPO" broken
printf '%s\n' "$GATE_OUT" | grep -qE '\[FAIL\] shell-quality .*bash -n: scripts/subcommands/broken' \
  || bail "a syntax-broken extension-less scripts/subcommands/ entrypoint did not FAIL the gate: $GATE_OUT"

# Each of the four A4 codes is individually flaggable — proves the scoped
# ShellCheck is real (not a no-op over an empty scope).
mkdir -p "$SANDBOX/qual"
write_fixture() {  # write_fixture <name> <body>
  printf '%s\n' "$2" > "$SANDBOX/qual/$1.sh"
}
# Clean file: passes the scoped check (false-positive guard).
write_fixture clean $'#!/usr/bin/env bash\ncd /tmp || exit 1\n'
if ! shellcheck -i "$A4_CODES" -x -- "$SANDBOX/qual/clean.sh" >/dev/null 2>&1; then
  bail "scoped shellcheck flags a clean file (over-reports; gate would false-FAIL)"
fi
# One fixture per A4 code; each must be flagged.
write_fixture sc2012 $'#!/usr/bin/env bash\nls *.txt 2>/dev/null | head -1\n'    # ls-for-selection
write_fixture sc2015 $'#!/usr/bin/env bash\n[ -z "$X" ] && X=1 || true\n'        # A&&B||C
write_fixture sc2148 $'# no shebang here\ntrue\n'                                # missing shebang
write_fixture sc2164 $'#!/usr/bin/env bash\ncd /tmp\n'                           # unchecked cd
for code_file in sc2012:SC2012 sc2015:SC2015 sc2148:SC2148 sc2164:SC2164; do
  base="${code_file%%:*}"; code="${code_file##*:}"
  if shellcheck -i "$A4_CODES" -x -- "$SANDBOX/qual/$base.sh" >/dev/null 2>&1; then
    bail "shellcheck -i did not flag $code on $base.sh (scope would miss the regression)"
  fi
  # Capture shellcheck's output and grep that — `set -o pipefail` would
  # otherwise make `shellcheck | grep` return shellcheck's non-zero (it
  # exits 1 when it finds issues), masking whether grep matched.
  out="$(shellcheck -i "$A4_CODES" -x -- "$SANDBOX/qual/$base.sh" 2>&1 || true)"
  printf '%s\n' "$out" | grep -q "$code" \
    || bail "$base.sh flagged, but not by $code (scope fired the wrong code)"
done

# --- report ---------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  printf 'FAIL: shell_quality_test.sh — %d assertion(s) failed:\n' "${#errs[@]}" >&2
  for e in "${errs[@]}"; do printf '  - %s\n' "$e" >&2; done
  exit 1
fi
echo "PASS: shell_quality_test.sh — wired + clean + discovers + scoped (T103 §A1–#5, T193)."
exit 0
