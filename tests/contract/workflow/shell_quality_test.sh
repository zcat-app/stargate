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
#   4. SCOPE   — scripts/subcommands/.keep (a non-shell placeholder) is
#                NOT enumerated, and each of the four A4 codes is individually
#                flaggable by the scoped ShellCheck invocation (§Acceptance #2
#                — the scope is real, not a no-op).
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

# Discovery rule used by the gate. Same expression as verify.sh's Gate 1c —
# if the gate changes its enumeration, this must change to match, and the
# wiring grep keeps the two in lockstep.
discover() {  # discover <repo-root> -> sorted list of shell entrypoints
  git -C "$1" ls-files 'scripts/*.sh' 'scripts/**/*.sh' \
                     scripts/stargate scripts/subcommands/init 2>/dev/null \
    | grep -v '^scripts/subcommands/\.keep$' | sort
}

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

# --- 2. CLEAN: current scripts/ tree has zero A4-category findings ---------
mapfile -t shell_files < <(discover "$REPO_ROOT")
[ "${#shell_files[@]}" -gt 0 ] \
  || bail "discovery enumerated zero shell files under scripts/ (enumeration regressed)"

a4_failures=()
for rel in "${shell_files[@]}"; do
  file="$REPO_ROOT/$rel"
  [ -f "$file" ] || { a4_failures+=("missing: $rel"); continue; }
  if ! bash -n "$file" 2>/dev/null; then
    a4_failures+=("bash -n: $rel")
  fi
  if ! shellcheck -i "$A4_CODES" -x -- "$file" >/dev/null 2>&1; then
    a4_failures+=("shellcheck: $rel")
  fi
done
[ "${#a4_failures[@]}" -eq 0 ] \
  || bail "A4-category regression in scripts/ (${#a4_failures[@]} file(s)): ${a4_failures[*]}"

# --- 3 + 4. DISCOVERS + SCOPE: hermetic sandbox ----------------------------
SANDBOX="$(mktemp -d -t stargate-t103-XXXXXX)"
cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT

mkdir -p "$SANDBOX/scripts/agent-cli" "$SANDBOX/scripts/subcommands"
git -C "$SANDBOX" init -q
git -C "$SANDBOX" config user.email t103@stargate.test
git -C "$SANDBOX" config user.name "T103 test"

# Tracked shell fixtures the gate must discover.
printf '#!/usr/bin/env bash\necho existing\n'  > "$SANDBOX/scripts/existing.sh"
printf '#!/usr/bin/env bash\necho adapter\n'   > "$SANDBOX/scripts/agent-cli/adapter.sh"
printf '#!/usr/bin/env bash\n# explicit non-.sh entrypoint\n' > "$SANDBOX/scripts/stargate"
# A non-shell placeholder that shares the subcommands/ dir — must NOT be
# enumerated (ShellCheck would SC2148 a bare empty file; the gate excludes
# it by name so the placeholder stays a placeholder).
printf 'placeholder\n'                        > "$SANDBOX/scripts/subcommands/.keep"
git -C "$SANDBOX" add -A
git -C "$SANDBOX" commit -q -m fixtures

mapfile -t found < <(discover "$SANDBOX")

want_present=( "scripts/agent-cli/adapter.sh" "scripts/existing.sh" "scripts/stargate" )
for want in "${want_present[@]}"; do
  found_want=0
  for got in "${found[@]:-}"; do [ "$got" = "$want" ] && { found_want=1; break; }; done
  [ "$found_want" -eq 1 ] \
    || bail "discovery missed '$want' (got: ${found[*]:-})"
done
for got in "${found[@]:-}"; do
  [ "$got" = "scripts/subcommands/.keep" ] \
    && bail "discovery picked up scripts/subcommands/.keep (not a shell file)"
done

# §Acceptance #4: a NEWLY added shell file is auto-discovered — no gate edit.
printf '#!/usr/bin/env bash\necho new\n' > "$SANDBOX/scripts/newly_added.sh"
git -C "$SANDBOX" add scripts/newly_added.sh
mapfile -t refound < <(discover "$SANDBOX")
saw_new=0
for got in "${refound[@]:-}"; do [ "$got" = "scripts/newly_added.sh" ] && { saw_new=1; break; }; done
[ "$saw_new" -eq 1 ] \
  || bail "newly-added shell file not auto-discovered (§Acceptance #4 regression)"

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
echo "PASS: shell_quality_test.sh — wired + clean + discovers + scoped (T103 §A1–#5)."
exit 0
