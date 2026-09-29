#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# verify_discovery_test.sh — hermetic regression guard for the discovered Go
# test gate (T076 §Acceptance #2 + #3 + #4 + #6).
#
# It builds throwaway go.work workspaces under mktemp -d with synthetic
# modules, runs the REAL scripts/go-workspace-gate.py against them, and
# asserts the verdict rules that are the falsifiable contract of T076:
#
# Workspace A (4 modules):
#   moda (pr, passes; one test
#         t.Skip with a reason)    -> PASS, plus a named per-test
#                                    `test SKIP:` line carrying the reason and
#                                    a `test PASS:` line for the passing test
#                                    (T183: a skipped privacy gate in a mixed
#                                    package must be named, not only counted)
#   modb (pr, all tests t.Skip)    -> SKIP, never PASS   (the core bug fix)
#   modc (pr, //stargate:required,
#         all t.Skip)              -> FAIL                (FAIL-when-required)
#   modd (//go:build docker,
#         failing test)            -> SKIP[docker] in hermetic run,
#                                    FAIL under STARGATE_TEST_TAGS=docker
#                                    (the named job actually runs it)
#
# Workspace B (1 broken module, isolated — a malformed go.mod in one go.work
# member poisons the whole workspace, so it gets its own go.work):
#   mode (malformed go.mod)        -> FAIL via the go-list path, NOT a silent
#                                    SKIP (T076 review Major finding: a broken
#                                    module must not regress while verify.sh
#                                    stays green).
#
# Plus discovery (T076 §Acceptance #3): a module added to go.work is gated
# automatically — no gate edit.
#
# HERMETIC: throwaway sandbox, no network, no Docker. Self-skip if the go
# toolchain or python3 is absent (CI has both; the gate needs both).

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GATE="$REPO_ROOT/scripts/go-workspace-gate.py"
[ -f "$GATE" ] || { echo "FAIL: $GATE missing" >&2; exit 1; }

command -v go >/dev/null 2>&1 || { echo "SKIP: go not installed"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }

SANDBOX="$(mktemp -d -t stargate-t076-XXXXXX)"
cleanup() { rm -rf "$SANDBOX"; }
trap cleanup EXIT

errs=()
bail() { errs+=("$*"); }
assert_grep() { local pat="$1" label="$2" out="$3"
  if printf '%s' "$out" | grep -qE "$pat"; then :; else
    bail "ASSERT FAIL [$label]: pattern /$pat/ not in gate output"; fi; }
assert_nogrep() { local pat="$1" label="$2" out="$3"
  if printf '%s' "$out" | grep -qE "$pat"; then
    bail "ASSERT FAIL [$label]: pattern /$pat/ SHOULD be absent but matched"; fi; }

write_mod() {  # write_mod <name> <go-file-body>
  local name="$1" body="$2"
  mkdir -p "$SANDBOX/$name"
  printf 'module example.com/%s\n\ngo 1.26\n' "$name" > "$SANDBOX/$name/go.mod"
  printf '%s\n' "$body" > "$SANDBOX/$name/${name}_test.go"
}

# --- Workspace A: the 4 behavioural fixtures ------------------------------
write_mod moda 'package moda

import "testing"

func TestPasses(t *testing.T) {}

func TestNeedsCapability(t *testing.T) { t.Skip("SKIP: needs CAP_NET_RAW for capture") }
'

write_mod modb 'package modb

import "testing"

func TestAllSkip(t *testing.T) { t.Skip("intentionally skipped") }
'

write_mod modc '// stargate:required — an all-skip required package is FAIL, not SKIP.

package modc

import "testing"

func TestRequiredButSkipped(t *testing.T) { t.Skip("intentionally skipped") }
'

write_mod modd '//go:build docker
// +build docker

package modd

import "testing"

func TestDockerOnlyFails(t *testing.T) { t.Fatal("must not run in hermetic PR gate") }
'

write_mod modf 'package modf

import (
	"os"
	"testing"
)

// TestMain exits non-zero WITHOUT flushing a JSON FAIL event — simulates a
// test run that hangs/crashes/times out (stargate-redteam finding). The gate
// MUST account this package FAIL, not SKIP (a dead privacy test must not
// mask as a clean SKIP while verify.sh stays GREEN).
func TestMain(m *testing.M) { os.Exit(2) }

func TestNeverReached(t *testing.T) {}
'

cat > "$SANDBOX/go.work" <<'EOF'
go 1.26

use (
	./moda
	./modb
	./modc
	./modd
	./modf
)
EOF

# --- run A1: hermetic (default) -------------------------------------------
HERMETIC_OUT="$(python3 "$GATE" "$SANDBOX" 2>&1)"
python3 "$GATE" "$SANDBOX" >/dev/null 2>&1; HERMETIC_RC=$?

# Discovery: all five modules enumerated from go.work, by name.
assert_grep "discovered 5 module\(s\) via go.work" "discover-count" "$HERMETIC_OUT"
assert_grep "moda" "discover-moda" "$HERMETIC_OUT"
assert_grep "modb" "discover-modb" "$HERMETIC_OUT"
assert_grep "modc" "discover-modc" "$HERMETIC_OUT"
assert_grep "modd" "discover-modd" "$HERMETIC_OUT"
assert_grep "modf" "discover-modf" "$HERMETIC_OUT"

# Core bug fix (§Acceptance #2): modB's all-skip package is SKIP, NEVER PASS.
assert_grep "SKIP[[:space:]]+.*example\.com/modb" "modb-is-skip" "$HERMETIC_OUT"
assert_nogrep "PASS[[:space:]]+.*example\.com/modb" "modb-not-pass" "$HERMETIC_OUT"

# FAIL-when-required branch (§Acceptance #2): modC's required all-skip is FAIL.
assert_grep "FAIL[[:space:]]+.*example\.com/modc" "modc-is-fail" "$HERMETIC_OUT"

# modA passes.
assert_grep "PASS[[:space:]]+.*example\.com/moda" "moda-is-pass" "$HERMETIC_OUT"

# T183 (acceptance 4): a skipped test inside a PASSING mixed package is named
# with its reason, and the test that ran is named too — the package's
# aggregate `skip=1` alone hides which gate did not run. The per-test lines
# are indented so verify.sh's gate-level `^SKIP:` sentinel cannot fire on them
# (a named test skip must not downgrade the whole Go gate to SKIP).
assert_grep "^    test SKIP: example\.com/moda\.TestNeedsCapability — SKIP: needs CAP_NET_RAW for capture$" "moda-skip-named" "$HERMETIC_OUT"
assert_grep "^    test PASS: example\.com/moda\.TestPasses \(" "moda-pass-named" "$HERMETIC_OUT"
assert_nogrep "^SKIP:" "no-gate-level-skip-sentinel" "$HERMETIC_OUT"

# Cadence separation (§Acceptance #4): modD's docker build-tagged suite is
# accounted SKIP[docker] in the hermetic run, NOT executed (no FAIL from its
# t.Fatal). Compile-checked via vet (go-vet PASS).
assert_grep "SKIP\[docker\][[:space:]]+.*example\.com/modd" "modd-skip-docker" "$HERMETIC_OUT"
assert_nogrep "FAIL[[:space:]]+.*example\.com/modd" "modd-not-fail-hermetic" "$HERMETIC_OUT"

# Masking guard (stargate-redteam finding): modF's TestMain exits non-zero
# with no JSON FAIL event; the package MUST be FAIL, not SKIP. A dead
# privacy test must not mask as a clean SKIP while verify.sh stays GREEN.
assert_grep "FAIL[[:space:]]+.*example\.com/modf" "modf-is-fail" "$HERMETIC_OUT"
assert_nogrep "SKIP[[:space:]]+.*example\.com/modf" "modf-not-skip" "$HERMETIC_OUT"

# Overall: RED in hermetic mode because of modC (required all-skip) and modF
# (dead test run); modD's docker suite contributed no FAIL.
[ "$HERMETIC_RC" -eq 1 ] || bail "ASSERT FAIL [hermetic-exit-1]: got rc=$HERMETIC_RC, want 1 (modC/modF fail)"

# --- run A2: named Docker job (STARGATE_TEST_TAGS=docker) -----------------
# The SAME entrypoint (no divergent command list — §Acceptance #5) executes
# the docker suite; modD now FAILs on its t.Fatal (the named job RUNS it).
NAMED_OUT="$(STARGATE_TEST_TAGS=docker python3 "$GATE" "$SANDBOX" 2>&1)"
assert_grep "NAMED mode" "named-mode-banner" "$NAMED_OUT"
assert_grep "FAIL[[:space:]]+.*example\.com/modd" "modd-fails-named" "$NAMED_OUT"

# --- Workspace B: a broken module (malformed go.mod), isolated ------------
# A malformed go.mod in a go.work member poisons the whole workspace's
# `go list`, so mode gets its own go.work. `go list ./...` exits nonzero
# with empty stdout; the gate MUST FAIL (not silently SKIP).
mkdir -p "$SANDBOX/broken/mode"
printf 'module example.com/mode\nthis is not valid go.mod syntax\n' \
  > "$SANDBOX/broken/mode/go.mod"
cat > "$SANDBOX/broken/go.work" <<'EOF'
go 1.26

use (
	./mode
)
EOF
BROKEN_OUT="$(python3 "$GATE" "$SANDBOX/broken" 2>&1)"
assert_grep "FAIL[[:space:]]+go-list:mode" "mode-is-fail" "$BROKEN_OUT"
assert_nogrep "SKIP[[:space:]]+go:mode" "mode-not-skip" "$BROKEN_OUT"

# --- report ---------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  printf 'FAIL: verify_discovery_test.sh — %d assertion(s) failed:\n' "${#errs[@]}" >&2
  for e in "${errs[@]}"; do printf '  - %s\n' "$e" >&2; done
  printf '\n--- hermetic (A) gate output ---\n%s\n' "$HERMETIC_OUT" >&2
  printf '\n--- named (A) gate output ---\n%s\n' "$NAMED_OUT" >&2
  printf '\n--- broken (B) gate output ---\n%s\n' "$BROKEN_OUT" >&2
  exit 1
fi

echo "PASS: verify_discovery_test.sh — discovery + JSON skip accounting + cadence separation + broken-module FAIL hold."
exit 0
