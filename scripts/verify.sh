#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# scripts/verify.sh — the single green gate for Stargate.
#
# Why this exists: an autonomous run (a /loop, a scheduled routine, a cloud
# agent) needs ONE deterministic command that answers "is the tree green?"
# without the caller knowing which planes/tests currently exist. The build
# spans Go (data plane), Maven/Quarkus (control plane), shell contract tests,
# license headers, and reproducibility — no single tool covers them.
#
# Phase-aware by design: the repo is built incrementally (spec-kit tasks).
# Each gate SELF-DETECTS whether it has anything to run and reports SKIP
# rather than FAIL when the code it would check does not exist yet. So this
# script is green at scaffolding time and does strictly more as code lands —
# you never have to "turn gates on". A gate is FAIL only when code that
# exists is actually broken.
#
# Exit status: 0 if every gate is PASS or SKIP; 1 if any gate FAILs.
# Full command output is appended to target/verify.log (a fixed path the
# review/commit steps can read; see .specify/memory/review-loop.md).
#
# Opt-outs (for fast inner loops): STARGATE_SKIP_CP=1 skips the Maven gate
# (slow, network); STARGATE_VERIFY_REPRO=1 opts INTO the release-cadence
# reproducibility gate (off by default — it builds twice and is slow);
# STARGATE_SKIP_GROUND=1 skips the external-pin grounding gate;
# STARGATE_GROUND_ONLINE=1 deepens grounding to resolve digests + check EOL
# online (needs curl/docker) — recommended before a release tag.

set -uo pipefail   # NOT -e: run every gate and aggregate, don't abort early.

cd "$(git rev-parse --show-toplevel)"

mkdir -p target
LOG="target/verify.log"
: > "$LOG"

# --- result tracking ------------------------------------------------------
declare -a G_NAME G_STATE G_NOTE
FAILED=0

say() { printf '%s\n' "$*" | tee -a "$LOG" ; }
hr()  { say "------------------------------------------------------------"; }

# record <name> <PASS|SKIP|FAIL> <note>
record() {
  G_NAME+=("$1"); G_STATE+=("$2"); G_NOTE+=("${3:-}")
  [ "$2" = "FAIL" ] && FAILED=1
  say "  [$2] $1 ${3:+— $3}"
}

# run <name> <note-on-skip-not-used> -- <cmd...> ; PASS if cmd exits 0.
run_cmd() {
  local name="$1"; shift
  [ "${1:-}" = "--" ] && shift   # tolerate an explicit -- separator at call sites
  say ">>> $name"
  if "$@" >>"$LOG" 2>&1; then record "$name" PASS; else record "$name" FAIL "see target/verify.log"; fi
}

have() { command -v "$1" >/dev/null 2>&1; }

say "Stargate verify — $(git rev-parse --short HEAD 2>/dev/null || echo no-git)"
hr

# === Gate 1: license headers (always available) ===========================
if [ -x scripts/check-license-headers.sh ]; then
  run_cmd "license-headers" -- scripts/check-license-headers.sh
else
  record "license-headers" SKIP "scripts/check-license-headers.sh absent"
fi

# === Gate 1b: external-fact grounding (pins not covered by consistency) ===
# Offline by default (fast, surfaces pins, fails only on a broken pin). Set
# STARGATE_GROUND_ONLINE=1 to additionally resolve digests + check EOL.
if [ "${STARGATE_SKIP_GROUND:-0}" = "1" ]; then
  record "ground-check" SKIP "STARGATE_SKIP_GROUND=1"
elif [ -x scripts/ground-check.sh ]; then
  run_cmd "ground-check" -- scripts/ground-check.sh
else
  record "ground-check" SKIP "scripts/ground-check.sh absent"
fi

# === Gate 2: Go data plane ================================================
# Heuristic for "real source exists": any .go file other than tools.go (the
# build-tagged tool-pin file, which compiles to nothing on its own).
go_src=$(find data-plane -name '*.go' ! -name 'tools.go' 2>/dev/null | wc -l | tr -d ' ')
if ! have go; then
  record "go" SKIP "go toolchain not installed"
elif [ -f data-plane/go.mod ]; then
  ( cd data-plane && go mod verify ) >>"$LOG" 2>&1 \
    && record "go-mod-verify" PASS || record "go-mod-verify" FAIL "see target/verify.log"
  # gofmt applies even to tools.go.
  if [ "$(find data-plane -name '*.go' | wc -l | tr -d ' ')" -gt 0 ]; then
    badfmt=$( cd data-plane && gofmt -l . 2>/dev/null )
    [ -z "$badfmt" ] && record "gofmt" PASS \
      || record "gofmt" FAIL "unformatted: $(printf '%s' "$badfmt" | tr '\n' ' ')"
  fi
  if [ "$go_src" -gt 0 ]; then
    run_cmd "go-vet"  -- sh -c 'cd data-plane && go vet ./...'
    run_cmd "go-test" -- sh -c 'cd data-plane && go test ./...'
    # Static analysis: policy in CONTRIBUTING §Code style. Run if installed.
    if have staticcheck; then run_cmd "staticcheck" -- sh -c 'cd data-plane && staticcheck ./...'
    else record "staticcheck" SKIP "not installed"; fi
    if have gosec; then run_cmd "gosec" -- sh -c 'cd data-plane && gosec -quiet ./...'
    else record "gosec" SKIP "not installed"; fi
  else
    record "go-vet/test" SKIP "no data-plane source yet (only tools.go)"
  fi
else
  record "go" SKIP "no data-plane/go.mod"
fi

# === Gate 3: Quarkus control plane =======================================
java_src=$(find control-plane -name '*.java' 2>/dev/null | wc -l | tr -d ' ')
if [ "${STARGATE_SKIP_CP:-0}" = "1" ]; then
  record "control-plane" SKIP "STARGATE_SKIP_CP=1"
elif [ "$java_src" -gt 0 ] && [ -x control-plane/mvnw ]; then
  run_cmd "mvnw-verify" -- sh -c 'cd control-plane && ./mvnw -B -q verify'
else
  record "control-plane" SKIP "no Java sources yet"
fi

# === Gate 4: shell/contract tests ========================================
contract_tests=$(find tests/contract -type f \( -name '*_test.sh' -o -name '*.bats' \) 2>/dev/null | wc -l | tr -d ' ')
if [ "${contract_tests:-0}" -gt 0 ]; then
  while IFS= read -r t; do run_cmd "contract:$(basename "$t")" -- bash "$t"; done \
    < <(find tests/contract -type f \( -name '*_test.sh' -o -name '*.bats' \) 2>/dev/null)
else
  record "contract-tests" SKIP "none authored yet"
fi

# === Gate 5: reproducibility (release cadence; opt-in) ====================
if [ "${STARGATE_VERIFY_REPRO:-0}" = "1" ]; then
  repro=$(find tests/reproducibility -name '*.sh' 2>/dev/null | wc -l | tr -d ' ')
  if [ "${repro:-0}" -gt 0 ]; then
    while IFS= read -r t; do run_cmd "repro:$(basename "$t")" -- bash "$t"; done \
      < <(find tests/reproducibility -name '*.sh' 2>/dev/null)
  else
    record "reproducibility" SKIP "no scripts yet"
  fi
else
  record "reproducibility" SKIP "release-cadence; set STARGATE_VERIFY_REPRO=1 to run"
fi

# === Summary =============================================================
hr
say "Summary:"
pass=0; skip=0; fail=0
for i in "${!G_NAME[@]}"; do
  case "${G_STATE[$i]}" in PASS) pass=$((pass+1));; SKIP) skip=$((skip+1));; FAIL) fail=$((fail+1));; esac
done
say "  PASS=$pass  SKIP=$skip  FAIL=$fail   (full log: target/verify.log)"
hr
if [ "$FAILED" -ne 0 ]; then
  say "RESULT: RED — $fail gate(s) failed."
  exit 1
fi
say "RESULT: GREEN — nothing failed ($skip gate(s) not yet applicable)."
exit 0
