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

# Make the Go toolchain discoverable even when the caller's shell never sourced
# ~/.profile — e.g. a non-interactive CI runner, or the tool-shell an autopilot
# /loop spawns per command. go.dev's tarball installs to /usr/local/go; without
# this, the `have go` check below false-SKIPs the Go gate while Go is in fact
# installed — a silent green that never compiles the data plane. Pure fallback:
# if `go` is already on PATH this is a no-op, and if Go is genuinely absent the
# gate still SKIPs honestly.
command -v go >/dev/null 2>&1 || PATH="$PATH:/usr/local/go/bin"
export PATH

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

# === Gate 2: Go workspace modules (discovered via go.work) ================
# T076: every workspace Go module (data plane, proto, contract, integration,
# shared log invariants) is discovered from go.work and gated with JSON skip
# accounting. A package whose tests all skip is reported SKIP, never PASS.
# Suites carrying `//go:build docker|live|release` are kept out of the
# hermetic PR run (accounted SKIP[<cadence>], compile-checked via
# `go vet -tags`) and run in the named Docker/live/release job through the
# SAME entrypoint — `STARGATE_TEST_TAGS=docker scripts/verify.sh` — not a
# divergent command list (T076 §Acceptance #2/#4/#5). The gate is a separate
# script so its discovery + accounting is independently testable
# (tests/contract/workflow/verify_discovery_test.sh).
if ! have go; then
  record "go-workspace" SKIP "go toolchain not installed"
elif [ -x scripts/go-workspace-gate.py ]; then
  run_cmd "go-workspace" -- python3 scripts/go-workspace-gate.py "$(pwd)"
else
  record "go-workspace" SKIP "scripts/go-workspace-gate.py absent"
fi

# === Gate 2b: browser extension tests (discovered) ========================
# T076 §Acceptance #3: discover the extension test runner rather than
# enumerate a fixed path. The runner lands with T034b; until then this gate
# self-SKIPs so verify.sh is green at scaffolding time.
if [ -x extension/run-tests.sh ]; then
  run_cmd "extension-tests" -- sh -c 'cd extension && ./run-tests.sh'
elif [ -d extension ]; then
  record "extension-tests" SKIP "no extension/run-tests.sh (T034b not landed)"
else
  record "extension-tests" SKIP "no extension/ dir"
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
