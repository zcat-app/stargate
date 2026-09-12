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
# review/commit steps can read; see .specify/memory/review-loop.md);
# STARGATE_VERIFY_LOG redirects it (the T108 contract probe sets it so a
# nested verify run cannot clobber the outer run's log).
#
# Gate self-skip convention (T108): a gate that exits 0 but printed a line
# starting "SKIP:" self-reported a skip — run_cmd records SKIP, counted
# separately, never in the PASS count. tests/reproducibility/*.sh emit it
# when their build tool is absent: a repro gate that compared zero bytes
# must not summarize as PASS. A nonzero exit is FAIL even when the output
# carries "SKIP:" — the sentinel can only downgrade a pass, never mask a
# fail (an exit-code convention was rejected: bash exits 2 on script
# syntax errors, which would record a broken test as SKIP).
#
# Opt-outs (for fast inner loops): STARGATE_SKIP_CP=1 skips the Maven gate
# (slow, network); STARGATE_VERIFY_REPRO=1 opts INTO the release-cadence
# reproducibility gate (off by default — it builds twice and is slow);
# STARGATE_SKIP_GROUND=1 skips the external-pin grounding gate;
# STARGATE_GROUND_ONLINE=1 deepens grounding to resolve digests + check EOL
# online (needs curl/docker) — recommended before a release tag.

set -uo pipefail   # NOT -e: run every gate and aggregate, don't abort early.

# `cd || exit`, not bare `cd`: a failed cd would otherwise run every gate
# against the wrong $PWD and silently mis-report (T103 A4 / SC2164).
cd "$(git rev-parse --show-toplevel)" || exit 1

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
LOG="${STARGATE_VERIFY_LOG:-target/verify.log}"
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

# run <name> -- <cmd...>
# PASS on exit 0 — unless the output carries the self-skip sentinel (a line
# starting "SKIP:", see the header): then SKIP, annotated with the sentinel
# text. Nonzero exit is always FAIL, sentinel or not (T108).
run_cmd() {
  local name="$1" out rc=0
  shift
  [ "${1:-}" = "--" ] && shift   # tolerate an explicit -- separator at call sites
  say ">>> $name"
  out="$("$@" 2>&1)" || rc=$?
  printf '%s\n' "$out" >>"$LOG"
  if [ "$rc" -ne 0 ]; then
    record "$name" FAIL "see target/verify.log"
  elif printf '%s\n' "$out" | grep -q '^SKIP:'; then
    record "$name" SKIP "$(printf '%s\n' "$out" | grep -m1 '^SKIP:' | sed 's/^SKIP:[[:space:]]*//')"
  else
    record "$name" PASS
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

say "Stargate verify — $(git rev-parse --short HEAD 2>/dev/null || echo no-git)"
hr

# === Gate 1: license headers (always available) ===========================
# Required tooling is invoked through its interpreter: file mode is not a
# coverage switch (Constitution VII / T139). Missing tooling fails too.
run_cmd "license-headers" -- bash scripts/check-license-headers.sh

# === Gate 1b: external-fact grounding (pins not covered by consistency) ===
# Offline by default (fast, surfaces pins, fails only on a broken pin). Set
# STARGATE_GROUND_ONLINE=1 to additionally resolve digests + check EOL.
if [ "${STARGATE_SKIP_GROUND:-0}" = "1" ]; then
  record "ground-check" SKIP "STARGATE_SKIP_GROUND=1"
else
  run_cmd "ground-check" -- bash scripts/ground-check.sh
fi

# === Gate 1c: shell quality (release-critical scripts/) ====================
# T103 §Acceptance #1 + #2: bash -n on every Bash entrypoint under scripts/,
# plus a PINNED + SCOPED ShellCheck gate covering only the four A4 categories
# from review/sol-review.md#A4 — SC2012 (ls-for-file-selection), SC2015
# (A&&B||C as if-then-else), SC2148 (missing shebang), SC2164 (unchecked cd).
# Installer/workflow shell is release-critical; the gate keeps the scope
# narrow on purpose so it stays tight without churning style-only findings.
# Absence of ShellCheck is SKIP locally; CI (CI=true | GITHUB_ACTIONS=true)
# requires it — the policy is enforced here so a shellcheck-less CI run can
# never claim GREEN on release-critical shell.
#
# Discovery (§Acceptance #4): every tracked *.sh under scripts/ (incl. the
# agent-cli/ adapters) PLUS the named non-.sh shell entrypoints
# (scripts/stargate, scripts/subcommands/init). scripts/subcommands/.keep
# is excluded explicitly — it is a placeholder, not shell. A new shell file
# added under scripts/ is gated automatically — no gate edit needed.
if ! have bash; then
  record "shell-quality" SKIP "bash toolchain not installed"
else
  mapfile -t _shell_files < <(
    git ls-files 'scripts/*.sh' 'scripts/**/*.sh' \
                 scripts/stargate scripts/subcommands/init 2>/dev/null \
      | grep -v '^scripts/subcommands/\.keep$' || true
  )
  if [ "${#_shell_files[@]}" -eq 0 ]; then
    record "shell-quality" SKIP "no shell entrypoints under scripts/"
  else
    _sq_fail=0; _sq_notes=()
    # §Acceptance #1: bash -n on every entrypoint (syntax never has false positives).
    for f in "${_shell_files[@]}"; do
      [ -f "$f" ] || continue
      if ! bash -n "$f" >>"$LOG" 2>&1; then
        _sq_fail=1; _sq_notes+=("bash -n: $f")
      fi
    done
    # §Acceptance #2: scoped ShellCheck (the four A4 codes only).
    if have shellcheck; then
      _sq_sc=""; _sq_checked=0
      for f in "${_shell_files[@]}"; do
        [ -f "$f" ] || continue
        _sq_checked=$((_sq_checked + 1))
        # -x follows `source` across files; -i restricts to the pinned A4 set.
        if _out="$(shellcheck -i SC2012,SC2015,SC2148,SC2164 -x -- "$f" 2>&1)"; then :
        else
          _sq_fail=1; _sq_notes+=("shellcheck: $f"); _sq_sc+="$_out"$'\n'
        fi
      done
      [ -n "$_sq_sc" ] && printf '%s\n' "$_sq_sc" >>"$LOG"
      if [ "$_sq_fail" -ne 0 ]; then
        record "shell-quality" FAIL "${_sq_notes[*]}"
      else
        _sq_ver="$(shellcheck --version | awk '/^version:/ {print $2; exit}')"
        record "shell-quality" PASS "$_sq_checked entrypoint(s), shellcheck $_sq_ver"
      fi
    elif [ "${CI:-false}" = "true" ] || [ "${GITHUB_ACTIONS:-false}" = "true" ]; then
      record "shell-quality" FAIL "shellcheck absent in CI (required; install or the gate is hollow)"
    else
      record "shell-quality" SKIP "shellcheck absent — required in CI, locally SKIP"
    fi
  fi
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
else
  run_cmd "go-workspace" -- python3 scripts/go-workspace-gate.py "$(pwd)"
fi

# === Gate 2b: browser extension tests (discovered) ========================
# T139: distinguish an empty scaffold from a missing runner over existing
# JavaScript substrate. Either an existing runner or source requires execution.
if [ -f extension/run-tests.sh ] || [ -n "$(find extension -type f -name '*.js' -print -quit 2>/dev/null)" ]; then
  run_cmd "extension-tests" -- bash -c 'cd extension && bash run-tests.sh'
elif [ -d extension ]; then
  record "extension-tests" SKIP "no extension JavaScript sources or test runner yet"
else
  record "extension-tests" SKIP "no extension/ dir"
fi

# === Gate 3: Quarkus control plane =======================================
java_src=$(find control-plane -name '*.java' 2>/dev/null | wc -l | tr -d ' ')
if [ "${STARGATE_SKIP_CP:-0}" = "1" ]; then
  record "control-plane" SKIP "STARGATE_SKIP_CP=1"
elif [ "$java_src" -gt 0 ]; then
  run_cmd "mvnw-verify" -- sh -c 'cd control-plane && sh mvnw -B -q verify'
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
say "  PASS=$pass  SKIP=$skip  FAIL=$fail   (full log: $LOG)"
hr
if [ "$FAILED" -ne 0 ]; then
  say "RESULT: RED — $fail gate(s) failed."
  exit 1
fi
say "RESULT: GREEN — nothing failed ($skip gate(s) skipped)."
exit 0
