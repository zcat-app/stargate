#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/secret-scan/scan_test.sh — hermetic regression guard for the
# pre-commit fallback's contextual 32-hex bearer-token rule (T102 §Acceptance
# #1, #2, #4). Covers the documented-placeholder allowlist, the false-positive
# guard against longer hex runs (sha256 digests, PGP fingerprints, git object
# ids), staged-only scanning, and the redaction property (the secret value
# never reaches scanner output).
#
# WHY THE FALLBACK ONLY: gitleaks is the authoritative path where installed,
# but it is not guaranteed on a fresh machine (the very case the fallback
# exists for). This test forces the fallback deterministically by giving the
# hook a PATH that contains git/grep/sed but NOT gitleaks. The gitleaks path
# itself is exercised by the CI history-scan job added in the same ticket.
#
# SOURCE-SELF-SAFETY: the synthetic 32-hex "secret" below is assembled from
# three sub-32 fragments so that NO single line of this test source contains
# a keyword (`token`/`bearer`/`stargate_test_token`) adjacent to a 32-hex
# literal — otherwise committing this file would trip the very rule it tests.
# The fragments are deliberately unrelated to the documented allowlist
# placeholder.
#
# ISOLATION: one fresh throwaway git repo per scenario (same convention as
# tests/contract/workflow/run_task_test.sh) — a hook-blocked commit leaves the
# staged change in the index, which would poison the next scenario if a
# single repo were reused.
#
# HERMETIC: throwaway repos under mktemp -d; no network; no Docker.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_SRC="$REPO_ROOT/.githooks/pre-commit"
[ -f "$HOOK_SRC" ] || { echo "FAIL: $HOOK_SRC missing" >&2; exit 1; }

errs=()
bail() { errs+=("$*"); }
assert() { local cond="$1" label="$2"; if eval "$cond"; then :; else bail "ASSERT FAIL [$label]: $cond"; fi; }

# Synthetic 32-hex value, NOT in the allowlist. Assembled from fragments so no
# source line pairs a keyword with a 32-hex literal (see header note).
SECRET_PFX='5a3f9c8e1b2d'   # 12 lowercase hex
SECRET_MID='4a6f8e0c'        #  8 lowercase hex
SECRET_SFX='2b4d6f8a0c2e'   # 12 lowercase hex   (12 + 8 + 12 = 32)
SECRET="$SECRET_PFX$SECRET_MID$SECRET_SFX"

# Documented spec-doc example bearer token — one of two values allowlisted in
# .githooks/pre-commit AND .gitleaks.toml (see data-model.md / quickstart.md /
# contracts/socks5-auth.md). Using a real documented placeholder keeps a single
# source of truth for the allowlist across the hook and the test.
PLACEHOLDER='9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f'

# --- controlled PATH: git/grep/sed/bash present, gitleaks ABSENT -----------
STUB_BIN="$(mktemp -d -t stargate-t102-bin-XXXXXX)"
for tool in bash git grep sed cut head tail tr wc; do
  p=$(command -v "$tool" 2>/dev/null) && ln -sf "$p" "$STUB_BIN/$tool"
done

ROOT_SANDBOX="$(mktemp -d -t stargate-t102-XXXXXX)"
ERR="$ROOT_SANDBOX/err"
REPO_IDX=0
cleanup() { rm -rf "$ROOT_SANDBOX" "$STUB_BIN"; }
trap cleanup EXIT

# make_repo -> sets $REPO to a fresh throwaway repo with the hook installed.
make_repo() {
  REPO_IDX=$((REPO_IDX + 1))
  REPO="$ROOT_SANDBOX/repo-$(printf '%03d' "$REPO_IDX")"
  git init -q "$REPO"
  git -C "$REPO" config user.email "t102@test.local"
  git -C "$REPO" config user.name "t102-test"
  mkdir -p "$REPO/.githooks"
  cp "$HOOK_SRC" "$REPO/.githooks/pre-commit"
  chmod +x "$REPO/.githooks/pre-commit"
  git -C "$REPO" config core.hooksPath ".githooks"
}

# stage_and_commit <path> <content> -> hook exit code (output captured in $ERR)
stage_and_commit() {
  local path="$1" content="$2"
  mkdir -p "$REPO/$(dirname "$path")"
  printf '%s' "$content" > "$REPO/$path"
  git -C "$REPO" add -- "$path"
  PATH="$STUB_BIN" git -C "$REPO" commit -q -m "t:$path" 2>"$ERR"
  return $?
}

# --- Scenario 1: TRUE POSITIVES — real bearer token MUST be blocked --------
make_repo
rc=0; stage_and_commit "a.yaml" "bearer: $SECRET"$'\n' || rc=$?
assert '[ "$rc" -ne 0 ]' "bearer: <secret> blocked"

make_repo
rc=0; stage_and_commit "b.env" "STARGATE_TEST_TOKEN=$SECRET"$'\n' || rc=$?
assert '[ "$rc" -ne 0 ]' "STARGATE_TEST_TOKEN=<secret> blocked"

make_repo
rc=0; stage_and_commit "c.txt" "the access token value is $SECRET here"$'\n' || rc=$?
assert '[ "$rc" -ne 0 ]' "token <secret> (keyword substring) blocked"

# --- Scenario 2: FALSE POSITIVES — longer/non-adjacent hex MUST pass -------
make_repo
rc=0; stage_and_commit "d.txt" \
  "checksum: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"$'\n' || rc=$?
assert '[ "$rc" -eq 0 ]' "sha256 digest (64 hex) not flagged"

make_repo
rc=0; stage_and_commit "e.txt" \
  "fingerprint: 1234567890abcdef1234567890abcdef12345678"$'\n' || rc=$?
assert '[ "$rc" -eq 0 ]' "40-hex fingerprint not flagged"

make_repo
rc=0; stage_and_commit "f.txt" "hash: $SECRET"$'\n' || rc=$?
assert '[ "$rc" -eq 0 ]' "32-hex under non-keyword (hash) not flagged"

make_repo
rc=0; stage_and_commit "g.txt" \
  "commit 1a2b3c4d5e6f7081920304050607080910111213"$'\n' || rc=$?
assert '[ "$rc" -eq 0 ]' "40-hex git oid not flagged"

# --- Scenario 3: ALLOWLIST — documented placeholder MUST pass --------------
make_repo
rc=0; stage_and_commit "h.yaml" "token: $PLACEHOLDER"$'\n' || rc=$?
assert '[ "$rc" -eq 0 ]' "documented placeholder allowlisted"

# --- Scenario 4: STAGED-ONLY — unstaged secret must NOT be scanned ---------
make_repo
printf 'clean content\n' > "$REPO/clean_i.txt"
printf 'bearer: %s\n' "$SECRET" > "$REPO/dirty_unstaged.txt"   # intentionally NOT staged
git -C "$REPO" add -- clean_i.txt
rc=0; PATH="$STUB_BIN" git -C "$REPO" commit -q -m "t:staged-only" 2>"$ERR" || rc=$?
assert '[ "$rc" -eq 0 ]' "unstaged secret not scanned"

# --- Scenario 5: REDACTION — secret value MUST NOT leak into scanner output -
make_repo
printf 'bearer: %s\n' "$SECRET" > "$REPO/redact_i.txt"
git -C "$REPO" add -- redact_i.txt
PATH="$STUB_BIN" git -C "$REPO" commit -q -m "t:redact" 2>"$ERR" || true
# The full 32-hex secret must never appear in stderr.
assert '! grep -q -- "$SECRET" "$ERR"' "secret value redacted from output"
# And the rule must be identifiable (path/rule reported).
assert 'grep -qiE "bearer|token|stargate|secret|redact" "$ERR"' "rule identified in output"

# --- Report ---------------------------------------------------------------
if [ "${#errs[@]}" -ne 0 ]; then
  printf 'FAIL — %d assertion(s):\n' "${#errs[@]}" >&2
  for e in "${errs[@]}"; do printf '  - %s\n' "$e" >&2; done
  exit 1
fi
echo "PASS — secret-scan fallback regression (${0##*/})"
