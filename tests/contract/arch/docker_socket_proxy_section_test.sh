#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/arch/docker_socket_proxy_section_test.sh — structural +
# cross-file contract test for the docker-socket-proxy section (§16.1) in
# specs/000-architecture/spec.md (T018).
#
# Why this is structural (no runtime bring-up): the arch spec is a
# documentation artifact. Its CONTRACT for the docker-socket-proxy section
# is the lock-step with SECURITY-DECISIONS.md's docker-socket-proxy entry
# (T017a) on TWO load-bearing clauses that T017a's r3 redteam flagged as
# drifted:
#
#   - M9 (root-run honesty): §16.1's Mitigations list MUST carry the
#     honest "no defense-in-depth user-isolation control / proxy runs as
#     root" framing; the FALSE "proxy runs as the unprivileged user its
#     upstream image declares" clause MUST NOT appear (verified at T017a
#     via `docker image inspect` — tecnativa/docker-socket-proxy:0.3.0
#     has empty Config.User = runs as root).
#
#   - M10 (three-reacher release-blocker): §16.1's Profile-applicability
#     release-blocker paragraph MUST name the data plane (DP) AND Tor as
#     reachers alongside the CP — the DP is the most concerning pivot
#     since it faces internet-supplied input the CP does not, and Tor is
#     also reachable. The CP-only narrowing ("expose the CP to non-
#     localhost callers" as the sole reacher) MUST NOT appear.
#
# Plus cross-file digest equality: the docker-socket-proxy image digest
# at compose/env/local.env.example's DOCKER_SOCKET_PROXY_IMAGE= line MUST
# appear verbatim in §16.1, gating silent digest bumps at either file.
#
# This test is the arch-spec-side companion to T017a's
# tests/contract/security-decisions/docker_socket_proxy_entry_test.sh,
# which scopes the same assertions to the SECURITY-DECISIONS.md entry
# block. Together they gate the lock-step on BOTH sides going forward
# (T017a's R8 follow-up, promoted into the gated set by T018).
#
# Scope: assertions are scoped to the §16.1 section (extracted by anchor
# `### 16.1 \`docker-socket-proxy\`` through the next `^---` separator or
# the next `^## ` heading, whichever comes first). File-scoped assertions
# would false-positive on incidental mentions elsewhere in the spec.
#
# Properties gated (M-numbers reference T018 §Analysis):
#   - A-M9 §16.1 root-run honesty (positive: "runs as root" / "no
#         defense-in-depth"; negative: NOT "unprivileged user its upstream
#         image declares").
#   - A-M10 §16.1 three-reacher release-blocker (paragraph-scoped
#         positive: DP + Tor named alongside CP; negative: NOT CP-only
#         "expose the CP to non-localhost" as the sole reacher).
#   - A-cross tecnativa digest verbatim in §16.1.
#
# Hermetic: file reads + grep + awk only. No network, no daemon.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

SPEC="specs/000-architecture/spec.md"
ENV_EXAMPLE="compose/env/local.env.example"

errs=()
bail() { errs+=("$*"); }

[ -f "$SPEC" ]       || { echo "FAIL: $SPEC missing" >&2; exit 1; }
[ -f "$ENV_EXAMPLE" ]|| { echo "FAIL: $ENV_EXAMPLE missing" >&2; exit 1; }
command -v grep >/dev/null 2>&1 || { echo "FAIL: grep not installed" >&2; exit 1; }
command -v awk >/dev/null 2>&1 || { echo "FAIL: awk not installed" >&2; exit 1; }

# --- extract §16.1 --------------------------------------------------------
# Anchor: `### 16.1 \`docker-socket-proxy\``. Section ends at the next
# `^---` separator (the spec's section divider) OR the next `^## ` heading,
# whichever comes first. Robust against both layouts.
SECTION_START=$(grep -nE '^### 16\.1 `docker-socket-proxy`' "$SPEC" | head -1 | cut -d: -f1)
[ -n "$SECTION_START" ] || { echo "FAIL: §16.1 heading not found in $SPEC" >&2; exit 1; }

# Find the first `^---` OR `^## ` after SECTION_START.
SECTION_END=$(awk -v s="$SECTION_START" 'NR>s && (/^---$/ || /^## /) {print NR; exit}' "$SPEC")
[ -n "$SECTION_END" ] || { echo "FAIL: §16.1 section end not found" >&2; exit 1; }
# Section content is lines SECTION_START..SECTION_END-1.
SECTION_BLOCK=$(awk -v s="$SECTION_START" -v e=$((SECTION_END - 1)) 'NR>=s && NR<=e' "$SPEC")

# has_sec <pattern> <label> — grep -Ei scoped to §16.1.
has_sec() { printf '%s' "$SECTION_BLOCK" | grep -Ei -- "$1" >/dev/null 2>&1 || bail "$2 (pattern '$1' not found in §16.1 lines $SECTION_START..$((SECTION_END-1)))"; }
lacks_sec() { printf '%s' "$SECTION_BLOCK" | grep -Ei -- "$1" >/dev/null 2>&1 && bail "$2 (forbidden pattern '$1' found in §16.1 lines $SECTION_START..$((SECTION_END-1)))"; }

# Sanity: the extracted block MUST contain the load-bearing §16.1 markers
# (if it doesn't, the anchor / end-detection has drifted and every
# downstream assertion is non-load-bearing).
has_sec "docker-socket-proxy" "sanity: §16.1 block must mention docker-socket-proxy"
has_sec "TCB" "sanity: §16.1 block must mention the TCB (residual-trust framing)"

# --- A-M9: root-run honesty ------------------------------------------------
# Positive: §16.1 MUST carry the honest "no defense-in-depth user-isolation
# control" framing naming the verified-empty Config.User / runs-as-root
# fact (mirrors SECURITY-DECISIONS.md docker-socket-proxy entry M4 —
# redteam r2 MAJOR-2; T018 propagates the same fix to §16.1).
has_sec "(no defense-in-depth|Config\.User is empty|runs as root|verified.*empty)" \
  "A-M9: §16.1 Mitigations MUST carry the 'no defense-in-depth user-isolation control / runs as root' framing (T017a r2 MAJOR-2 propagation)"
# Negative: §16.1 MUST NOT carry the FALSE "unprivileged user its upstream
# image declares" clause (verified false at T017a via docker image inspect).
lacks_sec "unprivileged user its upstream image declares" \
  "A-M9: §16.1 MUST NOT carry the false 'unprivileged user its upstream image declares' clause (verified false — Config.User empty = root)"

# --- A-M10: three-reacher release-blocker ----------------------------------
# The Release-blocker paragraph is extracted by anchor `**Profile
# applicability**` through the next blank line (mirrors T017a's M9
# paragraph-scope pattern, redteam r3 MIN-1's positive-assertion inversion).
RB_ANCHOR='\*\*Profile applicability\*\*'
RB_START=$(printf '%s' "$SECTION_BLOCK" | grep -nE "$RB_ANCHOR" | head -1 | cut -d: -f1)
[ -n "$RB_START" ] || bail "A-M10: could not locate Release-blocker paragraph by anchor 'Profile applicability' in §16.1"
RB_PARA=$(printf '%s' "$SECTION_BLOCK" | awk -v s="$RB_START" 'NR<s {next} NR==s {print; next} /^$/ {exit} {print}')
has_rb() { printf '%s' "$RB_PARA" | grep -Ei -- "$1" >/dev/null 2>&1 || bail "$2 (pattern '$1' not found in §16.1 Release-blocker paragraph)"; }
lacks_rb() { printf '%s' "$RB_PARA" | grep -Ei -- "$1" >/dev/null 2>&1 && bail "$2 (forbidden pattern '$1' found in §16.1 Release-blocker paragraph)"; }

# Positive: the Release-blocker paragraph MUST name the data plane (DP) AND
# Tor alongside the CP. The DP is the most concerning pivot (faces internet-
# supplied input the CP does not); Tor is also a reacher. Inverted-shape
# guard — regex tripwires cannot distinguish "narrows" from "honestly
# describes narrowing," so assert the POSITIVE.
has_rb "(data plane|\bDP\b)" \
  "A-M10: §16.1 Release-blocker paragraph MUST name the data plane (DP) — T017a r2 MAJ-1 / r3 MIN-1 propagation"
has_rb "\bTor\b" \
  "A-M10: §16.1 Release-blocker paragraph MUST name Tor"
has_rb "\bCP\b|control plane" \
  "A-M10: §16.1 Release-blocker paragraph MUST still name the CP (the third reacher)"
# Negative: the CP-only narrowing phrase ("expose the CP to non-localhost
# callers" as the SOLE reacher) MUST NOT appear in the Release-blocker
# paragraph. We scope the negative to the paragraph rather than the whole
# section because incidental mentions elsewhere in §16.1 are legitimate.
lacks_rb "expose the CP to non-localhost callers" \
  "A-M10: §16.1 Release-blocker paragraph MUST NOT carry the CP-only narrowing phrase 'expose the CP to non-localhost callers' (T017a r2 MAJ-1 / r3 MAJ-1)"

# --- A-cross: tecnativa digest verbatim in §16.1 ----------------------------
# Source of truth: compose/env/local.env.example DOCKER_SOCKET_PROXY_IMAGE=.
# §16.1 MUST quote the same digest verbatim (gates silent digest bumps at
# either file — same shape as T017a's M5 on the entry side).
ENV_LINE=$(grep -E '^DOCKER_SOCKET_PROXY_IMAGE=' "$ENV_EXAMPLE" | head -1)
[ -n "$ENV_LINE" ] || { echo "FAIL: DOCKER_SOCKET_PROXY_IMAGE missing from $ENV_EXAMPLE" >&2; exit 1; }
DSP_DIGEST=$(printf '%s' "$ENV_LINE" | grep -Eo 'sha256:[0-9a-f]{64}' | head -1)
[ -n "$DSP_DIGEST" ] || { echo "FAIL: no sha256:<64hex> digest in $ENV_EXAMPLE's DOCKER_SOCKET_PROXY_IMAGE line" >&2; exit 1; }
has_sec "$DSP_DIGEST" \
  "A-cross: docker-socket-proxy digest $DSP_DIGEST (from $ENV_EXAMPLE) missing in §16.1 — silent digest drift"

# --- report ----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T018 §16.1 docker-socket-proxy section contract test (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T018 §16.1 docker-socket-proxy section contract test (root-run honesty + three-reacher release-blocker + cross-file digest invariants, §16.1-scoped)"
exit 0
