#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/security-decisions/docker_socket_proxy_entry_test.sh —
# structural + cross-file contract test for the docker-socket-proxy entry
# in SECURITY-DECISIONS.md (T017a).
#
# Why this is structural (no runtime bring-up): SECURITY-DECISIONS.md is a
# documentation artifact. Its CONTRACT is (a) the docker-socket-proxy entry
# exists as a dated entry above the Tor entry (T017's preamble locks
# newest-first ordering), (b) it carries the load-bearing property claim
# ("CP/DP/Tor compromise does NOT escalate to host root") and the honest
# residual ("any code-exec inside the proxy container is host-root-
# equivalent"), and (c) the docker-socket-proxy image digest MUST NOT drift
# from the compose env.example source-of-truth. The cross-file M5 check is
# the load-bearing part: it promotes drift-detection into the PR-cadence
# gate (editing env.example's digest without updating SECURITY-DECISIONS.md
# — or vice versa — fails the test).
#
# Scope: most keyword assertions are line-range-scoped to the
# docker-socket-proxy entry block (DSP_LINE..TOR_LINE-1) so the sibling Tor
# entry's prose does not satisfy them. The r1-promoted clauses (M2 DP/Tor
# reachers, M3 transitive-dep closure, M4 unprivileged-user caveat) only
# become load-bearing under this scoping (redteam r2 MIN-1).
#
# Properties gated (M-numbers reference T017a §Analysis):
#   - M1 new dated entry heading present AND above the Tor entry (newest-first).
#   - M2 property bought: CP/DP/Tor-compromise-does-not-escalate-to-host-root
#         prose AND all three reachers named (redteam r1 MAJOR-2 promotion).
#   - M3 residual trust honest: proxy IS in the TCB; any code-exec inside
#         the proxy container is host-root-equivalent; transitive-dep closure
#         (HAProxy / Alpine base / libssl-analogue) named outside the env-flag
#         filter (redteam r1 MAJOR-1 promotion).
#   - M4 mitigations recorded: POST=0 / EVENTS=1 / CONTAINERS=1 / T019c /
#         digest-pinned / compose-internal-only AND the explicit "no
#         defense-in-depth user-isolation control" clause naming the
#         verified-empty Config.User (redteam r2 MAJOR-2 — proxy runs as
#         root; demoted sub-note replaced with a verified-empty assertion).
#   - M5 docker-socket-proxy image digest cross-equals compose/env/local.env.example.
#   - M6 THREAT-MODEL §3.1 citation present.
#   - M7 arch spec §16.1 citation present.
#   - M8 LAN/VPS release-blocker flag present.
#   - M9 regression guard: entry block MUST NOT contain the "limited to
#         CP-process-compromise" narrowing (redteam r2 MAJ-1 — r1 MAJOR-2
#         fix was incomplete until propagated to this paragraph).
#
# Hermetic: file reads + grep + awk only. No network, no daemon.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

SD="SECURITY-DECISIONS.md"
ENV_EXAMPLE="compose/env/local.env.example"
COMPOSE="compose/docker-compose.local.yml"

errs=()
bail() { errs+=("$*"); }

[ -f "$SD" ]         || { echo "FAIL: $SD missing" >&2; exit 1; }
[ -f "$ENV_EXAMPLE" ]|| { echo "FAIL: $ENV_EXAMPLE missing" >&2; exit 1; }
[ -f "$COMPOSE" ]    || { echo "FAIL: $COMPOSE missing" >&2; exit 1; }
command -v grep >/dev/null 2>&1 || { echo "FAIL: grep not installed" >&2; exit 1; }
command -v awk >/dev/null 2>&1 || { echo "FAIL: awk not installed" >&2; exit 1; }

# has <pattern> <label> — grep -Ei on SECURITY-DECISIONS.md (whole-file scope).
has() { grep -Ei -- "$1" "$SD" >/dev/null 2>&1 || bail "$2 (pattern '$1' not found in $SD)"; }

# --- M1: new dated entry heading AND above the Tor entry --------------------
# Both headings exist as `## <date> — <topic>` lines.
grep -E '^## [0-9]{4}-[0-9]{2}-[0-9]{2} — docker-socket-proxy' "$SD" >/dev/null 2>&1 \
  || bail "M1: no '## <date> — docker-socket-proxy ...' heading in $SD"
grep -E '^## [0-9]{4}-[0-9]{2}-[0-9]{2} — Tor sidecar' "$SD" >/dev/null 2>&1 \
  || bail "M1: Tor entry heading missing (T017a entry's position reference)"
# The docker-socket-proxy entry MUST appear BEFORE (lower line number than)
# the Tor entry — the preamble (T017) locks newest-first ordering. T017a
# is newer by being appended after T017, so it goes at the TOP of the
# dated-decisions region, directly below the preamble's `---` separator.
DSP_LINE=$(grep -En '^## [0-9]{4}-[0-9]{2}-[0-9]{2} — docker-socket-proxy' "$SD" | head -1 | cut -d: -f1)
TOR_LINE=$(grep -En '^## [0-9]{4}-[0-9]{2}-[0-9]{2} — Tor sidecar' "$SD" | head -1 | cut -d: -f1)
[ -n "$TOR_LINE" ] || bail "M1: could not resolve Tor entry line"
[ -n "$DSP_LINE" ] || bail "M1: could not resolve docker-socket-proxy entry line"
# Only compare once both lines are resolved (avoids `[: -lt :]` integer error).
[ "$DSP_LINE" -lt "$TOR_LINE" ] \
  || bail "M1: docker-socket-proxy entry (line $DSP_LINE) MUST appear ABOVE the Tor entry (line $TOR_LINE) — newest-first per preamble"

# Extract the docker-socket-proxy entry block (DSP_LINE..TOR_LINE-1) so the
# keyword assertions below are scoped to THIS entry rather than the whole
# file. Redteam r2 MIN-1: without this scoping the sibling Tor entry's
# "libssl3" and "Tor" tokens permanently satisfy several alternations,
# making the r1-promoted clauses non-load-bearing.
BLOCK_END=$((TOR_LINE - 1))
ENTRY_BLOCK=$(awk -v s="$DSP_LINE" -v e="$BLOCK_END" 'NR>=s && NR<=e' "$SD")

# has_blk <pattern> <label> — grep -Ei on the docker-socket-proxy entry block.
has_blk() { printf '%s' "$ENTRY_BLOCK" | grep -Ei -- "$1" >/dev/null 2>&1 || bail "$2 (pattern '$1' not found in docker-socket-proxy entry block $DSP_LINE..$BLOCK_END)"; }
lacks_blk() { printf '%s' "$ENTRY_BLOCK" | grep -Ei -- "$1" >/dev/null 2>&1 && bail "$2 (forbidden pattern '$1' found in docker-socket-proxy entry block $DSP_LINE..$BLOCK_END)"; }

# --- M2: property bought (CP/DP/Tor compromise ≠ host root) ----------------
has_blk "docker\.sock" "M2: docker-socket-proxy entry must reference docker.sock"
has_blk "host root" "M2: property-bought prose must name 'host root'"
has_blk "(does not escalate|does NOT escalate|cannot escalate|not[ -]escalate)" \
  "M2: property-bought prose must assert the CP-compromise-does-not-escalate property"
has_blk "control plane" "M2: property-bought prose must reference the control plane (CP)"
# Redteam r1 MAJOR-2: the proxy is reachable by the DP (untrusted-bytes boundary)
# and Tor too, not only the CP. The entry MUST name all three reachers so an
# auditor does not conclude "the proxy isolates only the CP."
has_blk "(data plane|\bDP\b)" \
  "M2: property-bought prose must reference the data plane (DP) — redteam r1 MAJOR-2"
has_blk "\bTor\b" \
  "M2: property-bought prose must reference the Tor sidecar as a third reacher — redteam r1 MAJOR-2"

# --- M3: residual trust honest (proxy IS in the TCB) -----------------------
has_blk "TCB" "M3: residual-trust prose must name the TCB"
has_blk "(host-root-equivalent|host root equivalent|host root)" \
  "M3: residual-trust prose must name proxy-compromise-is-host-root-equivalent"
# Redteam r1 MAJOR-1: residual is wider than env-flag-filter bypass. The
# entry MUST name the transitive-dep closure (HAProxy / base image / libssl
# analogue) as TCB sitting OUTSIDE the env-flag filter — same shape as T017's
# libssl3 residual. Without this clause a future softening could narrow the
# residual back to "filter bypass only."
has_blk "(transitive|HAProxy|base image|dependency closure|libssl)" \
  "M3: residual-trust prose must name the proxy's transitive-dep closure (HAProxy / base / libssl-analogue) as TCB outside the env-flag filter — redteam r1 MAJOR-1"
has_blk "(code-exec|code execution|arbitrary code)" \
  "M3: residual-trust prose must frame the residual as 'code-exec inside the proxy container' (wider than env-flag-filter bypass) — redteam r1 MAJOR-1"

# --- M4: mitigations recorded (matches the task body's enumerated list) -----
has_blk "POST=0" "M4: mitigation list must reference POST=0 lockdown"
has_blk "EVENTS=1" "M4: mitigation list must reference EVENTS=1"
has_blk "CONTAINERS=1" "M4: mitigation list must reference CONTAINERS=1"
has_blk "T019c" "M4: mitigation list must reference T019c runtime gate"
has_blk "(digest-pinned|digest pin|sha256:|pinned by.*digest)" \
  "M4: mitigation list must reference the digest pin (Principle IV)"
# Redteam r2 MAJOR-2: the prior "declares a non-root user today" claim was
# verified FALSE via `docker image inspect` (Config.User is empty = root).
# The entry MUST now carry the honest "no defense-in-depth user-isolation
# control" clause naming the verified-empty Config.User; it MUST NOT carry
# a "declares a non-root user" assertion. (The does-NOT-reduce-residual
# caveat from r1 MAJOR-3 is preserved inside this clause.)
has_blk "(no defense-in-depth|Config\.User is empty|runs as root|verified.*empty)" \
  "M4: entry must carry the verified 'no defense-in-depth user-isolation control' clause (proxy runs as root; redteam r2 MAJOR-2)"
lacks_blk "declares a non-root user" \
  "M4: entry MUST NOT carry the false 'declares a non-root user today' claim (verified false at r2 — Config.User is empty)"
has_blk "(compose-internal|no[ \`]ports:\`|not reachable|non-routable)" \
  "M4: mitigation list must reference the compose-internal-only / non-routable property"

# --- M5: docker-socket-proxy image digest + cross-file ----------------------
# Source of truth: compose/env/local.env.example DOCKER_SOCKET_PROXY_IMAGE=.
# Compose reads it via ${DOCKER_SOCKET_PROXY_IMAGE}. SECURITY-DECISIONS.md
# quotes the same digest verbatim.
ENV_LINE=$(grep -E '^DOCKER_SOCKET_PROXY_IMAGE=' "$ENV_EXAMPLE" | head -1)
[ -n "$ENV_LINE" ] || { echo "FAIL: DOCKER_SOCKET_PROXY_IMAGE missing from $ENV_EXAMPLE" >&2; exit 1; }
# Extract the sha256:<64hex> from the env line.
DSP_DIGEST=$(printf '%s' "$ENV_LINE" | grep -Eo 'sha256:[0-9a-f]{64}' | head -1)
[ -n "$DSP_DIGEST" ] || { echo "FAIL: no sha256:<64hex> digest in $ENV_EXAMPLE's DOCKER_SOCKET_PROXY_IMAGE line" >&2; exit 1; }
# SECURITY-DECISIONS.md MUST quote the same digest (scoped to entry block —
# the Tor entry does not contain this digest today, but scope it anyway so
# a future unrelated dated entry quoting the same hex does not satisfy M5).
has_blk "$DSP_DIGEST" \
  "M5: docker-socket-proxy digest $DSP_DIGEST (from $ENV_EXAMPLE) missing in entry block"

# --- M6: THREAT-MODEL §3.1 citation ----------------------------------------
has_blk "(§3\.1|3\.1)" "M6: docker-socket-proxy entry must cite §3.1"
has_blk "(THREAT-MODEL|threat model|local profile)" \
  "M6: §3.1 citation must pair with a THREAT-MODEL / local-profile keyword"

# --- M7: arch spec §16.1 citation ------------------------------------------
has_blk "(§16\.1|16\.1)" "M7: docker-socket-proxy entry must cite §16.1"
has_blk "(arch|architecture spec|auxiliary)" \
  "M7: §16.1 citation must pair with an arch / auxiliary keyword"

# --- M8: LAN/VPS release-blocker flag --------------------------------------
# Use word boundaries (`\b`) so the case-insensitive has_blk helper does not
# false-positive on tokens like "plant"/"land" (LAN).
has_blk "\bLAN\b" "M8: release-blocker prose must reference the LAN profile"
has_blk "\bVPS\b" "M8: release-blocker prose must reference the VPS profile"
has_blk "(release-block|MUST be revisited|revisit|non-localhost)" \
  "M8: release-blocker prose must flag the LAN/VPS profile as requiring re-evaluation"

# --- M9: regression guard — Release-blocker paragraph must name the
# three reachers (redteam r2 MAJ-1, tightened at r3 MIN-1).
#
# r2 MAJ-1 caught a fix-incomplete defect: the r1 MAJOR-2 widening
# landed in the Exposure-surface paragraph but was NOT propagated to
# the Release-blocker paragraph (which still narrowed to CP-only).
# r3 MIN-1 tightened the original regex tripwire but the regex shape
# fundamentally cannot distinguish "the entry narrows" from "the entry
# honestly describes §16.1's narrowing" (drift-reconciliation prose
# legitimately names §16.1's CP-only sentence) or from honest widening
# phrasings like "reachable only from internal (CP, DP, and Tor)".
# Per the redteam's recommended inversion: assert the POSITIVE — the
# Release-blocker paragraph MUST name the DP (the most concerning
# reacher per the Exposure-surface framing). A future narrowing that
# strips the DP from the Release-blocker paragraph fails this positive
# assertion regardless of how the narrowing is phrased.
RB_ANCHOR='Release-blocker for any future'
RB_START=$(printf '%s' "$ENTRY_BLOCK" | grep -nE "$RB_ANCHOR" | head -1 | cut -d: -f1)
[ -n "$RB_START" ] || bail "M9: could not locate Release-blocker paragraph by anchor '$RB_ANCHOR' in entry block"
# The Release-blocker paragraph extends from RB_START to the next blank line.
RB_PARA=$(printf '%s' "$ENTRY_BLOCK" | awk -v s="$RB_START" 'NR<s {next} NR==s {print; next} /^$/ {exit} {print}')
has_rb() { printf '%s' "$RB_PARA" | grep -Ei -- "$1" >/dev/null 2>&1 || bail "$2 (pattern '$1' not found in Release-blocker paragraph)"; }
has_rb "(data plane|\bDP\b)" \
  "M9: Release-blocker paragraph MUST name the DP (positive assertion; inverted-shape guard — redteam r2 MAJ-1 regression line)"
has_rb "\bTor\b" \
  "M9: Release-blocker paragraph MUST name Tor (positive assertion; inverted-shape guard)"
# Positive redundancy: the entry block MUST carry the three-reacher
# framing (slash-separated or comma-separated CP/DP/Tor) somewhere —
# a future narrowing that defeats the paragraph-scoped M9 tripwire would
# also defeat this entry-block-level assertion.
has_blk "(CP/DP/Tor|CP, DP,? and Tor|CP.*DP.*Tor)" \
  "M9: entry MUST carry the three-reacher framing (CP/DP/Tor or CP, DP, and Tor) somewhere in the block"

# --- report ----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T017a docker-socket-proxy entry contract test (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T017a docker-socket-proxy entry contract test (property-bought + residual-trust + cross-file digest invariants, entry-block-scoped)"
exit 0
