#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/live-e2e/mullvad-browser-hardening/run.sh
#
# Release-cadence live end-to-end verification of the browser-hardening
# precondition (Constitution Principle III bullet 3 as amended by T091;
# architecture spec §14.5; FR-004).
#
# NOT run by scripts/verify.sh on the hermetic PR path. This is the real-
# browser proof that the externally verified precondition holds: a green
# Node unit over invented prefs is explicitly NOT evidence (sol-review B4).
#
# Cadence: run manually before a release tag, and on any change to arch
# §14.5, THREAT-MODEL §5.3/§5.4/§5.5, or the Principle III amendment.
#
# Opt in with STARGATE_LIVE_E2E=1. Without it, SKIP and exit 0.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# --- opt-in gate -----------------------------------------------------------
if [ "${STARGATE_LIVE_E2E:-0}" != "1" ]; then
  echo "SKIP: release-cadence live-e2e. Set STARGATE_LIVE_E2E=1 to run."
  echo "  See tests/live-e2e/mullvad-browser-hardening/README.md"
  exit 0
fi

# --- preconditions ---------------------------------------------------------
BROWSER_BIN="${MULLVAD_BROWSER_BIN:-/opt/mullvad-browser/Mullvad Browser}"
PROFILE_DIR="${MULLVAD_BROWSER_PROFILE:?MULLVAD_BROWSER_PROFILE must point at the dedicated test profile dir}"
EXTENSION_ZIP="$(ls extension/dist/stargate-*.zip 2>/dev/null | head -1 || true)"

if [ ! -x "$BROWSER_BIN" ]; then
  echo "FAIL: Mullvad Browser not found at '$BROWSER_BIN'." >&2
  echo "  Set MULLVAD_BROWSER_BIN to the real binary path." >&2
  exit 1
fi
if [ ! -d "$PROFILE_DIR" ]; then
  echo "FAIL: test profile dir not found: '$PROFILE_DIR'." >&2
  echo "  Create a dedicated test profile (see README.md Preconditions)." >&2
  exit 1
fi
if [ -z "$EXTENSION_ZIP" ]; then
  echo "FAIL: extension zip not found at extension/dist/stargate-*.zip." >&2
  echo "  Build it first: bash extension/package.sh" >&2
  exit 1
fi

PREFS_JS="$PROFILE_DIR/prefs.js"
if [ ! -f "$PREFS_JS" ]; then
  echo "FAIL: $PREFS_JS not found. Start Mullvad Browser once with the test" >&2
  echo "  profile so it materialises prefs.js, then re-run." >&2
  exit 1
fi

echo ">>> Mullvad Browser hardening live-e2e"
echo "    browser:   $BROWSER_BIN"
echo "    profile:   $PROFILE_DIR"
echo "    extension: $EXTENSION_ZIP"
echo

# --- property map (README §"What it verifies") ----------------------------
# Each property: <id>|<name>|<grep pattern against prefs.js>|<expected match>
# Properties 1-3 are load-bearing: the WebExtensions API does not expose
# these prefs, so this out-of-band read is the ONLY verification.
# NOTE on pref values:
#  - prop 1 requires network.trr.mode == 5 (the EXPLICITLY-OFF sentinel:
#    "TRR disabled"). A stock profile with mode 0 (default, also effectively
#    DoH-off) would false-RED; the test profile must set mode 5 explicitly.
#  - patterns match only user_pref(...) lines; a profile enforcing via
#    lockPref/policies.json (not written as user_pref) would false-RED —
#    see README §"Pref-source caveat".
declare -a PROPS=(
  "1|DoH off (network.trr.mode==5)|user_pref\(\"network\.trr\.mode\", 5\)|1"
  "2|DoT off (no network.dns.over_tls.* set to true)|user_pref\(\"network\.dns\.over_tls[^\"]*\",[[:space:]]*true\)|0"
  "3|HTTP/3 off (network.http.http3.enable==false)|user_pref\(\"network\.http\.http3\.enable\", false\)|1"
  "4|WebRTC off (media.peerconnection.enabled==false)|user_pref\(\"media\.peerconnection\.enabled\", false\)|1"
)

FAIL=0
check_prop() {
  local id="$1" name="$2" pattern="$3" expected="$4"
  local actual
  # `grep -c` always prints the count and exits 1 on no-match; under `set -e`
  # that non-zero exit would abort the script, so tolerate it with `|| true`
  # (true is silent — unlike `|| echo 0`, which would append a second 0).
  actual=$(grep -Ec "$pattern" "$PREFS_JS" 2>/dev/null || true); actual=${actual:-0}
  if [ "$actual" -eq "$expected" ]; then
    printf '  [PASS] %s. %s (matches=%s, expected=%s)\n' "$id" "$name" "$actual" "$expected"
  else
    printf '  [FAIL] %s. %s (matches=%s, expected=%s)\n' "$id" "$name" "$actual" "$expected" >&2
    FAIL=1
  fi
}

echo ">>> Part 1 — externally verified profile precondition (prefs.js)"
for p in "${PROPS[@]}"; do
  IFS='|' read -r id name pattern expected <<<"$p"
  check_prop "$id" "$name" "$pattern" "$expected"
done
echo

# Property 4-runtime and property 6 require real-browser observations; the
# connection-level probes documented in README cover their named scenarios.
# Observe the current runtime result and routing behavior, rather than reading
# an audit result from the obsolete storage.local.hardening key (T205).
# Property 5's implementation and claim reconciliation remains T197's
# responsibility. Record actual outcomes in the release run sheet.
echo ">>> Part 2 — extension runtime gate + foreign-extension inventory"
echo "  MANUAL (Phase 5+ automation deferred): load the extension, confirm"
echo "  hardeningOk agrees with peerConnectionEnabled, exercise the foreign-"
echo "  extension inventory (allowlisted present, disallowed flagged), and"
echo "  confirm fail-closed routing with WebRTC forcibly enabled."
echo "  Record the result in the release run sheet."
echo

# --- summary --------------------------------------------------------------
if [ "$FAIL" -ne 0 ]; then
  echo "RESULT: RED — one or more hardening prefs are wrong in the profile." >&2
  echo "  Fix the profile, re-run. A failure here is a release blocker." >&2
  exit 1
fi
echo "RESULT: GREEN (automated floor) — prefs 1-4 verified against $PREFS_JS."
echo "  Complete the manual Part 2 checks per the README before tagging."
exit 0
