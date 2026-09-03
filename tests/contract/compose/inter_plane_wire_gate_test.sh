#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# inter_plane_wire_gate_test.sh — substrate test for the inter-plane wire
# gate's RUNTIME-tier detection probes (T115; the gate itself is T095).
#
# The gate self-lifts from SKIP to FAIL-forcing when it detects the
# T038/T045/T050 impl. Its two detection probes must satisfy exactly:
#
#   Fixture A (comment-only .go file naming the RPCs in prose):
#     T045's ReloadTokens handler + WatchEvents subscription described in
#     comments — the probe must NOT fire (gate stays SKIP, exit 0).
#     This is the T115 regression: the old bare-word probe
#     `grep -rqE 'ReloadTokens|WatchEvents'` matched comment text and
#     flipped verify.sh RED on an impl-absent tree.
#
#   Fixture B1 (server registration call-site):
#     a non-comment `grpcpb.RegisterControlServer(gs, s)` line — the probe
#     MUST fire (gate FAILs on 0/9 LIFT-MARKERs; forcing function intact,
#     NOT softened into always-skip).
#
#   Fixture B2 (client construction call-site):
#     a non-comment `grpcpb.NewEventsClient(conn)` line — same MUST fire,
#     independently of B1 (either alternative suffices, as before).
#
# Plus: the gate still carries a `runtime_content_detected` probe and the
# bare-word probe is gone (T115 §Acceptance #3).
#
# MECHANICS: fixtures are created INSIDE the real data-plane/internal/ tree
# (the gate greps a fixed relative path) in a directory whose name starts
# with `_` — the go tool ignores `_`-prefixed directories, so even a
# kill -9 leak cannot break the data-plane build; the EXIT trap removes it
# on every normal path. verify.sh runs contract tests sequentially, so no
# other gate observes the fixtures mid-flight.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GATE="$REPO_ROOT/tests/contract/compose/inter_plane_wire_test.sh"
[ -f "$GATE" ] || { echo "FAIL: $GATE missing" >&2; exit 1; }
[ -d "$REPO_ROOT/data-plane/internal" ] || {
  echo "FAIL: data-plane/internal/ missing — the gate's probe tree" >&2; exit 1; }

FIXDIR="$(mktemp -d "$REPO_ROOT/data-plane/internal/_wire-gate-fixture-XXXXXX")"
cleanup() { rm -rf "$FIXDIR"; }
trap cleanup EXIT

errs=()
bail() { errs+=("$*"); }
assert_grep() { local pat="$1" label="$2" out="$3"
  if printf '%s' "$out" | grep -qE "$pat"; then :; else
    bail "ASSERT FAIL [$label]: pattern /$pat/ not in gate output"; fi; }
assert_nogrep() { local pat="$1" label="$2" out="$3"
  if printf '%s' "$out" | grep -qE "$pat"; then
    bail "ASSERT FAIL [$label]: pattern /$pat/ SHOULD be absent but matched"; fi; }

run_gate() {  # run_gate -> stdout+stderr of the real gate; rc in GATE_RC
  GATE_OUT="$(bash "$GATE" 2>&1)"
  GATE_RC=$?
}

# --- Fixture A: comment-only file names the RPCs — must NOT fire -----------
cat > "$FIXDIR/reload_doc.go" <<'EOF'
// Wire-gate substrate fixture A (T115) — COMMENT-ONLY file.
// T045's ReloadTokens handler rejects stale proposals; the WatchEvents
// subscription is T045's client. This is prose: no gRPC construction
// symbol exists in this tree, so the RUNTIME tier must stay SKIP.
EOF
run_gate
if [ "$GATE_RC" -eq 0 ]; then :; else
  bail "A-exit-0: comment-only fixture made the gate exit $GATE_RC (probe fired on prose — the T115 false-positive class)"
fi
assert_grep 'RUNTIME tier SKIP:' "A-stays-skip" "$GATE_OUT"
assert_nogrep 'GATE-LIFT REQUIRED' "A-no-lift" "$GATE_OUT"
assert_grep 'structural tier green' "A-structural-still-green" "$GATE_OUT"
rm -f "$FIXDIR/reload_doc.go"

# --- Fixture B1: server registration call-site — MUST fire ------------------
cat > "$FIXDIR/server_reg.go" <<'EOF'
// Wire-gate substrate fixture B1 (T115) — detection-POSITIVE, server side.
// Never compiled: the enclosing _-prefixed directory is ignored by the go
// tool. The non-comment line below is the fixture.
package fixture

grpcpb.RegisterControlServer(gs, s)
EOF
run_gate
if [ "$GATE_RC" -eq 1 ]; then :; else
  bail "B1-exit-1: registration call-site did NOT force the gate FAIL (rc=$GATE_RC) — forcing function broken"
fi
assert_grep 'RUNTIME tier GATE-LIFT REQUIRED' "B1-lift-required" "$GATE_OUT"
assert_grep 'LIFT-MARKER' "B1-blames-markers" "$GATE_OUT"
assert_grep 'FAIL: T095 inter-plane wire contract test' "B1-gate-fails" "$GATE_OUT"
rm -f "$FIXDIR/server_reg.go"

# --- Fixture B2: client construction call-site — MUST fire, independently ---
cat > "$FIXDIR/client_ctor.go" <<'EOF'
// Wire-gate substrate fixture B2 (T115) — detection-POSITIVE, client side.
package fixture

grpcpb.NewEventsClient(conn)
EOF
run_gate
if [ "$GATE_RC" -eq 1 ]; then :; else
  bail "B2-exit-1: client-construction call-site did NOT force the gate FAIL (rc=$GATE_RC) — forcing function broken"
fi
assert_grep 'RUNTIME tier GATE-LIFT REQUIRED' "B2-lift-required" "$GATE_OUT"
rm -f "$FIXDIR/client_ctor.go"

# --- Probe mechanism pins (T115 §Acceptance #3) -----------------------------
# The content probe still exists under its contract name...
if grep -q 'runtime_content_detected' "$GATE"; then :; else
  bail "probe-var-present: runtime_content_detected missing from the gate"
fi
# ...but the detection mechanism must not regress to a bare-word grep. This
# pin is a NARROW net: its pattern matches only a standalone -q flag followed
# by a single-quoted bare RPC word — it cannot see every historical spelling
# (e.g. the -rqE flag bundle and the two-grep alternation form evade it).
# Fixture A above is the load-bearing bare-probe regression catch: restoring
# any prose-matching probe makes the comment-only fixture fire the gate and
# the A-exit-0 assertion in this test fails.
if grep -qE "grep .*-q.*'(ReloadTokens|WatchEvents)'" "$GATE"; then
  bail "bare-probe-gone: the bare-word 'ReloadTokens|WatchEvents' grep is still the detection mechanism"
fi

# --- report -----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  printf 'FAIL: inter_plane_wire_gate_test.sh — %d assertion(s) failed:\n' "${#errs[@]}" >&2
  for e in "${errs[@]}"; do printf '  - %s\n' "$e" >&2; done
  exit 1
fi

echo "PASS: inter_plane_wire_gate_test.sh — comment-only no-detect + symbol-call detection (server, client) + probe mechanism pins hold."
exit 0
