---
id: T128
title: 'Stabilize TestMutualTLSHandshakeEndToEnd benign closeNotify close'
status: done
created: 2026-09-07
last_updated: 2026-09-07
source: hand-filed (T121 convention); observed RED on 001-tor-route during the 2026-09-07 T061 cherry-pick verify
phase: "6: Polish & Cross-Cutting Concerns"
story: ''
blocked_by: []
parallel: true
files_budget: 3   # raw-diff-path counting: 1 test-file edit + this ticket + STATUS regen (T116 convention)
privacy_critical: false   # test-harness stability; no product code paths touched (controlclient is the auth surface, but the fix is in test code)
complexity: low
risk: low
round_cap: 2
spec_refs:
   - specs/001-tor-route/contracts/control-grpc.md   # inter-plane mTLS pin contract the test guards (§3.3)
decision_refs:
   - data-plane/internal/controlclient/controlclient_test.go:461-473 — honest-client round trip; the Fatalf-on-Close at :469 is the flake
   - T105 (stabilize flaky run-task test) / T116 (journal race) — prior stability-ticket conventions
reviews: { round: 1, date: 2026-09-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T128: Stabilize TestMutualTLSHandshakeEndToEnd benign closeNotify close

## Context

Hand-filed 2026-09-07 after the flake surfaced as the single RED gate on
`001-tor-route` during the T061 cherry-pick verify (and was then
reproduced and root-caused by hand).

**Test**: `data-plane/internal/controlclient/controlclient_test.go`
`TestMutualTLSHandshakeEndToEnd`.

**Failure** (line ~469):

    close: tls: failed to send closeNotify alert (but connection was
    closed anyway): write unix @->…/handshake.sock: write: broken pipe

**Mechanism**: the honest-client leg writes its 4-byte ping, then calls
`tls.Conn.Close()`, which additionally writes the TLS closeNotify alert.
The in-test server goroutine reads the 4 bytes and immediately closes its
side. When the server's close wins that race, the client's closeNotify
write hits EPIPE, and `tls.Conn.Close` returns the (benign, explicitly
self-describing) "failed to send closeNotify alert (but connection was
closed anyway)" error — which the test currently escalates via `t.Fatalf`.
The property under test — mutual pin acceptance, ground-truthed by the
`serverErr` channel read at ~line 471 — is unaffected either way.

**Repro** (flaky, ~1 block in 3 under repetition; surfaced once in a full
`verify.sh` under load):

    cd data-plane && go test -count=10 -run TestMutualTLSHandshakeEndToEnd ./internal/controlclient/

Observed rates 2026-09-07: 4/40 and 9/30 failing sub-runs under
`-count=10` repetition; 15/15 clean single-package runs between bursts.

## Analysis

*(Quick pass — test-harness stability; no product code.)*

## Acceptance

1. The honest-client `Close` at ~line 469 no longer fails the test on the
   benign closeNotify/broken-pipe class (e.g. accept the
   "failed to send closeNotify alert" error explicitly, or `_ =` the Close
   with a comment naming why) — the round-trip ground truth remains the
   `serverErr` channel.
2. Zero assertion-weakening elsewhere: the rogue-client and wrong-server-key
   negatives (§3.3) keep their exact error expectations; the test still
   fails loudly on any serverErr anomaly.
3. Repro gate: `go test -count=10 -run TestMutualTLSHandshakeEndToEnd
   ./internal/controlclient/` passes 5 consecutive blocks.
4. `bash scripts/verify.sh` GREEN.

## Out-of-scope

- Any change to product code in `internal/controlclient` (server.go /
  client.go / tls.go) — the flake is test-side.
- The rogue/sneaky negative legs' semantics.
- Other packages' tests.

## Notes

Hand-filed 2026-09-07. Prior art: T105 (flaky run-task probe), T116
(watchevents journal race) — same "stability ticket" shape.

Constitution check: test-harness-only change; no privacy surface; Principle
VII unaffected (the test's assertions stay at full strength).
