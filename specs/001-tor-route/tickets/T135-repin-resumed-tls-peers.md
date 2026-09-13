---
id: "T135"
title: "Reject resumed TLS peers after public-key rotation"
status: in-review
created: "2026-09-12"
last_updated: 2026-09-13
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T045", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T045"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T135: Reject resumed TLS peers after public-key rotation

## Context

M2: production server TLS session resumption skips the current cp.pub pin; the independent real-UDS probe accepted the old identity after replacement.

## Analysis

- Must hold: every full or resumed TLS connection to `dp.sock` must prove possession of the
  key currently pinned by `cp.pub` before `ReloadTokens` dispatch. Replacing that pin without
  restarting the DP must reject the old CP identity while a fresh handshake from the newly pinned
  identity succeeds. TLS 1.3, mutual authentication, protocol-version rejection, and the existing
  wrong-key behavior remain unchanged.
- Gated: a production-server regression over a real Unix socket obtains and reuses a TLS 1.3
  session ticket, observes that resumption was attempted after the pin replacement, and checks the
  server generation to prove the rejected peer dispatched no RPC. Existing controlclient tests pin
  full-handshake wrong-key rejection, TLS 1.3/ALPN configuration, and protocol-version handling;
  `scripts/verify.sh` runs the Go workspace containing them.
- Residue: the hermetic regression proves the Go DP server and gRPC handler boundary, not the
  Java/Go compose path or the separate certificate validity/renewal policy owned by T148. Review
  must therefore confirm the verification hook executes on resumed handshakes and still re-reads
  `cp.pub` for each connection; no claim is made that rotation terminates already-established
  channels.

## Acceptance

1. Before implementation, add a real-UDS regression that obtains a session ticket, replaces cp.pub without restarting DP, and proves the old client cannot invoke ReloadTokens on a resumed connection.
2. Require a fresh handshake with the newly pinned identity to succeed; preserve existing wrong-key, version and TLS1.3 tests.
3. Apply current pin verification to resumed connections or disable the resumption path. Do not change key-rotation policy or weaken mTLS.
4. Run scripts/verify.sh and both required independent review stages.

## Out-of-scope

Certificate validity-policy changes (T148), CP retry semantics (T132/T137), or rotation by restarting DP as a test workaround.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
