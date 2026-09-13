---
id: "T137"
title: "Create a fresh deadline for each token-reload RPC"
status: done
created: "2026-09-12"
last_updated: 2026-09-13
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T038", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T038"
tests_first: []
reviews: { round: 2, date: 2026-09-13, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T137: Create a fresh deadline for each token-reload RPC

## Context

M4: ReloadTokensClient retains a stub whose absolute deadline begins at construction; a first call after eleven seconds already fails locally.

## Analysis

- **Must hold** — every `ReloadTokensClient.reload` invocation receives an
  independent ten-second deadline measured from that invocation. Constructing
  or idling the retained client must not consume the first RPC's budget, and a
  delayed stale-generation response must not consume the reconciled attempt's
  budget. Calls remain bounded; the loader's maximum-attempt, generation
  adoption and transport-error policies do not change. Mutual TLS, version
  metadata and opaque verifier handling remain unchanged.
- **Gated** — a real-UDS, mutually authenticated production-client regression
  idles beyond ten seconds before its first call. A production loader/channel
  regression scripts a delayed stale reply followed by a delayed successful
  reply and observes both generations complete. Java contract tests and
  `scripts/verify.sh` cover the surrounding client and reconciliation paths.
- **Residue** — the regressions use deliberate wall-clock margins, so extreme
  scheduler stalls remain outside deterministic proof. Independent redteam
  reviews whether any retained or reconciled call can still inherit an aged
  deadline and whether the existing bounded-failure policy was preserved.

## Acceptance

1. Write a production-client regression that idles past the current deadline before calling a reachable authenticated DP fixture; the first call must still get its full bounded attempt window.
2. Exercise stale-generation reconciliation after a delayed first reply; its next attempt gets a fresh deadline.
3. Move the per-attempt deadline to RPC invocation while preserving bounded calls and the existing generation/transport-error policy.
4. Run Java contract tests, scripts/verify.sh and both required independent reviews.

## Out-of-scope

General retry/backoff or DP-restart re-push policy (T132), and changing token revocation semantics.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.

Round-2 evidence note: the original red Maven output was overwritten by later
green Surefire reports. `reviews/T137/README.md` preserves an honestly labelled
retrospective replay of the unchanged final regressions against the identified
base production snapshot and repaired candidate; it does not claim recovery of
the missing original transcript.
