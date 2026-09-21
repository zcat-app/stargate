---
id: "T165"
title: "Validate Tor observer deployment and consumers"
status: in-progress
created: "2026-09-19"
last_updated: 2026-09-21
source: "specs/001-tor-route/tickets/T138-investigate-tor-observer-authority.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T138", "T162", "T164"]
parallel: false
files_budget: 14
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs:
  - ".specify/memory/constitution.md"
  - "specs/001-tor-route/contracts/foundation-boundaries.md §Deployment and authority"
  - "specs/001-tor-route/tickets/T138-investigate-tor-observer-authority.md"
  - "THREAT-MODEL.md §3.1, §4.2 and §5.8"
decision_refs: []
remediates: "T138"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T165: Validate Tor observer deployment and consumers

## Context

T164 supplies the observer implementation and unit/contract regression. This
ticket proves the deployment boundary in the real Local topology selected by
T134/T162 and updates every consumer that depends on Tor health or lifecycle
events, including the clean-host deployment checks and T155's integrated gate.

## Analysis

- **Must hold:** from the CP production identity, the cookie path, Tor-cookie
  group, raw `tor:9051`, stream/circuit/configuration commands and arbitrary
  command forwarding are unavailable; from the observer identity, the bounded
  health path works; positive health and negative controls are captured in the
  relevant namespaces.
- **Gated:** compose structure, socket ownership, AppArmor/network policy where
  applicable, CP event mapping, and the disposable-to-production probe suite.
- **Residue:** external human release review and any future lifecycle capability
  remain release/governance work, not observer health permission.

## Acceptance

1. Exercise the clean-host Local deployment with the observer and T162's
   per-consumer fabrics. Assert CP cannot see the cookie or raw Tor endpoint,
   while the observer can return sanitized health.
2. Run the concrete T138 §"Concrete safe probe matrix" from the CP production context and a
   positive health probe with a positive capture/control fixture. Prove the
   forbidden commands never reach the Tor control listener and no raw value
   enters events, logs, metrics, audit rows or errors.
3. Validate restart, timeout, malformed-reply, observer-down and CP-down
   behavior against T138's exact token/event matrix, including refused
   invalid/absent caller authentication and no false Tor exit/restart event.
   CP health remains advisory; authenticated DP routing continues without
   route downgrade or request admission through CP.
4. Update deployment checks and the fixed event consumers, including the
   affected clean-host consumer T123. Explicitly verify that T124's
   sidecar-native healthcheck remains inside the Tor TCB rather than becoming a
   CP-facing command proxy, and preserve the current-gap language until the
   evidence is complete.
5. Attach the production-namespace evidence to T155 and run the exact
   `scripts/verify.sh` gate on the reviewed candidate.

## Out-of-scope

Adding Tor lifecycle commands, exposing stream/circuit data to CP, changing
CONNECT isolation semantics, or accepting an unresolved observer boundary.

## Notes

This ticket is the closure/evidence follow-up, not permission to weaken the
observer contract for a convenient stack startup.
