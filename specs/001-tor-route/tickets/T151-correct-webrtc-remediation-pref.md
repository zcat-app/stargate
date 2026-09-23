---
id: "T151"
title: "Name the actual WebRTC remediation preference"
status: done
created: "2026-09-12"
last_updated: 2026-09-23
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T055", "T139", "T156"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "low"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T055"
tests_first: []
reviews: { round: 1, date: 2026-09-23, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T151: Name the actual WebRTC remediation preference

## Context

Browser Minor m2: the notification tells operators to set the WebExtensions API path in about:config rather than media.peerconnection.enabled.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Write notification tests expecting media.peerconnection.enabled=false for a confirmed enabled setting, consistent with architecture section 14.5.
2. Distinguish confirmed enabled from unreadable API state without inventing a measured value; preserve restart instructions and the release-only hardening boundary.
3. Correct only remediation copy and directly related assertions; do not weaken runtime gates.
4. Run hardening/browser tests, scripts/verify.sh and both reviews; retain real-browser verification as separate release evidence.

## Out-of-scope

Broader runtime hardening changes, DoH/DoT/HTTP3 enforcement claims, or security-guarantee amendments.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.

Tests-first evidence (2026-09-23, pre-fix source snapshot `2f27afa`):
`node --test background/hardening.test.js` exited 1 with the new confirmed-enabled,
unset, and rejected-read notification assertions failing against the old copy.
After the implementation change, the same command passed all eight tests and
`extension/run-tests.sh` passed the full browser-extension suite. Real-browser
verification remains release-cadence evidence and is not claimed by these Node tests.
