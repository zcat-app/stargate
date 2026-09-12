---
id: "T136"
title: "Prevent cross-site first-party isolation collisions"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T053", "T139", "T156"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T053"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T136: Prevent cross-site first-party isolation collisions

## Context

M3: actual router probes collapse alice.co.uk/bob.co.uk and alice.github.io/bob.github.io onion subrequests onto equal SOCKS usernames.

## Analysis

- Must hold: the ticket acceptance and cited constitutional properties.
- Gated: existing baseline verify is green; it did not catch the audited issue.
- Residue: the specific missing property in Context; the acceptance probes below must discriminate it. Investigation-only tickets must resolve the design before authorizing production changes.

## Acceptance

1. Write failing router-level tests with identical device credentials and same onion destination but distinct governing documents under co.uk and github.io; require distinct usernames.
2. Ground the exact FR-002 eTLD+1 contract; use correct registrable-domain computation or obtain the required spec decision before a conservative full-host alternative. Never guess the last two labels.
3. Preserve documentUrl/originUrl precedence, onion/IP identities, malformed-input behavior, proxyDNS and credential non-disclosure.
4. Run the relevant browser suites, scripts/verify.sh, and both required independent reviews. Record the separate live-browser/circuit validation limit honestly.

5. T156 refinement: isolate authenticated devices and browser profiles as well as initiating
   sites; specify and test suffix/private-domain, onion, scheme/port, IP, opaque/worker/navigation
   cases and bounded collision-resistant wire encoding. No runtime suffix fetch or bearer-secret
   exposure to Tor. Add both peer/browser regression and compatibility evidence before code.

## Out-of-scope

Popup semantics (T150), runtime hardening policy, unrelated routing features, or live network fetching of suffix data.

## Notes

Filed from the current-state foundation audit. This is pending work, not a
review approval or accepted risk. For implementation, demonstrate the privacy
regression before the fix; tests_first is empty because the named regression
is authored within this ticket rather than a separate test ticket. For design
work, no production implementation is authorized until its stated decision
boundary is satisfied. Preserve approved historical commits.
