---
id: "T206"
title: "Reject degraded DNS capture evidence"
status: in-progress
created: "2026-10-03"
last_updated: 2026-10-10
source: "T155 resumed transport falsification m1; falsify-1-transport.md (2026-10-03); maintainer-approved next scope after T203"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T183"]
parallel: false
files_budget: 8
privacy_critical: true
tests_first: []
complexity: medium
risk: medium
round_cap: 2
remediates: "T183"
spec_refs:
  - "specs/001-tor-route/spec.md FR-003 and FR-007"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
constitution_refs:
  - "I: Dumb Router, no destination DNS"
  - "III: DNS and route failure"
  - "VII/VIII: discriminating evidence and honest executed/skipped coverage"
decision_refs:
  - "2026-10-03 maintainer: approve full next scope after T203; file DNS capture Minor with release/consumer blockers, without making it a T155 blocker or executing it ahead of the agreed sequence"
  - "2026-10-10 maintainer: authorize T206 as a prerequisite while finishing the step-14 batch; keep Astra+Luna review with GLM paused, run only affected-part tests, and do not use a VM"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T206: Reject degraded DNS capture evidence

## Context

The independent T155 transport falsification found a surviving Minor in the completed T183
DNS observation gate. `tests/integration/dns_leak_test.go` logs a non-timeout packet-read
error and continues; neither that recovered error nor kernel packet drops are inputs to
`t034Verdict`. Before/after capture controls can both succeed while a middle interval is
unreliable. This is an evidence-integrity defect, not an observed production DNS leak or
a claim that historical captures dropped packets. The retained report is
`/home/claudia/stargate/.scratch/tmp/T155/redteam-a4r/falsify-1-transport.md`.

## Analysis

- Must hold: zero observed routed DNS is accepted only with an intact capture on every
  required interface, effective before/after controls, and successful routed traffic.
- Gated: the existing harness checks capture startup, both controls, forwarding and the
  injected-DNS falsifier. The hermetic gate honestly skips privileged capture without capability.
- Residue: recovered read failures and final packet-socket drop/statistics failures do not
  currently affect the verdict. Tests must exercise the actual verdict with all other guards
  satisfied; a diagnostic-only assertion cannot close this defect.

## Acceptance

1. Before changing the capture implementation, add deterministic regressions injecting a
   recovered non-timeout read error and a nonzero packet-socket drop count between successful
   before/after controls while routed traffic is present. The actual zero-leak verdict must
   fail. Preserve a behavioral RED on the starting implementation and identical-command GREEN
   using `scripts/test-first-evidence.py`; retain every predecessor record.
2. Carry capture-integrity state and final packet-socket statistics into the result and
   verdict before handles close. Unknown/unreadable statistics and degraded capture cannot
   earn a clean zero-leak PASS. Keep expected polling timeouts and intentional cancellation
   distinct from integrity failures. Preserve bounded shutdown and resource handling.
3. Preserve the observed-DNS injection falsifier, forwarding/partition controls, intact
   capture PASS, and explicit capability SKIP. A captured leak remains positive evidence;
   failure of another guard cannot transform it into a clean result. No production DP DNS,
   routing or confinement behavior is changed to accommodate this harness repair.
4. Run the permitted real capture tier in a recorded disposable environment and retain actual
   final statistics, positive controls and candidate/tool identities. Refresh the affected
   DNS evidence; a required privileged run that did not execute remains NOT RUN/SKIP.
   Existing scope is this namespace's loopback and default-route NIC over UDP/53; do not
   generalize it into all-browser, physical-NIC or encrypted-DNS assurance.
5. Reconcile capture/result/verdict comments and affected cadence/evidence documentation in
   this same repair. Driver verification and the ordinary independent review gate must pass.
   The final evidence identifies executed/skipped checks and remaining limitations.

## Grounded files budget

Eight paths allow the ticket, generated STATUS, tests-first JSON, sanitized capture-evidence
JSON, `tests/integration/dns_leak_test.go`, a focused same-package integrity regression file,
and directly affected cadence/evidence documentation or a required capture fixture. Every
actual path must implement an acceptance item or repair an orphan made by this change.
Budget pre-grants remain governed by the existing rule; no unrelated subsystem is included.

## Out-of-scope

Production DNS/routing changes; browser DNS; the T202 host-direct proposal; changing global
host policy; observer/CP authority repairs; T155's TLS/GetStatus probes; policy waivers;
unrelated test cleanup. Existing `dns_leak_test.go` may be changed only to make capture health
part of its verdict and preserve its controls. Any affected regression fixture may be
updated to test the stronger integrity requirement, never to suppress a genuine failure.

## Filing and sequencing

T078 and T081 depend on T206. T079 already depends on T081. T034a's manual measurement and
T034f's separate harness are not assumed to consume this gate, so no automatic new edges
are added. Under the approved T155 acceptance rule, this Minor alone does not block T155;
T155 must disclose the unmeasured capture-integrity limitation until T206 supplies evidence.
This approval files the owner; execution remains outside the current T204, T205, T155,
T202, T200, T201 sequence unless the maintainer separately changes the order.
