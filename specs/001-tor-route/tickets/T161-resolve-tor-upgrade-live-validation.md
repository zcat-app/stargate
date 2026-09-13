---
id: "T161"
title: "Resolve Tor upgrade live validation failures before promotion"
status: done
created: "2026-09-12"
last_updated: 2026-09-13
source: "specs/001-tor-route/tickets/T160-upgrade-tor-security-release.md"
phase: "Urgent security update validation"
story: "-"
blocked_by: ["T160", "T139"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: "medium"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/contracts/torrc.md", "specs/001-tor-route/contracts/foundation-boundaries.md"]
decision_refs: []
remediates: "T160"
tests_first: []
reviews: { round: 1, date: 2026-09-13, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T161: Resolve Tor upgrade live validation failures before promotion

## Context

T160 prepares the official Tor 0.4.9.12 candidate and closes its build-time package
substitution gap. Two unchanged cold T058 circuit-isolation runs stopped at descriptor
loading after five minutes, then failed the first onion CONNECT (EOF / REP=6). They
produced no circuit-isolation evidence. A separate T032 cold/configuration run bootstrapped
in about 17 seconds and passed its checks. Later T062 control and T058a username-less
checks passed, including T058a's distinct-username/different-circuit calibration. These
results narrow the unresolved evidence to the failed T058 runs and their preconditions;
they do not establish a root cause or demonstrate a Tor isolation leak. Preserve the actual
T160 evidence and candidate identity, and reuse unaffected passing evidence honestly.

## Analysis

- Must hold: the selected Tor artifact satisfies required sidecar behavior before deployment
  or release promotion; known-unavailable evidence cannot become PASS by relabeling it.
- Gated: T160 authenticates and checks actual package bytes; native build/configuration and
  package-manifest reproducibility are separate from live stream/circuit behavior.
- Residue: public-network availability, fixture assumptions and possible version regressions
  are not distinguished by an isolated timeout. Neither a warning nor completed T160 closes this.

## Acceptance

1. Reproduce against the exact content-pinned candidate and record image/package identities,
   environment, clocks, cold/warm state, bootstrap phases and actual control/proxy outcomes.
   Distinguish network availability, existing harness assumptions, topology and version regression
   with controls; do not attribute a cause from one successful or failed run.
2. Establish the required live control/configuration and distinct-credential same-target isolation
   properties, including a positive control capable of detecting fused identities. Re-evaluate
   native username-less behavior against the supported-ingress contract; within-partition
   single-circuit sharing is not a constitutional guarantee. Native Tor probes do not prove the
   DP forwards the correct isolation partition (T126/T155 still own that integrated evidence).
3. Preserve the cold failures. A warm run must be labeled warm and cannot establish cold readiness.
   Do not increase deadlines, preseed mounts/keys, weaken assertions or amend the constitution merely
   to obtain green output. Any proven code/fixture defect needs a spec-derived failing regression
   and the normal independent review loop. File concrete children when needed and block this
   validation ticket, T155 and affected consumers on them without introducing cycles.
4. Complete only when required behavior has current, attributable evidence or a separately reviewed
   contract refinement establishes the applicable requirement. Unavailable evidence keeps this
   ticket pending/in-progress and promotion blocked. T124's readiness design and T134/T138/T147
   investigations remain independent obligations; do not silently fold them into a timeout fix.
5. Record exact-candidate evidence, run scripts/verify.sh and obtain independent codereview/redteam.
   Later changes invalidate affected results. T155/T078/T079 and actual update/release promotion
   remain blocked by this ticket and any required children.

## Out-of-scope

Treating a successful package build as live validation, automatic publication/deployment,
or inferring that an upstream security release fixes the remaining Stargate foundation defects.

## Evidence

The exact-candidate identities, environment, commands, raw-log hashes and cold results are retained
in [T161 live-validation evidence](../../../reviews/T161/README.md). T160's two cold failures remain
unchanged and unattributed. Two new cold T058 runs passed the same-target distinct-credential
property without changing the harness, and independent cold T032/T062/T058a controls established
configuration, control access, observable fusion and distinct-username discrimination. A separate
cold start lingered at descriptor loading before completing, so public-network variability remains
an explicit limitation rather than a claimed root cause. No code/fixture defect was proven and no
deadline, target, mount, key or assertion was changed.
