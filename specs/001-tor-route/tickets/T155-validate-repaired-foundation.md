---
id: "T155"
title: "Validate repaired foundation before feature work"
status: "pending"
created: "2026-09-12"
last_updated: "2026-09-12"
source: "reviews/redteam-20260912-677960b.md"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T134", "T135", "T136", "T137", "T138", "T139", "T140", "T141", "T142", "T143", "T144", "T145", "T146", "T147", "T148", "T149", "T150", "T151", "T152", "T153", "T156", "T120", "T114", "T121", "T123", "T124", "T126", "T132", "T157", "T158", "T159"]
parallel: false
files_budget: 8
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs: [".specify/memory/constitution.md", "specs/001-tor-route/spec.md"]
decision_refs: []
remediates: "T125"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T155: Validate the repaired foundation before feature work

## Context

The September foundation audit failed despite a green baseline. This checkpoint prevents
investigation-only completion from unblocking feature work while defects remain unfixed.

## Analysis

- Must hold: T156 constitutional deployment, isolation, authority and routing guarantees.
- Gated: per-ticket regressions and independent reviews, followed by current integrated evidence.
- Residue: synthetic and skipped tests do not establish clean-host or browser-network behavior.

## Acceptance

1. Reconcile every September audit finding and the July finding ownership table against
   current code and durable review evidence. All required implementation follow-ups must
   exist in this ticket's `blocked_by` and be done; recommendations alone cannot pass.
2. Run `scripts/verify.sh` on the exact candidate and preserve its gate summary. Exercise
   the documented clean-volume operator startup without harness-only provisioning fixes,
   then real CP/DP authenticated reload, idle reload, peer-pin rotation/resumption, DP restart,
   CP-down routing survival and same-target/distinct-first-party isolation.
3. Prove the selected topology and observer boundary using positive controls and negative
   probes from production namespaces: bind refusal, DNS/TCP/UDP egress and prohibited Tor
   commands. Test the selected CONNECT contract and operational journal policy.
4. Create/update `specs/001-tor-route/live-e2e/README.md` with prerequisites, commands, snapshot and evidence
   for foundation checks and remaining release-cadence checks, including D-live-N decisions,
   preserve/reset semantics and transport-relevant/invisible classification. Track a real-browser
   hardening/token-failure probe for unintended Direct fallback, with packet attribution.
   Required foundation checks that cannot run keep this ticket pending; do not convert SKIP
   into PASS. Milestone-wide T034a/T034f/T070a evidence remains required later.
5. Obtain a fresh independent cumulative foundation redteam pass under the canonical
   workflow. No unresolved Blocker/Major may pass without explicit maintainer disposition;
   constitutional conflicts require the governance path and cannot be accepted by this plan.
   Record the reviewed snapshot and invalidate affected evidence after further changes.
6. Leave T078/T079 pending for the completed milestone. File new findings as focused
   remediation tickets, add blockers here and to affected consumers, and reverify closure.

7. Verify T156 policy end-to-end: device/profile/site partitioning, no Direct fallback,
   complete-hour-only metric publication, operational-writer/retention cleanup, and acknowledged
   revocation surviving supported rollback/restart. No active inherited contract exception may
   substitute for these checks. Add required implementation children before closure.

## Out-of-scope

Feature expansion, constitution amendments, fabricated historical tests-first evidence,
release publication, and substituting this checkpoint for final milestone reviews.
