---
id: T112
title: 'Wire the stale-prose regression guard as a contract test'
status: pending
created: 2026-09-02
last_updated: "2026-09-12"
source: T083 review round 1 RECOMMENDED-FOLLOW-UP #1
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T083", "T155", "T156"]
parallel: true
files_budget: 4   # complete change: substantive paths, ticket and STATUS
privacy_critical: false
complexity: low
risk: low
round_cap: 2
spec_refs: []
decision_refs: []
constitution_refs:
  - "VI: Open and auditable"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T112: Wire the stale-prose regression guard as a contract test

## Context

T083 (doc-hygiene sweep) removed known-stale prose from living docs at
review time; its r1 review recommended making the guard **mechanical**
instead of PR-time prose: grep living docs for the exact stale phrases
the sweep removed, as a wired check. Verified 2026-09-02: the phrases
("once that file is authored", "outstanding follow-up", "owed for
both") have ZERO hits under specs/ and docs/ excluding tickets/ and
.handoffs/ — the guard wires green immediately and its only job is to
prevent reintroduction of the specific defect classes T083 cleaned.
tickets/ and .handoffs/ are excluded on purpose: they are historical
records where dated prose is allowed to say what was once true (2
ticket files legitimately contain the phrases today). Constitution
Principle VI's auditability and the falsify-before-publishing doctrine
are why the guard is wired rather than remembered. Falsified attempt to
kill this candidate: "a 3-phrase grep is too blunt to matter" — the
guard's claim is not generalized prose quality; it is a
zero-false-positive, self-documenting lock on known-cleaned phrases,
the same regression-guard shape the repo uses everywhere else.

## Acceptance

1. A new `tests/contract/doc_hygiene_test.sh` (auto-discovered by
   verify.sh Gate 4) greps specs/ and docs/ (excluding tickets/ and
   .handoffs/) for the curated stale-phrase list and FAILs naming
   file:line on any hit.
2. The phrase list lives in the test with a per-entry provenance
   comment (which ticket/sweep removed it and why) and a documented way
   to add entries — the list is the contract, so future doc sweeps
   extend it instead of re-litigating.
3. Tests-first: the guard is demonstrated red by temporarily
   reintroducing one listed phrase into a living doc, then green after
   removal.
4. verify.sh Gate 4 discovers and passes it on the clean tree; no
   changes to scripts/verify.sh itself are needed (discovery is
   automatic).

## Out-of-scope

Generalized prose-quality or NLP-ish checks; re-editing T083's landed
content; adding phrases beyond the three verified ones (later sweeps
extend the list via acceptance #2's mechanism).
