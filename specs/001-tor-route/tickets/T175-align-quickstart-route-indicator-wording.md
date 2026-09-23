---
id: "T175"
title: "Align live quickstart wording with scoped route indicators"
status: done
created: "2026-09-23"
last_updated: 2026-09-23
source: "T150 round-2 GLM Minor; candidate b7b1b4407a7a11fd4c165ad6c6ebe9107a71659578648a9b3f10f973b4d0207f"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T150"]
parallel: false
files_budget: 6
privacy_critical: true
complexity: "low"
risk: "low"
round_cap: 2
spec_refs: ["specs/001-tor-route/spec.md §Per-tab indicator scope", "THREAT-MODEL.md §4.2", ".specify/memory/constitution.md Principles III/V/VIII"]
decision_refs: []
remediates: "T150"
tests_first: []
reviews: { round: 1, date: 2026-09-23, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T175: Align live quickstart wording with scoped route indicators

## Context

T150's independent reviewers approved the scoped main-navigation indicator while identifying
an outside-diff documentation inconsistency: the current quickstart Step 6 still promises
`Route: Tor` for the tab. Update current operator wording to match the implemented scope and
connection-success limitation. Historical ticket text remains historical.

## Analysis

- Must hold (III/V): current operator guidance cannot infer whole-tab protection or successful
  tunnel establishment from the main-navigation route decision.
- Gated: existing router/popup tests pin implemented labels; ticket lint and verify check the
  repository. Existing tests do not automatically validate all operator prose.
- Residue: independently review the quickstart and any other current label quotations for
  consistency with spec.md and THREAT-MODEL.md. This is a document-only correction; use
  consistency checks and independent review, not fabricated runtime red/green evidence.

## Acceptance

1. Update quickstart Step 6 to name the main-navigation decision scope, explain that other
   requests may use different routes, and distinguish the label from successful connection/load.
2. Check current operator/release documentation for the retired unqualified label quotations;
   reconcile those within scope or identify a concrete follow-up. Preserve historical task,
   ticket and review evidence.
3. Confirm wording against spec.md §Per-tab indicator scope, THREAT-MODEL.md §4.2 and the
   popup's canonical strings. Record the consistency-check result; run ticket lint,
   scripts/verify.sh and both required independent reviews.

## Out-of-scope

Changing route selection, popup behavior, permissions, browser hardening, or unrelated stale
quickstart instructions. No existing runtime-test expectation changes are authorized.

## Notes

Filed after T150's focused commit from the reviewers' recorded Minor follow-up. The initial
ticket record made no claim that the documentation inconsistency had already been repaired.

Consistency check (2026-09-23): current operator/release Markdown outside historical task,
ticket and review evidence was searched for the retired `Route: Tor` / `Route: Direct
(unrouted)` quotations and the replacement `Main navigation decision:` prefixes. Quickstart
Step 6 was the only current unqualified quotation. Its replacement matches spec.md §Per-tab
indicator scope, THREAT-MODEL.md §4.2, and the canonical strings in `popup.js` and
`popup.test.js`; no additional follow-up is required. Historical evidence remains unchanged.
