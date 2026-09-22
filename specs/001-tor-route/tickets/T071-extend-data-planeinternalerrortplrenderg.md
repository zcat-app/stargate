---
id: T071
title: "Extend future HTTP error renderer only"
status: pending
created: 2026-07-04
last_updated: "2026-09-21"
source: tasks.md#T071
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T065", "T066", "T067", "T156"]
parallel: false
files_budget: 12
privacy_critical: true
complexity: medium
risk: medium
round_cap: 2
spec_refs: ["specs/001-tor-route/contracts/error-template.md", "docs/process/workflow.md §Evidence and atomic tests-first work (T156)"]
decision_refs: []
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T071: Extend future HTTP error renderer only

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Extend `data-plane/internal/errortpl/render.go` (from T048) to cover `ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT` per the status/reason table in `contracts/error-template.md` §"Status line"; verify the `LOCAL_REFERENCE_ID` generation is shared across all codes. Verified by T065–T069.

## Analysis

- Must hold: all four future formats contain only their fixed status/header/body fields and
  fresh random reference IDs, with no ingress wiring or request-derived values.
- Gated: direct production-renderer tests, full-response leak scans and verify.sh.
- Residue: finite reference-ID sampling cannot prove unlinkability; inspect use of crypto/rand
  and absence of request inputs in independent review. No Tor ingress property is claimed.

## Acceptance

1. Before production edits, add direct production-renderer tests for ROUTE_DOWN (502),
   ROUTE_REFUSED (502) and ROUTE_TIMEOUT (504), with AUTH_REQUIRED (407) as the positive control.
   Preserve failing commands/results and source snapshots proving missing route rendering;
   build/tool/fixture failures are not red evidence. No skips or self-lifting marker gates.
2. Implement the three codes, then pass the same tests. For every code assert exact status,
   four headers in order with no extras, Content-Length, literal body with only the permitted
   substitutions, full response leak corpus and no request-derived values.
3. Absorb T068's byte-exact body assertions and T069's reference-ID checks: 1000 sequential
   renders per code produce distinct 16-lowercase-hex IDs, a documented distribution check,
   and repeated identical inputs produce distinct IDs. Preserve AUTH_REQUIRED's existing
   shape/variable-slot tests. Sampling is evidence, not proof of cryptographic independence.
4. Replace T173's unsupported-code zero-output/error assertions only as the corresponding
   positive tests turn green; map every changed assertion. Do not wire HTTP responses into
   port 8881 or change SOCKS failure semantics. T068/T069 remain superseded records, not done.
5. Run the direct renderer suite, full-response leak checks, verify.sh and the independent
   review gate on the exact candidate. Tests and implementation land in this one ticket.

## Out-of-scope

Tor ingress, SOCKS routing, authentication and live-network behavior. No new HTTP endpoint.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Limit `render.go` extension to direct future-format renderer calls for all four codes; preserve status/reason, four-header order, body, reference-ID and leak-corpus tests. Do not wire HTML responses to Tor port 8881 or claim they are an implementation of FR-009.

## T173 authorized refinement — atomic owner

T068/T069's previously separate tests are included in Acceptance and authored red before
this implementation. `tests_first: []` avoids a red-only dependency, not Principle VII.
T065/T066/T067 retain their independent SOCKS obligations; they are not substitutes for
renderer tests. T071 remains behind T155 and therefore cannot block T173's ingress repair.
