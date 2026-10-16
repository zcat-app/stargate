---
id: T080
title: "Sweep final source licenses and documentation pointers"
status: pending
created: 2026-07-04
last_updated: 2026-10-16
source: tasks.md#T080
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by:
  - "T009"
  - "T155"
  - "T081"
  - "T077"
  - "T156"
  - "T220"
  - "T202"
  - "T212"
  - "T215"
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - ".specify/memory/constitution.md §VI"
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T080: Sweep with `scripts/check-license-headers.sh` (from T006); verify Apac

## Binding October16 dependency reconciliation

Sweep after the native/measurement/human and broader cadence/runner source owners, including
all new shared-component/artifact files. T077 remains the human gate; T220 remains direct so the
source/native split cannot bypass it. This ticket is a license/doc sweep, not runtime approval.

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical task summary (current acceptance/dependencies above govern):**
>
> Sweep with `scripts/check-license-headers.sh` (from T006); verify Apache 2.0 headers on every new file; update CLAUDE.md "Current plan" pointer if downstream specs land before this feature merges.

## Analysis

The final source must have Apache-2.0 headers where required, accurate current-plan pointers,
and no credentials/raw private evidence in the deliverable. Existing license/header tools provide
the gate; they do not qualify routing/privacy. Correct only this sweep's concrete findings.

## Acceptance

1. Run the existing scripts/check-license-headers.sh on the final candidate and require success;
   inspect every new T225/T226/T223 source file and generated-versus-source classification.
2. Verify Apache-2.0 license/notice obligations and current documentation pointers, including the
   CLAUDE.md thin pointer. No duplicated policy, stale scope or unsupported implementation claim.
3. Record exact source snapshot, command/result and any surgical header/doc repairs. Renew the
   affected source checks/review if repairs change executable bytes; no false historical RED.
4. Keep native results, first-time-human timing and external release review with their owners;
   a clean license sweep cannot satisfy them. Stop before T078/T079 execution.

## Out-of-scope

Product behavior, privacy acceptance, dependency updates, native execution and release publication.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
