---
id: T017
title: 'Author `SECURITY-DECISIONS.md` (new file at repo root) with the Tor si'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T017
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T017: Author `SECURITY-DECISIONS.md` (new file at repo root) with the Tor si

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `SECURITY-DECISIONS.md` (new file at repo root) with the Tor sidecar trust rationale (FR-015): why `deb.torproject.org` over a fork; the apt-key fingerprint and rotation policy; the Debian-slim and final-image digest values; and a section reserved for adversarial-review findings from Phase N. (The docker-socket-proxy trust rationale is a separate concern from C1 remediation and lives in T017a, which appends to the same file.)

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
