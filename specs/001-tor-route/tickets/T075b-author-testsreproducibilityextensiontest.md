---
id: T075b
title: 'Author `tests/reproducibility/extension_test.sh`'
status: pending
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T075b
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: false
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

# T075b: Author `tests/reproducibility/extension_test.sh`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `tests/reproducibility/extension_test.sh` — invoke `extension/package.sh` (T005) twice in clean working directories and `cmp` the resulting `dist/stargate-extension.zip` outputs; CI runs this on every PR touching `extension/`. Verifies the deterministic-zip-packaging claim from plan.md Constitution Check row VI / arch §12.3 (`SOURCE_DATE_EPOCH=0`, sorted entries) — paired with T075 so the byte-reproducibility guarantee is tested for every artefact this feature ships, not just the Go binary.

## Analysis

*(Omit — not privacy-critical and not high-complexity.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
