---
id: T075b
title: 'Author `tests/reproducibility/extension_test.sh`'
status: in-progress
created: 2026-07-04
last_updated: 2026-09-02
source: review/sol-review.md#M7
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: true
files_budget: 4
privacy_critical: false
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §12.3
  - .specify/memory/constitution.md §VI
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

The falsification case is source trees with identical bytes but deliberately
different mtimes. Comparing two copies that preserve the same mtimes would
reconfirm the current script instead of testing reproducibility.

## Acceptance

1. Copy the extension sources into two clean trees and assign distinct mtimes
   to every input file before packaging.
2. Assert the two zip files are byte-identical and every member has the one
   canonical timestamp, deterministic permissions, sorted order, and no
   host-specific extra fields.
3. Demonstrate the test fails against the current Info-ZIP behavior before
   T097 changes `extension/package.sh`.
4. Wire the test into the release-cadence reproducibility inventory and pass
   `scripts/verify.sh` without weakening the comparison.

## Out-of-scope

The package implementation is T097. Runtime extension behavior is not changed.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
