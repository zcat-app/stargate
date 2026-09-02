---
id: T097
title: 'Fix extension archive reproducibility'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#M7
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T075b]
parallel: true
files_budget: 4
privacy_critical: false
constitution_refs:
  - "VI: Open and auditable"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §12.3
  - specs/001-tor-route/plan.md §"Constitution Check"
decision_refs: []
remediates: T005
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T097: Fix extension archive reproducibility

## Context

Info-ZIP 3.0 ignores `SOURCE_DATE_EPOCH` for stored member timestamps, so the
current package script does not satisfy Principle VI.

## Acceptance

1. T075b first proves two builds from source trees with deliberately different
   mtimes produce byte-identical archives and normalized member timestamps.
2. `extension/package.sh` stages files with a deterministic timestamp before
   archiving (or uses an equivalently pinned deterministic archive tool).
3. Entry order, permissions, extra fields, and timestamps are deterministic;
   the output contains only the intended extension files.
4. The targeted reproducibility test and release-cadence verify gate pass.

## Out-of-scope

Extension runtime behavior and browser-hardening design (T091).

## Notes

From the T075b round-1 review (2026-09-02; verdict archived at
`target/runs/T075b-r1.verdict`, gitignored — recorded here so it survives):

- The byte-identity gate fails on MODES alone (upstream Info-ZIP 3.0 stores
  source modes verbatim; the test perturbs one tree to 0664) even with a
  SOURCE_DATE-EPOCH-honoring zip — the package.sh rewrite must normalize
  member modes to 0644 in addition to pinning member timestamps to the
  epoch-0 encoding. Staging at `touch -d @0` + `zip -X` yields exactly the
  canonical form the test asserts (verified against upstream zip 3.0).
- Absorb the T075b test's "Known-fail until T097" boilerplate in its
  `fail()` once this gap closes — post-T097 it would misattribute a real
  reproducibility regression to the closed gap.
