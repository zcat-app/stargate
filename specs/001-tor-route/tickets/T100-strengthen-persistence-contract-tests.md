---
id: T100
title: 'Strengthen persistence contract tests'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#A1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T092, T093]
parallel: true
files_budget: 6
privacy_critical: true
constitution_refs:
  - "III: Privacy-preserving by construction"
  - "VII: Contract test-first"
complexity: medium
risk: medium
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §6
  - specs/001-tor-route/data-model.md §1
  - specs/001-tor-route/data-model.md §4
decision_refs: []
remediates: T012
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T100: Strengthen persistence contract tests

## Context

The current migration test proves only that table names exist. It misses
column/nullability/uniqueness drift and cannot exercise the manual-token insert
shape that exposed the `enrolled_devices` contradiction.

## Analysis

- **Must hold** — the migrated schema matches the amended data model, manual
  configured-token records are insertable without fake enrollment fields,
  and the audit log is append-only by mechanism.
- **Gated** — schema introspection plus real repository integration tests run
  against a fresh SQLite database in the Maven gate.
- **Residue** — migration compatibility with pre-release development DBs is
  documented but no production upgrade promise exists before v1.

## Acceptance

1. Introspect every v1 table's columns, types, nullability, defaults, checks,
   indexes, and uniqueness constraints against the amended data model.
2. Exercise the exact repository insert/update/delete shapes consumed by
   configured tokens, audit logging, counters, and sidecar state.
3. Enforce append-only `audit_log` semantics with SQLite triggers rejecting
   UPDATE and DELETE, and test both rejection paths.
4. Run from an empty database and through the full Flyway chain; Maven verify
   and `scripts/verify.sh` pass.

## Out-of-scope

Dashboard enrollment and production database migration support before v1.
