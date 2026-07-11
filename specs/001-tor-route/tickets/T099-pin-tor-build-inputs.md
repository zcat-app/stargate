---
id: T099
title: 'Pin immutable Tor build inputs'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#M7
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T089, T087]
parallel: false
files_budget: 8
privacy_critical: true
constitution_refs:
  - "IV: Pinned, tested, manually promoted updates"
  - "VI: Open and auditable"
  - "VII: Sidecar contract test-first"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md §FR-015
  - specs/000-architecture/spec.md §7
  - specs/000-architecture/spec.md §12.4
decision_refs:
  - SECURITY-DECISIONS.md §"2026-07-04 — Tor sidecar trust rationale (FR-015)"
remediates: T014
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T099: Pin immutable Tor build inputs

## Context

The Tor Dockerfile verifies a signing key but installs unversioned packages
from mutable apt repositories. Rebuilding the same commit can therefore select
different Tor or Debian bytes.

## Analysis

- **Must hold** — base image, repository snapshot, package versions, and
  package hashes are immutable and auditable; upgrades remain manual.
- **Gated** — a clean rebuild verifies retained package hashes and the live
  Tor sidecar contract against the selected inputs.
- **Residue** — snapshot/operator trust remains part of the Tor TCB and must be
  recorded in the threat model and decision log.

## Acceptance

1. Resolve Debian and Tor packages from immutable snapshot locations with
   explicit versions and retained cryptographic hashes; no unversioned
   `apt-get install` remains.
2. Preserve fingerprint verification and fail closed on missing, expired, or
   hash-mismatched repository metadata.
3. Add a reproducibility/grounding test that rebuilds from a cold cache and
   confirms the resolved package set and final image digest are stable.
4. Update FR-015, architecture, threat model, build documentation, and
   `SECURITY-DECISIONS.md` with the exact trust and rotation procedure.
5. Refine T081 to use a two-phase candidate flow: build/record/review digests,
   then tag the exact commit containing its release metadata. No post-tag
   source commit or decision-log mutation is permitted.
6. Tor contract tests and `scripts/verify.sh` pass.

## Out-of-scope

Background package updates or mutable-tag promotion.
