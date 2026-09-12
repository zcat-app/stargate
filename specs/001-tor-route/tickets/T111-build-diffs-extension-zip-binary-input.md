---
id: T111
title: 'BUILD-DIFFS: document extension zip binary as build input'
status: pending
created: 2026-09-02
last_updated: "2026-09-12"
source: T097 review round 1 (APPROVE) RECOMMENDED-FOLLOW-UP
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T155", "T156"]
parallel: true
files_budget: 3   # complete change: substantive paths, ticket and STATUS
privacy_critical: false
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/000-architecture/spec.md §12.3
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

# T111: BUILD-DIFFS: document extension zip binary as build input

## Context

`extension/package.sh` neutralizes every host leak it can control —
staged `touch -d @0`, `chmod 0644`, `LC_ALL=C sort`, `zip -X`, `zip -9`,
`SOURCE_DATE_EPOCH` exported — but the **zip binary itself is an
unpinned build input**. `tests/reproducibility/extension_test.sh`
compares two builds produced by the SAME zip binary on the same host,
so cross-zip-version variance (Info-ZIP deflate implementation drift,
UTF-8/EFS flag handling for non-ASCII names, version-specific header
quirks) is invisible to the gate. Constitution Principle VI declares
the extension tier "fully reproducible via deterministic zip
packaging" — a cross-host claim — and BUILD-DIFFS.md, the canonical
record of expected variance, has no extension section (only JVM and
Tor today). T097-r1 flagged exactly this gap: "worth one line in
BUILD-DIFFS.md when release artefacts are wired". T081 (release.yml)
is the natural release-docs wiring point but is not a blocker: the
auditor-facing caveat is true today. Falsified attempts to kill this
candidate: package.sh does not pin or record the zip version; no
existing doc covers it; the repro gate cannot catch cross-version
drift by construction.

## Acceptance

1. BUILD-DIFFS.md gains an extension section stating:
   - the gated property — two same-host builds are byte-identical
     (asserted by the extension reproducibility test under
     `STARGATE_VERIFY_REPRO=1`);
   - the expected variance — a different Info-ZIP build/version may
     produce different bytes for identical input; the zip binary is a
     build input the repo does not pin;
   - what an auditor should do — compare release artefacts built with
     the recorded/pinned zip version once T081 records one; treat
     cross-version diffs in the documented vectors as expected, all
     other diffs as defects.
2. The section names the residual vectors honestly (deflate drift,
   EFS/Unicode flag handling) and does NOT claim cross-version
   byte-stability the repo does not assert.
3. scripts/verify.sh stays green (docs-only diff; Gate 5 unaffected).

## Out-of-scope

Pinning the zip binary in package.sh or CI — a real but separate
supply-chain decision (Principle IV promotion flow); file its own
ticket if T081's release build needs it. Any change to package.sh or
the reproducibility test.
