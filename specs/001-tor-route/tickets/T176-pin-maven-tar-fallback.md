---
id: "T176"
title: "Pin or refuse the Maven tar fallback"
status: pending
created: 2026-09-25
last_updated: 2026-09-25
source: "T145 implementation observation: cold-cache wrapper without unzip"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T145"]
parallel: false
files_budget: 6
privacy_critical: false
complexity: "low"
risk: "medium"
round_cap: 2
spec_refs: [".specify/memory/constitution.md Principles IV/VI"]
decision_refs: []
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T176: Pin or refuse the Maven tar fallback

## Context

The checked-in Maven properties pin the ZIP distribution SHA-256. On a cold
cache when `unzip` is absent, `control-plane/mvnw` changes the download URL to
`.tar.gz` but retains that ZIP checksum. The tarball therefore cannot pass the
archive check even when its bytes are valid. T145 correctly keeps verification
fail-closed; this separate availability defect needs an explicit contract.

## Acceptance

1. Reproduce the cold-cache branch without `unzip` using the checked-in wrapper and properties, with a controlled local archive and no production artifact request.
2. Choose and document an explicit contract: require `unzip` before download, or pin the tarball by its own independently grounded SHA-256 and select the digest for the archive actually fetched. No fallback may skip verification.
3. Add a regression that exercises the selected cold-cache behavior and rejects changed archive bytes before execution. Preserve the ZIP path's T145 positive and negative controls.
4. Run the focused fixture and `scripts/verify.sh`; record which checksum identity applies to each supported archive format under Constitution IV/VI.

## Out-of-scope

Maven version upgrades, JVM artifact reproducibility, and runtime proxy paths.

## Notes

Filed from a T145 implementation observation. This ticket does not reopen the
reviewed T145 commit or weaken its checksum presence gate.
