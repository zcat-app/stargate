---
id: "T176"
title: "Pin or refuse the Maven tar fallback"
status: done
created: 2026-09-25
last_updated: 2026-09-28
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
reviews: { round: 1, date: 2026-09-28, verdict: APPROVE }
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

## Integrity scope (Constitution IV/VI)

Reproduction (pre-fix): the checked-in `control-plane/mvnw` and properties,
run with a cold `MAVEN_USER_HOME`, no `unzip` on PATH and a fake `wget`
serving local bytes, requested
`.../apache-maven-3.9.14-bin.tar.gz` and failed "Failed to validate Maven
distribution SHA-256": the tarball was checked against the ZIP pin, so no
valid tarball could ever install.

Contract: **`unzip` is required before download.** A cold install without
`unzip` now dies before fetching any
archive or creating the Maven install directory; the temporary download
directory it creates first is trap-cleaned on exit. The `.tar.gz` fallback
and its `tar` extraction branch are removed.
Pinning the tarball was rejected because it adds a second content identity
that would need its own independently grounded digest from a production
download, while the ZIP pin from T098 is already grounded. An existing
verified `MAVEN_HOME` still runs without `unzip`, since it needs no extraction.

Checksum identity per archive format:

| Format | Unix `mvnw` | Windows `mvnw.cmd` | Identity |
|---|---|---|---|
| `apache-maven-3.9.14-bin.zip` | only format fetched | only format fetched (`Expand-Archive`) | `distributionSha256Sum` (T098, verified before extraction) |
| `apache-maven-3.9.14-bin.tar.gz` | never fetched; refused without `unzip` | never fetched | none: not a supported input |

Regression: `tests/contract/workflow/maven_wrapper_integrity_test.sh` now
builds its PATH from the host minus `unzip`, and supplies a local `unzip`
for the ZIP cases so they no longer depend on host tooling (previously a
host without `unzip` silently exercised a fixture-pinned tarball instead).
Without `unzip`, matching bytes, changed bytes and the checked-in properties
verbatim all exit non-zero with no download and no execution. A cached
install still executes. T145's ZIP positive, cached, absent/empty-checksum
and changed-bytes controls are unchanged, and the ZIP download URL is now
asserted.
