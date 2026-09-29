---
id: T184
title: 'Pin the Tor sidecar package closure against index rollback'
status: pending
created: 2026-09-29
last_updated: 2026-09-29
source: "reviews/redteam-20260929-694dbd8.md (area 3 M1, survived falsification, narrowed scope)"
phase: "Foundation audit remediation"
story: ''
blocked_by: []
parallel: true
files_budget: 5
privacy_critical: true
tests_first: []
test_for: []
constitution_refs:
  - "IV: Pinned, Tested, Manually Promoted Updates"   # locked identities; refuse rolled-back metadata
  - "VI: Open and Auditable"
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - .specify/memory/constitution.md
decision_refs:
  - "SECURITY-DECISIONS.md T099 entry: claims the snapshot closure is frozen; falsification shows it is not against an on-path attacker"
remediates: "T160"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: ["20260929-002-tor-closure-index-rollback"]
clarity_check: {}
---

# T184: Pin the Tor sidecar package closure against index rollback

## Context

`sidecars/tor/Dockerfile` fetches `snapshot.debian.org` over plain HTTP and
pins only top-level packages. Falsification (2026-09-29) fetched the snapshot
InRelease files for 20260714, 20251201 and 20240101: none carries Valid-Until,
and apt's `Max-ValidTime` defaults to 0. A fresh build therefore accepts an
older, genuinely signed bookworm index. The `ca-certificates=20230311+deb12u1`
pin sets the replay floor at Debian 12.12, so in practice libssl3 can be rolled
back from 3.0.20 to 3.0.17. The reproducibility test compares build A with
build B, so a consistent attacker passes it. The T099 decision's "frozen"
wording is false against this adversary; Constitution IV requires refusing
rolled-back metadata.

## Analysis

- Must hold: every installed package in the Tor image (name, version, arch and
  content hash) matches a committed manifest, and a mismatch fails the build.
- Gated: a build fed an older signed index fails before producing an image.
- Residue: the Tor `.deb` hash pin (T160) stays; base image digest pins stay.

## Acceptance

1. Commit a golden per-arch package manifest for the Tor image and assert it
   during the build (or pin the snapshot InRelease hash before `apt-get update`,
   or both). Any difference fails the build.
2. `tests/reproducibility/tor_sidecar_manifest_test.sh` compares each build
   with the committed manifest, not only with another build.
3. Red before green: a hermetic or docker-cadence test serving an older signed
   index (or a tampered manifest) fails the build; record red then green.
4. Correct the Dockerfile comments and add a `SECURITY-DECISIONS.md` entry
   superseding the T099 "frozen" claim.

## Out-of-scope

Tor version promotion (T177 procedure); switching distributions.
