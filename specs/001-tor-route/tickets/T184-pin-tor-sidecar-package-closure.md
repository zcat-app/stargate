---
id: T184
title: 'Pin the Tor sidecar package closure against index rollback'
status: in-review
created: 2026-09-29
last_updated: 2026-09-30
source: "reviews/redteam-20260929-694dbd8.md (area 3 M1, survived falsification, narrowed scope)"
phase: "Foundation audit remediation"
story: ''
blocked_by: ["T192"]
parallel: true
files_budget: 11   # acceptance files (Dockerfile, verify-closure.sh, package-closure.lock, repro test, SECURITY-DECISIONS.md) + orphans T184 falsifies (THREAT-MODEL.md, BUILD-DIFFS.md, tor_build_inputs_test.sh) + ticket + STATUS.md + evidence; raised at START, user-authorized, no deferral
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
- Design (START 2026-09-30): pin the snapshot InRelease SHA-256 and check it after
  every `apt-get update` in both stages, before installing from it; after the last
  install, compare every installed package (name, version, arch, authenticated
  archive SHA-256 or `base`) with the committed per-arch lock. The amd64 rows come
  from a real build; no arm64 builder exists here, so arm64 rows are resolved by
  bookworm APT from the same pinned indexes and labelled as not build-confirmed
  (a wrong row fails the arm64 build closed).
- Orphans this falsifies, fixed here: Dockerfile T099 comments, THREAT-MODEL.md
  T099 "frozen"/"cannot drift" attributions, BUILD-DIFFS.md "holds because",
  tor_build_inputs_test.sh header; the T099 SECURITY-DECISIONS entry gets a
  superseding entry and a `Superseded by:` back-link.
- Red falsifier: a docker-cadence control serves the genuine 12.15 index to stage
  1 and the older signed 12.12 index (20251201) to stage 2 through a loopback
  proxy; pre-fix the build succeeds with libssl3 3.0.17, post-fix it must fail at
  the InRelease pin. A tampered-lock control must fail at the closure check.

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
