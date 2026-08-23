---
id: T107
title: 'Digest-pin alpine:3.20 in stargate-cli contract tests'
status: pending
created: 2026-08-23
last_updated: 2026-08-23
source: T084 review round 1 (post-refine) Major-1  # carve-out tracking artifact
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: []
parallel: true
files_budget: 2   # init_docker_test.sh + fixtures/fixture-compose.yml
privacy_critical: true   # executable code pulling by mutable tag = supply-chain surface (Principle IV); test-only but real pull at docker-gated runtime
complexity: low
risk: low
round_cap: 2
spec_refs: []
decision_refs:
  - SECURITY-DECISIONS.md (digest-pinning rotation policy)
constitution_refs:
  - "IV: Every external component digest-pinned"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T107: Digest-pin alpine:3.20 in stargate-cli contract tests

## Context

Carved out of T084 (doc-hygiene sweep) at its 2026-08-23 review:
T084's filing-time premise — "no committed executable code pulls
images by mutable tag" — went stale when the stargate-cli contract
tests landed. Two committed executable sites now pull `alpine:3.20`
by mutable tag:

- `tests/contract/stargate-cli/init_docker_test.sh:40`
  (`STAT_IMAGE="alpine:3.20"`; used in five `docker run` / `docker
  create` invocations).
- `tests/contract/stargate-cli/fixtures/fixture-compose.yml` (3
  services, `image: alpine:3.20`; brought up by the docker-gated
  test — self-SKIPs only when no daemon is reachable).

This is test-only surface, but it is a live Principle IV deviation in
executable code: on any host with a Docker daemon, the tag resolves at
pull time with no integrity anchor.

## Analysis

Privacy property map (ticket is privacy_critical: true):

- **Asset**: host Docker daemon + the test's own integrity guarantees.
  A malicious or compromised `alpine:3.20` tag payload runs with
  Docker-level access on the test host (mounted repo volume,
  `/var/run/docker.sock` reach in daemon tests).
- **Threat**: tag mutation / registry compromise between pin time and
  pull time (classic Principle IV supply-chain surface; THREAT-MODEL
  §5.x sidecar-image provenance reasoning applies mutatis mutandis).
- **Property wanted**: byte-anchored resolution — every `docker run` /
  compose service references `alpine:3.20@sha256:<digest>` with ONE
  canonical digest, single source of truth, rotation documented like
  the golang/debian pins (SECURITY-DECISIONS.md policy).

## Acceptance

1. Resolve the current `alpine:3.20` digest from the registry
   (`docker buildx imagetools inspect alpine:3.20`) and record it in
   SECURITY-DECISIONS.md per the rotation policy.
2. `init_docker_test.sh`: `STAT_IMAGE` becomes
   `alpine:3.20@sha256:<resolved-digest>`; all uses flow from that one
   const (no second literal).
3. `fixtures/fixture-compose.yml`: all three services reference the
   same digest-pinned ref. Consider a YAML anchor so the digest
   appears exactly once in the file.
4. Validation is docker-gated (the suite already self-SKIPs without a
   daemon): with a daemon reachable, `init_docker_test.sh` passes
   end-to-end against the pinned refs; document in the ticket how to
   run it (`docker` present → not SKIP).
5. Whole-tree grep for `alpine:[0-9][^@]` shows no NEW uncovered
   actionable hits beyond those already excluded by T084's taxonomy.

## Out-of-scope

- Rotating any existing pin (golang/debian/alpine:3 in
  port_exposure_test.go) — separate rotations follow
  SECURITY-DECISIONS.md cadence.
- Changing what the tests assert; this ticket changes ONLY image
  reference pinning.

## Notes

- Filed as the tracking artifact required by T084's §Out-of-scope
  carve-out ("Until that lands" exclusion). Until T107 lands, T084's
  acceptance-#2 grep gate excludes these two files explicitly.
- Standalone docs/ticket commit convention (T105/T106 precedent);
  NOT chargeable to T084's files_budget.
