---
id: T088
title: 'Repair local init and Compose provisioning'
status: pending
created: 2026-07-11
last_updated: 2026-07-11
source: review/sol-review.md#B1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T087, T092, T094, T095, T099]
parallel: false
files_budget: 12
privacy_critical: true
constitution_refs:
  - "II: Plane separation"
  - "III: Privacy-preserving by construction"
  - "VII: Tests-first for privacy-critical and contract code"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/000-architecture/spec.md §9
  - specs/001-tor-route/spec.md §SC-001
  - specs/001-tor-route/data-model.md §6
decision_refs: []
remediates: T016
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T088: Repair local init and Compose provisioning

## Context

The shipped `init` path cannot create the local stack: it omits the env file,
uses logical volume names as physical names, guesses container names, and does
not initialize writable mounts for the non-root service UIDs. This remediates
T015/T016 and is a release blocker for SC-001.

## Analysis

- **Must hold** — one command builder owns project name, compose file, and env
  file; every volume written by UID 5101/5102 is initialized with explicit
  ownership and mode; health uses Compose service IDs, never guessed names.
- **Gated** — a Docker-backed fixture test exercises the exact `init` command,
  two isolated project names, volume ownership, idempotence, and health lookup.
- **Residue** — Docker daemon/platform differences remain release-cadence
  coverage and are recorded by T077.

## Acceptance

1. Write the Docker-backed regression test first. It uses tiny fixture images
   and proves env loading, project isolation, physical-volume resolution,
   ownership/mode for keys, IPC, CP state, DP state, and Tor config, plus
   idempotent reruns and `docker compose ps -q <service>` health discovery.
2. `scripts/subcommands/init` invokes one authoritative Compose command that
   always supplies the local env file and explicit project name.
3. Volume initialization resolves project-scoped physical names by Compose
   labels/rendered configuration; no literal `stargate-*` physical name is
   assumed.
4. The key volume remains fail-closed: existing keys are preserved, partial
   keysets fail, and permissions match the inter-plane contract.
5. Quickstart token, restart, teardown, and wipe commands use the same Compose
   identity and env-file convention.
6. The targeted regression test and `scripts/verify.sh` pass.

## Out-of-scope

Tor config startup ordering is T089/T087. Token-verifier key material is T092;
this ticket provisions any install-time secret shape that T092 has already
made authoritative without designing that shape itself.

## Notes

The regression test must fail against the pre-fix installer for the reasons in
review B1, then pass after the implementation in this ticket.

**T092 amendment (2026-07-15) — pepper provisioning is authoritative.**
T092 makes the install-time pepper shape authoritative
(`specs/001-tor-route/data-model.md` §1.7). This ticket provisions it,
per its existing out-of-scope note ("this ticket provisions any
install-time secret shape that T092 has already made authoritative"):
`init` step 3 generates `/etc/stargate/pepper.key` via
`openssl rand -bytes 32` (arch §9.1 step 3, amended), mode `0640`, owned
by the reading plane UID, group `stargate-ipc` (GID 5100) — the same
ownership/mode scheme as the ed25519 inter-plane keypairs in the
`stargate-keys` volume. `export` must include it (warn the bundle carries
a secret), `import` restores it verbatim, `wipe` removes it alongside
keys and state, and rotation (re-pepper → re-HMAC every configured token
→ bump generation) is operator-initiated. The regression test should
cover pepper ownership/mode alongside the existing key-volume checks
(acceptance #4).
