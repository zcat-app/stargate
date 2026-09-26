---
id: T123
title: 'Validate fresh-host CP mount provisioning'
status: done
created: 2026-09-07
last_updated: 2026-09-26
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: ["T139", "T134", "T138", "T156", "T162", "T164", "T165", "T167", "T172", "T173"]
parallel: true
files_budget: 4
privacy_critical: false
complexity: medium
risk: "medium"
round_cap: 2
spec_refs:
   - specs/001-tor-route/contracts/control-grpc.md §"Socket topology"   # pins /etc/stargate/keys as the contract mount path
   - specs/001-tor-route/spec.md#FR-017   # pins /etc/stargate/tokens.yaml inside the :ro config volume — the nesting is inherent to the two contract paths
   - specs/001-tor-route/tasks.md#T059   # discoverer (live run, 2026-09-07)
   - specs/001-tor-route/tickets/T167-repair-control-plane-overlapping-read-only-mounts.md
decision_refs:
   - .specify/memory/constitution.md#Principle-IV   # retain pinned, networkless provisioning
reviews: { round: 1, date: 2026-09-26, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T123: Validate fresh-host CP mount provisioning

## Context

Hand-filed from T059's live run (2026-09-07, docker 29.1.3). On a fresh
volume set, `stargate-control` cannot start:

```
error mounting "/var/lib/docker/volumes/<proj>_stargate-keys/_data" to
rootfs at "/etc/stargate/keys": create mountpoint for /etc/stargate/keys
mount: make mountpoint "/etc/stargate/keys": mkdirat …: read-only file system
```

The CP mounts `stargate-control-config:/etc/stargate:ro` (FR-017's fixed
tokens.yaml path) AND `stargate-keys:/etc/stargate/keys` (control-grpc.md
"Socket topology" contract path). runc creates mountpoints depth-late: by
the time the keys mountpoint is created, the ro parent is already applied,
and mkdir inside a read-only mount fails (EROFS). On a fresh volume the
`keys/` subdir does not exist inside the config volume → the CP never
boots → the full local profile never comes up on a clean host. Masked so
far because only the tor service had ever been brought up live (T019b/
T032/T058/T058a) and the structural compose contract greps YAML, not
runtime mounts.

**Live experiment (2026-09-07):** pre-creating `keys/` inside the config
volume content lets the container start and the keys volume mounts rw at
the contract path (marker-file verified). T059's harness does exactly that
as operator-equivalent provisioning (`t059SeedToken`) until this lands.

**Scope datum from the same live chain (2026-09-07, round-1 T059 review):**
the EROFS mount gap and the missing pepper/keys/volume-root provisioning
were BOTH masked until the first full-stack bring-up ever ran — whichever
option is chosen here, consider folding the init-equivalent provisioning
(key material + volume-root ownership) for test/CI projects into the same
resolution, so the full-stack suites (T059/T060/T061/T033) share one
helper instead of three per-suite copies.

## Authorized refinement (2026-09-26)

The maintainer authorized validation and closure after grounding found that T167 had already
implemented this mount repair. T167 preserved the read-only config parent, added installer
provisioning of its `keys/` child, captured the failing fresh-volume Docker result before the
fix, and passed the privacy-critical review gate. This ticket makes no implementation or
privacy-contract change. Its `privacy_critical: false` classifies this **validation-only diff**;
it does not reclassify T167's implementation or waive independent review here. Recreating a
new red result on the already repaired baseline would be false tests-first evidence.
Constitution Principle VII was satisfied by T167's implementation record; it does not
require inventing a second failing result for this documentation-only validation.

## Analysis

- **Must hold:** a fresh `stargate init` provisions the project config mountpoint without
  operator-only mkdir/chown/key seeding; CP starts with the effective read-only parent and
  writable keys child, without changing the fixed token/key paths or network boundary.
- **Gated:** T167's historical red/green Docker record; the current real-image CP mount
  regression; the real installer against a fresh disposable four-service fixture; the Local
  Compose structural gate and repository verify gate.
- **Residue:** the fixture does not exercise the actual Tor network or production images
  together. T163 owns production-namespace and physical-host topology evidence; T124 owns
  Tor's cold-bootstrap health semantics. Neither result is inferred from the mount tests.

## Acceptance

1. Confirm T167's recorded pre-fix Docker EROFS result, test-first source identity, reviewed
   fix, and T163's later full Local `scripts/stargate init` startup on a disposable nested
   host. Label that Local result historical; do not claim it binds today's source or a
   physical host.
2. Run `bash tests/contract/stargate-cli/init_docker_test.sh` against empty disposable project
   volumes. Its real `scripts/stargate init` invocation must start all four fixture services
   without harness-only mkdir/chown/key seeding, retain project-scoped key and pepper ownership,
   and require the observer's current readiness query rather than process presence alone.
3. Run `bash tests/contract/compose/control_mount_test.sh` with the real CP image and effective
   Local mounts. It must reach CP application startup with `/etc/stargate:ro` and the writable
   `/etc/stargate/keys` child. Run `bash tests/contract/compose/local_compose_test.sh` to pin
   the unchanged read-only and least-privilege topology. An unavailable Docker gate is
   incomplete validation, not a pass.
4. Run `bash scripts/verify.sh` GREEN on the reviewed tree. Record executed checks and skips
   without claiming Tor bootstrap, browser routing, packet egress, CP outage or SOCKS forwarding
   from these startup tests. Keep T163/T124/T155 as the owners of those wider outcomes.

## Out-of-scope

- Production mount or installer changes: T167 already delivered the repair with its own
  failing regression and review. A newly discovered defect needs a focused follow-up.
- T059's runtime assertion and harness, DP-side mounts, Tor cold-bootstrap behavior,
  CP outage/reconnect and SOCKS forwarding. Their existing owners retain those checks.

## Notes

Hand-filed by the T059 session (2026-09-07) per the surgical-changes doctrine.
T167 subsequently repaired the same production mount gap before T123 ran. T163's
post-T167 disposable deployment reached the full Local stack; its separate packet and
physical-host conclusions remain under T163.

T147 migration dependency: T172 reconciles HTTP CONNECT contracts and consumer acceptance;
T173 implements refusal with preserved authenticated SOCKS coverage and deployed evidence.
Both must complete before this consumer runs; T147 planning completion alone is insufficient.

## T172 Tor ingress consumer constraint

T173 is complete and remains a direct blocker. This validation-only ticket does not make a
new ingress, outage or forwarding claim. T173's deployed HTTP refusal and authenticated SOCKS
positive control remain its evidence; T155 owns cumulative post-change deployment validation.

## Validation record (2026-09-26)

- T167's committed `control_mount_test.sh` at `e33dc3b` hashes to the SHA-256 recorded in
  its ticket. Its preserved local pre-fix log shows the keys-only control starting and the
  full CP mount failing with Docker exit 125 and `read-only file system` at
  `/etc/stargate/keys`. T167 records the subsequent passing result and independent review.
- `bash tests/contract/stargate-cli/init_docker_test.sh` passed with Docker 29.1.3. It ran
  the real dispatcher against fresh four-service fixture projects, then checked provisioning,
  idempotence and project isolation. The fixture's CP/Tor are stand-ins, not production images.
- `bash tests/contract/compose/control_mount_test.sh` passed with the real CP image and
  effective Local mounts; Quarkus migration reached startup with the intended mount modes.
  `bash tests/contract/compose/local_compose_test.sh` passed the static topology checks.
- T163 records a post-T167 `scripts/stargate init` full Local startup on a disposable nested
  Docker host. This is historical evidence tied to that earlier source, not a current physical
  host or complete packet/ingress result.
- `bash scripts/verify.sh` was GREEN: 33 PASS, 2 SKIP, 0 FAIL. The Docker operational-log
  capture requires `STARGATE_TEST_TAGS=docker`; reproducibility is a separate release-cadence
  gate. Neither skip is claimed as measured evidence here.
