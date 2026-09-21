---
id: T123
title: 'Fresh-host CP start fails: rw child mount under :ro volume parent'
status: pending
created: 2026-09-07
last_updated: "2026-09-12"
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: ["T139", "T134", "T138", "T156", "T162", "T164", "T165"]
parallel: true
files_budget: 4
privacy_critical: true
complexity: medium
risk: "medium"
round_cap: 2
spec_refs:
   - specs/001-tor-route/contracts/control-grpc.md §"Socket topology"   # pins /etc/stargate/keys as the contract mount path
   - specs/001-tor-route/spec.md#FR-017   # pins /etc/stargate/tokens.yaml inside the :ro config volume — the nesting is inherent to the two contract paths
   - specs/001-tor-route/tasks.md#T059   # discoverer (live run, 2026-09-07)
decision_refs:
   - .specify/memory/constitution.md#Principle-IV   # if the resolution touches the :ro hardening posture, record it there
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T123: Fresh-host CP start fails: rw child mount under :ro volume parent

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

## Analysis

*(Quick pass — the resolution is a design decision for the compose owners;
this ticket frames the options and the evidence.)*

Options (any ONE satisfies acceptance #1):
- **Provisioning:** `scripts/stargate init` (T016) + quickstart Step 2
  pre-create `keys/` in the config volume (same helper-container pattern
  the quickstart already uses for tokens.yaml). Cheapest; keeps the :ro
  posture byte-for-byte.
- **Image-side:** create `/etc/stargate/keys` in the CP image. Does NOT
  help: the ro volume mount shadows the rootfs path before the child
  mountpoint is made (same EROFS). Listed so nobody retries it.
- **Compose redesign:** mount the config volume at a different parent and
  bind/copy tokens.yaml to its fixed path, or drop the `:ro` — EITHER
  touches a contract path or the hardening posture, so it requires a
  SECURITY-DECISIONS.md entry (Constitution IV discipline).

## Acceptance

1. On a clean project volume set, the supported `scripts/stargate init`
   sequence brings up all four Local services (DP, CP, Tor and observer)
   without manual volume surgery. Tor's Docker healthcheck and the
   observer's process-running state are reported distinctly; an observer
   process alone is not proof of authenticated Tor health.
2. If the chosen option touches the :ro posture or a contract path, the
   change is recorded in SECURITY-DECISIONS.md and the structural compose
   contract (local_compose_test.sh M-gates) is extended to pin the new
   shape.
3. `bash scripts/verify.sh` GREEN.

### Required planning refinement


The supported clean-start sequence was selected after T134/T138. Acceptance #1 means
empty project volumes followed by the documented operator initialization and Compose startup;
raw `compose up` is not an alternative success claim. Test the
actual operator commands without harness-only mkdir/chown/key seeding. Preserve read-only
configuration and least privilege. Record the failing fresh-volume regression before fixing it.
The earlier design options are hypotheses, not permission to weaken the hardening posture.

## Out-of-scope

- T059's runtime assertion (its harness pre-creates the mountpoint until
  this lands — remove that note's staleness only if the mechanism changes).
- DP-side mounts (no nesting there) and the tor service (single volume).

## Notes

Hand-filed by the T059 session (2026-09-07) per the surgical-changes
doctrine: the boot gap is real and user-facing (every fresh-host operator
hits it), but fixing it inside T059 would expand that ticket's scope from
test-authoring to deployment redesign.
