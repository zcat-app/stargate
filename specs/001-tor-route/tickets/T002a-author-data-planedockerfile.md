---
id: T002a
title: 'Author `data-plane/Dockerfile`'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T002a
phase: "1: Setup (Shared Infrastructure)"
story: '-'
blocked_by: [T002]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T002a: Author `data-plane/Dockerfile`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `data-plane/Dockerfile` — multi-stage build that compiles the Go binary using the toolchain from T002 and the byte-reproducible build flags from T004 (`-trimpath -buildvcs=false -ldflags="-buildid="` + `CGO_ENABLED=0`) in the builder stage, then `COPY --from=builder` into a minimal runtime base image (e.g., digest-pinned `gcr.io/distroless/static-debian12:nonroot` or `scratch` with the binary statically linked). The runtime stage declares the `stargate-dp` user (UID 5102) and adds it to the supplementary group `stargate-ipc` (GID 5100) — the GID/UID numerics MUST match T015's compose `user:` directive and `contracts/control-grpc.md` §"Socket topology". `WORKDIR /opt/stargate`; `ENTRYPOINT ["/opt/stargate/stargate-proxy"]`. Apache 2.0 header per T006. The final image digest is pinned in `compose/docker-compose.local.yml` by T015 (Principle IV); reproducibility is asserted by T075 (the binary inside) and the Dockerfile itself is gated by `tests/reproducibility/data_plane_test.sh` re-building it twice. Depends on T002 (go.mod) and T004 (Makefile / build flags); can run [P] with T003a.

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derive from the spec at `/start` — see `docs/process/ticket-template.md`
for the preferred shapes: named test, behavioral assertion, runnable command.)*

## Out-of-scope

*(Fill at `/start` if the task body references exclusions or other tickets' work.)*

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
