---
id: T003a
title: 'Author `control-plane/Dockerfile`'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T003a
phase: "1: Setup (Shared Infrastructure)"
story: '-'
blocked_by: [T003]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
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

# T003a: Author `control-plane/Dockerfile`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `control-plane/Dockerfile` — multi-stage build that runs the Quarkus JVM-mode package step (`./mvnw -B -DskipTests package` against the reactor from T003) in the builder stage on a pinned JDK 25 LTS Temurin image (research.md §1), then `COPY --from=builder` the `quarkus-app/` layout into a JDK 25 LTS runtime base image (Temurin 25 JRE, digest-pinned). The runtime stage declares the `stargate-cp` user (UID 5101) and adds it to the supplementary group `stargate-ipc` (GID 5100) — same matching-numerics requirement as T002a. `WORKDIR /opt/stargate`; `ENTRYPOINT ["java", "-jar", "/opt/stargate/quarkus-run.jar"]` (or the equivalent module-path invocation Quarkus 3.33 emits). The image exposes the Compose healthcheck endpoint (`HealthEndpoint` from T040, `GET /healthz`) internally on the compose network only — there is no `EXPOSE` to the host (no host-port mapping; Compose healthcheck reaches it via the container network namespace). Apache 2.0 header per T006. The final image digest is pinned in `compose/docker-compose.local.yml` by T015 (Principle IV). Native-image is **not** in scope for this feature (plan.md "the JVM build is what this feature exercises"; native-image lands with the first release tag). Depends on T003 (Maven reactor); can run [P] with T002a.

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
