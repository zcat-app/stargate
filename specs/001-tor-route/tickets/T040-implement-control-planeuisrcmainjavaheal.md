---
id: T040
title: 'Implement `control-plane/ui/src/main/java/.../HealthEndpoint.java`'
status: pending
created: 2026-07-04
last_updated: 2026-09-06
source: tasks.md#T040
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # counted set: ui/pom.xml + HealthEndpoint.java + HealthEndpointTest.java (specs/ exempt per T039 r2 precedent)
out_of_scope:
  - compose/**                  # the stargate-control `healthcheck:` block is a separate ticket (T016 note: would modify T015's contract surface)
  - control-plane/runtime/**    # @QuarkusMain wiring, quarkus-maven-plugin activation, port/host config = T041
  - control-plane/Dockerfile    # T003a's "until T040 … activates the quarkus-maven-plugin" comment is T041's wiring, not this ticket
  - control-plane/api/** control-plane/core/** control-plane/persistence/**
privacy_critical: false
complexity: low   # confirmed at /start 2026-09-06: single constant-response route in an empty module
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/tasks.md#T040 (verbatim task body: single GET /healthz, 200, no body)
  - specs/001-tor-route/spec.md §Assumptions ("No Quarkus dashboard UI yet" — CP exposes no HTTP surface beyond a health endpoint used by docker compose healthchecks)
  - specs/001-tor-route/research.md §"Decision" (headless control plane: ui/ is a stub responding to GET /healthz → 200 and serves nothing else)
decision_refs:
  - research.md §"Decision" (headless CP; minimal subset)
  - plan.md §"Tech Stack" — DEVIATION recorded: plan lists "Quarkus Qute (stub healthcheck page)" but the task body pins "200 with no body"; a body-less healthcheck needs no template engine (see Notes)
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T040: Implement `control-plane/ui/src/main/java/.../HealthEndpoint.java`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `control-plane/ui/src/main/java/.../HealthEndpoint.java` — single `GET /healthz` returning 200 with no body (consumed by the Compose healthcheck only; no admin surface).

## Analysis

*(Omitted — `privacy_critical: false`, `complexity: low`.)*

## Acceptance

1. **Named test `HealthEndpointTest`**
   (`control-plane/ui/src/test/java/app/zcat/stargate/ui/HealthEndpointTest.java`,
   `@QuarkusTest` — boots the module's real HTTP layer): `GET /healthz`
   returns **200** with an **empty body** (the compose-healthcheck
   contract; spec §Assumptions "No Quarkus dashboard UI yet").
2. **Same test**: `POST /healthz` does **not** return 200 — the endpoint
   is bound to GET only ("single `GET /healthz`").
3. **Same test**: `GET /` returns **404** — the module serves nothing
   beyond the healthcheck path ("no admin surface"; research.md §"Decision":
   the stub "serves nothing else").
4. **Runnable command**: `scripts/verify.sh` is green — in particular the
   control-plane gate (`cd control-plane && ./mvnw -B verify`) compiles
   `ui/` under the inherited Error Prone + NullAway main-source config and
   passes `HealthEndpointTest`.

## Out-of-scope

- **The compose `healthcheck:` block for `stargate-control`** — T015's
  compose file deliberately ships none yet; T016's ticket records that
  adding real `healthcheck:` blocks "is a SEPARATE ticket (would modify
  T015's contract surface)". T040 delivers the endpoint the future block
  will consume.
- **All runtime wiring** (`control-plane/runtime/**`, per T041): the
  `@QuarkusMain` entry point, `quarkus-maven-plugin` activation in
  `runtime/`, and any `application.properties` (port/host binds). Note:
  control-plane/Dockerfile's comment says the image build fails "until
  T040 lands Java sources **and activates the quarkus-maven-plugin in
  runtime/**" — the maven-plugin activation is T041's wiring (T041 is
  the runnable-app ticket; runtime/pom.xml prose defers it "to later
  tasks"). After T040 the Docker build still does not run; that is the
  pre-existing T003a↔T041 contract, unchanged by this ticket.
- **No THREAT-MODEL / data-model amendment**: the listener adds a
  constant, unauthenticated `200` with no body on a compose-internal
  `internal: true` network — no host mapping, no state change, no bytes
  of information beyond liveness, no request parsing (no headers are
  read). It discloses nothing the network position doesn't already.
  Constitution Principle II is why `privacy_critical` is false: request
  bytes never transit this plane, and this endpoint carries none.

## Notes

Grounding decisions (at `/start` 2026-09-06):

1. **HTTP substrate = `quarkus-vertx-http`, declarative `@Route`** — not
   `quarkus-rest`/JAX-RS, not Qute. The verbatim task body pins "200 with
   no body", so plan.md's "Quarkus Qute (stub healthcheck page)" template
   idea is dropped: a body-less healthcheck needs no template engine. And
   the stub must "serve nothing else" (research.md §"Decision") — pulling
   a REST layer into a stub module is accidental surface the future
   admin-UI feature would inherit before its own spec exists. One
   `@Route(path="/healthz", methods=GET)` on a `@ApplicationScoped` bean
   is the minimal faithful implementation.
2. **Package `app.zcat.stargate.ui`** — module-reflective, and covered by
   the parent pom's NullAway `AnnotatedPackages=app.zcat.stargate`.
3. **ui/pom.xml staleness fixed in-passing**: its T104-era description
   says "Empty in v1 … this pom exists only to satisfy the reactor" and
   "no sources in v1" — written before implementation tickets were
   reached. T040's mandate requires sources; the pom is edited anyway to
   add the `quarkus-vertx-http` dependency, so its description is updated
   to name the healthcheck stub. The default-testCompile un-gating stanza
   stays (T104a pattern — tests remain outside Error Prone/NullAway).
4. **Port/bind config untouched**: Quarkus defaults apply (8080,
   all-interfaces inside the container). No script or test pins a port
   yet; the consumer (compose `healthcheck:`) is a separate ticket and
   T041 owns host/port configuration for the app.

Derivation note: `blocked_by: [T009]` (proto stubs) is satisfied — T009
is `done`; STATUS lists T040 as runnable.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
