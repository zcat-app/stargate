---
id: T019b
title: 'Contract test for FR-012 Tor port-exposure invariant'
status: done
created: 2026-07-04
last_updated: 2026-07-05
source: tasks.md#T019b
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]
parallel: true
files_budget: 8
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md §"FR-012"
  - specs/000-architecture/spec.md §4.2
  - specs/001-tor-route/contracts/control-grpc.md §"Socket topology"
decision_refs:
  - specs/001-tor-route/research.md §5
reviews: { round: 1, date: 2026-07-05, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T019b: Contract test for FR-012 Tor port-exposure invariant

## Context

Derived from `specs/001-tor-route/tasks.md` (T019b). FR-012 requires that the
Tor sidecar's `SocksPort` (9050) and `ControlPort` (9051) MUST NOT be published
to the host — they are reachable only on the compose-internal bridge network
shared with the data plane. T015's `local_compose_test.sh` gates the
compose-FILE precondition statically (no daemon containers started); this
ticket gates the RUNTIME property after `docker compose up` so that a silent
compose regression is caught end-to-end.

## Analysis

- **Must hold:**
  - (a) After bringing up the `tor` service, a TCP dial from the host network
    namespace to `127.0.0.1:9050` AND `127.0.0.1:9051` both fail (no listener
    on the host loopback) — the tor container is reachable ONLY on the
    `stargate-internal` bridge network.
  - (b) `docker inspect tor` (via Docker SDK) returns `NetworkSettings.Ports`
    with `9050/tcp` and `9051/tcp` both absent (no published binding entry),
    confirming the runtime state matches the compose-file invariant T015 M2
    checks statically.
  - (c) An ephemeral container attached to the `stargate-internal` network can
    TCP-dial `tor:9050` and succeed — FR-007's data-plane → sidecar path is
    not accidentally broken by over-restricting the network.
  - The test self-skips cleanly when its prerequisites are unmet (no docker
    daemon → whole test skips; `data-plane/cmd/stargate-proxy/main.go` absent
    → (c) skips only). The (c) content-gate is the proxy for "stargate-dp
    image is buildable"; it self-lifts without code change when the DP-main
    ticket lands.
- **Gated:**
  - `tests/contract/compose/local_compose_test.sh` M2 statically asserts
    `tor.ports` is null/absent in the rendered compose config — catches the
    `ports: ["9050:9050"]` regression class at PR cadence without bringing
    anything up.
  - T015's local_compose_test.sh M3/M4 assert `stargate-internal` is the only
    network and `tor` is attached to it.
  - License-header check gates the SPDX header on the new Go files.
- **Residue:**
  - "(c) verifies bridge-reachability on the stargate-internal network,
    NOT per-container ACL isolation" — FR-012's wording ("only the data
    plane container needs SocksPort access") is descriptive of design
    intent, NOT enforceable by Compose today. A docker bridge network
    exposes L3 reachability to EVERY attached container; Compose does
    not provide per-container ACLs. The ephemeral-probe-on-same-network
    check verifies the property Compose CAN enforce (bridge-reachability
    of `tor:9050`). A future regression that re-attaches `tor` to a
    different docker network is caught statically by T015's
    `local_compose_test.sh` M3/M4. Per-container ACL isolation, if
    needed in a future profile (LAN/VPS), is a separate feature-spec
    concern.
  - "(c) self-lifts when `data-plane/cmd/stargate-proxy/main.go` lands" —
    that content gate is a proxy for "stargate-dp image is buildable",
    not the literal truth. A future edit that adds the file but breaks
    the build silently surfaces as a (c) failure (build fail →
    fail-not-skip), which is the desired behavior.
  - "Tor image build is reproducible + apt-key fingerprint matches at
    build time" — gated by sidecars/tor Dockerfile's own RUN assertion
    (PUB_COUNT==1 + fingerprint match). Inherited, not re-gated here.
    (Taxonomy note: this is technically a §Gated item rather than
    residue; listed here for cross-reference continuity with T017.)

## Acceptance

1. New file `tests/contract/tor/port_exposure_test.go` defines
   `TestTorPortExposure` with three `t.Run` sub-tests:
   - `HostCannotReachTorPorts`: after `docker compose -f
     compose/docker-compose.local.yml --env-file
     compose/env/local.env.example up -d tor`, dials `127.0.0.1:9050` and
     `127.0.0.1:9051` from the test process; both dials MUST fail (any
     non-nil error satisfies the property; specifically expecting
     connection-refused when nothing else on the host binds those ports).
   - `TorContainerHasNoPublishedPorts`: uses `github.com/docker/docker/client`
     SDK to inspect the `tor` container; asserts
     `NetworkSettings.Ports["9050/tcp"]` and `["9051/tcp"]` are both nil.
   - `StargateDPNamespaceCanReachTorSocksPort`: only runs when
     `data-plane/cmd/stargate-proxy/main.go` exists in the repo (content
     gate); brings up the `stargate-dp` service, then runs an ephemeral
     `alpine:3@sha256:28bd5fe8…43f8b` container (digest-pinned per
     Constitution Principle IV) attached to the `stargate-internal`
     compose network — network name resolved at runtime via the SDK's
     `NetworkList` with compose-project + compose-network labels (NOT
     hardcoded as `<project>_<name>`, which is an undocumented Compose
     v2 convention). The container runs `nc -z -w 2 tor 9050`; exit
     code 0 is the success criterion. Skips with a precise message
     when the content gate is unmet.
2. The file defines a `probeImage` constant at package scope holding
   the digest-pinned alpine reference, used at both the `docker pull`
   and `docker run` sites so the pin cannot drift between them. The
   `const` comment cites Principle IV and the `docker buildx imagetools
   inspect alpine:3` resolution procedure so a future rotation is
   self-documenting.
2. New `tests/contract/go.mod` — module
   `github.com/zcat-app/stargate/tests/contract`, `go 1.26`,
   `toolchain go1.26.3`, requiring `github.com/docker/docker` (client SDK).
   This is the shared module for ALL future Go contract surfaces per
   research.md §5 (`torrc/`, `error-template/`, `sidecar-proxy/`).
3. `tests/contract/go.sum` committed alongside (run `go mod tidy` in the
   throwaway validation container).
4. `go.work` updated to add `./tests/contract` to the `use(...)` block.
5. `t.Cleanup` brings down the stack via `docker compose ... down --volumes`
   using a unique `-p stargate-t019b-test` project name so the test never
   collides with operator-authored state.
6. The whole test `t.Skip`s when the Docker daemon is unreachable.
7. License header `// SPDX-License-Identifier: Apache-2.0` at the top of
   every new Go file (incl. `go.mod` per T019a precedent — belt-and-braces).
8. Container validation (host has no Go toolchain):
   ```
   docker run --rm \
     -v /var/run/docker.sock:/var/run/docker.sock \
     -v "$PWD":/src -w /src \
     golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c \
     sh -c '
       # Install docker-ce-cli + docker-compose-plugin (the golang image
       # ships neither); the daemon is reached via the mounted socket.
       install docker + compose plugin (apt + download.docker.com repo)
       cd tests/contract && gofmt -l . && go vet ./... && \
         go test -race -v -count=1 ./...
   '
   ```
   The `golang:1.26.3-bookworm` digest pin (`@sha256:252599…01c`) mirrors
   `data-plane/Dockerfile:36` exactly — Principle IV: every external
   image reference is digest-pinned, never by mutable tag. The shared
   digest means a single rotation (in `data-plane/Dockerfile`) is the
   promotion gate; bumping this validation command without bumping the
   Dockerfile is a smell.

## Out-of-scope

- `tests/contract/sidecar-proxy/lockdown_test.go` is T019c.
- `tests/contract/control-grpc/*` is T022.
- T076's CI workflow wiring is NOT touched here. This test runs in container
  validation today and in CI when T076 lands.
- The compose-file static structural properties (M1-M11) are T015's
  `local_compose_test.sh` — this test does NOT duplicate them.
- `data-plane/cmd/stargate-proxy/main.go` itself is owned by a Phase-3+
  ticket; we only gate on its presence for sub-test (c).
- No change to `compose/docker-compose.local.yml`, `sidecars/tor/Dockerfile`,
  or any Stargate runtime source.

## Notes

- Why ephemeral container on `stargate-internal` for (c) instead of
  `docker exec stargate-dp`: the runtime image is `FROM scratch` (no shell,
  no `nc`). Ephemeral alpine + `nc` on the same docker network is the
  cheapest equivalent check for the bridge-reachability property FR-012
  actually constrains.
- Why shell-out for `docker compose up` rather than compose Go SDK: the
  compose SDK (`github.com/compose-spec/compose-go` + cli) is much heavier
  than the `docker/client` SDK the ticket mandates. The ticket specifies
  the latter for inspect ops, not full compose lifecycle.
- Why shared `tests/contract/go.mod` (not per-surface): research.md §5
  names three more Go contract surfaces (`torrc/`, `error-template/`,
  `sidecar-proxy/`). A single shared module hosts all of them without
  re-structuring when those tickets land.
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance derived at `/start` 2026-07-05 against HEAD `d5e9b9c`.
