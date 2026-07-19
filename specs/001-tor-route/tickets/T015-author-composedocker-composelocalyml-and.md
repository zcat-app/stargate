---
id: T015
title: 'Author `compose/docker-compose.local.yml` and `compose/env/local.env.e'
status: done
created: 2026-07-04
last_updated: 2026-07-04
source: tasks.md#T015
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: [T006]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low
risk: low
round_cap: 2
spec_refs:
  - spec.md#FR-005
  - spec.md#FR-007
  - spec.md#FR-012
  - spec.md#FR-015
  - contracts/control-grpc.md#Socket-topology
  - data-model.md#6-compose-volume-identities
constitution_refs:
  - "II: Plane separation (DP keeps routing if CP unreachable)"
  - "IV: Pinned, tested, manually promoted"
  - "VI: Open and auditable"
decision_refs:
  - plan.md#C1-remediation (docker-socket-proxy trust rationale → T017a)
reviews: { round: 1, date: 2026-07-04, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T015: Author `compose/docker-compose.local.yml` and `compose/env/local.env.e

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Author `compose/docker-compose.local.yml` and `compose/env/local.env.example` — **four services**: `stargate-dp`, `stargate-control`, `tor`, and `docker-socket-proxy` (a digest-pinned `tecnativa/docker-socket-proxy` instance that bridges `/var/run/docker.sock` to a filtered HTTP API; see SidecarMonitor at T039 and the trust rationale at T017a). Loopback-only port binding for 8881 on the data plane; no host port mapping for the Tor SocksPort or ControlPort; no host port mapping for the proxy. Named volumes per data-model.md §6. Per-plane runtime users created in each Stargate-owned image's Dockerfile and pinned via the compose `user:` directive — `stargate-cp` (UID 5101) for `stargate-control`, `stargate-dp` (UID 5102) for `stargate-dp`. A **shared supplementary group `stargate-ipc` (GID 5100)** is declared in both Stargate Dockerfiles, and both runtime users are added to it; this group owns the UDS files in `stargate-ipc` (per `contracts/control-grpc.md` §"Socket topology": `control.sock` owned `stargate-cp:stargate-ipc`, `dp.sock` owned `stargate-dp:stargate-ipc`, mode 0660). The mode/group scheme is the kernel-enforced gate that (a) lets the peer plane `connect(2)` its dial-direction socket — `0600` with distinct UIDs would silently break inter-plane comms — while (b) keeping random unprivileged same-host processes outside the dial surface; role separation itself is enforced by `bind(2)` (only the hosting plane is wired to call it on each path), not by the file mode. Distinct hosting UIDs are retained as defense-in-depth: a compromise of one plane does not yield filesystem-write access to the *other plane's* state volume (`stargate-control-state` vs `stargate-dp-state`); only the IPC volume is shared. The GID/UID numeric values used here MUST match the values referenced by the `user:` directives and any `chown` invocations across the CP and DP Dockerfiles. The Tor container drops to its own `tor` user per T014; `docker-socket-proxy` runs as the unprivileged user its upstream image declares. `docker-socket-proxy` is the ONLY service that mounts `/var/run/docker.sock` (read-only) from the host; the CP reaches it as `http://docker-socket-proxy:2375` over the compose-internal network. Proxy environment locked to the minimum surface SidecarMonitor needs: `EVENTS=1`, `CONTAINERS=1`, all other endpoint flags unset so they default to deny, and `POST=0` to forbid container spawn/kill/exec (verified by T019c). sha256-pinned image digests for the Debian-slim base, the final Tor sidecar image (FR-015), and the docker-socket-proxy image (Principle IV — every external component is digest-pinned). The Tor sidecar's compose service key is `tor` so its in-network DNS name matches FR-007 / T047's `tor:9050` dial target. **Verified by T019b (Tor port exposure), T019c (proxy lockdown), and T022's extended invariants (peer-dial succeeds, out-of-group dial fails).**

## Analysis

**Ground truth verified on-disk:**
- `sidecars/tor/Dockerfile` (T014, DONE) — runtime user `tor`, base digest-pinned in both stages, ENTRYPOINT `tor -f /etc/tor/torrc`, HEALTHCHECK probes control port 9051.
- `data-plane/Dockerfile` (T002a, DONE) — `FROM scratch`, UID 5102 / GID 5100, ENTRYPOINT `/opt/stargate/stargate-proxy`. Build will fail until T007 lands Go sources — `build:` directive in compose is correct regardless.
- `control-plane/Dockerfile` (T003a, DONE) — `eclipse-temurin:25-jre-noble`, UID 5101 / GID 5100, ENTRYPOINT `java -jar /opt/stargate/quarkus-run.jar`. Build will fail until T040 lands Java sources.
- `tecnativa/docker-socket-proxy:0.3.0` multi-arch index digest resolved live via `docker buildx imagetools inspect`: `sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2`. Tagged release (not `latest`) per Principle IV.
- `scripts/check-license-headers.sh` covers `*.sh` but NOT `*.yml`/`*.yaml`/`*.env` — the compose file's SPDX header is unenforced by verify.sh; convention-only.
- `scripts/ground-check.sh` scans only Dockerfile `FROM` lines for digest pins; compose `image:` lines are NOT scanned.
- `tests/contract/{tor,sidecar-proxy}/` exist but empty — T019b (Tor port exposure) and T019c (proxy lockdown) are separate Phase-2 tickets, not in this ticket's scope.

**Spec interpretation — FR-015 "final composed image pinned by digest":** for the three Stargate-built images (DP/CP/Tor) there is no registry in the Phase-2 scaffolding horizon, so a literal `image: <name>@sha256:<digest>` pin against a built image is not meaningful (every rebuild changes it). The base-image digest pins already live inside each Dockerfile (the actual deployment-time content pin), and T014's header comment names compose-time final-image pinning a release-tag-time concern. This ticket uses `build:` for Stargate-built images and applies the literal `image:@sha256:` digest pin ONLY to the external image (`tecnativa/docker-socket-proxy`). Forward reference: T017's SECURITY-DECISIONS.md rotation policy records the deferral. Flagged as residue below.

- **Must hold:**
  - **M1 (FR-005).** DP publishes port 8881 on loopback only: the `ports:` entry is the long-form `127.0.0.1:8881:8881/tcp`, never the short form `8881:8881` (which silently binds `0.0.0.0`).
  - **M2 (FR-012).** Tor's `SocksPort` (9050) and `ControlPort` (9051) are NEVER listed under any service's `ports:`. They are compose-internal only via `expose:`.
  - **M3 (FR-012).** `docker-socket-proxy` has zero host port mapping — only `expose: [2375]`.
  - **M4 (task body / T017a).** `/var/run/docker.sock` is mounted ONLY by `docker-socket-proxy`, and read-only (`/var/run/docker.sock:/var/run/docker.sock:ro`).
  - **M5 (task body / T019c).** `docker-socket-proxy` env locks the surface to `EVENTS=1`, `CONTAINERS=1`, `POST=0`; every other endpoint flag is unset (default deny). No `EX=1` / `EXEC=1` / `POST=1` / `BUILD=1` / `IMAGES=1` etc.
  - **M6 (task body / control-grpc.md §"Socket topology").** `user:` directives exactly match the Dockerfile numerics: `stargate-control` → `5101:5100`, `stargate-dp` → `5102:5100`. The Tor container inherits T014's `USER tor` (no `user:` override needed; if specified it must be the upstream-declared uid).
  - **M7 (data-model.md §6).** Exactly seven named volumes declared under `volumes:`: `stargate-keys`, `stargate-ipc`, `stargate-control-config`, `stargate-control-state`, `stargate-dp-state`, `stargate-tor-state`, `stargate-tor-config`. Mount semantics match the table: `stargate-tor-config` is CP RW + Tor `:ro`; `stargate-ipc` is mounted into both planes at `/run/stargate`; `stargate-keys` into both planes at `/etc/stargate/keys`; `stargate-tor-state` into Tor at `/var/lib/tor`; `stargate-control-config` + `stargate-control-state` into CP; `stargate-dp-state` into DP.
  - **M8 (FR-007).** Tor service key is `tor` so compose DNS yields `tor:9050` matching T047's dial target.
  - **M9 (Principle IV).** The external image (`tecnativa/docker-socket-proxy`) is pinned `image: tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2`. Stargate-built images (DP/CP/Tor) use `build:` with their Dockerfile's base digest pin as the content pin.
  - **M10 (Principle II).** DP has NO `depends_on:` entry — even on CP or Tor. CP may `depends_on: [tor, docker-socket-proxy]` for healthcheck ordering (CP is allowed to wait for sidecars it observes); DP is not.
  - **M11 (task body).** Exactly four services are declared: `stargate-dp`, `stargate-control`, `tor`, `docker-socket-proxy`.
  - **M12 (task body / T006).** SPDX-License-Identifier: Apache-2.0 in both new files.
  - **M13 (FR-005).** Network topology: one compose-internal bridge network shared by all four services; only DP publishes a host port (M1).

- **Gated:**
  - License-header check (verify.sh gate 1) catches M12 — but only for `local_compose_test.sh` (`*.sh`); the compose `.yml` and `.env` files are NOT gated. (Convention only for those.)
  - `docker compose -f compose/docker-compose.local.yml config --quiet` catches parse errors and unknown-volume references (M7 completeness).
  - **New gate added by this ticket** — `tests/contract/compose/local_compose_test.sh` promotes M1, M2, M3, M4, M5, M6, M8, M9, M10, M11 from residue to gated via static structural assertions on the rendered compose config. See §Acceptance AT-2.
  - Future T019b (Tor port exposure, runtime) and T019c (proxy lockdown, runtime HTTP probes) layer RUNTIME verification on top of this ticket's STATIC verification — they are not in scope here but their compose-file preconditions are gated by AT-2.

- **Residue:**
  - **R1.** Final-image digest pin for the three Stargate-built images (literal FR-015 reading). Deferred to release-tag time (no registry in Phase-2 scaffolding horizon). Recorded in T017's SECURITY-DECISIONS.md rotation policy entry (cross-reference, not in this ticket's scope). Not gated by anything; deployment-time reproducibility is the fallback (T075 data plane, future CP/Tor equivalents).
  - **R2 (CLOSED — hardening commit `HARDENING-ground-check-compose-pins`).** The docker-socket-proxy digest pin (M9) is validated by AT-2's structural regex as "has `tag@sha256:<64hex>` shape" AND, as of the post-T015 hardening commit, by `scripts/ground-check.sh`'s new "Compose image pins" section which resolves compose `image:` references (literal or `${VAR}`-substituted-from-env-files) against the registry in ONLINE mode. Run `STARGATE_GROUND_ONLINE=1 bash scripts/verify.sh` before a release tag — a pruned/malformed digest fails loudly. (Closes redteam finding m1.)
  - **R3.** `stargate-tor-config` RW-for-CP / RO-for-Tor mount-mode asymmetry (M7) is asserted structurally by AT-2 (the `:ro` suffix on the Tor mount); a future regression that drops only the `:ro` would still leave both services mounting the volume, and the structural grep must check the suffix specifically.
  - **R4.** Compose schema validity across compose-spec versions is `docker compose config`'s job; if a future compose-file feature requires a newer schema version, the schema pin at the top of the file (`version:`) must be bumped deliberately. AT-2 does not assert a specific schema version. (The `version:` key is intentionally omitted — Compose v2 ignores it.)
  - **R5.** The `:ro` suffix on the `/var/run/docker.sock` bind mount is convention-only and provides NO kernel-enforced isolation — Unix-domain sockets are bidirectional; the mount mode does not constrain the proxy's write-direction requests to the Docker daemon. The actual enforcement is the HTTP-level filter inside `docker-socket-proxy` (EVENTS=1, CONTAINERS=1, POST=0), gated at runtime by T019c. The `:ro` suffix is retained as intent-documentation only; do not treat it as a security boundary. (redteam finding m3.)

## Acceptance

**AT-1 — Compose file parses clean.**
```bash
docker compose -f compose/docker-compose.local.yml config --quiet
```
Exits 0 (no parse errors, no dangling volume references, no unknown service refs). Local.env.example is consumed without override.

**AT-2 — Static structural contract test (gates M1–M4, M5–M11).**
```bash
bash tests/contract/compose/local_compose_test.sh
```
Renders the compose config via `docker compose -f compose/docker-compose.local.yml config` (no `up` — no daemon containers started) and asserts, with `jq` + `grep`:
- (a) **M11** exactly four services: `stargate-dp`, `stargate-control`, `tor`, `docker-socket-proxy`.
- (b) **M1** `stargate-dp.ports` contains `"127.0.0.1:8881:8881/tcp"` and NO entry whose published-bind host is `0.0.0.0` or empty-prefix `8881:`.
- (c) **M2** the `tor` service has NO `ports` key (or it is `null`).
- (d) **M3** the `docker-socket-proxy` service has NO `ports` key (or `null`).
- (e) **M4** exactly one service mounts `/var/run/docker.sock`, it is `docker-socket-proxy`, and the mount mode contains `:ro`.
- (f) **M5** `docker-socket-proxy.environment` has `EVENTS=1`, `CONTAINERS=1`, `POST=0`, and grepping the rendered config for `EXEC=1`, `BUILD=1`, `IMAGES=1`, `INFO=1`, `NETWORKS=1`, `NODES=1`, `PLUGINS=1`, `SERVICES=1`, `SESSION=1`, `SWARM=1`, `SYSTEM=1`, `TASKS=1`, `VOLUMES=1`, `AUTH=1`, `DISTRIBUTION=1`, `SECRETS=1`, `POST=1` returns zero matches.
- (g) **M6** `stargate-control.user` is `"5101:5100"` and `stargate-dp.user` is `"5102:5100"`.
- (h) **M7** exactly the seven named volumes are declared; `stargate-ipc` is mounted into both `stargate-dp` and `stargate-control` at `/run/stargate`; `stargate-tor-config` mount on `tor` carries `:ro`.
- (i) **M8** the `tor` service key exists (compose DNS name `tor`).
- (j) **M9** the `docker-socket-proxy.image` matches regex `^tecnativa/docker-socket-proxy:[^@]+@sha256:[0-9a-f]{64}$`.
- (k) **M10** `stargate-dp` has no `depends_on` key (or it is `null`/empty).

Non-zero exit on any failed assertion. Test file carries the Apache 2.0 SPDX header (gated by verify.sh license-headers gate).

**AT-3 — `compose/env/local.env.example` exists and is documented.**
File exists, carries SPDX header, and every variable it sets is referenced by `${...}` in the compose file (no orphan env vars, no undeclared compose substitutions).

## Out-of-scope

- **T019b** (runtime Tor port exposure contract test — TCP connect + `docker inspect`): separate ticket, layered on top of this compose file.
- **T019c** (runtime docker-socket-proxy lockdown contract test — HTTP probes): separate ticket.
- **T022** (peer-dial / out-of-group dial contract tests): separate ticket; validates the runtime effect of M6's UID/GID scheme.
- **Final-image digest pin for Stargate-built images** (DP/CP/Tor): release-tag-time concern; deferred to the registry-push step (see R1).
- **`scripts/stargate` compose-up wiring** (T016): the entrypoint that consumes this compose file is a separate ticket.
- **`--profile` flags or alternate `docker-compose.lan.yml` / `docker-compose.vps.yml`**: out of scope; this ticket authors the `local` profile only.

## Notes

- **R2 operator guidance:** before a release tag, run `STARGATE_GROUND_ONLINE=1 bash scripts/verify.sh`. The post-T015 hardening commit extended `scripts/ground-check.sh` to resolve compose `image:` references against the registry in ONLINE mode — the tecnativa/docker-socket-proxy digest pin is now verified end-to-end. (Closes redteam finding m1.)
- **Compose `version:` field:** omitted. Docker Compose v2 (the `docker compose` plugin, installed: 29.6.1 server) ignores the `version:` key and warns if present. The schema is the current Compose specification.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
