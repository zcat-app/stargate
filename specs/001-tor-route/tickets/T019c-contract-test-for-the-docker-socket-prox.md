---
id: T019c
title: 'Contract test for the `docker-socket-proxy` lockdown invariants'
status: done
created: 2026-07-04
last_updated: 2026-07-06
source: tasks.md#T019c
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
  - specs/001-tor-route/spec.md §"FR-016"
  - specs/001-tor-route/spec.md §"FR-012"
  - specs/000-architecture/spec.md §16.1
  - THREAT-MODEL.md §3.1
decision_refs:
  - SECURITY-DECISIONS.md §"2026-07-04 — docker-socket-proxy trust rationale"
  - specs/001-tor-route/research.md §5
reviews: { round: 1, date: 2026-07-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings:
  - '2026-07-06 major: CONTAINERS=1 read surface understated (archive/inspect of every container) — resolved: SECURITY-DECISIONS 2026-07-06 corrective entry + §Residue corrected'
  - '2026-07-06 minor: deny-by-default probed single request shape only — resolved in-code: GET /v1.43/version + HEAD /_ping probes added'
  - '2026-07-06 info: seeded torrc + --user 0 seed examined, not exploitable — no action'
clarity_check: {}
---

# T019c: Contract test for the `docker-socket-proxy` lockdown invariants

## Context

Derived from `specs/001-tor-route/tasks.md` (T019c). The `docker-socket-proxy`
service (T015) is the only container that mounts `/var/run/docker.sock`; the
C1-remediation property "CP compromise ≠ host root" (T017a,
SECURITY-DECISIONS.md) rests on its HTTP-level filter actually denying
everything except the GET-only observe surface SidecarMonitor (T039) needs.
T015's `local_compose_test.sh` M5 gates the compose-file *env keys* statically;
this ticket gates the *runtime behaviour* of the pinned image under that env,
so a silent regression in a compose edit OR an upstream image-default change
is caught end-to-end.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for the `docker-socket-proxy` lockdown invariants in
> `tests/contract/sidecar-proxy/lockdown_test.go` — brings up the compose
> stack and asserts, against `http://docker-socket-proxy:2375`:
> (a) `POST /containers/create`, `POST /containers/tor/kill`,
> `POST /containers/tor/exec`, `POST /images/create` all return HTTP 403
> (the `POST=0` lockdown from T015);
> (b) `GET /containers/tor/json` returns 200 with `State.Status` and
> `State.Health.Status` populated (the surface SidecarMonitor depends on
> per T039);
> (c) `GET /events?filters={"type":["container"]}` returns a streamed
> response on container start/stop transitions (also depended on by T039);
> (d) Endpoints NOT in the allowlist — `/networks/create`, `/volumes/create`,
> `/swarm/init`, `/info`, `/version` — all return 403, verifying the proxy
> denies-by-default rather than allows-by-default;
> (e) The proxy is NOT reachable from the host's network namespace on any
> host-published port (paralleling T019b's invariant for `tor:9050`).
> Gates the C1-remediation property "CP compromise ≠ host root" against
> silent compose-file regressions; the privacy-TCB rationale lives in T017a.

## Analysis

**Grounding finding (corrects the task body and the compose comment):**
probed empirically at /start (2026-07-06) against the pinned image
`tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e75…7ac2` running with the
compose-identical env (`EVENTS=1, CONTAINERS=1, POST=0`):

| Probe | Task body expects | Actual (pinned image) |
|---|---|---|
| `GET /version` | 403 | **200** — upstream defaults `VERSION=1` |
| `GET /_ping` | (not listed) | **200** — upstream defaults `PING=1` |
| `GET /info` | 403 | 403 |
| `GET /networks`, `GET /volumes` | (403 implied) | 403 |
| all `POST` probes | 403 | 403 |

The upstream image is NOT deny-by-default for `VERSION` and `PING` — the
compose comment ("all other endpoint flags unset so they default to deny")
and arch spec §16.1's "minimum surface" claim are factually wrong for those
two flags today. SidecarMonitor's documented surface (T039: `GET /events` +
`GET /containers/{name}/json` only) needs neither. Remediation is in-scope
per `docs/process/analysis.md`'s refine path: set `VERSION: 0` and `PING: 0`
explicitly in the compose file, promote the static check into M5, and assert
403 at runtime here — making the task body's (d) list true as written.

- **Must hold:**
  - (a) Every POST probe through the proxy returns HTTP 403 with `POST=0`:
    `/containers/create`, `/containers/{tor}/kill`, `/containers/{tor}/exec`
    (as `/containers/{id}/exec`, the API-correct path), `/images/create`.
  - (b) `GET /containers/{tor}/json` returns 200 and the body's
    `State.Status` and `State.Health.Status` are non-empty strings —
    the exact fields SidecarMonitor (T039) reads. (`{tor}` is the runtime
    container name resolved via compose labels; compose names it
    `<project>-tor-1`, so the literal path `/containers/tor/json` in the
    task body is shorthand, not the on-wire path.)
  - (c) `GET /events?filters={"type":["container"]}` (URL-encoded) streams:
    a container start/stop transition occurring while the request is open
    yields at least one `"Type":"container"` event line in the response
    body — the long-poll channel T039 depends on works through the proxy.
  - (d) Deny-by-default holds at runtime: `GET /info`, `GET /version`,
    `GET /_ping`, `GET /networks`, `GET /volumes`, `POST /networks/create`,
    `POST /volumes/create`, `POST /swarm/init` all return 403 under the
    amended env (`VERSION: 0`, `PING: 0` added; every non-granted section
    denied).
  - (e) The proxy is unreachable from the host netns: no published-port
    binding on the proxy container (SDK inspect) AND a host TCP dial to
    `127.0.0.1:2375` fails — paralleling T019b's FR-012 invariant.
  - All probes originate INSIDE the compose network (ephemeral digest-pinned
    curl container) — the proxy is compose-internal by design, so in-network
    probing is the only honest vantage point; (e) is the sole host-side probe.
  - The test self-skips cleanly when the docker daemon is unreachable
    (mirrors T019b), and tears down its own compose project + probe
    containers via `t.Cleanup` registered before bring-up.
- **Gated:**
  - `local_compose_test.sh` M5 statically asserts `EVENTS=1, CONTAINERS=1,
    POST=0` and rejects any extra flag set to `1` — catches the
    grant-broadening regression class at PR cadence. This ticket extends M5
    to also require `VERSION: "0"` and `PING: "0"` literals, so removing the
    new lockdown lines regresses statically, not just at runtime cadence.
  - `local_compose_test.sh` M9 gates the image digest-pin shape; Gate 1b
    ground-check covers pin liveness in ONLINE mode.
  - License-header check gates the SPDX header on the new Go file.
  - `gofmt`/`go vet` (container validation; verify.sh Gate 2 covers only
    `data-plane/`) cover the syntactic surface.
- **Residue:**
  - `CONTAINERS=1` grants **every GET/HEAD under `^(/v[\d.]+)?/containers`**
    — not just list/inspect/logs but also `GET /containers/{id}/archive`
    (arbitrary file read from ANY container's filesystem, e.g. Tor's
    entry-guard state, THREAT-MODEL §4.2) and full inspects (env, mounts)
    of every container. Section+method granularity is all HAProxy env flags
    can express; the CP-side invariant ("MUST NOT call any path outside
    `/events` and `/containers/{name}/json`") is T039's per-test mock at
    the CP unit-test layer, NOT enforceable at the proxy boundary.
    Surface characterization corrected per the T019c redteam major finding;
    durable record: SECURITY-DECISIONS.md §"2026-07-06 —
    docker-socket-proxy `CONTAINERS=1` read surface".
  - The read surface above (incl. `/logs` → Tor's notice-level stdout and
    `/archive` → guard state) is accepted for the LOCAL profile only, under
    THREAT-MODEL §3.1 (same-host attacker already game-over; the CP already
    mounts the keys volume directly) and contracts/torrc.md invariant #8
    (notice level carries no request data). The LAN/VPS release-blocker
    sweep (T017a entry + 2026-07-06 corrective entry) MUST re-scope against
    the section-granular grant.
  - The runtime probes run at container-validation/CI cadence, not every
    PR gate on hosts without docker — the M5 static extension is the
    PR-cadence backstop (this is the promoted-into-gated remainder).
  - arch spec §16.1 prose still says flags "default to deny" upstream;
    after this ticket the *stack* denies (the compose-file comment WAS
    corrected in this diff as truth-maintenance — review round 1 minor
    finding) but the arch-spec prose about upstream defaults stays slightly
    off. Flagged for the T083 doc-hygiene sweep rather than amending the
    arch spec here (scope).

## Acceptance

1. `compose/docker-compose.local.yml` `docker-socket-proxy.environment`
   gains `VERSION: 0` and `PING: 0` with a why-comment citing the /start
   probe (upstream defaults them to allow; SidecarMonitor needs neither).
   No other compose change.
2. `tests/contract/compose/local_compose_test.sh` M5 additionally asserts
   `environment.VERSION == "0"` and `environment.PING == "0"` (same
   `bail`-style as the existing EVENTS/CONTAINERS/POST literals).
3. New file `tests/contract/sidecar-proxy/lockdown_test.go` (package
   `sidecarproxy`, shared module `github.com/zcat-app/stargate/tests/contract`
   per research.md §5 — no new go.mod) defines `TestSocketProxyLockdown`
   which, after `docker compose -p stargate-t019c-test -f
   compose/docker-compose.local.yml --env-file compose/env/local.env.example
   up -d --build tor docker-socket-proxy` (DP/CP images are not yet
   buildable — same constraint T019b documents), runs sub-tests:
   - `PostSurfaceDenied` (a): POST probes to `/containers/create`,
     `/containers/{torName}/kill`, `/containers/{torName}/exec`,
     `/images/create` each return exactly HTTP 403.
   - `ContainerInspectSurfaceForSidecarMonitor` (b): GET
     `/containers/{torName}/json` returns 200; decoding the body yields
     non-empty `State.Status` and `State.Health.Status`.
   - `EventsStreamDelivers` (c): a streaming GET of
     `/events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D` opened
     before, and read while, an ephemeral container starts/stops, captures
     at least one `"Type":"container"` event.
   - `DenyByDefaultSurface` (d): GET `/info`, `/version`, `/_ping`,
     `/networks`, `/volumes`, POST `/networks/create`, `/volumes/create`,
     `/swarm/init`, plus two shape-variant probes hardening against
     upstream ACL regressions (redteam minor finding): GET `/v1.43/version`
     (version-prefixed path) and HEAD `/_ping` (method filter) — each
     returns exactly HTTP 403.
   - `HostCannotReachProxy` (e): SDK inspect of the proxy container shows no
     published binding for `2375/tcp`; host dial `127.0.0.1:2375` fails
     (any non-nil dial error, per T019b's non-over-narrow-match rationale).
4. Probes execute via ephemeral
   `curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69`
   containers attached to the compose network (resolved via SDK
   project+network labels, mirroring T019b's `lookupComposeNetwork`), using
   `-s -o /dev/null -w %{http_code}` for status assertions; the pin is a
   package-scope `probeImage` const whose comment cites Principle IV and the
   `docker buildx imagetools inspect` resolution procedure.
5. `t.Cleanup` (registered before bring-up) runs `docker compose … down
   --volumes --remove-orphans` under the unique `-p stargate-t019c-test`
   project; the whole test `t.Skip`s when the docker daemon is unreachable.
6. License header `// SPDX-License-Identifier: Apache-2.0` on the new Go
   file.
7. Container validation (host has no Go toolchain) — same harness as T019b:
   `golang:1.26.3-bookworm@sha256:252599…011c` with docker.sock + repo
   mounted, docker-ce-cli + compose plugin installed, then
   `cd tests/contract && gofmt -l . && go vet ./... && go test -race -v
   -count=1 -run TestSocketProxyLockdown ./sidecar-proxy/`.
8. `bash tests/contract/compose/local_compose_test.sh` and
   `bash scripts/verify.sh` both green.

## Out-of-scope

- SidecarMonitor itself and its CP-side path-allowlist mock — T039.
- `tests/contract/control-grpc/*` — T022.
- CI workflow wiring — T076. This test runs in container validation today.
- Amending arch spec §16.1 / T017a prose about upstream defaults — flagged
  for T083 (doc-hygiene sweep); the runtime property this ticket lands makes
  the *claimed* lockdown true regardless of prose.
- Re-testing T019b's tor-port invariants or M1–M11 statics beyond the M5
  extension — no duplication (spec.md FR-016 / analyze finding E1).
- Per-path (rather than per-section) proxy filtering — not expressible in
  tecnativa's env-flag model; documented as residue, owned by T039's CP-side
  gate.

## Notes

- The (d) list diverges deliberately from the task body: `/version` (and
  `/_ping`, unlisted there) return **200** under the stock pinned image —
  verified empirically at /start. Asserting 403 without the compose
  `VERSION: 0` / `PING: 0` amendment would be red on arrival; asserting 200
  would enshrine surface the threat model never granted. The amendment path
  keeps arch spec §16.1's "minimum surface" property true at runtime.
- Risk accepted: if T039's implementation later adopts a Docker SDK client
  (which pings/negotiates via `/_ping`), it will hit 403 and must either use
  plain HTTP GETs (as its task body already specifies) or re-grant PING via
  an explicit threat-model amendment — deny-by-default forces that
  conversation, which is the point.
- Why ephemeral curl probes instead of host-side HTTP: the proxy is
  compose-internal only (no `ports:`), so the host cannot reach it by
  design; in-network probing is the only vantage point that exercises the
  real CP→proxy path. Precedent: T019b's ephemeral `nc` probe.
- Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04. §Analysis +
  §Acceptance derived at `/start` 2026-07-06 against HEAD `ba22b2b`;
  lockdown table probed live against the pinned image (docker 29.6.1).
