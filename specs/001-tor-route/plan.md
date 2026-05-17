# Implementation Plan: Tor Route — v1 Vertical Slice

**Branch**: `001-tor-route` | **Date**: 2026-05-17 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification at `specs/001-tor-route/spec.md`

**Derives from**: `.specify/memory/constitution.md` v1.1.0 · `specs/000-architecture/spec.md` · `THREAT-MODEL.md` §3.1, §4.2.

---

## Summary

Stand up the first end-to-end Stargate route: Mullvad Browser → WebExtension →
data plane (port 8881, loopback) → Tor sidecar (SOCKS5 9050, compose-internal) →
Tor network → `.onion` destination. Per-first-party-domain stream isolation is
enforced via Tor's `IsolateSOCKSAuth` driven by the extension's SOCKS5 username.
The control plane runs headlessly in this slice — it loads bearer tokens from a
YAML file at startup, pushes hashed tokens to the data plane via gRPC
`ReloadTokens`, and emits `SidecarEvent`s — but exposes no admin UI beyond a
healthcheck endpoint. Failure modes return the privacy-safe error template from
architecture spec §10, including a new `AUTH_REQUIRED` code introduced by this
feature.

The vertical proves: (1) the data plane forwards bytes correctly through a real
sidecar to a real anonymity network; (2) the extension's `proxy.onRequest` path
works end-to-end with SOCKS5h and stream isolation; (3) the contract-test gate
(Principle IV) blocks merges that break the Tor surface Stargate depends on;
(4) the Go data plane build produces a byte-reproducible artefact.

## Technical Context

**Language/Version**:

- **Data plane**: Go (toolchain pinned via `go.mod` `toolchain` directive — concrete patch fixed during scaffold task; v1.23.x line per `NEEDS CLARIFICATION` resolved in research.md §1).
- **Control plane**: JDK 25 LTS + Quarkus 3.33 LTS (constitution Tech Stack pin). This feature builds the *JVM-mode* artefact; native-image is not load-bearing for this slice (spec Assumption "Reproducibility holds for the Go data plane in this feature").
- **Extension**: WebExtensions MV2, vanilla JavaScript (ES2022), no build step (arch §12.3, Principle VI — avoid npm supply chain on a privacy-critical component).
- **Sidecar**: Tor (from `deb.torproject.org`) on pinned `debian:12-slim` base, built by Stargate's Dockerfile at `sidecars/tor/`.

**Primary Dependencies**:

- **Data plane**: Go stdlib (`net`, `crypto/subtle`, `context`, `log/slog`); `golang.org/x/net/proxy` for SOCKS5 client outbound to the Tor sidecar; `google.golang.org/grpc` for the inter-plane client; protobuf v3 generated stubs from `proto/stargate/v1/`. No third-party HTTP server frameworks — the data plane uses the stdlib for SOCKS5 framing and CONNECT.
- **Control plane**: Quarkus core, Quarkus gRPC, Hibernate ORM with Panache, Quarkus JDBC SQLite, Flyway, Quarkus Qute (used only for a stub healthcheck page in this feature), SnakeYAML for `tokens.yaml` parsing.
- **Extension**: WebExtensions APIs — `proxy`, `storage`, `webRequest`, `webRequestBlocking`, `privacy`, `notifications`. No third-party JS deps.

**Storage**:

- **Control plane**: SQLite (WAL) at `/var/lib/stargate/control.db` mounted from named volume `stargate-control-state`. This feature populates `audit_log` (one row per token load) and reads/writes `enrolled_devices` indirectly via the YAML loader (token records are derived from the file; the row is created in the DB for audit but never used as the source of truth in v1).
- **Data plane**: in-memory `tokenList` plus on-disk fallback at `/var/lib/stargate/dp-snapshot.json` (arch §5.5) — last-known token hash list, route enable mask, restored at cold start if control plane is unreachable.
- **Extension**: `storage.local` per arch §14.4. Bearer token stored in `storage.local` with a visible warning in the options UI (resolves arch §15 #8 for v1 — see research.md §6).
- **Tor sidecar**: `/var/lib/tor/` mounted from named volume `stargate-tor-state` (entry-guard state persists across container restarts — THREAT-MODEL §4.2 "Stargate-specific notes").

**Testing**:

- **Data plane unit + integration**: Go `testing`, table-driven. Integration tests in `tests/integration/` exercise port 8881 against the live Tor sidecar via docker-compose.
- **Control plane**: JUnit 5 via Quarkus Test framework; gRPC server tested against an in-process client.
- **Contract tests**: at `tests/contract/tor/` (Tor SOCKS surface), `tests/contract/error-template/` (privacy-safe template invariants), and `tests/contract/torrc/` (rendered config invariants). Harness language: **Go** (research.md §5) so the suite runs in the same toolchain as the data plane and can spin sidecars via the docker SDK.
- **Reproducibility**: `tests/reproducibility/` builds the Go binary twice in clean containers and `cmp`s the output (arch §12.1).
- **Browser-level**: Mullvad Browser integration tests are run manually for the SC-001 walkthrough in this feature; automation is deferred (no headless privacy-safe Mullvad Browser harness exists in v1).

**Target Platform**: Linux x86_64 (the local Compose profile). Mullvad Browser on Linux desktop for the user-facing walkthrough. `arm64` data-plane builds are produced by CI for distribution but not exercised by this feature's integration harness.

**Project Type**: Multi-language monorepo — three language planes (Go data plane, Quarkus control plane, JS extension) + Docker-orchestrated sidecars + cross-cutting contract tests. Layout is defined in architecture spec §3; this feature populates a vertical slice through that layout.

**Performance Goals**:

- ≥200 concurrent `.onion` CONNECTs in the integration harness (SC-005). Measured against a *synthetic* SOCKS5 backend that mimics the Tor sidecar's accept-and-relay surface (research.md §7) — driving 200 concurrent live circuits through the real Tor network would flood guards and is not the property under test.
- Data-plane forwarding path: no per-request allocation that retains beyond request lifetime (SC-005, `stargate-perf` agent verifies on completion).
- Cold-start of the data plane: ≤2 s to first port-accept (operational target; not a hard FR but tracked).

**Constraints**:

- Loopback-only bind for all listeners in the local profile (FR-010 + arch §4 bind table); `BIND_REFUSED` startup error if violated.
- SOCKS5h enforced both inbound (extension sets `proxyDNS: true`) and outbound (data plane never resolves hostnames locally) — FR-003, FR-007.
- No per-request metadata logging at finer than 1-hour resolution (FR-008).
- Privacy-safe error template — exactly four response headers, byte-for-byte body match modulo permitted substitutions (FR-009 + arch §10).
- All sidecar images digest-pinned in `compose/docker-compose.local.yml` (FR-015, Principle IV); contract tests block merge on a digest bump that breaks the Tor surface (FR-016).
- No outbound network from Stargate components except routed requests (Principle III); the control plane's gRPC server is UDS-only, the data plane's listener is loopback-only, and there are no telemetry/update-check channels.

**Scale/Scope**:

- Single device, single user, single bearer token (the manual-config flow). Multi-device enrollment is a later feature.
- One sidecar (Tor) in this slice; I2P, Nym, Direct sidecars are out of scope.
- The token list is expected to contain 1 entry in the common case; the data plane's auth path is designed for O(N) constant-time comparison up to ~64 tokens without performance concern.

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-evaluated after Phase 1 design.*

| # | Principle / Invariant                                      | Status | Mechanism that satisfies it in this feature                                                                                                                                                                                                                                                                                                                                                                                                                  |
|---|------------------------------------------------------------|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| I | Dumb Router (NON-NEGOTIABLE)                               | **PASS** | Data plane parses only SOCKS5 framing (RFC 1928 + 1929) and the HTTP `CONNECT host:port` request line on port 8881. Port 8881 → Tor sidecar binding is fixed at data-plane startup (FR-005). No TLS termination, no payload parsing past SOCKS5 negotiation, no header rewriting, no local DNS, no per-request logs. Cover/decoy traffic is forbidden and not generated. Verified by `tests/contract/error-template/` leak-corpus pass.                       |
| II | Plane Separation                                           | **PASS** | Control plane runs as a separate container; inter-plane is gRPC over Unix-domain socket `/run/stargate/control.sock` (arch §5.4). Data plane survives control-plane restart by serving from its `dp-snapshot.json` and last-known in-memory token list (FR-013, arch §5.5). The token-loader flow goes through `ReloadTokens` — control plane never sits in the request path. Versioned `stargate.v1` package; rejects higher major peers.                    |
| III | Privacy-Preserving by Construction                         | **PASS** | (a) SOCKS5h enforced inbound and outbound (FR-003, FR-007). (b) Per-first-party stream isolation via SOCKS5 username + `IsolateSOCKSAuth` in rendered `torrc` (FR-002, FR-011). (c) Counters at hour resolution only (FR-008, arch §6.4). (d) No outbound network channels other than the routed request (Principle III bullet 6). (e) Hardening audit gates routing on DoH/WebRTC/QUIC state (FR-004). (f) `AUTH_REQUIRED` body strips token/destination.    |
| IV | Pinned, Tested, Manually Promoted Updates                  | **PASS** | Tor sidecar image is Stargate-built from a digest-pinned `debian:12-slim` base, installing `tor` from `deb.torproject.org` with the apt-key fingerprint pinned in the Dockerfile and verified at build time (FR-015). Both the base digest and the final composed image digest are pinned in `compose/docker-compose.local.yml`. `tests/contract/tor/` is the gate for digest bumps (FR-016). No background auto-update logic is introduced by this feature.    |
| V | Honest Threat Model                                        | **PASS** | Threat statements for the Tor onion route (THREAT-MODEL §4.2) and the Local profile (§3.1) are pre-existing and unmodified by this feature. The plan adds no new privacy claim beyond what the underlying Tor design supports. The `AUTH_REQUIRED` code introduces no new privacy property — it is an authentication gate, documented in arch §10.1.                                                                                                          |
| VI | Open and Auditable                                          | **PASS** | All artefacts land in the repo: rendered `torrc` is asserted byte-for-byte by `tests/contract/torrc/`; the extension ships as a deterministic zip with `SOURCE_DATE_EPOCH=0` (arch §12.3); the Go binary is built with `-trimpath -buildvcs=false` and is byte-reproducible per `tests/reproducibility/`. Apache 2.0 headers on new source files.                                                                                                              |
| VII | Tests-First for Privacy-Critical and Contract Code         | **PASS** | The privacy-critical FRs each have a "test MUST verify" clause in the spec: FR-002 stream isolation, FR-003 DNS leak absence, FR-006 auth, FR-008 logging restraint, FR-009 error template. The tasks plan (out of scope for `/speckit-plan`) will sequence these tests before their implementation tasks. Contract tests at `tests/contract/tor/`, `tests/contract/error-template/`, `tests/contract/torrc/` exist before the matching implementation lands. |
| VIII | Adversarial Review at Milestones                         | **PASS (deferred)** | `stargate-redteam` and `stargate-perf` are run at the end of `/speckit-implement` for this feature, before merge to `main`. Findings either resolve in-feature or move to `SECURITY-DECISIONS.md`. The agent definitions live under `.claude/agents/` (already scaffolded per the user's session context).                                                                                                                                                  |
| — | **Tech Stack — Bind-safety invariant**                      | **PASS** | `data-plane/internal/bind` performs the startup check before any listener is opened (FR-010). Local profile has no WireGuard sidecar; the only acceptable binds are on `127.0.0.1`. The check is a separate unit-tested function so the LAN/VPS-profile extensions reuse it.                                                                                                                                                                                  |
| — | **Inter-plane contract — versioning and auth**              | **PASS** | `proto/stargate/v1/control.proto` + `events.proto` declare the v1 package. Handshake exchanges a v1 marker (`stargate.v1` go_package); mismatched major-version peers are rejected and the data plane logs to journal and exits non-zero (arch §5.5 row 4). Mutual auth uses ed25519 keypairs generated by `stargate init`; this feature reuses that machinery — see Out-of-Scope note below.                                                                  |

**Constitution Check verdict**: **PASS**. No principle requires an
explicit waiver; the Complexity Tracking section below is therefore empty.
The single open question that *could* have produced a tension —
`specs/000-architecture/spec.md` §15 #6 (Mullvad Browser MV2 support window)
— is resolved by research.md §2 with the assumption holding for v1: Firefox
ESR and therefore Mullvad Browser still ship MV2 alongside MV3, and the
`proxy.onRequest` API used here has no MV3 equivalent that Mozilla intends
to deprecate. This is documented as a maintenance risk to track rather than
a v1 blocker.

**Out-of-scope reuses an upstream-not-yet-built dependency**: the gRPC mTLS
key-pair generation is normally done by `scripts/stargate init` (arch §9.1
step 3). This feature *uses* the keys but does not deliver the full `init`
flow — the manual-config flow assumes the operator runs `init` to generate
keys, then populates `tokens.yaml`. The `init` script's full behaviour
ships in a later feature; this slice delivers only the minimum subset
needed to bring the local stack up: key-pair generation + compose-up +
healthcheck wait. Surfaced in research.md §8 as a deliberate scope split.

---

## Project Structure

### Documentation (this feature)

```text
specs/001-tor-route/
├── plan.md              # This file
├── spec.md              # The feature specification (input)
├── research.md          # Phase 0 — open questions resolved
├── data-model.md        # Phase 1 — entities and state transitions
├── quickstart.md        # Phase 1 — operator walkthrough
├── contracts/           # Phase 1 — boundary contracts
│   ├── control-grpc.md      # gRPC RPCs used by this feature (subset of arch §5)
│   ├── socks5-auth.md       # Bearer-token auth via SOCKS5 username/password and Proxy-Authorization
│   ├── error-template.md    # Privacy-safe error template for ROUTE_*, AUTH_REQUIRED
│   └── torrc.md             # Rendered Tor config invariants
└── checklists/          # Pre-existing — clarification log lives in spec.md
```

### Source Code (repository root)

Repository layout is defined by architecture spec §3 and is shared across
all feature specs. This feature populates the following slice of that
layout. Files marked `(new)` are created by this feature's implementation;
files marked `(stub)` ship a placeholder that later features extend.

```text
stargate/
├── data-plane/
│   ├── go.mod                                                  (new)
│   ├── cmd/stargate-proxy/main.go                              (new)
│   ├── internal/
│   │   ├── bind/check.go             # bind-safety (FR-010)    (new)
│   │   ├── listener/socks5.go        # port 8881 listener      (new)
│   │   ├── listener/connect.go       # HTTP CONNECT framing    (new)
│   │   ├── auth/token.go             # constant-time auth      (new)
│   │   ├── forward/tor.go            # SOCKS5h to tor:9050     (new)
│   │   ├── controlclient/client.go   # gRPC client → CP        (new)
│   │   ├── controlclient/snapshot.go # dp-snapshot.json        (new)
│   │   ├── audit/counters.go         # hour-bucket aggregates  (new)
│   │   └── errortpl/render.go        # arch §10 template       (new)
│   └── (no other dirs in this feature)
│
├── control-plane/
│   ├── pom.xml                       # parent reactor          (new)
│   ├── api/
│   │   └── src/main/java/.../ControlGrpcService.java           (new)
│   ├── core/
│   │   ├── src/main/java/.../TokenLoader.java                  (new)
│   │   ├── src/main/java/.../SidecarMonitor.java               (new)
│   │   └── src/main/java/.../HealthEndpoint.java               (new)
│   ├── persistence/
│   │   ├── src/main/java/.../entity/AuditLog.java              (new)
│   │   └── src/main/resources/db/migration/V001__init.sql      (new — full schema arch §6 created up-front; only audit_log and enrolled_devices written by this feature)
│   ├── ui/                           # empty in v1 of this feature (stub)
│   └── runtime/
│       └── src/main/java/.../StargateControlPlane.java         (new)
│
├── extension/
│   ├── manifest.json                 # MV2                     (new)
│   ├── background/router.js          # proxy.onRequest         (new)
│   ├── background/hardening.js       # arch §14.5 audit        (new)
│   ├── options/options.html          # token paste UI          (new)
│   ├── options/options.js                                      (new)
│   ├── popup/popup.html              # per-tab indicator       (new)
│   ├── popup/popup.js                                          (new)
│   ├── lib/storage.js                                          (new)
│   ├── lib/firstparty.js             # eTLD+1 + documentUrl    (new)
│   └── package.sh                    # deterministic zip       (new)
│
├── proto/stargate/v1/
│   ├── control.proto                                           (new)
│   └── events.proto                                            (new)
│
├── sidecars/tor/
│   ├── Dockerfile                    # FR-015                  (new)
│   └── apt-key.fingerprint           # pinned                  (new)
│
├── compose/
│   ├── docker-compose.local.yml      # only profile this feature delivers (new)
│   └── env/local.env.example                                   (new)
│
├── scripts/
│   ├── stargate                      # entrypoint              (new)
│   └── subcommands/init              # minimal subset only     (new — full init in a later feature)
│
├── tests/
│   ├── contract/tor/                 # FR-016                  (new)
│   ├── contract/error-template/      # arch §10.3              (new)
│   ├── contract/torrc/               # FR-011 byte-match       (new)
│   ├── integration/onion_load_test.go        # US1             (new)
│   ├── integration/stream_isolation_test.go  # US2             (new)
│   ├── integration/error_template_test.go    # US3             (new)
│   └── reproducibility/data_plane_test.sh    # build×2 + cmp   (new)
│
├── ARCHITECTURE.md                   # human-facing pointer; this feature does not author it (out of scope)
├── BUILD-DIFFS.md                    # native-image only; not load-bearing here (out of scope)
└── CLAUDE.md                         # updated to reference this plan
```

**Structure Decision**: This feature follows the multi-language repo layout
fixed by architecture spec §3. No new top-level directories are introduced.
The data plane is a single Go module (`data-plane/go.mod`); the control
plane is a Maven multi-module reactor; the extension is a flat
zero-build-step directory; the proto definitions live at the repo top so
both planes import from one source. Tests are split: contract tests live
at the repo top under `tests/contract/<sidecar>/` per arch §3's rationale
(they outlive any single plane), integration tests under
`tests/integration/`, reproducibility under `tests/reproducibility/`.

---

## Phase 0 / Phase 1 outputs

- **Phase 0**: `research.md` — resolves 9 open questions the spec/architecture
  flagged or that surfaced while planning.
- **Phase 1**:
  - `data-model.md` — the entities the data plane and control plane hold
    in memory or on disk for this feature.
  - `contracts/control-grpc.md`, `contracts/socks5-auth.md`,
    `contracts/error-template.md`, `contracts/torrc.md` — the boundary
    contracts that feed Principle IV's contract-test gate and Principle
    VII's test-first discipline.
  - `quickstart.md` — the SC-001 5-minute operator walkthrough.

## Complexity Tracking

*No constitution violations; this section is intentionally empty.*

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|--------------------------------------|
| —         | —          | —                                    |

---

## Plan-level tensions surfaced for review

These are spots where the spec, the architecture, and the practical
implementation needed reconciliation. None block the plan; all are
resolved in research.md, called out here so the maintainer can review
the resolutions deliberately rather than accepting them implicitly.

1. **Manifest V2 assumption holds for v1** (arch §15 #6 / spec Assumption).
   research.md §2 records the rationale and the v1.5 review point.

2. **Control-plane scope in this slice**. The spec says "no Quarkus
   dashboard UI yet" but the control plane must run to load tokens and
   emit `SidecarEvent`s. The plan defines a *headless* control plane
   in this feature: `api/` (gRPC server only), `core/` (token loader,
   sidecar monitor), `persistence/` (`audit_log` writes), and `ui/`
   shipping only a Compose healthcheck endpoint. The full UI lands in
   a separate feature. research.md §3.

3. **`SC-005` (≥200 concurrent CONNECTs) is measured against a synthetic
   SOCKS5 backend**, not the live Tor network — driving 200 concurrent
   live circuits would abuse guards and is not the property being
   measured. The real Tor sidecar is used for US1 (page-load) and US2
   (circuit isolation, sequential corpus). research.md §7.

4. **Contract-test harness is in Go**. The architecture spec did not pin
   a language for `tests/contract/<sidecar>/`. Picking Go keeps the
   suite in the same toolchain as the data plane and reuses the Docker
   SDK for sidecar bring-up. research.md §5.

5. **Extension token storage is `storage.local` with a UX warning** (arch
   §14.4 / arch §15 #8). WebExtensions on Firefox ESR offers no
   credential-grade storage API to extensions; `storage.local` is the
   only path for non-form-fill secrets, so v1 uses it and documents the
   residual risk. research.md §6.

6. **`§11` hot-reload row vs FR-018 token-reload restart are not in
   conflict**. §11 describes the *inter-plane RPC* behaviour (token
   updates land in the data plane *Live* via `ReloadTokens` once
   pushed). FR-018 describes the *v1 manual flow's* upstream cadence
   (the control plane re-reads `tokens.yaml` only at process start). A
   control-plane restart is the upstream trigger; the data plane still
   applies the new generation Live via the existing RPC. research.md §4.

7. **`AUTH_REQUIRED` on SOCKS5 returns the sub-negotiation failure byte,
   not the HTML template**. The architecture spec §10.2 template is HTML
   and only applies to HTTP CONNECT framing. SOCKS5 RFC 1929 specifies a
   2-byte response (version + status); on rejection the data plane sends
   `0x01 0xFF` and closes. The contract test in
   `contracts/socks5-auth.md` enforces both behaviours. research.md §9.

8. **`scripts/stargate init` ships a minimum subset only**. Full `init`
   (arch §9) is a later feature; this slice delivers only key generation
   + compose-up + healthcheck wait (no admin enrollment URL, no
   admin-credential generation — there is no admin UI to enroll
   against). research.md §8.

9. **Quarkus 3.33 LTS / JDK 25 / Mandrel 25 compatibility** (arch §15 #9
   / constitution v1.1.0 Sync Impact Report deferred entry). The JVM
   build is exercised by this feature; the native-image build is not
   load-bearing for SC-1 through SC-5. The constitution amendment that
   pinned these versions remains the source of truth; the concrete
   Mandrel 25 builder image digest is pinned at first release tag, not
   in this feature. research.md §1.
