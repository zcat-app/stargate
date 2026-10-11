# Implementation Plan: Tor Route — v1 Vertical Slice

> T156: Current operational rows, isolation and recovery descriptions below are implementation
> history where superseded by `contracts/foundation-boundaries.md`; the Constitution Check records
> pending compliance. T156 introduces no runtime fix.

**Branch**: `001-tor-route` | **Date**: 2026-05-17 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification at `specs/001-tor-route/spec.md`

**Derives from**: `.specify/memory/constitution.md` v1.0.0 (with the pre-release T091 amendment to Principle III bullet 3) · `specs/000-architecture/spec.md` · `THREAT-MODEL.md` §3.1, §4.2.

---

## Summary

Stand up the first end-to-end Stargate route: Mullvad Browser → WebExtension →
data plane (port 8881, loopback) → Tor sidecar (private SOCKS Unix socket) →
Tor network → `.onion` destination. Per-first-party-domain stream isolation is
enforced via Tor's `IsolateSOCKSAuth` driven by the extension's SOCKS5 username.
The control plane runs headlessly in this slice — it loads bearer tokens from a
YAML file at startup, pushes hashed tokens to the data plane via gRPC
`ReloadTokens`, and emits `SidecarEvent`s — but exposes no admin UI beyond a
health endpoint that is not used for Docker health history. Tor-port failures use fixed SOCKS5 replies. HTTP CONNECT is refused at first byte
under the T172 contract implemented by T173. The architecture §10 HTML
error template remains a future-format renderer, not a Tor-port response.

The vertical proves: (1) the data plane forwards bytes correctly through a real
sidecar to a real anonymity network; (2) the extension's `proxy.onRequest` path
works end-to-end with SOCKS5h and stream isolation; (3) the contract-test gate
(Principle IV) blocks merges that break the Tor surface Stargate depends on;
(4) the Go data plane build produces a byte-reproducible artefact.

## Verification repair prerequisites — T202 deferred

The maintainer authorized the reviewed repair plan's defer/prerequisite route after guest15's
failed aggregate cadence. Pending serial tickets are [T210](tickets/T210-repair-tor-verification-transport-deadlines.md)
for ordinary Tor verification transport/diagnostics/real I/O bounds,
[T211](tickets/T211-repair-workflow-fixture-context-cleanup.md) for fixture tag boundaries and
owned child cleanup, then [T212](tickets/T212-close-docker-verification-budgets-history-ci.md)
for grounded aggregate budgets, authentic history and dependency-driven CI. T202 is deferred on
all three, with T212 the final scalar prerequisite; ordinary repairs remain outside T202's scope.
Their tracked evidence outputs and exact path inventories are declared in each ticket.

Constitution Check: I/II runtime routing and plane behavior remain unchanged. III retains
private Unix transport/isolation and disposable privileged capture boundaries; IV/VI retain
pins, authentic history and source-bound tool/evidence identity. V distinguishes historical
partial results, named ordinary CI DNS SKIPs and actual same-candidate disposable DNS acceptance.
VII requires atomic spec-derived RED/fix/GREEN, finite existing operation windows and all mandatory
controls. VIII preserves exact native independent implementation review; advisory Fable/Astra
plan consultation is separate. This filing does not establish runtime compliance or GREEN.

The linked prerequisite tickets define admission, independent source bootstrap, owned controls,
verification and evidence acceptance. T202's [Verification prerequisite deferral](tickets/T202-scoped-live-runner-fresh-vm-overlays.md#verification-prerequisite-deferral)
defines preservation and the reviewed reopen sequence. Historical guest15 aggregate remains FAILED.

## Technical Context

**Language/Version**:

- **Data plane**: Go (toolchain pinned via `go.mod` `go` + `toolchain` directives — concrete patch fixed during scaffold task; v1.26.x line per research.md §1).
- **Control plane**: JDK 25 LTS + Quarkus 3.40 LTS, promoted by T217 under the dependency-promotion process. This feature builds the *JVM-mode* artefact; native-image is not load-bearing for this slice (spec Assumption "Reproducibility holds for the Go data plane in this feature").
- **Extension**: WebExtensions MV2, vanilla JavaScript (ES2022), no build step (arch §12.3, Principle VI — avoid npm supply chain on a privacy-critical component). **Node 20 LTS** is pinned as a *CI-only* dependency for extension JS unit tests (`node:test` runner, see research.md §10); no Node deps ship to the user.
- **Sidecar**: Tor (from `deb.torproject.org`) on pinned `debian:12-slim` base, built by Stargate's Dockerfile at `sidecars/tor/`.

**Primary Dependencies**:

- **Data plane**: Go stdlib (`net`, `crypto/subtle`, `context`, `log/slog`); `golang.org/x/net/proxy` for SOCKS5 client outbound to the Tor sidecar; `google.golang.org/grpc` for the inter-plane client; protobuf v3 generated stubs from `proto/stargate/v1/`. No third-party HTTP server frameworks — the data plane uses the stdlib for SOCKS5 framing and CONNECT.
- **Control plane**: Quarkus core, Quarkus gRPC, Hibernate ORM with Panache, Quarkus JDBC SQLite, Flyway, `quarkus-vertx-http` (body-less GET `/healthz` with T204 pre-listen IPv4 loopback enforcement; Compose does not probe it), SnakeYAML for `tokens.yaml` parsing.
- **Extension**: WebExtensions APIs — `proxy`, `storage`, `webRequest`, `webRequestBlocking`, `privacy`, `notifications`. No third-party JS deps.
- **Test-only (Go, not shipped)**: `github.com/google/gopacket` for live-packet capture in `tests/integration/dns_leak_test.go` (T034) and `tests/integration/egress_consensus_test.go` (T034f) — requires `CAP_NET_RAW` or root on the test runner (CI configures this for the integration job). `github.com/docker/docker/client` (Docker SDK for Go) for every `tests/contract/` Docker bring-up harness (research.md §5). Both are CI-only and never linked into the data-plane binary. Pinned via `go.mod` at scaffold time (T002 / T002a) and updated only through the regular dependency-update workflow (Principle IV — pinned, tested, manually promoted).

**Storage**:

- **Named-volume manifest**: the canonical mapping of compose-named volumes to their contents lives in `data-model.md` §6. The bullets below summarise the storage of each *data type* this feature persists and cross-reference the volume that holds it; if the two diverge, `data-model.md` §6 is authoritative.
- **Control plane**: SQLite (WAL) at `/var/lib/stargate/control.db` mounted from named volume `stargate-control-state`. The operator-authored `tokens.yaml` is mounted at `/etc/stargate/tokens.yaml` from `stargate-control-config` (FR-017). The safe `torrc` is **baked into the Tor image at build time** (T087, per T089's amendment to FR-011) — the CP does NOT render `torrc` at boot in this slice (Constitution Principle II / sol-review B2), so the `stargate-tor-config` volume's CP-rendered-`torrc` role is deferred to the dynamic-config feature (T037 `TorrcRenderer` is deferred with it). The pre-T156 implementation populates `audit_log` with one row per `enrolled` / `revoked` / `config_error` / `sidecar_healthy` / `sidecar_unhealthy` action (the five fixed-vocabulary actions enumerated in data-model.md §4) and reads/writes `enrolled_devices` indirectly via the YAML loader: `enrolled_devices` is **not** the source of truth for the live token list (that role belongs to `tokens.yaml` + the in-memory generation in the data plane) — the table is diffed across loads to derive the `enrolled` vs `revoked` audit-log rows in T035.
- **Data plane**: in-memory `tokenList` plus on-disk fallback at `/var/lib/stargate/dp-snapshot.json` mounted from named volume `stargate-dp-state` (arch §5.5) — last-known token hash list (the snapshot carries token hashes only — no route-admission state is persisted; cold-start attempts the fixed upstream on every admitted request and admission is never event-gated per Principle II; data-model.md §1.4 / §2; sol-review B3), restored at cold start when the control plane is unreachable.
- **Inter-plane runtime state**: `stargate-keys` holds the ed25519 mutual-auth keypairs generated by `scripts/stargate init` (T016) — `cp.priv` mode 0600 owned `stargate-cp`, `dp.priv` mode 0600 owned `stargate-dp`, `cp.pub` and `dp.pub` mode 0644 (public material, both planes read both pubs for the handshake). `stargate-ipc` holds the two UDS sockets `/run/stargate/control.sock` (CP-hosted) and `/run/stargate/dp.sock` (DP-hosted), each mode 0660 with the shared supplementary group `stargate-ipc` (GID 5100) as group owner per `contracts/control-grpc.md` §"Socket topology".
- **Extension**: `storage.local` per arch §14.4. Bearer token stored in `storage.local` with a visible warning in the options UI (canonical warning text in data-model.md §5.1; resolves arch §15 #8 for v1 — see research.md §6).
- **Tor sidecar**: `/var/lib/tor/` mounted from named volume `stargate-tor-state` (entry-guard state persists across container restarts — THREAT-MODEL §4.2 "Stargate-specific notes"). The safe `torrc` is baked into the Tor image at `/etc/tor/torrc` at build time (T087, per T089's amendment to FR-011); Tor loads it via the entrypoint at container start with no dependency on the control plane or the `stargate-tor-config` volume (which is deferred to the dynamic-config feature).

**Testing**:

- **Data plane unit + integration**: Go `testing`, table-driven. Integration tests in `tests/integration/` exercise port 8881 against the live Tor sidecar via docker-compose.
- **Control plane**: JUnit 5 via Quarkus Test framework; gRPC server tested against an in-process client.
- **Contract tests**: five directories under `tests/contract/` — `tor/` (Tor SOCKS surface), `torrc/` (rendered config invariants), `socks5/` (RFC 1928/1929 surface on port 8881), `error-template/` (future renderer format only), and `control-grpc/` (inter-plane RPC + event-kind invariants). Authoritative list is FR-016 + the project-structure tree below. Harness language: **Go** (research.md §5) so the suite runs in the same toolchain as the data plane and can spin sidecars via the docker SDK.
- **Reproducibility**: `tests/reproducibility/` builds the Go binary twice in clean containers and `cmp`s the output (arch §12.1).
- **Extension JS units**: Node 20 LTS + built-in `node:test` runner; MV2 background scripts are loaded into the test via `vm.runInNewContext()` with a synthesized `browser` global, so production code stays in idiomatic browser-script style (no UMD wrapper, no test-only export branch). Used in this feature for the FR-004 hardening-audit test (research.md §10).
- **Browser-level**: Mullvad Browser integration tests are run manually for the SC-001 walkthrough in this feature; automation is deferred (no headless privacy-safe Mullvad Browser harness exists in v1).

**Target Platform**: Linux x86_64 (the local Compose profile), with AppArmor, Landlock
ABI >= 4 (upstream Linux 6.7+) and seccomp thread synchronization. The DP is built
with `CGO_ENABLED=0`; confinement failure refuses serving. Mullvad Browser on Linux
desktop is the user-facing walkthrough. `arm64` data-plane builds use native kernel
constants but cross-compilation alone is not runtime verification; they are not
exercised by this feature's integration harness. T168's mechanism and supported
restart behavior are normative in `contracts/foundation-boundaries.md`.

**Project Type**: Multi-language monorepo — three language planes (Go data plane, Quarkus control plane, JS extension) + Docker-orchestrated sidecars + cross-cutting contract tests. Layout is defined in architecture spec §3; this feature populates a vertical slice through that layout.

**Performance Goals**:

**Reference workstation (measurement baseline for SC-001, SC-003, SC-005,
plan.md §"Scale/Scope", data-model.md §1.5)**: Linux x86_64 desktop;
≥8 physical cores at ≥3 GHz (Zen 3 / Alder Lake or newer); ≥16 GiB RAM;
NVMe SSD; not under thermal throttling at measurement time. The hand-driven
T077 walkthrough and the T034a Wireshark capture record the concrete CPU
model used at the time the artefact is produced in their respective
markdown outputs, so a reader can verify the number against the hardware it
was measured on. **(T092 amendment)** the verifier is now
`HMAC-SHA-256(pepper, candidate)` — a single ~sub-microsecond HMAC per
request (data-model.md §1.5), not the retired ~50 ms Argon2id hash. The
former Argon2id-derived cost model (linear in N, capped at N ≤ 4, 64 MiB
allocation per hash) is RETIRED: HMAC auth is O(1) hash work per request
regardless of N and O(1) per-request allocation, so the N ≤ 4 cap and the
Argon2id-derived fill-time math below no longer bound the design. The
*invariants* (no DNS leak, no leak-corpus matches,
renderer-only byte-for-byte template render, stream isolation, no retained allocations,
and now: bounded per-request memory under unauthenticated flood —
sol-review B5) hold regardless of wall-clock numbers.

- ≥200 concurrent `.onion` CONNECTs in the integration harness (SC-005). Measured against a *synthetic* SOCKS5 backend that mimics the Tor sidecar's accept-and-relay surface (research.md §7) — driving 200 concurrent live circuits through the real Tor network would flood guards and is not the property under test.

  **Measurement model for SC-005 (T092 amendment)**: "200 concurrent CONNECTs" means 200 client connections established and held open simultaneously through port 8881, each having completed its authenticated SOCKS5 CONNECT handshake (one HMAC-SHA-256 verifier computation + constant-time compare against the current generation) and bridged to the synthetic upstream. Under HMAC auth the per-request CPU cost is a single sub-microsecond HMAC plus a constant-time compare loop over N verifiers; it is no longer the Argon2id bottleneck that previously dominated fill time. The 200-connection pool therefore fills in wall-clock dominated by the synthetic upstream's accept rate and goroutine scheduling, not by auth work. SC-005 is met if the pool fills within 30s and the connections remain stable for ≥60s of bidirectional traffic. The load-bearing property T092 adds (sol-review B5): **peak RSS stays inside a documented memory ceiling under a 200-connection unauthenticated flood**, because auth no longer allocates 64 MiB per attempt — this is the falsifier for the B5 finding and is asserted by T079a's extended design (peak-RSS + unauthenticated-flood bounds), not by pool-fill timing alone. T079's `stargate-perf` run uses this measurement model; the steady-state and the fill-time are reported as separate numbers in its findings document, not collapsed into a single throughput figure.

  **Burst CONNECT scenario (not in SC-005 but tracked here)**: a realistic worst-case user burst is Mullvad Browser session-restore or "open all bookmarks in tabs" — 30 to 100 parallel CONNECTs in a few seconds. Under HMAC auth (T092) per-request auth cost is negligible at any realistic N, so burst latency is dominated by upstream accept + goroutine scheduling, not by the retired Argon2id fill-time math. The prior "N ≤ 4 ceiling" and "shared-salt migration" are retired — auth is already O(1) in N. The migration trigger that remains is the §1.5 residue (pepper-compromise + snapshot-leak → offline candidate testing at HMAC speed, mitigated by 128-bit entropy — see THREAT-MODEL §5.14 / SECURITY-DECISIONS.md), which is a residue, not a perf cap.
- Data-plane forwarding path: no per-request allocation that retains beyond request lifetime (SC-005, `stargate-perf` agent verifies on completion).
- Cold-start of the data plane: ≤2 s to first port-accept (operational target; not a hard FR but tracked).

**Constraints**:

- Loopback-only bind for all listeners in the local profile (FR-010 + arch §4 bind table); `BIND_REFUSED` startup error if violated.
- SOCKS5h enforced both inbound (extension sets `proxyDNS: true`) and outbound (data plane never resolves hostnames locally) — FR-003, FR-007.
- No per-request metadata logging at finer than 1-hour resolution (FR-008).
- Fixed SOCKS5 auth and route-failure replies with zero upstream/destination text;
  the four-header HTML template is renderer-only future-format coverage (FR-009).
- Reviewed base/build inputs remain pinned in source local Compose/Dockerfiles. T081 generates separate release Compose with four final registry digests and a signed manifest bound to the exact reviewed source; it never writes final digests back into source or moves tags (FR-015, Principles IV/VI). Contract tests gate changed Tor inputs (FR-016).
- Enforce Constitution III's actor matrix: DP has only the fixed pathname Unix
  adapter and authenticated Unix IPC; CP has narrow local management and no
  independent IP egress. T168 confines DP origins in the kernel before serving;
  source-level dial review alone is insufficient against process compromise.
  Tor's native maintenance is a separate sidecar permission. No telemetry or
  background update checks. Explicit test-time fetches for release evidence
  (such as T034f's Tor consensus fixture) run in the test runner's namespace,
  outside the deployed proxy services.

**Scale/Scope**:

- Single device, single user, single bearer token (the manual-config flow). Multi-device enrollment is a later feature.
- One sidecar (Tor) in this slice; I2P, Nym, Direct sidecars are out of scope.
- The token list is expected to contain 1 entry in the common case (the manual-config flow is single-device by design). **(T092 amendment)** auth cost is O(1) hash work per request regardless of N: the candidate's HMAC-SHA-256 tag is computed once and compared with `crypto/subtle.ConstantTimeCompare` against every verifier in the current generation (no short-circuit on first match — that would leak which slot matched; the comparison loop stays constant-time across the full list). The former "linear in N / N ≤ 4 cap / 64 MiB per hash" Argon2id design is RETIRED (sol-review B5; data-model.md §1.5). There is no N-based perf cap in v1; the multi-device-enrollment feature can grow N without redesign. The retained residue is pepper/secrecy management (THREAT-MODEL §5.14), not verifier cost.

---

## Constitution Check — T156 target; implementation not yet compliant

The constitution amended on 2026-09-12 and `contracts/foundation-boundaries.md` govern this plan.

| Principle | State and required closure |
|---|---|
| I — dumb router | Negotiation/management scope clarified; T147 selected HTTP `C` refusal on Tor port 8881, T172 reconciles the contract, and T173 records implementation and the scope of measured evidence. |
| II — separation | CP authority, recovery/rollback and peer lifecycle incomplete: T138/T132/T135/T148/T159. |
| III — privacy | Isolation, browser blocking, aggregate-only diagnostics and completed-hour publication: T136/T147/T152/T157/T158. |
| IV — immutable updates | T160 delivers Tor package/content and dependency-source enforcement; T081 prepares immutable artifacts from reviewed source and a separate protected promotion gate. Actual input/signature/protection/live release evidence remains required; source fixtures alone do not close it. |
| V — honest threat model | Known gaps recorded; T155 and final live evidence must establish actual compliance. |
| VI — reproducibility | Obligations remain pending T075/T109/T081; no empty comparison is PASS. |
| VII — tests-first | Required-coverage/evidence repairs T139/T144; implementations preserve real failing-before-fix evidence. |
| VIII — independent reviews | Amendment review in T156; foundation T155 and final T078/T079 remain required. |
| Deployment | T162 enforces loopback and Unix fabrics; T168 adds irreversible all-thread IP confinement before serving. Owner rules remain installer-required defense in depth. T170 preserves enforcing-profile signal/lifecycle behavior. T163 records cumulative evidence from actual deployment namespaces on an independently booted Linux host, under the foundation contract's capture, family, failure/recovery and restart requirements. The maintainer approved VM evidence on 2026-09-21; the measured guest result makes no physical-NIC, hypervisor or untested-environment claim. |

**T124 scoped Constitution Check (Local Tor init).** Principle II keeps CP health
advisory for DP routing. Principle III keeps Docker health history and raw diagnostics
disabled; the installer observes only the isolated observer's finite READY result.
Principle V requires a bounded cold-start claim and actual fresh-volume evidence;
300 seconds is an operator wait, not a Tor availability guarantee. Principle VII
requires the delayed-READY red/green regression before changing the installer,
plus retrospective negative credential guards. Principle VIII requires the exact
candidate and live-evidence limits in the independent ticket review. This check
does not convert the plan's other pending foundation obligations into PASS.

**Verdict: IMPLEMENTATION BLOCKED ON REMEDIATION**, not PASS (deferred). This plan specifies
work to reach compliance; it does not waive current defects. Use `remaining-implementation-plan.md`
and executable ticket dependencies for implementation order. The current JVM slice does not
claim the future native-image or other v1 route features complete.

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
│   ├── socks5-auth.md       # SOCKS5 bearer auth; HTTP C refusal
│   ├── error-template.md    # Future HTTP renderer format only
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
│   ├── Dockerfile                       # T002a                (new)
│   ├── cmd/stargate-proxy/main.go                              (new)
│   ├── internal/
│   │   ├── bind/check.go             # bind-safety (FR-010)    (new)
│   │   ├── listener/socks5.go        # SOCKS; HTTP C refused (T173)
│   │   ├── auth/token.go             # constant-time auth      (new)
│   │   ├── forward/tor.go            # SOCKS5h to tor:9050     (new)
│   │   ├── controlclient/client.go   # gRPC client → CP        (new)
│   │   ├── controlclient/server.go   # DP-hosted gRPC server (ReloadTokens, GetStatus) on /run/stargate/dp.sock (new)
│   │   ├── controlclient/snapshot.go # dp-snapshot.json        (new)
│   │   ├── audit/counters.go         # hour-bucket aggregates  (new)
│   │   └── errortpl/render.go        # future HTTP renderer    (new)
│   └── (no other dirs in this feature)
│
├── control-plane/
│   ├── pom.xml                       # parent reactor          (new)
│   ├── Dockerfile                    # T003a                   (new)
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
│   ├── contract/sidecar-proxy/      # C1 remediation; T019c   (new)
│   ├── contract/error-template/      # future renderer only    (new)
│   ├── contract/torrc/               # FR-011 byte-match       (new)
│   ├── contract/socks5/              # SOCKS5 + HTTP refusal   (new)
│   ├── contract/control-grpc/        # inter-plane RPC surface (new)
│   ├── integration/onion_load_test.go        # US1             (new)
│   ├── integration/stream_isolation_test.go  # US2             (new)
│   ├── integration/route_failure_test.go     # US3 SOCKS       (new)
│   └── reproducibility/data_plane_test.sh    # build×2 + cmp   (new)
│
├── ARCHITECTURE.md                   # human-facing pointer; this feature does not author it (out of scope)
├── BUILD-DIFFS.md                    # native-image only; not load-bearing here (out of scope)
└── CLAUDE.md                         # updated to reference this plan
```

**Tree convention**: the tree above enumerates the top-level directories
the v1 footprint touches and the files this feature creates at each
level. Per-test helpers and fixtures under `tests/` — for example
`tests/internal/loginvariants/` (shared log allowlist consumed by T025a,
T025b, T070a), `tests/contract/tor/control_port.go` (cookie-authenticated
Tor control-port helper consumed by T058 and T070a, authored under T062),
`tests/integration/fake_socks5_tor.go` (synthetic SOCKS5 backend authored
by T019a), and `tests/integration/synthetic_onion_corpus.txt` (T063) —
are introduced by the task that owns them and are not all re-listed in
the tree.

### Compose topology (this feature)

The supported Local stack has four services. The DP shares the host namespace
but binds its listener to loopback and reaches Tor only through a private Unix
socket. CP and the observer have no IP network; Tor alone has bridge egress.

| Service | Current Local role |
|---|---|
| `stargate-dp` | Listens on `127.0.0.1:8881`, uses its DP-only Tor SOCKS fabric, and retains authenticated admission during CP outage. |
| `stargate-control` | Loads current auth state and receives only authenticated finite observer health over its CP-only Unix fabric. It holds no Tor cookie or raw control path. |
| `tor` | Loads the image-baked `torrc`, serves private SOCKS/control Unix sockets, and performs Tor-native bootstrap. |
| `tor-observer` | Reads only the latest bounded tmpfs health record, verifies its original boot-time lease, and serves authenticated finite health; no raw Tor mount. |
| Tor-internal publisher | Part of Tor's image/route TCB; autonomously performs a fixed bounded bootstrap query and publishes finite state, with no observer/CP input channel. |

Docker healthchecks and raw container diagnostics are disabled under
Constitution III (T152). The installer waits for the observer's current
authenticated READY sample within one post-Compose window, default 300 seconds
(T124); CP health remains advisory to DP routing (T164/T165). The former
`docker-socket-proxy` was removed by T094a; T162 supplies the distinct fabrics.

**Structure Decision**: This feature follows the multi-language repo layout
fixed by architecture spec §3. No new top-level directories are introduced.
The data plane is a single Go module (`data-plane/go.mod`); the control
plane is a Maven multi-module reactor; the extension is a flat
zero-build-step directory; the proto definitions live at the repo top so
both planes import from one source. Tests are split: contract tests live
at the repo top under `tests/contract/<sidecar>/` per arch §3's rationale
(they outlive any single plane), integration tests under
`tests/integration/`, reproducibility under `tests/reproducibility/`.

**Naming convention — data plane**: the Go binary is `cmd/stargate-proxy/main.go`,
but the compose service, the runtime UID, and the state volume all use the
shorter form `stargate-dp` / `stargate-dp-state` (T015). The user-facing
artefact name kept the `-proxy` suffix because that is what the user invokes
(`./scripts/stargate ...` shells into the proxy); the compose-side artefacts
took the `-dp` abbreviation because it is what shows up in `docker ps` output
and journal lines, where "data plane" is referenced often. The split is
intentional and is recorded here so future readers don't treat it as drift.

---

## Phase 0 / Phase 1 outputs

- **Phase 0**: `research.md` — resolves 11 open questions the spec/architecture
  flagged or that surfaced while planning (§10 was added by a later
  `/speckit-analyze` C1 remediation for the JS test toolchain pin; §11
  was added by the `/speckit-analyze` F3 remediation for the minimum-
  subset `GetStatus` RPC declaration in v1's proto).
- **Phase 1**:
  - `data-model.md` — the entities the data plane and control plane hold
    in memory or on disk for this feature.
  - `contracts/control-grpc.md`, `contracts/socks5-auth.md`,
    `contracts/error-template.md`, `contracts/torrc.md` — the boundary
    contracts that feed Principle IV's contract-test gate and Principle
    VII's test-first discipline.
  - `quickstart.md` — the SC-001 5-minute operator walkthrough.

## T172 Constitution Check — selected Tor ingress

Principles I/III require bounded SOCKS negotiation and an intact device/profile/site
partition. HTTP `C` cannot carry trusted context in the existing client and must close
before auth, counters or upstream dial; no application-header inference, error body,
route conversion or Direct fallback is allowed. Principle II keeps authenticated SOCKS
forwarding alive across CP outage and ignores advisory sidecar events for admission.
Principle V: T173 removes the conflicting HTTP path and records verification limits;
T172 remains historical planning evidence. Principle VII: T173 preserves the named
real-socket regression and its pre-fix failure before production edits; documentation
uses consistency evidence. Principle VIII: T172 and T173 each need independent
candidate-bound review. No Constitution amendment or risk acceptance is made.

---

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
   shipping a health endpoint with effective `127.0.0.1` option enforcement
   before listening (T204). HTTPS, HTTP domain sockets and the separate management
   interface are unsupported. Compose does not probe the endpoint. The full UI lands in
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

7. **`AUTH_REQUIRED` on Tor port 8881 uses only SOCKS5 failure bytes.**
   Authenticated SOCKS5 is the sole supported ingress; RFC 1929 rejection
   sends `0x01 0xFF` and closes. HTTP `C` closes before authentication with
   zero response bytes. The HTML template is renderer-only future-format
   coverage. This T172 decision supersedes historical research.md §9; T173
   makes the runtime conform.

8. **`scripts/stargate init` ships a minimum subset only**. Full `init`
   (arch §9) is a later feature; this slice delivers only key generation
   + compose-up + authenticated observer readiness wait (no admin enrollment URL, no
   admin-credential generation — there is no admin UI to enroll
   against). research.md §8.

9. **Quarkus 3.40 LTS / JDK 25 / Mandrel 25 compatibility** (arch §15 #9
   / constitution pre-release JDK-pin note). The JVM
   build is exercised by this feature; the native-image build is not
   load-bearing for SC-1 through SC-5. The constitution amendment that
   pinned these versions remains the source of truth; the concrete
   Mandrel 25 builder image digest is pinned at first release tag, not
   in this feature. research.md §1.

10. **Minimum-subset `GetStatus` RPC ships in v1 proto, called by tests
    only**. The production CP→DP `GetStatus` pull and SQLite
    persistence are deferred to the admin-UI feature (spec FR-008,
    `data-model.md` §3, `contracts/control-grpc.md` "RPCs explicitly
    NOT used"). The RPC *declaration* — `StatusRequest{} →
    StatusResponse{repeated RouteCounter counters}` with
    `RouteCounter{string route; uint64 hour_bucket; uint64
    request_count; uint64 byte_count;}` — still ships in
    `proto/stargate/v1/control.proto` (T007) and is hosted by the DP
    (T045) so the contract tests T025c (auth-fail counter
    non-increment) and T025d (auth-pass counter increment) can probe
    counter invariants via the public gRPC surface rather than a
    test-only sideline. The trade-off: a small additive surface
    increment in `stargate.v1` proto now, in exchange for not bumping
    `stargate.v2` when the admin-UI feature wires the production
    caller. research.md §11.
