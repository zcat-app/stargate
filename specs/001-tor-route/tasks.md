# Tasks: Tor Route — v1 Vertical Slice

**Input**: Design documents from `/specs/001-tor-route/`

**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Test discipline is governed by Constitution Principle VII. This
feature touches every privacy-critical code category named by the principle —
DNS resolution (FR-003, FR-007), routing decisions (FR-005), header handling
(FR-009), authentication (FR-006), and sidecar contracts (FR-011, FR-013,
FR-014) — so **tests are MANDATORY and MUST be written test-first** for every
implementation task in Phases 3–5. Public API surfaces (the `stargate.v1` gRPC
RPCs, the SOCKS5/CONNECT surface, the rendered `torrc`) require contract
test-first per Principle IV's contract-test gate.

**Organization**: Tasks are grouped by user story to enable independent
implementation and testing of each story. User stories are pulled from
spec.md §"User Scenarios & Testing"; priorities, independent-test criteria,
and acceptance scenarios there are authoritative.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies on incomplete tasks)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Each task names an exact file path; file paths follow the layout in plan.md §"Project Structure"

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Repository scaffolding that every later phase depends on.

- [ ] T001 Create the top-level directory skeleton from plan.md §"Project Structure" — `data-plane/`, `control-plane/{api,core,persistence,ui,runtime}/`, `extension/{background,options,popup,lib}/`, `proto/stargate/v1/`, `sidecars/tor/`, `compose/{,env}/`, `scripts/{,subcommands}/`, `tests/{contract/{tor,sidecar-proxy,error-template,torrc,socks5,control-grpc},integration,reproducibility}/` — using `.keep` placeholders where the directory is otherwise empty for this feature.
- [ ] T002 Author `data-plane/go.mod` with `go 1.23` and `toolchain go1.23.x` (latest 1.23.x patch at scaffold time per research.md §1); add `golang.org/x/net/proxy`, `google.golang.org/grpc`, `google.golang.org/protobuf` as direct dependencies; commit `data-plane/go.sum`.
- [ ] T003 Author the Maven multi-module reactor — `control-plane/pom.xml` (parent, packaging `pom`, modules `api core persistence ui runtime`, `<maven.compiler.release>25</maven.compiler.release>`, Quarkus 3.33 LTS BOM import) plus stub `pom.xml` files for each module declaring `<parent>` and module-appropriate Quarkus extensions (Quarkus gRPC for `api`, Hibernate ORM + Panache + JDBC SQLite + Flyway for `persistence`, etc.).
- [ ] T004 [P] Author `data-plane/Makefile` (or equivalent) wiring the byte-reproducible build flags `-trimpath -buildvcs=false -ldflags="-buildid="` and `CGO_ENABLED=0`, per arch §12.1.
- [ ] T005 [P] Author `extension/package.sh` producing a deterministic zip with `SOURCE_DATE_EPOCH=0` and sorted entries per arch §12.3; produces `dist/stargate-extension.zip`.
- [ ] T006 [P] Author `licenses/APACHE-2.0-HEADER.txt` and a `scripts/check-license-headers.sh` invoked by CI to verify every new `.go`, `.java`, `.js`, `.proto`, `.sh`, `Dockerfile`, and `.sql` file under this feature's footprint carries the Apache 2.0 header (Principle VI / constitution Open and Auditable).

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Cross-plane contracts, shared constants, and infrastructure that every user story depends on.

**⚠️ CRITICAL**: No user-story work can begin until this phase is complete. The proto stubs, the error template literal, the bind-safety check, the Tor sidecar image, and the compose file are inputs to multiple user stories.

- [ ] T007 Author `proto/stargate/v1/control.proto` declaring `package stargate.v1`, `option go_package = ".../grpcpb"`, the `ReloadTokens` RPC, and the messages `ReloadTokensRequest`, `ReloadTokensResponse`, `TokenHash`, `ApplyStatus` — exactly per `contracts/control-grpc.md` §"ReloadTokens".
- [ ] T008 Author `proto/stargate/v1/events.proto` declaring the `WatchEvents` RPC and the messages `WatchEventsRequest`, `SidecarEvent`, `EventKind` — exactly per `contracts/control-grpc.md` §"WatchEvents".
- [ ] T009 [P] Generate Go proto stubs into `data-plane/internal/grpcpb/` via `protoc` + `protoc-gen-go` + `protoc-gen-go-grpc`; commit generated files; add a `data-plane/scripts/regen-proto.sh` to make the regeneration step deterministic and auditable.
- [ ] T010 [P] Wire Quarkus gRPC code generation in `control-plane/api/pom.xml` (`quarkus-grpc` already handles generation at build time from `proto/stargate/v1/*.proto`); add the `proto` source path to the build.
- [ ] T011 [P] Author shared Argon2id parameter constants — `data-plane/internal/auth/params.go` and `control-plane/core/src/main/java/.../auth/Argon2idParams.java` — with the exact values from data-model.md §1.5 (`time=3, memory=64MiB, parallelism=4, hashLen=32, saltLen=16`); both files reference data-model.md §1.5 in their header comment.
- [ ] T012 Author `control-plane/persistence/src/main/resources/db/migration/V001__init.sql` with the full schema from architecture spec §6 (so later features add data without schema churn); this feature writes only `audit_log` and `enrolled_devices` per data-model.md §4.
- [ ] T013 [P] Implement `data-plane/internal/bind/check.go` — the loopback-only bind-safety check (FR-010) that runs before any listener opens; returns `BIND_REFUSED` and exits non-zero on violation. Pure unit-tested function (no listener side effects).
- [ ] T014 [P] Author `sidecars/tor/Dockerfile` — pinned `debian:12-slim` base by sha256 digest, installs `tor` from `deb.torproject.org`, verifies the apt-repo signing key at build time against `sidecars/tor/apt-key.fingerprint` (per FR-015), drops privileges to a non-root `tor` user, declares `HEALTHCHECK` parsing for "Bootstrapped 100%" against `Log notice stdout` from the rendered config.
- [ ] T015 Author `compose/docker-compose.local.yml` and `compose/env/local.env.example` — **four services**: `stargate-dp`, `stargate-control`, `tor`, and `docker-socket-proxy` (a digest-pinned `tecnativa/docker-socket-proxy` instance that bridges `/var/run/docker.sock` to a filtered HTTP API; see SidecarMonitor at T039 and the trust rationale at T017a). Loopback-only port binding for 8881 on the data plane; no host port mapping for the Tor SocksPort or ControlPort; no host port mapping for the proxy. Named volumes per data-model.md §6. Per-plane runtime users created in each Stargate-owned image's Dockerfile and pinned via the compose `user:` directive — `stargate-cp` (UID/GID 5101) for `stargate-control`, `stargate-dp` (UID/GID 5102) for `stargate-dp`; the Tor container drops to its own `tor` user per T014; `docker-socket-proxy` runs as the unprivileged user its upstream image declares. The two Stargate UIDs are distinct so the UDS files in `stargate-ipc` (per `contracts/control-grpc.md` §"Socket topology": `control.sock` owned by `stargate-cp`, `dp.sock` owned by `stargate-dp`) actually enforce role separation via the 0600 mode — same UID would collapse C2's invariant. The UIDs MUST match across the CP and DP Dockerfiles because Docker named-volume ownership is set by the first writer, so `stargate-ipc` is shared on the same uid:gid namespace. `docker-socket-proxy` is the ONLY service that mounts `/var/run/docker.sock` (read-only) from the host; the CP reaches it as `http://docker-socket-proxy:2375` over the compose-internal network. Proxy environment locked to the minimum surface SidecarMonitor needs: `EVENTS=1`, `CONTAINERS=1`, all other endpoint flags unset so they default to deny, and `POST=0` to forbid container spawn/kill/exec (verified by T019c). sha256-pinned image digests for the Debian-slim base, the final Tor sidecar image (FR-015), and the docker-socket-proxy image (Principle IV — every external component is digest-pinned). The Tor sidecar's compose service key is `tor` so its in-network DNS name matches FR-007 / T047's `tor:9050` dial target. **Verified by T019b (Tor port exposure) and T019c (proxy lockdown).**
- [ ] T016 Author `scripts/stargate` entrypoint and `scripts/subcommands/init` delivering the minimum subset per research.md §8: preflight, ed25519 key generation into `stargate-keys` volume with mode 0600, hard-coded `compose/docker-compose.local.yml`, bounded healthcheck wait, Tor-only verification, status table, stable exit codes (10/20/30/40/50).
- [ ] T017 Author `SECURITY-DECISIONS.md` (new file at repo root) with the Tor sidecar trust rationale (FR-015): why `deb.torproject.org` over a fork; the apt-key fingerprint and rotation policy; the Debian-slim and final-image digest values; and a section reserved for adversarial-review findings from Phase N. (The docker-socket-proxy trust rationale is a separate concern from C1 remediation and lives in T017a, which appends to the same file.)
- [ ] T017a Append to `SECURITY-DECISIONS.md` (created by T017) the **`docker-socket-proxy` aux container** trust rationale (T015 / T039): why a privilege-isolating proxy instead of mounting `/var/run/docker.sock` directly into the CP. State the property the proxy buys: a compromise of the Quarkus control plane (YAML parser, gRPC server, future admin UI) does NOT escalate to host root, because the CP holds no docker.sock handle and can only invoke the `EVENTS=1 CONTAINERS=1` GET-only surface the proxy exposes. State the residual trust honestly: the proxy itself IS in the TCB; a compromise of the proxy is host-root-equivalent. Mitigations recorded: digest-pinned image (Principle IV); `POST=0` lockdown gated by T019c contract test; proxy runs as the unprivileged user its upstream image declares; proxy is not reachable from outside the compose-internal network. Cross-reference THREAT-MODEL.md §3.1 (local profile assumes local code execution is already game-over) so the residual-risk framing is consistent. **Release-blocker on any future LAN or VPS profile feature spec**: that profile exposes the CP to non-localhost callers and changes the compromise-probability calculus; this entry MUST be revisited (and likely the proxy mechanism replaced) before the LAN/VPS spec ships.
- [ ] T018 Amend `specs/000-architecture/spec.md` in lock-step: §7 Tor row updates to drop the `NEEDS CLARIFICATION` and reference FR-015's image-provenance pin; §10.1 adds `AUTH_REQUIRED` to the error-code enum with status 407 and the SOCKS5 binary-failure mapping per research.md §9.
- [ ] T019 Author the privacy-safe error template **literal** in `data-plane/internal/errortpl/template.go` — the exact byte sequence from `contracts/error-template.md` §"Response body" stored as a single Go string constant; LF line endings; placeholder tokens `{ROUTE_LABEL}`, `{CODE}`, `{LOCAL_REFERENCE_ID}` only. The renderer that substitutes the placeholders lives in T048 / T071.
- [ ] T019a [P] Author `tests/integration/fake_socks5_tor.go` — synthetic SOCKS5 backend that mimics the Tor sidecar's accept-and-relay surface (research.md §7). Configurable modes: `accept-and-relay` (default — used by SC-005 load runs via T079), `slow` (used by T067 to trigger `ROUTE_TIMEOUT`), `hung` (reserved for negative leak-corpus tests). Pure Go, no docker-compose dependency. Apache 2.0 header.
- [ ] T019b [P] Contract test for FR-012's Tor port-exposure invariant in `tests/contract/tor/port_exposure_test.go` — uses the Docker SDK for Go (already pulled in by the contract-test harness per research.md §5) to bring up `compose/docker-compose.local.yml`, then asserts:
  (a) TCP connect from the host network namespace to `127.0.0.1:9050` and `127.0.0.1:9051` both fail with `ECONNREFUSED` (the Tor SocksPort and ControlPort are not bound on the host);
  (b) `docker inspect tor` returns `NetworkSettings.Ports` with no published binding for `9050/tcp` or `9051/tcp`;
  (c) from inside the `stargate-dp` container's network namespace, a TCP connect to `tor:9050` succeeds (the port IS reachable on the compose bridge network — failure here would mean we over-corrected and broke FR-007's data-plane → sidecar path).
  Gates FR-012 against silent compose-file regressions; pairs with T015's no-host-port-mapping rule.
- [ ] T019c [P] Contract test for the `docker-socket-proxy` lockdown invariants in `tests/contract/sidecar-proxy/lockdown_test.go` — brings up the compose stack and asserts, against `http://docker-socket-proxy:2375`:
  (a) `POST /containers/create`, `POST /containers/tor/kill`, `POST /containers/tor/exec`, `POST /images/create` all return HTTP 403 (the `POST=0` lockdown from T015);
  (b) `GET /containers/tor/json` returns 200 with `State.Status` and `State.Health.Status` populated (the surface SidecarMonitor depends on per T039);
  (c) `GET /events?filters={"type":["container"]}` returns a streamed response on container start/stop transitions (also depended on by T039);
  (d) Endpoints NOT in the allowlist — `/networks/create`, `/volumes/create`, `/swarm/init`, `/info`, `/version` — all return 403, verifying the proxy denies-by-default rather than allows-by-default;
  (e) The proxy is NOT reachable from the host's network namespace on any host-published port (paralleling T019b's invariant for `tor:9050`).
  Gates the C1-remediation property "CP compromise ≠ host root" against silent compose-file regressions; the privacy-TCB rationale lives in T017a.

**Checkpoint**: Foundation ready — user-story implementation can begin in parallel.

---

## Phase 3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP

**Goal**: A Mullvad Browser user with a pasted bearer token loads a `.onion` page through the local-profile stack; no DNS leak, no clearnet metadata about the destination.

**Independent Test**: Spec §"User Story 1 — Independent Test" — Wireshark capture on `lo` and host egress NIC during a `.onion` page load shows zero A/AAAA queries for `*.onion` and zero egress packets outside the current Tor consensus.

### Tests for User Story 1 (per Constitution Principle VII) ⚠️

> **NOTE: Write these tests FIRST, run them, ensure they FAIL before the corresponding implementation task lands.** All file paths are exact.

- [ ] T020 [P] [US1] Contract test for `ReloadTokens` (happy / stale / invalid / snapshot-persist-failure / concurrency) in `tests/contract/control-grpc/reload_tokens_test.go` — per `contracts/control-grpc.md` §"ReloadTokens · Tests".
- [ ] T021 [P] [US1] Contract test for `WatchEvents` happy path (`STARTED` → `HEALTHY` for `tor`, fixed-vocabulary `detail`) in `tests/contract/control-grpc/watch_events_test.go` — per `contracts/control-grpc.md` §"WatchEvents · Tests" rows 1–3. **Extended in T074's scope to also cover the `UNHEALTHY` / `STOPPED` / `CRASHED` / `RESTARTED` transitions** — same file, same harness, same fixed-vocabulary `detail` invariant; T074 adds the assertions for the failure-side `detail` tokens (`healthcheck_fail`, `container_exit`) and the audit-log row writes.
- [ ] T022 [P] [US1] Contract test for inter-plane transport invariants in `tests/contract/control-grpc/transport_test.go` — both UDS paths exist (`/run/stargate/control.sock` hosted by the CP, `/run/stargate/dp.sock` hosted by the DP); each socket is mode 0600 and owned by its hosting plane's runtime user; neither plane dials TCP; each plane refuses to dial the *other* socket path (no role swap); mutual ed25519 auth on each socket; schema-version handshake on either socket rejects `stargate.v2` peers; plane-down survival (DP keeps serving port 8881 across a CP restart, CP re-dials `dp.sock` and re-pushes the current generation on reconnect). Per `contracts/control-grpc.md` §"Transport invariants".
- [ ] T023 [P] [US1] Contract test for SOCKS5 first-byte demultiplex (`0x05` → SOCKS5, `'C'` → CONNECT, anything else → silent close) and method negotiation (`0x05 0x02` for clients offering USERNAME/PASSWORD; `0x05 0xFF` for NO_AUTH-only) in `tests/contract/socks5/demux_test.go` — per `contracts/socks5-auth.md` §"Two inbound protocols, one port" and §"Auth method negotiation".
- [ ] T024 [P] [US1] Contract test for SOCKS5 username/password sub-negotiation success (`0x01 0x00`) and forwarding of `UNAME` verbatim into upstream SOCKS5 in `tests/contract/socks5/userpass_success_test.go` — per `contracts/socks5-auth.md` §"Username/password sub-negotiation".
- [ ] T025 [P] [US1] Contract test for SOCKS5 leak invariants (no token bytes in any response capture; constant-time comparison latency distribution; no per-request journal entry on auth failure; rejection of same-host NO_AUTH-only clients) in `tests/contract/socks5/leak_test.go` — per `contracts/socks5-auth.md` §"Invariants enforced by the contract test".
- [ ] T025a [P] [US1] Contract test for SOCKS5 success-path log invariants — drive 100 sequential authenticated CONNECTs through port 8881 to an in-process upstream (the `accept-and-relay` mode of `fake_socks5_tor.go` from T019a); capture the data plane's stderr / journal output for the duration of the run; assert (a) no destination hostname, full URL, request or response header value, or body byte appears anywhere in the captured log; (b) no per-request timestamp at finer resolution than the ≥1-hour aggregate-counter bucket (FR-008, arch §6.4); (c) the only emitted lines belong to a fixed allowlist: startup, shutdown, `SidecarEvent` consumption, `ReloadTokens` apply, snapshot-write events. Expose the allowlist used by assertion (c) as a small shared Go helper (e.g. `tests/internal/loginvariants/`) so T025b and T070a reference the same canonical set rather than duplicate it — `tests/contract/socks5/no_per_request_logs_test.go`.
- [ ] T025b [P] [US1] Contract test for long-lived bidirectional CONNECT (Principle I byte-pipe invariant; spec §"Edge Cases" rows *WebSocket upgrade through CONNECT* and *HTTP/2 connections (forced fallback from QUIC)* — both mechanically subsumed: any TLS-over-CONNECT payload (H1, H2, WebSocket) is opaque bytes to the data plane after the SOCKS5/CONNECT handshake completes, so the byte-pipe transparency assertion covers all three protocol shapes without needing protocol-specific tests) — open an authenticated SOCKS5 *and* HTTP CONNECT through port 8881 to the `accept-and-relay` upstream from T019a; after handshake, exchange interleaved frames in both directions for ≥30s (mix of small / medium / large byte runs; asymmetric bandwidth; idle gaps up to 5s); assert (a) every byte round-trips unmodified — no insertion, deletion, reordering, or rewriting in either direction; (b) the data plane emits no log line for the frame traffic (the T025a shared allowlist applies); (c) the connection stays open until *either end* initiates close — the data plane MUST NOT close it due to inactivity, frame content, or size; (d) the same property holds whether the inbound framing was SOCKS5 or HTTP CONNECT — in `tests/contract/socks5/long_lived_connect_test.go`.
- [ ] T025c [P] [US1] Contract test for auth-failure counter side-channel resistance (FR-006, FR-008; data-model.md §3 — "auth failures leave `request_count` unchanged"; counting them would be a side channel for token-guessing attacks since an attacker can submit tokens at will). Establish a baseline `request_count` snapshot for `route='TOR'` via a direct gRPC probe to the data plane's status surface (arch §5.2 `GetStatus`, used here as a test-only probe; this is why the test lives next to the SOCKS5 leak tests rather than under `tests/contract/control-grpc/` — the property under test is at the SOCKS5/auth boundary, not the inter-plane RPC contract). Send N=100 SOCKS5 CONNECTs and N=100 HTTP CONNECTs with malformed bearer tokens to port 8881 — mix of: missing password, all-zero token, wrong-length token, correct-length token absent from current generation. Take a second snapshot. Assert (a) `request_count` delta is exactly zero; (b) `byte_count` delta is exactly zero (the synthesised AUTH_REQUIRED template body is excluded by data-model.md §3); (c) the gRPC probe itself does not increment any counter — verified by a no-traffic sandwich: snapshot, sleep ≥1s, snapshot again, assert no change. File: `tests/contract/socks5/auth_failure_counter_test.go`. Pairs with T049's implementation; T025 gates the log/journal side channel and T025c gates the counter side channel — both must hold or the auth-failure path leaks.
- [ ] T026 [P] [US1] Contract test for HTTP CONNECT auth success — `CONNECT host:443 HTTP/1.1` + `Proxy-Authorization: Bearer <valid>` returns `HTTP/1.1 200 Connection Established\r\n\r\n` then bridges to upstream — in `tests/contract/error-template/auth_success_test.go`.
- [ ] T027 [P] [US1] Contract test for `AUTH_REQUIRED` on CONNECT path (missing header → 407 + template; malformed token → 407 + template byte-identical to missing-header case; leak-corpus scan over response bytes) in `tests/contract/error-template/auth_required_test.go` — per `contracts/error-template.md` §"Contract tests" row 1 and `contracts/socks5-auth.md` §"HTTP CONNECT path · Invariants".
- [ ] T028 [P] [US1] Contract test for `AUTH_REQUIRED` on SOCKS5 path — exact 2-byte response `0x01 0xFF` then close, no additional bytes — in `tests/contract/socks5/auth_required_test.go` — per research.md §9 and `contracts/socks5-auth.md` §"Auth failure response".
- [ ] T029 [P] [US1] Contract test asserting the rendered `torrc` matches the v1 template byte-for-byte in `tests/contract/torrc/render_byte_match_test.go` — per `contracts/torrc.md` §"render_byte_match_test.go".
- [ ] T030 [P] [US1] Contract test asserting each `torrc` invariant individually (rows 1–12 from the contract document) in `tests/contract/torrc/invariants_test.go`.
- [ ] T031 [P] [US1] Contract test asserting no bridge / pluggable-transport strings appear anywhere in the rendered `torrc` in `tests/contract/torrc/no_bridges_test.go`.
- [ ] T032 [P] [US1] Contract test spinning up the live Tor sidecar with the rendered config and asserting `GETCONF SocksPort` returns a value containing `IsolateClientAddr` and `IsolateSOCKSAuth` in `tests/contract/torrc/live_sidecar_test.go`.
- [ ] T033 [P] [US1] Integration test for the full vertical: bring up `compose/docker-compose.local.yml`; load `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion` via the data plane's port 8881 (driven from a Go HTTP client through SOCKS5h); assert page bytes received and Tor sidecar's circuit-status reports an established circuit — `tests/integration/onion_load_test.go`.
- [ ] T034 [P] [US1] Integration test asserting no DNS query for any `*.onion` name appears on `lo` or egress NIC for the duration of a 60-second Go-driven routed session — `tests/integration/dns_leak_test.go`. Uses `gopacket` to capture both interfaces; fails on any A/AAAA/MX containing `.onion`. This is a fast PR-time regression gate on the SOCKS5h + `proxyDNS:true` mechanism (FR-003, FR-007); the spec-level SC-003 measurement is T034a.
- [ ] T034a [US1] Hand-driven SC-003 measurement on the reference workstation — fresh Mullvad Browser profile, 10-minute continuous `.onion`-only browsing session through the local-profile stack, simultaneous Wireshark capture on `lo` and egress NIC, capture filter `dns and frame contains ".onion"` returning zero packets across both interfaces. Result recorded in `tests/integration/sc003_dns_leak.md` (markdown artefact alongside T077's walkthrough record). Run before each release tag, not on every PR.
- [ ] T034b [P] [US1] Unit test for `extension/background/hardening.js` (Principle VII; FR-004) — pure-logic test using Node.js built-in `node:test` runner (no third-party deps; aligned with extension's no-build-step constraint per plan.md §"Technical Context" and research.md §10) against a thin handwritten mock of the `browser.privacy.network.*`, `browser.proxy.settings`, and `browser.notifications` APIs. Because MV2 background scripts are loaded by the browser as global scripts (not ES modules), the test loads `hardening.js` via Node's `vm.runInNewContext()` with a synthesized `browser` global — no source-code contortion (UMD wrapper, conditional `module.exports`, etc.) is added to the extension to make it testable. Cases:
  (a) all preconditions satisfied (DoH off, WebRTC = `disable_non_proxied_udp` or stricter, HTTP/3 off) → `routingBlocked` flag is `false`, no dialog payload generated.
  (b) DoH enabled → `routingBlocked` is `true`; dialog payload mentions the DoH precondition specifically.
  (c) WebRTC permissive (`default` or `default_public_interface_only`) → `routingBlocked` is `true`; dialog payload mentions WebRTC.
  (d) HTTP/3 enabled → `routingBlocked` is `true`; dialog payload mentions HTTP/3.
  (e) Multiple preconditions failing simultaneously → all failing preconditions appear in dialog payload (not just the first one detected) — verifies the audit reports the full failure set, not a fail-fast subset (rationale: a fail-fast audit would force the user to fix preconditions one at a time across reloads, which is both hostile UX and an "is routing on?" oracle each reload window).
  Mock + test live at `extension/background/hardening.test.js`; runner script `extension/run-tests.sh` discovers any `*.test.js` under `extension/` (so future test files — e.g. T056's `options.test.js` — are picked up automatically without per-task runner amendments) and is invoked from CI on every PR touching `extension/`. Requires Node 20 LTS (CI pin — see research.md §10).

### Implementation for User Story 1

**Control plane** (Java / Quarkus):

- [ ] T035 [US1] Implement `control-plane/core/src/main/java/.../TokenLoader.java` — parse `/etc/stargate/tokens.yaml` per data-model.md §1.1 validation table; argon2id-hash each plaintext using shared `Argon2idParams` (T011); zero the plaintext `byte[]` after hashing; log warnings without token bytes on validation failure. Diff the post-load label set against the previous generation's `enrolled_devices` rows (injected Panache repository) and emit, via `AuditLogService` (T036): `enrolled` for each label new this load, `revoked` for each label present in the previous generation but absent from the new file, `config_error` for each parse or validation failure (`detail_json.kind = "parse"|"validation"` per data-model.md §4, with line number where the YAML parser surfaces one; no token bytes ever appear in `detail_json` or in the warning logs). Update `enrolled_devices` to match the new label set as part of the same transaction.
- [ ] T036 [US1] Implement `control-plane/persistence/src/main/java/.../entity/AuditLog.java` (Panache entity matching V001 schema) and `AuditLogService.java` exposing one `write(action, target, detailJson)` method that emits any of the five fixed-vocabulary actions enumerated in data-model.md §4: `enrolled`, `revoked`, `config_error`, `sidecar_healthy`, `sidecar_unhealthy`. `actor` is set to `tokens.yaml` for the three token actions and to `system` for the two sidecar transitions, per §4. The callers wired by this feature are T035 (`enrolled`, `revoked`, `config_error`), T039 (`sidecar_healthy`), and T074 (`sidecar_unhealthy`).
- [ ] T037 [US1] Implement `control-plane/core/src/main/java/.../TorrcRenderer.java` rendering the byte-exact template from `contracts/torrc.md`; atomic write (`tmp` + fsync + rename) to the `stargate-tor-config` named volume. Verified by T029.
- [ ] T038 [US1] In `control-plane/api/src/main/java/.../`: (a) `ControlGrpcService.java` hosts the `WatchEvents` gRPC server, binding `/run/stargate/control.sock` (mode 0600, owned by the control-plane runtime user); (b) `ReloadTokensClient.java` is the gRPC *client* stub that dials the data plane's `/run/stargate/dp.sock` — used by `StargateControlPlane` (T041) to push token generations. Both endpoints perform the mutual ed25519 handshake using keys from `stargate-keys`. The CP does NOT host `ReloadTokens` — that server lives in the data plane (T045) because `ReloadTokens` direction is CP→DP per `contracts/control-grpc.md` §"ReloadTokens". Verified by T022 (transport invariants on both sockets) and T021 (`WatchEvents` server-side behaviour); the `ReloadTokens` client-side push is gated against the DP server by T020.
- [ ] T039 [US1] Implement `control-plane/core/src/main/java/.../SidecarMonitor.java` — for the Tor sidecar only, emit `STARTED` + `HEALTHY` `SidecarEvent`s (with fixed-vocabulary `detail` `container_start`, `healthcheck_pass`) over the gRPC stream when the docker-socket-proxy (T015) reports the corresponding events, **and** write a `sidecar_healthy` row to `audit_log` via `AuditLogService` (T036) on each transition into HEALTHY (`detail_json` shape per data-model.md §4). Observation channel: long-poll `GET http://docker-socket-proxy:2375/events?filters={"type":["container"]}` for the container event stream (the `type=container` filter has been stable since Engine API v1.22 and sharply reduces volume vs no filter); the SidecarMonitor then drops any event whose `Actor.Attributes.name` is not in a CP-internal allowlist (`{"tor"}` for this feature; later sidecar features add their names to the set). Keeping the container-name filter in CP code rather than the URL avoids Engine API filter-syntax versioning quirks and makes the test surface a plain Java set-membership check. On each surviving event and on a bounded interval, poll `GET /containers/{name}/json` to read `State.Health.Status` (`healthy` → `HEALTHY`; `unhealthy` is mapped in T074). SidecarMonitor MUST NOT issue any HTTP method other than `GET` to the proxy and MUST NOT call any path outside `/events` and `/containers/{name}/json` — both invariants are gated by T019c at the proxy boundary and by a per-test mock at the CP unit-test layer. UNHEALTHY/STOPPED/CRASHED/RESTARTED transitions are added in T074.
- [ ] T040 [US1] Implement `control-plane/ui/src/main/java/.../HealthEndpoint.java` — single `GET /healthz` returning 200 with no body (consumed by the Compose healthcheck only; no admin surface).
- [ ] T041 [US1] Implement `control-plane/runtime/src/main/java/.../StargateControlPlane.java` (`@QuarkusMain`) — wires the startup sequence: render `torrc` (T037) → start `SidecarMonitor` (T039) → load `tokens.yaml` (T035) → push `ReloadTokens` (T038); on missing/empty token file, log warning and proceed with empty list per FR-018.

**Data plane** (Go):

- [ ] T042 [P] [US1] Implement `data-plane/internal/listener/socks5.go` — first-byte demultiplex (`0x05` vs `'C'`), RFC 1928 method negotiation (require `0x02` USERNAME/PASSWORD; reject NO_AUTH-only with `0x05 0xFF`), RFC 1929 sub-negotiation framing. Verified by T023, T024, T025.
- [ ] T043 [P] [US1] Implement `data-plane/internal/listener/connect.go` — parse only the request line and the `Proxy-Authorization` header from `CONNECT host:port HTTP/1.1`; no other header is read; on success, write `HTTP/1.1 200 Connection Established\r\n\r\n` and hand off to the forward path. Verified by T026.
- [ ] T044 [US1] Implement `data-plane/internal/auth/token.go` — argon2id-hash candidate token using shared `Argon2idParams` (T011) and the per-token salt from the current generation; compare with `crypto/subtle.ConstantTimeCompare`; never log the offered token or hash. Verified by T024, T025, T027, T028.
- [ ] T045 [US1] Implement `data-plane/internal/controlclient/` — (a) `client.go`: gRPC client that dials `/run/stargate/control.sock`, consumes the server-streamed `WatchEvents` from the control plane, and applies events to `routeEnableMask` (see T073 for the failure-transition mapping); (b) `server.go`: gRPC server hosting `/run/stargate/dp.sock` (mode 0600, owned by the data-plane runtime user) exposing the `ReloadTokens` handler — atomic-swaps the `tokenStore` pointer and rejects stale generations with `APPLY_STATUS_STALE_GENERATION`. Mutual ed25519 handshake on both sockets using keys from `stargate-keys`. The package name `controlclient` is carried over from when the DP was client-only; renaming is deferred until a second gRPC service forces the issue. Verified by T020, T021, T022.
- [ ] T046 [US1] Implement `data-plane/internal/controlclient/snapshot.go` — atomic `os.Rename` write of `dp-snapshot.json` per data-model.md §1.4 on every successful `ReloadTokens`; restore on cold start when the control plane is unreachable.
- [ ] T047 [US1] Implement `data-plane/internal/forward/tor.go` — port-8881-to-Tor binding fixed at process startup (Principle I); SOCKS5h dial to `tor:9050` via `golang.org/x/net/proxy`; pass SOCKS5 `UNAME` through verbatim as the upstream SOCKS5 username; never resolve target hostnames locally (FR-007). Verified by T032, T033.
- [ ] T048 [US1] Implement `data-plane/internal/errortpl/render.go` — render the template literal from T019 for the `AUTH_REQUIRED` case on the CONNECT path; emit exactly four headers in declared order; generate `LOCAL_REFERENCE_ID` via `crypto/rand.Read(8)` + hex (16 chars). Verified by T027. Extended in T071 for the remaining error codes.
- [ ] T049 [US1] Implement `data-plane/internal/audit/counters.go` — in-memory `(route, hour_bucket) → (request_count, byte_count)` aggregates counted per data-model.md §3 (auth-passed requests increment `request_count`; only bytes forwarded between client and upstream contribute to `byte_count`, not the synthesised error-template body); flush via the control plane's pull-based `StatusResponse`. Verified by T025c (auth-failure counter side-channel).
- [ ] T050 [US1] Implement `data-plane/cmd/stargate-proxy/main.go` — run `bind/check.go` (T013) FIRST; load `dp-snapshot.json` (T046); dial the control plane (T045); open the port-8881 listener (T042 + T043); wait for at least one `HEALTHY` `SidecarEvent` for `tor` before transitioning `routeEnableMask[TOR]` to ENABLED (data-model.md §2). Verified end-to-end by T033, T034.

**Extension** (vanilla MV2 JS):

- [ ] T051 [P] [US1] Author `extension/manifest.json` — Manifest V2, `browser_specific_settings.gecko.id`, permissions `proxy`, `storage`, `webRequest`, `webRequestBlocking`, `privacy`, `notifications`, host permission for `<all_urls>`; background script is non-persistent per arch §14.1.
- [ ] T052 [P] [US1] Author `extension/lib/storage.js` — thin async wrappers over `browser.storage.local.get/set` for the device schema in data-model.md §5.
- [ ] T053 [P] [US1] Author `extension/lib/firstparty.js` — first-party-domain computation per arch §14.3: prefer `requestDetails.documentUrl`/`originUrl` eTLD+1; for top-level `.onion` navigation, return the onion address itself; for subresources under a `.onion` document, return the parent page's onion address.
- [ ] T054 [US1] Author `extension/background/router.js` — `browser.proxy.onRequest` listener that returns `{ type: "socks", host: "127.0.0.1", port: 8881, username: <first-party from T053>, password: <bearer token from T052>, proxyDNS: true, failoverTimeout: 5 }` for hosts matching `.onion`; no proxy for other hosts in this feature.
- [ ] T055 [US1] Author `extension/background/hardening.js` — DoH off / WebRTC `disable_non_proxied_udp` (or stricter) / HTTP/3 off audit per arch §14.5; blocking dialog on failure; routing is blocked via a flag that `router.js` (T054) checks before returning the SOCKS descriptor (FR-004). **Verified by T034b.**
- [ ] T056 [US1] Author `extension/options/options.html` and `extension/options/options.js` — single bearer-token field with `^[0-9a-f]{32}$` client-side validation; visible warning about `storage.local` per research.md §6 and FR-019. The canonical user-facing warning string is pinned in data-model.md §5.1; this task MUST include an inline test at `extension/options/options.test.js` (node:test + `vm.runInNewContext()` pattern per T034b / research.md §10) that reads `options.html`'s text content and asserts byte-for-byte presence of the canonical string. Test fails if either side drifts. Quickstart.md Step 4 may quote the string for operator reference but data-model.md §5.1 is the single source of truth.
- [ ] T057 [US1] Author `extension/popup/popup.html` and `extension/popup/popup.js` — per-tab indicator reading the routing decision from `webRequest.onBeforeRequest` cache for the active tab; surfaces `Route: Tor` for `.onion` tabs, `Route: Direct (unrouted)` otherwise.

**Checkpoint**: US1 complete. The MVP path — Mullvad Browser → port 8881 → data plane → Tor sidecar → `.onion` — works end-to-end. T033 (page load) and T034 (no DNS leak) pass against a freshly built stack.

---

## Phase 4: User Story 2 — Stream isolation per first-party domain (Priority: P2)

**Goal**: Two distinct first-party `.onion` origins use two distinct Tor circuits; same-origin requests share a circuit.

**Independent Test**: Spec §"User Story 2 — Independent Test" — parallel CONNECTs to two distinct first-party `.onion` destinations attach to distinct Tor circuit IDs (queried via cookie-authenticated control port); 10 distinct first-party domains yield ≥9 distinct circuits.

### Tests for User Story 2 (per Constitution Principle VII) ⚠️

> Per US1 + Phase 2, the routing mechanism (extension passes first-party-domain as SOCKS5 username; data plane forwards verbatim; `torrc` declares `IsolateSOCKSAuth`) is already in place. US2 tests verify the *privacy property* the mechanism is supposed to deliver.

- [ ] T058 [P] [US2] Contract test in `tests/contract/torrc/isolate_socks_auth_effect_test.go` — spins up the Tor sidecar with the rendered config, issues two SOCKS5 CONNECTs with distinct usernames, queries the control port for `circuit-status`, asserts the two streams attached to distinct circuit IDs. (`contracts/torrc.md` §"isolate_socks_auth_effect_test.go".)
- [ ] T059 [P] [US2] Integration test in `tests/integration/stream_isolation_test.go` — through port 8881 (not directly against the sidecar), issue parallel CONNECTs to two distinct `.onion` targets with different SOCKS5 usernames; assert distinct circuit IDs at the control port. (Spec US2 acceptance scenario 1.)
- [ ] T060 [P] [US2] Integration test in `tests/integration/same_origin_shared_circuit_test.go` — two parallel CONNECTs to the same first-party `.onion` (different resources) attach to the **same** circuit ID. (Spec US2 acceptance scenario 3 — this is the design, not a leak.)
- [ ] T061 [P] [US2] Integration test in `tests/integration/circuit_isolation_corpus_test.go` — SC-002 measurement: 100 sequential CONNECTs to 100 distinct first-party `.onion` strings from a synthetic corpus, assert ≥95 distinct circuit IDs. (Spec SC-002.)

### Implementation for User Story 2

- [ ] T062 [US2] Author `tests/contract/tor/control_port.go` — cookie-authenticated Tor control-port client (helper consumed by T058 and the integration tests T059–T061); reads the cookie from the `stargate-tor-state` volume mount.
- [ ] T063 [US2] Author `tests/integration/synthetic_onion_corpus.txt` — 100 distinct onion-style address *strings* (well-formed but not necessarily reachable; the property under test is circuit selection, not reachability, per research.md §7 / spec Assumptions).

**Checkpoint**: US2 complete. Stream isolation is verifiable end-to-end and as a contract gate on the rendered `torrc`.

---

## Phase 5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)

**Goal**: Errors returned when the Tor sidecar is unreachable, refused, or timing out reveal nothing about destinations, upstream addresses, sidecar internals, or backtraces.

**Independent Test**: Spec §"User Story 3 — Independent Test" — with the Tor sidecar stopped, a `.onion` CONNECT returns the privacy-safe template with `{CODE}=ROUTE_DOWN`, exactly four headers, no values from the curated leak corpus.

### Tests for User Story 3 (per Constitution Principle VII) ⚠️

- [ ] T064 [P] [US3] Author the curated leak corpus `tests/contract/error-template/leak-corpus.txt` per `contracts/error-template.md` §"Leak-corpus invariant" — the SC-001/002 reference target onion; the 100-domain synthetic corpus from T063; placeholder lines for the data plane's egress IP and a representative Tor exit IP filled in at test time; version-string fragments (`Tor`, `Quarkus`, `Hibernate`, `SQLite`, `Mandrel`); backtrace fragments (`panic:`, `goroutine`, `stack trace`, `at line`).
- [ ] T065 [P] [US3] Contract test `tests/contract/error-template/route_down_test.go` — stop the Tor container, send CONNECT with valid auth; assert 502 + template + `X-Stargate-Error: ROUTE_DOWN`; leak-corpus scan passes.
- [ ] T066 [P] [US3] Contract test `tests/contract/error-template/route_refused_test.go` — Tor up, CONNECT targets a non-resolvable `.onion`; assert 502 + template + `ROUTE_REFUSED`; leak-corpus scan passes (in particular, no Tor SOCKS5 reason text in the body).
- [ ] T067 [P] [US3] Contract test `tests/contract/error-template/route_timeout_test.go` — substitute the synthetic slow SOCKS5 backend (`tests/integration/fake_socks5_tor.go` from T019a, configured in `slow` mode); CONNECT to a hung target; assert 504 + template + `ROUTE_TIMEOUT`.
- [ ] T068 [P] [US3] Contract test `tests/contract/error-template/body_byte_match_test.go` — for one failure of each of the four codes, assert the body matches the template byte-for-byte after substituting the four permitted fields; no other bytes present.
- [ ] T069 [P] [US3] Contract tests `tests/contract/error-template/reference_id_unique_test.go` and `reference_id_unlinked_test.go` — 1000 sequential failures yield 1000 distinct reference IDs with uniform distribution; the same request issued twice yields two distinct reference IDs (proves the ID is not derived from request data).
- [ ] T070 [P] [US3] Integration test `tests/integration/error_template_test.go` — end-to-end version of T065: bring up the stack, stop the Tor sidecar mid-session, request a `.onion` URL through the data plane, capture the full response, run the leak-corpus scan.
- [ ] T070a [P] [US3] Integration test for mid-request Tor circuit drop (Principle I no-retry + Principle III no-upstream-derived-leak; spec §"Edge Cases" — *Tor circuit failure mid-request*) — bring up the local-profile stack; using the cookie-authenticated control-port helper from T062, open an authenticated CONNECT through port 8881 to a known-reachable `.onion`, begin a slow read so the stream stays in-flight, then issue `CLOSECIRCUIT <id>` on the control port to kill *that specific circuit* (not the whole sidecar); capture every byte written to the browser side until the browser-side socket finishes closing; assert (a) after the data plane observes EOF (or RST) on the upstream SOCKS5 stream, zero new bytes are written to the browser side — the data plane MUST NOT synthesise an error template, status line, or reason text at this layer (in-flight bytes Tor delivered before the close are passed through verbatim and are tested only against the leak-corpus scan in assertion (d)); (b) the browser-side socket is closed by the data plane (TCP close, not a rendered HTTP response — the post-CONNECT byte pipe has no framing context for one); (c) the data plane issues no retry to the Tor sidecar (verified by control-port `circuit-status` showing no new circuit for the same SOCKS5 username within a bounded watch window); (d) leak-corpus scan over the captured bytes returns zero matches; (e) the T025a shared log allowlist applies to the data plane's output during the run — in `tests/integration/circuit_drop_midstream_test.go`. Run before each release tag, not on every PR (real-Tor reachability + control-port timing make this unsuitable as a per-PR gate; same cadence as T034a).

### Implementation for User Story 3

- [ ] T071 [US3] Extend `data-plane/internal/errortpl/render.go` (from T048) to cover `ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT` per the status/reason table in `contracts/error-template.md` §"Status line"; verify the `LOCAL_REFERENCE_ID` generation is shared across all codes. Verified by T065–T069.
- [ ] T072 [US3] Extend `data-plane/internal/forward/tor.go` (from T047) to map upstream SOCKS5 connect-failure replies to `ROUTE_REFUSED` and to enforce a bounded dial+I/O deadline mapped to `ROUTE_TIMEOUT`. **No Tor reason text or upstream error string propagates into the response** (FR-009).
- [ ] T073 [US3] In `data-plane/internal/controlclient/client.go` (from T045), wire the `SidecarEvent` consumer to set `routeEnableMask[TOR]=false` on `UNHEALTHY`/`STOPPED`/`CRASHED` per data-model.md §2 state machine; the forwarding path checks the mask before dialing and returns `ROUTE_DOWN` (via T071) when disabled.
- [ ] T074 [US3] Extend `control-plane/core/src/main/java/.../SidecarMonitor.java` (from T039) to emit `UNHEALTHY`, `STOPPED`, `CRASHED`, `RESTARTED` `SidecarEvent`s for the Tor sidecar; `detail` is drawn from the fixed vocabulary `{"healthcheck_fail","container_exit"}` per `contracts/control-grpc.md` §"WatchEvents · Contract". On every transition to `UNHEALTHY`/`STOPPED`/`CRASHED`, write a `sidecar_unhealthy` row to `audit_log` via `AuditLogService` (T036) with `detail_json.kind` set to the matching state (data-model.md §4). `RESTARTED` is event-only and does **not** write an audit-log row — §4's `sidecar_unhealthy` vocabulary excludes it, and the next transition into HEALTHY emits the `sidecar_healthy` row via T039. Verified by T021 (extended to cover the failure transitions) and T070.

**Checkpoint**: All three user stories independently functional. The privacy-safe failure property holds for all four error codes the data plane can emit.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Properties that ride on top of every user story, plus the adversarial-review gate (Principle VIII).

- [ ] T075 [P] Author `tests/reproducibility/data_plane_test.sh` — build the data-plane Go binary twice in clean containers (matching arch §12.1) and `cmp` the output; CI runs this on every PR touching `data-plane/`.
- [ ] T075b [P] Author `tests/reproducibility/extension_test.sh` — invoke `extension/package.sh` (T005) twice in clean working directories and `cmp` the resulting `dist/stargate-extension.zip` outputs; CI runs this on every PR touching `extension/`. Verifies the deterministic-zip-packaging claim from plan.md Constitution Check row VI / arch §12.3 (`SOURCE_DATE_EPOCH=0`, sorted entries) — paired with T075 so the byte-reproducibility guarantee is tested for every artefact this feature ships, not just the Go binary.
- [ ] T076 [P] Wire `tests/contract/tor/` and `tests/contract/error-template/` into CI as **required** checks for any PR that bumps a sidecar image digest in `compose/docker-compose.local.yml` (FR-016, Principle IV); the CI config lives in `.github/workflows/contract.yml` (GitHub Actions; matches constitution §VI's commitment to GitHub hosting with a Codeberg mirror as a v1.5+ consideration).
- [ ] T077 Run the `quickstart.md` walkthrough on a clean Linux x86_64 reference workstation with a fresh Mullvad Browser profile and a fresh git clone; measure SC-001 wall-clock time; record result in `tests/integration/quickstart_walkthrough.md` (a markdown artefact, not a Go test — the SC-001 measurement is intentionally hand-driven against a real browser, per plan.md §"Performance Goals").
- [ ] T078 Run the `stargate-redteam` agent against the completed feature branch (Principle VIII); findings either resolve in-feature or land in `SECURITY-DECISIONS.md` (T017) with explicit acceptance rationale.
- [ ] T079 Run the `stargate-perf` agent against the data plane (Principle VIII); verifies SC-005 (≥200 concurrent CONNECTs against the synthetic SOCKS5 backend from T019a) and the zero-retained-allocation property on the forwarding hot path.
- [ ] T080 Sweep with `scripts/check-license-headers.sh` (from T006); verify Apache 2.0 headers on every new file; update CLAUDE.md "Current plan" pointer if downstream specs land before this feature merges.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — can start immediately.
- **Foundational (Phase 2)**: Depends on Setup. BLOCKS all user-story phases.
- **User Story 1 (Phase 3, P1)**: Depends on Foundational. Independently testable per spec US1.
- **User Story 2 (Phase 4, P2)**: Depends on Foundational AND on US1 implementation tasks T047 (`forward/tor.go` username passthrough), T054 (extension router setting SOCKS5 username), T037 (`TorrcRenderer` writing `IsolateSOCKSAuth`). The US2 test tasks (T058–T061) can be authored before US1 implementation lands but will fail until the wiring is in place.
- **User Story 3 (Phase 5, P3)**: Depends on Foundational AND on US1 task T048 (initial `errortpl/render.go`) AND T045 (`SidecarEvent` consumer scaffold). The US3 implementation extends US1 code rather than duplicating it.
- **Polish (Phase 6)**: Depends on all user stories being complete.

### Within Each User Story

- Tests MUST be written and FAIL before the matching implementation tasks (Principle VII; the principle applies to every category this feature touches).
- Within US1, the dependency chain is roughly: proto stubs (T009/T010) → control-plane primitives (T035, T037, T039) → control-plane wiring (T038, T041); independently, data-plane primitives (T042, T043, T044) → forward/control-client (T047, T045) → main (T050); independently, extension libs (T052, T053) → extension surfaces (T054, T056, T057).
- Within US3, two cross-story dependencies exist: T070a depends on T062 (control-port helper, authored in Phase 4 for US2), and T064 depends on T063 (synthetic onion corpus, authored in Phase 4 for US2 — used as input to the leak-corpus file); T025b reuses the shared log allowlist authored as part of T025a.

### Parallel Opportunities

- All Phase 1 setup tasks except T001 (which establishes directories every other task writes into) can run [P] after T001.
- Phase 2 has heavy [P] coverage — T009/T010, T011, T013, T014 can all run in parallel; T015 depends on T014 (compose references the Tor image).
- All 16 test tasks in Phase 3 (T020–T034b) are [P] across distinct test files and can land before any US1 implementation begins.
- The three planes' implementations (control plane, data plane, extension) within US1 are largely independent — a three-developer team could parallelise them, with the integration tests T033/T034 as the merge point.
- All US3 test tasks (T064–T070) are [P] across distinct test files.

---

## Parallel Example: User Story 1 tests

All 15 US1 contract+integration test tasks land before any US1 implementation. They can be split across reviewers:

```text
# Inter-plane gRPC contract tests:
T020 — reload_tokens_test.go
T021 — watch_events_test.go
T022 — transport_test.go

# Inbound surface (port 8881) contract tests:
T023 — socks5/demux_test.go
T024 — socks5/userpass_success_test.go
T025 — socks5/leak_test.go
T026 — error-template/auth_success_test.go
T027 — error-template/auth_required_test.go
T028 — socks5/auth_required_test.go

# Tor sidecar contract tests:
T029 — torrc/render_byte_match_test.go
T030 — torrc/invariants_test.go
T031 — torrc/no_bridges_test.go
T032 — torrc/live_sidecar_test.go

# End-to-end integration tests:
T033 — integration/onion_load_test.go
T034 — integration/dns_leak_test.go

# Extension JS tests:
T034b — extension/background/hardening.test.js
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Complete Phase 1: Setup (T001–T006).
2. Complete Phase 2: Foundational (T007–T019) — CRITICAL, blocks every user story.
3. Complete Phase 3: User Story 1 (T020–T057), writing tests first.
4. **STOP and VALIDATE**: run T033 + T034 against a freshly built stack; walk through `quickstart.md` Steps 1–6.
5. If the privacy property holds (no `.onion` DNS query in the capture; page renders through Tor), the MVP is shippable as an internal preview. Continue to US2 and US3 before public release.

### Incremental Delivery

1. Setup + Foundational → foundation ready for parallel work.
2. US1 → MVP shipped → first public preview of the project (internal only, since US3's failure-mode privacy isn't yet in).
3. US2 → privacy property of Tor route is *demonstrable end-to-end*, not just *implemented*.
4. US3 → failure-mode privacy property holds → ready for the adversarial-review gate.
5. Polish → reproducibility, perf, redteam, walkthrough timing → release candidate.

### Parallel Team Strategy

With three developers after Phase 2 completes:

- Dev A — control plane: T035, T036, T037, T038, T039, T040, T041, then T074.
- Dev B — data plane: T042, T043, T044, T045, T046, T047, T048, T049, T050, then T071, T072, T073.
- Dev C — extension + tests: T020–T034 (the tests, in parallel with the planes' implementations), then T051–T057, then T058–T070.

US2 and US3 ride on US1's surfaces; the same developer pairing carries through to Phase 5. Polish is whole-team.

---

## Notes

- `[P]` tasks touch distinct files and have no dependency on incomplete tasks.
- `[Story]` labels (`[US1]`, `[US2]`, `[US3]`) appear only on user-story phase tasks; Setup, Foundational, and Polish tasks are unlabelled.
- Tests-first is mandatory for every implementation task — Principle VII applies to every category this feature touches.
- Commit after each task or logical group; never bundle a test and its corresponding implementation into one commit (the failing-test signal is part of the audit trail).
- Stop at any checkpoint (end of US1, end of US2) to validate the story's independent-test criterion before continuing.
- Avoid: vague tasks, two tasks writing the same file in parallel, cross-story dependencies that defeat independent testability.
