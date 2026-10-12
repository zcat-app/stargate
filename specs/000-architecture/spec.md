# Architecture Specification (Pre-Feature)

> **T156 constitutional reconciliation:** the active constitution and feature 001
> `contracts/foundation-boundaries.md` supersede historical wildcard binds, CP Tor-cookie
> access, automatic stale-auth renumbering and per-event audit/metric examples below.
> These remain implementation gaps, not accepted protections. Concrete toolchain/UI pins
> stay binding here and change only through reviewed, tested updates (Principles IV/VII/VIII).

**Spec ID**: `000-architecture`

**Status**: Draft

**Created**: 2026-05-17

**Derives from**: `.specify/memory/constitution.md` v1.0.0 (with the pre-release T091 amendment to Principle III bullet 3)

**Supersedes**: nothing (this is the foundational system-shape spec)

---

## 1. Purpose & Scope

This spec defines the **concrete system shape** inside which Stargate's v1
feature specs are authored. It fixes the module boundaries, the listening
ports, the inter-plane contract surface, the on-disk state schema, the build
and reproducibility pipeline, and the lifecycle scripts that all v1 features
share.

It is a **pre-feature** spec: there are no user stories here. Per-feature
behaviour (Tor route, I2P route, Nym route, Direct route, bridges, admin UI
flows, enrollment, audit) is deferred to numbered feature specs under
`specs/001-*/` and later.

Anything here that is not explicitly resolved is marked `NEEDS CLARIFICATION`
and must be answered before the relevant feature spec can be planned. The
constitution (`.specify/memory/constitution.md`) is the authority: where this
document and the constitution disagree, the constitution wins and this spec
must be amended.

---

## 2. High-Level Topology

```
                     ┌────────────────────────────────────────┐
                     │  Mullvad Browser  (or LibreWolf)       │
                     │  ┌──────────────────────────────────┐  │
                     │  │ Stargate WebExtension            │  │
                     │  │  proxy.onRequest → port mapping  │  │
                     │  │  domain → route in local storage │  │
                     │  └──────────────────────────────────┘  │
                     └──────────────────┬─────────────────────┘
                                        │ TCP (Tor: SOCKS5; other routes: per-route contract)
              ┌─────────────────────────┴─────────────────────────┐
              │            Stargate proxy listening ports         │
              │                                                   │
              │  8881 Tor   8882 I2P   [8883 IPFS-v2]  8884 Mix   │
              │  8885 Direct                                      │
              └───┬──────────┬────────────┬─────────────┬─────────┘
                  │          │            │             │
                  ▼          ▼            ▼             ▼
       ┌──────────────┐ ┌─────────┐ ┌────────────┐ ┌──────────────┐
       │  Tor sidecar │ │  i2pd   │ │ Nym client │ │ (no sidecar) │
       │  SOCKS UDS   │ │  4444   │ │ SOCKS 1080 │ │  egress NIC  │
       └──────┬───────┘ └────┬────┘ └─────┬──────┘ └──────┬───────┘
              │              │            │               │
              ▼              ▼            ▼               ▼
          Tor network    I2P network   Nym mixnet     Clearnet

       ┌─────────────────────────────────────────────────────────┐
       │ Control plane (Quarkus) — admin UI on 8443 (loopback or │
       │ tunnel iface). Talks to data plane over Unix gRPC only. │
       │ State in SQLite (named volume). No request-path role.   │
       └────────────────────────┬────────────────────────────────┘
                                │ gRPC over /run/stargate/control.sock
                                ▼
       ┌─────────────────────────────────────────────────────────┐
       │ Data plane (Go)  — owns the listening ports above.      │
       │ Forwards bytes only. Stateless w.r.t. requests.         │
       └─────────────────────────────────────────────────────────┘

  LAN / VPS profile adds:
       ┌──────────────────┐
       │ WireGuard sidecar│  wg0 inside compose network.
       │ UDP 51820 public │  Proxy + admin UI bind only to wg0.
       └──────────────────┘
```

**Privacy invariant (Principle III, deployment-mode clause)**: arrows out of
the proxy that target an anonymity network MUST go via a sidecar; the proxy
itself never opens a socket to a public destination except where Direct
clearnet routing is explicitly selected by the client.

---

## 3. Repository Layout

```
stargate/
├── data-plane/                         # Go module
│   ├── go.mod                          # toolchain directive pins Go version
│   ├── cmd/stargate-proxy/main.go
│   └── internal/
│       ├── forward/                    # SOCKS5h forwarding (per route)
│       ├── listener/                   # per-port listeners
│       ├── sidecar/                    # health, restart RPC
│       ├── controlclient/              # gRPC client (to control plane)
│       ├── audit/                      # aggregate counter sink
│       └── bind/                       # interface-binding safety check
│
├── control-plane/                      # Quarkus multi-module Maven project
│   ├── pom.xml                         # parent POM
│   ├── api/                            # gRPC server, REST admin API
│   ├── core/                           # services, domain model
│   ├── persistence/                    # Hibernate Panache entities, Flyway
│   ├── ui/                             # Qute templates, static assets
│   └── runtime/                        # @QuarkusMain, packaging
│
├── extension/                          # WebExtensions JavaScript
│   ├── manifest.json
│   ├── background/                     # proxy.onRequest handler
│   ├── options/                        # options page (settings)
│   ├── popup/                          # per-tab route indicator
│   └── lib/                            # storage, audit, blocklist
│
├── proto/stargate/v1/
│   ├── control.proto                   # Control service definition
│   └── events.proto                    # SidecarEvent message types
│
├── tests/
│   ├── contract/
│   │   ├── tor/                        # Tor SOCKS contract suite
│   │   ├── i2pd/                       # i2pd HTTP-proxy contract suite
│   │   ├── nym/                        # Nym SOCKS contract suite
│   │   └── wireguard/                  # tunnel-up contract suite
│   ├── integration/                    # end-to-end with real sidecars
│   └── reproducibility/                # build-twice-and-compare
│
├── compose/
│   ├── docker-compose.local.yml
│   ├── docker-compose.lan.yml
│   ├── docker-compose.vps.yml
│   └── env/                            # per-profile .env.example
│
├── scripts/
│   ├── stargate                        # entrypoint (subcommands below)
│   ├── lib/                            # shared shell helpers
│   └── subcommands/{init,enroll,export,import,wipe,status,update}
│
├── .specify/                           # spec-kit configuration (existing)
├── specs/                              # feature specs (this one + future)
├── ARCHITECTURE.md                     # human-facing summary derived from this spec
├── THREAT-MODEL.md                     # per-mode and per-route threat models
├── SECURITY-DECISIONS.md               # append-only accepted-finding log
├── BUILD-DIFFS.md                      # native-image expected variations
├── CONTRIBUTING.md
├── CLAUDE.md                           # AI assistant quick-reference
└── LICENSE                             # Apache 2.0
```

**Notes.**

- The data plane is a single Go module. The control plane is a Maven
  multi-module reactor (Quarkus convention); modules are pure Java with no
  CGO/JNI bridge to the data plane (Principle II).
- `tests/contract/<sidecar>/` is a top-level peer of the planes because
  contract tests cover the gap between Stargate and the upstream image;
  they outlive any single plane.
- `scripts/stargate` is a thin shell dispatcher to subcommand scripts;
  language choice is shell to keep zero runtime deps for ops tooling.

---

## 4. Port Assignments

All TCP unless noted. "Bind iface" is the interface the listener attaches to
per deployment profile. "Internal" means container-internal on the compose
network, never published to the host.

### 4.1 Externally observable (browser-facing and admin-facing)

| Purpose                           | Port  | Proto         | Local profile bind | LAN profile bind | VPS profile bind |
|-----------------------------------|-------|---------------|--------------------|------------------|------------------|
| Tor route (forward proxy)         | 8881  | SOCKS5 only  | `127.0.0.1`        | `wg0` only       | `wg0` only       |
| I2P route                         | 8882  | SOCKS5+HTTP   | `127.0.0.1`        | `wg0` only       | `wg0` only       |
| IPFS route (RESERVED v2)          | 8883  | —             | (not bound in v1)  | (not bound)      | (not bound)      |
| Mixnet (Nym) route                | 8884  | SOCKS5+HTTP   | `127.0.0.1`        | `wg0` only       | `wg0` only       |
| Direct (clearnet, no privacy)     | 8885  | SOCKS5+HTTP   | `127.0.0.1`        | `wg0` only       | `wg0` only       |
| Admin UI (control plane HTTPS)    | 8443  | HTTPS         | `127.0.0.1`        | `wg0` only       | `wg0` only       |
| WireGuard listener (LAN/VPS only) | 51820 | UDP           | (n/a)              | host `0.0.0.0`   | host `0.0.0.0`   |

The proxy MUST refuse to start if any of the route ports or the admin UI
port would bind to a non-loopback interface while no WireGuard sidecar is
present in the compose stack (constitution **Tech Stack / Deployment Model**
privacy invariant; enforced in `data-plane/internal/bind`).

**Why ports 8881–8885 and not consecutive lower numbers**: avoiding common
clashes (8080/8081 dev servers, 8888 jupyter-like tools), keeping a
contiguous identifiable block, and reserving 8883 to slot IPFS in cleanly at
v2 without renumbering. **Why 8443 for admin UI**: conventional HTTPS-admin
port; visually distinct from route ports.

### 4.2 Sidecar-internal endpoints (never host-published)

| Sidecar       | Service                | Port  | Bound on              |
|---------------|------------------------|-------|-----------------------|
| Tor           | SOCKS5 (stream-iso)    | UDS   | `/run/tor-fabric/private/tor-socks.sock` in Tor; hardlinked as `/run/stargate-tor/tor-socks.sock` in the DP-only fabric |
| Tor           | Control socket (cookie) | UDS  | `/var/lib/tor/control/tor-control.sock`, private to Tor and its fixed internal publisher; no observer mount (T203) |
| i2pd          | HTTP proxy             | 4444  | `0.0.0.0` in container |
| i2pd          | SOCKS proxy            | 4447  | `0.0.0.0` in container |
| i2pd          | SAM bridge (reserved)  | 7656  | `0.0.0.0` in container |
| Nym client    | SOCKS5                 | 1080  | `0.0.0.0` in container |

The Local Tor endpoints have no TCP listener. Only Tor attaches to the Docker
egress bridge; the DP uses host networking with an exception-free loopback
bind, and the CP has no Docker network. The DP-only fabric contains the
SOCKS re-exposure; the CP-only fabric is reserved for T164's authenticated
sanitized health observer. Other routes are later feature contracts.

### 4.3 Non-TCP endpoints

- **Inter-plane gRPC sockets**: two unix-domain sockets in a named volume
  (`stargate-ipc`), one per dial direction:
  - `/run/stargate/control.sock` — listened on by CP, dialled by DP
    (i.e. CP-hosted).
  - `/run/stargate/dp.sock` — listened on by DP, dialled by CP
    (i.e. DP-hosted).
  Both files: mode `0660`, owned by per-plane UIDs sharing the
  `stargate-ipc` GID. Numeric IDs fixed for reproducibility:
  `stargate-cp` UID 5101, `stargate-dp` UID 5102, `stargate-ipc` GID 5100.
  Per-feature byte-level invariants (which plane invokes which RPC, who
  may dial, etc.) live in each feature's `contracts/control-grpc.md`.
- **Inter-plane keys**: `/etc/stargate/keys/` mounted from a named volume
  (`stargate-keys`). Generated at first `stargate init`. Each plane owns
  its own private key (`cp.priv`, `dp.priv`) mode `0600`; both public
  keys (`cp.pub`, `dp.pub`) mode `0644` so the mutual ed25519 handshake
  can read the peer's.

### 4.4 Privacy notes on port topology

- One protocol per port; the upstream binding for each port is fixed at
  data-plane startup. Per **Principle I**, the data plane never picks a route
  per request — the browser extension picks the port.
- Direct (8885) is intentionally a distinct port from anonymity routes so
  that the browser extension's UI surface and audit log can clearly
  distinguish clearnet egress from privacy egress (Principle V — honest
  threat model; clearnet is not privacy).

---

## 5. Inter-Plane gRPC Contract Sketch

Lives at `proto/stargate/v1/control.proto` and `events.proto`. Per
**Principle II**, the control plane is an advisor — none of these RPCs sit
in the request hot path.

### 5.1 Service surface

```
service Control {
  // --- Lifecycle ----------------------------------------------------
  rpc EnableProtocol  (EnableProtocolRequest)  returns (ProtocolStatus);
  rpc DisableProtocol (DisableProtocolRequest) returns (ProtocolStatus);
  rpc RestartSidecar  (RestartSidecarRequest)  returns (RestartResult);

  // --- Configuration reload ----------------------------------------
  rpc ReloadTokens    (ReloadTokensRequest)    returns (ReloadTokensResponse);
  rpc ReloadBlocklist (ReloadBlocklistRequest) returns (ReloadBlocklistResponse);

  // --- Observability (pull) ----------------------------------------
  rpc GetStatus       (StatusRequest)          returns (StatusResponse);

  // --- Observability (push) ----------------------------------------
  rpc WatchEvents     (WatchEventsRequest)     returns (stream SidecarEvent);
}
```

### 5.2 Message shapes (informal)

- `EnableProtocolRequest { Route route; }`  
  `ProtocolStatus { Route route; bool listening; uint32 bound_port; HealthState health; }`
- `RestartSidecarRequest { string sidecar_name; bool drain_existing_streams; }`
- `ReloadTokensRequest { repeated TokenVerifier tokens; uint64 generation; }`  
  The data plane stores only the *current* generation; older generations
  are dropped (Principle III — no per-user history). **(T092 / sol-review
  B5+M1)** the verifier is `HMAC-SHA-256(pepper, token)` (no per-token
  salt); `ReloadTokensResponse` carries `current_generation` so a stale CP
  reconciles and retries. The detailed contract lives in
  `specs/001-tor-route/contracts/control-grpc.md` §"ReloadTokens" and the
  pepper/verifier lifecycle in `specs/001-tor-route/data-model.md` §1.
- `StatusResponse { repeated ProtocolStatus per_protocol; AggregateCounters counters; }`  
  `AggregateCounters` contains only `route × hour-bucket` counts — never
  per-destination or per-token (Principle III, ≥1 h resolution).
- `SidecarEvent { google.protobuf.Timestamp ts; string sidecar; EventKind kind; string detail; }`  
  `EventKind ∈ { STARTED, STOPPED, HEALTHY, UNHEALTHY, RESTARTED, CONFIG_RELOADED, CRASHED }`.
  `detail` is a fixed-vocabulary token (not free text from a sidecar log) so
  events never leak request-level data into the control plane log.

`Route` is an enum: `TOR | I2P | NYM | DIRECT | IPFS_RESERVED_V2`.

### 5.3 Versioning

Package is `stargate.v1`. Additive fields and additive RPCs ship in minor
constitution-aligned increments; breaking changes require bumping to
`stargate.v2` and shipping a migration test (constitution **Inter-Plane
Contract** section). The data plane refuses to handshake if the control
plane reports a higher major version than it understands.

Version is carried at runtime as authenticated gRPC metadata on **every**
RPC, not as a one-shot handshake RPC. The metadata keys
(`x-stargate-proto-major`, `x-stargate-proto-minor`, `x-stargate-capabilities`),
the rejection rule (unknown-major → `FailedPrecondition` before any application
handler runs), the v1 closed capability set, and the interceptor placement
are binding and live in `specs/001-tor-route/contracts/wire-auth.md` §5. T038
(CP server + client) and T045 (DP server + client) install the interceptors;
this §5.3 paragraph is the authoritative pointer and intentionally does not
duplicate the wire shape so a future minor cannot drift the two locations.

### 5.4 Transport and authentication

- Unix-domain socket at `/run/stargate/control.sock`. Permissions enforce
  same-host, same-user access; no TCP grpc surface exists.
- Mutual auth: each plane has an ed25519 keypair generated at first
  `stargate init`, public keys cross-installed in `/etc/stargate/keys/`.
  Handshake uses gRPC's TLS-over-UDS with self-signed certs derived from
  these keys; either side rejects a peer whose pinned public key does not
  match (pin-on-key, not pin-on-cert — see `contracts/wire-auth.md` §3).
- The complete wire contract — X.509 certificate derivation (when, where,
  field values, determinism), peer public-key pinning (byte-equal against
  `/etc/stargate/keys/<peer>.pub`, not CA-chain, not hostname), certificate
  validity policy (`NotBefore = now − 5 min`, `NotAfter = now + 30 days`,
  re-derived on every plane restart, never persisted), UDS authority/SAN
  handling (URI SAN `spiffe://stargate.local/<plane>`; pin is load-bearing,
  SAN is defence-in-depth), and key ownership — is binding and lives in
  `specs/001-tor-route/contracts/wire-auth.md`. This §5.4 paragraph is the
  authoritative pointer; T038/T045/T050 consume that document verbatim and
  add no wire-shape detail of their own.
- A handshake failure is a startup error for the control plane and a
  non-fatal silent degraded state for the data plane (it MUST keep
  forwarding — Principle II).

### 5.5 Failure semantics

Constitution II's condition/behavior matrix is binding. A valid last acknowledged snapshot
supports CP-down admission; missing/corrupt/incompatible state cannot authorize clients.
Automatic reconnect is required, but stale auth content cannot be renumbered into authority.
T132/T159 specify recovery/durable application and both-peer compatibility tests. Events remain
advisory and do not gate dial/forwarding. Invalid peer identity rejects IPC; CP startup reports
failure while a DP with valid auth state continues independent routing. Incompatible CP protocol
must not cause an otherwise valid DP to abandon routing (T153). No per-event journal is permitted.

Snapshots contain auth verifiers/generation, never routing history. GetStatus is an aggregate
counter response, not a source of auth snapshots. See feature 001 data-model.md and its foundation
boundary contract for snapshot and completed-hour publication semantics. T158 implements
completed traffic buckets with a nondecreasing effective UTC hour and seven-day expiry from
bucket start. No current totals or per-client fields cross GetStatus. Its explicit pre-release
semantic transition preserves the v1 field layout and tests Java/Go decoding together;
production CP polling and traffic persistence remain deferred to the admin-UI feature.

---

## 6. SQLite Schema Sketch

Stored in the control-plane container under
`/var/lib/stargate/control.db` (named volume `stargate-control-state`),
opened in **WAL mode** (constitution Tech Stack). Hibernate Panache entities
back each table; Flyway manages migrations (`control-plane/persistence/src/main/resources/db/migration/`).

### 6.1 `enrolled_devices` — devices enrolled via the dashboard (future)

```
CREATE TABLE enrolled_devices (
  id              INTEGER PRIMARY KEY,
  name            TEXT    NOT NULL UNIQUE,
  pubkey          BLOB    NOT NULL,             -- ed25519 device key
  token_hash      BLOB    NOT NULL,             -- HMAC-SHA-256 verifier under the pepper (T092)
  created_at      INTEGER NOT NULL,             -- unix seconds
  last_seen_hour  INTEGER,                      -- rounded to hour-bucket
  revoked_at      INTEGER                       -- nullable
);
-- last_seen_hour is bucketed to satisfy Principle III (≥1h log resolution).
```

> **Amended by T092 / sol-review M1.** Both `pubkey` and `token_hash`
> remain NOT NULL: this table is reserved for the future **dashboard-
> enrollment** feature, the only path that has a device public key. The
> **manual `tokens.yaml` path** (v1) persists to the dedicated
> `configured_tokens` table (§6.6) — it does NOT touch this table, so no
> manual insert requires a nonexistent device key. The `token_hash` column
> holds an HMAC-SHA-256 verifier under the install-time pepper (the prior
> Argon2id comment is superseded; see data-model.md §1.5).

### 6.2 `admin_credentials` — admin login credentials (WebAuthn + ed25519 fallback)

```
CREATE TABLE admin_credentials (
  id                INTEGER PRIMARY KEY,
  kind              TEXT    NOT NULL CHECK (kind IN ('webauthn','ed25519')),
  credential_id     BLOB    NOT NULL UNIQUE,    -- WebAuthn credId or ssh-key fingerprint
  public_key_cose   BLOB,                       -- WebAuthn only
  ssh_pubkey_line   TEXT,                       -- ed25519 fallback only
  label             TEXT,
  created_at        INTEGER NOT NULL,
  revoked_at        INTEGER
);
```

### 6.3 `tor_bridges` — toggleable per Constitution v1 Scope

```
CREATE TABLE tor_bridges (
  id          INTEGER PRIMARY KEY,
  bridge_line TEXT    NOT NULL UNIQUE,          -- full "Bridge ..." torrc line
  transport   TEXT    NOT NULL,                 -- obfs4 | snowflake | webtunnel | direct
  enabled     INTEGER NOT NULL DEFAULT 0,
  added_at    INTEGER NOT NULL
);
```

### 6.4 `aggregate_counters` — routing counters at hour resolution

```
CREATE TABLE aggregate_counters (
  route        TEXT    NOT NULL CHECK (route IN ('TOR','I2P','NYM','DIRECT')),
  hour_bucket  INTEGER NOT NULL,                -- unix-hour
  request_count INTEGER NOT NULL DEFAULT 0,
  byte_count   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (route, hour_bucket)
);
-- No destination, no token id, no sub-hour granularity (Principle III).
```

### 6.5 Operational aggregates (T156)

Replace the per-event journal with completed-hour aggregates under Constitution III.
Feature 001 fields, categories, retention and migration are specified in its
`contracts/foundation-boundaries.md`; T152 supplies the forward V002 migration, completed-hour writer and runtime suppression. No actor, token label,
request identifier, per-event timestamp or arbitrary `detail_json` is permitted. Current
static command errors and health enums are responses, not a retained history.

### 6.6 `configured_tokens` — manual `tokens.yaml` token records (T092)

```sql
CREATE TABLE configured_tokens (
  label TEXT NOT NULL PRIMARY KEY,
  verifier BLOB NOT NULL
);
```

T152's V002 migration preserves only current credentials and deletes unnecessary
creation/revocation/last-seen history. The generation singleton remains unchanged.


> Added by T092 / sol-review M1. Manual tokens carry `(label, verifier)`
> only — no device public key — so they cannot live in `enrolled_devices`
> (§6.1, both `pubkey` and `token_hash` NOT NULL). This table is the
> manual-path home; `enrolled_devices` is reserved for the future
> dashboard-enrollment feature that actually has a device key. Full
> contract + the rejected alternative (nullable `enrolled_devices.pubkey`)
> in `specs/001-tor-route/data-model.md` §1.9. `verifier` is an HMAC tag
> under the install-time pepper, NOT an Argon2id hash (§1.5).

### 6.7 `token_generation` — persisted monotonic generation counter (T092)

```
CREATE TABLE token_generation (
  generation  INTEGER PRIMARY KEY   -- singleton row; the last-assigned generation
);
```

> Added by T092 / sol-review M1. The source of truth for the monotonic
> `ReloadTokens` generation, so a control-plane restart proposes `last + 1`
> instead of restarting at 1 (which would be stale the moment the data
> plane accepted any generation ≥ 1 and would silently revoke every
> client). Read at CP start; bumped after a successful `tokens.yaml` parse.
> If the row is absent (CP DB wiped) the CP reconciles against the data
> plane's reported `current_generation` rather than guessing. Full
> semantics in `specs/001-tor-route/data-model.md` §1.8.

**What is deliberately NOT in this schema** (Principle III):

- No per-request URL, hostname, IP, or timestamp.
- No mapping from token-id to routing choices.
- No DNS resolution cache.
- No browser fingerprint, user-agent, or any other client-derived header.

---

## 7. Sidecar Image Strategy

Each sidecar is referenced by **digest** in compose files (Principle IV). The
control plane offers update prompts when an automated tracker (Renovate)
opens a PR with a newer digest and contract tests pass.

| Sidecar     | Candidate image                                  | Digest pinning                                          |
|-------------|--------------------------------------------------|---------------------------------------------------------|
| Tor         | **`stargate/tor`** — Stargate-built image installing `tor` from `deb.torproject.org` (Tor Project's official Debian apt repository) on a pinned Debian-slim base. Dockerfile lives in `sidecars/tor/`. Tor Project signing key pinned by fingerprint (`A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`, in `sidecars/tor/apt-key.fingerprint`) and verified at build time. Resolved by `specs/001-tor-route/` §Clarifications 2026-05-17 Q1. | **Pinned by sha256 digest per FR-015**: the Debian-slim base (`debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df`) and build inputs remain pinned in reviewed source. Source `compose/docker-compose.local.yml` remains source-build configuration and does not contain the final digest of its built Tor image. T081 generates separate digest-pinned Local preview Compose and binds the final Tor image digest to reviewed source in the signed release manifest; completed-v1 profile bundles likewise pin distributed images in derived Compose. No final digest is written back into source or a reviewed tag. Source invariants remain cross-checked by `tests/contract/compose/` (T015) and `tests/contract/security-decisions/tor_entry_test.sh` (T017). The Debian build inputs (every `apt-get install` package incl. `tor`'s transitive closure) are pinned to an immutable `snapshot.debian.org` run with explicit `=version` pins and retained sha256 hashes (T099), cross-checked by `tests/contract/security-decisions/tor_build_inputs_test.sh` and verified stable across cold rebuilds by `tests/reproducibility/tor_sidecar_manifest_test.sh`. The trust rationale and rotation procedure are in `SECURITY-DECISIONS.md` (T017, T099). |
| i2pd        | `purplei2p/i2pd` (upstream maintainer)           | resolve and pin before the first artifact for its profile ships |
| Nym client  | `NEEDS CLARIFICATION: Nym's official Docker distribution status is not resolved in this spec; either pin an upstream image if maintained or build from a pinned `nymtech/nym` source tree.` | `NEEDS CLARIFICATION` |
| WireGuard   | `linuxserver/wireguard`                          | resolve and pin before the first artifact for its profile ships |
| Base (data-plane, control-plane runtime images) | Distroless static (Go) and `quarkus.io/builder`-derived | `NEEDS CLARIFICATION` |

`NEEDS CLARIFICATION` entries here are not invented digests. They are
flags that the maintainer must resolve, with an `SECURITY-DECISIONS.md`
entry per sidecar covering: who maintains the image, how its provenance is
verified, and what the contract test suite asserts about it.

**Trust rationale**: recorded in `SECURITY-DECISIONS.md` (T017 Tor
entry — apt-key fingerprint, digest pins, transitive-dependency
closure, residual risk). The inline narrative above is the historical
pre-entry framing; the entry is the authoritative source.

---

## 8. Sidecar Config Generation

**Decision**: the control plane generates sidecar config files at startup
and on each relevant change, writing into a per-sidecar named volume that
the sidecar reads at container start (or SIGHUP-reload, where supported).
Sidecar containers themselves are run with **read-only root filesystems**;
the config volume is the only writable mount, and it is mounted at the
sidecar's expected config path.

**Why this approach** rather than templated-at-compose-up or
baked-into-image:

- Compose-up templating cannot react to UI-driven changes (Tor bridges
  toggling on/off without a stack restart) without secondary tooling, which
  would duplicate control-plane logic.
- Baked-in static configs cannot express user-configurable knobs at all
  (bridges, bridge transport selection, custom Nym gateway choice in v1.5+).
- A control-plane-driven generator centralises the privacy-sensitive
  rendering logic in one auditable place (Principle VI).

**What each sidecar gets**:

- **Tor** — v1 image-baked `torrc` uses a private Unix `SocksPort` with
  `IsolateClientAddr IsolateSOCKSAuth`, a Tor-private `ControlSocket`,
  `CookieAuthentication 1`,
  `ClientUseIPv6 0`, `AvoidDiskWrites 1`, plus zero or more `Bridge` lines
  and `UseBridges 1` when enabled. Toggling bridges writes a new `torrc`
  and restarts the Tor container (SIGHUP is not always sufficient for
  bridge-set changes — see §11).
- **i2pd** — `i2pd.conf` rendered with HTTP proxy on 4444, SOCKS proxy on
  4447, SAM bridge disabled in v1, transit traffic disabled (we are a
  client, not a router contributor — that is opt-in, deferred), and
  `floodfill=false`.
- **Nym client** — initialised via `nym-client init` against the user's
  chosen gateway (a v1 default gateway is selected at init; gateway choice
  UI is v1.5+). The init artefacts are persisted in the Nym named volume;
  the control plane only injects connect-time overrides, not the keypair.

**Privacy note** (Principle III): no rendered config contains data derived
from per-user routing decisions. Config inputs are: the set of enabled
routes, the list of Tor bridges, and static defaults. Per-request data
never reaches sidecar config.

`NEEDS CLARIFICATION`: Nym v1 default-gateway selection policy — pin one
gateway, randomise from a vetted list at install, or require user choice on
first run? Defer to feature spec `specs/00X-mixnet-route/`.

---

## 9. `scripts/stargate init` Behaviour

`init` is the entry point for fresh installs. It is **idempotent**: a second
invocation against an already-initialised stack detects existing state and
either exits cleanly with status `0` or — given `--force` — prompts before
destructive change.

### 9.1 Steps

1. **Preflight**
   - Verify `docker` and `docker compose v2` are present.
   - Verify the user has permission to talk to the Docker socket.
   - Detect existing Stargate volumes (`stargate-control-state`,
     `stargate-keys`, `stargate-ipc`, sidecar volumes); if any exist, switch
     to existing-stack mode.
2. **Profile selection**
   - `--profile {local,lan,vps}`; default `local`. For `lan` and `vps`,
     prompt for WireGuard peer configuration before any container is started.
3. **Key generation**
   - Generate inter-plane ed25519 keypairs (data plane + control plane).
   - Generate the 32-byte bearer-token pepper (`openssl rand -bytes 32`)
     shared by CP and DP for HMAC-SHA-256 verifier computation (T092;
     `specs/001-tor-route/data-model.md` §1.7). Written to
     `/etc/stargate/keys/pepper.key` in the `stargate-keys` volume, mode `0640`,
     group `stargate-ipc`, so both planes can read it. Never regenerated
     unless the operator explicitly rotates.
   - Generate WebAuthn relying-party id and a one-time admin enrollment
     code (printed once, never stored).
   - Write into `stargate-keys` volume with `0600` perms.
4. **Compose up**
   - `docker compose -f compose/docker-compose.<profile>.yml up -d`.
   - In the current Local Tor slice, confirm all four service processes are
     running, then retry the isolated observer's authenticated `--check-ready`
     query until it returns READY. Use one bounded window after Compose up
     (default 300 s, operator-overridable), not a separate window per sidecar.
     Tor authentication alone or an open DP listener does not establish READY.
     Docker healthchecks and raw container log tails are disabled by
     Constitution III; the operator gets a fixed timeout status and the
     containers remain available for inspection.
5. **Verification**
   - The current Local Tor installer checks only the DP's loopback TCP
     listener after observer READY. Downstream contract and live tests cover
     authenticated SOCKS forwarding and browser behavior; the installer
     does not claim those properties from a TCP connect.
6. **Status table**

   The current Local slice reports the data plane, control plane, Tor sidecar
   and Tor observer. The following wider multi-route table and admin URL are
   future feature targets, not current installer output.

   ```
   ┌──────────────┬──────────┬────────────┬──────────────────────┐
   │ Component    │ Status   │ Bind       │ Notes                │
   ├──────────────┼──────────┼────────────┼──────────────────────┤
   │ Data plane   │ HEALTHY  │ 127.0.0.1  │ ports 8881–8885      │
   │ Control plane│ HEALTHY  │ 127.0.0.1  │ admin UI on :8443    │
   │ Tor sidecar  │ HEALTHY  │ internal   │ SOCKS5 over UDS      │
   │ i2pd sidecar │ STARTING │ internal   │ tunnel build pending │
   │ Nym sidecar  │ HEALTHY  │ internal   │ gateway: <id>        │
   └──────────────┴──────────┴────────────┴──────────────────────┘

   Admin enrollment URL: https://127.0.0.1:8443/enroll?code=XXXX
   This code is shown ONCE and expires in 15 minutes.
   ```
7. **Exit**
   - `0` on success, non-zero with a clear error code on failure
     (preflight=10, key-gen=20, compose=30, readiness=40, verify=50).

### 9.2 Failure modes

- **Docker missing** → exit 10 with a link to install docs.
- **Existing stack detected without `--force`** → exit 0 after printing the
  status table for the existing stack.
- **Readiness timeout** → exit 40, leave containers up and preserve user
  data. In-progress observer samples and the two-second retry interval can
  make the return occur just after the configured window. A 300-second
  budget improves cold-start tolerance but does not guarantee Tor bootstrap.

### 9.3 Idempotence guarantees

- Re-running `init` against a healthy stack: no-op (prints status table).
- Re-running `init` against an unhealthy stack: prints status table and
  exits non-zero; explicit `init --repair` is the documented way to
  regenerate missing config without touching keys or DB.
- `init` MUST NOT regenerate inter-plane keys if `stargate-keys` is
  populated — doing so would invalidate enrolled devices.

---

## 10. Error Response Contract

A supported route returns its protocol-specific fixed failure response. Tor
port 8881 supports authenticated SOCKS5: RFC 1928/1929 binary failures only.
HTTP first byte `C` is refused silently before authentication or upstream dial
under the T172 contract implemented by T173. The HTML template below is a
future HTTP renderer format without a Tor ingress claim. Other routes require
separate ingress contracts. No response may include upstream IPs, sidecar
versions, exit identifiers, DNS answers or request-specific text.

### 10.1 Error codes (proxy-internal, also emitted as response header)

| Code              | Meaning                                                    | HTTP status | SOCKS5 reply |
|-------------------|------------------------------------------------------------|-------------|--------------|
| `ROUTE_DISABLED`  | The port's route is administratively disabled              | 503         | REP `0x03` (Network unreachable; reuses `ROUTE_DOWN`'s reply path) |
| `ROUTE_DOWN`      | Upstream sidecar unreachable (no TCP connection)            | 502         | REP `0x03` (Network unreachable) |
| `ROUTE_TIMEOUT`   | Upstream did not respond within the configured timeout     | 504         | REP `0x06` (TTL expired) |
| `ROUTE_REFUSED`   | Sidecar accepted the SOCKS handshake but refused the target| 502         | REP `0x04` (Host unreachable) |
| `AUTH_REQUIRED`   | Bearer token missing or invalid (introduced by `specs/001-tor-route/` FR-006) | future HTTP format only; no Tor HTTP ingress | sub-negotiation `0x01 0xFF` (RFC 1929 §2; not RFC 1928 §6) |
| `BIND_REFUSED`    | Bind-safety check would publish on a non-tunnel interface  | 500 (only at start-up; never per-request) | n/a (start-up only) |

Authoritative source for the post-auth `REP`-byte rows is `specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)"`; for `AUTH_REQUIRED`'s sub-negotiation form, the Tor SOCKS auth contract.
The HTTP-status column describes only the future renderer format, not Tor port 8881.

### 10.2 Response body template (HTML, for browser display)

```
<!doctype html><meta charset=utf-8>
<title>Stargate: route unavailable</title>
<h1>Route unavailable</h1>
<p>The {ROUTE_LABEL} route is currently not serving requests.</p>
<p>Code: {CODE} · Reference: {LOCAL_REFERENCE_ID}</p>
<p>See the admin dashboard for details.</p>
```

Permitted substitutions:

- `{ROUTE_LABEL}` ∈ `{"Tor", "I2P", "Mixnet", "Direct"}` — fixed vocabulary.
- `{CODE}` — one of the codes in §10.1.
- `{LOCAL_REFERENCE_ID}` — a 64-bit random id, **not derived from request
  data**, used only to correlate this response with the corresponding
  aggregate-counter entry. Discarded after the hour-bucket flush.

Forbidden in the body or headers: target hostname, target IP, upstream
sidecar address or version, exit-relay identifier, sidecar log line, DNS
record content, Tor circuit identifier, request method/path, byte counts.

### 10.3 Contract test pattern

`tests/contract/error-template/` tests the future HTTP renderer directly,
without claiming Tor-port ingress. It captures each rendered response and asserts:

1. Status code matches the table.
2. Body matches the template byte-for-byte after substitution of the three
   permitted fields (`{ROUTE_LABEL}`, `{CODE}`, `{LOCAL_REFERENCE_ID}` per
   §10.2 and `specs/001-tor-route/contracts/error-template.md` §"Response
   body").
3. Response headers contain only: `Content-Type`, `Content-Length`,
   `Cache-Control: no-store`, `X-Stargate-Error: <CODE>`. Any other
   header (`Server`, `Via`, `X-Forwarded-*`, etc.) fails the test.
4. The body, headers, and `X-Stargate-Error` value do not contain any
   substring from a curated leak corpus (test IPs, test hostnames, test
   circuit ids).

Adding a new error code requires adding a contract-test row; the test suite
is the canonical list (Principle VII).

---

## 11. Hot Reload vs Restart Matrix

Effect of each change category. "Live" = applied without dropping
established connections. "Drains" = applied after existing streams complete
or a timeout. "Restart" = full container restart.

| Change                                  | Component affected                | Effect                                                                  |
|-----------------------------------------|-----------------------------------|--------------------------------------------------------------------------|
| Add/remove bearer token                 | Data plane (token list)           | **Live** via `ReloadTokens` RPC; new generation atomic-swapped           |
| Enable/disable a route                  | Data plane (listener for port)    | **Drains** — port stops accepting new connections; existing finish or time out |
| Change route↔sidecar binding            | Data plane                        | **Restart** of data plane — port-to-upstream is fixed at startup (Principle I) |
| Change a listening port number          | Data plane                        | **Restart** of data plane                                                |
| Add/remove a Tor bridge                 | Tor sidecar                       | **Restart** of Tor sidecar — `torrc` rewritten by control plane         |
| Toggle bridges on/off globally          | Tor sidecar                       | **Restart** of Tor sidecar                                               |
| Update sidecar image digest             | Affected sidecar                  | **Restart** of that sidecar (other planes untouched)                     |
| Update data-plane image                 | Data plane                        | **Restart** of data plane (drops in-flight streams)                      |
| Update control-plane image              | Control plane                     | **Restart** of control plane only — routing unaffected (Principle II)    |
| Add/revoke admin WebAuthn credential    | Control plane DB                  | **Live** — control plane reads on every admin request                    |
| Reload static blocklist                 | Browser extension + data plane    | **Live** via `ReloadBlocklist` RPC; extension polls on its own schedule  |
| Profile switch (local→lan, etc.)        | Whole stack                       | **Restart** of stack (different compose file)                            |

The matrix is encoded in the admin UI: each settings change displays its
disruption tier ("Live", "Drains existing connections", "Requires restart of
X") before the user confirms.

---

## 12. Build Pipeline

### 12.1 Data plane (Go)

- Toolchain pinned via `go.mod` `toolchain go1.x.y` directive; CI verifies.
- Build command (illustrative — actual lives in `Makefile` or `justfile`):

  ```
  go build \
    -trimpath \
    -buildvcs=false \
    -ldflags='-s -w -buildid= -X main.version=$(VERSION)' \
    -o dist/stargate-proxy \
    ./cmd/stargate-proxy
  ```

- `CGO_ENABLED=0`, `GOFLAGS=-mod=readonly`.
- Reproducibility tier: **byte-reproducible** (Principle VI). Verified by
  `tests/reproducibility/` building twice in clean containers and `cmp`-ing.

### 12.2 Control plane (Quarkus)

- **JDK 25 LTS** pinned in `control-plane/pom.xml` via
  `<maven.compiler.release>25` plus a CI matrix lock. Concrete JDK
  distribution (Temurin / Liberica / Zulu / Corretto) is interchangeable
  for bytecode reproducibility; the CI build pins one for the release
  artefact.
- **Quarkus 3.40 LTS** pinned in the parent POM via the
  `<quarkus.platform.version>` property; managed by the Quarkus platform
  BOM. Subsequent Quarkus upgrades follow the same digest-promoted flow
  as sidecar image updates (Principle IV).
- JVM bytecode reproducibility via `reproducible-build-maven-plugin`
  configured at the parent POM. `mvn -B clean package -DskipTests=false`.
- **Completed-v1 native build**: `mvn package -Pnative`, with
  `-Dquarkus.native.reproducible-build=true` and a pinned
  `quay.io/quarkus/ubi-quarkus-mandrel-builder-image` digest for the
  **Mandrel 25** (JDK 25) builder, matching the Quarkus 3.40 LTS
  compatibility matrix. The 001 feature-preview is JVM-only; the native
  artifact and its verification remain required before completed v1.
- Reproducibility tier: **JVM bytecode = byte-reproducible**;
  **completed-v1 native-image = best-effort** with expected variations
  enumerated in `BUILD-DIFFS.md` (Principle VI). Completed-v1 CI runs both
  builds twice and diffs; expected-variation bytes are masked before
  comparison. The feature-preview makes no native reproducibility claim.

### 12.3 Browser extension

- Sources are pure JavaScript / HTML / CSS — no build step in v1 (avoids
  pulling in npm supply-chain risk on a privacy-critical component).
- Packaging: deterministic zip with `SOURCE_DATE_EPOCH=0`, entries sorted
  lexicographically, no extended attributes, fixed compression level.
  Reference packaging script in `extension/package.sh`.
- Reproducibility tier: **byte-reproducible** (Principle VI).

### 12.4 Container images

- Multi-stage builds; final stage is `gcr.io/distroless/static-debian12`
  for the Go data plane and a Quarkus-supported minimal base for the
  control plane. Both pinned by digest.
- Built with `docker buildx build --provenance=true --sbom=true` so SBOM
  and provenance attestations ship with each release.
- The Tor sidecar's Debian build inputs are pinned to an immutable
  `snapshot.debian.org` run with explicit `=version` pins (T099), so a
  clean rebuild selects a byte-stable package manifest, including Tor's
  transitive closure. For the 001 feature-preview, T081 prepares a separate
  digest-pinned Local release Compose and signed derived manifest; source
  `compose/docker-compose.local.yml` remains source-build configuration,
  and the reviewed source commit is not rewritten with generated digests.
  Completed-v1 profile bundles likewise pin distributed images in derived
  Compose bound to reviewed source by their signed release manifest. Expected
  image-digest variance is documented in `BUILD-DIFFS.md` (Principle VI).
  Preparing the workflow does not authorize tag creation or publication.

### 12.5 Release artefacts

The 001 deliverable is an **internal feature-preview**, not completed v1 or a public release. Its distributed inventory is Local/JVM/Linux amd64: DP, JVM CP, Tor and observer images, reproducible extension ZIP, complete fast-jar CP payload, signed release data and audit source. Candidate and signed manifest carry `channel: feature-preview`; prepared GitHub Release metadata carries `prerelease: true`. T081 implementation does not authorize tag creation or publication. A public preview is the first public release and requires Constitution Governance and VIII external-human review.

The preview retains the arm64 cross-build only as internal evidence marked unvalidated; it is not a distributed asset or support claim. Completed v1 still requires native CP, Local/LAN/VPS profiles and runtime-verified supported architectures.

The 001 feature-preview artifacts are prepared from an explicitly selected existing immutable `v<x.y.z>` tag and include:
- `stargate-proxy_linux_amd64`; the unvalidated arm64 cross-build remains internal evidence and is not distributed.
- The complete JVM `quarkus-app/` fast-jar tree in `stargate-control.tar`.
  `quarkus-run.jar` is a thin launcher and cannot be delivered alone.
- `stargate-extension.zip`, from unchanged `extension/package.sh` in the pinned
  amd64 archive environment, with its actual input/output identities.
- Four amd64 OCI runtime images (DP, JVM CP, Tor, observer), retaining SBOM and
  provenance blobs; generated `compose.json` pins their registry digests.
- Full source/install material and a source-file manifest, plus a cosign keyless
  signed release manifest/bundle bound to exact source, artifacts and evidence.
  `init --release-dir` runs from the exact verified source checkout; release data
  never supplies executable code or arbitrary Compose policy.

Preparation has no publication/signing authority. Protected manual promotion checks
retained immutable artifact identity, detached same-repository evidence and exact
workflow/repository/ref/OIDC identity before publication. T078/T079, applicable live
checks and Constitution VIII external-human review remain separate publication
prerequisites. No source or tag is rewritten. See `docs/releasing.md` (T081).

Completed v1 still requires native CP binaries, Local/LAN/VPS Compose profiles, the full supported runtime architecture matrix and applicable verification evidence. This preview does not discharge those obligations or claim arm64 runtime evidence.

---

## 13. Backup, Restore, Decommission

`scripts/stargate {export,import,wipe}`.

### 13.1 `export`

Produces a single passphrase-encrypted file:
`stargate-backup-<hostname>-<unix>.tar.gz.age`.

Encryption: **age** with a passphrase recipient (scrypt KDF). Chosen for
simplicity and a small, auditable implementation; `NEEDS CLARIFICATION`
if the maintainer prefers `gpg --symmetric` for ecosystem familiarity.

The backup tarball contains:

- `control.db` (SQLite, copied with `.backup` to be consistent).
- Inter-plane keys from `stargate-keys` volume.
- Sidecar persistent state that is meaningful across reinstalls:
  - Tor: the sidecar's `DataDirectory` is included, **including the
    entry-guard state file**. Rationale: Tor's guard design assumes
    persistence; cycling guards faster than the natural rotation period
    increases statistical exposure to malicious guards. `export` /
    `import` therefore preserve guards; `wipe` discards them. See
    `THREAT-MODEL.md` §4.2 "Stargate-specific notes" and §3.3 (backup
    encryption is load-bearing for the linkability property this
    creates). No other Tor state is intentionally persisted; the
    `AvoidDiskWrites 1` torrc directive minimises incidental writes
    beyond guards.
  - i2pd: router info and netdb cache (functional, low-sensitivity).
  - Nym: client identity keypair (otherwise re-enrollment is required).
- `metadata.json` describing schema versions and Stargate release that
  produced the backup.

Excluded from the backup:

- Logs (none should exist beyond aggregate counters; verified at export).
- Container images themselves (re-pulled by digest on import).
- Anything from the browser extension (lives client-side; Principle III).
- The user's WebAuthn private keys (live in their authenticators).

### 13.2 `import`

- Requires a target stack initialised with `stargate init --profile <p>` but
  with empty state. Refuses to overwrite a populated stack.
- Prompts for the export passphrase.
- Verifies the backup's metadata schema version is compatible with the
  installed Stargate version; refuses cross-major imports without an
  explicit `--migrate` flag and a documented migration.
- Stops the running stack, restores volumes, starts the stack, runs the
  same verification step `init` runs.

### 13.3 `wipe`

- Removes: all stargate-prefixed Docker named volumes, the inter-plane
  keys directory, the compose stack (`docker compose down -v`), and the
  generated compose `.env` files. After `wipe`, no Stargate state remains
  on the host.
- Cannot remove (and reports this explicitly):
  - Browser extension storage (client-side; user must wipe in-browser).
  - WireGuard peer configs on remote devices.
  - Cached Docker images (kept by default to make reinstall fast;
    `wipe --images` removes them).
  - System-level logs (journald, etc.); we cannot guarantee absence of
    references in OS-managed logs.
- Requires `--yes` to proceed; otherwise prints the deletion plan and
  exits non-zero.

`wipe` reports a static confirmation directly to the invoking operator. It must not retain
an identifying per-event journal before or after destroying state. Recovery/export contracts
must account for legacy logs and backup copies under T152's explicit cleanup limits.

---

## 14. Browser Extension Architecture

### 14.1 Manifest

- **Manifest version**: **v2**, with Gecko `strict_min_version: "153.0"`. Firefox 153 adds the
  native `publicSuffix` API and document-bound metadata on `proxy.onRequest` and
  `webNavigation`; both are required for T136's isolation guarantee. Older Mullvad Browser builds
  reject the extension instead of receiving a weaker compatibility path. Mullvad Browser Alpha
  16.0a11 / Gecko 153.2.0 is the development reference, but v1 release is gated until the stable
  Mullvad Browser channel uses Gecko 153 or newer and still supports MV2. If that release drops
  MV2, the proxy decision path requires a new design and Constitution-level review.
- **Background lifetime**: the MV2 background page is persistent. The proxy and blocking listeners
  are the fail-closed authority for every protected request; Firefox must not suspend that
  authority and temporarily resume browser-default routing. A non-persistent event page can expose
  a fallback window while that authority is absent. T157 tests a held initialization dependency;
  T155 retains browser-launch/session-restore coverage on the stable supported browser.

### 14.2 Permissions and justifications

| Permission                              | Why                                                                 |
|-----------------------------------------|---------------------------------------------------------------------|
| `proxy`                                 | Set per-request proxy via `proxy.onRequest` listener (core function)|
| `<all_urls>` (host permission)          | The proxy listener must see all outbound URLs to apply mapping      |
| `storage`                               | Persist per-domain route preferences, blocklist and the random browser-profile isolation id in `storage.local` |
| `webRequest`, `webRequestBlocking`      | Cancel a protected request when routing prerequisites or the applied proxy fail validation; also block known DoH/DoT endpoints as defense-in-depth (the primary DoH/DoT/HTTP-3 guarantee is the externally verified profile per §14.5, not this rule) |
| `webNavigation`                         | Bind committed top-level and child `documentId` values through `parentDocumentId`; avoids destination, iframe-site and tab-reuse fallbacks |
| `publicSuffix`                          | Firefox gates the `browser.publicSuffix` namespace behind this permission; without it the native `publicSuffix.getDomain()` registrable-domain authority for the isolation site (§14.3, Firefox 153+) is not injected and every DNS-site derivation fails closed |
| `privacy`                               | Read WebRTC state via `privacy.network.peerConnectionEnabled` — the only hardening surface Firefox's stable WebExtensions API exposes (sol-review B4; §14.5) |
| `management` (optional)                 | Enumerate foreign extensions for the §14.5 allowlist inventory. Retained for v1 per the foreign-extension decision (THREAT-MODEL §2.7); detection, not prevention. If a future release drops the inventory, this permission is removed. |
| `notifications` (optional)              | Local desktop notifications only (Constitution Notifications scope) |

No `tabs`, no `history`, no `bookmarks`, no `cookies`, no `identity` —
these are not required and would be additional privacy attack surface.

### 14.3 `proxy.onRequest` routing sketch

For each request:

1. Classify the requested destination. A requested `.onion` hostname selects the Tor route in this
   feature regardless of whether its initiating top-level site is clearnet or onion; the initiating
   site never replaces the destination for route classification.
2. Look up routing decision in this order:
   - Anti-pattern blocklist (e.g., `.onion.to`, `.onion.ws` clearnet
     gateways): if matched, return an explicit block decision and surface
     a UI notice — never proxy.
   - Explicit per-domain rule from `storage.local`.
   - Hostname-suffix defaults: `.onion` → Tor, `.i2p` → I2P.
   - Default route for new domains (user-configured; reasonable default
     "Tor" for Mullvad Browser, "ask" for first-encounter domains —
     `NEEDS CLARIFICATION` whether v1 prompts on first-encounter or
     applies the default silently).
3. Resolve the initiating top-level site under
   `specs/001-tor-route/contracts/foundation-boundaries.md` §“Browser SOCKS isolation identity —
   T136”. Top-level navigation uses its request URL; frame-zero subresources use a valid present
   `documentUrl` bound to `documentId`; nested frames and tab-associated workers use only exact
   ancestry established by `webNavigation.onCommitted` `documentId`/`parentDocumentId` values.
   `documentUrl` precedes `originUrl`, but `originUrl` alone is not
   sufficient because it can identify an intermediate stylesheet. There is no subresource
   destination fallback. Unknown/detached/opaque context produces identity-unavailable; T157 owns
   cancelling the protected request and proving no browser/system fallback.
4. Build the authenticated-device/browser-profile/site isolation tuple. DNS sites use Firefox
   153's native ICANN-and-PRIVATE `publicSuffix.getDomain()` result with unknown/plain suffixes
   refused; complete onion and canonical IP identities remain whole. Scheme and port do not enter
   the site. The exact tuple and HMAC encoding are the T136
   boundary contract; the fixed 68-byte `sg1:` username reveals neither the site nor bearer.
5. `proxy.onRequest` creates one bounded request record before asynchronous work and returns a
   non-rejecting Promise. The record binds Firefox's `requestId` plus the route-relevant request
   fields to one decision. `webRequest.onBeforeRequest`, registered with `['blocking']`, consumes
   that exact decision after the proxy event, revalidates the token/hardening/document generations
   and the applied proxy endpoint, and deletes the record. Missing, mismatched, stale or evicted
   records cancel protected targets. A redirect that reuses a request id first replaces the record
   from its new proxy event; retries and subresources get current decisions rather than inherited
   authorization.
6. For an allowed protected request, return an array containing the SOCKS5 proxy descriptor and a
   terminal `null`. The descriptor points at the chosen port (`127.0.0.1:888x`) with the derived
   isolation username, device bearer token as password and **`proxyDNS: true`** (Firefox SOCKS5h
   equivalent). Terminal `null` ends Firefox's failover chain, so an unavailable/refusing sidecar
   cannot fall through to browser/system proxy settings or Direct. A protected prerequisite
   failure returns no Direct/other-route descriptor and the blocking listener returns
   `{cancel: true}` before dispatch. Intentional non-protected Direct remains separate. No proxy
   callback exception/rejection may escape, because Firefox otherwise preserves default proxy
   behavior.

### 14.4 `storage.local` layout

```
{
  "schemaVersion": 1,
  "device": {
    "name": "alice-laptop",
    "tokenRef": "vault-managed key id, not the token itself"
  },
  "routes": {
    "default": "TOR",
    "byDomain": {
      "example.com": { "route": "DIRECT", "addedAt": <hourBucket> },
      "duckduckgo.com": { "route": "TOR" }
    },
    "askOnFirstEncounter": true
  },
  "blocklist": {
    "version": <generation>,
    "patterns": [ "*.onion.to", "*.onion.ws", "*.onion.cab", "..." ]
  }
}
```

T205 removes the obsolete persistent hardening failure record. At background startup,
`storage.local.remove('hardening')` removes only that legacy key, without reading its
shape or rewriting device credentials, isolation profile identity or route settings.
Cleanup failure leaves initialization unknown and protected routing closed; no durable
migration marker, replacement event/hour/error record or raw diagnostic is created.
API-visible deletion does not establish physical erasure or removal of external copies.

Bearer tokens themselves SHOULD be stored in the browser's OS keyring via
the WebExtensions password-storage path if available; otherwise in
`storage.local` with a clear UX warning. **Resolved-for-v1 by FR-019 +
`specs/001-tor-route/research.md` §6**: Firefox ESR (Mullvad Browser's
engine) exposes no credential-grade storage API to extensions in the v1
release window, so the token is persisted to `storage.local` with the
canonical warning text pinned verbatim in
`specs/001-tor-route/data-model.md` §5.1 (asserted byte-for-byte by
T056's inline test). A future feature may revisit this if WebExtensions
on Firefox ESR gain a credential-grade storage API; until then the
residual filesystem-read risk is acknowledged under THREAT-MODEL §3.1
(local profile assumes local code execution is already game-over).

### 14.5 Browser hardening — externally verified precondition

**Enforcement boundary (amended by T091; Constitution Principle III bullet
3 — pre-release amendment, no version bump).** Stable Firefox WebExtensions APIs do NOT expose the DoH
(`network.trr.mode`), DoT (`network.dns.over_tls.*`), or HTTP/3
(`network.http.http3.enable`) preferences. The pre-T091 wording asserted an
extension guarantee that could not be implemented (sol-review finding B4),
risking false assurance from a green mock over invented prefs or a
fail-open implementation. The amended boundary has three parts.

**Part 1 — Hardened target-browser configuration is an externally verified
precondition** for non-Direct routing, verified out-of-band against a test
profile that models the target browser's hardened defaults (Mullvad Browser
by default), NOT via the WebExtension API. The required profile state:

- DoH off (`network.trr.mode = 5`).
- DoT off (no `network.dns.over_tls.*` family present, or all-false — a
  defense-in-depth check against a future ESR adding DoT).
- HTTP/3 / QUIC off (`network.http.http3.enable = false`).
- WebRTC fully disabled. The Firefox pref verified out-of-band in
  `prefs.js` is `media.peerconnection.enabled = false` (the older
  `webRTCIPHandlingPolicy = disable_non_proxied_udp` is insufficient —
  it blocks non-proxied UDP but leaves SDP/ICE candidate gathering
  reachable over the proxy, leaking local-network info to the remote
  peer). The extension's runtime gate (Part 2) reads the same state via
  the stable WebExtensions API `browser.privacy.network.peerConnectionEnabled`,
  which wraps this pref — the API path is NOT itself a `prefs.js` key.

Verification is performed by the release-cadence live-e2e test
`tests/live-e2e/mullvad-browser-hardening/` against a test profile that
models the target browser's hardened defaults (transport-relevant; not
hermetic — see `docs/process/workflow.md` §"Live end-to-end
verification"). The test reads the profile's `prefs.js` `user_pref(...)`
entries; note that hardened distributions sometimes enforce prefs via
`lockPref`/`policies.json` (not written to `prefs.js` as `user_pref`), so
the test profile must be one that writes these prefs as `user_pref` (or
the test must be extended to read effective pref state via Marionette —
deferred to Phase 5+). A green Node
unit over invented prefs is explicitly NOT evidence for these four
surfaces.

**Part 2 — The extension gates only surfaces Firefox's stable API
truthfully exposes:**

- WebRTC: `browser.privacy.network.peerConnectionEnabled` (read at startup
  and on browser restart; the extension refuses to route non-Direct if
  this is not `false`).
- SOCKS5h: `proxy.ProxyInfo` with `proxyDNS: true` and the SOCKS5
  username/password set per FR-002/FR-003.

The extension does NOT claim to read or write the DoH/DoT/HTTP-3 prefs.
When T034b lands (step-17 refine, after this amendment is accepted), Node
units will be retained only for logic over API values that truly exist
(`peerConnectionEnabled`, `proxyDNS`, the SOCKS5 username/password
computation) — not over invented pref shapes. No Node unit exists in the
tree at the start-phase commit (verify.sh `extension-tests` gate SKIPs).

**Part 3 — Foreign-extension inventory (decision, T091 acceptance #5):
retained for v1.** Enumerating other extensions requires the `management`
permission (§14.2). The inventory is **detection, not prevention** — the
user must remove a disallowed extension; Stargate cannot stop it running
in the same profile (THREAT-MODEL §2.7). The real-browser live-e2e test
exercises the inventory against a profile with a known allowlisted
extension (Mullvad Browser default uBlock Origin) and a known disallowed
one. T051's manifest edit to request `management` lands at the step-17
refine of the dependent tickets (T091 acceptance #6); until then T051
remains `pending`, `blocked_by: [T091]`.

**Failure UX.** The runtime gate is WebRTC only (the one surface the
stable WebExtensions API exposes — Part 2). On `peerConnectionEnabled !=
false` at runtime (browser startup and on restart), the extension:

1. Raises a notification naming WebRTC as the runtime-blocked surface
   and the remediation ("WebRTC is enabled — set `media.peerconnection.enabled`
   to false in your Mullvad Browser profile"). It is transient (Gecko rejects
   `requireInteraction`; T195); the routing block and the popup's blocked state
   are what persist. The notification
   must NOT claim a runtime block on DoH/DoT/HTTP-3; it states those
   surfaces are release-cadence-verified (Part 1) and names their drift as
   accepted residue (THREAT-MODEL §5.4/§5.5).
2. Begins with `hardeningOk = false` and `auditHardening.status = 'unknown'`.
   Only successful targeted legacy-key removal and an API-measured disabled value
   set `hardeningOk = true`. Measured enabled, unknown/unavailable reads, pending
   initialization and failed cleanup keep protected routing closed. Direct routes
   remain separate. Results are finite current volatile state, with no stored history.
   A delayed older audit cannot override a newer invocation's result. Startup/restart
   remains the production cadence; T190 owns any per-request audit-policy decision.
3. Delivers finite latest-check status through an opt-in `hardening` field in the
   existing `stargate:getRoute` reply (`includeHardening: true`). Its values are
   `enabled`, `disabled` or `unknown`. The popup presents it separately from the
   main-navigation decision. This is no signed export, dashboard or history stream.

Notifications are explanatory only, and their rejection cannot authorize routing or
retain arbitrary error detail. Enforcement is the protected-request gate and asynchronous
blocking cancellation described in §14.3; the notification does not cancel a request.
The popup reports a committed main-navigation cancellation as Blocked, distinguishes it
from intentional Direct, and retains mixed-request and unverified-connection scope.
T205 absorbs T117's complete §14.4/§14.5 reconciliation; its historical acceptance is
superseded without rewriting completed T034b/T055 lineage.

Non-Direct routing is **fail-closed at runtime against WebRTC**. The
DoH/DoT/HTTP-3 surfaces are release-cadence-verified (Part 1) plus
defense-in-depth `webRequest` blocklist (§14.2); their post-verification
drift is accepted residue (THREAT-MODEL §5.4/§5.5) — there is no
runtime signal that catches a pref flip between live-e2e runs, because
the stable WebExtensions API does not expose those prefs (sol-review B4).

**What changed from the pre-T091 wording.** The DoH/DoT/HTTP-3 prefs are
no longer claimed as extension-readable; their guarantee moves to the
externally verified profile (Part 1, release-cadence). WebRTC remains
extension-gated (the API is real) and is the sole runtime fail-closed
surface. The foreign-extension inventory is explicitly retained (with
`management`), not silently assumed. The pre-T091 "confirmed for this
session" runtime clause is removed — it asserted a per-session binding the
mechanism cannot deliver (stargate-redteam M1, 2026-07-12).

### 14.6 Anti-pattern blocklist

- Data structure: a JSON array of hostname-suffix patterns, versioned by a
  monotonic `generation` integer.
- Delivery: shipped inside the extension package (no fetch from a remote
  URL — Principle III, no outbound). Updates require an extension update.
- Match algorithm: longest-suffix wins; case-insensitive; punycode-normalised
  before match.
- Contents (v1, illustrative): clearnet Tor gateways (`.onion.to`,
  `.onion.ws`, `.onion.cab`, `.onion.pet`, `.onion.ly`), and known
  homoglyph/typo onion-phishing patterns. Maintained as a versioned data
  file at `extension/lib/blocklist/v1.json`.

---

## 15. Open Questions (`NEEDS CLARIFICATION`)

Consolidated list. Each must be resolved before the feature spec that
relies on it can be planned.

1. **§7 Sidecar image trust** — ~~Which Tor~~ **Tor: resolved** by
   `specs/001-tor-route/` §Clarifications 2026-05-17 Q1 (Stargate-built
   image from `deb.torproject.org` on pinned Debian-slim). **Nym
   remains open**: Nym's official Docker support status needs
   verification; either pin an upstream image if maintained, or build
   from a pinned `nymtech/nym` source tree. `SECURITY-DECISIONS.md`
   rationale entry owed for **Nym only** (Tor entry authored under T017
   — `SECURITY-DECISIONS.md` §"2026-07-04 — Tor sidecar trust rationale
   (FR-015)"; file exists at repo root, verified at HEAD).
2. **§7 Image digests** — Resolve and pin each external image before the
   first artifact for its applicable profile ships. The preview pins its
   Local distributed images in signed derived release data; completed-v1
   profile artifacts require their own verified pins.
3. **§8 Nym default gateway** — Pin a default Nym gateway at install, pick
   randomly from a vetted list, or require user choice on first run?
   (Defer to mixnet-route feature spec; flag here so it isn't lost.)
4. **§12.5 Signing tool** — T081 selects digest-verified cosign keyless signing
   for feature 001 with exact GitHub workflow identity and a reviewed trust anchor.
   Actual anchor authentication/signature checks remain prerequisites to publication.
5. **§13.1 Backup encryption** — `age` (preferred) vs `gpg --symmetric`
   (more ecosystem familiarity)?
6. **§14.1 Manifest version** — ~~Confirm MV2 support on Mullvad Browser
   at v1 release window~~ **Resolved-for-v1** by `specs/001-tor-route/`
   §Clarifications + `research.md` §2: implement the extension as Manifest
   V2 with `proxy.onRequest` (Mozilla's stated policy is to maintain MV2
   indefinitely for APIs that have no MV3 equivalent; no MV3 migration
   path preserves per-request routing with per-request SOCKS5 username —
   which is how stream isolation is driven). **Maintenance flag**: re-
   verify MV2 support on each Mullvad Browser major-version bump; if a
   bump drops MV2, redesign the proxy decision path for MV3 (out of scope
   for v1; the redesign would force a Constitution-level review of the
   stream-isolation guarantee).
7. **§14.3 First-encounter behaviour** — Prompt the user on first
   encounter of a new domain, or apply the configured default silently?
   (UX-vs-security trade-off; surfaces a privacy decision to the user but
   adds friction.)
8. **§14.4 Token storage** — ~~Does Mullvad Browser expose a credential-
   grade storage API for the device bearer token, or do we accept
   `storage.local` with a documented residual risk?~~ **Resolved-for-v1**
   by FR-019 + `research.md` §6: accept `storage.local` with the canonical
   warning text pinned in `data-model.md` §5.1. §14.4 amended in lock-
   step; see that section for the cross-reference.
9. **§12.2 Completed-v1 Mandrel compatibility** — Pin and verify the
    Mandrel 25 builder image before the first completed-v1 native artifact.
    Separately, the Quarkus 3.40 LTS / JDK 25 runtime pair used by the JVM
    feature-preview must be verified before that preview is prepared. Deferring
    native-image construction does not defer runtime compatibility.

None of these are deviations from the constitution; they are unresolved
implementation choices within the space the constitution allows.

---

## 16. Auxiliary Infrastructure Containers

Beyond the route sidecars enumerated in §7, the compose stack MAY run a
small number of **auxiliary containers** that do not carry user traffic
but support the proxy's operation (privilege isolation, future
observability hooks, etc.). Each must be declared here so that any
future profile (LAN, VPS) inherits a complete picture of the trusted
component set.

**Current state (T162; T203 observer authority repair):** the local profile runs one auxiliary
container, `tor-observer`, which serves authenticated finite health to the control plane.
The publisher runs as a process inside the Tor container. The `docker-socket-proxy` auxiliary container that
previously lived in this section — a digest-pinned
`tecnativa/docker-socket-proxy` that bridged `/var/run/docker.sock` to a
filtered HTTP API so the control plane could observe sidecar lifecycle
(`EVENTS=1`, `CONTAINERS=1`, `POST=0`) — was **removed by T094a**. The
former control-plane direct cookie/ControlPort path is withdrawn. Tor's
`ControlSocket` and cookie remain inside the Tor container. T164 introduced the
separate `tor-observer` container. T203 removes its raw Tor authority: a fixed Tor-internal
publisher writes one bounded boot-time-leased sample on shared tmpfs, mounted read-only
by the observer. The publisher accepts no observer/CP input; its compromise is a Tor-TCB
compromise. See foundation-boundaries.md for exact freshness and failure semantics. No service in
`compose/docker-compose.local.yml` mounts `/var/run/docker.sock`
(gated by `tests/contract/compose/local_compose_test.sh` M4). The raw
control socket is neither host-published nor mounted into either plane
(Constitution Principle III; THREAT-MODEL §3.1).

The removal rationale — why T090's removal of control-plane route-
admission gating made the proxy unnecessary for routing correctness,
and why the cookie-auth control port is the narrower observation
surface — is recorded in `SECURITY-DECISIONS.md` §"2026-07-16 —
docker-socket-proxy mechanism removed (T094a)", which supersedes the
2026-07-04 and 2026-07-06 docker-socket-proxy trust-rationale entries.
Those entries' prose is retained verbatim (append-only discipline) with
`Superseded by:` back-links.

**LAN/VPS release-blocker (carried forward).** The cookie-auth
ControlPort observation surface inherits the local-profile scoping of
the mechanism it replaces (THREAT-MODEL §3.1: local code execution is
already game-over). Any future LAN or VPS profile feature spec MUST
revisit how the control plane observes sidecar lifecycle: a non-
localhost profile changes the compromise-probability calculus for every
observation surface (the data plane is the most concerning reacher since
it faces internet-supplied input the CP does not), and the chosen
surface must be re-evaluated before that profile's compose file ships.

---

## Constitution Compliance Cross-Reference

| Constitution principle / section                  | Where addressed in this spec                                |
|---------------------------------------------------|-------------------------------------------------------------|
| I. Dumb Router                                    | §2 topology, §4 port-protocol fixed binding, §10 error template no payload data, §11 row "Change route↔sidecar binding requires restart" |
| II. Plane Separation                              | §5.4 transport, §5.5 failure semantics, §11 control-plane restart row, §3 module split |
| III. Privacy-Preserving by Construction           | §6 schema (no per-request data), §8 config no per-user data, §10 leak corpus test, §14.3 SOCKS5h + stream isolation, §14.6 in-package blocklist |
| IV. Pinned, Tested, Manually Promoted Updates     | §7 digest-pinning + contract gating, §12.4 SBOM/provenance  |
| V. Honest Threat Model                            | §15 open questions explicitly flagged for THREAT-MODEL.md, §4.4 Direct ≠ privacy |
| VI. Open and Auditable                            | §12 reproducibility tiers, §3 doc files alongside code      |
| VII. Tests-First                                  | §10.3 error contract test pattern, §3 `tests/contract/`, §9 init verification |
| VIII. Adversarial Review                          | §3 stargate-redteam / stargate-perf agent directory referenced; §6 audit log "verified by stargate-redteam" |
| Tech Stack — Bind safety invariant                | §4 binding columns + §9 init checks                          |
| Inter-plane contract (governance)                 | §5.3 versioning, §5.4 mutual auth                            |
