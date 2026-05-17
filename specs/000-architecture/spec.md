# Architecture Specification (Pre-Feature)

**Spec ID**: `000-architecture`

**Status**: Draft

**Created**: 2026-05-17

**Derives from**: `.specify/memory/constitution.md` v1.1.0

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
                                        │ TCP (SOCKS5 / HTTP CONNECT)
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
       │  SOCKS 9050  │ │  4444   │ │ SOCKS 1080 │ │  egress NIC  │
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
| Tor route (forward proxy)         | 8881  | SOCKS5+HTTP   | `127.0.0.1`        | `wg0` only       | `wg0` only       |
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

### 4.2 Sidecar-internal (compose network only, never published)

| Sidecar       | Service                | Port  | Bound on              |
|---------------|------------------------|-------|-----------------------|
| Tor           | SOCKS5 (stream-iso)    | 9050  | `0.0.0.0` in container |
| Tor           | Control port (cookie)  | 9051  | `0.0.0.0` in container |
| i2pd          | HTTP proxy             | 4444  | `0.0.0.0` in container |
| i2pd          | SOCKS proxy            | 4447  | `0.0.0.0` in container |
| i2pd          | SAM bridge (reserved)  | 7656  | `0.0.0.0` in container |
| Nym client    | SOCKS5                 | 1080  | `0.0.0.0` in container |

These are reachable only across the Docker bridge network shared by the
proxy and sidecar containers; none are mapped to the host.

### 4.3 Non-TCP endpoints

- **Inter-plane gRPC socket**: `/run/stargate/control.sock`, mounted into
  both the data-plane and control-plane containers via a named volume
  (`stargate-ipc`). Mode `0600`, owner = `stargate` user (UID 10001, fixed
  for reproducibility).
- **Inter-plane keys**: `/etc/stargate/keys/` mounted from a named volume
  (`stargate-keys`), readable only by `stargate`. Generated at first
  `stargate init`.

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
- `ReloadTokensRequest { repeated TokenHash tokens; uint64 generation; }`  
  The data plane stores only the *current* generation; older generations
  are dropped (Principle III — no per-user history).
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

### 5.4 Transport and authentication

- Unix-domain socket at `/run/stargate/control.sock`. Permissions enforce
  same-host, same-user access; no TCP grpc surface exists.
- Mutual auth: each plane has an ed25519 keypair generated at first
  `stargate init`, public keys cross-installed in `/etc/stargate/keys/`.
  Handshake uses gRPC's TLS-over-UDS with self-signed certs derived from
  these keys; either side rejects an unrecognised peer cert.
- A handshake failure is a startup error for the control plane and a
  non-fatal degraded-mode warning for the data plane (it MUST keep
  forwarding — Principle II).

### 5.5 Failure semantics

| Failure                                     | Data plane behaviour                                |
|---------------------------------------------|-----------------------------------------------------|
| Control plane down at startup               | Continue with last-known config snapshot from disk  |
| Control plane down at runtime               | Continue routing; queue counter increments locally  |
| `ReloadTokens` RPC fails midway             | Atomic swap — old generation remains until success  |
| Schema-version mismatch (peer is newer)     | Reject handshake, log to journal, exit non-zero     |

The data plane caches the last successful `StatusResponse → token list +
route enable/disable mask` on disk at `/var/lib/stargate/dp-snapshot.json`
so cold-start without the control plane still serves the right ports.

---

## 6. SQLite Schema Sketch

Stored in the control-plane container under
`/var/lib/stargate/control.db` (named volume `stargate-control-state`),
opened in **WAL mode** (constitution Tech Stack). Hibernate Panache entities
back each table; Flyway manages migrations (`control-plane/persistence/src/main/resources/db/migration/`).

```
-- 6.1 Devices that may use the proxy.
CREATE TABLE enrolled_devices (
  id              INTEGER PRIMARY KEY,
  name            TEXT    NOT NULL UNIQUE,
  pubkey          BLOB    NOT NULL,             -- ed25519 device key
  token_hash      BLOB    NOT NULL,             -- argon2id of bearer token
  created_at      INTEGER NOT NULL,             -- unix seconds
  last_seen_hour  INTEGER,                      -- rounded to hour-bucket
  revoked_at      INTEGER                       -- nullable
);
-- last_seen_hour is bucketed to satisfy Principle III (≥1h log resolution).

-- 6.2 Admin login credentials (WebAuthn + ed25519 fallback).
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

-- 6.3 Tor bridges (toggleable per Constitution v1 Scope).
CREATE TABLE tor_bridges (
  id          INTEGER PRIMARY KEY,
  bridge_line TEXT    NOT NULL UNIQUE,          -- full "Bridge ..." torrc line
  transport   TEXT    NOT NULL,                 -- obfs4 | snowflake | webtunnel | direct
  enabled     INTEGER NOT NULL DEFAULT 0,
  added_at    INTEGER NOT NULL
);

-- 6.4 Aggregate routing counters at hour resolution.
CREATE TABLE aggregate_counters (
  route        TEXT    NOT NULL CHECK (route IN ('TOR','I2P','NYM','DIRECT')),
  hour_bucket  INTEGER NOT NULL,                -- unix-hour
  request_count INTEGER NOT NULL DEFAULT 0,
  byte_count   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (route, hour_bucket)
);
-- No destination, no token id, no sub-hour granularity (Principle III).

-- 6.5 Append-only admin action audit.
CREATE TABLE audit_log (
  id           INTEGER PRIMARY KEY,
  ts           INTEGER NOT NULL,                -- unix seconds (admin action time, not user request time)
  actor        TEXT    NOT NULL,                -- admin credential label
  action       TEXT    NOT NULL,                -- enum: enrolled, revoked, sidecar_restart, bridge_toggle, export, import, wipe
  target       TEXT,                            -- entity affected (e.g. device name)
  detail_json  TEXT                             -- fixed-schema metadata; never request data
);
-- Inserts only; no UPDATE/DELETE in code paths. Verified by stargate-redteam.
```

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
| Tor         | **`stargate/tor`** — Stargate-built image installing `tor` from `deb.torproject.org` (Tor Project's official Debian apt repository) on a pinned Debian-slim base. Dockerfile lives in `sidecars/tor/`. Tor Project signing key pinned by fingerprint and verified at build time. Resolved by `specs/001-tor-route/` §Clarifications 2026-05-17 Q1. | `NEEDS CLARIFICATION` — pin both the Debian-slim base and the final composed image at first release tag |
| i2pd        | `purplei2p/i2pd` (upstream maintainer)           | `NEEDS CLARIFICATION` — pin at first release tag        |
| Nym client  | `NEEDS CLARIFICATION: Nym's official Docker distribution status is not resolved in this spec; either pin an upstream image if maintained or build from a pinned `nymtech/nym` source tree.` | `NEEDS CLARIFICATION` |
| WireGuard   | `linuxserver/wireguard`                          | `NEEDS CLARIFICATION` — pin at first release tag        |
| Base (data-plane, control-plane runtime images) | Distroless static (Go) and `quarkus.io/builder`-derived | `NEEDS CLARIFICATION` |

`NEEDS CLARIFICATION` entries here are not invented digests. They are
flags that the maintainer must resolve, with an `SECURITY-DECISIONS.md`
entry per sidecar covering: who maintains the image, how its provenance is
verified, and what the contract test suite asserts about it.

**Outstanding follow-up for the Tor row**: the trust-rationale narrative
required by Principle IV must land in `SECURITY-DECISIONS.md` once that
file is authored (constitution Sync Impact Report lists it as TODO).
Until then, the rationale lives inline above (Tor Project as upstream
package maintainer; their signing infrastructure as the trust root).

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

- **Tor** — `torrc` rendered with: `SocksPort 9050 IsolateClientAddr
  IsolateSOCKSAuth`, `ControlPort 9051`, `CookieAuthentication 1`,
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
   - Generate WebAuthn relying-party id and a one-time admin enrollment
     code (printed once, never stored).
   - Write into `stargate-keys` volume with `0600` perms.
4. **Compose up**
   - `docker compose -f compose/docker-compose.<profile>.yml up -d`.
   - Wait for each container's healthcheck to pass with a bounded retry
     budget (default 60 s per sidecar). On timeout, abort and print the
     failing container's `docker logs` tail.
5. **Verification**
   - Run a subset of contract tests against the live stack: each route's
     SOCKS5 endpoint accepts a connect, the admin UI responds with HTTP
     401 on `/admin`, the data plane's gRPC handshake to control plane
     succeeds.
6. **Status table**

   ```
   ┌──────────────┬──────────┬────────────┬──────────────────────┐
   │ Component    │ Status   │ Bind       │ Notes                │
   ├──────────────┼──────────┼────────────┼──────────────────────┤
   │ Data plane   │ HEALTHY  │ 127.0.0.1  │ ports 8881–8885      │
   │ Control plane│ HEALTHY  │ 127.0.0.1  │ admin UI on :8443    │
   │ Tor sidecar  │ HEALTHY  │ internal   │ SOCKS5 9050          │
   │ i2pd sidecar │ STARTING │ internal   │ tunnel build pending │
   │ Nym sidecar  │ HEALTHY  │ internal   │ gateway: <id>        │
   └──────────────┴──────────┴────────────┴──────────────────────┘

   Admin enrollment URL: https://127.0.0.1:8443/enroll?code=XXXX
   This code is shown ONCE and expires in 15 minutes.
   ```
7. **Exit**
   - `0` on success, non-zero with a clear error code on failure
     (preflight=10, key-gen=20, compose=30, healthcheck=40, verify=50).

### 9.2 Failure modes

- **Docker missing** → exit 10 with a link to install docs.
- **Existing stack detected without `--force`** → exit 0 after printing the
  status table for the existing stack.
- **Healthcheck timeout** → exit 40, leave containers up so the user can
  inspect `docker logs`. `init` never deletes user data on failure.

### 9.3 Idempotence guarantees

- Re-running `init` against a healthy stack: no-op (prints status table).
- Re-running `init` against an unhealthy stack: prints status table and
  exits non-zero; explicit `init --repair` is the documented way to
  regenerate missing config without touching keys or DB.
- `init` MUST NOT regenerate inter-plane keys if `stargate-keys` is
  populated — doing so would invalidate enrolled devices.

---

## 10. Error Response Contract

When a routed request cannot be served, the proxy returns a **fixed-template
error response** to the browser. The template is privacy-safe by design: it
never includes upstream IPs, sidecar version strings, exit-relay identifiers,
DNS responses, or precise timing — anything that could be exfiltrated through
an error-channel side channel.

### 10.1 Error codes (proxy-internal, also emitted as response header)

| Code              | Meaning                                                    | HTTP status |
|-------------------|------------------------------------------------------------|-------------|
| `ROUTE_DISABLED`  | The port's route is administratively disabled              | 503         |
| `ROUTE_DOWN`      | Sidecar is unreachable or unhealthy                        | 502         |
| `ROUTE_TIMEOUT`   | Upstream did not respond within the configured timeout     | 504         |
| `ROUTE_REFUSED`   | Sidecar accepted the SOCKS handshake but refused the target| 502         |
| `AUTH_REQUIRED`   | Bearer token missing or invalid (introduced by `specs/001-tor-route/` FR-006) | 407 (CONNECT framing) / SOCKS5 auth-fail equivalent |
| `BIND_REFUSED`    | Bind-safety check would publish on a non-tunnel interface  | 500 (only at start-up; never per-request) |

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

`tests/contract/error-template/` runs each error condition against a stub
backend, captures the response, and asserts:

1. Status code matches the table.
2. Body matches the template byte-for-byte after substitution of the four
   permitted fields.
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
- **Quarkus 3.33 LTS** pinned in the parent POM via the
  `<quarkus.platform.version>` property; managed by the Quarkus platform
  BOM. Subsequent Quarkus upgrades follow the same digest-promoted flow
  as sidecar image updates (Principle IV).
- JVM bytecode reproducibility via `reproducible-build-maven-plugin`
  configured at the parent POM. `mvn -B clean package -DskipTests=false`.
- Native-image build via `mvn package -Pnative`, with
  `-Dquarkus.native.reproducible-build=true` and a pinned
  `quay.io/quarkus/ubi-quarkus-mandrel-builder-image` digest for the
  **Mandrel 25** (JDK 25) builder, matching the Quarkus 3.33 LTS
  compatibility matrix.
- Reproducibility tier: **JVM bytecode = byte-reproducible**; **native-image
  = best-effort** with expected variations enumerated in `BUILD-DIFFS.md`
  (Principle VI). CI runs both builds twice and diffs; expected-variation
  bytes are masked before comparison.

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

### 12.5 Release artefacts

Each tagged `v<x.y.z>` produces:

- `stargate-proxy_<x.y.z>_linux_amd64` and `_arm64` (Go binary).
- `stargate-control_<x.y.z>.jar` (JVM) and a native `stargate-control`
  binary per arch.
- `stargate-extension_<x.y.z>.zip` (web-ext packaging).
- `stargate_<x.y.z>_compose.tar.gz` containing the three compose files and
  `scripts/stargate`.
- Detached signatures (minisign or cosign — `NEEDS CLARIFICATION`: which
  signing tool is the v1 standard?) + SBOMs + provenance.

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

`wipe` writes an `audit_log` entry **before** destroying the database, so
the action is recorded in the audit chain (if the user separately exported
the DB beforehand).

---

## 14. Browser Extension Architecture

### 14.1 Manifest

- **Manifest version**: **v2** (Firefox-ESR / Mullvad Browser still
  support MV2 and the `proxy.onRequest` API used here is well-supported
  there; MV3 in Firefox does not expose an equivalent blocking
  proxy.onRequest at time of writing).  
  `NEEDS CLARIFICATION`: maintainer to confirm MV2 remains supported on
  Mullvad Browser at the v1 release window; if not, the extension moves to
  MV3 and the proxy logic relocates to `proxy.settings` + DNS-leak hardening
  via `dns.setMode` (Firefox-specific).

### 14.2 Permissions and justifications

| Permission                              | Why                                                                 |
|-----------------------------------------|---------------------------------------------------------------------|
| `proxy`                                 | Set per-request proxy via `proxy.onRequest` listener (core function)|
| `<all_urls>` (host permission)          | The proxy listener must see all outbound URLs to apply mapping      |
| `storage`                               | Persist per-domain route preferences and blocklist in `storage.local` |
| `webRequest`, `webRequestBlocking`      | Block DoH/DoT requests pre-proxy and enforce hardening invariants   |
| `privacy`                               | Read/write WebRTC, DNS-over-HTTPS, HTTP/3 prefs (hardening)         |
| `notifications` (optional)              | Local desktop notifications only (Constitution Notifications scope) |

No `tabs`, no `history`, no `bookmarks`, no `cookies`, no `identity` —
these are not required and would be additional privacy attack surface.

### 14.3 `proxy.onRequest` routing sketch

For each request:

1. Compute first-party domain (use the `requestDetails.documentUrl` /
   `originUrl` when available; otherwise fall back to the request URL's
   eTLD+1).
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
3. Return the SOCKS5 proxy descriptor pointing at the chosen port
   (`127.0.0.1:888x`) with `username` set to the first-party domain (Tor
   stream isolation — Principle III) and `password` set to the device's
   bearer token. **`proxyDNS: true`** in the returned descriptor (Firefox
   SOCKS5h equivalent) — no local DNS, ever.

### 14.4 `storage.local` layout

```
{
  "schema": 1,
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
  },
  "hardening": {
    "lastAuditedAt": <hourBucket>,
    "lastAuditResult": { "doh": "disabled", "webrtc": "disabled", "h3": "disabled" }
  }
}
```

Bearer tokens themselves SHOULD be stored in the browser's OS keyring via
the WebExtensions password-storage path if available; otherwise in
`storage.local` with a clear UX warning. `NEEDS CLARIFICATION`: which
storage path Mullvad Browser exposes for credential-grade secrets.

### 14.5 Install-time configuration audit

On first run and on browser startup, the extension performs a hardening
audit (read-only):

- WebRTC must be off (`privacy.network.webRTCIPHandlingPolicy =
  disable_non_proxied_udp` or stricter).
- DoH must be off (`network.trr.mode = 5`, Firefox).
- HTTP/3 / QUIC must be off (`network.http.http3.enable = false`).
- No foreign extensions other than allowlisted ones (Mullvad Browser
  default uBlock Origin is allowlisted).

On any failure, the extension displays a blocking dialog explaining the
issue and offers a one-click remediation where the API permits it. Audit
results are written to `storage.local.hardening.lastAuditResult` for the
admin dashboard to surface (read via a future signed-export flow — out of
scope for this spec).

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
   rationale entries still owed for both once that file is authored.
2. **§7 Image digests** — Concrete sha256 digests for Tor, i2pd, Nym
   client, WireGuard, distroless base, and the Quarkus native builder
   image. To be pinned at first release tag.
3. **§8 Nym default gateway** — Pin a default Nym gateway at install, pick
   randomly from a vetted list, or require user choice on first run?
   (Defer to mixnet-route feature spec; flag here so it isn't lost.)
4. **§12.5 Signing tool** — minisign or cosign as the v1 release-signing
   standard?
5. **§13.1 Backup encryption** — `age` (preferred) vs `gpg --symmetric`
   (more ecosystem familiarity)?
6. **§14.1 Manifest version** — Confirm MV2 support on Mullvad Browser at
   v1 release window; if MV2 is gone, redesign the proxy decision path
   for MV3.
7. **§14.3 First-encounter behaviour** — Prompt the user on first
   encounter of a new domain, or apply the configured default silently?
   (UX-vs-security trade-off; surfaces a privacy decision to the user but
   adds friction.)
8. **§14.4 Token storage** — Does Mullvad Browser expose a credential-grade
   storage API for the device bearer token, or do we accept `storage.local`
   with a documented residual risk?
9. **§12.2 Quarkus / JDK / Mandrel compatibility matrix** — Confirm
    Quarkus 3.33 LTS officially targets JDK 25 as a runtime, and pin the
    matching Mandrel 25 builder image digest at first release tag. If
    Quarkus 3.33 LTS lags JDK 25 support, fall back to the highest Quarkus
    LTS that does and reopen the constitution amendment that introduced
    these pins (constitution v1.1.0).

None of these are deviations from the constitution; they are unresolved
implementation choices within the space the constitution allows.

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
