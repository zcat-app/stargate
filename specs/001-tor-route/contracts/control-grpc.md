# Contract — Inter-Plane gRPC (subset used by Tor-route v1)

> **T156 normative update:** [foundation boundaries](foundation-boundaries.md) specify
> snapshot/reconnect/rollback semantics (T132/T159), aggregate-only GetStatus (T158), and
> sanitized event observation (T138/T152). Current message examples are not permission for
> changing current-hour counters or per-event persistent logs. Owners record wire transitions
> and compatibility tests before implementing; both peers must be reviewed together.

**Status**: Phase 1 contract document

**Scope**: this contract document declares the *subset of the
`stargate.v1` gRPC surface* that the Tor-route v1 feature relies on. The
full surface is defined in architecture spec §5. This document is the
input for the contract tests at `tests/contract/` and for the Phase 1
proto stubs at `proto/stargate/v1/`.

The surface is versioned as `stargate.v1`. Any change to the messages or
RPCs below requires either (a) an additive minor change with backwards-
compatibility tests, or (b) a major version bump to `stargate.v2` with
documented migration (constitution Inter-Plane Contract section).

---

## RPCs used by this feature

### `ReloadTokens`

```
rpc ReloadTokens(ReloadTokensRequest) returns (ReloadTokensResponse);
```

**Direction**: control plane → data plane.

> **Amended by T092 (sol-review B5+M1).** The verifier is an HMAC-SHA-256
> tag under a shared install-time pepper, not an Argon2id hash. `TokenHash`
> is renamed `TokenVerifier` and drops its `salt` field (single shared
> pepper → no per-token salt), carrying only the 32-byte verifier. The
> response gains a `current_generation` field so a stale CP can reconcile
> against the DP's truth and retry. This breaking pre-release contract
> change is recorded as an amendment NOTE (SECURITY-DECISIONS.md §"Bearer-
> token verifier: HMAC-SHA-256 + install-time pepper (T092)"), NOT a
> `stargate.v2` bump — no consumers exist today and semver-on-amendments
> becomes binding at first public release (T091/T099 doctrine). See
> data-model.md §1.

**Request**:

```proto
message ReloadTokensRequest {
  uint64 generation = 1;              // monotonic; CP proposal = persisted last + 1
  repeated TokenVerifier tokens = 2;
}

message TokenVerifier {
  bytes verifier = 1;                 // 32 bytes (HMAC-SHA-256 tag under the pepper)
}
```

**Response**:

```proto
message ReloadTokensResponse {
  uint64 applied_generation = 1;
  ApplyStatus status = 2;
  uint64 current_generation = 3;      // DP current generation; stale content cannot be renumbered into authority (T159)
}

enum ApplyStatus {
  APPLY_STATUS_UNSPECIFIED = 0;
  APPLY_STATUS_OK = 1;
  APPLY_STATUS_STALE_GENERATION = 2; // request.generation <= current
  APPLY_STATUS_INVALID = 3;          // malformed verifier / wrong length
}
```

**Contract**:

- The data plane MUST atomically swap to the new generation before
  returning `APPLY_STATUS_OK`. In-flight requests holding the previous
  generation continue against it.
- If `request.generation <= currentGeneration`, the data plane MUST
  return `APPLY_STATUS_STALE_GENERATION`, set `current_generation` to its
  current generation (for authority reconciliation under T159), and leave
  the current generation unchanged.
- Each `TokenVerifier.verifier` MUST be exactly 32 bytes; mismatch returns
  `APPLY_STATUS_INVALID` with no generation change.
- On `APPLY_STATUS_OK`, the data plane MUST persist the new
  generation to `dp-snapshot.json` (verifiers only — never the pepper)
  before reporting durable application. Persistence failure MUST NOT report durable success
  or allow acknowledged revocation to revert on restart. T159 specifies failure responses,
  in-memory state and crash recovery with a reviewed peer transition before implementation.
- The data plane MUST NOT log the verifier bytes, the pepper, or any
  token label (labels are not in the message anyway, by design —
  labels remain auth-configuration state and MUST NOT enter any audit log).

**Tests** (`tests/contract/control-grpc/reload_tokens_test.go`):

1. Happy path: new generation applied; subsequent inbound proxy auth
   uses the new verifiers.
2. Stale generation: `request.generation = currentGeneration` →
   `APPLY_STATUS_STALE_GENERATION`, current generation unchanged,
   `current_generation` echoes the DP's current generation (T092
   reconciliation field).
3. Invalid verifier length: `request.tokens[i].verifier` is 31 or 33 bytes →
   `APPLY_STATUS_INVALID`, current generation unchanged.
4. Snapshot persist failure: inject read-only/full/unavailable storage and crash/restart;
   no false durable success and no restored acknowledged revocation (T159).
5. Concurrency: two `ReloadTokens` calls with generations N and N+1 in
   parallel; the data plane converges on generation N+1 and rejects
   the older one as stale on retry.
6. **Authority reconciliation (T159):** reconnect current persisted authority automatically,
   but reject an older restored CP credential set. Verify revoked tokens stay rejected and
   explicit operator rollback recovery is distinguishable from ordinary reconnect.


### `WatchEvents`

```
rpc WatchEvents(WatchEventsRequest) returns (stream SidecarEvent);
```

**Direction**: data plane streams from control plane.

**Request**: `WatchEventsRequest {}` — empty in v1.

**Response stream** (each message):

```proto
message SidecarEvent {
  google.protobuf.Timestamp ts = 1;
  string sidecar = 2;                 // "tor" for this feature
  EventKind kind = 3;
  string detail = 4;                  // fixed-vocabulary token
}

enum EventKind {
  EVENT_KIND_UNSPECIFIED = 0;
  EVENT_KIND_STARTED = 1;
  EVENT_KIND_STOPPED = 2;
  EVENT_KIND_HEALTHY = 3;
  EVENT_KIND_UNHEALTHY = 4;
  EVENT_KIND_RESTARTED = 5;
  EVENT_KIND_CONFIG_RELOADED = 6;
  EVENT_KIND_CRASHED = 7;
}
```

**Contract**:

- Events for the Tor sidecar use `sidecar = "tor"`. Other sidecar
  values appear in later features; this feature ignores them.
- `detail` is a **fixed-vocabulary token** drawn from the closed set
  `{"healthcheck_pass", "healthcheck_fail", "container_exit",
  "container_start", "config_render"}`. The data plane and the
  contract test treat unknown `detail` values as a contract violation.
  In v1 of the Tor-route feature the emitted subset is
  `{"container_start", "healthcheck_pass", "healthcheck_fail",
  "container_exit"}` with these `(kind, detail)` pairings (per T039 / T074):
  `STARTED → container_start`, `HEALTHY → healthcheck_pass`,
  `UNHEALTHY → healthcheck_fail`, `STOPPED → container_exit`,
  `CRASHED → container_exit`, `RESTARTED → container_start`.
  `RESTARTED` reuses `container_start` because `detail`'s role is to
  describe the container action, not to disambiguate `kind` (which the
  `kind` field already does); keeping the closed set stable across this
  feature avoids a future-compat vocabulary bump for a purely
  informational event.
  `config_render` is reserved for `EVENT_KIND_CONFIG_RELOADED`, which
  the **bridges feature** will emit when `UseBridges` / `Bridge`
  lines are toggled and `TorrcRenderer` re-renders live; this feature
  bakes the safe `torrc` into the Tor image at build time (T089 / T087,
  FR-011) and emits no `CONFIG_RELOADED` event — the CP does not render
  `torrc` at boot in this slice (Constitution Principle II / sol-review
  B2). Keeping `config_render` in the closed set
  now (rather than adding it later) prevents a future minor-version
  vocabulary bump that would force the data-plane contract test to
  treat a previously-unknown `detail` value as a contract violation
  during the bridges-feature rollout window.
- The control plane MUST NOT include log lines, version strings, or
  any other free text from the sidecar in `detail` (arch §5.2).
- The stream is long-lived. On disconnect, the data plane reconnects
  with exponential backoff (initial 1 s, cap 30 s, jitter ±20%).
  During disconnect the data plane keeps routing — `SidecarEvent`s are
  advisory status/audit hints and MUST NOT gate admission (Constitution
  Principle II; data-model.md §2; sol-review B3). The upstream dial is
  the ground truth on every reconnect, just as it is on cold start.

**Tests** (`tests/contract/control-grpc/watch_events_test.go`):

1. Advisory events: the data plane dials `control.sock`; emitting
   `STARTED` then `HEALTHY` for `tor` does NOT change admission — a
   request forwards through a reachable upstream before any event is
   sent and continues to forward after each event (proves events are
   advisory, not a precondition; Constitution Principle II).
2. Forbidden `detail`: control plane test harness emits a
   `SidecarEvent` with `detail = "could not bind 0.0.0.0:9050"` → the
   contract test fails (the offending field should never have been
   generated; the test is a regression gate against a maintainer
   accidentally piping log lines into `detail`).
3. Disconnect/reconnect: the data plane retries the stream with
   bounded backoff; events delivered after reconnect are applied
   normally. Admission is unchanged across the disconnect (the data
   plane keeps routing per Principle II).

### `GetStatus` (minimum subset)

```
rpc GetStatus(StatusRequest) returns (StatusResponse);
```

**Direction (v1)**: contract-test harness caller in the `stargate-ipc` group → data plane.
In v1 the **only** caller is the contract-test harness (T025c, T025d, T067b);
the production CP→DP pull and the SQLite persistence path described in
arch §5.2 + data-model.md §3 are **deferred to the admin-UI feature**.
The RPC ships in `stargate.v1` proto now (T007) rather than later so
the admin-UI feature can wire its caller without bumping the package
to `stargate.v2` — see plan.md §"Plan-level tensions surfaced for
review" #10 for the trade-off rationale.

**Request**: `StatusRequest {}` — empty in v1.

**Response**:

```proto
message StatusResponse {
  repeated RouteCounter counters = 1;
}

message RouteCounter {
  string route        = 1;   // "TOR" in this feature; later sidecars add their own labels
  uint64 hour_bucket  = 2;   // unix-hour bucket per data-model.md §3
  uint64 request_count = 3;
  uint64 byte_count   = 4;
}
```

**Contract**:

- The data plane MUST return only finalized immutable completed-hour aggregates under
  data-model.md §3 and foundation-boundaries.md. Current-hour counters are private volatile
  state. Repeated calls must not reveal sub-hour updates, including via alternate fields.
  T158 updates old point-in-time semantics and their compatibility tests before code.
- The data plane MUST NOT increment any counter as a side-effect of
  serving `GetStatus` — this is the property T025c's no-traffic
  sandwich verifies; a side-effecting probe would defeat the test's
  purpose.
- Auth-failure / auth-pass increment semantics live in data-model.md §3
  and FR-008; this RPC is the read surface, not the write surface.
- In v1, counter state is process-memory only; restarting the data
  plane resets the snapshot. The persistence path to the
  `aggregate_counters` SQLite table is out of scope here (arch §5.2 /
  data-model.md §3).
- The DP hosts this RPC on `/run/stargate/dp.sock` (T045), same socket
  as `ReloadTokens`; the mode/group scheme described in §"Socket
  topology" gates dial access to in-group callers.

**Tests**:

1. `tests/contract/socks5/auth_failure_counter_test.go` (T025c) —
   probes `GetStatus` before and after 200 auth-failure attempts;
   asserts both counter deltas are exactly zero.
2. `tests/contract/socks5/auth_passed_counter_test.go` (T025d) —
   probes `GetStatus` before and after 100 auth-passing CONNECTs each
   transferring exactly `2B` bytes; asserts `request_count` delta is
   100 and `byte_count` delta is exactly `100 × 2B`.
3. `tests/contract/socks5/route_failure_counter_test.go` (T067b) —
   probes `GetStatus` before and after 60 auth-pass CONNECTs (20 each
   against `ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT`); asserts
   `request_count` delta is exactly 60 and `byte_count` delta is
   exactly zero. Gates the FR-008 / data-model.md §3 asymmetry that
   route failures DO increment `request_count` post-auth while their
   synthesised error-template bodies do NOT contribute to `byte_count`.
4. No-side-effect: between two `GetStatus` calls separated by ≥1 s of
   wall-clock idle (no inbound port-8881 traffic), both counter values
   are identical — verifies `GetStatus` itself does not increment
   counters. Asserted as a sandwich inside T025c.

---

## RPCs explicitly NOT used by this feature

`EnableProtocol`, `DisableProtocol`, `RestartSidecar`,
`ReloadBlocklist`. Listed for completeness; the contract test suite
for this feature does not exercise them. They are exercised by the
features that own them.

(`GetStatus` was in this list before the `/speckit-analyze` F3
remediation introduced the minimum-subset v1 declaration above;
the production CP→DP pull is still deferred to the admin-UI feature
but the RPC itself is now in-scope for v1 via the test-harness caller.)

---

## Transport invariants (arch §5.4)

The contract tests for this feature MUST verify the transport-level
invariants of the inter-plane channel.

> **Wire-auth contract.** The complete wire contract for Ed25519 X.509
> certificate derivation, peer public-key pinning, certificate validity,
> UDS authority/SAN handling, key ownership, and the authenticated gRPC
> metadata (protocol major/minor + capabilities) carrying the version
> negotiation lives in **`contracts/wire-auth.md`** (T095). The invariants
> below name the wire-auth sections they rest on; this document does not
> re-specify the wire shape. T022 covers the local-process tier of this
> table; the compose-level rows T022 deferred are owned by
> `tests/contract/compose/inter_plane_wire_test.sh` (T095).

### Socket topology

This feature uses **two** UDS files in the shared `stargate-ipc`
volume — one per gRPC server. The split follows directly from the
RPC directions: `WatchEvents` is server-streamed by the control
plane (CP must be the server), and `ReloadTokens` is invoked by the
control plane on the data plane (DP must be the server). A single
UDS file binds one listener, so two servers means two sockets.

| Socket path                  | Hosted by      | Service(s) it serves | Dialed by      |
|------------------------------|----------------|----------------------|----------------|
| `/run/stargate/control.sock` | control plane  | `WatchEvents`        | data plane     |
| `/run/stargate/dp.sock`      | data plane     | `ReloadTokens`       | control plane  |

Each socket is owned by the runtime user of the plane that hosts it
(`stargate-cp` for `control.sock`, `stargate-dp` for `dp.sock`) and
group-owned by the shared `stargate-ipc` group (GID 5100). Both planes
are members of that group. Mode is `0660`:

- **Role separation comes from `bind(2)`, not from the file mode.**
  Only the hosting plane is wired to call `bind(2)` on its socket
  path; the OS rejects a second `bind(2)` against an existing socket.
  The CP cannot accidentally accept a `ReloadTokens` request because
  it never opens a listening FD on `dp.sock`; the DP cannot
  accidentally emit a `SidecarEvent` because it never opens a
  listening FD on `control.sock`.
- **Mode `0660` + shared group lets the peer plane dial.**
  `connect(2)` on a UDS requires write permission on the socket
  file; with `0600` and distinct hosting UIDs the peer plane cannot
  connect at all. The shared `stargate-ipc` group is the kernel-
  enforced "loopback-equivalent" gate that keeps random unprivileged
  same-host processes from dialling without granting access to every
  local user.
- **Distinct hosting UIDs are preserved** as defense-in-depth: a
  compromise of one plane does not yield filesystem-write access to
  the other plane's state (`stargate-control-state` is `stargate-cp`-
  owned, `stargate-dp-state` is `stargate-dp`-owned). The shared
  group covers only the IPC volume.

Mutual ed25519 authentication on each socket is the second, primary
gate against any caller that *does* manage to connect (e.g., a
future LAN/VPS profile that exposes the proxy differently); the
mode/group scheme is not load-bearing for authentication, only for
keeping the dial surface small in the local profile.

### Invariants

| Invariant                                                                       | Test                                                                                                                                                                                                                                                                                                                            |
|---------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| No TCP transport on either side                                                 | Contract test asserts each plane refuses to dial a TCP gRPC address.                                                                                                                                                                                                                                                            |
| DP dials only `/run/stargate/control.sock`; CP dials only `/run/stargate/dp.sock` | Contract test points each plane at the *other* socket path and asserts the dial is rejected before any RPC is attempted.                                                                                                                                                                                                        |
| `/run/stargate/control.sock` mode `0660`, owned `stargate-cp:stargate-ipc`      | Contract test stats the socket file after init.                                                                                                                                                                                                                                                                                 |
| `/run/stargate/dp.sock` mode `0660`, owned `stargate-dp:stargate-ipc`           | Contract test stats the socket file after init.                                                                                                                                                                                                                                                                                 |
| Peer plane can `connect(2)` its dial-direction socket                            | Contract test as the *peer-plane UID* (in the `stargate-ipc` group) opens the dial-direction socket — the DP-uid process must succeed connecting `control.sock`; the CP-uid process must succeed connecting `dp.sock`. Regression gate against accidental revert to `0600` (which would silently break inter-plane comms).                                                                                                       |
| Same-host process outside the `stargate-ipc` group cannot dial either socket    | Contract test as an arbitrary UID outside the group: both `connect(2)` calls fail with `EACCES`. Verifies the mode/group scheme actually narrows the dial surface and isn't equivalent to `0666`.                                                                                                                                |
| Mutual auth: both planes have ed25519 keys                                      | Contract test verifies the data plane refuses a peer cert it cannot validate against `/etc/stargate/keys/control.pub` (on `control.sock`), and the control plane refuses a peer cert it cannot validate against `/etc/stargate/keys/dp.pub` (on `dp.sock`). Pinned by byte-equal public-key comparison per `contracts/wire-auth.md` §3 (T095; `tests/contract/compose/inter_plane_wire_test.sh`).                                                                     |
| Schema-version handshake                                                        | Contract test simulates a `stargate.v2` peer offering an unknown major-version marker (gRPC metadata `x-stargate-proto-major`, per `contracts/wire-auth.md` §5) on either socket → the receiving service rejects the RPC; CP startup reports failure, while a DP with valid auth state continues routing (T153). No per-event journal is permitted. Minor-version compatibility (additive minor accepted) is asserted in the same test. Pinned by `tests/contract/compose/inter_plane_wire_test.sh` (T095).                                                                                                                                              |
| Plane-down survival                                                             | Contract test stops the control plane after a successful `ReloadTokens`; the data plane MUST continue accepting proxy requests on port 8881 and authenticating them. (When the CP comes back, it re-dials `dp.sock` and pushes the current generation; the DP re-dials `control.sock` with the §"WatchEvents" backoff schedule.) |
| v1: production CP MUST NOT invoke `GetStatus` on `/run/stargate/dp.sock`; only the contract-test harness invokes it | Contract test greps the control-plane production source tree (excluding `**/test/**` and `**/*Test.java`) for `GetStatus(` and asserts zero matches. Regression gate against the admin-UI feature silently wiring a production caller before research.md §11's deferral is revisited. |

These tests live at `tests/contract/control-grpc/transport_test.go`.
