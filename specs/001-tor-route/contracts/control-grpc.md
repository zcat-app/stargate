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

T159 makes one synchronized pre-release exception inside `stargate.v1`: the
legacy scalar fields remain only as a fail-closed bridge while the mandatory
`auth-set-v1` envelope and acknowledgment replace their semantics. This is a
stop-the-world two-peer transition, not a rolling-compatible additive minor.

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
> response gains a `current_generation` diagnostic field. T159 later forbids
> using it to renumber rejected content. This breaking pre-release contract
> change is recorded as an amendment NOTE (SECURITY-DECISIONS.md §"Bearer-
> token verifier: HMAC-SHA-256 + install-time pepper (T092)"), NOT a
> `stargate.v2` bump — no consumers exist today and semver-on-amendments
> becomes binding at first public release (T091/T099 doctrine). See
> data-model.md §1.

**Request**:

```proto
message ReloadTokensRequest {
  uint64 generation = 1;              // legacy mirror of durable.generation
  repeated TokenVerifier tokens = 2;  // empty in auth-set-v1; old DP sees revoke-all only
  DurableAuthSet durable = 3;          // mandatory versioned authority envelope
}

message DurableAuthSet {
  uint32 semantics_version = 1;        // exactly 1
  uint64 generation = 2;              // nonzero; equals request.generation
  repeated TokenVerifier tokens = 3;
  bytes commitment = 4;               // 32-byte auth-set-v1 commitment
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
  uint64 current_generation = 3;      // diagnostic only; never a CP renumbering instruction
  uint32 acknowledgment_version = 4;  // exactly 1 after durable application
  bytes commitment = 5;               // acknowledged auth-set-v1 commitment
}

enum ApplyStatus {
  APPLY_STATUS_UNSPECIFIED = 0;
  APPLY_STATUS_OK = 1;
  APPLY_STATUS_STALE_GENERATION = 2; // request.generation <= current
  APPLY_STATUS_INVALID = 3;          // malformed verifier / wrong length
}
```

**Contract**:

- `durable.semantics_version` MUST be `1`; `durable.generation` MUST be
  nonzero and equal the legacy `request.generation`; the legacy `tokens`
  list MUST be empty. A missing/unknown durable envelope is a static
  `FAILED_PRECONDITION` before mutation. Other malformed fields return
  `APPLY_STATUS_INVALID` without a durable acknowledgment.
- `auth-set-v1` is SHA-256 over ASCII `stargate-auth-set-v1` followed by one
  zero byte, the verifier count as an unsigned 64-bit big-endian integer,
  then the lexicographically sorted 32-byte verifier members concatenated.
  Duplicates are preserved. The DP recomputes and constant-shape compares
  the 32-byte commitment; mismatch changes nothing. Commitments are
  credential-derived private state and MUST NOT enter logs or errors.
  Independently derived reference vectors (lowercase hex) are:

  | Verifier input | `auth-set-v1` commitment |
  |---|---|
  | empty set | `d1a4d9356a1106626240b962a184f79428f0a4bc69fae59633b599df95411675` |
  | one member containing bytes `00` through `1f` | `0c649950e636116a68b5a738b8f2772a8a8e86147c2e9a552329c600f16793d1` |
  | input order `[ff..e0, 00..1f, ff..e0]` | `090dc7c7c4c28962f5ebe37fb34db11a67afffa98c8b5a1784587e1aa2f2c4c0` |

  The third vector pins unsigned lexicographic sorting and duplicate
  preservation; it is the two members ordered as `00..1f, ff..e0, ff..e0`
  before hashing.
- For a generation greater than the current generation, the DP writes a
  valid schema-v3 snapshot, fsyncs the file, renames it, and fsyncs the
  containing directory before swapping the in-memory pointer. Only then may
  it return `APPLY_STATUS_OK`, `acknowledgment_version=1`, the exact applied
  generation, and exact commitment. A persistence failure returns a static
  non-success gRPC status and leaves the active in-memory generation unchanged.
- A request equal to the current generation is idempotently acknowledged only
  when its commitment and verifier multiset equal the current state. Before
  that acknowledgment the DP rewrites and syncs the current snapshot, repairing
  a newer candidate that may have reached rename before a prior directory-sync
  failure. Equal generation with different content and every lower generation
  return `APPLY_STATUS_STALE_GENERATION` without mutation. `current_generation`
  is diagnostic only and MUST NOT be used to relabel rejected content.
- Each durable `TokenVerifier.verifier` MUST be exactly 32 bytes. A valid
  empty durable set is revoke-all authority; generation zero is never an
  authority generation.
- The CP reserves a changed candidate's next generation before changing its
  stored verifier rows, then delivers only after the row transaction commits.
  A crash before row commit may consume a generation number; it cannot pair
  new content with the old number. Before each actual reload RPC, the CP
  durably prearms one current `UNRESOLVED(G)` marker for the complete candidate.
  Only the exact authenticated generation-and-commitment acknowledgment plus a
  committed conditional clear removes it. A CP restart with `UNRESOLVED` or
  `STALE` blocks token loading and delivery until explicit offline recovery;
  unreadable marker state also blocks. A stale refusal immediately stops the
  process and records absorbing `STALE(G)`; if recording fails, the prior
  `UNRESOLVED(G)` remains the restart barrier. No file edit, timeout, reconnect,
  or ordinary restart clears a gate. Rejection, timeout, missing/wrong
  acknowledgment, or crash never adopts `DP.current_generation + 1`. While the
  originating CP remains running, one coalescing
  redelivery worker retries the latest exact candidate over local IPC with
  exponential backoff capped at five seconds; stale conflict and client close
  terminate that candidate's retry. After acknowledgment, the running CP keeps
  the latest non-stale exact authority in memory and queues it once when the
  authenticated local channel reaches READY after a peer-side disconnect.
  The client's scheduled 55-second credential-lifetime channel retirement
  establishes a fresh READY baseline and MUST NOT issue `ReloadTokens` or
  rewrite the DP snapshot. This event-driven peer-recovery replay repairs a
  DP-only restart with missing/invalid state; it adds no periodic application
  RPC, proxy probe, or public-network traffic.
- Mixed peers fail closed: a new CP sends no legacy tokens, so an old DP can
  install at most revoke-all and cannot return a recognized acknowledgment;
  a new DP rejects an old CP's missing envelope before mutation. Deploy by
  stopping both planes and replacing them together. Legacy schema-v2
  snapshots are incompatible and deny until a matching new CP reseeds.
- In-flight requests holding the previous generation pointer complete against
  it. Reload adds no CP call to an established application byte pipe.
- The data plane MUST NOT log the verifier bytes, the pepper, or any
  token label (labels are not in the message anyway, by design —
  labels remain auth-configuration state and MUST NOT enter any audit log).

**Tests** (`tests/contract/control-grpc/reload_tokens_test.go`):

1. Happy path: new generation applied; subsequent inbound proxy auth
   uses the new verifiers.
2. Replay/conflict: exact same-generation content reasserts its snapshot and
   returns the exact durable acknowledgment; same-generation different content
   and lower generations return `APPLY_STATUS_STALE_GENERATION` without
   mutation or renumbering. A post-rename failure followed by replay restores
   the exact active authority before acknowledgment.
3. Invalid verifier length: `request.durable.tokens[i].verifier` is 31 or 33 bytes →
   `APPLY_STATUS_INVALID`, current generation unchanged.
4. Snapshot persist failure: inject read-only/full/unavailable storage and crash/restart;
   no false durable success and no restored acknowledged revocation (T159).
5. Concurrency: two valid durable calls with generations N and N+1 in
   parallel converge on N+1; retry observes either exact idempotent authority
   or a stale conflict, never a snapshot older than live memory.
6. **Authority reconciliation (T159):** reconnect current persisted authority automatically,
   but reject an older restored CP credential set. Verify revoked tokens stay rejected and
   explicit operator rollback recovery is distinguishable from ordinary reconnect. Exercise
   both mixed-peer directions, snapshot failure, SIGKILL after acknowledgment, valid empty
   restart, and existing byte-pipe completion. Pin the reference commitment vectors on both
   language implementations and run the production Java bootstrap against the production Go
   control server with a restored production SQLite/JTA CP authority older than the DP, asserting
   the revoked credential remains rejected. Then restart only that server without its snapshot
   and prove the still-running CP reseeds the acknowledged set. Shorten the production client's
   channel lifetime, cross at least two local retirements with zero replay, then restart the peer
   and prove one exact replay. Abruptly kill production SQLite/JTA child processes after reservation
   and after candidate commit for both revocation and generation-zero enrollment; each recovery
   process MUST reopen the original database files.

**Supported explicit rollback (T159).** Stop both planes (terminating current
byte pipes), preserve the newer matched DP/CP/key state as the abort path,
restore the selected CP database/configuration with its matching pepper and
IPC keys, and move—not edit—the active DP snapshot out of the state directory.
The operator-confirmed offline recovery procedure explicitly clears a retained
CP `STALE` or `UNRESOLVED` delivery gate before the matching peers restart;
ordinary restart, reconnect, and file edits never clear it. Start matching new
peers and perform the normal durable reseed. The DP persists the exact candidate
before it admits that generation; the CP reports `PENDING` until it receives the
exact authenticated acknowledgment and commits its local clear. A lost response
can therefore leave the CP inhibited even if the DP already installed the set.
Verify intended credential outcomes before reopening service. This operator-
confirmed action may reauthorize credentials present in the selected backup.
Never hand-edit generation/commitment fields. Host/root rollback of all trusted
state is not claimed safe.


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
  T203 preserves T138's authenticated finite health protocol. Its observer reads
  an autonomously published cached state whose original CLOCK_BOOTTIME age must be
  less than four seconds; the six-second RPC cap does not renew that lease.
  Publisher failure, stale state and observer loss are UNAVAILABLE and cannot gate
  DP routing. The sanitized health channel emits only
  `STARTED → container_start`, `HEALTHY → healthcheck_pass`, and
  `UNHEALTHY → healthcheck_fail`. The first authenticated READY or NOT_READY
  sample emits STARTED once. Entry into READY emits HEALTHY; READY to
  NOT_READY or UNAVAILABLE emits UNHEALTHY once. Repeated samples and
  NOT_READY/UNAVAILABLE transitions emit nothing. Health cannot prove Tor
  exited or restarted, so this channel emits no STOPPED, CRASHED or RESTARTED.
  Those enum values and the closed detail vocabulary remain reserved for
  independently substantiated lifecycle sources; no such source ships here.
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
- The stream is long-lived. On disconnect, the data plane reconnects with exponential backoff (initial 1 s, cap 30 s, jitter ±20%). During disconnect the data plane keeps routing; events delivered after reconnection are validated and delivered to the advisory sink. Event receipt does not create a data-plane operational aggregate or sidecar status and MUST NOT gate admission or short-circuit a dial (Constitution Principle II; data-model.md §2). The upstream dial remains the ground truth on cold start, during disconnect, and after reconnect.

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
   plane keeps routing per Principle II). After the server closes the
   first stream, the fake server rejects replacement WatchEvents RPCs
   with `Unavailable`. The test waits for at least one rejected retry,
   proves an authenticated SOCKS5 request still forwards while rejection
   remains enabled, then re-enables WatchEvents and proves forwarding
   after reconnect. It retains the bounded first-retry backoff assertion.

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

### T158 pre-release status transition (2026-09-22)

This is a semantic transition of the existing `stargate.v1` response, with unchanged field
numbers, types and version metadata. Deploy the revised DP and same-revision test/Java bindings
together. Old clients can decode the response but their immediate-delta expectations are no
longer valid; do not mix old accounting probes with the new producer. No production CP status
poller or SQLite traffic writer exists in this feature. Both language bindings must decode
empty and finalized responses over authenticated RPCs before this transition is approved.

- All clock samples and increments serialize under the counter mutex. The effective UTC hour
  is the maximum observed nonnegative Unix hour. Backward wall-clock movement cannot reopen
  a finalized/expired bucket: new increments go to that effective current hour and remain
  private until a later hour is observed. Large forward adjustments can finalize and expire
  rows immediately; host-clock integrity is a precondition, not a protection supplied here.
- Each authenticated request counts at admission; its bytes count exactly once after both
  forwarding pumps finish, in the effective completion hour. Long-lived tunnels never amend
  the earlier request bucket. An empty hour has no row. Reads increment no traffic counters.
- Publish only rows strictly older than the effective hour, as independent sorted copies.
  Finalized row values never change; retention can remove whole rows. No current totals,
  observation timestamps or per-client labels are added to metadata, health or error responses.
- Delete rows when the effective hour reaches `hour_bucket + 168` (seven days from bucket
  start). Every access enforces this cutoff. A lifecycle-bound worker also sweeps at UTC hour
  boundaries while idle; process suspension/scheduler delays can delay physical memory cleanup,
  but an expired row is never returned after execution resumes. Expired rows never reappear
  after rollback. Restart loses all private and finalized traffic state.
- `STARGATE_TRAFFIC_COUNTERS=false` disables accumulation and export from startup; unset/`true`
  enables them. Other values refuse startup with a fixed error. Disabling retention means no
  traffic rows, never unlimited retention. No production control can accelerate this clock.

**Tests**:

1. `tests/contract/socks5/auth_failure_counter_test.go` (T025c) —
   probes `GetStatus` before and after 200 SOCKS auth-failure attempts, plus HTTP `C` refusal probes;
   asserts both finalized counter deltas after controlled rollover are exactly zero.
2. `tests/contract/socks5/auth_passed_counter_test.go` (T025d) —
   probes `GetStatus` before traffic, during the private hour, and after controlled
   rollover following 100 auth-passing CONNECTs each
   transferring exactly `2B` bytes; asserts `request_count` delta is
   100 and `byte_count` delta is exactly `100 × 2B`.
3. `tests/contract/socks5/route_failure_counter_test.go` (T067b) —
   probes `GetStatus` before and after 60 auth-pass CONNECTs (20 each
   against `ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT`); asserts
   `request_count` delta is exactly 60 and `byte_count` delta is
   exactly zero. Gates the FR-008 / data-model.md §3 asymmetry that
   route failures DO increment `request_count` post-auth while their
   SOCKS failure replies do NOT contribute to `byte_count`. HTTP `C` refusal
   does not authenticate, dial or change either counter.
4. Repeated polling, rollback, late completion, concurrent reads, retention and Java/Go
   decoding are exercised against authenticated RPCs with a test-only clock.
5. No-side-effect: between two `GetStatus` calls separated by ≥1 s of
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
