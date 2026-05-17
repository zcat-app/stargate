# Contract — Inter-Plane gRPC (subset used by Tor-route v1)

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

**Request**:

```proto
message ReloadTokensRequest {
  uint64 generation = 1;              // monotonic
  repeated TokenHash tokens = 2;
}

message TokenHash {
  bytes hash = 1;                     // 32 bytes (argon2id output)
  bytes salt = 2;                     // 16 bytes
}
```

**Response**:

```proto
message ReloadTokensResponse {
  uint64 applied_generation = 1;
  ApplyStatus status = 2;
}

enum ApplyStatus {
  APPLY_STATUS_UNSPECIFIED = 0;
  APPLY_STATUS_OK = 1;
  APPLY_STATUS_STALE_GENERATION = 2; // request.generation <= current
  APPLY_STATUS_INVALID = 3;          // malformed hash / wrong length
}
```

**Contract**:

- The data plane MUST atomically swap to the new generation before
  returning `APPLY_STATUS_OK`. In-flight requests holding the previous
  generation continue against it.
- If `request.generation <= currentGeneration`, the data plane MUST
  return `APPLY_STATUS_STALE_GENERATION` and leave the current
  generation unchanged.
- Each `TokenHash.hash` MUST be exactly 32 bytes and each `salt`
  exactly 16 bytes; mismatch returns `APPLY_STATUS_INVALID` with no
  generation change.
- On `APPLY_STATUS_OK`, the data plane MUST persist the new
  generation to `dp-snapshot.json` before returning. If the persist
  fails, the response is still `APPLY_STATUS_OK` (in-memory truth
  wins; the snapshot is only a cold-start cache).
- The data plane MUST NOT log the hash bytes, the salt bytes, or any
  token label (labels are not in the message anyway, by design —
  labels live only in the control-plane audit log).

**Tests** (`tests/contract/control-grpc/reload_tokens_test.go`):

1. Happy path: new generation applied; subsequent inbound proxy auth
   uses the new hashes.
2. Stale generation: `request.generation = currentGeneration` →
   `APPLY_STATUS_STALE_GENERATION`, current generation unchanged.
3. Invalid hash length: `request.tokens[i].hash` is 31 or 33 bytes →
   `APPLY_STATUS_INVALID`, current generation unchanged.
4. Snapshot persist failure: simulated by mounting `dp-snapshot.json`
   parent dir read-only → response still `APPLY_STATUS_OK`; data plane
   logs the snapshot-write failure to the journal.
5. Concurrency: two `ReloadTokens` calls with generations N and N+1 in
   parallel; the data plane converges on generation N+1 and rejects
   the older one as stale on retry.

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
- The control plane MUST NOT include log lines, version strings, or
  any other free text from the sidecar in `detail` (arch §5.2).
- The stream is long-lived. On disconnect, the data plane reconnects
  with exponential backoff (initial 1 s, cap 30 s, jitter ±20%).
  During disconnect the data plane keeps using its last-known
  `routeEnableMask` (which is essentially "trust until proven
  otherwise").

**Tests** (`tests/contract/control-grpc/watch_events_test.go`):

1. Happy path: control plane emits `STARTED` then `HEALTHY` for `tor`;
   data plane transitions to ENABLED for the TOR route.
2. Forbidden `detail`: control plane test harness emits a
   `SidecarEvent` with `detail = "could not bind 0.0.0.0:9050"` → the
   contract test fails (the offending field should never have been
   generated; the test is a regression gate against a maintainer
   accidentally piping log lines into `detail`).
3. Disconnect/reconnect: the data plane retries the stream with
   bounded backoff; events delivered after reconnect are applied
   normally.

---

## RPCs explicitly NOT used by this feature

`EnableProtocol`, `DisableProtocol`, `RestartSidecar`,
`ReloadBlocklist`, `GetStatus`. Listed for completeness; the contract
test suite for this feature does not exercise them. They are exercised
by the features that own them.

---

## Transport invariants (arch §5.4)

The contract tests for this feature MUST verify the transport-level
invariants of the inter-plane channel:

| Invariant                                    | Test                                                                                                                                                                |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| UDS path is `/run/stargate/control.sock`     | Contract test asserts the data plane refuses to dial a TCP grpc address.                                                                                            |
| Socket file mode is `0600`, owner `stargate` | Contract test stats the socket file after init.                                                                                                                     |
| Mutual auth: both planes have ed25519 keys   | Contract test verifies the data plane refuses a peer cert it cannot validate against `/etc/stargate/keys/control.pub`.                                              |
| Schema-version handshake                     | Contract test simulates a `stargate.v2` peer offering an unknown major-version marker → data plane logs to journal and exits non-zero (arch §5.5 row 4).            |
| Plane-down survival                          | Contract test stops the control plane after a successful `ReloadTokens`; the data plane MUST continue accepting proxy requests on port 8881 and authenticating them. |

These tests live at `tests/contract/control-grpc/transport_test.go`.
