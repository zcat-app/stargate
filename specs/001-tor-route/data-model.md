# Phase 1 — Data Model (Tor Route v1)

> **T156:** `contracts/foundation-boundaries.md` governs auth rollback/recovery and aggregate
> data. Earlier lifecycle diagrams/SQL field sketches are current implementation history where
> they describe automatic renumbering of stale auth (T159). T152 replaces operational
> journals with the implemented §4 aggregate schema and current-only §1.9 auth records.

**Status**: Complete

This document enumerates the entities the data plane and control plane
hold for this feature, their fields, validation rules, and state
transitions. The extension's `storage.local` shape is defined by
architecture spec §14.4 and is not re-stated here; only the bearer-token
field is materially new to this feature and is covered below.

Persistent storage shapes (SQLite schema) are defined in architecture
spec §6 once for the whole project; this feature populates only
`operational_aggregates` and `configured_tokens` (from `tokens.yaml`), plus
maintains the in-memory token list and the data-plane snapshot file.

---

## 1. Bearer token (in-memory verifiers + persisted HMAC tags)

> **Amended by T092 (sol-review B5+M1).** The verifier is **HMAC-SHA-256
> over a dedicated install-time pepper**, not Argon2id. Rationale: a bearer
> token is a uniformly random 128-bit value, so the slow-KDF property
> Argon2id provides is worthless (offline brute-force of a 128-bit secret is
> infeasible at any verifier speed) while its 64 MiB / parallelism-4
> allocation is an unbounded memory-DoS vector — 200 concurrent one-token
> auths allocate ~12.8 GiB (sol-review B5). A single HMAC tag per request
> makes per-request allocation O(1) regardless of N or flood size. A
> persistent CP generation record + exact durable-authority replay replaces the
> prior "CP restart re-hashes and pushes generation 1" path that silently
> revoked every client (sol-review M1). See SECURITY-DECISIONS.md §"Bearer-
> token verifier: HMAC-SHA-256 + install-time pepper (T092)" for the
> accepted-finding rationale and THREAT-MODEL §5.14 for the pepper residue.

### Lifecycle

```
                ┌─────────────────────────────────┐
                │  install-time pepper (32 B)     │
                │  /etc/stargate/keys/pepper.key       │
                │  (generated once by `init`)     │
                └───────────┬──────────┬──────────┘
       read by CP at start  │          │ read by DP at start (auth path)
                            ▼          ▼
   ┌──────────────────────────────────────────────┐
   │  tokens.yaml on disk                         │
   │  (operator-authored)                         │
   └───────────┬──────────────────────────────────┘
               │ read at control-plane start
               ▼
   ┌──────────────────────────────────────────────┐
   │  Control plane — TokenLoader                 │
   │  - read last generation from token_generation│
   │  - parse YAML; validate (32-char lowercase   │
   │    hex)                                      │
   │  - ON FAILURE (missing/unreadable/invalid/   │
   │    unparseable): log config_error, do NOT    │
   │    call ReloadTokens (DP keeps last-known)   │
   │  - verifier = HMAC-SHA-256(pepper, token)    │
   │  - drop plaintext from the mutable buffer    │
   │  - reserve changed generation, then persist   │
   │    the full configured_tokens candidate      │
   │  - count enrolled/revoked only after the DP  │
   │    acknowledges this exact generation (T187) │
   └────────────────────────┬─────────────────────┘
                            │ gRPC ReloadTokens(generation, verifiers[])
                            ▼
   ┌──────────────────────────────────────────────┐
   │  Data plane — auth.tokenStore                │
   │  - equal exact: rewrite snapshot + ACK        │
   │  - equal conflict/lower: STALE, no mutation  │
   │  - higher: write+sync snapshot, then swap     │
   │  - acknowledge exact generation+commitment   │
   └────────────────────────┬─────────────────────┘
                            │ per-request lookup
                            ▼
   ┌──────────────────────────────────────────────┐
   │  Inbound on port 8881                        │
   │  - extract token from SOCKS5 password        │
   │  - HTTP first byte C closes before auth      │
   │  - tag = HMAC-SHA-256(pepper, candidate)     │
   │  - constant-time compare tag against EVERY   │
   │    verifier in current generation (no short- │
   │    circuit — leaks which slot matched)       │
   └──────────────────────────────────────────────┘
```

### 1.1 `tokens.yaml` (operator-authored, read once at start)

Path inside the control-plane container: `/etc/stargate/tokens.yaml`,
mounted from named volume `stargate-control-config`. Volume is
operator-populated for v1 (no UI to write it).

Format:

```yaml
tokens:
  - label: alice-laptop                              # free-form, current auth configuration only
    token: 9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f          # 32-char lowercase hex
  - label: alice-desktop
    token: 1a2b3c4d5e6f70819a8b7c6d5e4f3a2b
```

Validation rules:

| Field   | Rule                                                                                 | Failure behaviour                                                                                       |
|---------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `label` | Non-empty, ≤64 UTF-8 chars, no NUL bytes. Must be unique within the file.            | Reject the record and increment volatile `config_error`; no label/detail is retained. Continue with other records. |
| `token` | Exactly 32 chars, matching `^[0-9a-f]{32}$`. (FR-017: 128-bit hex from `openssl rand -hex 16`.) | Reject the record and increment volatile `config_error`; no label/index/detail is retained. Continue with other records. |
| File    | Valid YAML; `tokens` key present and a sequence. A successfully parsed explicit empty list (`tokens: []`) is permitted and is the **revoke-all** path (FR-018). | Count revoked credentials without identity/detail; push an empty generation. Data plane returns `AUTH_REQUIRED` on all requests. |
| File    | Missing (first-boot: the file does not exist yet).                                   | Emit no diagnostic or operational count (the legitimate first-boot state is also "file does not exist yet"); **do NOT call `ReloadTokens`** — the DP keeps its last-known list and keeps serving (Principle II). (T092 / sol-review M1; §1.6; §4 first-boot exemption.) |
| File    | Unreadable (I/O error other than not-exists, e.g. `AccessDeniedException`).          | Increment the hourly `config_error` category; no event/detail row; **do NOT call `ReloadTokens`** — the DP keeps its last-known list and keeps serving (Principle II). (T092 / sol-review M1; §1.6.) |
| File    | Unparseable YAML, or fails validation so no record set can be derived.               | Increment the hourly `config_error` category; no event/detail row; **do NOT call `ReloadTokens`** — the DP keeps its last-known list and keeps serving. Only a successfully parsed explicit empty list revokes all. (T092 / sol-review M1; §1.6.) |

Plaintext tokens are copied into a mutable `byte[]` the control plane
allocates for the duration of one HMAC operation, and that `byte[]` is
cleared to zero (`Arrays.fill(...)`) before the next file entry is
processed. Plaintext NEVER leaves the control-plane process.

**Memory-erasure claim is deliberately narrow (T092 / sol-review M1).** The
zeroing guarantee covers ONLY mutable buffers the implementation fills
itself — the `byte[]` above. It does NOT cover the `String` values
SnakeYAML materializes while parsing `tokens.yaml`: SnakeYAML hands back
immutable Java `String` objects whose backing array the loader cannot reach
or overwrite, so claiming those were "erased" would be false. The narrowed,
honest claim is: *the HMAC input buffer is cleared; the YAML parser's
internal `String` objects are not, and are left to GC.* T035a's test
observes the buffer it can reach (`byte[]`) and must not be read as proving
the broader parser-internal claim. If full-plaintext erasure ever becomes a
hard requirement, the path is a deliberately mutable secret reader that
never materializes a `String` (recorded as a rejected option for v1, where
the threat model §2.8 already scopes process-memory attackers out).

### 1.2 Verifier (in-memory in data plane, persisted in `configured_tokens`)

The verifier is the 32-byte HMAC-SHA-256 tag of the plaintext token under
the install-time pepper: `verifier = HMAC-SHA-256(pepper, token)`. There is
**no per-token salt** — a single shared pepper makes the candidate's tag
independent of which slot it is compared against, so authentication hashes
the candidate exactly once per request and compares that one tag against
every stored verifier (constant-time; see §1.5).

Fields:

| Field        | Type     | Notes                                                                                          |
|--------------|----------|------------------------------------------------------------------------------------------------|
| `verifier`   | `[]byte` | 32-byte HMAC-SHA-256 tag under the install-time pepper.                                        |
| `generation` | `uint64` | The token-list generation this verifier belongs to; outdated generations are discarded.        |

The pepper is NEVER transmitted, persisted to `dp-snapshot.json`, or logged.
Only verifiers cross the inter-plane RPC and only verifiers appear in the
cold-start snapshot — a snapshot-file leak does not expose the pepper
(THREAT-MODEL §5.14).

### 1.3 Token generation (atomic-swap unit in the data plane)

Fields:

| Field         | Type             | Notes                                                                                |
|---------------|------------------|--------------------------------------------------------------------------------------|
| `generation`  | `uint64`         | Monotonic; assigned by the control plane from its persisted record (§1.7).           |
| `verifiers`   | `[]Verifier`     | The complete current set. Replaces the previous generation atomically.               |
| `loadedAt`    | `time.Time`      | Time when the last authority-changing generation was applied. Exact replay preserves it; it is not the time of the latest snapshot rewrite or an expiry timestamp. Never emitted to diagnostics. |

Replacement semantics: the data plane's `tokenStore` holds a single
`*Generation` pointer guarded by an atomic load/store. `ReloadTokens`
constructs the new `*Generation` and atomic-swaps the pointer. In-flight
requests holding the previous generation pointer complete against it;
new requests pick up the new pointer. The previous pointer is then
garbage-collected.

**Durable authority handshake (T159).** A generation is acknowledged only as
the exact `auth-set-v1` verifier multiset commitment after its snapshot is
durable. Exact same-generation replay first rewrites the active snapshot, then
is idempotently acknowledged; equal-generation
different content and lower generations are conflicts. The CP replays an
unchanged durable candidate at the same generation and never promotes rejected
content by adding one to the DP's current generation. A coalescing local-IPC
redelivery worker retries a pending exact candidate while the CP remains up, so
DP restart does not require CP restart. After acknowledgment, the CP retains
the latest non-stale exact authority in process memory and queues it once when
the authenticated local channel becomes READY after a peer-side disconnect.
The client's scheduled 55-second channel retirement creates a fresh readiness
baseline and neither sends `ReloadTokens` nor rewrites the DP snapshot. This
repairs a DP-only restart with lost/invalid snapshot state without periodic
application RPCs. Automatic reauthorization from stale state is prohibited.

### 1.4 `dp-snapshot.json` (data-plane on-disk cache, arch §5.5)

Path: `/var/lib/stargate/dp-snapshot.json`, mounted from named volume
`stargate-dp-state`. Atomic write via `os.Rename`.

Schema (informal):

```json
{
  "schemaVersion": 3,
  "authSetVersion": 1,
  "generation": 7,
  "commitment": "<base64 32 B auth-set-v1 SHA-256 commitment>",
  "loadedAt": "2026-05-17T14:00:00Z",
  "verifiers": [
    { "verifier": "<base64 32 B HMAC-SHA-256 tag>" }
  ]
}
```

Note: no route-admission state is in the snapshot. See §2 for the rationale (cold start unconditionally attempts the fixed upstream; admission is never gated on a control-plane event — Constitution Principle II).

The snapshot contains **verifiers and their credential-derived commitment
only** — never plaintext, never the pepper, and no per-token salt. It is restored at
data-plane cold start when the control plane is unreachable (arch §5.5
"Control plane down at startup"). The snapshot is rewritten atomically
before every new-generation durable acknowledgment: temp-file write and
fsync, rename, then containing-directory fsync precede the in-memory swap.
Schema 3 adds `authSetVersion: 1` and the recomputed commitment. Schema 1 and
2 snapshots are incompatible and ignored silently: an old DP could report OK
without a successful snapshot write, so schema 2 cannot prove acknowledged
authority through this transition. Missing, corrupt, incompatible,
zero-generation, or commitment-mismatched state restores no authority and
admits nobody. A valid schema-3 empty set is durable revoke-all. Once seeded,
a valid schema-3 snapshot preserves normal CP-down cold-start admission.

### 1.5 Verifier construction — HMAC-SHA-256 over the install-time pepper

```
algorithm   = HMAC-SHA-256
key         = install-time pepper, 32 random bytes
message     = the 32-char lowercase-hex plaintext token (FR-017)
tag length  = 32 bytes
salt        = NONE (single shared pepper; see below)
comparison  = crypto/subtle.ConstantTimeCompare, against EVERY verifier,
              no short-circuit on first match
```

**Why HMAC, not Argon2id (T092 / sol-review B5).** A bearer token is a
uniformly random 128-bit value. Offline brute-force of a correctly
generated 128-bit secret is infeasible at ANY verifier speed (the
2^128 space dwarfs any feasible guess rate), so the slow-KDF property
Argon2id sells is worthless here — Argon2id earns its keep on
*low-entropy human passwords*, which bearer tokens are not. Meanwhile the
64 MiB / parallelism-4 Argon2id allocation is an unbounded memory-DoS
vector: `golang.org/x/crypto/argon2.IDKey` allocates its full `memory`
block slice up front, so 200 concurrent one-token auths allocate
~`200 × 64 MiB = 12.8 GiB` and any local process can reach the loopback
proxy to trigger it. A single HMAC tag per request makes per-request
allocation O(1) regardless of token-list size N or concurrent flood size
— falsified by T093's peak-RSS + unauthenticated-flood bounds (extending
T079a), not by a pool-fill timing test.

**Why no per-token salt.** A single shared pepper makes the candidate's
HMAC tag independent of which verifier slot it is compared against, so
authentication computes the candidate's tag exactly once and compares it
against every stored verifier. This is O(1) hash work per request
regardless of N (the prior Argon2id design was O(N) hash work AND O(N)
64 MiB allocations to keep comparison constant-time). The cost model that
capped v1 at N ≤ 4 is therefore retired: HMAC auth scales to any realistic
N at negligible per-request cost.

**Constant-time comparison is still required.** Although the candidate's
tag is computed once, the comparison loop over the verifier set MUST NOT
short-circuit on the first match: short-circuiting leaks which slot
matched via timing. `ConstantTimeCompare` against every verifier, every
request; the loop's wall-clock is independent of which (if any) verifier
matches.

**Shared constants.** The pepper length (32 B) and the HMAC algorithm
identifier are wired in shared constants (`auth.PepperLen`,
`auth.VerifierAlgo`) so both planes agree; the DP never needs the pepper
length from the RPC — it receives ready-made verifiers. The candidate-side
HMAC in the DP uses the SAME pepper the CP used to mint verifiers (both
read `/etc/stargate/keys/pepper.key`); a pepper mismatch authenticates nothing
and is a misconfiguration surfaced as "all auth fails" at first boot.

### 1.6 Entity-level invariants

- Plaintext tokens never persist outside `tokens.yaml`.
- The pepper never persists outside `/etc/stargate/keys/pepper.key` and never
  appears in `dp-snapshot.json`, the inter-plane RPC, any log, or any audit
  `detail_json`.
- The data plane never sees plaintext tokens (only verifiers) over the RPC.
- Token format violations never log the offending bytes.
- `generation` is monotonic. Exact same-generation/content replay is
  idempotently acknowledged; equal-generation different content and all
  lower generations are rejected without mutation. `current_generation` is
  diagnostic and never authorizes CP renumbering.
- **Failure semantics (T092 / sol-review M1).** A missing, unreadable,
  invalid, or unparseable `tokens.yaml` makes the CP increment the hourly `config_error` aggregate
  category (no sub-kind, line, label or detail retained) and **NOT call
  `ReloadTokens`** — the DP keeps its last-known list and keeps serving port
  8881 (Constitution Principle II "continue routing"). Only a
  successfully-parsed explicit empty list (`tokens: []`) is the revoke-all
  path: that alone pushes an empty generation, after which the DP returns
  `AUTH_REQUIRED` on all requests.

### 1.7 Install-time pepper (`/etc/stargate/keys/pepper.key`)

A 32-byte secret generated once by `scripts/stargate init` (arch §9.1 step
3), shared by CP and DP. T092 makes this shape authoritative; T088
provisions it.

| Concern            | Rule                                                                                                                                                                                                       |
|--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Path               | `/etc/stargate/keys/pepper.key` inside both containers, mounted from the `stargate-keys` named volume (alongside the inter-plane ed25519 keypairs).                                                              |
| Generation         | `openssl rand -bytes 32` (256 bits) at first `init`, written once. Never regenerated unless the operator explicitly rotates (below).                                                                       |
| Ownership / mode   | Owned by the runtime UID of the plane that reads it; group-readable by `stargate-ipc` (GID 5100) so both planes can read it; mode `0640`. (Same ownership/mode scheme as the ed25519 keypairs in that volume.) |
| What reads it      | CP `TokenLoader` (to mint verifiers) and DP `auth` (to mint the candidate's tag). No other component.                                                                                                       |
| Export / import    | Included in `scripts/stargate export` (explicit operator action; warns that the export bundle now contains a secret). `import` restores the pepper verbatim. T088 wires both.                              |
| Backup             | The pepper MUST be in any operator backup of `stargate-keys`; without it every persisted verifier is uncomputable and all stored tokens effectively revoke. Documented in quickstart.md.                   |
| Rotation           | Operator-initiated only: generate a new pepper → re-HMAC every configured token under the new pepper → write new verifiers + bump generation → push via `ReloadTokens`. Old verifiers stop authenticating immediately. |
| Wipe               | `scripts/stargate wipe` removes the pepper file alongside keys and state. T088 extends wipe to cover it.                                                                                                   |
| Not in snapshot    | The pepper is NEVER written to `dp-snapshot.json` (verifiers only — §1.4). A cold-start DP reads the pepper from the keys volume, not the snapshot.                                                       |

**Residue.** Pepper compromise + a `dp-snapshot.json` leak lets an attacker
test candidate tokens offline at HMAC speed. This is mitigated by the
128-bit token entropy: even at billions of HMAC/sec, batch brute-force of a
128-bit space is infeasible — which is precisely why the slow-KDF defence
Argon2id provided was unnecessary for a random token (THREAT-MODEL §5.14).

### 1.8 Control-plane generation record (`token_generation`)

A single persisted row is the source of truth for the monotonic generation
counter, so a CP restart can replay the persisted candidate at its assigned
generation instead of restarting at 1 (which would be stale the moment the DP
has accepted any generation ≥ 1 — sol-review M1).

| Concern            | Rule                                                                                                                                                                                |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Shape              | `token_generation(generation INTEGER PRIMARY KEY)` singleton row in the CP SQLite DB (arch §6.7). The PRIMARY KEY column holds exactly one row, `generation`, the last-assigned value.     |
| Read               | At CP start, `TokenLoader` reads `generation` and current `configured_tokens`. Exact unchanged verifier content replays that generation; changed content proposes `generation + 1`. |
| Write              | After a successful changed `tokens.yaml` parse, the CP reserves the next generation before changing verifier rows, commits the full candidate, then issues durable `ReloadTokens`. A crash before row commit may consume a number but cannot bind new content to an old number. Delivery/ack loss leaves the exact candidate pending for same-generation replay/redelivery. |
| Stale recovery | Refuse stale credential contents. No rejection, timeout, response field, or restart automatically promotes old content to `current + 1`. Explicit rollback is offline and operator-confirmed. |
| DB-wipe recovery | Missing CP authority does not authorize an empty or old list. T159 defines explicit recovery; retain valid DP state meanwhile. |
| Delivery status (T187) | The running CP's current delivery state for its candidate is `PENDING` (no exact acknowledgment yet), `ACKNOWLEDGED(<generation>)` (exact durable acknowledgment) or `STALE_CONFLICT` (stale refusal; terminal for that CP process, never retried or renumbered). It is one overwritten ASCII line in the CP container's private `/tmp` tmpfs file `/tmp/stargate-control/auth-delivery` (mode 0600 in a 0700 directory; not the shared `/run/stargate` IPC volume or persistent `/var/lib/stargate`), removed at CP start, and the CP attempts to write `PENDING` before the initial RPC. UNKNOWN can also occur while a delivery is in flight if status publication fails. A failed replacement write withdraws the previous value (an obsolete state never reads as current) and is retried in the background until the latest state is written. `scripts/stargate status` reads it through `docker compose exec` and prints only validated vocabulary: an absent file is `UNKNOWN` (exit 50), an unreadable one is "state unavailable" (exit 20), and a Docker call that does not answer within its bound (`STARGATE_STATUS_TIMEOUT`, T193) stops the command with exit 70; none claims a lifecycle. No history, timestamp, label or count is recorded (Constitution III current-lifecycle-enum allowance). Stale-conflict recovery is the operator procedure in quickstart.md §"Stale-conflict recovery" (THREAT-MODEL §5.15). |
| Durability         | The generation is durable state, not a cache. Losing it does NOT revoke clients (the DP keeps serving) and does NOT authorize automatic reseeding; use the explicit offline recovery procedure. A running CP redelivers its intact pending candidate when DP IPC returns and retains the latest acknowledged non-stale authority for one event-driven replay after a peer-side authenticated-channel disconnect. Scheduled local channel retirement sends no reload. |

### 1.9 `configured_tokens` — the manual-YAML token record (T092 / sol-review M1)

Manual tokens from `tokens.yaml` carry `(label, verifier)` only; they have
no device public key. Persisting them in `enrolled_devices` (whose `pubkey`
and `token_hash` columns are both `NOT NULL` per arch §6.1 / V001) would
require fabricating a nonexistent key. T092 therefore introduces a dedicated
`configured_tokens` entity for the manual path; `enrolled_devices` is
reserved for the future dashboard-enrollment feature, which is the only
path that actually has a device public key.

| Column | Type | Notes |
|---|---|---|
| `label` | TEXT | Current token configuration key, unique and non-null; never an operational label. |
| `verifier` | BLOB | Current 32-byte HMAC-SHA-256 verifier under the installation pepper. |

V002 preserves active `(label, verifier)` records and the generation singleton. It deletes
revoked records and removes creation/revocation/last-seen columns: those were operational
history rather than required authentication state. A revoke deletes the record; a subsequent
explicit enrollment inserts current state afresh. Transaction rollback still restores the
previous credential set. The unrelated future `enrolled_devices` scaffold has no v1 writer.

**Rejected alternative** (recorded so it is not re-litigated
later): making `enrolled_devices.pubkey` nullable to host manual records.
Rejected because it muddies `enrolled_devices`'s contract (a device row
without a device key is not a device row) and leaves a NOT-NULL `token_hash`
column named for a verifier it does not hold; the separate entity is the
clean separation the ticket asks for.

---

## 2. Tor route admission

There is **no control-plane-driven admission gate** for the Tor route. The data plane attempts the fixed upstream (`unix:///run/stargate-tor/tor-socks.sock`) on every admitted request; the upstream dial/handshake result alone decides success or the privacy-safe route error (`ROUTE_DOWN` / `ROUTE_REFUSED` / `ROUTE_TIMEOUT` per FR-009). A control-plane `SidecarEvent` is delivered to the data plane as an advisory routing signal only. Receipt does not create a data-plane operational aggregate or sidecar status, and MUST NOT be a precondition for listening, authenticating, dialing, or forwarding (Constitution Principle II; sol-review B3).

**Why no mask.** A cold-start mask that begins DISABLED and waits for the
first `HEALTHY` event makes routing availability depend on the advisor
plane, which is exactly the failure coupling Principle II forbids:
restarting only the data plane during a control-plane outage would stop
routing even when Tor and the last-known token snapshot are healthy. The
fixed upstream dial is the authoritative signal — try the DP-only Tor SOCKS
fabric socket, forward
on success, return the protocol-safe route failure on connect/handshake
failure. Absence or staleness of a sidecar event can never deny admission.

**Advisory consumption (control-plane aggregates; data-plane routing only).** The control plane records its own source-observed Tor sidecar `HEALTHY` / `UNHEALTHY` transitions in the corresponding `sidecar_healthy` / `sidecar_unhealthy` completed-hour operational aggregate through the sole writer in §4. Those counts describe control-plane observations while it runs, not data-plane event receipts. Receipt of any `SidecarEvent`—including `STARTED`, `HEALTHY`, `UNHEALTHY`, `STOPPED`, `CRASHED`, or `RESTARTED`—does not create a data-plane operational counter or sidecar status. The data plane validates and delivers matching Tor `SidecarEvent`s to its advisory sink only; its `GetStatus` exposes traffic route counters, not sidecar state. For every admitted request, the data plane MUST attempt the fixed upstream dial. A stale or forged event cannot suppress a dial that would succeed; only the upstream dial result selects `ROUTE_DOWN` / `ROUTE_REFUSED` / `ROUTE_TIMEOUT`. Advisory event handling MUST NOT log destination, token, or per-request metadata (Principle III).

**No persisted admission state.** The snapshot at §1.4 carries token
hashes only; there is no per-route enable bit to persist. Cold start
begins with the same admission policy as a warm process: every admitted
request reaches the upstream dial.

---

## 3. Aggregate counters (arch §6.4)

This feature populates the `aggregate_counters` row for `route = 'TOR'`.
Columns are defined in architecture spec §6.4; restated here for clarity:

| Column          | Type    | Update rule                                                                            |
|-----------------|---------|----------------------------------------------------------------------------------------|
| `route`         | TEXT    | Always `'TOR'` for rows produced by this feature.                                       |
| `hour_bucket`   | INTEGER | Effective UTC Unix hour at increment time, never below the greatest hour observed this boot (T158).                         |
| `request_count` | INTEGER | Incremented by 1 on each authenticated SOCKS5 CONNECT through port 8881. HTTP `C` refusal does not authenticate or increment it. Auth failures are NOT counted (Principle III — counting them would be a side channel for token-guessing attacks, since an attacker can submit tokens at will). Route failures (`ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT`) DO count: they are not attacker-controlled in the same way, and the gap between `request_count` and "the fraction of `byte_count > 0` per hour" gives the admin sidecar-health visibility at negligible privacy cost. |
| `byte_count`    | INTEGER | Incremented by the total bytes **forwarded between client and upstream** in both directions at request close. SOCKS failure replies and renderer-only future HTTP bodies are NOT included — `byte_count` reflects actual cross-network transfer only. HTTP `C` refusal forwards zero bytes and does not increment it. |

The data plane buffers increments in-memory only in this feature. The
CP→DP `GetStatus` pull (arch §5.2) is the documented flush mechanism;
the **RPC itself ships in v1's proto and is hosted by the DP** per
`contracts/control-grpc.md` §"GetStatus (minimum subset)", but the
**production CP-side caller** that flushes counters to SQLite is
**deferred to the admin-UI feature**. In v1 the only caller is the
contract-test harness (T025c, T025d), which probes counter invariants
without persisting anything. The counters live in the data plane's
process memory and are lost on DP restart. The FR-008 invariant
(no per-request data, hour-bucketed aggregates only) holds regardless:
deferring the CP caller does not relax what the DP records, only where
the counts ultimately reach. When the admin-UI feature wires its
caller, the CP writes the pulled rows to SQLite via Hibernate Panache.

**T158 publication and retention:** only completed rows cross GetStatus. A row expires at
`hour_bucket + 168`; active and retained rows are volatile and restart loses both. Clock rollback
never reopens published or expired hours; completion bytes enter the effective current hour,
including when admission's row has already expired. The exact clock, idle-cleanup and pre-release
peer transition are in [control-grpc.md](contracts/control-grpc.md#t158-pre-release-status-transition-2026-09-22).
`STARGATE_TRAFFIC_COUNTERS=false` disables accumulation/export for the boot. No production
clock override or SQLite traffic writer is added. Finalized rows are immutable until removed,
so a future persistence consumer must expire whole rows and must never poll for active totals.

**Invariants (T158 implementation; evidence in reviews/T158/README.md)**:

- GetStatus/export/storage disclose only completed immutable hour buckets. Never return a changing
  current-hour count; repeated reads must not reveal fine-grained request activity.
- No row contains destination, token, or sub-hour data.
- The data plane never reads from or writes to the SQLite
  `aggregate_counters` table — it holds in-memory counters only and
  serves a snapshot of them via the DP-hosted `GetStatus` RPC. Persisting
  the snapshot to SQLite is the CP's responsibility (deferred to the
  admin-UI feature's CP-side caller per §3 preamble above).

---

## 4. Operational aggregates (T152)

The forward `V002__operational_aggregates.sql` migration drops `audit_log` and its triggers.
V001 remains an immutable migration fixture; its historical append-only/schema tests target
V001 explicitly, while migration and aggregate-service tests exercise the active schema.
Flyway retains version/checksum/success as schema identity; V002 replaces installation actor,
time and duration with fixed placeholders, including later migration inserts. Validation still
checks the original migration checksums. These fields carry no installation event history.

```sql
CREATE TABLE operational_aggregates (
  hour_bucket INTEGER NOT NULL, -- UTC start, integer multiple of 3600
  category TEXT NOT NULL,       -- fixed five-category vocabulary below
  count INTEGER NOT NULL,      -- nonnegative signed 64-bit counter, saturating on overflow
  PRIMARY KEY (hour_bucket, category)
) WITHOUT ROWID;
```

SQL CHECKs enforce these types/ranges and the vocabulary: `enrolled`, `revoked`, `config_error`,
`sidecar_healthy`, `sidecar_unhealthy`. UPDATE is refused and duplicate inserts/replacements
leave the original record intact. DELETE is permitted for retention. No surrogate/sequence
ID, actor, token/device label, per-event timestamp, generation or arbitrary detail is present.

`AuditLogService` is the sole operational counter writer. Its existing in-process
`write(action, target, detailJson)` seam remains source compatible; only the allowlisted action
is used. The other two arguments are discarded immediately, never put into accumulator or
transaction state. An invalid category raises a static error without echoing input. Existing
loader/parser tests can inspect transient caller arguments; those fixtures are not a storage
contract or permission to retain them.

T187: `enrolled`/`revoked` describe applied credential changes. The loader records them outside
the candidate transaction, only after the DP acknowledges that exact generation, as standalone
observations in the acknowledgment's hour. A pending delivery counts nothing until acknowledged
while this CP runs; a stale refusal never counts; a CP restart before acknowledgment replays the
same candidate with no diff, so that change is never counted (an undercount, never a premature
success claim). A later reconnect re-acknowledgment does not count again.

A transaction stores only a five-counter vector in transaction-local memory. Only a successful
commit contributes it, using the UTC hour at completion. Rollback and rollback-only transactions
contribute nothing. Standalone sidecar/configuration events count in their observation hour.
Counters remain volatile until that hour closes; crash/restart can lose the open hour and
unpersisted completed counts. Operational counts describe observations made by this running
CP, not a durable event journal or an uninterrupted monitoring guarantee.

A one-second worker finalizes eligible buckets and expires retention; it also runs at startup.
No new event is needed to close an hour. Failed writes retry the same immutable bucket, with
at most seven days of pending hourly vectors. Counts are never moved into a different hour to
hide clock regression. A future export must call the same finalization/expiry boundary before
querying rows; there is no production operational export API in feature 001 yet.

The most recent completed hour retains a zero `enrolled` counter when no enrollment was
observed. This valid aggregate supplies a restart clock boundary even after older nonzero
counts expire. Other zero categories may be omitted. Within a collection lifetime, backwards
clock readings contribute no new events until they catch up; startup reads the maximum retained
hour and cannot reopen it, including for a category previously absent from that hour.

Rows expire when `hour_bucket + 3600 + 7 days <= latest observed time`. The running worker
removes them on its next tick (normally within one second); startup removes rows aged during
an outage before use. A stopped/unwritable database cannot erase itself. No export may bypass
expiry. `stargate.operational.retention-enabled=false` deletes all operational rows at startup
and collects none. Disabling retention/deleting the database deliberately ends that collection
lifetime and its clock checkpoint; a later explicit re-enable starts a new lifetime. Host-wide
clock/state rollback is not a forensic or tamper-proof chronology guarantee.

Java/Go operational diagnostics are silent. DP admission, credential application, sidecar
advisory delivery and static IPC failures keep their existing behavior. Go process descriptors
and Java/Tor entrypoints suppress native/framework stdout/stderr before private state is read;
Compose disables raw logging, core dumps and Docker health-history capture. Current Tor health
still comes from the authenticated observer; installer readiness requires its bounded one-shot
`--check-ready` query to return READY. Cleanup of legacy SQLite WAL, container archives
and backups is specified in THREAT-MODEL §5.18; no forensic host-erasure claim is made.

---

## 5. Extension `storage.local` — token field only

This feature adds one field to the extension's `storage.local` shape
(otherwise defined by arch §14.4):

```json
{
  "device": {
    "name": "<user-entered, free-form>",
    "bearerToken": "<32-char lowercase hex>",      <-- this feature
    "tokenStoredAt": <hourBucket>                  <-- this feature
  }
}
```

Validation in the options page:

- `bearerToken` must match `^[0-9a-f]{32}$` before save.
- On save, the extension displays a warning if the storage path is
  `storage.local` and not a credential-grade keyring (research.md §6 —
  this is always the case in v1, so the warning always shows).

### 5.1 Canonical `storage.local` warning text

The warning text rendered in `extension/options/options.html` MUST be
exactly the following string (locked here as the single source of
truth; T056's inline test asserts byte-for-byte equality):

> Your bearer token will be saved to disk in this extension's
> storage.local, inside your browser profile directory. Any local
> process with read access to that directory can read it. Firefox ESR
> offers no credential-grade alternative for extensions.

Devs reading this section: the rationale for accepting `storage.local`
as the storage path despite the residual filesystem-read risk is in
research.md §6 and aligns with THREAT-MODEL §3.1's local-execution
assumption. That justification is **not** carried into the user-facing
string — users see a clean factual notice, not a doc cross-reference.

Drift between `options.html`'s rendered text and the string above is a
contract violation; the test gates against silent edits to either side.

---

## 6. Compose / volume identities

Named volumes this feature creates (referenced by name in
`docker-compose.local.yml`):

| Volume                       | Mounted into                                  | Contents                                       |
|------------------------------|-----------------------------------------------|------------------------------------------------|
| `stargate-keys`              | data-plane and control-plane containers       | ed25519 keypairs for inter-plane gRPC mTLS     |
| `stargate-ipc`               | both planes                                   | the two inter-plane UDS files: `/run/stargate/control.sock` (CP-hosted, `WatchEvents`; owned `stargate-cp:stargate-ipc` mode 0660) and `/run/stargate/dp.sock` (DP-hosted, `ReloadTokens`; owned `stargate-dp:stargate-ipc` mode 0660) — see `contracts/control-grpc.md` §"Socket topology" for why the shared `stargate-ipc` group (GID 5100) is the right mechanism for "peer dials, no one else does" |
| `stargate-control-config`    | control-plane container                       | operator-authored `tokens.yaml`                |
| `stargate-control-state`     | control-plane container                       | SQLite DB and Flyway state                     |
| `stargate-dp-state`          | data-plane container                          | `dp-snapshot.json`                             |
| `stargate-tor-state`         | Tor sidecar container only                    | Tor `DataDirectory`, entry-guard state, private control socket and cookie. Neither application plane mounts this volume. The contract-test harness reaches the control socket inside Tor; the CP's former direct control access is withdrawn pending T164's sanitized observer. |
| `stargate-tor-dp-fabric`     | Tor sidecar RW; data plane RO                  | Only the group-gated Tor SOCKS re-exposure. Tor's native socket directory remains private within this volume; the DP cannot traverse it. |
| `stargate-tor-cp-fabric`     | control plane RO                               | Reserved for T164's sanitized observer; no raw Tor control socket or cookie. |
| `stargate-tor-config`        | (none — removed from v1 by T191)              | **Not created in v1.** The safe `torrc` is baked into the Tor image at build time (T087, FR-011 amended by T089); Tor loads `/etc/tor/torrc` from the image with no dependency on the control plane (Constitution Principle II / sol-review B2). T191 removed the dormant CP-writable mount, the volume declaration and init's root setup. A future dynamic-config feature (bridges toggle, live reload; T037 `TorrcRenderer`) that needs a CP-RW / Tor-RO config volume must reintroduce it under its own contract and review. |

These volumes are the unit `scripts/stargate wipe` operates on (out of
scope for this feature — wipe ships in a later feature).
