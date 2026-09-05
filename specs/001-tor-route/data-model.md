# Phase 1 — Data Model (Tor Route v1)

**Status**: Complete

This document enumerates the entities the data plane and control plane
hold for this feature, their fields, validation rules, and state
transitions. The extension's `storage.local` shape is defined by
architecture spec §14.4 and is not re-stated here; only the bearer-token
field is materially new to this feature and is covered below.

Persistent storage shapes (SQLite schema) are defined in architecture
spec §6 once for the whole project; this feature populates only
`audit_log` and (indirectly, via `tokens.yaml`) `enrolled_devices`, plus
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
> persistent CP generation record + reconciliation handshake replaces the
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
   │  - persist generation+verifiers to           │
   │    configured_tokens; bump token_generation  │
   │  - INSERT audit_log row per label diff       │
   └────────────────────────┬─────────────────────┘
                            │ gRPC ReloadTokens(generation, verifiers[])
                            ▼
   ┌──────────────────────────────────────────────┐
   │  Data plane — auth.tokenStore                │
   │  - if generation <= current: STALE, reply    │
   │    current_generation for CP retry           │
   │  - else atomic-swap to new generation        │
   │  - write dp-snapshot.json (verifiers ONLY)   │
   │  - acknowledge applied_generation            │
   └────────────────────────┬─────────────────────┘
                            │ per-request lookup
                            ▼
   ┌──────────────────────────────────────────────┐
   │  Inbound on port 8881                        │
   │  - extract token from SOCKS5 pw or           │
   │    Proxy-Authorization                       │
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
  - label: alice-laptop                              # free-form, audit-log only
    token: 9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f          # 32-char lowercase hex
  - label: alice-desktop
    token: 1a2b3c4d5e6f70819a8b7c6d5e4f3a2b
```

Validation rules:

| Field   | Rule                                                                                 | Failure behaviour                                                                                       |
|---------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `label` | Non-empty, ≤64 UTF-8 chars, no NUL bytes. Must be unique within the file.            | Reject the record. Log a warning with **label only** (never the token bytes). Continue with other records. |
| `token` | Exactly 32 chars, matching `^[0-9a-f]{32}$`. (FR-017: 128-bit hex from `openssl rand -hex 16`.) | Reject the record. Log a warning **without the offending token bytes** (record index + label only). Continue with other records. |
| File    | Valid YAML; `tokens` key present and a sequence. A successfully parsed explicit empty list (`tokens: []`) is permitted and is the **revoke-all** path (FR-018). | Log a warning; push an empty generation. Data plane returns `AUTH_REQUIRED` on all requests. |
| File    | Missing (first-boot: the file does not exist yet).                                   | Log a warning (path only, no token context — there are none); write **no** audit row (the legitimate first-boot state is also "file does not exist yet"); **do NOT call `ReloadTokens`** — the DP keeps its last-known list and keeps serving (Principle II). (T092 / sol-review M1; §1.6; §4 first-boot exemption.) |
| File    | Unreadable (I/O error other than not-exists, e.g. `AccessDeniedException`).          | Log a `config_error` audit row (`kind=io`, `line=null`); **do NOT call `ReloadTokens`** — the DP keeps its last-known list and keeps serving (Principle II). (T092 / sol-review M1; §1.6.) |
| File    | Unparseable YAML, or fails validation so no record set can be derived.               | Log a `config_error` audit row (`kind=parse` / `validation`); **do NOT call `ReloadTokens`** — the DP keeps its last-known list and keeps serving. Only a successfully parsed explicit empty list revokes all. (T092 / sol-review M1; §1.6.) |

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
| `loadedAt`    | `time.Time`      | Wall-clock when the data plane received the generation (used only for journal logs at restart, NOT per-request). |

Replacement semantics: the data plane's `tokenStore` holds a single
`*Generation` pointer guarded by an atomic load/store. `ReloadTokens`
constructs the new `*Generation` and atomic-swaps the pointer. In-flight
requests holding the previous generation pointer complete against it;
new requests pick up the new pointer. The previous pointer is then
garbage-collected.

**Reconciliation handshake (T092 / sol-review M1).** `generation` is
monotonic; the data plane rejects a `ReloadTokens` RPC with
`generation <= currentGeneration` by returning
`APPLY_STATUS_STALE_GENERATION` and reporting its `current_generation` in
the response, so the control plane can re-read its persisted record, propose
`current + 1`, and retry deterministically. This is the mechanism that lets
a restarted CP converge without accidentally revoking clients: it never
restarts at 1 (it reads its persisted record, §1.7), and if its proposal is
somehow stale (e.g. its DB was restored from an older backup) the DP tells
it the truth and it retries.

### 1.4 `dp-snapshot.json` (data-plane on-disk cache, arch §5.5)

Path: `/var/lib/stargate/dp-snapshot.json`, mounted from named volume
`stargate-dp-state`. Atomic write via `os.Rename`.

Schema (informal):

```json
{
  "schemaVersion": 2,
  "generation": 7,
  "loadedAt": "2026-05-17T14:00:00Z",
  "verifiers": [
    { "verifier": "<base64 32 B HMAC-SHA-256 tag>" }
  ]
}
```

Note: no route-admission state is in the snapshot. See §2 for the rationale (cold start unconditionally attempts the fixed upstream; admission is never gated on a control-plane event — Constitution Principle II).

The snapshot contains **verifiers only** — never plaintext, never the
pepper, and (amended by T092) no per-token salt. It is restored at
data-plane cold start when the control plane is unreachable (arch §5.5
"Control plane down at startup"). The snapshot is rewritten atomically
every time `ReloadTokens` succeeds. `schemaVersion` bumped 1 → 2 by T092
(reflects the `hash`+`salt` → `verifier` shape change); a cold start that
reads a stale `schemaVersion: 1` snapshot MUST ignore it (log a warning,
serve no tokens until the CP pushes a fresh generation) rather than
misparse it — parsing v1 `{hash, salt}` pairs as v2 verifiers would
authenticate nothing and silently break routing.

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
- `generation` is monotonic; the data plane rejects a `ReloadTokens` RPC
  with `generation <= currentGeneration`, replies with its
  `current_generation`, and leaves the active generation unchanged.
- **Failure semantics (T092 / sol-review M1).** A missing, unreadable,
  invalid, or unparseable `tokens.yaml` makes the CP log a `config_error`
  audit row (sub-kind `io` | `validation` | `parse`) and **NOT call
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
counter, so a CP restart proposes `last + 1` instead of restarting at 1
(which would be stale the moment the DP has accepted any generation ≥ 1 and
would silently revoke every client via the reconciliation handshake —
sol-review M1).

| Concern            | Rule                                                                                                                                                                                |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Shape              | `token_generation(generation INTEGER PRIMARY KEY)` singleton row in the CP SQLite DB (arch §6.7). The PRIMARY KEY column holds exactly one row, `generation`, the last-assigned value.     |
| Read               | At CP start, `TokenLoader` reads `generation`. The proposal for this boot is `generation + 1`.                                                                                       |
| Write              | After a successful `tokens.yaml` parse, the CP writes the new verifiers to `configured_tokens`, bumps `token_generation.generation` to the proposal, then issues `ReloadTokens`.    |
| Stale recovery     | If the CP's persisted record is older than the DP's current generation (e.g. CP DB restored from an older backup), `ReloadTokens` returns `APPLY_STATUS_STALE_GENERATION` + the DP's `current_generation`; the CP adopts `current + 1`, re-reads its persisted tokens, and retries. |
| DB-wipe recovery   | If the CP DB is wiped (no `token_generation` row), the CP reconciles against the DP's reported `current_generation` (proposes `current + 1`, or 1 if the DP has none) rather than guessing. |
| Durability         | The generation is durable state, not a cache. Losing it does NOT revoke clients (the DP keeps serving) but DOES require the reconciliation path above to re-sync.                    |

### 1.9 `configured_tokens` — the manual-YAML token record (T092 / sol-review M1)

Manual tokens from `tokens.yaml` carry `(label, verifier)` only; they have
no device public key. Persisting them in `enrolled_devices` (whose `pubkey`
and `token_hash` columns are both `NOT NULL` per arch §6.1 / V001) would
require fabricating a nonexistent key. T092 therefore introduces a dedicated
`configured_tokens` entity for the manual path; `enrolled_devices` is
reserved for the future dashboard-enrollment feature, which is the only
path that actually has a device public key.

| Column          | Type    | Notes                                                                                  |
|-----------------|---------|----------------------------------------------------------------------------------------|
| `label`         | TEXT    | From `tokens.yaml`; unique; audit-log key. Same validation as §1.1.                    |
| `verifier`      | BLOB    | 32-byte HMAC-SHA-256 tag under the pepper (§1.5).                                      |
| `created_at`    | INTEGER | Unix seconds; set when the label is first seen (audit `enrolled`).                     |
| `last_seen_hour`| INTEGER | Hour-bucket of last auth pass (Principle III ≥1h). Nullable until first use.           |
| `revoked_at`    | INTEGER | Nullable; set when the label disappears from `tokens.yaml` (audit `revoked`).          |

Full DDL lands in arch §6.6 and `V001__init.sql` in lock-step with this
section (T092). **Rejected alternative** (recorded so it is not re-litigated
later): making `enrolled_devices.pubkey` nullable to host manual records.
Rejected because it muddies `enrolled_devices`'s contract (a device row
without a device key is not a device row) and leaves a NOT-NULL `token_hash`
column named for a verifier it does not hold; the separate entity is the
clean separation the ticket asks for.

---

## 2. Tor route admission

There is **no control-plane-driven admission gate** for the Tor route. The
data plane attempts the fixed upstream (`tor:9050`) on every admitted
request; the upstream dial/handshake result alone decides success or the
privacy-safe route error (`ROUTE_DOWN` / `ROUTE_REFUSED` / `ROUTE_TIMEOUT`
per FR-009). A control-plane `SidecarEvent` (`HEALTHY`, `UNHEALTHY`,
`STOPPED`, `CRASHED`, `RESTARTED`, `STARTED`) is an **advisory local
status/audit hint** — it MUST NOT be a mandatory precondition for
listening, authenticating, dialing, or forwarding (Constitution Principle
II; sol-review B3).

**Why no mask.** A cold-start mask that begins DISABLED and waits for the
first `HEALTHY` event makes routing availability depend on the advisor
plane, which is exactly the failure coupling Principle II forbids:
restarting only the data plane during a control-plane outage would stop
routing even when Tor and the last-known token snapshot are healthy. The
fixed upstream dial is the authoritative signal — try `tor:9050`, forward
on success, return the protocol-safe route failure on connect/handshake
failure. Absence or staleness of a sidecar event can never deny admission.

**Advisory consumption (audit + status only).** The data plane MUST
always attempt the upstream dial on every admitted request.
`SidecarEvent`s feed the audit journal (`sidecar_healthy` /
`sidecar_unhealthy` rows per §4) and may drive status reporting; they
MUST NOT influence the admission decision or short-circuit the dial.
A `STOPPED` / `CRASHED` event is recorded in the audit log and may
surface "sidecar unhealthy" in status, but the data plane still dials
`tor:9050` — a stale or forged event cannot suppress a dial that would
succeed (Constitution Principle II: "a compromise of the management UI
cannot silently corrupt routing decisions"). The upstream dial result
is the sole input to `ROUTE_DOWN` / `ROUTE_REFUSED` / `ROUTE_TIMEOUT`
selection. Advisory consumption MUST NOT log destination, token, or
per-request metadata (Principle III).

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
| `hour_bucket`   | INTEGER | Current `time.Now().Unix() / 3600`, computed at increment time.                         |
| `request_count` | INTEGER | Incremented by 1 on each SOCKS5 or HTTP CONNECT through port 8881 that passes authentication. Auth failures are NOT counted (Principle III — counting them would be a side channel for token-guessing attacks, since an attacker can submit tokens at will). Route failures (`ROUTE_DOWN`, `ROUTE_REFUSED`, `ROUTE_TIMEOUT`) DO count: they are not attacker-controlled in the same way, and the gap between `request_count` and "the fraction of `byte_count > 0` per hour" gives the admin sidecar-health visibility at negligible privacy cost. |
| `byte_count`    | INTEGER | Incremented by the total bytes **forwarded between client and upstream** in both directions at request close. The error-template body synthesised by the data plane for `AUTH_REQUIRED` / `ROUTE_DOWN` / `ROUTE_REFUSED` / `ROUTE_TIMEOUT` is NOT included — `byte_count` reflects actual cross-network transfer only. |

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

**Invariants**:

- No row contains destination, token, or sub-hour data.
- The data plane never reads from or writes to the SQLite
  `aggregate_counters` table — it holds in-memory counters only and
  serves a snapshot of them via the DP-hosted `GetStatus` RPC. Persisting
  the snapshot to SQLite is the CP's responsibility (deferred to the
  admin-UI feature's CP-side caller per §3 preamble above).

---

## 4. Audit-log entries

This feature writes audit-log rows on:

| Trigger                                          | `action`             | `target` (label)           | `detail_json`                                                  |
|--------------------------------------------------|----------------------|----------------------------|-----------------------------------------------------------------|
| New token label encountered during file load     | `enrolled`           | `<label>`                  | `{"source": "tokens.yaml", "generation": <gen>}`                |
| Token label removed (label present in last load but missing now) | `revoked`            | `<label>`                  | `{"source": "tokens.yaml", "generation": <gen>}`                |
| `tokens.yaml` load failure                       | `config_error`       | `tokens.yaml`              | `{"kind": "parse" \| "validation" \| "io", "line": <int or null>}` — `parse` for YAML syntax errors; `validation` for per-entry format violations (wrong length, non-hex); `io` for unreadable-file conditions other than not-exists (e.g. `AccessDeniedException`). The **missing-file** case writes no row (the legitimate first-boot state is also "file does not exist yet"); per the T092 / sol-review M1 amendment to FR-018, on missing/unreadable/invalid/unparseable input the CP logs a warning or `config_error` row and **does NOT call `ReloadTokens`** — the DP keeps its last-known list and keeps serving (Principle II). Only a successfully parsed explicit `tokens: []` revokes all. Distinguishing missing (first-boot, no row) from misconfigured-permissions (`io` row) is what the `io` kind exists for. |
| Tor sidecar transition to HEALTHY                | `sidecar_healthy`    | `tor`                      | `{"generation": <gen>}`                                         |
| Tor sidecar transition to UNHEALTHY/STOPPED/CRASHED | `sidecar_unhealthy` | `tor`                      | `{"kind": "<UNHEALTHY|STOPPED|CRASHED>"}`                       |

`actor` for token actions is the constant `"tokens.yaml"` (the source of
truth in v1); for sidecar transitions it is the constant `"system"`. No
user identity is captured because there is no admin UI in this feature.

The detail JSON schema is fixed-vocabulary — the `kind`/`source` values
are an enum, not free text. This satisfies arch §5.2's
"`detail` is a fixed-vocabulary token (not free text from a sidecar
log)" requirement.

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
| `stargate-tor-state`         | Tor sidecar container (whole volume); control-plane container reads ONLY the cookie file via a read-only single-file volume-subpath mount at `/run/tor/control_auth_cookie` (T039, GID-aligned to the tor image's GID 5103 — T094a rejected mounting the volume whole) | Tor `DataDirectory` — entry-guard persistence (THREAT-MODEL §4.2). The control-port cookie file (`/var/lib/tor/control_auth_cookie`) also lives here; the contract-test harness reads it via T062, and the CP's `SidecarMonitor` reads it via the subpath mount — see `contracts/torrc.md` for the auth flow. The subpath mount is the narrow-read invariant: entry-guard state is readable only inside the tor container. Gated by `local_compose_test.sh` M14. |
| `stargate-tor-config`        | (deferred — dynamic-config feature)           | **Deferred by T089.** For v1 the safe `torrc` is baked into the Tor image at build time (T087, FR-011 amended by T089), so this volume is NOT used for v1 boot — Tor loads `/etc/tor/torrc` from the image with no dependency on the control plane (Constitution Principle II / sol-review B2). The volume's CP-RW / Tor-RO mount and its role as the target of `TorrcRenderer`'s atomic write (T037) are future work for a dynamic-config feature (bridges toggle, live reload); T037 is deferred with it. Whether the volume remains declared-but-dormant in compose or is removed entirely for v1 is T087's implementation call; this row records only that v1 boot does not depend on it. |

These volumes are the unit `scripts/stargate wipe` operates on (out of
scope for this feature — wipe ships in a later feature).
