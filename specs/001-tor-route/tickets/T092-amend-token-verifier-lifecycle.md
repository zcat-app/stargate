---
id: T092
title: 'Amend the token verifier and lifecycle contract'
status: pending
created: 2026-07-11
last_updated: 2026-07-15
source: review/sol-review.md#B5+M1
phase: "2: Foundational (Blocking Prerequisites)"
story: '-'
blocked_by: []
parallel: false
files_budget: 16
privacy_critical: true
constitution_refs:
  - "II: Plane separation"
  - "III: Privacy-preserving by construction"
  - "VII: Tests-first for authentication"
complexity: high
risk: high
round_cap: 3
spec_refs:
  - specs/001-tor-route/spec.md §FR-006
  - specs/001-tor-route/spec.md §FR-013
  - specs/001-tor-route/data-model.md §1
  - specs/001-tor-route/contracts/control-grpc.md §"ReloadTokens"
decision_refs: []
spec_amend_for: specs/001-tor-route/data-model.md §1
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T092: Amend the token verifier and lifecycle contract

## Context

Per-request Argon2id can allocate roughly 12.8 GiB for 200 simultaneous
one-token authentications even though the token already has 128 random bits.
The same design lacks a persistent generation source and treats file I/O
failure as revoke-all.

## Analysis

Property map (grounding-verified 2026-07-15; `privacy_critical: true` →
required per `docs/process/analysis.md`). Constitution principles land here
as concrete properties, not prose. Source findings: sol-review B5 (memory-
based DoS path) + M1 (lifecycle inconsistency).

- **Must hold**
  - **Bounded-memory authentication (B5).** Per-request auth does exactly
    ONE HMAC-SHA-256 over the candidate token and compares the 32-byte tag
    against every stored verifier with `crypto/subtle.ConstantTimeCompare`.
    No Argon2id / KDF allocation path remains in the verifier; peak
    per-request allocation is O(1) regardless of token-list size N or
    concurrent flood size (Constitution Principle III — a local process
    must not be able to memory-DoS the loopback proxy by spamming auth).
  - **Constant-time across the verifier set.** The comparison does NOT
    short-circuit on the first match (short-circuiting leaks which slot
    matched); the candidate tag is computed once and compared against all
    N verifiers every request (Principle III side-channel resistance).
  - **Pepper secrecy (new secret).** The verifier is `HMAC-SHA-256(pepper,
    token)` over a dedicated 32-byte install-time pepper shared by CP and
    DP. The pepper NEVER appears in `dp-snapshot.json`, never in any log or
    audit `detail_json`, and never crosses the inter-plane RPC (only
    verifiers do). The snapshot carries verifiers only — a snapshot-file
    leak does NOT expose the pepper (Principle III).
  - **Monotonic generation survives CP restart (M1).** A single persistent
    CP generation record (a dedicated `token_generation` row / state file)
    is the source of truth. On CP restart it reads the last-used generation
    and proposes `last + 1`; it does NOT restart at 1 (which would be stale
    the moment the DP has accepted any generation ≥ 1).
  - **Reconciliation handshake.** `ReloadTokens` carries the proposed
    generation; the DP compares against `currentGeneration`. A stale
    proposal (`<= current`) returns `APPLY_STATUS_STALE_GENERATION` AND the
    DP's current generation in the response, so the CP can re-read its
    persisted record, propose `current + 1`, and retry deterministically
    (Constitution Principle II — inter-plane contract is versioned +
    reconcilable, not fire-and-forget).
  - **DP state preserved on input failure (M1).** A missing, unreadable,
    invalid, or unparseable `tokens.yaml` makes the CP NOT call
    `ReloadTokens` at all — the DP keeps its last-known list and keeps
    serving port 8881 (Principle II "continue routing"). Only a
    successfully-parsed explicit `tokens: []` is the revoke-all path.
  - **Explicit empty list = revoke-all.** A successfully parsed empty list
    is the ONLY input that pushes an empty generation (the DP then returns
    `AUTH_REQUIRED` on all requests). This is the deliberate operator
    action; every failure mode above is distinct from it.
  - **Manual configured-tokens separated from enrollment-only fields
    (M1).** Manual YAML token records carry `(label, verifier)` only; no
    insert requires a nonexistent device public key. The `enrolled_devices`
    entity (device pubkey + token_hash, both NOT NULL today per
    `V001__init.sql:20-27`) is reserved for the future dashboard-enrollment
    feature, which is the only path that has a device public key. A
    separate `configured_tokens(label, verifier, created_at,
    last_seen_hour, revoked_at)` entity is the manual-path home.
  - **Honest memory-erasure claim (M1).** The data model claims zeroing
    only for mutable buffers the implementation can actually clear (e.g. a
    `byte[]` it filled itself). It does NOT claim SnakeYAML-materialized
    Java `String` values were erased — SnakeYAML hands back immutable
    `String` objects the loader cannot reach inside. The claim is narrowed
    to match what Java can guarantee.

- **Gated** — T093 (blocked_by T092) pins every must-hold above as an
  executable test before production implementation resumes: HMAC
  acceptance/rejection + one-hash-per-request, constant-time comparison
  work, no pepper in snapshots/logs, restart-safe generations, the
  stale-retry reconciliation handshake, the missing/unreadable/parse-failure
  → no-`ReloadTokens` semantics, explicit-empty → revoke-all, and peak-RSS
  + unauthenticated-flood bounds (extending T079a). Principle VII
  (tests-first for authentication) is discharged by T093, not by this
  amendment ticket; T092 makes the contract authoritative so T093 can pin
  it. T035/T041/T044/T046 consume the amended contract and remain pending.

- **Residue** (accepted residual risk, recorded in THREAT-MODEL.md +
  SECURITY-DECISIONS.md):
  - **The pepper is a new secret.** It must be covered by installer
    permissions (0600, owned by the CP/DP runtime UID, group
    `stargate-ipc`-readable so both planes can read it), an export/import +
    wipe policy (included in `scripts/stargate wipe` and export scope;
    export requires explicit operator action), a rotation procedure
    (re-pepper → re-HMAC every configured token → bump generation), and a
    threat-model entry: pepper compromise + snapshot leak makes offline
    candidate testing feasible at HMAC speed — mitigated by the 128-bit
    token entropy which makes batch brute-force infeasible regardless of
    verifier speed (the property Argon2id was over-engineered to defend,
    pointlessly, for a random 128-bit token).
  - **Constant-time over the verifier set** is functionally tested in T093;
    adversarial confirmation is a `stargate-redteam` residue (timing
    side-channels are not fully captured by functional tests).
  - **Generation-persistence durability.** A CP DB wipe loses the
    generation counter; mitigation: on a stale/zero persisted record the CP
    reconciles against the DP's reported current generation (proposes
    `current + 1`, or 1 if the DP has none) rather than guessing.

Grounding findings resolved into acceptance (two):

1. The proto `TokenHash { hash; salt }` carries a per-token `salt` that is
   dead under HMAC-over-a-single-pepper (verifier = `HMAC(pepper, token)`,
   no per-token salt). Dropping `salt` is a breaking pre-release contract
   change. Per the pre-release amendment doctrine (T091 / T099 precedent —
   semver-on-amendments + the 7-day comment window become BINDING at first
   public release; no consumers exist today), this is recorded as an
   amendment NOTE in SECURITY-DECISIONS.md + the contract doc, NOT a
   `stargate.v2` bump. Folded into acceptance #1 + #7.

2. Acceptance #5 (separate manual records) cannot be satisfied by editing
   `data-model.md §1` alone: the schema source-of-truth is arch §6 and the
   landed migration is `V001__init.sql`. The in-lock-step amendment of arch
   §6 + V001 is in scope for this ticket (nothing has shipped; T012's
   "schema lands once up-front" makes the pre-release window the intended
   time to amend it). Design decision: a dedicated `configured_tokens`
   table (clean separation; the rejected alternative — making
   `enrolled_devices.pubkey` nullable — muddies that entity's contract and
   is recorded as the rejected option). Folded into acceptance #5 + #7.

## Acceptance

1. Replace Argon2id for random bearer tokens with HMAC-SHA-256 using a
   dedicated 32-byte install-time pepper shared by CP and DP. Hash each
   candidate once and compare against every verifier with constant-time
   operations; keep the pepper out of `dp-snapshot.json`. The verifier is
   `HMAC-SHA-256(pepper, token)` — a single 32-byte tag per token, NO
   per-token salt. The proto `TokenHash` therefore drops its `salt` field
   (verifier-only: `bytes hash = 1`); this breaking pre-release contract
   change is recorded as an amendment NOTE (SECURITY-DECISIONS.md +
   contract doc), NOT a `stargate.v2` bump, per the T091/T099 pre-release
   doctrine.
2. Specify pepper generation, ownership, backup/export/import, rotation, and
   wipe behavior; update T088 provisioning acceptance as needed.
3. Persist a CP generation record and define reconciliation using the DP's
   current generation, including explicit retry behavior after stale status.
4. Preserve the DP's last-known generation on missing, unreadable, invalid, or
   unparseable input. Only a successfully parsed explicit empty list revokes
   all tokens.
5. Separate manual configured-token records from enrollment-only fields so no
   insert requires nonexistent device public keys. Authoritative design: a
   dedicated `configured_tokens(label, verifier, created_at,
   last_seen_hour, revoked_at)` entity is the manual-YAML path's home;
   `enrolled_devices` (device pubkey + token_hash, both NOT NULL today) is
   reserved for the future dashboard-enrollment feature that actually has a
   device public key. Amend arch §6 (schema source-of-truth) and
   `V001__init.sql` in lock-step — nothing has shipped, so the pre-release
   window is the intended time to amend the "lands-once" schema (T012).
   The rejected alternative (make `enrolled_devices.pubkey` nullable) is
   recorded in data-model.md as the rejected option.
6. Narrow Java memory-erasure claims to mutable buffers the implementation can
   actually clear; do not claim SnakeYAML-created `String` values were erased.
7. Update spec, plan, data model, proto contract, threat model, and
   `SECURITY-DECISIONS.md`; refine T020/T020a/T035a/T035/T041/T044/T046/T079a.
   Amend arch §6 + `V001__init.sql` in lock-step with acceptance #5, and
   the contract doc + `proto/stargate/v1/control.proto` in lock-step with
   acceptance #1 (drop `salt`; add the generation-reconciliation response
   field from acceptance #3).

## Out-of-scope

Human-memorable passwords and dashboard enrollment are separate features.
