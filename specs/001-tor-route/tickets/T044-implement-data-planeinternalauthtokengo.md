---
id: T044
title: 'Implement `data-plane/internal/auth/token.go`'
status: done
created: 2026-07-04
last_updated: 2026-09-03
source: tasks.md#T044
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009, T092, T093]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - "specs/001-tor-route/data-model.md §1.5 (verifier = HMAC-SHA-256(pepper, token); ConstantTimeCompare against EVERY verifier, no short-circuit; O(1) per request; shared constants PepperLen/VerifierAlgo)"
  - "specs/001-tor-route/data-model.md §1.2 (verifier is the 32-byte tag; no per-token salt)"
  - "specs/001-tor-route/data-model.md §1.3 (tokenStore = single *Generation under an atomic pointer; swap semantics)"
  - "specs/001-tor-route/data-model.md §1.6 (token format violations never log the offending bytes)"
  - "specs/001-tor-route/data-model.md §1.7 (pepper at <keysDir>/pepper.key, exactly 32 bytes, shared by both planes)"
  - "specs/001-tor-route/data-model.md §1.1 (token format rule ^[0-9a-f]{32}$, FR-017)"
  - "specs/001-tor-route/contracts/socks5-auth.md §\"Username/password sub-negotiation (RFC 1929)\" (PASSWD is the candidate; failure reply byte-identical across the AUTH_REQUIRED family)"
  - "specs/001-tor-route/spec.md FR-006 (authenticate every inbound request; failures indistinguishable)"
  - "THREAT-MODEL.md §5.14 (snapshot leak does not expose the pepper; HMAC-speed residue accepted)"
decision_refs: []
reviews: { round: 2, date: 2026-09-03, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T044: Implement `data-plane/internal/auth/token.go`

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Implement `data-plane/internal/auth/token.go` — argon2id-hash candidate token using shared `Argon2idParams` (T011) and the per-token salt from the current generation; compare with `crypto/subtle.ConstantTimeCompare`; never log the offered token or hash. Verified by T024, T025, T027, T028.

## Analysis

Property map (grounding-verified 2026-09-03; required — `privacy_critical:
true` per `docs/process/analysis.md`).

**Grounding findings resolved into this design (body-vs-reality items):**

1. **The `^[0-9a-f]{32}$` format gate lives inside `VerifyPassword`, for
   BOTH framings.** T093's shipped algorithm-contract tests
   (`data-plane/internal/auth/hmac_verifier_test.go` — the designated
   test-first gate for this ticket) pin "malformed input rejected BEFORE
   any HMAC work — no hash allocated for garbage" as a must-hold, and
   `TestMalformedRejectedBeforeHash` models the auth path's ordering as
   gate-then-hash. T042's §Analysis finding 3 and the `socks5.go`
   `Verifier` docstring read the gate as CONNECT-path-only with "every
   PASSWD funnels through hash+compare" — that describes the LISTENER's
   surface (socks5.go still performs no format gate, no hashing, no
   comparison — Principle I framing-only holds) and predates T093's
   contract. Wire-observable behavior is unchanged either way: the SOCKS5
   failure reply is byte-identical `01 FF` across the whole AUTH_REQUIRED
   family (research.md §9), and the ~µs HMAC skip for malformed input
   leaks only syntax validity, which is public. T092 + T093 are the
   later, superseding authority for the auth seam, and the internal gate
   is what gives the SOCKS5 raw-PASSWD path (1–255 opaque bytes) the same
   zero-hash-work-for-garbage resource bound (sol-review B5 family).
   Orphan created by this decision: `socks5.go`'s "malformed candidates
   funnel through hash+compare" parenthetical — corrected by this ticket
   (comment-only edit; T042's code is untouched).
2. **token.go owns the `TokenStore`/`Generation` container**
   (data-model.md §1.3: a single `*Generation` under an atomic pointer),
   because the candidate verifier reads "the current generation" on every
   request, and the consumers that install generations — T045's
   `ReloadTokens` handler, T046's snapshot restore, T050's boot — do not
   exist yet and must not be imported. The store starts at an empty
   generation (the revoke-all state), never nil, so `VerifyPassword`
   needs no defensive nil check inside the trust boundary (CONTRIBUTING
   doctrine). §1.2's per-verifier `generation` field is realized at the
   Generation level (§1.3): the set swaps as a unit; a per-element copy
   would be dead data, and neither the wire shape (`grpcpb.TokenVerifier`
   = verifier bytes only) nor the snapshot shape (§1.4) carries it.
3. **Seam conformance without import.** `listener.Verifier`
   (`VerifyPassword(candidate []byte) bool`, T042) is satisfied
   structurally by `auth.TokenVerifier`; the auth package imports stdlib
   only — no listener, no grpcpb (verifiers cross the RPC as
   `grpcpb.TokenVerifier` and T045 converts at the edge). A mirror
   interface assertion in `token_test.go` pins the method set against
   drift. T050 wires `NewTokenVerifier` into `Deps.Auth` /
   `ConnectDeps.Auth`.
4. **Pepper loading is boot-time; shape failures are loud, mismatch is
   not.** `LoadPepper(keysDir)` reads `keysDir/pepper.key` (§1.7;
   `PepperFile = "pepper.key"` is the harness contract surface from
   `dpharness/auth.go`; `DefaultKeysDir = "/etc/stargate/keys"`) and
   requires exactly `PepperLen` bytes — a wrong-length file is a corrupt
   install and errors at boot (HMAC would otherwise run forever
   authenticating nothing, silently). A same-length DIFFERENT pepper is
   the §1.5 "all auth fails" misconfiguration surface: it boots and
   authenticates nothing by design (T093's pepper-mismatch test pins the
   algorithm side). The loader returns a `[PepperLen]byte` value (wrong
   length is a compile error at the constructor — no runtime defensive
   check anywhere) and zeroes the file buffer it allocated (Principle III
   hygiene; the deliberately-narrow erasure claim per §1.1). Env
   resolution (`STARGATE_KEYS_DIR` vs the default) is T050's, not this
   file's.

- **Must hold:**
  - One `HMAC-SHA-256(pepper, candidate)` per request, computed once and
    compared against EVERY verifier in the current generation;
    per-request work and allocation are O(1) in N (data-model.md §1.5;
    sol-review B5; Principle III — no per-request memory-DoS vector).
  - No short-circuit on first match: the comparison loop visits every
    verifier every request; timing is independent of which slot (if any)
    matched (§1.5; Principle III side-channel resistance).
  - The pepper is read from `<keysDir>/pepper.key` (§1.5/§1.7); a pepper
    mismatch authenticates nothing (the "all auth fails" surface, §1.5).
  - Token format `^[0-9a-f]{32}$` enforced BEFORE any HMAC work — zero
    hash work (and zero allocations) for malformed input, both framings
    (§1.1 validation rule; T093 must-hold).
  - The offered candidate, the pepper, and the verifiers are never
    logged, never appear in an error string, and are never persisted
    (Principle III; §1.6; token.go has no log or error-emission path at
    all).
  - `auth.PepperLen` (32) and `auth.VerifierAlgo` ("HMAC-SHA-256")
    replace the retired Argon2id constants as the shared design point
    both planes agree on (§1.5; T092; the CP-side mirror lands with
    T035's TokenLoader path).
  - Generation swap is atomic (single pointer store/load); in-flight
    requests complete against the generation they loaded; an empty or
    swapped-away generation authenticates nothing (§1.3; FR-018
    revoke-all).
- **Gated:**
  - T093's `hmac_verifier_test.go` pins the algorithm contract
    (`TestOneHmacPerCandidate`, `TestConstantTimeAcrossSet`,
    `TestMalformedRejectedBeforeHash`, `TestNoSecretInOutput`,
    `TestVerifierIs32Bytes`, `TestPepperMismatchAuthenticatesNothing`);
    `cd data-plane && go test ./internal/auth/` runs them.
  - This ticket's API-level tests (`token_test.go`) pin the concrete
    implementation to those properties: slot-invariance at first/last
    slot of N=8, allocation-count N-independence (O(1)) and zero
    allocations on the malformed path (both gate halves: wrong length,
    wrong charset), store swap semantics, pepper loader shape errors, and
    swap-under-verify race-cleanliness (`go test -race ./internal/auth/`
    standalone — see acceptance 3 for the gate-gap routing to T114).
  - `scripts/go-workspace-gate.py` (compile + vet) and the license-header
    check gate the mechanical surface; end-to-end wiring is gated by the
    T024/T025/T027/T028 contract tests, which self-lift when T045/T050
    land (their content gate on `controlclient/server.go` +
    `cmd/stargate-proxy/main.go`).
- **Residue:**
  - "Timing is independent of which slot matched" is only functionally
    assertable at unit level (visits-every-verifier); a true timing
    side-channel survives functional tests. Accepted by T093's residue
    note for `stargate-redteam` adversarial review; the
    `tests/contract/socks5/` slot-invariance + best-effort statistical
    timing rows (T025) are the runtime backstop once wiring lands.
  - "Response bytes stay byte-identical across the AUTH_REQUIRED family"
    is a listener property, gated by the T025/T028 contract tests — not
    re-asserted here; the internal format gate does not change it
    (finding 1).
  - "No logging from token.go" holds by construction (the file imports no
    logging facility and returns no error strings carrying secret
    material); no static gate enforces the absence of future log calls —
    covered by review plus the T025a journal allowlist once wired.

## Acceptance

1. `auth.TokenVerifier.VerifyPassword` satisfies the `listener.Verifier`
   seam: accepts a candidate whose HMAC matches a verifier in the current
   generation — match at the FIRST and at the LAST slot of an N=8 set
   (no short-circuit) — and rejects well-formed-but-wrong, empty, short,
   long, non-hex, and nil candidates, everything under an empty
   generation (revoke-all), and everything under a pepper mismatch.
   — `TestVerifyPassword*` in `data-plane/internal/auth/token_test.go`;
   runnable: `cd data-plane && go test ./internal/auth/`.
2. Per-request hash work is exactly one HMAC regardless of N and
   allocations are O(1): `testing.AllocsPerRun` counts are equal for N=1
   and N=64, and the malformed-candidate path allocates 0 (format gate
   precedes any hash work — the API-level pin of T093's must-hold).
   — `TestVerifyPasswordAllocsO1` in `token_test.go`.
3. `auth.TokenStore` swaps generations atomically; the zero store is the
   empty (revoke-all) state; swap-under-concurrent-verify is race-clean.
   — `TestTokenStore*`, `TestSwapUnderVerifyRace` in `token_test.go`;
   runnable: `cd data-plane && go test -race ./internal/auth/ -count=1`
   (the standalone channel — the green gate's go test does NOT carry
   `-race`; wiring the flag into `scripts/go-workspace-gate.py` is gate
   infrastructure routed to T114, not this ticket's diff).
4. `auth.LoadPepper` reads exactly `PepperLen` bytes from
   `<keysDir>/pepper.key`; missing / short / long files error with
   messages carrying path and length only, never file bytes.
   — `TestLoadPepper*` in `token_test.go`.
5. Shared constants rewritten per the T092 amendment: `auth.PepperLen` =
   32, `auth.VerifierAlgo` = "HMAC-SHA-256"; no `Argon2id` symbol and no
   `x/crypto/argon2` reference remains in the data-plane module.
   — `TestSharedVerifierConstantsMatchSpec` in `params_test.go`;
   runnable: `grep -rn 'Argon2id\|x/crypto/argon2' data-plane/
   --include='*.go'` is empty.
6. `go build ./... && go vet ./...` clean for the data-plane module; the
   full tree stays green: `scripts/verify.sh`.
7. Orphan fix (comment-only): `socks5.go`'s `Verifier` docstring no
   longer claims malformed candidates "funnel through hash+compare" —
   the auth seam now states the gate-before-hash contract (T093); T042's
   framing code is untouched.

## Out-of-scope

- gRPC `ReloadTokens` handling, stale-generation rejection, and the
  dp.sock server — T045 (`controlclient/server.go`), which consumes
  `TokenStore.Swap`/`Current`.
- `dp-snapshot.json` write/restore (schemaVersion 2, verifiers-only) —
  T046 (`controlclient/snapshot.go`).
- `STARGATE_KEYS_DIR` env resolution and boot ordering — T050
  (`cmd/stargate-proxy/main.go`).
- The control-plane side (TokenLoader, pepper read, verifier minting,
  the CP-side constants mirror) — T035.
- End-to-end contract tests (T024/T025/T027/T028) — already authored;
  they self-lift when T045/T050 land.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**T092 amendment (2026-07-15) — consume the amended contract.**
`auth/token.go` must: (a) compute the candidate's verifier ONCE per request
as `HMAC-SHA-256(pepper, candidate)` reading the pepper from
`/etc/stargate/keys/pepper.key` (`data-model.md` §1.5), NOT Argon2id; (b)
compare with `crypto/subtle.ConstantTimeCompare` against EVERY verifier in
the current generation with NO short-circuit on first match (timing must
be independent of which slot matched); (c) keep per-request allocation
O(1) — this is the sol-review B5 fix; the falsifier is T079a's peak-RSS +
unauthenticated-flood bounds, not a pool-fill timing test. The retired
N ≤ 4 cap and the `argon2` import are gone. **This ticket also owns the
shared constants rewrite** that T011 (done) shipped against the now-retired
contract: replace `data-plane/internal/auth/params.go`'s `Argon2idParams`
with `auth.PepperLen` (`32`) and `auth.VerifierAlgo` (`HMAC-SHA-256`),
drop the `golang.org/x/crypto/argon2` import, and update the file's
header comment to reference `data-model.md` §1.5 (the Go-side mirror of
the CP-side constants lands in T035's `TokenLoader` path). T093
(blocked_by T092) gates this ticket test-first.
