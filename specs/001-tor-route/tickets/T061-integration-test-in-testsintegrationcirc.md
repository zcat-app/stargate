---
id: T061
title: 'Integration test in `tests/integration/circuit_isolation_corpus_test.g'
status: done
created: 2026-07-04
last_updated: 2026-09-07
source: tasks.md#T061
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T062, T063]   # manual edges: circuit IDs via the T062 control-port helper; CONNECT targets come from the T063 synthetic corpus (derive-deps missed prose deps; tightened 2026-09-07)
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: false
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - 'spec.md §SC-002 (the 100-CONNECT ≥95-distinct-circuit-IDs measurement this ticket implements)'
  - 'spec.md §"User Story 2" acceptance scenario 2 (the 10-CONNECT ≥9 shape T061 scales to corpus size)'
  - 'spec.md §Assumptions — reference-target bullet (corpus reachability assumption — FALSIFIED 2026-09-07, see §Notes grounding finding)'
  - 'spec.md FR-012 (ControlPort compose-internal; the T062 helper transport)'
  - 'spec.md FR-016 (T062 helper consumed by tests under integration/)'
  - 'contracts/torrc.md (invariants #1/#3/#11; T058 SOCKS_USERNAME correlation conventions)'
  - 'tasks.md#T061'
decision_refs:
  - 'tests/contract/tor/control_port.go (T062, done — cookie + session + Command consumed directly)'
  - 'tests/contract/torrc/isolate_socks_auth_effect_test.go (T058, done — in-container SOCKS dial, compose bring-up shape, SOCKS_USERNAME-tag circuit correlation)'
  - 'tests/integration/synthetic_onion_corpus.txt + tickets/T063 §Acceptance A5 (corpus load-time validity, fail with offending line)'
  - 'tests/integration/onion_load_test.go (T033 — repo-root discovery, compose bring-up + pre-registered cleanup, signal-safe teardown)'
  - 'research.md §7 (SC-002 corpus run goes against the real Tor sidecar, within its normal load envelope)'
  - 'Constitution Principle III (per-first-party stream isolation — the privacy property SC-002 measures)'
reviews: { round: 1, date: 2026-09-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T061: Integration test in `tests/integration/circuit_isolation_corpus_test.g

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Integration test in `tests/integration/circuit_isolation_corpus_test.go` — SC-002 measurement: 100 sequential CONNECTs to 100 distinct first-party `.onion` strings from a synthetic corpus, assert ≥95 distinct circuit IDs. (Spec SC-002.)

## Analysis

*(Quick pass — `privacy_critical: false`, `complexity: low`. The privacy
property measured here is Constitution Principle III's per-first-party
isolation; this ticket changes no trust-boundary code, so the map below
scopes the harness only.)*

- **Must hold:**
  - Before any CONNECT, the committed corpus
    (`tests/integration/synthetic_onion_corpus.txt`) validates clean per
    T063 §Acceptance A5 (100 lines, LF-only single trailing newline,
    pairwise distinct, `^[a-z2-7]{56}\.onion$`, key‖checksum‖version with
    version `0x03` and `checksum == SHA3-256(".onion checksum" ‖ key ‖
    0x03)[:2]`, reference target absent); any violation FAILs with the
    offending line number. The corpus strings are used as the SOCKS5
    username (isolation key, per amended SC-002 / FR-007) — tor never
    parses them as addresses, so their Ed25519-invalid keys are harmless.
  - 100 sequential in-container SOCKS5 CONNECTs (UNAME = corpus line,
    PASSWD = fixed non-secret constant, target = the spec-pinned
    reference onion `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443`)
    each produce a `SOCKS_USERNAME="<corpus line>"`-tagged entry in
    `GETINFO circuit-status` (T058's correlation key), and the count of
    distinct circuit IDs across the 100 streams is ≥95 (amended SC-002).
  - Both transports stay compose-internal (FR-012): SOCKS via in-container
    `nc 127.0.0.1 9050`, control via the T062 helper's exec/nc transport;
    own compose project `stargate-t061-test`; pre-registered
    `down --volumes --remove-orphans` cleanup + signal-safe teardown
    (T033/T058 posture — an orphaned sidecar keeps circuits, exposing
    the operator's guards).
  - Harness plumbing never logs target list, cookie bytes, or auth
    material (T062 §Analysis M5 conventions; errors carry sizes/statuses).
- **Gated:** static torrc shape (T029/T030/T031), loaded-config GETCONF
  (T032), helper parser suite + live self-test (T062), hermetic compile
  check of this file via `go vet -tags docker` with SKIP[docker]
  accounting in the hermetic PR run (T076 cadence split), license-header
  gate.
- **Residue:** live-network dependence (bootstrap + the reference
  onion's reachability) fails at the named deadlines — environmental,
  not a code regression; absorbed by the `docker` build-tag cadence so
  it is never a hermetic-PR flake surface. Per-CONNECT circuit capture
  polls `circuit-status` with a per-CONNECT deadline (~5 s observed in
  probes; 30 s budgeted). Destination-based isolation is NOT asserted —
  the shipped torrc has no destination-isolation directive (see
  SECURITY-DECISIONS.md 2026-09-07); through-the-data-plane pass-through
  remains T059/T060's scope.

## Acceptance

1. `tests/integration/circuit_isolation_corpus_test.go` exists, is
   `//go:build docker` tagged (live cadence, T076), `package integration`,
   defines `TestCircuitIsolationCorpus` with skip guards mirroring
   T033/T058 (docker CLI absent / daemon unreachable), its own compose
   project `stargate-t061-test` against
   `compose/docker-compose.local.yml` + `compose/env/local.env.example`,
   pre-registered `down --volumes --remove-orphans` cleanup, and
   `up -d --build tor` (cold volume, image-baked torrc).
2. Named test, behavioral assertions (subtests):
   - `CorpusIsValid`: loads `synthetic_onion_corpus.txt`, asserts every
     T063 A5 property, FAILs naming the offending line number before any
     CONNECT is issued.
   - `SidecarBootstraps`: cookie read via `tor.ReadCookie` from the
     invariant-#11 path, `tor.Connect` + `Authenticate` succeed, and
     `GETINFO status/bootstrap-phase` reaches `PROGRESS=100` within the
     deadline.
   - `CorpusIdentitiesGetDistinctCircuits`: for each corpus line i (in
     order, sequential): open an in-container SOCKS5 session
     (method 0x02, UNAME = corpus line, PASSWD = fixed constant), write
     the CONNECT for the reference onion:443, poll `GETINFO
     circuit-status` until an entry carries
     `SOCKS_USERNAME="<corpus line>"` (per-CONNECT deadline; record its
     circuit ID), then close that session. After all 100: the set of
     recorded circuit IDs has **≥95 distinct members** (amended SC-002),
     with the test output naming any identities that failed to produce a
     tagged circuit. A count below 95 FAILs — that is the SC-002
     measurement.
3. Module wiring: `tests/integration/go.mod` gains
   `require github.com/zcat-app/stargate/tests/contract` + a filesystem
   `replace` to `../contract` so the T062 helper (FR-016's
   integration-side consumer edge) resolves; `go.sum` consistent.
4. Runnable command (live cadence):
   `cd tests/integration && go test -tags docker -run TestCircuitIsolationCorpus -v -timeout 45m`
   — or the same entrypoint verify.sh uses:
   `STARGATE_TEST_TAGS=docker scripts/verify.sh`. Hermetic PR run:
   compile-checked, accounted SKIP[docker].

## Out-of-scope

- Through-the-data-plane (port 8881) variants — T059 (scenario 1) and
  T060 (scenario 3) own the DP pass-through proofs; this ticket measures
  sidecar-scale isolation per amended SC-002.
- Destination-isolation assertions — not an isolation input in the
  shipped torrc; introducing one would be a spec change, not a test
  detail.
- Regenerating the corpus with valid Ed25519 keypairs — the corpus's
  keys are harmless in their two roles (isolation-key strings here,
  forbidden substrings in T064); noted as optional remediation in
  SECURITY-DECISIONS.md 2026-09-07, none filed.
- T064's leak-corpus embedding and any change to
  `synthetic_onion_corpus.txt` — the file is consumed verbatim.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**Refinement (2026-09-07, post-T063).** The corpus this test consumes is
`tests/integration/synthetic_onion_corpus.txt` (T063, done). On load,
assert corpus validity per T063 §Acceptance A5 — exactly 100 lines, LF-only
with a single trailing newline, pairwise distinct, every line
`^[a-z2-7]{56}\.onion$` decoding as key(32)‖checksum(2)‖version(1) with
version byte `0x03` and `checksum == SHA3-256(".onion checksum" ‖ key ‖
0x03)[:2]`, reference target absent — and FAIL with the offending line
number on any violation, before any CONNECT is issued. Rationale: no
`verify.sh` gate inspects a `.txt` corpus, so a post-hoc hand edit would
otherwise pass every gate green and surface only as a confusing
circuit-isolation measurement failure. (T063 round-1/2 verdict follow-up;
recorded here because `target/runs/*.verdict` is gitignored.)

**Grounding finding (2026-09-07, pre-implementation probes 1–4).** The task
body's mechanism — CONNECT to the corpus strings, count the sidecar's
distinct circuit IDs — is falsified on the pinned production sidecar
(T058's harness: `compose up tor`, T062 helper, in-container SOCKS5 dial).
§Acceptance is deliberately unfilled pending the escalation menu; the
findings:

1. **Corpus lines are parse-rejected.** `SOCKS5 CONNECT <corpus line>:443`
   (distinct corpus-line UNAMEs and short UNAMEs alike) → immediate
   `REP=0x01`, no stream, no circuit; the tor log shows
   `ed25519 group order scalarmult failed` /
   `Service address [scrubbed] has bad pubkey` /
   `Invalid onion hostname [scrubbed]; rejecting`. T063's A5 validates
   checksums but NOT Ed25519 key validity: the corpus's 100 random 32-byte
   keys are not valid Ed25519 public points, and this tor build rejects
   the address at parse before any circuit work.
2. **The reachability premise fails independent of the corpus.** A probe
   address built from a FRESH valid Ed25519 keypair (checksum-valid,
   unpublished — no descriptor exists) is accepted at parse, but its
   stream lingers at `SENTCONNECT 0` with NO per-connection circuit for
   the whole 60 s observation window; `GETINFO circuit-status` shows zero
   `SOCKS_USERNAME`-tagged circuits. Tor attaches an HS client stream to
   a circuit only after the descriptor arrives, which never happens for
   unpublished keys. So spec §Assumptions' "reachability is not required
   … only that the Tor sidecar attempts distinct circuits" is false on
   the pinned image: the sidecar does not attempt.
3. **Positive control passes.** The spec-pinned reference onion over the
   same dial path → stream SUCCEEDED, circuit tagged
   `SOCKS_USERNAME="…"` — the T058 correlation mechanism works; the
   negative results above are target-driven.

Consequence: "≥95 distinct circuit IDs across 100 CONNECTs to the corpus
targets" is unmeasurable as written. Escalated to the user (amend-spec is
the matching menu option) with the recommended replacement mechanism: keep
the corpus as the per-CONNECT SOCKS5 UNAME — the isolation key, exactly
what production sends as the first-party domain, which tor never parses as
an address (Ed25519-invalid keys harmless) — CONNECT to the spec-pinned
reachable reference onion, assert ≥95 distinct `SOCKS_USERNAME`-tagged
circuit IDs. (Flag note: `privacy_critical: false` stands because this
ticket changes no trust-boundary code — it MEASURES the Constitution
Principle III property the spec pins; the behavioral pins themselves are
T058/T058a/T059.) Probe sources: `/tmp/t061probe` (ephemeral); the
findings above are self-contained.

**Resolution (2026-09-07, user-approved amend-spec).** The escalation
above was resolved via the amend option: SC-002 and the §Assumptions
bullet now specify the corpus strings as the per-CONNECT SOCKS5 username
(isolation key) with CONNECTs targeting the pinned reachable reference
onion; property, corpus, scale, and threshold unchanged. Rationale and
no-weakening analysis: SECURITY-DECISIONS.md 2026-09-07 ("SC-002 corpus
measurement mechanism corrected"). §Analysis/§Acceptance/§Out-of-scope
below are filled per the amended mechanism.
