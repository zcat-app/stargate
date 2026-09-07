---
id: T058a
title: 'Pin no-username circuit sharing under IsolateSOCKSAuth (tor/ suite)'
status: in-review
created: 2026-07-04
last_updated: 2026-09-07
source: tasks.md#T058a
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T009, T062]   # manual edge: task body uses the T062 control-port helper for circuit-status queries (derive-deps missed prose deps; tightened 2026-09-07)
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md#FR-016   # tor/ dir must hold a behavioural invariant, not just port exposure
   - specs/001-tor-route/spec.md#FR-012   # tor ports compose-internal only → SOCKS+control both ride the in-container exec/nc transport
   - specs/001-tor-route/contracts/torrc.md §"isolate_socks_auth_effect_test.go"   # sibling contract; §"When this contract changes" #2 (digest-bump gate)
   - specs/001-tor-route/tasks.md#T058a   # source body
decision_refs:
   - .specify/memory/constitution.md#Principle-IV   # this test IS the sidecar contract test the manual-promotion flow runs (step 2)
   - .specify/memory/constitution.md#Principle-VII  # tests-first: pin derived from spec, not from observed code
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T058a: Contract test pinning Tor's behaviour under `IsolateSOCKSAuth` when an

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test pinning Tor's behaviour under `IsolateSOCKSAuth` when an upstream SOCKS5 client provides no username — `tests/contract/tor/username_less_isolation_test.go` (negative companion to T058). Spins up the Tor sidecar with the rendered torrc; connects directly to `tor:9050` (bypassing port 8881) twice with auth method `0x00` (NO_AUTH) and no username; uses the T062 control-port helper to query `circuit-status` and capture the circuit ID each stream attached to. Asserts: (a) Tor accepts both NO_AUTH connections (Tor's `SocksPort` permits NO_AUTH by default); (b) both streams attach to the SAME circuit ID — a default/shared circuit, because `IsolateSOCKSAuth` only isolates when a username is provided, so no-username traffic shares a circuit by design. This task exists to **pin Tor's actual behaviour** so T047's outbound-SOCKS5 contract (data plane always forwards with the inbound first-party username) is verified to be defensive against the real failure mode: silent circuit sharing if the data plane ever forwarded a username-less request. If a future Tor release changes this behaviour (e.g., rejects NO_AUTH outright under `IsolateSOCKSAuth`), this test fails during the digest-bump PR (Principle IV manual-promotion gate) and the data plane's outbound contract is renegotiated with a `SECURITY-DECISIONS.md` entry. Lives under `tests/contract/tor/` (not `torrc/`) so FR-016's `tor/` directory holds at least one behavioural-invariant test, not just the port-exposure assertion.

## Analysis

Property map (required: `privacy_critical: true`), grounded 2026-09-07 at
`001-tor-route` 780aaae. Ground-truth facts the design rides on:

- The sidecar's torrc is **image-baked** (`sidecars/tor/Dockerfile` COPYs
  `sidecars/tor/torrc`, itself the golden of `contracts/torrc.md`); the first
  line is `SocksPort 0.0.0.0:9050 IsolateClientAddr IsolateSOCKSAuth`. "The
  rendered torrc" therefore needs no harness rendering — `compose up tor` is
  the rendered config, the same posture as T062's live suite.
- FR-012 invariant #1 (pinned at runtime by `port_exposure_test.go`'s
  `HostCannotReachTorPorts`): the host cannot dial tor:9050/9051. So BOTH
  protocol transports ride `docker compose exec -T tor nc 127.0.0.1 <port>`
  with the Go side owning the wire bytes — control on 9051 via the landed
  T062 helper (`Connect`/`Authenticate`/`Command`), SOCKS on 9050 via a
  same-shaped exec session implemented in the test file (reuses the helper's
  unexported `composeArgs`; T062's reviewed file is not modified).
- "The circuit ID each stream attached to" is read from
  `GETINFO stream-status` (per-stream line `<StreamID> <Status> <CircID>
  <Target>`) — `GETINFO circuit-status` is circuit-level and does not name
  streams. `circuit-status` is still queried as the cross-surface check that
  the shared CircID exists there as BUILT (tor's two surfaces must agree).
- SOCKS CONNECT destination: the spec-pinned reference onion
  `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80`
  (T033's `t033Onion`; live `tests/integration/onion_load_test.go`). A fake
  `.example.onion` would never attach a stream (descriptor fetch fails before
  rendezvous), so the pin needs a real, resolvable onion. Its v3 address is
  an external anchor, not author-chosen bytes (calibration doctrine,
  780aaae).
- streams are matched by target string (`<onion>:80`), never by StreamID
  ordering — fresh container has no other traffic to that target, and the
  count is asserted to be exactly two, so no reliance on StreamID monotonicity.

- **Must hold:**
  - Two independent SOCKS5 connections to `tor:9050` (auth method `0x00`,
    RFC 1928 §3) are accepted under the rendered config: greeting reply is
    exactly `05 00` on both; CONNECT reply `REP=0` on both. (Ticket
    assertion (a); if a future tor rejects NO_AUTH outright, this fails in
    the digest-bump PR — Principle IV flow, renegotiation via
    `SECURITY-DECISIONS.md`.)
  - Both no-username streams attach to the SAME circuit ID
    (`IsolateSOCKSAuth` isolates only credential-bearing streams — ticket
    assertion (b); silent isolation here is the behaviour-change pin).
  - The shared CircID is non-zero, appears in `circuit-status` as BUILT
    (cross-surface agreement), and exactly two `stream-status` lines match
    the target (no phantom/paired streams).
  - Positive control (calibration doctrine 780aaae): two connections with
    distinct SOCKS5 usernames (method `0x02`) attach to DISTINCT circuits —
    proves the harness can detect isolation at all, so a green "same circuit"
    result is evidence, not artifact. This is the `torrc.md` contract's
    `isolate_socks_auth_effect_test.go` behaviour (T058's spec surface),
    anchored here as control only.
  - Principle VII: the pin is derived from spec + torrc contract, authored
    before any data-plane consumer relies on it; hermetic gate stays green
    (compile-only), the named Docker job executes it.
- **Gated:**
  - `verify.sh` go-workspace gate compile-checks the file via
    `go vet -tags docker`; hermetic PR run accounts it SKIP[docker] (T076).
  - The named Docker job (`STARGATE_TEST_TAGS=docker scripts/verify.sh`)
    executes the suite against the production tor image.
  - Control-port reply parsing rides T062's helper — parser discipline
    already gated by T062's hermetic suite.
  - License-header + shell gates unaffected (no shell changes).
- **Residue:**
  - Live-network latency (bootstrap, descriptor fetch, rendezvous) is
    deadline-bounded (T033's 90 s retry window precedent), but a slow day
    can flake the named Docker job — accepted residue, same as T032/T062.
  - "Same circuit" alone cannot distinguish credential-less sharing from "tor
    had only one circuit to offer" — mitigated (not eliminated) by the
    distinct-usernames control proving ≥2 circuits exist and diverge on
    credentials. Full discrimination lives in T058's contract test (`torrc/`).
  - Behaviour itself is empirical: if tor changes the pin, the test fails
    correctly but the renegotiation is a human step (SECURITY-DECISIONS.md),
    not a gate.

## Acceptance

1. `tests/contract/tor/username_less_isolation_test.go` exists,
   `//go:build docker`, package `tor`, test `TestUsernameLessIsolation` with
   subtests (each subtest owns its sessions outright — Go subtest cleanups
   run at SUBTEST end, so sessions are never handed across subtests;
   amended at implement time after the first live run, see §Notes):
   - `NoAuthAcceptedBothConnections` — two independent exec/nc SOCKS5
     sessions; each greeting `\x05\x01\x00` answered by exactly
     `\x05\x00` (ticket assertion (a)).
   - `NoAuthStreamsShareCircuit` — pairs two fresh sessions via
     `ulPairConnect` (dial+greet+CONNECT with bounded per-attempt retry:
     an onion CONNECT right after PROGRESS=100 fails transiently while tor
     fetches descriptors — T033's retry-window precedent, observed live as
     REP=1 within seconds of bootstrap); with both CONNECTed,
     `GETINFO stream-status` (via T062 helper) shows exactly two lines for
     `<reference-onion>:80`; their CircIDs are equal, non-zero, and present
     in `GETINFO circuit-status` as BUILT (ticket assertion (b)).
   - `CalibrationDistinctUsernamesDiverge` — control: two connections with
     method `0x02` and distinct usernames attach to distinct CircIDs
     (same reading machinery; per `contracts/torrc.md`
     §"isolate_socks_auth_effect_test.go"). Preceded by a drain wait until
     the previous subtest's streams detach, so the exactly-two count sees
     only its own streams.
2. Suite brings up its own compose project (`stargate-t058a-test`) with
   pre-registered `down --volumes --remove-orphans` cleanup (T019b/T062
   conventions), distinct from sibling suites' projects.
3. Runnable commands (both must pass before APPROVE):
   - Hermetic PR gate: `bash scripts/verify.sh` GREEN (suite compile-checked,
     SKIP[docker]).
   - Live: `STARGATE_TEST_TAGS=docker scripts/verify.sh`, or manually
     `cd tests/contract && go test -tags docker ./tor/ -run
     TestUsernameLessIsolation -v -timeout 20m`.
4. No changes outside the new test file + this ticket (files_budget: 2 of 8).

## Out-of-scope

- T058's `tests/contract/torrc/isolate_socks_auth_effect_test.go` (the
  distinct-username contract gate) — separate ticket, separate directory
  (FR-016 keeps them distinct); this ticket's calibration subtest is a
  control, not that gate.
- Any change to `tests/contract/tor/control_port.go` or T062's tests — the
  helper is consumed as landed (unexported `composeArgs` reused read-only).
- Data-plane changes (T047/T072 outbound contract), torrc/image changes
  (T086/T087 surface), CI wiring (T076), verify.sh changes (T120 owns
  parallel-run log safety).
- HTTP-level verification of the onion (only SOCKS CONNECT success + circuit
  attach are pinned; content fetch is T033's surface).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

Implement-time amendments (2026-09-07, live-run findings, worktree
`t058a`):

1. First live run failed with "service tor is not running": the suite had
   reused T062's `cpCompose` helper (which bakes T062's project const) for
   up/down while its exec transports used `stargate-t058a-test` — the run
   brought tor up under the WRONG project and polled an empty one. Fixed by
   the per-suite `ulCompose` runner (the T032/T062 re-implementation
   precedent each suite already follows). The mis-up was cleaned down by the
   suite's own cleanup; the parallel T058 session's containers were never
   touched (distinct project names did their job).
2. Sessions cannot be handed across subtests: Go runs a subtest's cleanups
   when the SUBTEST ends, so subtest-1-owned sessions arrived closed at
   subtest 2 ("file already closed" on the CONNECT write). Restructured:
   each subtest owns its sessions outright; subtest 1 closes its
   greeting-only sessions before subtest 2 counts streams.
3. `ulPairConnect` adds the bounded dial+greet+CONNECT retry: the first
   calibration CONNECT got REP=1 within seconds of PROGRESS=100 (descriptor
   fetch + circuit-builder warmup), the exact transience T033's
   90 s retry window exists for. A true pin regression fails every attempt
   and the deadline Fatal carries the last error verbatim.
4. Root cause of the persistent REP=1 storms (runs 3–4, named by the tor
   log tail this file attaches to failures): `connect()` passed the
   stream-status match target `"onion:80"` whole as the SOCKS5 ATYP=domain
   DST.ADDR — the wire field is the bare hostname; the port belongs only in
   the trailing DST.PORT bytes. tor read a 59-char onion and logged
   "malformed hostname" on every attempt. The independent Python reference
   client (bare onion) succeeded in 1 s against the same container, which
   isolated the wire difference. Fixed: `connect(ulOnion)`.
5. Calibration-subtest failure decoded from the same forensics:
   "Socks version 120 not recognized" = 0x78 = the PASSWD byte parsed as a
   NEW handshake — `greetingUserPass` appended `01 01 'x'` (a stray extra
   0x01), so tor consumed PLEN=1, PASSWD=0x01 and left `'x'` in the stream.
   Fixed to RFC 1929 §2 shape (`01 'x'`). After both fixes the full suite
   PASSES live (67 s warm): greeting accepted both, NO_AUTH streams shared
   circuit 14 (BUILT cross-check), distinct usernames diverged (18 vs 17).
6. `ulConnectWait` (3 m) provenance corrected: the widened window was
   justified by a misdiagnosis (runs 3–4 failures were #4, not warmup).
   Kept as cold-boot insurance with the honest note in the const comment;
   costs nothing on the happy path.
