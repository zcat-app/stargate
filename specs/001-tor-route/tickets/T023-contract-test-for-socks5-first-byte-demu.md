---
id: T023
title: 'Contract test for SOCKS5 first-byte demultiplex (`0x05` → SOCKS5, `''C'''
status: done
created: 2026-07-04
last_updated: 2026-07-06
source: tasks.md#T023
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by: [T009]   # derived by scripts/derive-deps.sh   # TODO: derive from phase ordering + prose deps
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/contracts/socks5-auth.md §"Two inbound protocols, one port"
  - specs/001-tor-route/contracts/socks5-auth.md §"Auth method negotiation"
decision_refs:
  - research.md §5 (Contract-test harness language — Go)
reviews: { round: 1, date: 2026-07-06, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T023: Contract test for SOCKS5 first-byte demultiplex (`0x05` → SOCKS5, `'C'

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> Contract test for SOCKS5 first-byte demultiplex (`0x05` → SOCKS5, `'C'` → CONNECT, anything else → silent close) and method negotiation: (a) `0x05 0x02` for `[0x02]`-only (input `0x05 0x01 0x02`); (b) `0x05 0x02` for `[0x00, 0x02]` mixed (input `0x05 0x02 0x00 0x02` — USERNAME/PASSWORD MUST win even when NO_AUTH is also offered); (c) `0x05 0xFF` for `[0x00]`-only (input `0x05 0x01 0x00`). In `tests/contract/socks5/demux_test.go` — per `contracts/socks5-auth.md` §"Two inbound protocols, one port" and §"Auth method negotiation".

## Analysis

T023 is tests-first (Constitution Principle VII) for T042
(`data-plane/internal/listener/socks5.go`) and T050 (DP main wiring
the listener). The test self-skips until those land; the byte-exact
contract below is what their implementation gets driven to satisfy.

- **Must hold:**
  - First-byte demux table (`0x05` → SOCKS5; `'C'` (`0x43`) → HTTP
    CONNECT; anything else → silent close, no body) —
    `contracts/socks5-auth.md` §"Two inbound protocols, one port".
  - On the SOCKS5 path, `0x02` (USERNAME/PASSWORD) is selected whenever
    present in the methods list — even when `0x00` (NO_AUTH) is also
    offered. The realistic stock-client shape is "both offered"; a
    regression that picks NO_AUTH would let same-host unprivileged
    processes use the proxy without the bearer token (THREAT-MODEL §3.1).
  - `0x05 0xFF` (no acceptable methods) is the reply iff the client
    offers ONLY `0x00`. After `0x05 0xFF` the connection MUST close with
    no further bytes (the test asserts EOF immediately after).
  - Silent-close path emits zero response bytes — there is no agreed
    framing in which to deliver an error, and emitting a template would
    itself be a protocol signal (Principle I — dumb router; FR-006).
- **Gated:**
  - `tests/contract/socks5/demux_test.go` (this ticket) is itself the
    fail-closed gate for the byte shapes above; once T042 lands the test
    flips from SKIP to RED, driving the implementation.
  - `go vet` + `staticcheck` + `gosec` cover the data-plane source's
    syntactic / security surface (verify.sh gates 3–5).
  - License-header check gates SPDX on the new files.
- **Residue:**
  - Demux timing side-channel on the first byte is not testable from
    userland; residue is honestly stated. T025 covers the auth constant-
    time surface; demux itself is a single `Read` of one byte and carries
    no secret-dependent branch.
  - HTTP CONNECT-path positive behaviour (the `'C'` row's success
    shape) is NOT asserted here — that is T026/T027's scope. This ticket
    asserts only the demux *routing* decision: `'C'` is not treated as
    SOCKS5 (no `0x05 …` reply) and not silently closed (the connection
    survives the first byte so CONNECT parsing can proceed). A negative
    case (`'G'`, ASCII for HTTP GET) DOES assert the silent-close row.

## Acceptance

Named test in `tests/contract/socks5/demux_test.go`, package `socks5`:

- `TestSOCKS5DemuxAndMethodNegotiation` with sub-cases, each dialling
  the DP's proxy listener (`STARGATE_LISTEN_ADDR`) once and asserting
  byte-exact replies:
  - (a) `MethodNegotiation_UserPassOnly`: write `05 01 02`, assert
    reply is exactly `05 02`.
  - (b) `MethodNegotiation_MixedMethods`: write `05 02 00 02`, assert
    reply is exactly `05 02` — USERNAME/PASSWORD wins over NO_AUTH when
    both are offered (the realistic-client shape; guards against an
    accidental NO_AUTH-accept regression).
  - (c) `MethodNegotiation_NoAuthOnly`: write `05 01 00`, assert reply
    is exactly `05 FF`, then assert EOF (no further bytes; connection
    closed by the DP).
  - (d) `Demux_HTTPConnectFirstByte`: write `43` (`'C'`), assert the
    connection is NOT closed and NO `05 …` reply is sent within a
    bounded read window — the DP routed the conn down the CONNECT path
    (full CONNECT-auth success is T026/T027's scope; here we only pin
    the demux routing decision).
  - (e) `Demux_UnknownFirstByte_SilentClose`: write `47` (`'G'`), assert
    EOF with zero reply bytes — silent-close per the demux table's
    "anything else" row.
- Content-gate: the test self-skips (never fails) while the DP
  implementation files are absent —
  `data-plane/internal/listener/socks5.go` (T042) and
  `data-plane/cmd/stargate-proxy/main.go` (T050). Once both exist, a
  byte-contract violation is FAIL, not SKIP.
- Shared harness: the DP-process boot harness lives in a new importable
  package `tests/internal/dpharness/` (non-`_test.go`, `package
  dpharness`), mirroring the `tests/internal/loginvariants/` precedent
  from `plan.md` §"Tree convention" and `tests/integration/` (T019a).
  The existing `tests/contract/control-grpc/dpharness_test.go` is NOT
  touched — its `_test.go` form is unimportable across packages, and
  refactoring it is out of scope for T023 (filed as follow-up).
- Runnable: `scripts/verify.sh` green (this test self-skips on a tree
  without T042/T050).

## Out-of-scope

- HTTP CONNECT positive-path testing (`'C'` first byte → auth-success
  → byte-pipe). That is T026 (`connect_auth_success_test.go`) and T027
  (`error-template/auth_required_test.go`) — the error-template path.
  T023 only pins the demux *routing* decision for `'C'`, not what the
  CONNECT path does after routing.
- Username/password sub-negotiation success and forwarding of `UNAME`
  verbatim — T024 (`userpass_success_test.go`).
- Auth-failure leak invariants (token bytes in reply, constant-time
  comparison, slot-invariance) — T025 (`leak_test.go`).
- Refactoring `tests/contract/control-grpc/dpharness_test.go` to import
  from the new shared `tests/internal/dpharness/` package — filed as
  follow-up; T020/T021/T022 stay self-contained.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
