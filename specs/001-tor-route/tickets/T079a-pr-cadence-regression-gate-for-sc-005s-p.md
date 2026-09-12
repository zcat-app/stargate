---
id: T079a
title: 'PR-cadence regression gate for SC-005''s pool-fill + steady-state prope'
status: pending
created: 2026-07-04
last_updated: "2026-09-12"
source: tasks.md#T079a
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T019a", "T044", "T047", "T049", "T050", "T092", "T093", "T155", "T072", "T156"]
parallel: true
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs: []   # TODO: cite spec.md § at /start
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T079a: PR-cadence regression gate for SC-005's pool-fill + steady-state prope

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Full task body (verbatim from tasks.md):**
>
> PR-cadence regression gate for SC-005's pool-fill + steady-state property in `tests/integration/concurrent_connects_test.go`. Uses `fake_socks5_tor.go` (T019a) in `accept-and-relay` mode as the upstream — same backend T079 uses, so the two tasks measure consistent surfaces. The test (a) brings up the data plane with a one-token in-memory generation; (b) opens 200 concurrent authenticated CONNECTs through port 8881 (mix of SOCKS5 and HTTP CONNECT inbound framing to exercise both surfaces); (c) asserts the pool reaches 200 established connections within 30 s wall-clock (the fill-time floor from plan.md §"Performance Goals" measurement model, with the upper bound chosen to absorb argon2id-auth latency at N=1 and reasonable CI hardware variance); (d) holds all 200 connections open for ≥60 s while exchanging interleaved frames in both directions; (e) asserts none of the 200 connections dropped, were starved, or hit a deadline during that hold window; (f) asserts the T025a shared log allowlist applies — no per-connection log line is emitted during fill or hold. Scope boundary: this task **does NOT** verify the zero-retained-allocation property (that requires heap profiling and stays with the milestone `stargate-perf` agent run, T079) — it is a PR-cadence regression line against bottlenecks, deadlocks, or accidental serialization in the listener/auth/forward path, complementing rather than replacing T079. CI runs this test on every PR touching `data-plane/` (gated alongside the six contract-test directories per T076's glob, by adding `tests/integration/` to the same workflow path filter). Depends on T019a (synthetic backend), T044 (auth), T047 (forward), T049 (counters), T050 (main).

## Analysis

*(Required — `privacy_critical: true`. Fill at `/start` per
`docs/process/analysis.md`.)*

## Acceptance

*(Derived by T093 acceptance #4 from `plan.md` SC-005 + the T092 HMAC
amendment. T079a implements the test; this section pins its design so
the impl ticket has executable acceptance, not just the Notes intent.)*

1. **Peak-RSS-under-flood assertion (the sol-review B5 falsifier).** The
   SC-005 probe opens **200 concurrent unauthenticated CONNECTs** through
   port 8881 (the flood surface a local process reaches over loopback).
   Under the retired Argon2id verifier this allocated ~`200 × 64 MiB ≈
   12.8 GiB`; under the HMAC-SHA-256 verifier (data-model.md §1.5) each
   auth allocates O(1) — one 32-byte tag + the per-connection buffer. The
   test asserts the DP's **peak RSS stays inside a documented ceiling**
   during the flood, reported as a separate number from the steady-state
   pool-fill timing. **Ceiling methodology (pinned at first green run,
   not invented here):** establish the idle baseline (DP RSS with 0
   inbound connections) and assert peak-RSS-under-flood ≤ `baseline +
   200 × connDeltaCeiling`, where `connDeltaCeiling` is the documented
   per-connection memory budget (a single SOCKS5/CONNECT conn's read +
   write buffers; ~64 KiB/order-of-magnitude, pinned from the first
   run's measurement). An absolute floor of **512 MiB** is the
   coarse-grained backstop (a Go proxy serving 200 idle loopback
   connections with HMAC auth sits well under this); the
   baseline-relative bound is the precise gate. A run that exceeds
   either FAILS — that is the B5 regression line.

2. **Steady-state pool-fill + 60 s hold (unchanged SC-005 core).** The
   probe fills 200 authenticated CONNECTs within 30 s wall-clock, holds
   them ≥60 s exchanging interleaved frames in both directions, and
   asserts none dropped / starved / deadline-hit. Reported as a SEPARATE
   number from peak-RSS — pool-fill timing alone does NOT falsify B5
   (the RSS-under-flood bound does); both must be present.

3. **No per-request log line during fill or hold** (T025a shared log
   allowlist applies). The flood must not trigger a per-connection log
   line — a logger activated per-auth would itself be a resource leak
   under flood and a Principle III side channel.

4. **HMAC-auth latency floor.** Under the prior Argon2id design each
   stored token cost ~50 ms of hash work; under HMAC the candidate's tag
   is computed once and compared (constant-time) against all verifiers
   (§1.5). The probe reports auth-decision latency as a separate number;
   no hard assertion (HMAC compare is sub-microsecond and dominated by
   loopback jitter), but the reported number is the falsifier-input for a
   future regression ceiling and confirms the flood is not
   auth-bottlenecked.

5. **CI path filter.** `tests/integration/` runs under the same
   `scripts/verify.sh` entrypoint (T076), `STARGATE_TEST_TAGS` unchanged
   — this is a hermetic PR-cadence test, not a Docker/live suite. It
   content-gates on T044/T047/T049/T050 (self-skips until they land).

## Out-of-scope

The **zero-retained-allocation** property (heap profiling) stays with
the milestone `stargate-perf` agent run (T079) — this ticket is a
PR-cadence regression line against bottlenecks, deadlocks, accidental
serialization, and the B5 memory-DoS, NOT a heap-profiling gate. Live
Tor-network behaviour is release-cadence (T034f / T077–T079).

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

**T092 amendment (2026-07-15) — the B5 falsifier is in scope here.** The
sol-review B5 finding (per-request Argon2id → ~12.8 GiB allocation under
200 concurrent auths) is fixed by the HMAC-SHA-256 verifier (O(1)
per-request allocation regardless of N or flood size; `data-model.md`
§1.5). **This ticket's gate is the falsifier for that fix**: extend the
SC-005 probe to assert (a) **peak RSS stays inside a documented memory
ceiling** under a 200-connection unauthenticated flood, and (b) the
steady-state pool-fill + 60s stability, reported as separate numbers
(`plan.md` SC-005 measurement model, T092 amendment). Pool-fill timing
alone does NOT falsify B5 — the RSS-under-flood bound does. T093
(blocked_by T092) pins the unit-level properties; this ticket is the
release-cadence perf gate.

**T093 design extension (2026-07-15).** T093 acceptance #4 fleshed out
the §Acceptance above (peak-RSS ceiling methodology, steady-state
separation, HMAC-auth latency floor, CI path filter). The concrete
ceiling numbers are pinned at first green run, not invented here — the
methodology (baseline-relative + a 512 MiB absolute floor) is the gate.
T079a remains `pending` (blocked_by T019a, T044, T047, T049, T050, T092,
T093); it implements the test described above once its blockers land.
