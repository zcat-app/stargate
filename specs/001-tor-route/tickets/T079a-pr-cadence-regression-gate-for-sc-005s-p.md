---
id: T079a
title: "Gate SC-005 SOCKS pool and memory"
status: done
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T079a
phase: "6: Polish & Cross-Cutting Concerns"
story: '-'
blocked_by: ["T019a", "T044", "T047", "T049", "T050", "T092", "T093", "T155", "T072", "T156"]
parallel: true
files_budget: 4
privacy_critical: true
constitution_refs:
  - "III: Privacy-preserving by construction"
  - "VII: Tests-first for privacy-critical and contract code"
complexity: low
risk: low
round_cap: 2
spec_refs:
  - "specs/001-tor-route/spec.md §SC-005"
  - "specs/001-tor-route/plan.md §Performance Goals — SC-005 measurement model"
  - "specs/001-tor-route/data-model.md §1.5"
decision_refs:
  - "specs/001-tor-route/tickets/T092-amend-token-verifier-lifecycle.md"
  - "specs/001-tor-route/tickets/T093-test-token-verifier-lifecycle.md"
  - "specs/001-tor-route/tickets/T172-reconcile-connect-refusal-contracts.md"
  - "specs/001-tor-route/tickets/T173-refuse-unpartitioned-http-connect.md"
  - "specs/001-tor-route/tickets/T076-wire-all-six-v1-contract-test-directorie.md"
reviews: { round: 2, date: 2026-10-09, verdict: APPROVE, findings: 0, candidate: "bc2e44b704bb28bee561b4e51ae20a39520ed18205e55f37dbb5f3a017bafdff", base: "49abbeef5732290fb2261dfdcded182a26f88752", reviewers: "Astra (Codex; gpt-6-astra; high; APPROVE); Luna (Codex; gpt-6-luna; high; APPROVE)" }
overrides: [{"date":"2026-10-09","by":"user","decision":"Limit verification to the affected Go selector and ticket/status/diff checks","reason":"The user directed testing only the parts changed and affected; Java and repository-wide verify.sh were excluded."}]
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T079a: Gate SC-005 SOCKS pool and memory

## Context

This ticket adds a focused regression gate for SC-005's authenticated SOCKS5 pool fill, 60-second bidirectional hold, and T093's invalid-auth HMAC memory falsifier. T172 selects SOCKS5-only success load; T173 owns HTTP refusal under load. The contract module is already discovered by T076's Go workspace gate, so no workflow path-filter change is required.

## Analysis

This test protects Constitution Principle III by checking that well-formed invalid credentials reach HMAC verification without producing an unbounded memory spike, and that the child's captured output remains unchanged under load. Principle VII requires these properties to be established by the test before implementation. The test measures the actual DP child through Linux `/proc` and skips before boot on other operating systems.

- **Must hold:** The invalid-auth fixture is exactly 32 lowercase hexadecimal characters and differs from the installed token. Synchronized canary cohorts at concurrency 1, 2, 4, 8, 16, 32, 64 and 128 precede a final barrier-released cohort of 200. Every request receives exactly `01 FF`. A sampler checks `VmRSS` and `VmHWM`; a ceiling breach immediately kills the DP and closes active clients. The relative ceiling is idle `VmHWM` + 200 × 64 KiB; the absolute ceiling is 512 MiB. The first green run must support these proposed ceilings. If it does not, stop for plan re-evaluation rather than silently raising either ceiling.
- **Must hold:** 200 authenticated SOCKS5 CONNECT sessions receive exact success replies within 30 seconds, reach the synthetic upstream, and each exchange unique bidirectional frames throughout a 60-second hold without starvation, early close or deadline.
- **Must hold:** Captured child output is byte-for-byte unchanged after invalid-auth load, pool fill and hold. Failures report only the changed-byte count. The test opts into `WithSuppressFailureJournal` so startup-timeout and cleanup failure paths also suppress raw child output; other harness callers retain the default diagnostics.
- **Gated:** The focused Go selector, ticket lint, STATUS regeneration/check and `git diff --check` cover this candidate. Verification is authorized to remain selector-only; Java and repository-wide `scripts/verify.sh` are not run.
- **Residue:** The fake backend proves the DP's SOCKS5 accept/relay behavior, not live Tor circuits, production-network load, heap profiling or zero-retained-allocation. T079 and T034f/T077–T079 retain those measurements and release evidence.

## Acceptance

The test `TestSC005ConcurrentSOCKS5Load` in `tests/contract/socks5/sc005_load_test.go` MUST:

1. Capture idle `VmRSS` and `VmHWM` after DP boot, installation of one valid token generation, and control-channel settling. Report both values. Set the relative ceiling to idle `VmHWM` + 200 × 64 KiB and the absolute ceiling to 512 MiB.
2. Run synchronized invalid-auth cohorts at concurrency 1, 2, 4, 8, 16, 32, 64 and 128, then 200 concurrent attempts. Each attempt uses the same distinct, well-formed 32-character lowercase-hex password and requires exactly `01 FF`. Continuously sample RSS/HWM, kill the child and close all active clients immediately on a ceiling breach, and bound the complete flood phase to 30 seconds.
3. Report attempt count, maximum concurrency, auth response latency, idle RSS/HWM, peak RSS/HWM, HWM delta and both ceilings. Keep these figures separate from pool-fill wall time. Close all flood sockets before filling the authenticated pool.
4. Open 200 authenticated SOCKS5 CONNECT sessions behind one start barrier, using unique test UNAMEs and inert `.onion` targets. Require exact method, auth and CONNECT success framing, exactly 200 synthetic-upstream CONNECTs, and completion within 30 seconds.
5. Hold all sessions open for 60 seconds. Each client sends unique frames on a bounded ticker and verifies the exact echo. Every session must complete round trips throughout the hold without a lost reply, close, starvation or deadline. Report pool-fill time independently from flood metrics.
6. Assert child output is byte-for-byte unchanged after flood, fill and hold; never print child output, credentials, username, destination or frame content. Use `dpharness.WithSuppressFailureJournal()` so startup-timeout and cleanup failure paths suppress the raw journal while other harness callers retain default diagnostics.
7. Run only the authorized affected-part checks from `tests/contract`: `timeout 240s go test -v ./socks5 -run '^TestSC005ConcurrentSOCKS5Load$' -count=1 -timeout 180s`, ticket lint, STATUS regeneration/check and `git diff --check`. Do not run Java, a VM, push or repository-wide `scripts/verify.sh`.

## Out-of-scope

The zero-retained-allocation property (heap profiling) remains with the T079 performance run. Live Tor-network behavior remains release-cadence evidence (T034f/T077–T079); this synthetic test makes no claim about circuits or external network behavior.

## Notes

T076's existing workspace gate discovers `tests/contract`; adding `tests/integration/` to a workflow path filter would duplicate the existing discovery mechanism. The 64 KiB per-connection value is a proposed ceiling pending the first green run. If observed HWM cannot support it, stop and re-evaluate the plan; do not tune the ceiling to fit the measurement.

**Selector evidence (2026-10-09, final revised candidate):** The authorized
focused selector passed in 61.23 seconds. Idle DP RSS/HWM were each
13,631,488 bytes; invalid-auth peak RSS/HWM were each 15,298,560 bytes,
for a 1,667,072-byte HWM increase. The baseline-relative ceiling was
26,738,688 bytes and the absolute ceiling was 536,870,912 bytes. The run
reached maximum concurrency 200 across 455 invalid-auth attempts; the final
200-request cohort's mean auth response latency was 3.154987 ms and its
maximum was 3.517884 ms. Flood wall time was 159.003607 ms, authenticated
pool fill was 69.560938 ms, and every client echoed in each one-second hold
window within the 60-second hold. The proposed memory ceilings passed
unchanged.
