---
id: T072
title: 'Extend `data-plane/internal/forward/tor.go` (from T047) to map upstrea'
status: done
created: 2026-07-04
last_updated: "2026-10-09"
source: tasks.md#T072
phase: "5: User Story 3 — Privacy-safe failure when Tor is down (Priority: P3)"
story: 'US3'
blocked_by: ["T009", "T155", "T065", "T066", "T067", "T067a", "T067b", "T070", "T071", "T156"]
parallel: false
files_budget: 8   # TODO: tighten per task
privacy_critical: true
complexity: low   # TODO: set per task
risk: low
round_cap: 2
spec_refs:
  - 'specs/001-tor-route/spec.md FR-008/FR-009 and US3 failure-path acceptance'
  - 'specs/001-tor-route/contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)" and §"Deadlines"'
  - 'specs/001-tor-route/data-model.md §3 (`request_count` and `byte_count`)'
  - '.specify/memory/constitution.md Principles I, III, and VII'
  - 'THREAT-MODEL.md §5.10 (pending upstream request and no idle deadline)'
decision_refs:
  - 'T172 selected acceptance: authenticated SOCKS5 only; fixed REP 03/04/06, zero BND fields, close, and no HTTP template ingress or fallback'
  - 'T173 selected acceptance: port-8881 HTTP CONNECT is refused before auth, counters, or Tor ingress; renderer remains disconnected'
  - 'T208: 250-second dial-and-handshake cap; Tor REP 06 is ROUTE_REFUSED, while only the data-plane deadline is ROUTE_TIMEOUT'
  - 'T149: forwarded-byte accounting is finalized after both forwarding pumps'
  - 'T025b: long-lived bidirectional SOCKS CONNECT has no idle deadline'
tests_first: ["T065", "T066", "T067", "T067a", "T067b", "T070"]
reviews: { round: 1, date: 2026-10-09, verdict: APPROVE, findings: 0, candidate: "d6b7fc64bacccdec0036f8ea87d9309fea07205154453e849a60cc622dd6c44b", base: "723d0eb6d482389f3fdc16bd31a341cee6b9b72a", reviewers: "Astra (Codex; gpt-6-astra; high; APPROVE); Luna (Codex; gpt-6-luna; high; APPROVE)" }
overrides: [{"date": "2026-10-09", "by": "user", "decision": "Limit verification to the two affected Go selector commands", "reason": "The user-scoped T072 instruction excludes repository-wide verify.sh and Java; the focused affected-part results are recorded below."}]
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T072: Extend `data-plane/internal/forward/tor.go` (from T047) to map upstrea

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical tasks.md body (superseded where conflicting by T172 acceptance below):**
>
> Extend `data-plane/internal/forward/tor.go` (from T047) to map upstream SOCKS5 connect-failure replies to `ROUTE_REFUSED` and to enforce the 30 s dial-and-handshake deadline mapped to `ROUTE_TIMEOUT` per `contracts/socks5-auth.md` §"Deadlines" (wired as a single named constant; no idle deadline after handshake — the post-handshake byte pipe is intentionally long-lived per Principle I). The mapping emits the **inbound-protocol-appropriate** response shape: on the HTTP CONNECT path, the privacy-safe HTML template via T071; on the SOCKS5 path, the 10-byte RFC 1928 §6 reply with `BND.ADDR`/`BND.PORT` zeroed per `contracts/socks5-auth.md` §"SOCKS5 request-phase failures (post-auth)" — `ROUTE_DOWN→0x03`, `ROUTE_REFUSED→0x04`, `ROUTE_TIMEOUT→0x06`. **No Tor reason text or upstream error string propagates into the response on either shape** (FR-009). Verified by T065–T070 (CONNECT shape), T067a (SOCKS5 shape), and T067b (counter-increment asymmetry across both shapes).

## Analysis

- **Must hold:** During upstream dial and SOCKS5 handshake, timeout classification
  takes precedence and maps the data plane's own deadline to `ROUTE_TIMEOUT` / REP
  `0x06`; an upstream SOCKS refusal, including Tor's own REP `0x06`, maps to
  `ROUTE_REFUSED` / REP `0x04`; other establishment failures map to `ROUTE_DOWN` /
  REP `0x03`. The client receives only the fixed ten-byte RFC 1928 reply with zero
  BND fields and then EOF; no upstream REP, reason, or error text is exposed. The
  single named dial-and-handshake deadline is 250 seconds. After a successful
  handshake there is no idle deadline: the byte pipe remains long-lived, and
  completed tunnel bytes are accounted after both pumps finish.
- **Source inspection:** `data-plane/internal/forward/tor.go` defines the 250-second
  `upstreamDialTimeout`, checks timeout before upstream refusal in `classify`, applies
  the context deadline to `DialContext`, and wraps a successful connection in
  `countingConn` only after the handshake. `data-plane/internal/listener/socks5.go`
  derives the failure REP from the route class and writes fixed zeroed BND fields;
  forwarding error text is not serialized. T173 keeps HTTP CONNECT off this ingress.
- **Fresh focused execution:** on 2026-10-09, the orchestrator ran the five forward
  selectors listed in Acceptance and they passed in 0.295s; the two fast contract
  selectors passed in 3.454s. These results are attributed to that execution and
  are distinct from the historical long-running T067a/b evidence below.
- **Historical evidence:** T065–T067 own authenticated exact route-failure replies,
  EOF and leak checks. T067a records the post-T208 focused timeout selector and its
  completion/review, but retains no explicit command output or elapsed time. T067b
  records its counter selector passing in 255.022 seconds. These records are not
  fresh T072 executions. T173 owns HTTP refusal; T149 owns final accounting after
  both pumps; T025b owns long-lived bidirectional behavior without an idle deadline.
  T070b covers advisory-event independence; T070a's relevant invariant is that a
  midstream Tor circuit close adds no synthesized failure bytes; T070 covers the
  integrated SOCKS route-down/no-fallback case. They remain historical consumer
  evidence, not T072 reruns. No relevant forwarder/listener runtime, harness, or
  dependency input changed after T067a/b; T071 only changes the disconnected renderer.
- **Residue:** upstream refusal classification depends on the pinned
  `x/net/proxy` error surface, guarded by the real protocol-byte selector. The REP
  mapping establishes the client-visible class, not Tor's internal reason or global
  sidecar health. The 250-second cap is a backstop and does not prove Tor exhausted
  every descriptor or rendezvous attempt.

## Acceptance

1. Source inspection must match the Analysis property map: `classify` gives timeout
   precedence, upstream SOCKS refusal maps to `0x04` even when Tor's REP is `0x06`,
   other establishment failure maps to `0x03`, the production dial-and-handshake
   deadline is 250 seconds, and a successful handshake enters a deadline-free pipe.
   The listener emits only one fixed ten-byte failure reply with zero BND fields and
   closes; no upstream error text reaches the client. T173 continues to own HTTP
   CONNECT refusal and no HTTP template is reachable from port 8881.
2. From `data-plane/`, run the focused forward classification/deadline selectors:

   ```sh
   go test ./internal/forward -run '^(TestForwardUnreachableUpstreamIsRouteDown|TestForwardUpstreamRefusalIsRouteRefused|TestForwardDialDeadlineIsRouteTimeout|TestForwardUpstreamTTLExpiredReplyIsRouteRefused|TestProductionDialDeadlineIsContractValue)$' -count=1
   ```

   These pin unreachable→`0x03`, upstream refusal→`0x04`, local deadline→`0x06`,
   Tor's own REP `0x06`→`0x04`, and the production 250-second constant.
3. From `tests/contract/`, run the fast authenticated wire selectors:

   ```sh
   go test ./socks5 -run '^(TestRouteDownSOCKS5Reply|TestRouteRefusedSOCKS5Reply)$' -count=1
   ```

   They pin the exact `ROUTE_DOWN` / `ROUTE_REFUSED` replies, zero BND fields, EOF,
   and the existing leak/privacy checks. Use T067a's historical timeout selector
   instead of repeating its unchanged 250-second wire case; retain T067b's recorded
   long counter result as historical evidence.
4. Keep T065–T067, T067a/b, T070, T070a/b, T149, T025b, T173, and T208 as cited
   historical owners/consumers; do not rewrite their records or represent them as
   fresh T072 executions. Repository-wide `verify.sh` and Java remain outside the
   scoped verification instruction. GLM remains paused; the review gate is fresh
   Astra plus Luna.

## Verification — 2026-10-09

- From `data-plane/`, the five-selector forward command in Acceptance passed (0.295s).
- From `tests/contract/`, the two-selector SOCKS5 command in Acceptance passed (3.454s).
- Repository-wide `scripts/verify.sh` and Java were not run under the user's scoped
  verification instruction. No Docker or VM checks were run.

## Out-of-scope

No production or test changes; no contract changes; no edits to T065–T067, T068/T069,
or other historical ticket records; no duplicate 250-second timeout or counter
execution; no Java, repository-wide `verify.sh`, Docker, or VM execution; no commit.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.

## T172 selected acceptance (supersedes conflicting historical task text)

Verify the upstream dial/handshake timeout at the contract value (250 s since T208;
`contracts/socks5-auth.md` §Deadlines) and map `ROUTE_DOWN/REFUSED/TIMEOUT` only to
the fixed SOCKS5 REP `03/04/06` with zero BND fields, EOF and no upstream text. No
idle deadline after handshake, event-gated admission, HTTP template path or fallback.
T065–T070/T067a/b remain the verification consumers.

## T173 renderer dependency refinement

T071 owns the consolidated T068/T069 tests and renderer implementation. Retain T071 as
the blocker; the superseded deferred test tickets must not independently block this consumer.
