---
id: T130
title: 'Inter-plane gRPC channel never establishes in the compose stack'
status: done
created: 2026-09-07
last_updated: 2026-09-07
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T122, T125, T129]   # stack must boot first: images (T122), publish (T125), CP boot (T129)
parallel: false   # THE live-path blocker; privacy-critical auth plumbing — needs dedicated investigation
files_budget: 9   # tightened 2026-09-07: the defect spans both planes' TLS wiring + the three harness surfaces that dialed dp.sock plaintext (data-plane ×4, tests/contract ×4, wire-auth.md) — each traces to acceptance
privacy_critical: true   # the channel carries ReloadTokens/WatchEvents — the auth-generation path
complexity: high
risk: medium
round_cap: 2
spec_refs:
   - specs/001-tor-route/contracts/control-grpc.md   # channel directionality: CP→dp.sock (ReloadTokens client), DP→control.sock (WatchEvents client); CP is the control.sock server
   - specs/001-tor-route/contracts/wire-auth.md §2   # TLS-over-UDS mutual handshake the channel requires
   - specs/001-tor-route/tasks.md#T059   # discoverer (live run, 2026-09-07)
decision_refs:
   - .specify/memory/constitution.md#Principle-II   # the DP keeps routing degraded — why the stack LOOKS alive while the channel is dead
reviews: { round: 1, date: 2026-09-07, verdict: APPROVE }
overrides:
   - 2026-09-07, user-approved ("do one more round"): round-2 REWORK's
     single Major — the degraded-mode journal line used field key
     `reason` where the control_channel class allows exactly `err` — was
     a one-token fix the round-2 verdict itself pre-authorized ("one-token
     fix (`reason`→`err`), then approve"). The token was applied and
     verified BEFORE the cap escalation fired (verify.sh GREEN
     PASS=20/0/1; the loginvariants gate's own fixtures at
     loginvariants_test.go:57 pin exactly `msg="control channel degraded"
     err=…`). Resolution: override recorded, cycle reset, fresh round-1
     review of the complete diff. No finding was declined; both round-1
     Majors are fixed in-tree.
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T130: Inter-plane gRPC channel never establishes in the compose stack

## Context

Hand-filed from T059's live chain (2026-09-07). With the stack fully
booted under the T122/T125/T127 fixes — images built, wildcard listen +
publish working (host TCP reaches the DP), CP healthy with SQLite open
and tokens.yaml loaded ("ReloadTokens generation 1" in the CP log) — the
inter-plane gRPC channel NEVER establishes:

- CP, once at boot: `WARN GrpcReloadChannel ReloadTokens generation 1 not
  delivered (UNAVAILABLE: io exception` — and no further attempts logged.
- DP, once at boot: `WARN control channel degraded err=…dial unix
  /run/stargate/control.sock: connect: no such file or directory` — the
  WatchEvents client's first dial raced the CP's control.sock creation,
  and no recovery is logged either.
- Ground truth at the filesystem (probed from inside the CP container):
  BOTH sockets exist with contract-correct ownership/mode —
  `srw-rw---- stargate-cp:stargate-ipc control.sock`,
  `srw-rw---- 5102:stargate-ipc dp.sock` — and the CP reads its keys and
  tokens.yaml fine. The transport is CONNECTABLE (sockets exist, perms
  correct); the failure is in the handshake/session layer above —
  wire-auth §2 TLS-over-UDS (cert derivation from the ed25519 pairs,
  mutual verification, identity binding) and/or the retry semantics.

Consequence: no ReloadTokens push ⇒ the DP's token generation stays
empty ⇒ every SOCKS5 auth through 8881 is rejected (`1 FF`) ⇒ the full
vertical is auth-dead even though every container looks alive. Principle
II's degraded-mode design (correctly) keeps routing up, which is exactly
why this defect is invisible to anything that doesn't authenticate.

## Analysis

*(Investigation plan as filed; RESOLVED below — root cause observed live
before any fix was written, per the falsify-first discipline.)*

**ROOT CAUSE (observed live 2026-09-07, logging repro in a provisioned
stack):** two composition defects, both invisible until the first-ever
Java-CP↔Go-DP execution —

1. **dp.sock served PLAINTEXT.** `main.go`'s wiring discarded the SERVER
   half of `DeriveDPTLS` (`clientTLS, _, tlsErr := …`), and
   `NewGRPCServer` had no TLS pathway at all. The DP's own log showed
   the CP's TLS ClientHello read as an HTTP/2 preface — grpc-go
   "bogus greeting" — and the CP logged `ReloadTokens generation 1 not
   delivered (UNAVAILABLE: io exception … SslHandler…)`. The crypto was
   never wrong: `TestMutualTLSHandshakeEndToEnd` pinned the §2/§3/§4
   material by wiring `tls.NewListener` itself — the COMPOSITION (the
   production server shape) was pinned by no test, and the contract
   harness dialed dp.sock with `insecure.NewCredentials()` under a
   "T022 seam: mutual-ed25519 client credentials attach at this dial"
   comment that was never implemented.
2. **No ALPN h2 on the Go configs.** gRPC over TLS requires negotiated
   `h2`; the Go `tls.Config`s set no `NextProtos`. Go↔Go pairs passed
   (both sides skip ALPN — mutually consistent, mutually underspecified,
   the T063 external-calibration lesson again), while grpc-java
   negotiates strictly. wire-auth.md §4 never named ALPN — a contract
   omission, now amended (exactly `["h2"]`, both planes, client+server).

Also observed: DP→CP (WatchEvents) CONNECTED fine even pre-fix (grpc-java
server accepted the ALPN-less Go client); the one-attempt-at-boot reading
was wrong on both sides — grpc channels auto-reconnect with backoff; the
CP's PUSH invocation is boot-time (§1.8 containment, as designed). The
DP-restarts-while-CP-up re-push gap is a separate follow-up (T132).

**FIX (tests-first):** `TestNewGRPCServerRequiresTLS`,
`TestGRPCServerServesMTLSOverUDS` (CP-shaped mTLS dial + plaintext
negative control through the PRODUCTION server shape),
`TestTLSConfigsOfferALPNH2` (red, then): `NewGRPCServer(control,
serverTLS)` REQUIRED (nil → error, never a plaintext fallback; degraded
mode serves NO dp.sock — main.go logs it and keeps routing, Principle
II), `NextProtos: ["h2"]` on the shared config constructor, harnesses
seed inter-plane keys and dial with CP-shaped pinned credentials
(control-grpc harness + the shared socks5/error-template dpharness),
wire-auth §4 amended (ALPN row + dp.sock-server-TLS row). The T095
R4-static gate caught the new bufconn test's unpinned InsecureSkipVerify
mid-flight — fixed by pinning dp.pub; the gate's own catch is the
system working.

**VALIDATION (full path, not symptom):** hermetic verify.sh GREEN
(20/0/1); all three affected contract suites green over the TLS dial;
live provisioned stack: DP log `tokens applied generation=1 count=1`
(push delivered over TLS dp.sock) and an authenticated CONNECT through
127.0.0.1:8881 → DP → tor → the reference onion returned HTTP 200 with
176 KB of body — the FIRST-EVER full-stack green. The T131 stack smoke
test (landed RED-by-design against this ticket) went
`--- PASS: TestStackSmoke (32.25s)` — the acceptance criterion this
ticket was driven against.

- **Observe the failure first**: enable gRPC/Netty debug logging on the
  CP (`QUARKUS_LOG_CATEGORY` env or a compose-scoped override) and
  capture the io.exception behind "ReloadTokens generation 1 not
  delivered"; on the DP, `GRPC_GO_LOG_VERBOSITY_LEVEL=2` /
  `GRPC_GO_LOG_SEVERITY_LEVEL=info` env for the client dial. The same
  run should show whether WatchEvents/retry loops ever re-attempt (the
  single-attempt-at-boot behaviour on BOTH sides is itself suspect —
  a channel that never retries cannot survive Principle II's CP-restarts
  and contradicts the degraded→recovered design intent).
- **Candidate surfaces** (in order of suspicion): (1) mTLS handshake —
  cert derivation from ed25519 keys (init's PKCS#8 shapes vs
  DeriveDPTLS/readPepper expectations — T035a/T044 formats), identity/
  hostname verification over UDS, trust-anchor publication (cp.pub/
  dp.pub exchange ordering — the CP writes the pubs at runtime per the
  compose comments; a fresh volume may leave one plane reading a pub the
  other hasn't written); (2) retry semantics — both sides log exactly
  one attempt at boot; (3) socket path/permissions under the IPC
  group (ruled out by the probe — both sockets are group-writable to
  stargate-ipc).
- **Constraint**: whatever the fix, it must NOT weaken wire-auth §2's
  mutual-authentication contract (no plaintext fallback, no
  InsecureSkipVerify equivalent). The degraded-mode contract (Principle
  II: routing continues, auth continues with the cached/empty
  generation) is correct and stays.

## Acceptance

1. With a freshly provisioned stack, the CP logs a DELIVERED generation
   and the DP accepts an authenticated SOCKS5 CONNECT through 8881
   (positive control — T059's live run passes its CONNECT phase).
2. Restarting stargate-control mid-run re-establishes the channel
   (retry semantics proven; no single-attempt dead-end).
3. wire-auth §2 mutual-auth contract unchanged (negative control: a
   plane presenting the wrong key pair is still rejected).
4. `bash scripts/verify.sh` GREEN.

## Out-of-scope

- Any change to FR-006 token semantics or the auth-failure reply shape.
- T059's test artifact (its AUTH classification + forensics already
  name this failure mode precisely).
