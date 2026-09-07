---
id: T130
title: 'Inter-plane gRPC channel never establishes in the compose stack'
status: pending
created: 2026-09-07
last_updated: 2026-09-07
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: [T122, T125, T129]   # stack must boot first: images (T122), publish (T125), CP boot (T129)
parallel: false   # THE live-path blocker; privacy-critical auth plumbing — needs dedicated investigation
files_budget: 8
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
reviews: {}
overrides: []
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

*(The investigation plan; the fix is unknown until the handshake failure
is observed.)*

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
