---
id: T124
title: 'Tor healthcheck bootstrap window shorter than real cold-boot time'
status: pending
created: 2026-09-07
last_updated: "2026-09-12"
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: ["T139", "T134", "T138", "T156", "T162", "T164", "T165"]
parallel: true
files_budget: 3
privacy_critical: true
complexity: low
risk: "medium"
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md §"User Story 1" acceptance scenario 1   # "Tor sidecar HEALTHY" presupposes the healthcheck is attainable on a normal cold boot
   - specs/001-tor-route/contracts/torrc.md   # invariant #8 (Log notice stdout) and the control-port probe the healthcheck rides
   - specs/001-tor-route/tasks.md#T059   # discoverer (live run #3, 2026-09-07)
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T124: Tor healthcheck bootstrap window shorter than real cold-boot time

## Context

Hand-filed from T059's live run #3 (2026-09-07). `sidecars/tor/Dockerfile`
HEALTHCHECK:

```
--interval=30s --timeout=10s --start-period=60s --retries=3
```

greps the control-port bootstrap-phase for `PROGRESS=100` — i.e. it demands
FULL live-network bootstrap within ~150 s worst case. A cold bootstrap on
the live Tor network legitimately takes minutes (T032 and T058a budget
5 minutes for exactly this; T059's run #1 bootstrapped within the window,
run #3 did not — same tree, fresh volume both times). The current installer
waits for Tor's Docker healthcheck, so a delayed bootstrap can time out the
operator's clean-host `init` even while the observer process is running.
The Tor-native healthcheck is inside Tor's TCB; it is not a CP command channel.

## Analysis

*(Quick pass — arithmetic + one knob.)*

- The healthcheck's JOB (compose file comments; T032) is to prove the
  Tor-local control socket authenticates with its own cookie. T164 moved CP
  observation to the separate authenticated finite-health observer, so the
  native healthcheck gives CP no cookie or raw-control authority.
  Demanding PROGRESS=100 goes beyond that job: the cookie + control
  listener exist LONG before bootstrap completes (tor writes the cookie
  at startup; bootstrap only builds circuits).
- **Fix (chosen):** keep the same Tor-native control probe but gate on
  `250 OK` from `AUTHENTICATE` (cookie
  present + control listener up), not PROGRESS=100. Runtime consumers
  needing full bootstrap (the tests) already poll for it with their own
  5-minute deadlines. Alternative (widening start-period to ~6 min)
  keeps the flake at a different threshold and delays every start; not
  chosen.
- **Residue:** none new — the probe channel and its failure modes are
  unchanged; only the grep target changes.

## Acceptance

1. With a fresh volume set and a deliberately slow/patchy Tor-network
   connection (or by temporarily narrowing the window), the supported
   `scripts/stargate init` brings up all four services: Tor reports healthy
   once its native control socket authenticates, without waiting for
   `PROGRESS=100`.
2. The Tor-native healthcheck still requires a valid cookie and control
   socket, while CP receives only the observer's authenticated finite token.
   Missing/invalid-cookie and delayed-bootstrap cases remain separate tests.
3. `bash scripts/verify.sh` GREEN (torrc structural contracts
   unaffected; the healthcheck lives in the Dockerfile, not the torrc).

### Required planning refinement


Re-ground the proposed healthcheck after T134/T138: readiness must prove the credential
and observation boundary actually selected, independently of full Tor bootstrap. Keep the
negative missing/invalid-credential case and delayed-bootstrap positive case as tests before
the change. Do not preserve direct CP cookie access merely to satisfy the historical wording.

## Out-of-scope

- T059's harness orchestration (pre-bootstraps tor on its own deadline
  until this lands — see stream_isolation_test.go bring-up comment).
- Any change to torrc itself or to the ControlPort exposure contract.

## Notes

Hand-filed by the T059 session (2026-09-07) per the surgical-changes
doctrine: the flake is real for every full-stack live test and operator
bring-up, but the healthcheck semantics belong to the sidecar owners.

T160 grounding (2026-09-12): two cold Tor 0.4.9.12 T058 runs exceeded their separate
five-minute descriptor-loading deadline; T032 bootstrapped in about 17 seconds. T161 owns
diagnosis and missing live-upgrade evidence. This does not establish that changing this
healthcheck's start-period or authentication criterion fixes those public-network failures.
