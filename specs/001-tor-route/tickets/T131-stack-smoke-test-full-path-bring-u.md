---
id: T131
title: 'Stack smoke test: full-path bring-up acceptance (RED until T130)'
status: done
created: 2026-09-07
last_updated: 2026-09-07
source: hand-filed (T120 convention; root-cause audit of the T059 cascade)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'   # serves every story; filed under US2 only because T059's cascade spawned it
blocked_by: [T122, T125, T129]   # the stack must be bootable for the smoke test to be meaningful; it is RED on T130 by design
parallel: false   # the stack-bring-up acceptance; single owner while the T123/T124/T130 consolidation runs behind it
files_budget: 3
privacy_critical: true   # it is the runtime gate for the full authenticated path: FR-006 token flow + FR-007 forwarding + FR-005 exposure, end to end
complexity: low
risk: low
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md#FR-005   # host loopback 8881 reachable — the exposure contract
   - specs/001-tor-route/spec.md#FR-006   # bearer-token authentication through the full vertical
   - specs/001-tor-route/spec.md#FR-007   # DP→tor:9050 SOCKS5h forwarding
   - specs/001-tor-route/spec.md §"User Story 1"   # the load-the-onion shape this smoke-minimises (T033's cadence problem, fixed)
decision_refs:
   - .specify/memory/constitution.md#Principle-VII   # tests-first applied to the STACK: the acceptance exists before the fixes that must turn it green
reviews: { round: 2, date: 2026-09-07, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T131: Stack smoke test: full-path bring-up acceptance (RED until T130)

## Context

Hand-filed from the root-cause audit of the T059 cascade (2026-09-07):
the full local-profile stack — DP + CP + tor with the inter-plane
channel up — had **never been executed once** before T059's live phase.
Every layer T122–T130 surfaced was a never-integrated assumption, and
each per-defect fix was validated against its own symptom layer, not the
full path (T125 round 1 was reviewed, approved, landed, and falsified 49
minutes later). This test is the structural cure: **one executable,
full-path acceptance** that every subsequent stack fix runs against —
Constitution Principle VII applied to the stack itself. It is the
docker-cadence gate T033 should have been (T033 exists but is
release-tag-gated, needs two live onions, and has never run).

## Analysis

*(Quick pass — the test is deliberately minimal; its VALUE is the path it
covers, not its assertion count.)*

- **Shape**: bring up the stack under this suite's own compose project
  (two-phase per the T059-landed compensation: tor bootstrapped first,
  then the planes — T124's product fix will obsolete the phase split);
  seed the run token (the T059-landed seed step); issue ONE authenticated
  SOCKS5 CONNECT through `127.0.0.1:8881` to the spec-pinned reference
  onion; assert the tunnel carries ≥1 application byte. Green means:
  images build (T122), host publish reachable (T125), CP boots (T129),
  inter-plane channel up + token generation pushed (T130 — open),
  DP-side auth + SOCKS5h forwarding to tor working, onion rendezvous
  completing. One assertion, the whole pyramid above it.
- **RED is the designed state**: T130 is open; the smoke test's AUTH
  failure IS its current expected output. It lands RED-at-live-cadence /
  green-hermetic, exactly like a test-first red for an unfixed product
  bug. The T123/T124/T130 fixes' live validation = this test flipping
  green, not per-ticket symptom probes.
- **Reuse vs duplicate**: same Go package as T059
  (`tests/integration`, one module) — reuses the project-agnostic pieces
  (token generation) and duplicates the project-bound runners/seed with
  `t131` prefixes. Each suite MUST own its compose project (T058a's
  live-found split-project failure); the shared-runner hoist is T121
  (open) and is the sanctioned place to deduplicate.
- **Operator prerequisite** rides T059's documented §Residue
  (init-equivalent keys/pepper/volume-roots for the project's volumes) —
  same prerequisite, same release/docker-cadence runbook.

## Acceptance

1. **Named test** `TestStackSmoke` in
   `tests/integration/stack_smoke_test.go` (build-tagged `docker`,
   daemon/CLI skip guards): two-phase bring-up under project
   `stargate-t131-test`; token seeded per the T059 seed step; ONE
   authenticated SOCKS5 CONNECT (UNAME = first-party domain, PASSWD =
   seeded token) through `127.0.0.1:8881` to
   `duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:443`;
   asserts the tunnel is established (REP=0) and carries ≥1 byte of
   application data; failure output carries the T059-style classification
   (AUTH vs ROUTE) + DP/CP log tails.
2. **Runnable (docker-cadence):** `cd tests/integration && go test -tags docker -run TestStackSmoke -v -timeout 35m` — RED while T130 is open (auth-rejected, classified), GREEN when the full path works. Hermetic `go vet` (untagged compile) green via verify.sh.
3. `bash scripts/verify.sh` GREEN (compile/vet only; the live body is tag-gated out).

## Out-of-scope

- Any product fix (T130 owns the channel; T123/T124 own their product
  sides — all validate AGAINST this test, none inside it).
- Isolation assertions (T059/T126 own those) — the smoke test asserts the
  path works once, not how streams separate.
- The shared-runner hoist (T121) and the harness-compensation deletions
  (they land with the product fixes that obsolete them).
