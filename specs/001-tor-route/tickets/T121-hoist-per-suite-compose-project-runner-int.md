---
id: T121
title: 'Hoist per-suite compose project runner into one shared helper'
status: in-progress
created: 2026-09-07
last_updated: 2026-09-28
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: ["T058", "T139", "T134", "T138", "T156"]
parallel: true
files_budget: 9   # amended 4 → 9 (user-authorized amendment, 2026-09-27 run):
                  # acceptance #1 itself requires the five suite files (named in
                  # §Context) + the new shared helper AND its tests-first
                  # compose_test.go + this ticket + the driver's STATUS.md regen
                  # (T120 counting convention) = 9 raw diff paths. 4 was infeasible
                  # as filed (T094a/T120 budget-amendment precedent, not scope creep)
privacy_critical: false   # plumbing only; body's "auth" hit is IsolateSOCKSAuth (a tor directive name), not an auth surface
complexity: low
risk: low
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md#FR-012   # compose-internal transport contract the runners share
decision_refs: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T121: Hoist per-suite compose project runner into one shared parameterized helper

## Context

Hand-filed from T058a's round-1 codereview RECOMMENDED-FOLLOW-UP (2026-09-07).
Every docker-cadence contract suite bakes its own compose project const into a
private `dockerCompose`/`cpCompose`/`ulCompose` runner — T019b
(`stargate-t019b-test`), T032 (`stargate-t032-test`), T062
(`stargate-t062-test`), T058 (its own), T058a (`stargate-t058a-test`). The
duplication is deliberate so far (each suite must never share a compose
project: T058a §Notes #1 records the live failure where reusing a sibling's
runner pointed `up` at the sibling's project while the exec transports used
its own), and the precedent notes in each file say the same thing: "a future
hoist can parameterize the project across all suites."

With a fourth-plus suite landed, the hoist is worth one ticket: a single
shared runner (unexported, in `tests/contract/tor/` or a small internal
package both `tor/` and `torrc/` modules can reach — mind that `tests/contract`
is one module, so an in-module helper works) taking `(project, composeFile,
envFile, args...)`, with each suite keeping its own project CONST but dropping
its private runner copy.

## Analysis

*(Quick pass — non-privacy, low complexity.)*

## Acceptance

1. One shared compose-runner helper exists; the private per-suite runners in
   the docker-cadence suites are deleted in favor of calls passing their own
   project const.
2. Every suite's compose project name is UNCHANGED (cross-suite isolation is
   the property that motivated the duplication; a rename could collide with
   operator state or parallel CI runs).
3. `bash scripts/verify.sh` GREEN; at least one docker-cadence suite exercised
   live (`STARGATE_TEST_TAGS=docker scripts/verify.sh` or the suite's manual
   command) to prove the hoisted runner still names the right project.

## Out-of-scope

- Changing any suite's assertions, deadlines, or compose project names.
- Making verify.sh log writes concurrency-safe (that is T120).
- Any control-port helper (T062) behaviour change.

## Notes

Derived by hand 2026-09-07 from T058a round-1 review follow-up; see T058a
§Notes #1 for the live failure that justifies keeping per-suite project
consts through the hoist. Grounding note (2026-09-27): port_exposure's
project const is now `stargate-t162-socket-test` (T162's amendment);
acceptance #2 pins whatever name is on disk, so the hoist carries it
verbatim. `files_budget` amended 4 → 9 at run start (user-authorized):
acceptance #1 mandates five suite edits + helper + helper test + ticket,
plus the driver's STATUS regen.

Live exercise (acceptance #3, round-1 REWORK remediation — the original
run passed but its transcript lived only outside the review scope).
Round-2 re-run, candidate-bound, `go test -count=1 -tags=docker -v`:

    cd tests/contract && go test -count=1 -tags=docker -v ./tor \
      -run '^TestTorSocketCallerMatrix$'
    === RUN   TestTorSocketCallerMatrix
    --- PASS: TestTorSocketCallerMatrix (15.72s)
    PASS
    ok  github.com/zcat-app/stargate/tests/contract/tor 15.724s

The suite EXECUTED (not SKIP: it brings up tor under
`stargate-t162-socket-test` via the hoisted runner, resolves the
compose-labeled volumes, probes all six caller-matrix cells, restarts
tor and re-probes, then tears down — `docker compose -p
stargate-t162-socket-test ps -a` is empty after, proving every
subcommand named this suite's own project through compose.Run).

Follow-up observation (2026-09-27 grounding): `tests/contract/compose/
network_hardening_test.go` carries the same private-runner pattern
(`dockerCompose`, const `stargate-t162-topology-test`) and PREDATES this
filing (added 2026-07-17, 68989ac / T094b) — the §Context enumeration
simply missed it. Acceptance #1 is satisfied against §Context's
enumerated scope (the five suites; the authorized files_budget=9 admits
exactly those five + helper + helper test + ticket + STATUS — a sixth
suite edit would itself have breached the budget); the residue is routed
to the planned one-liner follow-up ticket.

Constitution check: plumbing refactor only — no privacy surface changes (no
assertion, deadline, or transport-behaviour edits), so Principle VII's
tests-first mandate is unaffected and `privacy_critical` stays false. The
body's "IsolateSOCKSAuth" mentions name a tor directive, not an auth surface.
