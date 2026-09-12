---
id: T121
title: 'Hoist per-suite compose project runner into one shared helper'
status: pending
created: 2026-09-07
last_updated: "2026-09-12"
source: hand-filed (T120 convention)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: ["T058", "T139", "T134", "T138", "T156"]
parallel: true
files_budget: 4
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
consts through the hoist.

Constitution check: plumbing refactor only — no privacy surface changes (no
assertion, deadline, or transport-behaviour edits), so Principle VII's
tests-first mandate is unaffected and `privacy_critical` stays false. The
body's "IsolateSOCKSAuth" mentions name a tor directive, not an auth surface.
