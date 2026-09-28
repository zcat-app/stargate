---
id: T180
title: 'Converge remaining tests/contract compose runners onto T121 helper'
status: done
created: 2026-09-28
last_updated: 2026-09-28
source: hand-filed (T121 convention) — T121 run round-2 reviewer RECOMMENDED-FOLLOW-UP + T121 §Notes follow-up promise
phase: "6: Polish & Cross-Cutting Concerns"
story: ''
blocked_by: []
parallel: true
files_budget: 4   # raw-diff-path counting (T116/T120 convention):
                  # network_hardening_test.go, control_port.go, this ticket,
                  # STATUS regen
privacy_critical: false   # plumbing only; no assertion, deadline, or transport change
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-012   # compose-internal transport contract the runner fronts
decision_refs:
  - "T121 (done, 4a75e15): hoisted the five §Context-enumerated suite runners into tests/contract/internal/compose; its §Notes routes this residue here and defers the tests/integration family"
  - "T121 round-2 review (both reviewers APPROVE) RECOMMENDED-FOLLOW-UP: migrate network_hardening_test.go (import needs an alias — the suite's own package is `compose`); converge control_port.go's private composeArgs onto internal/compose.Args"
reviews: { round: 1, date: 2026-09-28, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T180: Converge remaining tests/contract compose runners onto the T121 shared helper

## Context

T121 (4a75e15) hoisted the five §Context-enumerated docker-cadence suite
runners into `tests/contract/internal/compose` (`Args` + `Run`) but left two
same-shaped copies in `tests/contract`, both outside its filed scope:

1. `tests/contract/compose/network_hardening_test.go:127-130` — private
   `dockerCompose` baking const `stargate-t162-topology-test`
   (added 2026-07-17, 68989ac / T094b — PREDATES T121's filing; the §Context
   enumeration simply missed it, and T121's budget admitted exactly its five
   suites). Call sites: lines 40 (down), 44 (up), 47 (ps -q tor).
2. `tests/contract/tor/control_port.go:90-98` — private `composeArgs`
   building the identical argv prefix; its doc comment still cites
   "dockerCompose/liveDockerCompose in the sibling suites", both deleted by
   T121 (stale prose, Constitution V).

Both are mechanical migrations onto the landed helper. The import in (1)
needs an alias (e.g. `composecli`) because the suite's own package is
`compose`. (2) keeps the unexported `composeArgs` signature — callers
(ReadCookie, Connect, ulDialSocks in username_less_isolation_test.go) stay
byte-identical; only its body delegates to `compose.Args`.

## Analysis

*(Quick pass — non-privacy, low complexity, two-file mechanical migration.)*

## Acceptance

1. `network_hardening_test.go` issues its compose invocations through
   `tests/contract/internal/compose.Run` under an aliased import; the
   private `dockerCompose` is deleted; const `stargate-t162-topology-test`
   and every assertion/deadline are UNCHANGED (T121 acceptance #2's
   project-name rule carries over verbatim).
2. `control_port.go`'s `composeArgs` delegates to `compose.Args` — argv
   byte-identical for every existing caller — and its comment no longer
   references the deleted sibling runners.
3. `bash scripts/verify.sh` GREEN; at least one migrated suite exercised
   live (e.g. `cd tests/contract && go test -count=1 -tags=docker -v
   ./compose/ -run '^TestLocalTorRuntimeTopology$'`) with the transcript's
   decisive lines (RUN/PASS, not SKIP; empty `docker compose -p
   stargate-t162-topology-test ps -a` after teardown) cited in §Notes —
   the inspectable-evidence practice T121 round 1 established.

## Out-of-scope

- The `tests/integration` runner family (same_origin_shared_circuit,
  stack_smoke, stream_isolation, circuit_isolation_corpus, onion_load):
  separate Go module, cannot import `tests/contract/internal`; needs its
  own placement decision (hoist the helper home to `tests/internal/...`
  per the loginvariants replace-directive pattern, touching both consumer
  `go.mod`s and re-pointing the T121-migrated suites) — explicitly deferred
  to a future ticket, NOT bundled here.
- Moving the helper out of `tests/contract/internal/compose`.
- Any behavior, assertion, deadline, or compose project name change.

## Notes

Filed per the user's direction (2026-09-28 session): one cleanup ticket for
the two in-module items, integration-module convergence deferred. This
ticket backs T121 §Notes' "planned one-liner follow-up ticket" promise
(widened by item 2 per the reviewer recommendation; still one coherent
cleanup of same-shaped residue).

Live exercise (acceptance #3). The acceptance's "e.g." suite
(`TestLocalTorRuntimeTopology`) FAILS on the current tree for a reason that
predates this ticket: its health poll (`docker inspect -f
"{{.State.Health.Status}}"`) cannot succeed since T152 (046f2dd) disabled
Tor's Docker healthcheck — `sidecars/tor/Dockerfile:206` declares
`HEALTHCHECK NONE`, compose sets `healthcheck: disable: true`, and FR-012
now reads "Tor's Docker healthcheck is disabled" (T174 migrated the
live-e2e consumers of that metadata; this docker-tagged, opt-in suite was
outside its scope and so lingered red). Falsified as pre-existing: with
this ticket's two code diffs stashed, the pristine tree fails identically
(`network_hardening_test.go:106: Tor health inspect: ... map has no entry
for key "Health"`). Within that failing run the migrated runner itself is
proven correct for every invocation it owns: `up -d --build tor` created
the container in `stargate-t162-topology-test`, `ps -q tor` returned its
id, and pre-registered teardown left `docker compose -p
stargate-t162-topology-test ps -a` EMPTY (verified after both the migrated
and the pristine run). Repairing the poll is an assertion change
(§Out-of-scope #3) and a fifth diff path would breach files_budget=4, so
the fix is routed to a follow-up decision, not bundled here.

The live RUN/PASS evidence is migration (2)'s direct consumer suite,
`cd tests/contract && go test -count=1 -tags=docker -v ./tor/ -run
'^TestControlPortLive$' -timeout 20m` — every ReadCookie/Connect call in
it rides the migrated `composeArgs` → `compose.Args`:

    === RUN   TestControlPortLive
        OK: cookie (32 bytes) read from /var/lib/tor/control_auth_cookie and AUTHENTICATE accepted
        OK: bootstrapped: status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done
    --- PASS: TestControlPortLive (9.25s)
    PASS
    ok  github.com/zcat-app/stargate/tests/contract/tor 9.257s

with `docker compose -p stargate-t062-test ps -a` empty after teardown.
`bash scripts/verify.sh`: PASS=33, SKIP=2 (opt-in), FAIL=0 — GREEN.

Constitution check: plumbing refactor only — no privacy surface changes
(no assertion, deadline, or transport-behaviour edits), so Principle VII's
tests-first mandate is satisfied by the landed T121 argv-pinning tests
(`compose_test.go`) plus acceptance #3's live run; `privacy_critical`
stays false.
