---
id: T181
title: 'Replace topology suite Docker-health poll with authenticated probe'
status: pending
created: 2026-09-28
last_updated: "2026-09-28"
source: hand-filed (T180 convention) — discovery recorded in T180 §Notes (run 2026-09-28, commit 262b7be); user direction 2026-09-28 session (one ticket, no companions)
phase: "6: Polish & Cross-Cutting Concerns"
story: ''
blocked_by: []
parallel: true
files_budget: 3   # network_hardening_test.go + this ticket + STATUS regen
privacy_critical: true   # edits a sidecar-contract suite's observation channel (Constitution VII category);
                        # harness-only diff, but the channel choice is exactly what review must check
tests_first: []   # combined regression/fix ticket (T174 precedent): the suite's current live
                  # failure IS the red evidence; acceptance #4 pins red-before-green transcripts
test_for: []
constitution_refs:
  - "III: Privacy-Preserving by Construction"          # why the Docker-health signal is gone and must stay gone
  - "VII: Tests-First for Privacy-Critical and Contract Code"
complexity: low
risk: low
round_cap: 2
spec_refs:
  - specs/001-tor-route/spec.md#FR-012   # "Tor's Docker healthcheck is disabled" + compose-internal harness transport
decision_refs:
  - "T152 (046f2dd): removed Docker health metadata (Constitution III, no health-probe journal) — made the suite's {{.State.Health.Status}} poll unsatisfiable by construction"
  - "T174 (done): sanctioned the replacement observation shape — bounded authenticated current readiness over the compose-internal cookie channel (live-e2e observer migration)"
  - "T180 (done, 262b7be) §Notes: falsification record — pristine-tree identical failure, with/without-healthcheck mechanism probe, T160→T177 dead-pin build blocker, no recorded historical PASS anywhere in specs/"
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T181: Replace topology suite Docker-health poll with authenticated probe

## Context

`tests/contract/compose/network_hardening_test.go` (the T162 local-topology
suite, project `stargate-t162-topology-test`) ends in a readiness wait that
polls `docker inspect -f '{{.State.Health.Status}}'` (lines 105–118 at
262b7be, 5-minute deadline). T152 (046f2dd) removed Docker health metadata
everywhere — `sidecars/tor/Dockerfile` now declares `HEALTHCHECK NONE`,
compose sets `healthcheck: disable: true`, and FR-012 states "Tor's Docker
healthcheck is disabled" — so `State.Health` no longer exists and the poll
fails deterministically (`map has no entry for key "Health"`). The suite has
been red since 2026-09-22, invisible to every default gate because
docker-cadence suites are opt-in (`STARGATE_TEST_TAGS=docker`); T180's run
falsified the failure as pre-existing (pristine-tree rerun identical;
minimal with/without-healthcheck probe reproduces the exact error on this
daemon) and routed the repair here. Historical execution of the bracket is
impossible today (T160→T177 pinned tor 0.4.9.12, since removed from the apt
repo), so the attribution rests on the mechanism probe plus `git log -S`
uniqueness: only T014 (created HEALTHCHECK) and T152 (disabled it) ever
touched that state.

The fix swaps the readiness wait onto the observation channel T174
sanctioned for exactly this post-T152 world: a bounded authenticated
bootstrap probe over the compose-internal transport (control-port
`GETINFO status/bootstrap-phase` to `PROGRESS=100`, cookie-authenticated,
via the established helper shape — `tor.ReadCookie`/`Connect` from
control_port.go, or the live suites' equivalent exec probe). FR-012 remains
the transport contract; T152's removal stays fully intact.

## Analysis

- **Must hold** — readiness is established ONLY through the authenticated
  compose-internal control-port channel; no Docker health metadata is read,
  and no healthcheck is re-enabled at image, compose, or test-override
  level; every hardening assertion, the project const, and the skip guards
  are otherwise byte-identical; a failing probe fails the suite loudly (no
  silent pass, no SKIP-to-PASS substitution).
- **Gated** — `internal/compose/compose_test.go` pins the argv the probe's
  transport rides; `scripts/verify.sh` gates the hermetic tree; acceptance
  #4's live transcript gates the runtime behavior.
- **Residue** — channel-choice correctness (an implementer could
  accidentally resurrect health metadata or probe an unsanctioned surface):
  mapped to acceptance #1 and #2's post-run negative check; teardown
  hygiene: mapped to acceptance #4's empty `ps -a`.

## Acceptance

1. The readiness wait in `network_hardening_test.go` is replaced by a
   bounded authenticated bootstrap poll — control-port
   `GETINFO status/bootstrap-phase` until `PROGRESS=100`, cookie-authenticated
   over the compose-internal transport, reusing the established helper shape
   (`tor.ReadCookie`/`Connect`, or the live suites' equivalent exec probe) —
   carrying the suite's existing 5-minute deadline; the poll's failure paths
   fail the test with transport diagnostics, never pass silently.
2. Zero health-metadata resurrection: `sidecars/tor/Dockerfile` and
   `compose/docker-compose.local.yml` are untouched by the diff, and §Notes
   cites a post-run `docker image inspect stargate/tor:local --format
   '{{json .Config.Healthcheck}}'` still reporting `{"Test":["NONE"]}`.
3. Every hardening assertion (sole-egress network, zero published/exposed
   ports, readonly rootfs, cap_drop ALL, no-new-privileges, mem/pids limits,
   /tmp + /run tmpfs, forbidden mounts), the project const, and the skip
   guards are UNCHANGED — this is a transport swap for the readiness wait
   only.
4. Red-before-green cited in §Notes: the pre-fix failing transcript (the
   current `map has no entry for key "Health"` failure), then
   `cd tests/contract && go test -count=1 -tags=docker -v ./compose/ -run
   '^TestLocalTorRuntimeTopology$'` showing RUN/PASS (not SKIP), empty
   `docker compose -p stargate-t162-topology-test ps -a` after teardown, and
   `bash scripts/verify.sh` GREEN.

## Out-of-scope

- Re-enabling any Docker healthcheck or health journal anywhere (image,
  compose, or a test-only compose override) — that is the T152/Constitution
  III regression this ticket must not commit while repairing T152's residue.
- Touching any other suite, `tests/contract/internal/compose`,
  `control_port.go`'s protocol, production code, or the torrc contract.
- Bumping the tor package pin (T177 owns promotions).
- The systemic question "the opt-in docker-cadence family has no periodic
  green gate, so suites rot invisibly" — maintainer decision surfaced in
  §Notes, deliberately NOT bundled (user direction 2026-09-28: one ticket).

## Notes

Discovery and falsification evidence live in T180 §Notes (commit 262b7be):
pristine-tree identical failure; with/without-healthcheck mechanism probe
on the same daemon (`healthy` vs the byte-identical template error);
`git log -S` shows 046f2dd alone added compose `disable: true` and is one
of only two commits ever to touch the Dockerfile HEALTHCHECK; the T160→T177
dead pin blocked historical bracket execution. No recorded historical PASS
of this suite exists anywhere in specs/ — acceptance #4's transcript
becomes the first inspectable green on record.

Constitution check: Principle III is why the old poll cannot be "fixed" by
restoring its signal — the Docker-health journal was removed by design, and
the replacement must observe through the already-sanctioned authenticated
cookie channel, adding no new surface (acceptance #1/#2). Principle VII is
satisfied by the combined regression/fix shape (T174 precedent): the
suite's live failure is the red evidence, and acceptance #4 pins the
red-before-green transcripts plus the live PASS.

Systemic observation for the maintainer (explicitly not a ticket): three
consecutively scoped tickets (T121, T174, T180-as-filed) each assumed or
missed this suite, and nothing in the default gate executes the opt-in
docker-cadence family — without a periodic green gate the next suite rots
the same way.
