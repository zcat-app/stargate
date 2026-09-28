---
id: T181
title: 'Replace topology suite Docker-health poll with authenticated probe'
status: done
created: 2026-09-28
last_updated: 2026-09-28
source: hand-filed (T180 convention) — discovery recorded in T180 §Notes (run 2026-09-28, commit 262b7be); user direction 2026-09-28 session (one ticket, no companions)
phase: "6: Polish & Cross-Cutting Concerns"
story: ''
blocked_by: []
parallel: true
files_budget: 4   # maintainer-authorized bump 3→4 (2026-09-28 session):
                   # the T144 evidence regime (2026-09-25) postdates this ticket's
                   # T174 transcript convention and mandates a staged
                   # evidence/T181-tests-first.json raw-diff path
privacy_critical: true   # edits a sidecar-contract suite's observation channel (Constitution VII category);
                         # harness-only diff, but the channel choice is exactly what review must check
tests_first: []   # combined regression/fix ticket (T174 precedent): the suite's current live
                  # failure IS the red evidence; acceptance #4 pins red-before-green transcripts.
                  # The T144 regime additionally requires the named regression to be authored
                  # within this ticket and recorded red/green: TestReadinessChannelContract
                  # (in-file source-contract pin, no extra diff path) + the driver-mandated
                  # evidence/T181-tests-first.json
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
reviews: { round: 1, date: 2026-09-28, verdict: APPROVE }
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
5. Transport-level deadline evidence (refine 2026-09-28, attempt-1 Astra
   round-2 finding): hermetic regressions drive the REAL `torBootstrapProbe`
   (not an injected stand-in) through `waitForTorBootstrap` over a
   controlled executable transport that stalls separately at cookie
   retrieval, the AUTHENTICATE reply and the GETINFO reply; each case fails
   within the shortened readiness deadline plus a stated cleanup allowance,
   and its error names the stalled phase. A positive control proves the
   same transport reaches PROGRESS=100 when nothing stalls. §Notes cites a
   mutation run showing that disconnecting the probe's transport calls from
   the supplied context makes the stall cases fail.

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

## Execution evidence (2026-09-28)

Baseline 2fb5daf (HEAD throughout; no intermediate commits). Red/green
record: `specs/001-tor-route/evidence/T181-tests-first.json`.

- Pristine pre-fix red transcript (acceptance #4; preserved gitignored at
  `target/runs/T181/suite-red.log`):
  `network_hardening_test.go:109: Tor health inspect: exit status 1:
  template parsing error: template: :1:8: executing "" at
  <.State.Health.Status>: map has no entry for key "Health"` →
  `--- FAIL: TestLocalTorRuntimeTopology (1.67s)`; teardown already left
  `docker compose -p stargate-t162-topology-test ps -a` empty.
- Named regression (T144 regime for `tests_first: []`):
  `TestReadinessChannelContract`, authored within this ticket — a
  source-contract pin (torrc byte-golden / compose argv-pin family) on the
  suite's readiness channel: no Docker health metadata read, authenticated
  bootstrap probe present. Needles are assembled at runtime so the
  contract's own source cannot satisfy or violate itself. Red (staged
  test-only diff) failed with the named property; the same probe command
  also records the suite's pre-fix `map has no entry for key "Health"`
  failure in the red output.
- Green probe (identical command, evidence record):
  `bash -lc "cd tests/contract && go test -count=1 -tags=docker -v ./compose/"`
  → `=== RUN TestLocalTorRuntimeTopology` / `--- PASS:
  TestLocalTorRuntimeTopology (12.94s)` and `--- PASS:
  TestReadinessChannelContract (0.00s)` — RUN/PASS, not SKIP.
- Teardown hygiene (acceptance #4): `docker compose -p
  stargate-t162-topology-test ps -a` empty (header only) after the green
  run.
- Acceptance #2 negative check, post-run: `docker image inspect
  stargate/tor:local --format '{{json .Config.Healthcheck}}'` →
  `{"Test":["NONE"]}`; `sidecars/tor/Dockerfile` and
  `compose/docker-compose.local.yml` carry no diff.
- `bash scripts/verify.sh`: PASS=33, SKIP=2 (opt-in), FAIL=0 — GREEN.
- Replacement semantics: single unchanged 5-minute deadline covering
  session establishment and PROGRESS=100; one fresh control-port session
  per attempt (ControlPort discard-after-error rule); deadline expiry
  fails loudly with the last observed phase and the last transport error.
- Maintainer authorizations (2026-09-28 session): files_budget 3→4 for
  the driver-mandated evidence JSON; keep the in-file named regression.

### Round 2 (Astra REWORK findings, both fixed)

Round-1 verdicts: GLM APPROVE; Astra REWORK with two Major findings,
both confirmed real and repaired:

- Finding 1 (deadline not enforced across blocking calls): the round-1
  wait checked the deadline only between attempts, so a stalled control
  session blocked under the suite's 8-minute ctx past the 5-minute
  readiness deadline, and a reply arriving after the deadline could still
  become success. Fixed: the wait is extracted into `waitForTorBootstrap`,
  which caps every attempt at the remaining readiness window
  (per-attempt `context.WithTimeout`), rejects success landed after the
  deadline, and aborts on parent cancellation — all failure paths carry
  the last phase + last transport error. New hermetic regression
  `TestBootstrapDeadlineEnforcement` (injected probe, no Docker):
  stalled transport is cut AT the deadline (300ms deadline, fails within
  1s bound; red against the naive round-1 logic took 10.03s under the
  parent ctx — transcript preserved gitignored at
  `target/runs/T181/deadline-red-naive.log`), and a late bootstrap reply
  is rejected (red under naive logic: accepted as success).
- Finding 2 (positive needle self-match via the diagnostic; recorded red
  partly self-inflicted): the round-1 contract's error message contained
  the literal `GETINFO status/bootstrap-phase`, so removing the actual
  probe command left the assertion passing; and the round-1 red patch's
  needles were literals, failing on their own source. Fixed: the
  diagnostic interpolates the runtime-assembled needle (the literal now
  exists ONLY in the production probe call); both needles
  mutation-verified — swapping the production command for
  `GETINFO version` fails the contract, and re-adding a
  `{{.State.Health.Status}}` poll fails it.
- Corrected evidence: the round-1 record is preserved verbatim
  (gitignored) at `target/runs/T181/superseded-r1-tests-first.json` — its
  green live PASS remains valid evidence, its named-regression red was
  self-matched. The tracked `evidence/T181-tests-first.json` was
  re-recorded with the FINAL tests against a worktree reverted to the
  base production poll: red (exit 1) = contract fails on the production
  `State.Health` poll itself + the suite's `map has no entry for
  key "Health"` failure; identical-command green (exit 0) = all four
  tests RUN/PASS — `TestLocalTorRuntimeTopology (12.17s)`,
  `TestReadinessChannelContract`,
  `TestBootstrapDeadlineEnforcement` (stall cut at 0.32s, late success
  rejected).
- Post-green checks re-run: `docker compose -p stargate-t162-topology-test
  ps -a` empty; `docker image inspect stargate/tor:local --format
  '{{json .Config.Healthcheck}}'` → `{"Test":["NONE"]}`;
  `bash scripts/verify.sh` PASS=33, SKIP=2, FAIL=0 — GREEN.

### Escalation resolution: refine (2026-09-28)

Attempt-1 round 2 split: GLM APPROVE; Astra ESCALATE at the round cap with
one Major coverage finding — the deadline regression replaced the whole
transport, so removing context propagation inside `torBootstrapProbe`
would leave it passing. The maintainer selected `refine` ("round 3 fixes
of round 2"): acceptance #5 makes that finding independently falsifiable;
no finding is overridden and no requirement is relaxed. Attempt-1
candidate patches, both verdict rounds, the reviewer set and the verify
log are preserved (gitignored) under `target/runs/T181-attempt-1/` before
`run-task.sh --reset`. The ticket resumes `in-progress` with its staged
candidate and baseline 2fb5daf intact — restarting from `pending` would
re-enter START, whose clean-tree guard refuses the staged candidate.

### Attempt 2 execution evidence (acceptance #5)

- New hermetic regression `TestBootstrapProbeTransportDeadline`: a fake
  `docker` executable shadows PATH and serves the helper's two real exec
  shapes (`compose exec -T tor cat <cookie>` / `... nc -U <socket>`), so
  the REAL `torBootstrapProbe` runs `ReadCookie` → `Connect` →
  `Authenticate` → `Command` → `Close` through `waitForTorBootstrap`.
  Stalls `exec` into a 10s sleep (the killed process owns the pipes).
  Readiness window 500ms; stated bound 2s (window + 1.5s cleanup
  allowance). Results: PositiveControl reaches PROGRESS=100 (0.01s);
  Stall_cookie / Stall_auth / Stall_getinfo each fail in 0.55s, with
  errors naming `read control cookie` / `authenticate:` / `control port
  closed mid-reply` (getinfo case asserts NOT `authenticate:`).
- Mutation falsification (transcript gitignored at
  `target/runs/T181/transport-mutation-red.log`): detaching
  `tor.ReadCookie` from the supplied ctx fails Stall_cookie only (10.05s);
  detaching `tor.Connect` fails Stall_auth and Stall_getinfo (10.06s
  each); detaching both fails all three stall cases. PositiveControl
  passes under every mutation — the stall cases fail for their stall.
- Tests-first evidence re-recorded (tracked JSON), same shape as attempt 1:
  red = final tests against the baseline production `State.Health` poll →
  exit 1 (suite `map has no entry for key "Health"` + contract failure);
  identical-command green → exit 0, all tests RUN/PASS —
  `TestLocalTorRuntimeTopology (184.64s)` (within the 5-minute window;
  attempt 1 recorded 12.17s — this run rebuilt/bootstrapped cold),
  `TestReadinessChannelContract`, `TestBootstrapDeadlineEnforcement`,
  `TestBootstrapProbeTransportDeadline`.
- Post-green: `docker compose -p stargate-t162-topology-test ps -a`
  empty; `docker image inspect stargate/tor:local --format
  '{{json .Config.Healthcheck}}'` → `{"Test":["NONE"]}`; no diff under
  `sidecars/` or `compose/`.
