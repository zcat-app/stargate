---
id: T126
title: 'Pin DP UNAME forwarding: same target, distinct usernames, via 8881'
status: in-progress
created: 2026-09-07
last_updated: 2026-09-28
source: hand-filed (T120 convention; T059 round-1 review Finding 4 + RECOMMENDED-FOLLOW-UP)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: ["T059", "T125", "T139", "T123", "T124", "T132", "T136", "T156", "T157"]
parallel: false   # same test file family as T059; lands after it
files_budget: 4   # user-authorized amendment 3 → 4 (2026-09-28 run): the tests-first evidence regime
                  # postdates this ticket and mandates a staged evidence/T126-tests-first.json
                  # (T181 precedent); test + evidence + ticket + STATUS.md regen = 4
privacy_critical: true   # this is the actual FR-002 end-to-end isolation gate — the DP-side credential-fusion failure mode
complexity: low
risk: low
round_cap: 2
spec_refs:
   - specs/001-tor-route/spec.md#FR-002   # distinct first-party domains produce distinct circuits — the property the DP hop is load-bearing for
   - specs/001-tor-route/spec.md#FR-007   # DP forwards the inbound UNAME verbatim upstream (forward/tor.go dialUpstream)
   - specs/001-tor-route/contracts/socks5-auth.md   # UNAME/PASSWD mapping the test reproduces
   - specs/001-tor-route/tasks.md#T059   # harness this extends
decision_refs:
   - .specify/memory/constitution.md#Principle-VII   # tests-first: the DP's forwarding contract currently has no runtime gate through the DP
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T126: Pin DP UNAME forwarding: same target, distinct usernames, via 8881

## Context

Hand-filed from T059's round-1 review (2026-09-07). T059's honest-mechanism
note (live-captured) established that its two DISTINCT onion destinations
make distinct circuits overdetermined: rendezvous circuits are
destination-bound, so a DP regression that fused, dropped, or constant-
folded the upstream SOCKS5 username (`forward/tor.go dialUpstream`'s
FR-007 contract) would still see two distinct circuit IDs and pass T059.
T058/T058a pin the username-isolation axis at tor level but dial
`tor:9050` directly — they bypass the DP hop entirely. No runtime test
today drives SAME target / DIFFERENT inbound usernames THROUGH port 8881;
the DP's UNAME-forwarding contract is therefore unpinned end-to-end.

## Analysis

**Required** — `privacy_critical: true`. Property map per
`docs/process/analysis.md` (grounded 2026-09-28).

### Grounding facts (verified on disk)

- The DP forwards the inbound UNAME intact as the upstream username with an
  empty password (`data-plane/internal/forward/tor.go` `dialUpstream`); it
  does not parse or enforce the `sg1:` shape — any fusion/drop/fold would
  be a DP regression this test must catch.
- Post-T172/T173 the production UNAME is the `sg1:` partition
  (`contracts/foundation-boundaries.md`: HMAC-SHA-256 keyed by the bearer
  over `["stargate-isolation-v1", profileId, mode, cookieStoreId,
  typedSite]`). T059's UNAME = raw onion address predates this; T126 uses
  real partitions. Same target + distinct partitions is produced in
  production by distinct profile ids (or mode/container) — the test varies
  `profileId`.
- T059's control-port probe (`t059ControlProbe`) still dials TCP
  `127.0.0.1:9051`, which T162 replaced with `ControlSocket
  /var/lib/tor/control/tor-control.sock` (`sidecars/tor/torrc:6`). That
  probe is stale and NOT reusable live. T126 reads circuits through the
  landed T062 helper `tests/contract/tor` (Unix-socket aware), already a
  dependency of this module (T060's shape). T059's stale probe is outside
  this ticket's budget; flagged for a follow-up ticket.
- Only T059's pure/project-agnostic helpers are reusable in-package:
  `t059NewToken`, `t059ClassifyDialErr`, `t059FindRepoRoot`,
  `t059CountSuffix`, `t059TerminalStreamStates`. Its seed/compose/log-tail helpers bake
  `t059Project`, so T126 carries project-scoped equivalents (the T131
  precedent; `tests/contract/internal/compose` is internal to the
  contract module and not importable here).
- Two streams to one target cannot be attributed by target string; the
  assertion therefore counts exactly two live streams at the target and
  compares their circuit IDs (T060's machinery), which needs no attribution.
- Discrimination: T060 live-pinned that tor consolidates SAME-credential
  concurrent streams to the same onion onto one circuit. A fusing DP
  reproduces exactly that input, so the test re-runs it through the DP as
  an in-suite control — without it a green result could mean "tor happened
  to build two rendezvous circuits", not "the DP kept credentials apart".

### Must hold

1. Two parallel authenticated CONNECTs through `127.0.0.1:8881` to the SAME
   real onion, with two DISTINCT complete `sg1:` partition usernames and the
   seeded bearer, attach to two distinct, non-zero circuits, each BUILT in
   `GETINFO circuit-status` (FR-002 / FR-007 end-to-end through the DP).
2. Calibration control: two parallel CONNECTs through 8881 with the SAME
   partition to the same target share one circuit — proves the harness can
   observe the credential-fusion failure mode it claims to catch.
3. Fatal paths carry T059's classification (AUTH/ROUTE) plus bounded DP and
   tor log tails; tor tail is SafeLogging-scrubbed.
4. Bearer token never in argv/source/logs (stdin seed; PASSWD only on the DP
   wire; DP sends empty upstream password).
5. Harness hygiene: own compose project, cleanup-before-up, signal-safe
   teardown, bounded per-phase deadlines under the suite context.
6. Hermetic PR gate: file compiles/vets; live body env-skips; the partition
   helper is pinned to the foundation-boundaries reference vector hermetically.

### Gated

- #6 by `scripts/verify.sh` go-workspace gate (compile, vet, hermetic
  reference-vector test).
- DP UNAME-verbatim byte shape by T047's hermetic
  `TestForwardPassesUNAMEVerbatimAsUpstreamUsername` (unit level only).

### Residue

- #1/#2 run only live (release cadence, operator key-provisioning
  prerequisite as T059/T131); a PR-cadence regression in DP forwarding is
  caught hermetically by T047 but end-to-end only at release run.
- An injective DP transform of the UNAME (not verbatim, but still distinct)
  passes this test; verbatim-ness is T047's gate, not this one's.
- Tor-behaviour dependence: if a future tor stops consolidating
  same-credential streams, control #2 fails loudly (uncalibrated), never a
  false green.

### Original quick-pass notes

- Shape: two parallel CONNECTs through 8881 to the SAME real onion
  (the spec-pinned DuckDuckGo reference) with two different first-party
  UNAMEs and the seeded PASSWD; assert the two streams land on distinct
  non-zero circuit IDs, both BUILT. A credential-fusing DP sends one
  upstream credential twice → tor's IsolateSOCKSAuth attaches both
  streams to one circuit → the assertion fails (positive control: T058
  already proved the tor-side mechanism with this exact shape).
- Real target required (stream-level attribution; T059 §Analysis).
- The transport/probe/seed/forensics machinery is T059's, reused; only
  the dial matrix (same target, distinct UNAMEs) is new.

## Acceptance

1. Named test in `tests/integration/` (e.g.
   `stream_isolation_dp_uname_test.go`) asserting the same-target /
   distinct-UNAME pair through 8881 lands on distinct, non-zero, BUILT
   circuits — with T059's classification + log-tail forensics on the
   fatal path.
2. Runnable live (T059 acceptance item 2's cadence + prerequisites).
3. `bash scripts/verify.sh` green (hermetic compile/vet; env-skip).

## Out-of-scope

- T059's distinct-destination scenario (complementary, already filed).
- Any production-code change — this is a verification-surface ticket.

## Notes

Hand-filed by the T059 session per the review follow-up; deliberately
NOT folded into T059 (its diff is under must-shrink on round 2, and the
two scenarios exercise different DP failure modes).

### Tests-first evidence (disposable host/VM)

User decision 2026-09-28: the test is authored and hermetically green on
the workstation, and the live red/green record is captured on the disposable
VM (the live-e2e approved host), since the current Local topology needs the
`stargate-dp` AppArmor profile, owner rules and init provisioning. Probe
command (identical for red and green):

    bash -c 'cd tests/integration && STARGATE_RUN_NETWORK_TESTS=1 go test -count=1 -run TestStreamIsolationDPUNAMEForwarding -v -timeout 50m'

- **red**: test staged plus a temporary DP mutation in
  `data-plane/internal/forward/tor.go` `dialUpstream` that sends one constant
  upstream username (credential fusion). Expected failure: the
  `DistinctPartitionsSameTargetDiverge` shared-circuit assertion.
- **green**: mutation reverted, test only. Both subtests pass.

Executed 2026-09-28 on a copy of the saved T132 enforcing Ubuntu VM
(`guest-t126.qcow2`, QEMU TCG, 4 vCPU, 6 GiB; kernel `6.8.0-139-generic`;
`stargate-dp (enforce)`, IPv4/IPv6 owner rules, synthetic keys and pepper
provisioned per `target/runs/T132-vm/provision.sh` for this project). The
probe `bash target/runs/T126-vm/live.sh` (gitignored wrapper) transfers the
tracked snapshot, compiles the harness natively with the guest source path
mapped (T132 procedure) and runs
`^(TestStreamIsolationDPUNAMEForwarding|TestT126.*)$` live; images were
rebuilt from the transferred tree.

Round 1 (superseded by the round-2 re-capture below): red exit 1, the
distinct partitions shared circuit 29; green exit 0, circuits 28 / 31, with
calibration sharing circuit 34.

Round 2 (superseded): red exit 1, the distinct partitions shared circuit
18, and the DP and tor tails reported the disabled logging driver; green exit
0, circuits 21 / 13, with calibration sharing circuit 23.

Round 3 re-capture after the refine: `TestT126SignalTrapReleasedAfterStop`
now exercises real signals only in a re-executed child process
(`STARGATE_T126_SIGNAL_CHILD`), and a parent sentinel asserts the parent
receives none. Local falsification on 2026-09-28:
- A no-op `stop` fails `StoppedTrapIgnoresLaterSignal`.
- A temporary sibling-style leaked `os.Exit` SIGTERM handler, registered
  earlier in the same binary, kills the round-2 in-process test
  (`SIBLING-HANDLER-EXIT`, binary exit 1). The round-3 test passes with
  that handler present.

Round-2 fixes carried over, each also falsified locally: per-operation
control deadlines, where an undeadlined `t126Op` hangs
`TestT126ControlPhaseDeadlines` until the go-test timeout; and forensics on
every live fatal path.

- red (exit 1, 275.31 s): `DistinctPartitionsSameTargetDiverge` FAILED with
  `ISOLATION: … shared circuit 22 through 127.0.0.1:8881`, followed by the
  DP and tor log-tail sections. Local's production log suppression means
  Docker reports the logging driver cannot be read. Calibration and all
  hermetic T126 tests passed.
- green (exit 0, 280.61 s): distinct partitions → circuits 15 / 22, both
  BUILT; calibration: the same partition shared circuit 24. All PASS.

Full outputs and snapshot hashes: `evidence/T126-tests-first.json`.
Follow-up to file: T182 — T059/T033 harnesses still dial TCP 9051 and send
raw-onion usernames. The ticket is drafted and lands in the post-commit
`docs:` update, not in this candidate.

### Escalation record — round 2 (refine, user-authorized round 3)

Round 2: GLM APPROVE; Astra ESCALATE [Major]. `TestT126SignalTrapReleasedAfterStop`
self-signalled the shared `go test` process. Under `-tags docker` the
sibling suites' retained SIGTERM handlers (`stack_smoke_test.go`,
`same_origin_shared_circuit_test.go`, `circuit_isolation_corpus_test.go`)
would run their teardown and `os.Exit(1)` mid-run. The user authorized a
refine on 2026-09-28 for exactly ONE further review round ("round 3"). The
documented refine path resets the driver's round counter (`--reset`), and
`round_cap` stays 2 because the lint caps 3 at high complexity/risk. A
failing round 3 therefore stops for the user; it does not use a fourth round. The refined must-hold:
the real-signal regression runs in an isolated child process, and the
parent test process never receives a synthetic signal. Acceptance is
unchanged.

## T172 Tor ingress consumer constraint

The two same-target CONNECTs are authenticated SOCKS5 CONNECT commands with distinct complete `sg1:` partition usernames, not HTTP requests. Preserve the actual circuit-ID and credential-fusion controls; T173 is transitively required through T132.
