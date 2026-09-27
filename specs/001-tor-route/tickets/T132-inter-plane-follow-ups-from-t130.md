---
id: T132
title: 'Inter-plane follow-ups from T130 (re-push, ALPN pins, fakecp ALPN)'
status: done
created: 2026-09-07
last_updated: 2026-09-27
source: hand-filed (T120 convention; T130 rounds 1–2 review follow-ups + audit plan)
phase: "4: User Story 2 — Stream isolation per first-party domain (Priority: P2)"
story: 'US2'
blocked_by: ["T130", "T139", "T135", "T137", "T148", "T156", "T159", "T172", "T173", "T178"]
parallel: false
files_budget: 7
privacy_critical: true   # re-push semantics touch the auth-generation delivery path
complexity: medium
risk: medium
round_cap: 2
spec_refs:
   - specs/001-tor-route/contracts/control-grpc.md §"ReloadTokens"
   - specs/001-tor-route/contracts/control-grpc.md §"Plane-down survival"
   - specs/001-tor-route/contracts/wire-auth.md §4   # the ALPN invariant (as amended by T130)
decision_refs: []
reviews: { round: 2, date: 2026-09-27, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check:
  analyzed_at: 2026-09-07
  verdict: PASS
---

# T132: Inter-plane follow-ups from T130 (re-push, ALPN pins, fakecp ALPN)

## Context

Three follow-ups the T130 review identified as out-of-diff (deliberately
not expanded into T130's rounds), plus one semantics gap observed live.
Filed as ONE ticket to avoid follow-up sprawl; each bullet is small and
all sit on the same surface.

1. **DP-restart recovery.** T159 subsequently specified and implemented
   exact-generation re-delivery after a peer-side disconnect on the
   authenticated ReloadTokens channel. Its real Java/Go IPC test proves
   that a running CP reseeds a restarted DP after its snapshot is lost.
   This ticket adds the missing authenticated SOCKS consumer probe. The
   WatchEvents stream remains advisory and is not an auth-delivery trigger.
2. **Java-side ALPN is satisfied only by library default.** wire-auth §4
   (as amended) demands exactly `["h2"]` on every TLS endpoint; CpTls
   relies on GrpcSslContexts' default application-protocol config rather
   than an explicit list. Pin it explicitly (comment + code) so a
   grpc-java upgrade changing defaults cannot silently drop h2.
3. **fakecp.StartTLS offers no ALPN h2.** The Go fake CP's TLS server
   does not set NextProtos — Go↔Go tolerates it (both sides skip ALPN),
   which is exactly the mutually-underspecified shape that hid T130's
   ALPN half. Give the fake the `["h2"]` shape so the test tier mirrors
   the Java peer's strictness.

## Analysis

- **Must hold:** a DP restarted without a valid snapshot denies admission
  until the running CP re-delivers its exact current generation; lower or
  conflicting generations never replace authority. A CP outage leaves the
  last valid DP generation serving authenticated SOCKS requests (Principle
  II). Both CP TLS roles and the fake CP offer only ALPN h2 (wire-auth §4).
- **Gated:** T159's Java/Go IPC tests cover peer-restart delivery, stale
  replay, and local channel retirement. The T132 live probe covers SOCKS5
  admission after DP-only restart; `TestT131PartitionUsernameReferenceVector`
  pins its complete SOCKS username to foundation-boundaries.md's independent
  vector; the fake-CP transport regression covers h2 negotiation. `verify.sh`
  covers Java/Go tests and contract tests.
- **Residue:** Docker and Tor availability determine whether the live probe
  executes in this run; a green hermetic gate alone does not prove it. The
  restarted DP must have its snapshot removed so the probe cannot pass by
  merely restoring local state. TLS library defaults can mask missing
  explicit protocol pins; review checks both CP builder call sites.

## Acceptance

1. T159's reviewed `ReloadTokens` contract and real Java/Go IPC regression
   govern exact-generation re-delivery on an authenticated peer reconnect.
   Add and pass a T131-sibling integration probe: stop only the DP, remove
   its snapshot, restart it with the CP still running, then authenticate and
   forward through SOCKS5 CONNECT using a complete partition username.
   `TestT131PartitionUsernameReferenceVector` must match the independent
   foundation-boundaries.md vector.
   Update the pre-existing T131 bootstrap fixture to query the private
   ControlSocket specified by T162, so the probe can reach this assertion.
   Allow the same bounded ten-minute cold-CP setup used by the T173 VM
   fixture; retain three-minute recovery and individual wire/read deadlines.
   A stale generation cannot be promoted; CP outage must preserve valid DP
   admission. HTTP first byte `C` remains silently refused.
2. Bullet 2: CpTls sets the h2 application protocol explicitly; a
   comment cites wire-auth §4.
3. Bullet 3: fakecp's TLS server offers exactly ["h2"]; the control-grpc
   suite stays green.
4. `bash scripts/verify.sh` GREEN.

### Required planning refinement


T159 already specified and tested cold snapshot delivery, generation monotonicity,
revocation, CP outage and reconnect. Its contract replays exact current
authority only on an authenticated ReloadTokens peer-reconnect edge, not on
WatchEvents stream establishment. This ticket adds the missing SOCKS consumer
probe and explicit h2 pins. No accepted residue or policy waiver is claimed.

## Out-of-scope

- T130's landed fix (this rides on it, does not revisit it).
- The T123/T124 product fixes (separate, behind the T131 smoke test).
- No change to T131's successful SOCKS/application-byte assertion. Its
  bootstrap helper follows T162's private ControlSocket instead of the
  retired TCP control port. Cold-CP setup allows T173's ten-minute VM budget;
  the new restart subtest retains its three-minute admission window.

T147 migration dependency: T172 reconciles HTTP CONNECT contracts and consumer acceptance;
T173 implements refusal with preserved authenticated SOCKS coverage and deployed evidence.
Both must complete before this consumer runs; T147 planning completion alone is insufficient.

The candidate's seven paths include the driver-generated STATUS board, this
ticket, the tests-first record, both ALPN source pins, the fake-CP ALPN
regression, and the T131-sibling live recovery probe. T178 was filed and
delivered separately for the newly observed initial token-load failure,
following AGENTS.md's out-of-scope-defect rule. The maintainer authorized
the probe and alignment with T159's reviewed delivery contract on 2026-09-26.

Local execution on 2026-09-26 reached Tor PROGRESS=100 and built both plane
images, then Docker refused to start the DP while applying `stargate-dp`
(`proc/thread-self/attr/apparmor/exec`: no such file). This is the measured
container-runtime failure, not proof that no suitable VM exists. On
2026-09-27 the maintainer requested reuse of the prior VM approach. A copy
of the saved guest loaded the enforcing production profile and started both
planes. No listener-security setting was relaxed.

Round-1 review on 2026-09-27 found that the proposed probe reused a bare
hostname username, closed the recovered tunnel before checking application
bytes, and needed longer stop/overall deadlines. The partition-vector test
first failed to build with `undefined: t131PartitionUsername`; after the
fixture implementation, its targeted `go test -tags docker` run passed.
Two VM attempts then failed initial authentication within the old three-minute
startup window. The second observed CP schema initialization, then one configured
credential at generation 1 and a DP snapshot near the deadline. This is failed
startup evidence, not a passing recovery result. Following T173's existing VM
fixture, cold-CP setup now has a separate ten-minute bound; individual dials,
reads and DP-only recovery retain three minutes. Retry contexts bound the whole
admission window. The stacked bound is 46.5 minutes, with a 48-minute suite
context and 50-minute outer test limit. Live evidence remains required.

### VM execution on 2026-09-27 — failed, recovery unexecuted

The third run also failed initial authentication after the ten-minute allowance;
overall `TestStackSmoke` duration was 751.54 seconds. Its partition reference
vector passed. The running CP had zero restarts, both IPC sockets existed,
generation 1 was persisted, and later checks still found zero configured
credentials and no DP snapshot. T178 owns diagnosis and repair; no root cause
or recovery success is claimed. T132 stays in progress with its live gate unmet.

- Host: saved T124 guest copied to `guest-t132.qcow2`, independently booted
  Ubuntu Linux `6.8.0-139-generic`, QEMU `11.1.1` TCG, 4 vCPU, 6 GiB RAM;
  Docker `29.1.3`, Compose `2.40.3+ds1-0ubuntu1~24.04.1`.
- All 685 initially transferred tracked files matched by SHA-256. The later
  startup-budget-only test change was retransferred and rebuilt; production
  sources/images were unchanged. Guest AppArmor enforced `stargate-dp` and
  both IP families had the production owner rules. This measures the guest.
- Native harness build from `tests/integration`:
  `GOTOOLCHAIN=go1.26.3 go test -tags docker -c -gcflags='github.com/zcat-app/stargate/tests/integration=-trimpath=/home/claudia/stargate=>/home/ubuntu/stargate-t132' -o /home/claudia/stargate/target/runs/T132-vm/integration.test .`.
  The source-path mapping lets `runtime.Caller` find the identical guest tree.
- Guest execution from `tests/integration`:
  `BUILDX_BUILDER=t132-native ../../target/integration.test -test.run '^(TestStackSmoke|TestT131PartitionUsernameReferenceVector)$' -test.count=1 -test.v -test.timeout=50m`.
- Final test source SHA-256:
  `b72407d887c88317cd58f4b757a4a43bad736b024bff46f5866360503f095a39`;
  harness: `ee4a8e96bc9322accc2fba5e0fb94ffb5ccbb9b59725eb5f9dc6c9a936836f81`;
  local `target/runs/T132-vm/live.log`:
  `dc2f64650ddb0590fbf9029060a6c91d394ac0c9a09c162b38a5ed2b92ea22c2`.
- Guest image IDs: DP
  `sha256:58065c2276b7f5e14bda0633778c24b61654cea710d8bbbff4f45eea5d6e324f`,
  CP `sha256:d44e03c6aab80bc0a168ce539b04e11462f54f1397f4fdbdda377cd2ce34ddab`,
  Tor `sha256:fede221f309c4a90804608d5ac4606cc8fb7a1d9067d3d95b4c94e0d240fbde0`.

### VM recovery acceptance after T178 and T179

T178 repaired the initial SQLite credential commit and the confined DP
snapshot fsync. Its reviewed live run used this ticket's unchanged staged
`CpTls` and integration harness as an identified overlay. On the enforcing
Ubuntu VM, `TestStackSmoke` passed in 539.86 seconds. Initial authenticated
SOCKS forwarding carried application bytes; the
`T132_DPOnlyRestartRecovery` subtest removed the stopped DP snapshot,
restarted only DP while CP remained running, and carried application bytes
after authenticated recovery (PASS, 47.25 seconds). The partition username
reference vector passed. A separate observer verified the CP container ID,
start time and zero-restart count across the DP restart. The run's source and
image identities and full sanitized output are in
`evidence/T178-tests-first.json` under `live_acceptance`; the local log is
`target/runs/T178-vm-repair/live-attempt2.log` (SHA-256
`2f364cea069faa5c1930078011a728a0924b7c9a36ff7870eeacaa4400408ed1`).
The harness SHA-256 is
`ee4a8e96bc9322accc2fba5e0fb94ffb5ccbb9b59725eb5f9dc6c9a936836f81`.
T179 changed only the SQLite regression test and ticket evidence; it did not
change the deployed CP, DP or Tor source used in that live run.

After T178/T179 merged, T132's original pre-fix test-only patch was replayed
against HEAD `fafb82a6aa5b3431fbaa13bfc721c2712ef1721c` and failed at
the missing explicit fake-CP h2 pin. The identical probe passed against the
unchanged staged implementation. The rebased red/green record is
`evidence/T132-tests-first.json`; the original record is retained at
`target/runs/T132-original-evidence.json`. No T132 production or test source
changed during this evidence rebase.

## T172 Tor ingress consumer constraint

After T173, exercise this ticket's CP/startup, reconnect and outage outcomes using authenticated SOCKS5 CONNECT with a complete partition username. HTTP first byte `C` must stay silent and must not authenticate, increment counters or dial. Preserve CP-independent SOCKS byte forwarding and the pending-delivery semantics; T173 remains a direct blocker.
