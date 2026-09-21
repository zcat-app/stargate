---
id: "T171"
title: "Separate topology probe launch and fixture timing"
status: in-review
created: "2026-09-21"
last_updated: 2026-09-21
source: "T163 full Ubuntu VM probe startup timeouts"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T169", "T170"]
parallel: false
files_budget: 6
privacy_critical: true
complexity: "medium"
risk: "medium"
round_cap: 2
spec_refs:
  - ".specify/memory/constitution.md"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
decision_refs:
  - "specs/001-tor-route/tickets/T163-verify-packet-level-topology-boundaries.md"
remediates: "T169"
tests_first: []
reviews: {}
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T171: Separate topology probe launch and fixture timing

## Context

T163's independently booted Ubuntu VM runs `T163-20260921-010358`,
`T163-20260921-011622` and `T163-20260921-013220` failed because an ordinary
Python probe exceeded its combined 2.8-second interpreter-start/socket budget.
The middle run passed the initial IPv4 capture matrix (all positive controls,
zero DP packets, DROP delta 3) before its forwarder probe timed out. Four VM
CPUs and higher test-process scheduling priority did not eliminate the startup
timeout. These remain failed runs, not denial evidence.

The fixture also starts its short accept/receive deadline before the recorders
are ready and before the child interpreter starts. A valid slow startup can
therefore lose the positive control even when packet policy is correct. This
ticket repairs test orchestration without changing production permissions or
using any timeout as an isolation verdict (Constitution III/V/VII).

## Analysis

- **Must hold:** helper startup has a separate finite process budget; the
  existing 0.8-second socket operation limit remains. Expired processes,
  missing completion markers, crashes and unknown confinement exits fail.
- **Gated:** spec-derived regressions inject real child-start delay and exercise
  real loopback fixture exchanges after slow recorder/probe startup. A hanging
  child still fails. Fixture workers end explicitly after the probes, with
  bounded cleanup; each negative retains its positive control and captures.
- **Residue:** the actual complete VM packet sweep, physical-host wording
  decision, and DNS-side-channel retirement remain T163's obligations.

## Acceptance

1. Preserve failing-before-fix tests for a delayed but valid helper and delayed
   forwarder/resolver setup, plus the actual VM timeout results above.
2. Give both ordinary and confined helper processes a finite 30-second default
   budget, separate from the unchanged socket-operation deadlines. Timeout is
   an error, never a successful denial. Retain exact ordinary completion-marker
   and confined exit-code requirements.
3. Start fixture workers after recorder readiness. Keep their real loopback
   services available until the bounded probes finish; then stop and join them
   with bounded cleanup, including on setup/probe failure. Do not manufacture
   packets or skip any capture/positive-control/denial assertion.
4. Document the timing distinction and failure semantics. Run the focused
   regressions, the full live suite on the VM, and `scripts/verify.sh`; both
   native reviewers and the driver-controlled commit must pass. The live suite
   must satisfy its existing assertions; a new production defect gets its own
   ticket, not a relaxed assertion here.

## Out-of-scope

Production code/topology/permissions, packet classification, recorder validity,
probe socket-operation deadlines, T163's host-evidence scope, DNS-channel closure,
browser/Tor-circuit or release guarantees.

## Execution record (2026-09-21)

Before the runner changed, the new regressions failed for delayed interpreter
startup, delayed forwarder/resolver controls, and four worker/recorder cleanup
cases (15 tests: four failures, three errors). The fixture socket wrapper then
needed to forward `accept()`'s `fileno` argument once the repaired runner could
reach that operation. The corrected control test was separately rerun against
the original runner and still failed for both expired services. A further
queued-negative-datagram falsifier failed against the first cleanup candidate;
workers now drain ready input before honoring stop on an idle receive.

The first focused green run passed all 16 tests, including real delayed-child UDP,
expired ordinary/confined helpers, real loopback controls and failure cleanup.
Raw results are retained locally under `target/live-e2e/T171-20260921/`.
The complete VM sequence then passed as `T163-20260921-015428` (exit 0):
IPv4 source/egress controls and zero DP TCP/UDP/DNS packets (initial owner
DROP delta 3); loopback forwarder/resolver controls and denial; Tor's caller
matrix before/after socket recreation; separate and combined owner-jump loss,
DP restart and re-init; refusal/recovery for each required Landlock/seccomp
installation fault. All 29 captures decoded and closed cleanly with zero
kernel drops. Routed IPv6 was unavailable and explicitly refused; IPv6
loopback resolver denial passed. Cleanup completed without bypasses.

The environment was Ubuntu Linux 6.8.0-139-generic, amd64, Landlock ABI 4,
Docker 29.1.3, Compose 2.40.3, and Go 1.26.3 in a four-CPU QEMU TCG VM with
6 GiB RAM. The installer used its existing 300-second health wait, and the
test runner used scheduling priority `nice -n -10`. The tested runner SHA-256
is `a02916931dfd0339a660646f69157390008810227529e842fffe9086971574ae`;
the capture-manifest SHA-256 is
`ff254ae0240b241ab22054557bd07f17056299c6c310ad7a4f449432c646c3df`.
This is full guest-deployment evidence, not a physical-NIC measurement or
T163 closure.

Before commit, an additional falsifier exposed a fixture I/O failure after a
successful positive control being accepted as denial. Both forwarder and resolver
cases failed the new regression against that candidate. Workers now propagate
accept, receive, exchange and reply failures into a failed phase after bounded
worker/recorder cleanup. All 17 focused tests then passed. The first candidate's
two independent approvals were invalidated; the repository gate and fresh
reviews must cover this correction.

The corrected candidate then passed the entire VM sequence again as
`T163-20260921-024737` (exit 0), including all failure/recovery phases and cleanup.
All 29 captures were valid with zero kernel drops. The corrected runner SHA-256
is `e9131771fab1e47cec3242a2716e6d26280f3c15f34b934dee80cca733d3f6da`;
the new capture-manifest SHA-256 is
`c665c3bb6d511260e95cd989c2b2c303a3fea9f820178aa4d9b0045a774a5f58`.
All 132 runtime/deployment/test source paths matched the guest before this run.
The same environment and scheduling settings described above were used.
