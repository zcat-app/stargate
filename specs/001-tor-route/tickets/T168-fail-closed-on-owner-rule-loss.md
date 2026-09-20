---
id: "T168"
title: "Keep data-plane egress closed across owner-rule loss"
status: done
created: "2026-09-20"
last_updated: 2026-09-20
source: "T163 RuleAbsentStartup live failure"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T162", "T167"]
parallel: false
files_budget: 32
privacy_critical: true
complexity: "high"
risk: "high"
round_cap: 3
spec_refs:
  - ".specify/memory/constitution.md"
  - "specs/001-tor-route/contracts/foundation-boundaries.md"
  - "specs/001-tor-route/spec.md"
decision_refs:
  - "specs/001-tor-route/tickets/T163-verify-packet-level-topology-boundaries.md"
  - "specs/001-tor-route/analysis/T134-local-topology.md"
remediates: "T162"
tests_first: []
reviews: { round: 1, date: 2026-09-20, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T168: Keep data-plane egress closed across owner-rule loss

## Context

T163 found that removing both owner OUTPUT jumps left SOCKS5 admission working.
The original red evidence is `target/live-e2e/T163-20260920-161720/run-result.txt`.
The maintainer challenged adding firewall machinery, requested falsification of
an intrinsic process restriction, and then explicitly requested completion in
this recorded 2026-09-20 session. The socket-only proposal failed on listener
reuse; the revised prototype also exposed Fast Open and MPTCP gaps before the
bounded corrected checks passed. This ticket turns that evidence into a
reviewed production repair rather than promoting the prototype's partial claim.

## Refinement and protection delta

The original acceptance treated loss of an owner jump as loss of the only IP
boundary and therefore required immediate SOCKS refusal. The user-authorized
replacement makes the application process's kernel restrictions the required
runtime IP boundary. Failure to establish them refuses startup. Once they are
established, deletion of either/both auxiliary owner jumps must preserve both
no-independent-egress and valid Unix-adapter service. T163's corresponding
acceptance and probe change in the same review; the original failure remains
historical evidence. No Constitution permission is expanded: I/II/III/V/VII/VIII
and loopback-only ingress remain binding. Existing installer owner rules remain
as defense in depth; their removal from setup is outside this repair.

The explicit 32-path budget includes the staged T163 evidence, T155 dependency,
T168 ticket, runtime/test changes, affected contracts and operator prose. This
is a single combined tests-first repair; no test obligation is disabled to
obtain green. The native review covers the complete candidate from e33dc3b.

## Analysis

- **Must hold:** before any proxy or IPC serving, establish a pure-Go, all-thread
  kernel restriction that denies independent IP origins and socket reuse;
  only ordinary TCP loopback listener replies and specified Unix adapter/IPC
  capabilities remain. Unexpected inherited socket/ring/device capabilities,
  missing kernel support, unsupported builds or partial installation refuse
  admission. AppArmor/fabric isolation remains a required deployment boundary.
- **Gated:** preserve red-before-green tests for socket reuse, Fast Open,
  inherited capabilities and thread coverage. Existing auth/IPC tests retain
  their assertions while their subprocess build/Unix upstream fixture matches
  production. A disposable live deployment verifies owner-loss independence,
  startup/restart and packet outcomes with positive capture controls.
- **Residue:** T163 still owns cumulative and physical-host packet evidence;
  T155 integrated closure, live Tor circuit/browser guarantees and external
  human release review remain separate. Cross-compilation is not runtime proof.

## Acceptance

1. Preserve the original T163 failure and the prototype's actual red/green
   evidence. Author production regressions before implementation and record
   their failing network/property results, then passing exact-candidate results.
2. Bind only a validated loopback literal using ordinary TCP, reject unexpected
   inherited network capabilities (including standard descriptors), then apply
   Landlock TCP connect/bind restrictions to every Go thread and synchronized
   seccomp before proxy/IPC serving. Cover existing/new threads, descendants,
   IPv4/IPv6 socket creation, listener/accepted-socket reconnect, Fast Open,
   descriptor import and alternate kernel socket paths. There is no environment
   or runtime bypass switch. Required-feature/installation failure exits before
   any SOCKS method or management response.
3. Keep current AppArmor, Unix fabric caller matrix and installer owner rules.
   Approved Unix reconnects, authenticated forwarding from retained state and
   CP outage/reconnect keep working. Direct TCP upstream overrides are refused;
   production and test adapter transport is pathname Unix. All new startup
   errors are fixed/redacted. Suppress self-generated Landlock denial auditing
   on ABIs with configurable logging; no per-request/per-attempt application log.
4. In a disposable checked-in Compose deployment, remove IPv4 only, IPv6 only
   and both owner jumps. Demonstrate continued loopback admission and zero IP
   emission/loopback-forwarder access from the same confinement code with
   positive packet controls. Test init/re-init and Compose DP restart while the
   auxiliary jumps are absent; initial init still installs/verifies its defense
   in depth. Direct Docker policy overrides remain unsupported. Verify refusal
   when required process restriction installation is unavailable, and recovery
   on a supported host. Unsupported families are explicitly refused/documented.
5. Reconcile T163, foundation contract, feature plan/spec, operator prerequisites
   and THREAT-MODEL in this reviewed change. Linux amd64/arm64 code paths use
   native constants; unsupported runtime combinations fail closed. State actual
   tested hosts and remaining release evidence honestly. T163 is not closed by
   this ticket's scoped live result.
6. Run `bash scripts/verify.sh` GREEN on the complete candidate, then the required
   native GLM/Astra combined review and bounded rework. Commit only through the
   driver after both exact-candidate approvals. Preserve existing staged evidence.

## Out-of-scope

Removing owner-rule installation, new privileged daemons, host verifiers or
per-request CP/management calls; observer work; browser/Tor circuit claims;
Constitution amendments or weakening the actor matrix. Fixture adaptations to
pure-Go builds and pathname Unix adapters are explicitly authorized to keep
existing protocol/auth assertions valid under the production restriction.


## Tests-first execution record (2026-09-20)

Before the production restriction was written, `TestSandbox` failed because an
existing Go thread connected successfully (`TCP connect: <nil>`). The expanded
red run also admitted each inherited IPv4/IPv6/Unix socket, including stdin,
and allowed a reset listener to reconnect (`operation now in progress`). These
are failing network properties, not missing-symbol/build failures. Local raw
logs are `target/runs/T168-confinement-red.log` and `T168-startup-red.log`.
The earlier prototype separately demonstrated listener reuse through the exact
DP AppArmor profile, Landlock's Fast Open gap on this kernel, and Go's MPTCP
listener behavior. Its original artifacts remain in the initiating checkout's
`target/t168-probe/`; no prototype-only result substitutes for candidate tests.

The candidate package now passes existing/future OS-thread coverage, public
startup descriptor rejection, accepted/listener reuse, Fast Open sendto/sendmsg,
message descriptor import and io_uring/pidfd entry denial. A fork/exec descendant
retains socket-creation and inherited-socket connect denial while Unix forwarding
works. A cgo-linked binary refuses installation. The real DP contract suite
passes authenticated forwarding and retained-state startup with CP absent,
CP disconnect/reconnect, and pathname Unix upstream recreation. The synthetic
backend's TCP fixture runs outside DP and is bridged to its Unix adapter by the
test harness; production has no TCP upstream exception.

The confined packet helper distinguishes permission denial (exit 77) from setup
failure (78), unexpected error (79), crashes and missing binaries. Recorder
selftests reject those failures; an empty capture or a TCP timeout never proves
confinement. Linux arm64 package/test and executable cross-compilation passed;
this is not an arm64 runtime result. The tested kernel is Linux 6.8.0-124-generic,
Landlock ABI 4, amd64; ABI >= 7 logging flags are not runtime-tested here.

## Scoped live result (2026-09-20)

The complete sequence passed on a disposable nested Docker 29.8.1 host using
the checked-in Local Compose deployment, Linux 6.8.0-124-generic / Landlock ABI 4,
amd64. Evidence: `target/live-e2e/T163-20260920-213147/` and
`target/runs/T168-live-run6.log` in the implementation checkout.

- Initial init installed both owner jumps and the enforcing AppArmor profile.
  Baseline controls were visible; DP TCP/UDP/DNS markers were absent and DROP
  increased by three. The Tor Unix caller matrix passed across socket recreation.
- IPv4-only, IPv6-only and both-jump removal preserved loopback admission.
  Confined socket-creation/reuse/Fast Open probes produced zero forbidden IPv4
  packets on source and egress captures, with positive controls and DROP delta 0.
  Loopback forwarder and IPv4/IPv6 dummy resolver mediation were refused.
- Compose DP restart with both jumps absent repeated that result. Re-init
  restored both jumps and admission. Fault policies separately denying
  `landlock_create_ruleset`, `landlock_restrict_self` and `seccomp` each caused
  exit 1 with the fixed confinement error and no SOCKS admission. Removing each
  policy restored service. These overrides are fault fixtures, not operator paths.
- The host has no routed IPv6 path; `::1:8881` refuses admission. IPv6 loopback
  resolver and kernel socket/reconnect tests passed, but no routed IPv6 packet
  result is claimed. Physical-host and arm64 runtime evidence remain outside
  this scoped result. A Linux/386 build was executed and refused startup.

Earlier live attempts exposed fixture defects: the private checkout parent was
not traversable by probe UIDs, libpcap buffered controls past recorder stop, and
text-buffered readiness could miss a line already read from the OS pipe. The
runner now feeds Python probes through stdin, uses a temporary executable
location accessible to the selected UID, enables immediate capture and reads
readiness bytes directly. A test-only Compose override also needed to append
only its additional seccomp option. None required relaxing production policy.
The readiness regression failed before its fix; dropped/missing kernel-loss
summaries also fail the decision tests. The current validator accepts all 29
saved capture summaries with zero kernel drops. These failed attempts were
never counted as zero-packet evidence.
