---
id: T034f
title: "Measure authenticated onion component egress with prepared artifacts"
status: deferred
created: 2026-07-04
last_updated: 2026-10-16
source: review/sol-review.md#A5
phase: "3: User Story 1 — First-time onion service load (Priority: P1) 🎯 MVP"
story: 'US1'
blocked_by:
  - "T009"
  - "T155"
  - "T064"
  - "T071"
  - "T072"
  - "T073"
  - "T126"
  - "T156"
  - "T162"
  - "T218"
  - "T223"
  - "T226"
  - "T227"
parallel: false
files_budget: 11
privacy_critical: true
complexity: medium
risk: high
round_cap: 3
spec_refs:
  - "specs/001-tor-route/spec.md §\"US1 Acceptance Scenario 3"
  - ".specify/memory/constitution.md §III"
  - "THREAT-MODEL.md §3.1 (T162 deployment mechanism)"
  - "specs/001-tor-route/contracts/qualification-boundary.md"
  - "specs/001-tor-route/design/qualification.md"
decision_refs: []
reviews: {}
deferred_on: T218
deferred_reason: blocked-on-new-ticket
overrides:
  - date: "2026-10-10"
    by: user
    decision: "Verify only T034f and directly affected parts; do not run scripts/verify.sh or unrelated Go/Java suites."
    reason: "User explicitly directed affected-part-only verification for the remaining batch."
  - date: "2026-10-10"
    by: user
    decision: "Use fresh Astra and Luna reviews for T034f; GLM remains paused."
    reason: "User explicitly selected Astra+Luna for this batch. This ticket-scoped override does not change the global review matrix or claim the default GLM+Astra launcher ran."
aborted_attempts:
  - "2026-10-10: current-VPS native attempt stopped before workload at scripts/stargate init exit 20 (EXIT_KEYGEN); registered cleanup passed and the following read-only preflight confirmed project/policy absent and baseline firewall snapshot unchanged. No acceptance observation was completed."
  - "2026-10-10: current-VPS native attempt stopped before workload at scripts/stargate init exit 20 (key-installation-failed). Bounded cleanup reported Compose teardown failure; a later exact-project Compose down removed only its labeled resources, and the following read-only preflight confirmed T162 policy/AppArmor profile absent and the baseline firewall snapshot unchanged. No acceptance observation was completed."
  - "2026-10-10: after binding host /dev/shm into the privileged initializer, current-VPS native attempt passed key installation but scripts/stargate init returned a non-20 failure whose exit code was not retained by the then-current test. Bounded cleanup also reported Compose teardown failure; exact-project resources were subsequently removed and the following read-only preflight confirmed project/policy absent and baseline firewall snapshot unchanged. The artifact did not preserve the init status, so the exact failing stage is unknown. No acceptance observation was completed."
  - "2026-10-10: current-VPS native attempt failed before workload at scripts/stargate init exit 30 (compose-start-failed); cleanup reported compose-exit-1. The exact run's labeled volumes were removed after confirming no run containers/networks; the exact T162 owner rule/chain and enforce profile were restored to the clean preflight baseline. A subsequent read-only preflight confirmed the original firewall snapshot hash and no project/policy/profile. No acceptance observation was completed."
  - "2026-10-10: after isolated successful builds of all three Compose services (control-plane Maven used -DskipTests), current-VPS native attempt again failed at scripts/stargate init exit 30 (compose-start-failed), cleanup compose-exit-1. No workload/capture was observed. Recovery and preflight details are recorded in the T034f round-3 plan; no acceptance observation was completed."
  - "2026-10-10: after all three service images built successfully and read-only Compose config passed through the pinned helper, current-VPS native attempt again failed at scripts/stargate init exit 30 (compose-start-failed), cleanup compose-exit-1. No workload/capture was observed. Exact run-owned volumes and T162 policy/profile were removed/restored, and preflight confirmed the original firewall hash with no owned policy/profile/project. No acceptance observation was completed."
  - "2026-10-10: latest current-VPS attempt stopped before workload at scripts/stargate init exit 30 (compose-start-failed); the shim found no allowlisted Compose stderr signature. No workload or capture occurred. In-test teardown returned Compose exit 1. Afterward, exact-run volumes were removed with exact-project Compose down; the exact T162 IPv4/IPv6 additions and enforce profile were restored only after the canonical snapshot excluding those additions matched prior baseline SHA-256 aebfe77769bd74579bdd6220c6c2c1149361f275369086ab3a2e719f113b4d40. Post-recovery read-only preflight passed with policy, profile, and project absent and the same baseline hash. No acceptance observation was completed."
  - "2026-10-10: round-6 current-VPS attempt passed read-only preflight and entered the initializer, then failed during t034fCaptureBuildImageIdentity before workload, capture, calibration, or acceptance assertions. The sanitized receipt records FAIL / NOT OBSERVED with reason build/runtime image identity binding failed; cleanup-failed. In-test cleanup proved exact project containers, network, and volumes absent after Compose down but refused T162/AppArmor restoration because no expectedPost snapshot existed and the partial-install policy check ran while Compose bridge rules remained. Recovery inspected the exact T162 chains and enforce profile, confirmed project resources absent, removed only the exact run additions, and verified both chains/jumps and profile absent. Bounded networkless cleanup removed root-owned Buildx refs/activity under this run's exact private state path; the Go TempDir is absent. Compose rebuilt the local control-plane and Tor images, which remain local; no global image/cache prune occurred. No acceptance observation was completed."
  - "2026-10-10: after the helper began returning fixed failure categories, one current-VPS native attempt reached DP identity and stopped at dp-helper-shell-exit after its bounded helper interval. The run-owned Compose resources were removed and exact T034f-labeled containers were absent afterward. No workload, capture, calibration, or acceptance observation completed."
  - "2026-10-10: the next current-VPS attempt localized the helper failure to dp-helper-namespace. Exact run-owned resources were removed and the following focused preflight passed with the owned policy/profile/project absent and firewall baseline unchanged. No workload or acceptance observation completed."
  - "2026-10-10: latest current-VPS attempt localized DP identity failure to dp-helper-target-netns-read (the helper's readlink of the target network-namespace link) after about 44 seconds. The sanitized receipt is FAIL / NOT OBSERVED; exact run-labeled helper/Compose resources were absent after cleanup. This stage identifies the failed operation but not its cause. No consensus, capture, calibration, workload, drain, or acceptance observation completed."
reopens: []
redteam_findings: []
clarity_check: {}
---

# T034f: Measure authenticated onion component egress with prepared artifacts

## Binding October16 artifact/native alignment

Use the qualified shared runtime/artifact interface; this ticket retains every authenticated
consensus, >=120s workload, exact CP/DP/Tor control, capture/loss/drain/restoration assertion below.
The Buildx discovery/build/iid-in-runtime mechanism in old quoted tasks is historical. Before init,
validate complete expected prepared artifacts/tools and unchanged production topology instead.
Build/test-binary production occurs outside runtime authority, with its original source/tool
identity and separately accounted evidence. Never build/pull/compile/import during the admitted
workload. All helper/recovery paths use shared pre-effect admission and exact intent/ACK.

The original runtime identities still bind source -> prepared archive/OCI/config/payload -> actual
container/executable, including observer and helper images; simply recording two hashes is not
provenance. Existing historical build identities remain historical. Cleanup inherits original
absolute deadlines rather than a fresh cancellation budget; no cap increase is authorized.
T218 readiness and T227 platform evidence are prerequisites, not this scenario's PASS. Preserve
all original failed attempts, parent-only ControlPort work and FAIL/NOT OBSERVED receipts.

## Context

Derived from `specs/001-tor-route/tasks.md` — see the full task body there. This
ticket is the executable work unit; the tasks.md entry is the
spec-kit plan that survives `/speckit-tasks` regeneration.

> **Historical task summary (current acceptance/dependencies above govern):**
>
> - [ ] T034f [US1] Release-cadence component observation for US1 acceptance-scenario 3 — `tests/integration/egress_consensus_test.go`. Use the real `scripts/stargate init`; before init, reject existing/unreadable UID-5102 processes or socket rows and prove Buildx discovery in the pinned initializer context. Preserve initialized named volumes through token provisioning, CP restart, and the routed workload. Start Tor capture and snapshot the accepted bounded microdescriptor consensus plus authenticated T062 validity metadata before any routed control. Keep one continuous Tor/CP capture and positive/inverse NFLOG reader pair through calibration, the authenticated >=120-second workload, post-workload controls, DP shutdown, and final drain. Every Tor TCP SYN must match an IPv4 OR endpoint in the unchanged valid consensus. Require CP runtime `network_mode: none`, complete interface inventory, capture of every interface (or proof only `lo` exists), and exact loopback controls before/after; claim only no observed non-loopback packets. Attribute DP OUTPUT attempts by UID 5102 and recursively monitored T162 cgroup-v2 subtree; calibrate distinct IPv4 positive controls before/after and exact IPv4/IPv6 outside-cgroup inverse SYN controls, with exact family/group records and DROP deltas. The bounded host identity helper binds exact container ID, PID/start-time, UID, cgroup and namespace; its read-only `/proc` and socket-FD authority, host-wide socket-table watcher visibility, sanitized output, and failure behavior are documented in THREAT-MODEL.md. Freeze/kill only the verified DP cgroup after the post-control and keep NFLOG readers active until every captured/inventoried TCP 5-tuple—including TIME-WAIT rows with UID/inode zero—and UDP socket is absent; then require CONFIG UNBIND ACK, same-socket drain to EAGAIN, sequence continuity, zero ENOBUFS/MSG_TRUNC, and exact counter/record reconciliation. Check SO_RCVBUF in the actual UID-0 host-network helper and use a justified effective burst bound; select and verify a gopacket-supported cooked capture format. Bind the frozen source/config manifest, pinned toolchain, independently hashed test binary, Compose build-result IDs, init-built observer iid, and running image IDs. Keep source read-only with separate writable mounts only for test binary, observer-build receipt, sanitized result, and private runtime state. Cover init env ownership for every Compose caller. Cleanup validates owned policy before teardown, proves exact run resources absent before policy removal, and verifies the original firewall/AppArmor baseline. Any ambiguity, loss, identity drift, unobserved tuple, timeout, cleanup mismatch, or secrets in diagnostics fails closed. The evidence artifact is `tests/integration/sc_us1_egress_consensus.md`; it reports no physical-NIC/hypervisor claim. Run before release tags, not per PR.

## Analysis

- **Must hold** — each Tor TCP SYN attempt observed in Tor's network namespace
  matches an endpoint in Tor's accepted microdescriptor consensus; CP's
  `network_mode: none` namespace emits no non-loopback packet; DP emits no
  prohibited IP attempt under T162's host-namespace owner/cgroup attribution.
- **Gated** — the test binds container, process, namespace and cgroup identities
   around capture, validates CP capture with an exact loopback packet control,
   live-calibrates IPv4-positive and IPv4/IPv6 inverse cgroup attribution, and
   reconciles family/group counters with complete NFLOG records and T162 DROP
   counters. It keeps NFLOG active through a cgroup-scoped producer shutdown
   and tuple-based host-netns drain; IPv6-positive attribution is structural
   only. DP records are pre-verdict attempts, not proof of wire egress.
- **Residue** — this component observation excludes unrelated host traffic and
  does not establish what a physical NIC or hypervisor observed. The live
  consensus must remain valid and unchanged across the measured window.

## Acceptance

1. Before real init, refuse existing or unreadable host UID-5102 processes and
   socket rows. Parse mandatory proc fields while accepting valid trailing
   kernel `-1` sentinels; never interpret unused kernel-specific columns as
   unsigned values. Verify the complete prepared artifact/helper/tool closure and expected immutable
   identities in the exact initializer context; no build discovery is performed in the native window. Capture Tor's actual network namespace and bind
   its container, init PID and net-namespace identity before and after capture.
2. After cookie authentication, obtain the endpoint set from Tor's
   `GETINFO dir/status-vote/current/consensus-microdesc` response on the same
   ControlPort session used to query `consensus/valid-after`,
   `consensus/fresh-until`, and `consensus/valid-until`. Parse and validate
   that bounded returned document; its validity timestamps must equal the
   metadata from that session. Do not read or substitute the unauthenticated
   cached-consensus file. After measurement, authenticate again, query the
   same document and metadata, and require the document digest and validity
   interval to remain identical. Every observed TCP SYN must match an IPv4 OR
   endpoint from the authenticated document. The ControlPort parser counts
   actual CRLF wire bytes under the 8 MiB aggregate cap, caps lines at 64 KiB,
   and applies one 131,072-line budget across status, continuation, and all
   data-block lines before dot unstuffing.
3. Require CP's runtime `HostConfig.NetworkMode` to be `none`. Inventory every
   interface in its namespace; either prove only `lo` exists or capture all
   interfaces. Require bounded TCP loopback controls before and after the
   workload to appear on `lo`; reject any observed non-loopback packet.
4. Attribute DP OUTPUT attempts by UID 5102 and verified cgroup-v2 subtree in
   T162's existing chain. Calibrate the positive cgroup rule with exact IPv4
   loopback reply controls before and after the workload; do not claim live
   IPv6-positive calibration. Require same-UID outside-cgroup IPv4 and IPv6
   loopback SYN controls only in their respective inverse groups, absent from
   the positive groups, with exact T162 DROP counter deltas and complete
   per-family/per-group NFLOG record reconciliation. These records precede the
   T162 verdict and are not wire-egress evidence.
5. Bind all four UID status values, DP PID/start time/network namespace/cgroup
  namespace and host rule-helper cgroup namespace independently. Both
  host-proc helpers use `--pid=host --cgroupns=host`; require and compare their
  cgroup namespace with the independently inspected host/rule-helper namespace.
  A discovery-only read may learn a nonzero PID start time; re-inspect the
  running container ID/PID and exact container cgroup component, then require
  that nonzero start time on every normal identity read and reject drift.
  Require exact host-relative cgroup components (never substring matches) and
  reject relative paths containing `..`. A bounded host identity helper may
  read only target `/proc` UID, start time, cgroup, namespace links and
  socket-FD links in its fixed program, bound to exact Docker container IDs.
  For the reviewed test-only `apparmor=unconfined` configuration, host PID
  visibility plus `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`, and Docker's seccomp
  configuration may permit reading or modifying host process state beyond
  that fixed program. The monitor has `CAP_SYS_PTRACE` and can write within
  its exact mounted DP cgroup subtree. These are trusted host-privileged test
  helpers; container argument tests do not establish kernel containment
  against compromise or mutation. They return only sanitized identities and
  in-memory socket inode/tuple data. Keep the production DP under the
  unchanged enforcing `stargate-dp` profile and T162 rules. Do not run
  host/kernel authority probes until the maintainer records acceptance of
  this residual authority.
  Continuously verify recursive DP cgroup-v2 membership; unknown processes,
  changed start times or monitor interruption fail.
6. Preserve initialized named volumes from `scripts/stargate init` through
  token provisioning, CP restart and the routed workload. Token seeding must
  pass Docker `--entrypoint sh` before the immutable Tor image ID, then use the
  script as `-ec` arguments (do not pass a duplicate `sh` command). Every
  inverse-control helper return path performs bounded stop/remove and exact
  name-absence verification under the original inherited absolute cleanup deadline; caller cancellation
  cannot skip cleanup, and cleanup errors are joined with the primary error.
  Keep one continuous
  NFLOG reader pair across calibration, workload, post-control and final
  shutdown. After the post-control, freeze and terminate only the verified DP
  cgroup; retain every captured/inventoried TCP tuple, including TIME-WAIT rows
  with UID/inode zero, and keep readers active until those tuples and UDP
  sockets are absent from host tables. Ignore unrelated tuples, fail on
  attribution ambiguity, then require UNBIND ACK, same-socket drain to EAGAIN,
  and exact counters. Cleanup checks owned policy before teardown, proves exact
  run containers/networks/volumes absent before removing this run's policy,
  then verifies full original firewall/AppArmor baseline. Handle signals with
  bounded cleanup and surface failures; SIGKILL and host failure are outside
  the guarantee.
  Every mutating firewall helper carries the current run's unique observer
  label and a unique run-scoped container name. Its iptables commands use a
  five-second xtables lock wait and an in-container command timeout; cleanup
  removes and verifies all labeled helper containers before policy inspection
  or restoration.
7. Bind a frozen candidate/source manifest (init, Compose, build inputs, tools),
  pinned Go toolchain and independently hashed test binary to a derived
  execution manifest. Verify prepared Compose service identities independently and bind
  the prepared observer image ID to the running container. Keep source read-only;
  writable mounts are limited to test binary, observer build receipt, sanitized
  result and private runtime state. Include the tracked
  `tests/contract/error-template/leak-corpus.txt` as an explicit frozen source
  input; its mutation changes source identity, while generated result/evidence
  mutations do not. Record sanitized namespace/cgroup
  identities, consensus digest/validity, manifest identity, duration and
  aggregate loss/result counts. Leak-corpus diagnostics must not print captured
  secret content.
  The CP claim is limited to no observed non-loopback packets; packet capture
  cannot detect a failed `connect` that emitted no packet.
8. The observation is component scoped; a physical-NIC or hypervisor claim
   requires capture at that vantage. T162 is the enforcement mechanism.
9. Before init, validate the exact pinned Docker/Compose and prepared helper/probe bindings in
   the actual initializer namespace/mount context. Refuse missing/substituted artifacts before
   policy effects; every native caller forces no-build/no-pull and refuses hidden compilation.
  Qualify the
  host-proc helper's effective capabilities against an inspected disposable
  networkless UID-5102 target that holds owner-only loopback socket FDs. Probe
  SYS_PTRACE-only, DAC_READ_SEARCH-only, and the combined set; separately record
  target namespace-link and socket-FD enumeration outcomes, verify effective
  CapEff, PID/start-time, exact container cgroup and namespace identities, and
  require the reviewed minimum combined set. On the qualified host, expect
  SYS_PTRACE-only to permit namespace reads but deny FD enumeration,
  DAC_READ_SEARCH-only to deny both, and the combined set to permit both; any
  other matrix fails preflight. Include the observed effective CapEff values
  and fixed denial categories in the sanitized qualification result. Use a
  second unrelated target to prove kernel-readable records fail the exact
  container/cgroup parser; label,
  bound and verify absence of every probe container before init. Fail before
  init on unexpected access, identity drift, timeout or cleanup error. This
  helper qualification supports only
   rootful Docker without user-namespace remapping; rootless or remapped hosts
   are unsupported and must fail preflight before init. In the exact UID-0 host-network NFLOG helper
   with only `NET_ADMIN` and `NET_RAW`, read back effective `SO_RCVBUF` before
   bind and prove it meets a documented 256 KiB floor and 200 ms burst bound;
   do not change host sysctls. Explicitly select a gopacket-supported cooked
   capture type and validate the pcap header before decoding. NFLOG
   expectations use an independent pinned-serializer fixture or semantic token
   parsing, never a fixture generated by the insertion argument builder.
10. After root init replaces the env file, every host-side Compose operation
    (service lookup, reads, controls, restart, teardown and recovery) must have
    an explicit bounded readable execution boundary while preserving the
    file's confidentiality. Exercise the actual ownership helper against
    caller-owned and root-owned/replaced temporary files; restore exact UID,
    GID and 0600 using `CHOWN` without a post-chown chmod, then verify the
    original caller can read the file. Exercise success, failure and
    cancellation without reading/logging file contents.
11. Bind source/build inputs using a frozen candidate/source manifest including
    init and Compose files, build contexts, tool identities and secret-free
    configuration. Build the test binary outside runtime authority with the pinned Go toolchain, hash it
    independently, and pass its expected reviewed digest to the helper. Keep the source
    mount read-only and use separate writable mounts for the binary, init's
    `target/observer-build` metadata, sanitized artifact and private runtime
    state. Independently validate prepared Compose and observer image identities,
    and require actual runtime image IDs to match the source-bound artifact mapping. Exclude generated outputs from
    the source manifest; bind them in a separate execution manifest/receipt.
    Each inverse helper is run-labeled and uniquely named; stop and remove use
    finite command deadlines, cleanup preserves the original operational error,
    and unexpected stop/remove failures or unverified absence fail the control.

Tor capture and its accepted-consensus/T062 snapshot begin before any routed
calibration request and remain active through the post-workload DP positive
reply control. The positive control runs both before and after the measured
workload on distinct exact tuples. Quiesce measured output, require each NFLOG
reader's CONFIG UNBIND ACK, then drain the same socket nonblocking to EAGAIN
before taking final per-family/group counters. Enable per-group sequence with
NFULA_CFG_FLAGS/NFULNL_CFG_F_SEQ; sequence continuity and zero ENOBUFS/MSG_TRUNC
are independent of exact post-drain counter-to-complete-record equality. The
bounded helper verifies its running executable SHA-256 before socket open and
requires kernel `6.8.0-146-generic`; record both. The inverse helper blocks
before socket creation until host UID, netns, PID start-time and outside-subtree
cgroup checks pass, and its exact source and destination ports are bound in the
expected packet tuple.

## Out-of-scope

Host-wide traffic attribution beyond the UID 5102 preflight and exact captured
tuples is outside the assertion surface. The watcher transiently reads
host-wide socket tables because DP uses host networking, but retains no
unrelated endpoints and makes no broader traffic claim. This ticket observes;
T162 enforces the topology.

## Notes

Derived by `scripts/bootstrap-tickets.sh` on 2026-07-04.
