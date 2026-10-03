---
id: "T203"
title: "Remove observer raw Tor authority with finite health publication"
status: done
created: "2026-10-03"
last_updated: 2026-10-03
source: "T155 resumed cumulative deployment M1; independent falsify-3-deployment.md; independent observer design-verification.md (2026-10-03 PASS WITH REQUIRED DESIGN CORRECTIONS)"
phase: "Foundation audit remediation"
story: "-"
blocked_by: ["T138", "T162", "T164", "T165", "T191", "T198"]
parallel: false
files_budget: 36
privacy_critical: true
complexity: high
risk: high
round_cap: 3
remediates: "T164"
spec_refs:
  - "specs/001-tor-route/contracts/foundation-boundaries.md §Deployment and authority"
  - "specs/001-tor-route/contracts/control-grpc.md §WatchEvents"
  - "specs/001-tor-route/contracts/torrc.md"
  - "THREAT-MODEL.md §3.1 and observer/Tor authority sections"
constitution_refs:
  - "II: Plane Separation"
  - "III: actor/traffic matrix, finite current readiness, Deployment Model"
  - "IV: pinned executable build inputs"
  - "V: honest boundary and TCB statements"
  - "VII/VIII: tests-first and independent evidence"
decision_refs:
  - "2026-10-03 user: approved one-time in-review to in-progress recovery retaining round2, baseline and review history so normal driver owns fresh verification; no driver code repair or hook bypass"
  - "2026-10-03 user: verify observer recommendation and proceed if it passes; observer-only scope"
  - "2026-10-03 user: approve both and apply wording; repair both advisory Majors within existing total-budget contract and apply exact12 reserved replacements SHA25660d17324e7bb236548e2a3e1cb24b58f36ec1fd2c2b2b413d243a6793f467e08"
  - "2026-10-03 independent design verification PASS WITH REQUIRED DESIGN CORRECTIONS; root read/accepted under the conditional observer-only go-ahead"
tests_first: []
reviews: { round: 2, date: 2026-10-03, verdict: APPROVE }
overrides: []
aborted_attempts: []
reopens: []
redteam_findings: []
clarity_check: {}
---

# T203: Remove observer raw Tor authority with finite health publication

Final independent design verification passed with required corrections on 2026-10-03;
those corrections are incorporated below. No other new T155 finding is included. T202 remains
reserved. The exact12 reserved wording replacements were independently evaluated and approved by the
maintainer on2026-10-03 (see decision_refs), then applied verbatim.

## Context

T164 removed CP raw-control authority but gave the observer Tor's unrestricted cookie and
ControlSocket mount. The observer actor remains subject to Constitution III's prohibition on
SOCKS/destination egress and arbitrary control authority. Independent falsification confirms
that capability contradiction; the proposed SETCONF/additional Unix SOCKS exploit on exact
Tor0.4.9.13 was not executed and is not claimed as demonstrated destination delivery.

The reviewed design candidate removes that credential/socket from the observer and moves
one fixed health exchange into Tor's own route-TCB-internal component, with no incoming
command/configuration channel from the observer. The observer receives only finite current
health through a volatile bounded handoff and keeps its existing authenticated CP protocol.
Container placement alone is not the justification: the publisher is explicitly part of the
Tor artifact/route TCB, with fixed code and no management-input surface. The independent design review established this classification without a constitutional
amendment, conditional on retaining the strict no-input boundary. Exact boundary wording passed the reserved-wording evaluation/approval procedure recorded above.

## Analysis

- Must hold: a compromised observer cannot obtain Tor cookie/raw control/SOCKS authority;
  only fixed Tor-internal health publication crosses the boundary; finite fresh readiness,
  authenticated CP framing and advisory routing independence remain intact.
- Gated: discriminating namespace/mount/DAC controls, fake Tor/publisher/freshness tests,
  unchanged CP client/protocol tests, real exact-candidate lifecycle and denial evidence,
  driver verify and independent review.
- Residue: compromised Tor route TCB retains its native route authority; this does not grant
  observer/CP authority. No public-network exploit reproduction, host escape claim, new
  deployment profile, logging history or external health probe is introduced.

## Acceptance

1. Ground the independent design verification and write the high-complexity outline. Use
   its concrete candidate contract: one query at a time, maximum four-second query budget,
   then one-second pause after each completed attempt. Sample-start timestamp comes from
   Linux CLOCK_BOOTTIME before the query. Accept cached finite health only while
   `0 <= current_boottime - sample_start < 4 seconds`; a late completion is UNAVAILABLE.
   Producer/consumer share the verified boot-time clock domain; incompatible time namespaces
   or clock failures fail unavailable. Real memory-backed boot-scoped storage prevents
   cross-host-reboot reuse. Scheduling/suspend/failure may extend unavailability, never READY's
   lease. These are specified bounds, not a claim of measured performance.
2. Tests first: actual rendered configuration/provisioning and production-namespace probes
   must reject the current observer credential/control-subpath shape, with a positive
   authenticated finite-health control. Retain a failing result on the starting candidate;
   same commands pass only after the authority is removed. A missing mount-name substring
   alone is insufficient: test effective paths, identity/mount context and raw-channel denial.
3. Implement a fixed Tor-side publisher as part of the pinned Tor image/route TCB. It accepts
   no observer/CP requests, command strings, paths, Tor destinations or configuration. It
   performs only the fixed bounded bootstrap/liveness exchange; malformed/auth/dial/time
   failures become finite UNAVAILABLE. Raw replies/errors, cookie bytes and arbitrary detail
   never cross the boundary or enter diagnostics/history. Preserve strict parser tests,
   including malformed replies containing PROGRESS=100, response bounds and timeouts.
4. Publish only finite current state using a volatile shared handoff, not persistent Tor
   state or an accumulating file/event journal. Expose no raw-control directory/cookie or
   sibling sensitive files to the observer. Observer reads are bounded, validate the exact
   handoff shape and fail to UNAVAILABLE for absent, malformed, stale or unproven-new state.
   Test old READY across publisher death, Tor/socket recreation, observer restart and relevant
   clock changes. Read and validate a bounded regular file on every health decision, including
   --check-ready; reject symlinks/FIFOs/devices, future/expired/wrong-version/partial/oversized
   records. Filesystem mtime and wall-clock changes cannot renew readiness. Consumer restart
   may reuse only the original remaining lease; no new timer starts. Atomic replacement may
   retain only one bounded latest file and one bounded temporary file, with no history.
5. Keep Tor entrypoint signal forwarding/reaping/shutdown responsive under a hung publisher
   or control query. A blocking periodic call must not stall Tor lifecycle handling. Bound
   and supervise the helper explicitly; test publisher/Tor termination, failure and recovery
   without orphan processes, uncontrolled retries or retained false READY.
6. Remove observer raw socket/cookie configuration and all grants, including the hardlink
   mechanism and effective control-subpath mount. Deny observer access to raw-control and
   SOCKS endpoints using external namespace/mount/DAC/capability boundaries, not a new
   allowlist inside the compromised process. Remove the obsolete cookie hardlink during
   supported upgrade as well as ceasing to create it. No extra observer IP interface/egress or generic
   broker is introduced. Provision handoff ownership/modes on clean install and upgrade.
7. Preserve CP-facing OBS/1 and HEALTH/1 authenticated framing, signatures, byte/EOF/deadline
   limits, finite tokens and --check-ready behavior. Preserve lifecycle mapping: bootstrap
   incomplete, publisher failure, stale state, observer-down and recovery cannot fabricate
   Tor exit/restart events. CP/observer/publisher unavailability must not stop authenticated
   DP routing, change route admission or trigger Direct fallback. CP wire schema is unchanged.
8. Obtain focused exact-candidate production-namespace evidence on a fresh disposable guest:
   record image/source identities, effective UID/groups/mounts/network/caps/policies; show
   allowed authenticated health and denied raw cookie/control/SOCKS access from both CP and
   observer identities. Include positive controls proving each denial probe ran correctly,
   malformed/stale/dead-publisher failures, Tor/socket recreation, consumer restart and
   recovery; establish CP-down routing independence. No privilege-elevated observer surrogate.
   Required unavailable tests stay NOT RUN/SKIP and cannot close acceptance. A public-internet
   SETCONF exploit is not necessary to justify the already confirmed credential removal.
9. Reconcile foundation-boundaries, applicable control-grpc health timing, torrc explanatory
   contract, normative architecture/plan topology and THREAT-MODEL in this same reviewed repair: explicit Tor-internal publisher
   trust, observer's removed authority, volatile freshness, finite output, failure semantics
   and residual Tor-TCB power. Draft exact reserved THREAT-MODEL/user-facing wording for
   maintainer approval after independent evaluation; do not write it on the strength of this
   ticket draft alone. No constitutional waiver/amendment is included.
10. Retain tests-first pre-fix snapshot/output and identical-command green with
    scripts/test-first-evidence.py; bind live evidence to final executable/image inputs.
    Driver verification and the ordinary independent review gate must pass. Return precise
    refreshed/invalidated evidence to T155; do not mark T155 or its unrelated findings closed.

## Grounded files budget: 36 paths

Inventory anticipates direct implementation/tests and own-change orphans. Final outline
must choose the smallest adequate set; these are a budget, not an instruction to touch all.
Routine in-scope budgeting follows existing pregrants; scope expansion requires its own
resolution. No unrelated cleanup is authorized.

1–3. T203 ticket, STATUS.md, evidence/T203-tests-first.json.
4–5. `data-plane/cmd/tor-observer/main.go`, `main_test.go` (remove raw control; consumer tests).
6–7. Proposed `data-plane/cmd/tor-health-publisher/main.go`, `main_test.go` (fixed producer).
8–9. Proposed `data-plane/internal/torhealth/{health.go,health_test.go}` (bounded shared finite
     state/freshness/parser mechanics if factoring is needed; no new module/dependency).
10–12. `sidecars/tor/{entrypoint.sh,Dockerfile}`, `sidecars/tor-observer/Dockerfile` (package,
     supervise, and build any shared source).
13. `compose/docker-compose.local.yml` (volatile handoff and removed raw-control grant).
14. `scripts/subcommands/init` (provisioning/upgrade/readiness owner).
15–18. `tests/contract/compose/{local_compose_test.sh,control_mount_test.sh,
     network_hardening_test.go,operational_logs_test.sh}` (actual boundary and silent state).
19–21. `tests/contract/stargate-cli/{init_docker_test.sh,init_readiness_test.sh,
     fixtures/fixture-compose.yml}` (provisioning fixtures, lifecycle and readiness).
22–25. `tests/live-e2e/local-topology/{observer.py,test_observer.py,observer_probe.go,
     observer_probe_test.go}` (focused runtime closure and its own test orphans).
26–28. `specs/001-tor-route/contracts/{foundation-boundaries.md,control-grpc.md,torrc.md}`.
29. `THREAT-MODEL.md` (approved exact boundary wording).
30. `tests/contract/torrc/invariants_test.go` (if observer-cookie contract assertion changes).
31. `tests/contract/torrc/render_byte_match_test.go` (if current contract/golden explanatory
     handling creates an orphan; no needless torrc byte change).
32. `specs/001-tor-route/evidence/T203-live-results.json` (sanitized retained closure).
33. `specs/000-architecture/spec.md` (directly affected observer authority/topology text).
34. `specs/001-tor-route/plan.md` (normative topology row; no historical T165 evidence edits).
35. `control-plane/core/src/test/java/app/zcat/stargate/sidecar/SidecarMonitorTest.java`
    (real Java/Go interop fixture now supplies finite publication, not observer raw Tor).
36. `control-plane/runtime/src/test/java/app/zcat/stargate/runtime/StargateControlPlaneTest.java`
    (production boot fixture if affected by the same health producer transition).

T155/T078 dependency/lifecycle filing belongs to the preceding explicit bookkeeping batch,
not hidden T203 implementation scope. Scorecard belongs to its docs: mark T203 done follow-up.
No control-plane production Java/proto wire change is planned; an actual need must be grounded before
expanding this inventory. Existing torrc golden remains unchanged unless a necessary owned
contract correction is established.

## Out-of-scope

T155 resumption-probe/GetStatus work and broad final pass; persistent extension hardening
record; CP wildcard listener; DNS capture integrity; T117/schema disposition; T190/T197/T200/
T201 product work; T202 host-direct proposal; new routes/profiles; generic management broker;
public-network exploit demonstration; constitution or SECURITY-DECISIONS edits; publication.

## Filing and closure dependencies

T155 is deferred-on and blocked by T203; T078 gains T203 as a cumulative closure blocker.
T203 must not depend on T155. Existing T081/T079/feature dependencies through T155 remain.
T155 still cannot complete after T203 while other surviving Majors are unresolved. Preserve
all earlier findings/dispositions/history; this focused owner does not authorize their fixes.

## Build and harness constraints from independent design verification

The current Tor Docker context is `../sidecars/tor`; it cannot COPY a root Go package without
an explicit context/build adjustment. Include new shared packages in both image COPY sets,
init's observer-source manifest and observer.py source_hash. Keep pinned build inputs and
exact image/entrypoint identities. Do not assert request independence by requiring all Tor
commands to stop after an invalid CP request: autonomous fixed sampling continues. Prove
absence of a causal input path instead. Fake-Tor phases must run the actual publisher in
its intended Tor-side boundary and require a sample begun after each phase trigger; cached
READY from an earlier phase cannot satisfy a later one. Keep no false lifecycle events and
no raw diagnostic marker. Historical T165 evidence stays unchanged and historical.

## Constitution VIII impact assessment

T203 materially changes the Tor/observer trust boundary: raw cookie/control access is
removed from the observer; a fixed autonomous publisher inside the Tor artifact/route
TCB sends finite health through a volatile read-only handoff. The publisher retains
Tor's native authority under compromise. Its fixed source commands do not constrain
arbitrary code execution in that component. CP cryptographic identity and authenticated
wire framing, protected routes and deployment listener exposure are unchanged.

This trust-boundary change meets Principle VIII's external-human-review trigger for a
release containing it, regardless of release version. T203's ordinary independent ticket
review and focused live evidence do not satisfy that release obligation or the cumulative
milestone security/privacy and performance/resource reviews. External human review by an
anonymity-systems reviewer must bind the release candidate and this boundary, with material
later changes requiring follow-up. T155 and unrelated surviving findings remain open;
T203 does not authorize publication or claim release readiness.

## Focused implementation evidence

`evidence/T203-tests-first.json` retains the baseline rendered-authority RED and
identical-command GREEN. `evidence/T203-live-results.json` binds the focused guest
results to exact executable/image inputs and harness hashes, with attempt history and
limitations. Baseline production observer probes exposed cookie/socket authority; the
same retained probe executable denies both CP and observer after repair. The final guest
matrix covers finite freshness/file failures, publisher death/stop, observer/Tor recreation,
authenticated CP event mapping and DP forwarding with all health components unavailable.
The two2026-10-03 advisory Majors were repaired under the explicit continuation approval:
actual supported Tor-image build/runtime closes the Dockerfile defect; delayed regular
cookie-I/O RED/GREEN plus one-worker recovery tests close the total-attempt-budget defect.

This refreshes only T155's observer-authority evidence. Historical T164/T165 evidence
remains historical; no other T155 finding or deferred ticket is closed by this result.

Own-change orphans, pre-granted (rule2026-10-01):
`tests/contract/stargate-cli/init_t198_test.sh` supplies the new finite tmpfs inspection
response so its existing key-generation checks are reached;
`tests/contract/security-decisions/tor_package_integrity_test.sh` follows the root-context
COPY paths while preserving all package-integrity rejection controls. Final inventory34
paths remains within36; no budget increase or unrelated scope is included.

The signed-record conversion deliberately interprets an int64 wire field, then rejects
negative/high-bit timestamps. A narrow G115 annotation documents that existing check;
explicit high-bit records test it. Original runtime manifests are preserved separately
from any final source/image identity refresh and binary-equivalence proof in the result.

## Ordinary round 1 disposition

Codex0.160.0 / `gpt-6-astra` high returned REWORK with two Minor findings;
OpenCode1.18.33 / `zai-coding-plan/glm-5.3-flash` xhigh returned
APPROVE-WITH-FIXES with one Minor. The independent complete record vector now
checks both encoder and decoder against contract-pinned bytes; simultaneously
mutating both domain fields to big-endian fails both subtests. The stale Compose
header and architecture auxiliary-container inventory are corrected under
acceptance9's existing internal-document reconciliation scope. This is no new
user approval; the original12 approved reserved replacements remain unchanged.

The round2 evidence section preserves tested source/image identities and records
byte-identical rendered Compose before/after its comment correction. Production
Go/image inputs and the live harness remain unchanged; the test calibration and
internal documentation changes do not claim another live run. Ordinary findings
and actual reviewer identities remain separately recorded from the earlier
user-requested advisory review and its authorized repairs.

The first round2 pair approved all three prior findings. Before commit, the
remaining FR-012 observer raw-mount claim was corrected as a direct own-change
orphan, pre-granted (rule2026-10-01), under acceptance9. This adds
`specs/001-tor-route/spec.md` to the actual inventory:35 paths within36. No
follow-up ticket defers this contradiction. The commit hook also rejected four
file-digest metadata entries as generic credentials; explicit SHA-256 objects
preserve their exact digest values and path associations. No hook was bypassed;
the changed snapshot requires fresh same-round review. No production code,
deployment configuration or live harness changed after the prior approvals.
