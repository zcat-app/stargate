<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Live end-to-end tracker — 001-tor-route

Single place for the release-cadence and foundation live checks the contract
tests (`tests/contract/`) structurally cannot see: real Tor, the real deployed
Compose stack, real kernel packet paths, and the real browser's proxy
decisions. Form per `docs/process/workflow.md` §"Live end-to-end
verification". Owner of the foundation checks: T155 (this file is its Acceptance
4 deliverable). Raw artefacts stay under gitignored `target/`; nothing here
contains a token, key, address or packet payload.

**Rules.** A check that did not run is `NOT RUN`, a check that skipped is
`SKIP`; neither is ever recorded as PASS. Every result retains the snapshot
it ran on. Later changes invalidate affected evidence; record the changed
inputs, affected checks and renewed results. Unaffected evidence may be carried
forward only with an explicit reviewed input/scope comparison, without claiming
the old full source or binary equals the current candidate. Live Tor-network
checks use synthetic tokens and keys only.

## 1. Foundation checks (T155)

Candidate snapshot, hosts and execution results are in the fixed sanitized
*Evidence index* at the end of this file. Commands run from the repository root
of the exact candidate; the definitions below make no execution claim.

| ID | Check (Acceptance) | Class | Command | Prerequisites |
|----|--------------------|-------|---------|---------------|
| F1 | Clean-volume real `scripts/stargate init`; DP binds only host loopback, refuses non-loopback and `::1`; DP-UID TCP/UDP/DNS egress denied with unrestricted-UID positive controls; owner-rule loss/restore; confinement refusals; CP/observer identities; prohibited Tor commands never arrive; CP-down authenticated Tor-routed bytes (A2, A3) | transport-relevant | `STARGATE_LIVE_E2E=1 STARGATE_DISPOSABLE_HOST=1 python3 -B tests/live-e2e/local-topology/run.py` (as root) | Section 2 |
| F2 | Quickstart operator surface on a clean init: `tokens.yaml` + `restart stargate-control` + `scripts/stargate status` (`token delivery: ACKNOWLEDGED(n)`); authenticated reload, post-rotation reload, idle reload (CP down longer than the IPC channel cap), DP restart with CP down restoring the last acknowledged generation, CP-down Tor-routed bytes, revocation, supported rollback (`STALE_CONFLICT`, revocation survives) and recovery, the inter-plane wire gate rows R1–R9 (`tests/contract/compose/inter_plane_wire_test.sh`, mutations enabled), old CP identity refused after rotation, TLS session resumption across a CP key rotation (`wireprobe resume`: the DP resumes an offered ticket before the rotation as a positive control; after it, the actual negative handshake must show the pin-verified selected PSK path and refuse the old identity RPC; a ticket offer or error alone is inconclusive; the old full identity is refused and the rotated identity is answered), authenticated `GetStatus` traffic publication (repeated active-hour absence, real UTC rollover on the same DP, nonzero completed request/byte row immutable after further traffic), separate completed-hour operational aggregates and retention cleanup, logging driver `none`, only-allowlisted state files (A2, A7) | transport-relevant | as root on the guest from the candidate tree: `python3 -B tests/live-e2e/local-topology/t155_stack.py` (exit 0 only when every mandatory check of the selected mode was recorded as passing; an interrupted run is a failure); the traffic phase can take a full real UTC hour; `--only traffic` runs its focused mutation probe; it drives `scripts/stargate init`, the quickstart commands and `tests/live-e2e/local-topology/connect_refusal.py`, and writes `results.json` | Section 2; the Compose project name `t155-stack` and `BUILDX_BUILDER` (default `t165-native`) set in the script |
| F3 | HTTP CONNECT refused with a silent close and no Tor connect (strace-traced), authenticated SOCKS still carries real Tor bytes, snapshot preserved (A3) | transport-relevant | `STARGATE_LIVE_E2E=1 STARGATE_DISPOSABLE_HOST=1 python3 -B tests/live-e2e/local-topology/connect_refusal.py` on an initialised stack | F2's stack |
| F4 | Same target: partitions differing in exactly one axis (profile, device token, first-party site) land on distinct BUILT circuits; the same partition twice shares one (calibration); different destinations separate (A2, A7) | transport-relevant | compile `tests/integration` (`go test -c`), then run `TestStreamIsolationDPUNAMEForwarding` and `TestT126.*` (T126 profile axis plus the T155 `DeviceAxis` and `SiteAxis` subtests, `partition_axes_test.go`), and `TestOnionLoad`, `TestT126PartitionUsernameReferenceVector`, `TestStreamIsolationPerFirstPartyDomain` (T182), each with `STARGATE_RUN_NETWORK_TESTS=1` | Section 2; provisioned test-project volumes (keys, token) as in `tests/integration/*_test.go` headers |
| F5 | Real-browser connection probes with the real extension: descriptor matrix, blocked-proxy, private-window access and the full T157 set (A7: no Direct fallback) | transport-relevant | Section 3 | Pinned Mullvad Browser, geckodriver, `strace` |
| F6 | `scripts/verify.sh` on the exact candidate (A2) | transport-invisible | driver runs it | none |
| F7 | Docker tier of the T162 enforcement test: the installer's confinement refusals and the abstract-socket denial with a byte-exchange control, after T198's `init` af_unix gate (A3) | transport-relevant | `STARGATE_TEST_TAGS=docker bash tests/contract/stargate-cli/t162_enforcement_test.sh` on the guest | Section 2 |

Hermetic coverage of the same properties (reload, pin, resumption, partition
and revocation unit/contract tests) runs in `scripts/verify.sh`; it is not a
substitute for F1–F5 or F7 and a green `verify.sh` is not live evidence. One of
these tests checks the live probe itself:
`tests/contract/compose/wireprobe/wireprobe_test.go` requires `wireprobe resume`
to fail against a DP stand-in that pins only full handshakes, and against one
that issues no tickets.

### Preserve / reset

- **Reset every run:** the Compose project and its volumes (`down --volumes`),
  `tokens.yaml`, CP SQLite state, DP `dp-snapshot.json`, the generated keys
  and pepper, and the browser profile (always a fresh ephemeral directory).
  `run.py` (F1) refuses a pre-existing `stargate-dp` AppArmor profile or owner
  rule and removes what it installs. F2 and F4 do not: `scripts/stargate
  init` and the test provisioning leave the profile, the UID-5102 owner rules,
  locally built and retagged images and, after a failed F2 run, its `/root`
  state backups on the host. That is why the host is disposable, F1 runs first
  on a freshly booted guest, and a rerun of F1 needs a reset or a reboot.
- **Preserve across runs:** only the VM base image and the pinned browser/driver
  archives. The DP cold-start cache (`dp-snapshot.json`, `data-model.md` §1.4)
  is *not* a live-test artefact: F2 deliberately exercises it within one run
  (restart restores the last acknowledged generation; a rolled-back CP set is
  refused) and discards it with the volumes.
- **Browser release-cadence profile check** (section 4, R-6) records actual
  shipped and effective preferences. T205 removed the persistent hardening
  audit key; current runtime state is volatile. T200 still owns shipped
  DoH/HTTP3 profile defaults. Injected probe preferences do not certify them.

### Transport-relevant versus transport-invisible

- **Transport-relevant (live only):** real Tor reachability and circuit
  isolation, packet-level DP egress denial and its positive controls, CP
  namespace absence of raw Tor control, real DNS resolver behaviour, deployed
  init/provisioning, container restart/ordering behaviour, the real browser's
  proxy decisions (Direct fallback, private windows, cache, startup order).
- **Transport-invisible (stays in contract tests):** SOCKS5 byte sequences,
  error-template literals, proto schema, token-file parsing, HMAC/pin logic in
  isolation, aggregate bucket arithmetic, request-label derivation.

## 2. Environment: disposable host (VM)

The Local topology needs the `stargate-dp` AppArmor profile and owner iptables
rules, so the checks run only on a disposable Linux Docker host with root,
AppArmor, Landlock ABI >= 4, seccomp TSYNC, `tcpdump`, `ip`, `ss`, `strace`,
IPv4/IPv6 iptables and Go. An independently booted QEMU guest (own kernel and
namespaces) is the approved host; record whether the host is a VM. Procedure
used for the foundation pass: boot the saved guest image from a per-ticket
copy, ship the candidate's tracked and staged files as one tar and record its
SHA-256 with the changed-file hashes, commit that tree to a throwaway
repository in the guest (`run.py`'s observer helper records `git rev-parse
HEAD`, which is then that local commit, not a project commit), compile the
integration test binary on the host with the guest source path mapped, and run
the phases in order. `run.py` refuses a host that already carries the
`stargate-dp` profile or owner rules, so it runs first on a freshly booted
guest. Stop owned VMs afterwards and retain the per-ticket copies and attempt
records for review; the saved base remains unchanged.

## 3. Real-browser probes (host)

The reference browser is Mullvad Browser; the extension refuses a browser older
than Gecko 153 (`minVersion` 153.0). The distribution's `/usr/bin/mullvad-browser`
may be older and is not used. Use a pinned Mullvad Browser (the foundation pass
used 153.3.0esr extracted under `target/t157-tools`) with geckodriver; probes use
disposable ephemeral profiles and bind only host loopback listeners (8881 among
them), so **do not run anything else that binds those ports or launches
browsers while they run**.

```sh
bash extension/package.sh
for m in descriptor-matrix blocked-proxy private-access full; do
  python3 tests/live-e2e/mullvad-browser-hardening/probe.py \
    --browser <pinned>/Browser/mullvadbrowser --driver <geckodriver> \
    --extension extension/dist/stargate-extension.zip --only $m \
    --report-out target/runs/<run>/$m.json
done
```

Each report must say `GREEN` with no failures. Record the shipped template,
actual effective settings and any injected preferences separately. Probe
settings do not establish T200's still-pending shipped DoH/HTTP3 defaults.
The browser default of `media.peerconnection.enabled` is true. Details and
mutation modes: `tests/live-e2e/mullvad-browser-hardening/README.md`.

**Real-browser hardening / token-failure probe (tracked).** T186
(`--only descriptor-matrix`, `--only blocked-proxy`) and T188 (`--only
private-access`) are the real-browser probes for unintended Direct fallback on
hardening failure, missing or malformed token, closed sidecar and
private-window access loss. Packet attribution is by calibrated catchers (a
destination listener, an ordinary-HTTP-proxy listener, a SOCKS impostor and a
resolver observer that combines `strace` of port-53 sockets with `MOZ_LOG`
`nsHostResolver`), each with an in-session positive control and a Tor-route
positive control; an incomplete request is a failure. This is attribution at the
browser's own sockets, not a host NIC capture: see R-3 below.

## 4. Release-cadence checks that remain required

Not run by T155 and **never recorded as PASS here**. Each must be run on the
release candidate and recorded with snapshot and evidence before a release tag.

| ID | Check | Class | Why it stays open |
|----|-------|-------|-------------------|
| R-1 | T034a SC-003 hand-driven measurement: fresh Mullvad Browser profile, 10-minute `.onion` session through the Local stack, Wireshark on `lo` and egress NIC, zero `.onion` DNS | transport-relevant | needs a stable browser on a reference workstation; record in `tests/integration/sc003_dns_leak.md` |
| R-2 | T034f egress-consensus capture: every SYN on the host egress NIC during a >=120 s routed window is in the live consensus | transport-relevant | needs the live consensus and a physical/real NIC capture; a VM NIC is not that |
| R-3 | Real-browser packet attribution on a host NIC for the F5 scenarios | transport-relevant | F5 attributes at the browser's own sockets and resolver, not on the wire |
| R-4 | T070a mid-request circuit drop (no retry, no synthesised bytes, leak-corpus scan) | transport-relevant | needs the control-port helper against a live circuit |
| R-5 | **Browser launch and session restore** with the stable supported browser: the extension's startup ordering (credential read vs the first protected request after process launch, restored tabs, cache-served protected subresources). T157's startup scenario only delays extension initialisation inside a running browser; a browser-process launch/session-restore experiment does not exist yet, and no live scenario covers a cache-served protected subresource. Obligation: run before every release and after any change to `extension/background/*`, `browser-profile/`, or the pinned browser version | transport-relevant | not automatable with the current probe |
| R-6 | Hardening profile check (`tests/live-e2e/mullvad-browser-hardening/run.sh`: Part 1 prefs, Part 2 runtime WebRTC gate) on a profile built from the shipped `browser-profile/user.js`. The foreign-extension inventory that `run.sh`'s Part 2 text names does not exist (T197 item 3) | transport-relevant | release cadence; a falsifier run on 2026-10-03 found Part 1 RED on a template-only profile (DoH and HTTP/3 prefs absent from `user.js`), see the T155 ticket |
| R-7 | Routed IPv6 egress, LAN and VPS profiles, physical NIC and hypervisor behaviour | transport-relevant | a VM whose only routed IPv6 is QEMU's site-local `fec0::/64` user network and a loopback-only Local profile establish none of these (THREAT-MODEL §3.1) |
| R-8 | Stable (non-Alpha) supported browser channel and LibreWolf tested-secondary | transport-relevant | the foundation pass used the pinned Alpha-channel build |

## 5. D-live decisions

- **D-live-1 (host).** The QEMU guest is the approved measurement host for the
  Local topology; its results are guest-kernel claims only (not physical NIC,
  routed IPv6, LAN/VPS or hypervisor). Reaffirms the T163/T165 decision.
- **D-live-2 (IPv6).** The QEMU user network hands the guest a `fec0::/64`
  route. Attempt 3 disabled guest IPv6 because `run.py` refused that route.
  Since T196, `run.py` probes a site-scope address like a global one, so guest
  IPv6 stays enabled and F1's IPv6 packet matrix, forwarder, resolver and
  listener refusal run on that path. A physical routed IPv6 network is R-7,
  never PASS.
- **D-live-3 (browser build).** The extension refuses Gecko < 153, so the host
  distribution browser (140 ESR) is not used. The probes run the pinned Mullvad
  Browser 153.x in disposable profiles. This is an Alpha-channel build (R-8).
- **D-live-4 (credentials).** Only synthetic bearer tokens, synthetic keys and
  throwaway projects. Evidence directories can hold the host's source address and
  stay local; reports are summarised, never pasted.
- **D-live-5 (observation).** Operational journal policy is verified by absence:
  logging driver `none` on every stack container and only the allowlisted state
  files in the CP and DP state volumes; no health history or per-request log is
  restored for the test.
- **D-live-6 (no SKIP-to-PASS).** A live check that skips or cannot run is open.
  Results keep their actual snapshots; changed inputs invalidate affected evidence
  and require renewal. An explicit reviewed input/scope comparison can carry
  unaffected property evidence forward, never substitute for a missing live result.
- **D-live-7 (harness defects).** A harness defect found during a pass is
  reported and fixed by a ticket; a pass in which the defective check failed is
  recorded as failed for that check, with the independent evidence listed beside
  it, not as passed.

## Evidence index

The T155 ticket is authoritative for lifecycle, historical dispositions and exact
Acceptance 6. The fixed result record is
`specs/001-tor-route/evidence/T155-live-results.json`; the candidate-bound red/green
pair of the combined D1/TLS command and the preserved earlier records are in
`specs/001-tor-route/evidence/T155-tests-first.json`. The result record separates this
pass from earlier attempts, which it keeps unchanged under `superseded`.

- **Snapshot.** Executable content is commit `f5558925547e81737987ea8ea34f6c09495e051d`
  (T155's START after T208 raised the data plane's upstream deadline to 250 s), plus
  the T155-owned test and harness delta. The result record holds the shipped archive
  hash, a per-file manifest hash, the data-plane tree hash (the same tree T208's
  final candidate had) and the integration test binary hash. A guest archive commit
  is not the project HEAD. T155 ships no product change.
- **Hosts.** F1-F4 and F7 ran on one fresh per-ticket copy of the saved QEMU TCG
  guest with IPv6 enabled. F5 ran on the host with the pinned Mullvad Browser
  153.3.0esr and geckodriver 0.37.0 in disposable profiles. Versions and binary
  hashes are in the result record.
- **Final pass, 2026-10-05.** Each of F1, the full F2 command (F3 runs inside it),
  both F4 suites, the four F5 modes and F7 was executed once on that candidate and
  ended without a failed or skipped check; no phase was repeated. The mandatory HTTPS
  onion load (`TestOnionLoad`) completed on its first attempt after 91.86 s, longer
  than the former 30 s deadline. Per-check counts, timings and raw-log hashes are in
  the result record, with its stated limits (one emulated guest, one evening, public
  onion availability).
- **Harness change after the pass.** Review found that `t155_stack.py` could exit 0 on an
  interrupted or incomplete run. Its entrypoint now exits 0 only when every mandatory
  check of the selected mode was recorded as passing; `test_t155_stack.py` covers it
  hermetically. The F2 result above came from the earlier entrypoint and is carried
  forward under D-live-6: the recorded `results.json` was checked against the new
  mandatory list (nothing missing, nothing failed) and no check body changed. Details
  are in the result record (`f2_carry_forward`). F2 was not run again.
- **Isolation limits.** Reusing one token on multiple devices identifies them as one
  authenticated device; copying a browser profile can copy its profile ID.
- **Evidence renewal.** T208 changed the data-plane binary, so every check that
  deploys it or runs the integration binary was executed again. No result taken on
  2026-10-04 or earlier is evidence for this candidate. Those attempts, including
  the two `TestOnionLoad` failures and the full F2 run that failed two checks on
  2026-10-04, keep their original baselines and hashes in the superseded records.
- **Where.** `target/runs/T155r/` holds the ignored wrappers, shipped archive,
  manifest, raw logs, guest evidence and browser reports of this pass. Earlier
  attempt paths and the original review history remain preserved.
- **Release residue.** R-1 to R-8 remain outside this foundation pass. T206's
  capture-integrity Minor blocks T078/T081; controls in other captures do not
  establish zero drops in that harness. T078/T079 remain pending under exact A6.
