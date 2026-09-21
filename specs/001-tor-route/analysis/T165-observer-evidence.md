<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# T165 observer deployment evidence

## Candidate and scope

T165 extends the Local topology runner with CP and observer identity, mount,
network, image-source, health, fake-control non-arrival, restart and packet
checks. Raw captures and run logs stay under gitignored `target/live-e2e/`.
The independently booted guest is the measurement host; a VM result is a
guest-kernel claim, not a physical-NIC or hypervisor-isolation claim. LAN/VPS
remain undeployed. T155 must separately consume this evidence with the other
foundation checks before asserting feature-wide compliance.

## Tests-first and local gates

- The status-table regression first failed because `stargate init` omitted
  its deployed observer (`target/runs/T165-status-red.log`), then passed after
  the output reported `Tor observer` as `RUNNING` without implying a valid
  health sample (`T165-status-green.log`).
- The observer-boundary verdict test failed when a full Tor-state mount and
  Docker socket were incorrectly accepted, then passed after both were
  rejected (`T165-boundary-red.log`, `T165-boundary-green.log`).
- The Tor-native healthcheck verdict test failed when a CP-fabric probe was
  accepted, then passed after requiring Tor's own cookie, private control
  socket and fixed bootstrap command (`T165-healthcheck-red.log`,
  `T165-healthcheck-green.log`).
- The packet verdict test failed when its positive control was absent, then
  passed after requiring a visible CP-namespace control and zero packets
  toward the Tor control address (`T165-capture-behavior-red.log`,
  `T165-capture-green.log`).
- A first integration of the live module broke the existing stdin probe
  import path. Moving that import to the live driver restored the complete
  local-topology selftest (`target/runs/T165-topology-selftest.log`). This
  was an observed runner regression, not evidence about the deployed stack.
- The first guest run exceeded the 120-second cold Go compile budget before
  deployment. A separate unbounded compile completed in the guest and warmed
  the cache. The second run exposed a real clean-host startup failure: Compose
  could not parse the observer image requirement during init's early DP stop,
  before an image digest existed. The operator command independently returned
  `cannot stop existing DP before checking host policy` with exit 60. A
  parse-only zero digest scoped to that `stop` command lets the verified build
  continue; it is never written to the env file or used for `up`. The focused
  contract was red before and green after (`T165-clean-init-red.log`,
  `T165-clean-init-green.log`). The failed runs are not deployment evidence.
- The software-emulated observer build was canceled after it used more than
  eight minutes before reaching the rest of the stack. A pinned native
  BuildKit worker was connected to the guest's Buildx client. Its first
  observer build proved another init gap: a remote Buildx result remains in
  worker cache without `--load`, so the guest daemon cannot inspect or pin
  it. The direct build printed the no-output warning. The installer now
  chooses `docker buildx build --load` only when `BUILDX_BUILDER` is set; the
  normal local `docker build` path is unchanged. The focused test was red then
  green (`T165-buildx-red.log`, `T165-buildx-green.log`). This is a build
  transport correction, not a change to the observer image contents.
- A retry with the guest's root-owned Buildx context reached a four-service
  deployment with Tor healthy. It passed into the existing topology runner,
  then failed its IPv6 egress probe because QEMU advertised a default route
  via `fe80::2` without assigning a usable global IPv6 source address. The
  guest's unusable advertised default route was removed and RA acceptance
  disabled on its virtual NIC; loopback IPv6 remains enabled. The failed
  attempt (`T165-vm-live-native-root.log`) is not counted as a topology or
  observer pass.
- Under QEMU 8.2.2 TCG, the Temurin 25 control-plane JVM later crashed in
  `DefNewGeneration::copy_to_survivor_space`. That guest run cannot establish
  deployment behavior. Rebooting the same disk with Debian's QEMU 11.1.1
  package avoided that emulator failure. The QEMU 11 run
  (`T165-vm-qemu11.log`) passed the existing T163 Local topology phases,
  including bind refusal, IPv4 packet capture, Tor fabric caller matrix,
  owner-rule loss, DP restart, reinit and mandatory confinement failure.
  It then reached the new observer checks and found that `docker cp` rejects
  writes into CP's read-only root filesystem even at its writable `/tmp`
  tmpfs. The harness now places its executable in the disposable CP config
  volume. This is a harness repair, not a production mount change.
- The first focused observer rerun (`T165-vm-observer-debug.log`) passed
  container identity, mount, immutable image and source-hash checks. Its
  packet recorder failed its startup check because tcpdump emitted another
  line before the `listening on` line. The recorder now consumes startup
  output through that readiness line. The failed focused run is not a
  deployed-boundary PASS.
- The next focused run (`T165-vm-observer-debug2.log`) passed the CP
  namespace capture with a visible loopback control and no Tor-control
  packet. A later negative request probe exited on an unlabelled socket
  error. The mode-labelled retry (`T165-vm-observer-debug3.log`) identified
  the `request` case: a malformed request whose unread bytes cause Linux to
  report the observer's zero-byte close as `ECONNRESET`. The probe now
  accepts only a zero-byte reset/broken pipe as a refusal; a token, other
  bytes or a timeout still fail. Neither partial run is a matrix PASS.
- The preserved fourth focused run (`T165-vm-observer-debug4.log`) passed
  the full fake-control response matrix, Tor socket recreation, observer
  restart/down recovery, and raw-marker scans. The disposable token was
  validly enrolled in CP's SQLite state, but its first CP→DP gRPC push missed
  the client's five-second deadline under QEMU TCG; DP kept its last-known
  list and correctly rejected the new token. A manual supported CP restart
  re-read the same file and DP then authenticated the token. This is
  evidence of the documented next-boot resync, not a first-attempt push PASS.
- The original CP-down positive fixture bound a fake SOCKS socket from the
  guest host. DP's AppArmor profile correctly refused it: the resolved file
  path was the host Docker-volume path, whereas the production Tor hardlink
  resolves to Tor's private socket path. No AppArmor rule was widened. With
  CP stopped and real Tor running healthy, the same enrolled token
  authenticated at DP; SOCKS CONNECT to `example.com:80` through the real
  Tor sidecar succeeded and returned HTTP response bytes. The manual probe
  printed only a SOCKS success code and PASS, not the token or response.
  The live harness now uses this actual Tor path, with a bounded CP startup
  resync retry for TCG scheduling variance.
- Round-one review found that the fake-control matrix had paused the
  production CP sampler, leaving the deployed CP→DP event mapping unmeasured.
  It also found that absent/wrong authentication and missing EOF had not been
  checked for Tor-command non-arrival against the fake listener, and that the
  observer's own key volume mode was unchecked. Mutation verdicts failed
  before those checks were implemented (`T165-r2-verdict-red.log`) and passed
  after (`T165-r2-verdict-green.log`).
- The first round-two focused VM run (`T165-r2-vm-observer-debug.log`) exposed
  a test orchestration error: `docker compose start tor-observer` followed its
  `depends_on` edge and restarted real Tor, bypassing the fake listener. A
  preserved-stack probe confirmed that direct `docker start` of the existing
  observer container left Tor stopped and produced the exact fixed command
  sequence. The focused deployed CP→DP event sequence then passed. That run
  is a harness diagnostic; the final clean-volume run below is the deployment
  verdict.
- The first full round-two run (`T165-r2-vm-final.log`) passed T163 and the
  fake-control matrix but observed no STARTED event after CP's restart: socket
  creation plus a fixed delay had not established that DP's live WatchEvents
  stream had reattached. The readiness verdict failed first
  (`T165-r2-stream-red.log`) and passed after requiring an established
  `control.sock` connection (`T165-r2-stream-green.log`). A later focused
  disposable run (`T165-r2-vm-stream-debug.log`) captured that connection
  before observer start and passed the exact deployed event matrix and CP-down
  forwarding. Its first CP JVM boot retried after a QEMU scheduling-related
  SQLite acquisition timeout; the focused pass relies on the subsequent real
  CP boot. The failed full run is not counted as deployment evidence.
- A full clean-volume run with stream readiness (`T165-r2-vm-final2.log`)
  passed T163 and T165, including CP-down forwarding. Before review, a
  command-recorder audit found that its sample cursor could advance past a
  command appended immediately after the expected triplet. A mutation test
  failed first (`T165-r2-command-red.log`); the revised cursor consumes only
  the expected names, checks the complete ordered command stream after CP
  stops sampling, and retains that trace (`T165-r2-command-green.log`). The
  passing run on the prior harness revision is retained as diagnostic evidence;
  the final run below exercises the reviewed recorder behavior.

## Disposable host and production run

The shared workspace Docker host runs unrelated containers and was not used
for Local live probes. A disposable Ubuntu 24.04 guest was booted under QEMU
11.1.1 TCG with four virtual CPUs and 6 GiB RAM. Its cloud-image SHA-256 is
`612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354`,
the same verified image recorded by T163. The guest reports Linux
`6.8.0-139-generic`, Docker 29.1.3, Compose 2.40.3 and Go 1.26.3. The
VM image, SSH identity, source bundle and toolchain transfer are ignored
local artifacts under `target/t165-vm/`.

The final full run used a fresh project and volumes via the supported
`scripts/stargate init` path, followed by
`STARGATE_LIVE_E2E=1 STARGATE_DISPOSABLE_HOST=1
STARGATE_HEALTHCHECK_TIMEOUT=300 python3 -B
tests/live-e2e/local-topology/run.py` in the guest. The guest's remote native
Buildx context supplied `BUILDX_BUILDER=t165-native`; the QEMU IPv6 virtual
NIC had no routed source address, so the explicit no-IPv6-egress branch ran
with IPv6 loopback controls. The run exited 0 at
`target/runs/T165-r2-vm-final3.log`; it cleaned the project containers, ten
volumes, owner rules and AppArmor profile. All pre-existing T163 phases
passed: bind refusal, IPv4 source/egress/loopback controls, no marked DP
TCP/UDP/DNS, Tor socket caller matrix before/after restart, individual and
combined owner-jump loss, DP restart, reinit, and mandatory
Landlock/seccomp failure and recovery.

The tested source base was `10be7d646298c8d29cb4cb31b6495b95d0f0cd50`.
The `run.py`, `observer.py` and `observer_probe.go` source SHA-256 values in
the guest matched the checkout, respectively:
`84d5c29ff09d1b456846cfda3ebed907aa01e2c01c0a1b9ed3cc5e3198de86f1`,
`62d076e23d74dc51278c8a23f3f551618f51aa18df26ae2089f9e091b16ace7d`,
and `d3b316c9af6539d8ba2cfc85ecc71cf101934cdb7228ffc1887c41786ff31906`.
The deployed observer's immutable image ID was
`sha256:65e3ae7ae05c10d036605ff04ffd9ca6525d38ea844c8d4e6f0c9a8753734173`;
its source label matched the tested source manifest SHA-256
`aa0a0d2abdcfa871a83f6972d574115db4e02aaf4bffe23b919f08132ef6e5bd`.

The production CP ran as `5101:5100` with no Tor-cookie group, raw-control
socket, cookie, SOCKS fabric, observer private key or IP network. The observer
ran as `5103:5100` with only Tor's `control` subpath, its own read-only key volume, and
the CP health fabric. Tor's native Docker healthcheck still authenticated
against its own private cookie and control socket. The CP namespace packet
capture saw seven packets for the loopback positive control and an expected
loopback TCP refusal at `127.0.0.1:9051`; it saw no packet to Tor's bridge
control address. Tcpdump reported zero kernel drops. The running CP probe
obtained an authenticated finite health token, while absent/wrong
authentication and malformed/extra/missing-EOF requests received no token.

Against the disposable fake Tor control listener, wrong/absent authentication,
missing EOF and thirteen prohibited CP inputs reached no Tor command or token.
Valid READY and NOT_READY samples each sent
only `AUTHENTICATE`, `GETINFO status/bootstrap-phase`, `QUIT`; malformed
reply produced UNAVAILABLE with the same bounded command set, and timeout
produced UNAVAILABLE after `AUTHENTICATE`, `GETINFO`. The complete fake Tor
trace contains 42 command names in that bounded order, with no configuration,
stream, circuit or lifecycle command. An established CP `control.sock` stream
was observed before the production monitor's first valid sample. DP then
received exactly STARTED, HEALTHY, UNHEALTHY, HEALTHY, UNHEALTHY, HEALTHY,
with the fixed details `container_start`, `healthcheck_pass` and
`healthcheck_fail`; repeated valid, malformed and timeout samples added no
duplicate or false STOPPED/CRASHED/RESTARTED event. The malformed raw marker
appeared in no CP/observer/DP logs or CP state/audit file. Tor socket
recreation and observer restart/down recovery passed. A disposable 32-character token
was enrolled by CP and delivered to DP on the first startup attempt. With CP
stopped and Tor natively healthy, DP still authenticated that token and
returned destination HTTP bytes from a SOCKS CONNECT through real Tor. The
token and destination response bytes were not retained in the evidence.

The guest's raw artifacts were copied to
`target/live-e2e/T165-vm-20260921-190436/` (gitignored):
`T165-observer-identity.json`, `T165-cp-any.pcap` and decoded text,
`T165-probe-matrix.json`, `T165-control-stream.txt`, `T165-cp-events.json`,
`T165-token-reload.txt`, `T165-cp-down.txt`, and
the T163 control captures. The transfer archive's SHA-256 matched in guest
and checkout:
`2590a79bbe1d66940954a54acca4dd0a3ed93a74eba93220b8fb0369a0d5341b`.
The transient token file was in a removed disposable Docker volume; it and
the compiled probe were excluded from the copied artifacts.

**Verification and review:** the exact `scripts/verify.sh` gate returned
PASS=26, SKIP=1, FAIL=0 (`target/runs/T165-r2-verify-final.log`); the one skip is
the documented release-cadence reproducibility gate. The task driver re-runs
the gate on the staged pre-review snapshot. T165's independent reviewer set
is the remaining ticket gate. The measured Local guest boundary does not
claim routed IPv6, physical-NIC behavior, LAN/VPS, hypervisor isolation,
browser fallback or release conformance; T155 remains pending for those
integrated checks.
