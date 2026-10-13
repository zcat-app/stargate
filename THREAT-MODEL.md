# Stargate Threat Model

> **Current compliance status — T156, 2026-09-12.** This document distinguishes required
> protections from known implementation gaps. The constitution and feature 001
> [foundation boundary contract](specs/001-tor-route/contracts/foundation-boundaries.md)
> supersede older topology, operational logging, counter-publication and auth-recovery claims.
> T125 is not constitutionally accepted. T134/T138/T152/T157–T159 and the other foundation
> repairs remain pending; no repaired runtime or live pass is claimed by this amendment.

**Status**: Draft
**Last updated**: 2026-10-12
**Derives from**:
- `.specify/memory/constitution.md` v1.0.0 (with the pre-release T091 amendment to Principle III bullet 3) (Principles III and V)
- `specs/000-architecture/spec.md` (concrete ports, profiles, sidecars)

---

## 1. Purpose

This document states **what Stargate protects against, what it does not, and
who must be trusted in each case**. It is the artefact required by
Constitution Principle V ("Honest Threat Model") and the primary input to the
`stargate-redteam` adversarial reviewer at every milestone (Principle VIII).

What this document **is**:

- A per-deployment-mode (Local / LAN / VPS) and per-route
  (Direct / Tor onion / Tor clearnet exit / I2P / Nym) statement of
  protections, residual risks, and trusted parties.
- A reference a privacy-conscious user can read to decide whether Stargate's
  shape matches their threat model.
- A reference a security reviewer can use to falsify Stargate's claims
  against deployed behaviour.

What this document is **not**:

- A guarantee. Stargate is best-effort software (Constitution Non-Goals);
  no uptime, anonymity, or unobservability is guaranteed beyond what the
  underlying networks' designs support.
- A substitute for the design papers and specifications of Tor, I2P, and
  Nym. Where those documents and this one disagree about anonymity
  properties, **those documents win**; please file an issue so we can fix
  the wording here.
- A statement about device security. OS-level attackers, malicious local
  software, and physical access are out of scope (§6).

Conflicts between this document and the constitution are resolved by
amending whichever is wrong. The constitution remains authoritative for
design decisions; this document is authoritative for *threat statements
about an implementation that satisfies the constitution*.

---

## 2. Adversary classes

The actors below are the threat model Stargate is designed against. Each
entry lists **what the actor can observe** and **what the actor can
manipulate**. Capabilities are stated so an auditor can verify or falsify
them against a running deployment.

### 2.1 Passive observer on the local link

A party with packet capture between the user's device and the next-hop
router (e.g., a roommate on the same Wi-Fi network, an employer on the same
corporate LAN, an attacker who compromised the access point but is observing
only).

- **Can observe**: layer-2/3 headers of all packets, byte counts, timing,
  TLS SNI (where unencrypted), destination IP addresses.
- **Cannot observe** (when the data plane is correctly configured):
  ciphertext inside an established TLS or WireGuard tunnel.
- **Can manipulate**: nothing (passive by definition). See §2.3 for the
  active variant.

### 2.2 Passive observer on the upstream link

The user's ISP, an upstream transit network, or an observer at any hop
between the Stargate host's egress NIC and the first hop of the chosen
anonymity network (e.g., a Tor guard relay, an I2P peer, a Nym gateway).

- **Can observe**: that the host is sending traffic to a Tor guard / I2P
  peer / Nym gateway / clearnet destination; byte counts; timing patterns.
- **In VPS mode**: by construction, this observer sees only an encrypted
  WireGuard tunnel between the user's device and the VPS. The VPS's ISP
  becomes the passive observer of the actual anonymity-network connection
  (see §3.3).
- **Cannot observe**: payload inside the tunnel to the next-hop anonymity
  node.
- **Can manipulate**: nothing (passive).

### 2.3 Active network-level adversary

Same vantage as §2.1 or §2.2 but also able to inject, drop, modify, or
delay packets.

- **Can observe**: as in §2.1–§2.2.
- **Can manipulate**: drop or delay packets (causing connection failures
  or measurable latency shifts that may aid traffic-confirmation attacks
  [Murdoch & Danezis 2005]); attempt downgrade (e.g., strip outer TLS).
  Cannot forge content end-to-end-protected by the anonymity network's
  own crypto.
- **Cannot**: defeat Tor's authenticated TLS to guards, decrypt onion-layer
  cells, decrypt Sphinx packets, or impersonate an I2P peer without that
  peer's key.

### 2.4 VPS provider (VPS mode only)

The hosting provider for the Stargate VPS instance, in the deployment where
Stargate runs on a remote VPS.

- **Can observe**: the egress traffic of the Stargate container at the
  hypervisor level — packets to Tor guards, I2P peers, Nym gateways,
  clearnet destinations; byte counts; timing patterns; the contents of the
  WireGuard tunnel after termination on the VPS (because the WireGuard
  endpoint is inside the VPS).
- **Can manipulate**: anything on the VPS. They control the kernel and can
  read process memory.
- **Cannot**: decrypt anonymity-network ciphertext beyond what its design
  exposes at the endpoint they observe (i.e., they see the same thing the
  VPS's ISP sees, plus whatever the running Stargate process is doing).

Trust statement: **In VPS mode the provider is in the privacy TCB.** Choose
a jurisdiction and provider accordingly. See §3.3 for residual risks.

### 2.5 Hostile destination

The website, onion service, or peer the user's request ultimately reaches.

- **Can observe**: everything an HTTP server normally sees from the chosen
  route — request headers chosen by the browser, the request body, the IP
  address visible to it (the Tor exit / I2P egress / Nym egress / Direct
  egress as applicable), TLS fingerprint, JS-derived signals (timing,
  feature support, fonts).
- **Can manipulate**: response content, including content designed to
  exfiltrate identifying information through legitimate browser APIs.
- **Cannot**: see anything Stargate does not pass them. Stargate adds no
  headers, performs no payload modification, and does not interpose
  certificates (Principle I).

Note: hostile destinations are explicitly out of Stargate's scope
(Constitution Non-Goals; §6). Browser-level hardening (Mullvad Browser
defaults; uBlock Origin; no foreign extensions) is the user's defence.

### 2.6 Compromised sidecar

A sidecar container (Tor, i2pd, Nym client, WireGuard) running a malicious
or backdoored binary.

- **Can observe**: everything traversing that sidecar. A backdoored Tor
  image, for instance, sees the SOCKS5 destination requests, the Tor
  circuit state, and any cleartext that would be visible at a Tor exit.
- **Can manipulate**: routing decisions inside its own protocol, the
  contents of its own log files, its responses to the proxy.
- **Cannot**: directly read the contents of *other* sidecars, the
  control-plane database, or the inter-plane gRPC keys — these are isolated
  by Docker's mount namespaces and per-volume mounts (architecture spec
  §4.3).

T203's required design includes a fixed health publisher in the Tor image and Tor's
per-route TCB. It holds Tor's native cookie/control authority and autonomously reads
only bootstrap status in normal operation. It accepts no observer/CP requests,
configuration, paths, keys or writable shared input. Its fixed command sequence does
not restrict an attacker executing code as the publisher: that attacker retains Tor's
full native control authority. Publisher compromise is therefore a Tor-TCB compromise.
The publisher joins the Tor launcher in the executable/build closure that must be reviewed.

The mechanisms below describe T203's required repair. T203 must record implementation
and validation status; any verified result must identify the exact candidate and tested
environment. This description does not itself establish a verified result. T155 owns
integrated foundation closure. Historical T164/T165 results do not validate the
replacement boundary.

Each sidecar is in the **per-route privacy TCB**. Pinned-digest selection
and the contract-test gate (Principle IV; architecture spec §7) are the
mitigations, but neither eliminates the risk. For the Tor sidecar
specifically, the build inputs are pinned to a `snapshot.debian.org` run
with explicit `=version` pins (T099). Those pins alone did not freeze the
closure: snapshot InRelease files carry no Valid-Until, so an on-path attacker
could replay an older signed index over HTTP (libssl3 3.0.20 → 3.0.17). T184
pins the snapshot InRelease hash and checks the installed closure against the
committed `sidecars/tor/package-closure.lock` in every build, so a clean
rebuild selects the reviewed packages (incl. `libssl3`) or fails — but this
makes the binary *auditable*, not *trustworthy*: the closure still rides Debian's archive key, and a
malicious-but-behaviourally-conforming library is undetected. See §5.8,
§5.9, and `SECURITY-DECISIONS.md` §"Debian archive snapshot pin".

**T160 security update (2026-09-12).** The selected Tor package is now
`0.4.9.12-1~d12.bookworm+1`, addressing the upstream security release that includes
client memory-safety, availability and Conflux stream-isolation fixes. The build verifies
amd64/arm64 package hashes independently of the mutable signed repository index before
installing the checked local file. This prevents same-version package replacement from
silently changing the reviewed bytes. Dependency resolution and offline installation enable only
the pinned Debian snapshot source, excluding the mutable Tor repository from the rest of the
executable closure. This also prevents a compromised Tor publisher from bypassing the Tor hash
through replacement dependencies; repository priority alone is insufficient for same-version
source isolation. The key, base and Debian snapshot trust remain;
malicious reviewed upstream code and the remaining foundation defects are not solved by
a version/hash check. Protocol/build results and their limits belong to T160 evidence. Its two
cold T058 attempts remain preserved failures: both stopped during descriptor loading and produced
no circuit evidence. T161 subsequently ran the unchanged exact candidate twice from cold state;
both same-target, distinct-credential probes reached bootstrap and attached to distinct circuits.
Independent cold configuration/control probes and a fusion-sensitive username-less control also
passed. A separate cold start lingered during descriptor loading before completing, demonstrating
run-to-run network variability without establishing the earlier failures' root cause. This clears
only the Tor-side upgrade validation gate. T126/T155 still own integrated partition forwarding and
constitutional validation, and T134/T138 still own topology/observer authority. See
[T161 evidence](reviews/T161/README.md), the dated T160 entry in SECURITY-DECISIONS.md and the
[official release announcement](https://forum.torproject.org/t/security-release-0-4-9-12/22096).

**T177 security update (2026-09-26).** The selected Tor package is now
`0.4.9.13-1~d12.bookworm+1`, following Tor's 2026-09-23 high-severity security
release. This supersedes T160's package selection while retaining its independent
amd64/arm64 content locks, checked local-file installation and Debian-only dependency
closure. The upstream announcement does not yet provide a complete public issue-level
account, and a verified package identity does not prove absence of defects. Native image
checks and their limits are recorded in `reviews/T177/README.md`; T124's fresh-volume
integrated READY result is still required. No current Tor-network availability,
arm64 runtime behavior or unchanged circuit-isolation behavior follows solely from
this package promotion. See the dated T177 decision in `SECURITY-DECISIONS.md` and the
[Tor release announcement](https://forum.torproject.org/t/security-release-0-4-9-13/22178).

**T213 package availability update (2026-10-09).** The selected Bookworm Tor
package is now `0.4.9.14-1~d12.bookworm+1`, after the pinned 0.4.9.13 artifact
was removed from the moving upstream index and a clean T212 build failed closed.
The amd64 and arm64 artifact bytes were each checked against their architecture's
Packages index, with both indexes bound to one currently valid signature from the
existing pinned Tor key. Only the native amd64 image is built and runtime-checked
by T213; authenticated arm64 package bytes do not establish arm64 behavior. The
Tor Project's [2026-10-08 security announcement](https://forum.torproject.org/t/security-release-0-4-9-14/22241)
recommends updating, but the issue-level account is not yet public, and package
identity does not establish absence of defects or integrated route readiness.
The amd64 package/version/closure/torrc observations, plus the initial
build-wrapper cleanup failure and its separately audited recovery, are recorded
in `reviews/T213/README.md`; this does not claim the first composite caller
passed. T212/T202 live closure remains pending. Because the repository index is
mutable and may remove this version on its next build, clean builds can again
fail closed pending a manual reviewed promotion; T213 adds no archival or cache
bypass policy. See the dated T213 decision in `SECURITY-DECISIONS.md` and the
provenance and build limits in `reviews/T213/README.md`.

### 2.7 Malicious browser extension

An extension running alongside the Stargate WebExtension in the same
browser profile.

- **Can observe** (depending on permissions): the same URLs the Stargate
  extension routes; via `webRequest`, the URL of every outbound request;
  via `storage` (per-extension, isolated), nothing of Stargate's storage.
- **Cannot**: read Stargate's `storage.local` entries (WebExtensions
  storage is per-extension); intercept the `proxy.onRequest` listener
  belonging to another extension; modify Stargate's routing decisions
  in-place.
- **Can effectively**: route its own requests outside Stargate's mapping
  by issuing them directly through the browser fetch APIs (which the
  browser then offers to the proxy chain — so they remain proxied), or
  exfiltrate through legitimate browser channels (DNS, fetch) that the
  hardening audit attempts to constrain but cannot fully eliminate.

The extension hardening audit (architecture spec §14.5) detects foreign
extensions outside the allowlist and warns the user. This is detection,
not prevention; the user must remove the extension.

**Foreign-extension inventory decision (T091 acceptance #5): retained for
v1.** Enumerating other extensions requires the `management` permission
(arch §14.2). The inventory runs against the actual Mullvad Browser
profile in the release-cadence live-e2e test
(`tests/live-e2e/mullvad-browser-hardening/`), not only a Node mock. A
future release may drop the inventory (and the `management` permission)
if the detection value is outweighed by the permission's attack surface;
until then it is retained. **Cost of retaining `management`** (the
fingerprint asymmetry — Stargate-as-observer, not just
foreign-extension-as-observer): `management.get`/`getAll` exposes every
other extension's ID, name, version, enabled state, and host permissions
to the Stargate extension; if Stargate is compromised, that inventory is
a fingerprint of the user's browser that a clean Stargate would not
collect. The detection benefit (warn on a disallowed extension that
could exfiltrate via legitimate browser channels — §2.7 above) is
judged to outweigh this cost for v1; it is revisited if the inventory's
detection value proves weak. The broader browser-hardening guarantee
(DoH/DoT/HTTP-3 off) is an **externally verified precondition** on the
profile, not an extension-API claim — see §5.3/§5.4/§5.5 (amended by T091;
Constitution Principle III bullet 3, pre-release amendment).

### 2.8 OS-level attacker (**out of scope**)

A process on the user's device with code execution outside the browser
sandbox, root on the device, an evil-maid physical attacker, a keylogger,
or a screen recorder.

- **Stargate makes no claims here.** Constitution Non-Goals are explicit:
  device compromise is out of scope. Any such attacker can read browser
  memory, exfiltrate bearer tokens from disk, capture decrypted traffic,
  or replace the Stargate binary on disk.

We name this class so users do not draw protective conclusions Stargate
does not deliver.

---

## 3. Per-deployment-mode threat models

The three deployment profiles defined in the architecture spec (§2, §4)
imply different trust boundaries. The mode is selected by which
`docker-compose.<profile>.yml` is used.

### 3.1 Local profile (`docker-compose.local.yml`)

**Required topology:** proxy service listeners and host publications are loopback-only
in their own namespaces. Sidecar endpoints have an enforced caller/port matrix; DP/CP
cannot use arbitrary public TCP/UDP/DNS. T134 compares compliant designs. Host publication
alone, `STARGATE_IN_CONTAINER` and no-masquerade are insufficient evidence.

**T204 CP HTTP mechanism:** the headless control plane retains a bodyless
`GET /healthz` application endpoint. When HTTP is enabled, its effective host
must be the literal IPv4 loopback address `127.0.0.1` in the CP's own network
namespace. With the pinned Quarkus 3.40.1 framework, the application guard checks
the effective options before HTTP server deployment and refuses other host
values without resolving them. IPv6 HTTP host values, HTTPS activation and HTTP domain sockets are unsupported;
the separate framework management interface is also unsupported. HTTP may be
disabled. Narayana separately reserves a loopback process-ID socket. Linux may
show both sockets in the IPv6 socket table as IPv4-mapped loopback addresses.

The Local Compose configuration retains CP `network_mode: none`, no published
CP port and the authenticated Unix management channels. Its CP healthcheck is
disabled, so Compose does not poll `/healthz` or accumulate Docker healthcheck
history for it. The endpoint reports process liveness only; it does not establish
Tor readiness, authenticated IPC or successful forwarding.

This repairs the existing Local listener requirement without adding a route,
cryptographic identity or permission for CP network egress. T204 records the
implementation and validation status, including the exact package, source,
configuration, harness and disposable Linux guest identities for executed
checks. Source inspection and focused tests do not establish final-package or
cross-platform validation. Untested platforms and deployment modes remain
unverified. T204 owns this focused repair and its evidence; T155 owns integrated
foundation closure. Ticket completion does not satisfy Constitution VIII's
cumulative milestone review or external human release review requirements.

**T162 deployment mechanism (T163 measured scope below):** the local DP uses the host
network namespace and binds `127.0.0.1:8881` through the strict loopback check;
the T125 wildcard exception is removed. The CP has `network_mode: none`; Tor alone
has bridge egress. The installer stops a previously running DP before replacing
host rules, loads an enforcing DP AppArmor profile, installs IPv4 and IPv6
OUTPUT owner-match rules for UID 5102, and verifies their placement before
Compose startup. Only ESTABLISHED/RELATED replies on `lo` are accepted;
all other DP-owned IP packets hit a silent DROP, with no LOG target.
The profile mediates AF_UNIX and denies abstract socket peers, closing the host
abstract-forwarder channel shown in T134 A.12. AppArmor is the only control on
that channel: the DP's Landlock ruleset (ABI 4 TCP rights only, also on kernels
offering ABI 6 abstract-socket scoping) and its seccomp filter do not restrict
AF_UNIX connect. The denies require kernel AppArmor af_unix mediation. Compiled
for a kernel without it, the parser accepts the profile without error but
downgrades the unix allow to a generic network rule and drops both denies (shown
with copied kernel feature sets, which show both effects, and with a 5.4
policy-ABI pin, which drops both denies; no kernel lacking the mediation was
available). The installer therefore refuses DP startup (exit 60), before loading
the profile, unless `/sys/kernel/security/apparmor/features/network/af_unix`
reads `yes` and the profile, compiled as the load compiles it, differs from the
same profile without its unix denies (T198). That path is the Ubuntu kernel's;
mainline Linux reports af_unix mediation (6.17+) under `features/network_v9/`
and is refused. The closure is measured only on Ubuntu 24.04 with Linux 6.8
(amd64): on 6.8.0-142 the profile as the installer loads it denied an
abstract-socket stream connect that an unconfined control completed (T198,
2026-10-02). Other kernels and distributions are unmeasured. The refusal was
exercised on that host with the feature file masked or set to `no` and with the
parser pinned to the 5.4 policy ABI. An install/load/verify
failure refuses DP startup; the DP has no automatic restart policy. The
host administrator and Docker daemon are trusted to retain the profile and
Unix fabric policy. T168 adds the process boundary below; owner rules remain
installer-required defense in depth. T163's complete capture matrix below
records the measured Local guest boundary.

**T168 process mechanism:** before proxy or IPC serving, the static pure-Go DP
binds an ordinary TCP loopback listener with MPTCP disabled. It rejects other
inherited sockets (including standard descriptors), unexpected anonymous handles
and devices. Landlock ABI >= 4 denies TCP bind/connect on every Go thread; a
seccomp TSYNC filter denies creation of non-Unix sockets, message-send Fast Open,
descriptor-import and io_uring paths. This prevents independent IP origins even
through reset/reused listeners or a host-loopback forwarder. Accepted stream
replies and pathname Unix adapter/IPC read/write remain available; AppArmor and
fabric ownership constrain Unix peers. Future threads and descendants inherit
the restrictions. ABI >= 7 disables this domain's configurable denial auditing.

Missing/unsupported features, a cgo build, unexpected descriptors or partial
installation cause a fixed startup failure before serving. There is no bypass
flag or CP dependency. The running process cannot remove these restrictions;
removing either/both owner jumps must preserve safe admission, including a
Compose DP restart. Re-init restores the extra owner rules. Overriding the
container's AppArmor/security policy is unsupported. Linux amd64/arm64 paths use
native constants; cross-compilation is not evidence of runtime conformance.

**T170 signal compatibility:** the enforcing DP AppArmor profile permits
same-profile signals so Go can coordinate all-thread confinement and runtime
preemption. It receives only INT/TERM/KILL from the trusted host peers
`unconfined` and `runc`; ordinary UID and PID-namespace checks still apply.
There is no grant to send signals to other profiles, no CP signal authority,
and no change to IP, Unix-file or process-confinement restrictions. The full
Ubuntu VM exposed missing self/lifecycle permissions that the earlier nested
host had not exposed: Go's `urg`/`rtmin+1` and host shutdown signals were denied.
An operator's ability to stop the route remains part of Principle II and the
existing trusted-host boundary. T163 still owns the cumulative packet result.

**T178 snapshot-directory compatibility:** the profile grants read access to the exact
`/var/lib/stargate/` directory so the DP can open and fsync it after an atomic snapshot
rename. Access to its contents was already permitted. Without this directory permission,
the visible snapshot was not durably acknowledged and new credentials correctly remained
inadmissible. The production writer/restore regression fails at that open under the old
enforcing profile and passes under the repaired one. This preserves the durable-auth
boundary in Principle II; directory sync remains mandatory. Network, Unix-socket and
signal restrictions are unchanged. It adds no trust boundary or cryptographic mechanism.

**T191 procfs narrowing:** because the DP shares the host network namespace, every
`/proc/<pid>/net/*` file it can open is the host's table (`tcp`, `tcp6`, `udp`, `unix`,
`arp`, `route`). Until T191 the profile's blanket `/proc/** r` let the DP read them, so a
compromised DP could map host listeners, peers and neighbours. The profile now grants only
the procfs reads the static Go DP needs (its cgroup and mountinfo for the runtime's
GOMAXPROCS sizing and its own descriptor directory for T168's start-up scan) and explicitly
denies `/proc/*/net/**` and `/proc/*/task/*/net/**`. Because `*` also matches `sys`, the
deny covers `/proc/sys/net/**` as well: Go's read of the listen backlog limit
(`/proc/sys/net/core/somaxconn`) is denied and its net package falls back to its built-in
constant; the kernel still caps the backlog at somaxconn. The
T162 docker-tier test shows UID 5102 under the loaded profile getting EACCES on
`/proc/self/net/tcp` and `/proc/thread-self/net/tcp`, with an unconfined positive
control. Host-netns socket tables remain readable to any other unconfined host process;
this narrows only the DP.

**T171 evidence timing:** probe processes have a separate bounded startup/run
allowance; ordinary socket-operation deadlines remain 0.8 seconds. Loopback
fixtures start after recorder readiness and drain queued attempts before
teardown; fixture I/O failures invalidate the phase even after a positive
control succeeds. Three full-VM attempts exceeded the former interpreter budget and
failed overall; none counts as a denial or cumulative packet result. This is
test orchestration, with production permissions and packet assertions retained.

**T163 initial measured status (2026-09-20):** no production packet result was claimed.
Disposable deployments built the checked-in images but `scripts/stargate init`
stopped at Compose startup (exit 30) before DP/CP admission or capture. The
CP's read-only `/etc/stargate` config volume covers the nested keys mount;
Docker could not create `/etc/stargate/keys` inside that parent. A direct
two-volume `docker run --read-only --network none` on the workstation daemon
reproduced exit 125, while a keys-only mount reached CP application startup.
This measurement established a startup blocker, not egress closure or a
runtime fail-closed result.

**T167 mount repair (2026-09-20):** the installer now creates the
`/etc/stargate/keys` child mountpoint inside the project-scoped config volume
before Compose mounts that volume read-only in CP. A real-image Docker test
observed the pre-fix nested-mount refusal (exit 125) while a keys-only
control reached Quarkus startup, then observed the full effective Compose
mount set start with the intended sources, targets and modes. This closes
the CP startup blocker only; T163 must rerun its production-namespace packet,
resolver and rule-absence matrix.

**T163 resumed measurement (2026-09-20, disposable nested Docker host):** the
repaired Local Compose deployment started. A `tcpdump` recorder on `any` and
the actual IPv4 egress interface saw unrestricted-UID TCP, UDP and UDP/53
positive controls; it saw zero DP-UID packets to the marked documentation
targets, with the owner DROP counter rising by three. A controlled loopback
forwarder and dummy resolver admitted the unrestricted identity and refused
the DP identity. The browser-facing SOCKS listener admitted only on
`127.0.0.1:8881`; IPv6 had no egress route and `::1:8881` refused admission.
The Tor socket caller matrix passed before and after socket recreation.
**The overall suite failed:** removing both host OUTPUT owner jumps while
the DP was running left SOCKS5 method admission working under the then-current
installer-only boundary. T168 replaces that dependency with mandatory process
confinement and refines the corresponding T163 acceptance. These are real packets in the nested host's
deployment namespace, but not physical-host evidence; no complete T163 or
DNS-side-channel closure is claimed.

**T168 scoped measured result (2026-09-20):** the complete live sequence passed
in a disposable nested Docker 29.8.1 host on Linux 6.8.0-124-generic, amd64,
Landlock ABI 4. After removing IPv4 only, IPv6 only and both owner jumps,
loopback admission continued while the production confinement helper emitted
zero marked TCP/UDP/DNS/reuse/Fast Open traffic; positive capture controls were
visible and owner DROP delta was zero. Loopback forwarder/resolver mediation
was denied. Compose DP restart with both jumps absent repeated the result;
re-init restored the extra rules. Denying each required Landlock/seccomp
installation syscall caused the actual DP to exit before serving, with recovery
after each fault was removed. All 29 capture summaries record zero kernel drops.
The host had no routed IPv6 path; IPv6 loopback/kernel denial tests passed and
`::1:8881` refused admission. No routed IPv6, physical-host, arm64 runtime or
ABI >= 7 runtime result is claimed. Contract tests separately prove authenticated
Unix forwarding from retained state with CP absent and Unix socket recreation.
Evidence and earlier failed fixture attempts are recorded in T168. At that
checkpoint T163's cumulative/physical-host obligation remained open. The later
approved VM scope and measurements follow; human release review remains required.

**T163 cumulative measured result (2026-09-21, independently booted Ubuntu VM):**
the maintainer approved the complete Linux VM as the deployment host under the
revised foundation contract. The guest has its own Linux 6.8.0-139-generic kernel,
Docker 29.1.3 daemon, AppArmor enforcement and deployment namespaces (amd64,
Landlock ABI 4). Run `T163-20260921-024737` passed with the committed T171 runner:
all 29 source/egress/loopback captures were ready, decoded and closed cleanly
with zero kernel drops. Unrestricted TCP/UDP/DNS controls were visible; no
marked DP traffic escaped. The real listener and Tor Unix caller matrix passed,
including socket recreation. Loopback forwarding and resolver mediation failed
for the DP probes while their unrestricted controls worked. Each owner-jump
loss, DP restart with both jumps absent, re-init, and required-confinement
failure/recovery phase passed. T170 separately proved enforcing-profile startup,
self-signal compatibility and trusted-host stop/restart behavior on this VM.

The DP has no Docker embedded-resolver attachment. Controlled resolver denial,
including with auxiliary owner rules absent, establishes closure of T125's
accepted embedded-DNS channel on this measured replacement Local boundary.
The separate legacy experiment made both TCP connects time out while its source
and veth captures distinguished one routed SYN from zero filtered SYNs; its
owner DROP counter was one. Timeout alone remains non-discriminating.

The [T163 evidence report](specs/001-tor-route/analysis/T163-packet-evidence.md)
binds these results to source, image, helper and capture identities. Actual DP
startup/admission/restart observations are distinct from attack helpers invoking
production confinement as UID 5102 in its namespace. SOCKS method admission
does not prove authenticated destination bytes or a Tor circuit. The guest had
no routed IPv6 path: `::1` admission was refused, and IPv6 loopback resolver
controls/denial passed. Routed IPv6, arm64, newer Landlock ABIs, physical NICs,
hypervisor isolation, LAN/VPS, browser fallback and release conformance remain
unmeasured here. T155 retains the integrated foundation closure obligation.

The historical [T165 observer evidence](specs/001-tor-route/analysis/T165-observer-evidence.md)
adds a clean-volume Local deployment under QEMU 11.1.1. From the running CP
identity, the cookie, Tor-cookie group, SOCKS fabric and raw control socket
were absent; the observer's image digest and source label matched the tested
candidate. A CP-namespace capture saw its loopback positive control and no
packet to Tor's bridge control address. Invalid caller/request inputs returned
no token or Tor-side command; the authenticated observer returned only finite
health tokens through ready, not-ready, malformed and timeout cases. The
deployed CP monitor's exact STARTED/HEALTHY/UNHEALTHY transitions reached
DP's live event consumer, while repeats, malformed replies and observer loss
produced no false Tor exit or restart event. Tor and observer socket
recreation recovered. A disposable token reached DP through
CP's authenticated reload; with CP stopped and Tor natively healthy, DP
authenticated and forwarded a request through Tor to destination response
bytes. These are guest-kernel Local claims, not physical-NIC, routed-IPv6,
LAN/VPS or hypervisor-isolation claims.

**Protects against**:

- Other devices on the same LAN observing Stargate-routed traffic — they
  cannot connect to the proxy ports (loopback-only) and have no in-band
  view of the loopback socket.
- Network-level adversaries (§2.1, §2.3) seeing *plaintext request
  metadata* for routed traffic — they see only the encrypted outer tunnel
  to the chosen anonymity network's first hop.
- Required target: constrain a compromised application plane to its authorized
  adapter/IPC capabilities. T162 gives the DP a group-gated SOCKS hardlink on a
  DP-only volume while Tor's native SOCKS directory and raw control socket remain
  private. T203 removes the observer's Tor-state/control-subpath mount and the
  legacy cookie hardlink. The separate observer reads only a bounded finite-health
  publication from a read-only shared tmpfs and its own Ed25519 key volume. It has
  no IP network and serves one authenticated finite health query on the CP-only Unix fabric. CP has that fabric read-only,
  no Tor cookie/group, observer private key, SOCKS or raw-control route.
  T164/T165's results remain historical evidence for their candidates. They do
  not prove removal of the observer's raw Tor authority. T203 owns the replacement
  authority, freshness and lifecycle evidence and must identify the exact tested
  candidate, environment and unexecuted checks. T155 still owns integrated
  foundation closure.

**Does NOT protect against**:

- Any process running locally with the privileges to read loopback traffic
  or `127.0.0.1` sockets (§2.8 OS-level attacker).
- Other browsers on the same machine that have not been configured to use
  Stargate. They bypass the proxy entirely; Stargate cannot stop them.
- Software firewalls or DLP agents on the same host that proxy or log
  outbound traffic of all processes.
- Anything an observer of the host's egress NIC can already do (see §2.2).

**Trusted parties** (in addition to those trusted in any mode — §3.4):

- The local OS, the kernel network stack, and any process able to read
  loopback.
- The Docker daemon on the host (it runs the sidecars and can read their
  network namespaces).
- The installer and host administrator who own the DP UID's firewall rules
  and AppArmor profile. Docker or another host-root actor can remove either;
  the policy is not self-healing or enforced by Compose alone. Owner-rule removal
  cannot remove T168's restrictions from a confined process. Host/root compromise
  can still replace its executable, deployment policy or kernel and remains excluded.

**Residual risks**:

- An attacker who gains local code execution can replace the data-plane
  binary on disk, swap a sidecar image, or read the inter-plane keys. Two
  mitigations apply but neither eliminates: reproducible builds (Principle
  VI) let the user verify on-disk binaries after the fact; pinned
  digests (Principle IV) detect silent sidecar swaps via image-pull
  checks.
- Clock skew on the host causes Tor circuits to fail silently (see §5.1).
- Browser sandbox escape compromises everything Stargate sees from that
  browser.
- T134's prototype saw on-link ARP while filtering IP egress. Owner-match
  OUTPUT rules do not gate L2 ARP; the TCP/UDP/IP packet claim does not
  include ARP or claim to suppress neighbor discovery. T163's VM captures
  establish the guest IP boundary above; physical-NIC behavior is unmeasured.

**Concrete attacks not mitigated**:

- A user running another browser (Chrome, Brave) on the same machine
  without Stargate-aware proxy settings: routes through the user's normal
  internet connection, leaking everything Stargate would have hidden.
- A scheduled OS-level network task (CalDAV sync, app auto-update) makes
  outbound connections directly while the user assumes Stargate has
  "anonymised the machine." It has not — Stargate only anonymises traffic
  from browsers configured to use it.

### 3.2 LAN profile (`docker-compose.lan.yml`)

**Shape**: Proxy and admin UI bind only to the WireGuard interface
(`wg0`). Devices in the household enrol as WireGuard peers and reach
Stargate through the tunnel. A single physical host (typically a home
server) runs the stack.

**Protects against**:

- Devices on the same LAN that are **not enrolled WireGuard peers**: they
  cannot connect to Stargate's ports. The proxy binds only to `wg0`, and
  the bind-safety check (architecture spec §4) prevents accidental binds
  to the LAN bridge.
- Passive snooping of household traffic by another device on the same
  Wi-Fi (the WireGuard tunnel encrypts).
- Plaintext-metadata visibility of Stargate's traffic to an in-household
  observer at the access point: they see only WireGuard UDP (port 51820)
  to the Stargate host, then the host's outbound tunnels to anonymity
  networks.

**Does NOT protect against**:

- A compromised enrolled device: peers can use the proxy as configured.
  Token revocation is the response; detection of compromise is
  out of band.
- The household's ISP linking the Stargate host's egress to Tor / I2P /
  Nym (§2.2) — exactly as in Local mode for that egress vantage.
- Anyone with physical access to the Stargate host (§2.8).
- Endpoint correlation: an observer who can see both household traffic
  *and* destination traffic (e.g., a global passive adversary) can attempt
  timing correlation against any single user as in Local mode.

**Trusted parties** (in addition to §3.4):

- All enrolled household devices and the people who control them. Stargate
  does not impose isolation between household members beyond per-device
  bearer tokens; one enrolled device that issues a request through the
  Direct route, for example, identifies the household to the destination
  exactly as in Local mode.
- The WireGuard sidecar (it can read all cleartext after tunnel
  termination on the host).

**Residual risks**:

- The household becomes a single privacy unit visible to external
  observers: Stargate-routed Tor traffic from any household device looks
  to the upstream ISP the same as if any other member had sent it. Per-
  first-party stream isolation (§5.10) prevents *cross-site* correlation
  within Tor; it does not prevent *cross-device* aggregation at the ISP.
- Multiple devices simultaneously exiting via the same Tor circuit are
  prevented by stream isolation, but timing correlation at the ISP across
  device boundaries is not addressed by Stargate.

**Concrete attacks not mitigated**:

- A roommate on an enrolled device routes a clearly-identified social
  account through the Direct route, then routes a "private" lookup through
  Tor a minute later, while a global passive adversary observes the home's
  egress. The two events are linkable by timing to the same household.
- A guest's laptop, briefly enrolled and then forgotten, retains its
  bearer token and routes traffic when it next has network access. Token
  revocation is the user's responsibility; Stargate has no auto-expiry in
  v1.

### 3.3 VPS profile (`docker-compose.vps.yml`)

**Shape**: Stargate runs on a remote VPS. The user's devices reach it
through WireGuard (or Tailscale) over the internet. Proxy and admin UI
bind only to the tunnel interface on the VPS. The VPS's public network
interface accepts only WireGuard UDP.

**Protects against**:

- The **user's ISP**: it sees only an encrypted WireGuard tunnel to the
  VPS's IP. The user's ISP cannot tell whether the user is browsing Tor,
  I2P, Nym, or clearnet. It can tell that the user is using *some* tunnel
  to *some* VPS — that fact remains visible.
- Most network-level adversaries between the user and the VPS (passive
  and active) — they see only the tunnel.

**Does NOT protect against**:

- **The VPS provider** (§2.4). The provider's hypervisor can inspect all
  traffic at the VPS network interface and all memory in the VM. Stargate
  cannot defend against this; choice of provider and jurisdiction is the
  user's lever.
- The VPS's ISP and upstream transit: from the VPS outward, the threat
  model is the same as the upstream-observer model (§2.2). Tor, I2P, and
  Nym design properties apply from the VPS.
- Correlation between the user's WireGuard endpoint (the user's home IP)
  and the VPS's outbound anonymity-network traffic by an adversary
  observing both ends. This is the well-known endpoint-correlation
  weakness of single-hop relays; using Stargate VPS as a "stepping stone"
  to Tor does not eliminate it [Tor design paper, §3].
- Legal compulsion of the VPS provider to log or hand over data.

**Trusted parties** (in addition to §3.4):

- The VPS provider, its staff, and anyone with legal or technical access
  to its hypervisor.
- The VPS's ISP (same threat-model role as the user's ISP in Local mode).
- The host OS and Docker daemon on the VPS.

**Residual risks**:

- The provider can be compelled, by legal process or by intrusion, to
  capture traffic at the VM interface. Stargate's data plane cannot
  detect or prevent this.
- VM snapshot or live migration can leak SQLite state and inter-plane
  keys. The control-plane DB contains aggregate counters at hour
  resolution (architecture spec §6); it does not contain request data,
  but it does contain enrolled-device public keys and admin credential
  records.
- **Backup files contain Tor entry-guard state** (§4.2). Anyone with
  the backup file *and* the passphrase can therefore link the new
  install to the previous one through the guard set. Backup encryption
  (`age` with a passphrase recipient — architecture spec §13.1) is
  load-bearing for this linkability property. Choose a strong
  passphrase and treat backup files as sensitive even though they
  contain no per-request data.
- Long-lived VPS reuse: a single VPS used over years becomes a
  pseudonymous identity tied to your devices, the same way a single
  long-lived Tor entry-guard set would be — by being persistently
  associated.

**Concrete attacks not mitigated**:

- The VPS provider tcpdumps the public NIC for a week, then offers
  destination-side correlation against any party that can subpoena it.
- The VPS host kernel is rooted by an unrelated container in a shared
  hypervisor. The attacker captures Stargate's outbound flows.
- An IXP between the user's ISP and the VPS, and a separate IXP between
  the VPS and a popular destination, are both monitored by the same
  adversary. Timing correlation against any single user becomes feasible
  (this is a standard limitation of single-hop tunnels, not specific to
  Stargate).

### 3.4 Trust common to all modes

Across all modes, the user trusts:

- The Stargate maintainers' release pipeline and signing keys (Principle
  VI mitigates this through reproducible builds).
- The host OS and the Docker daemon.
- The pinned sidecar images and the upstream maintainers of Tor, i2pd,
  Nym client, and WireGuard (Principle IV mitigates this through digest
  pinning and the contract-test gate).
- The browser (Mullvad Browser is the reference target; constitution
  Tech Stack section).

---

### 3.5 Release artifacts, evidence and installer authority (T081)

T081 prepares an internal Local/JVM/Linux-amd64 `feature-preview`, not completed
v1 or a public release. Candidate and signed manifest carry `channel: feature-preview`;
prepared GitHub Release metadata carries `prerelease: true`. Native CP, Local/LAN/VPS
profiles and runtime-verified supported architectures remain completed-v1 requirements.
A public preview is the first public release and requires Constitution Governance and
VIII external-human review.

The release workflow prepares bytes from one reviewed source C and an existing
version tag without write/signing grants. Generated release Compose pins four final
registry digests; source local Compose remains a development build entry point.
Generated digests and release evidence are derived artifacts and never rewrite source/tag.
Promotion reads the remote `refs/tags/<version>` object and resolves any
annotated tag chain to C at the approval-pack, pre-push, pre-draft and
pre-publish guards. A same-named branch does not substitute for a deleted
tag. A privileged tag mutation between guards remains outside transactional
guarantees and causes the next observed check to refuse.
Each retained OCI image carries a hashed BuildKit SLSA v1 statement with a
local Dockerfile/context request and source-C revision hints. Local-context
`vcs:revision` and revision labels are unverified metadata, and BuildKit does
not claim complete Git materials for that context. The driver rejects
conflicting structured values or a conflicting own-repository Git dependency;
source identity checked before and after building, shipped payload comparison,
and the signed release manifest supply the independent C binding. This is not
a claim that SLSA alone proves the local source commit.

Promotion treats same-repository evidence commit E as bounded regular-file data,
never executable workflow or deployment policy. Immutable artifact IDs, content
hashes, full reports and source bindings prevent accidental swaps and stale evidence;
they do not authenticate a report's author or prove its claims. A required non-self
reviewer in the protected stargate-release environment inspects report provenance and
approves the exact pack. Missing/unreadable protection, broad branch rules, possible
admin bypass or absent explicit approval refuse. Constitution VIII external-human
review remains independent of this deployment click.

GitHub, the repository administrators, reviewed release code/input publishers and
Sigstore trust roots are in this supply-chain TCB. Signing authenticates the expected
workflow identity, not code safety; reproducibility and review remain distinct.
Registry uploads across repositories are not atomic. Failed promotion can leave
immutable blobs but must not publish a final release or advance installation.
Administrative concurrent policy/tag mutation is outside transactional guarantees.
Tokenless preparation can retain candidate bytes for a version that later refuses;
it has no release publication authority. The read-only approval pack checks
published releases only. Protected promotion separately verifies the token's push
access, queries GraphQL for the exact-tag release (including drafts), and queries
REST for the published release before the first registry push and again before
draft creation. Presence, API errors, incomplete replies or conflicting results
refuse. An unrelated release deletion cannot shift the target across an
already-read offset page because no release list is used. The workflow
serializes target-version promotion runs; authorized human/API writers must
coordinate with that protocol. Neither exact-tag read reserves the version,
and a privileged out-of-band edit can race both checks or change the owned
draft before publication. An abandoned draft or lost create/publish response
requires manual reconciliation; the driver does not retry those writes
automatically.
GitHub's `GITHUB_TOKEN` cannot obtain Workflows write permission and may be
refused when C changes `.github/workflows` relative to the default branch.
Promotion compares those exact Git subtrees using canonical source and
current-default commit/tree API data at both guards; unknown or mismatched
data refuses before the next write phase. C need not equal default HEAD.
The default branch can change after the second check, so an API 403/404 or
lost create/publish response still requires manual reconciliation; no broader
credential is introduced.
Preparation's verifier uses the local Docker driver so tagged test images are
daemon-visible and the Tor rollback build can reach its runner-loopback replay
proxy. The pinned private BuildKit builder is reserved for retained OCI exports.
If the verifier cannot reach the proxy, its required receipt and pinned-hash
failure checks refuse the candidate; a connection error is not a successful
rollback-control observation.

New promotion refuses stale source-selected Sigstore metadata (the selected
2026-10-11 chain's earliest expiry is 2026-10-18T01:48:18Z). A reviewed source
refresh is required; neither evidence nor environment can extend it. Installation
of an existing signed artifact instead uses trusted signing-time validity.
Offline static roots cannot discover later compromise/revocation/rotation. The
historical root-5 bootstrap relies on official HTTPS selection; audited threshold
continuity to root 15 does not independently authenticate that initial selection.
The driver implements no custom cryptography or background TUF updater.

Every required live tracker row remains a publication prerequisite, including
R-7. Unmeasured/unsupported scope is release-blocking, never a PASS or N/A waiver.
R-2 observations do not discharge R-3 or R-7; evidence binds the exact tracker at C
and full report bodies, whose meaning and provenance need independent inspection.

`init --release-dir` executes only from the verified exact source checkout. The
release directory is data; pinned signature verification, source/file identity and
regenerated canonical topology checks finish before host policy, volumes, keys or
containers mutate. Approved release mode still requires local host confinement,
key preservation and authenticated observer readiness and uses `--no-build`.
Both source and release init resolve Docker's selected context and effective daemon
endpoint before provisioning. Only the default context at the local rootful Unix
socket is admitted; DOCKER_HOST, DOCKER_CONTEXT, stored context selection, alternate
sockets and rootless daemon reports fail before host policy or Docker mutation.
This check trusts the local Docker CLI/daemon and socket identity; a compromised
local host or daemon can still misreport state or subvert host policy (§3.1).
Fixture tests cannot establish apt/keyring acceptance, real tool interoperability,
configured remote protection, final/live reviews or a published release. Those
remain explicit later gates; no stronger protection is claimed by this mechanism.

## 4. Per-route threat models

Each listening port (architecture spec §4) corresponds to one upstream
anonymity property. The browser extension selects the port; the data plane
forwards bytes (Principle I).

### 4.1 Direct (port 8885)

**What this provides**: nothing more than transport. Direct is plain
SOCKS5/HTTP-CONNECT forwarding to clearnet. The proxy adds no privacy
properties.

**Why it exists**: deliberate clearnet egress, clearly labelled. Distinct
port and distinct UI surface so the user cannot mistake clearnet for a
private route (Principle V — honest threat model; architecture spec §4.4).

**Anonymity property NOT provided**:

- IP unlinkability — the destination sees the host's egress IP.
- SNI privacy — the destination's ISP sees the TLS SNI.
- DNS privacy — but the resolution happens at the sidecar boundary, not
  on the proxy host (SOCKS5h is still enforced; §5.2).

**Observable metadata that leaks**:

- Destination IP, port, TLS SNI, timing, byte counts.
- Anything the browser sends (cookies, fingerprints) reaches the
  destination as normal.

**Side-channel concerns**: none specific to Direct beyond what the
browser leaks.

**Trusted parties for this route**: same as the deployment mode (§3).
There is no anonymity-network layer.

### 4.2 Tor onion (`*.onion`, port 8881)

**What this provides**: end-to-end-encrypted, mutually-authenticated
rendezvous with a destination that has no clearnet identity, traversing
six relays (three on each side) selected by Tor's path-selection algorithm
[Tor v3 rend-spec; Tor design paper §5].

**Anonymity property provided** (subject to the underlying Tor design):

- The destination service does not learn the user's IP address.
- The user's ISP does not learn that the user is communicating with a
  specific onion service — only that the user is using Tor.
- No exit relay is involved (onion services have no exit; the destination
  is reached over the Tor network end-to-end).

**Anonymity property NOT provided**:

- Resistance to a **global passive adversary** capable of observing both
  ends of the circuit. Tor's design paper explicitly states this is out
  of scope [Tor design paper, §3 — "Tor does not protect against a global
  passive adversary"].
- Resistance to traffic-confirmation attacks by an adversary that
  observes the user's entry traffic and either the destination side or a
  significant slice of the Tor network [Murdoch & Danezis 2005].
- Protection against onion-service-side malice (a hostile onion service
  is the same threat as a hostile clearnet site; §2.5).
- Protection against denial-of-service attacks on the HSDir distribution.

**Observable metadata that leaks**:

- The user's guard relay sees the user's IP and that the user is using
  Tor.
- The pattern of Tor traffic is itself a signal (an active adversary can
  distinguish "user is using Tor" from "user is not using Tor"; bridges
  with pluggable transports partially mitigate this — see §5.11).
- Timing fingerprints of the user's request pattern remain observable to
  guards and to any global observer.

**Side-channel concerns**:

- Browser fingerprinting (§5.7) is unaffected by the route. Mullvad
  Browser's RFP defenses are the user's mitigation.
- Latency patterns differ between onion and exit; the destination cannot
  observe this, but the user's guard can.

**Trusted parties for this route**:

- The Tor network's consensus directories (the user trusts that the
  directory consensus is honest in aggregate; this is Tor's documented
  trust model).
- The Tor sidecar binary and its image maintainer (Principle IV).

**Stargate-specific notes**:

- **Popup scope (T150):** the per-tab label reports only the latest observed main-navigation
  request decision, including redirect targets. Onion images cannot make a Direct main request
  appear Tor-routed; Direct subresources cannot change an onion main request's Tor decision.
  The popup explicitly states that other requests may use different routes and connection success
  is unverified. Unknown/pending/unreadable state makes no route claim. This in-memory decision
  is neither measured mixed-resource coverage nor proof of tunnel establishment, successful load
  or whole-tab protection (Principles III/V). T157 adds the truthful `Blocked by Stargate` state
  only after the matching protected request is canceled; Direct remains reserved for an
  intentional Direct decision. Router/popup unit regressions cover this display contract.
- **Protected browser failure boundary (T157):** Firefox's proxy and blocking-webRequest events
  consume one bounded, request-id/fingerprint-bound decision. A valid Tor decision returns the
  ordered `[SOCKS5h descriptor, null]` chain, whose terminal `null` forbids browser-defined
  failover. Missing/malformed credentials, closed hardening, missing or changed request identity,
  unavailable first-party context, state-generation change, and applied-proxy mismatch are
  canceled asynchronously at `onBeforeRequest`. Intentional Direct decisions remain allowed and
  carry no Tor credential. As shipped by T157 the blocked proxy result was `null`, which is not
  "no descriptor": Gecko's `ProxyChannelFilter` maps `null` to no proxy at all — an explicit
  direct connection that also bypasses a configured browser/system proxy — while a rejected or
  throwing listener selects the default (system) proxy. Only the cancel listener stood between a
  blocked `.onion` request and Direct (redteam finding 20260929-004; T186 below).
- **Blocked protected proxy result (T186, maintainer-selected design D5):** every blocked
  protected path — missing request id, non-Tor decision, rejected decision or a throwing
  listener — now returns `[{type:'socks', host:'file:///dev/null/stargate-blocked', port:1,
  proxyDNS:true}, null]`. Gecko supports SOCKS over a Unix socket for a `file://` host; the path
  cannot exist (`/dev/null` is not a directory; no unprivileged process can create the path — a
  host-root attacker already owns the loopback ports and the extension and is outside this
  protection's threat class), so the connect fails with ENOTDIR,
  `proxyDNS` keeps the name from any local resolver, and the terminal `null` leaves no failover.
  The hop carries no credential or isolation identity. The cancel listener stays as the second
  layer. `.onion` classification strips every trailing dot and lowercases, so `x.onion.`,
  `x.onion..` and mixed-case forms are protected. Rejected alternatives: a loopback TCP port
  (Stargate's own, with an invalid credential) hands the name to whatever binds that port while
  the data plane is down — the matrix below shows a fake SOCKS listener there receives the name;
  D4 (`https` to `127.0.0.1:1023`) was also clean but depends on certificate validation that a
  user can click through on the resulting certificate-error page. Residue: a future Gecko that
  drops `file://` SOCKS support could fail in either of two ways — treating the sink as a
  hostname (a lookup of that constant name, never the destination), or rejecting the descriptor,
  which Gecko resolves to the default (system) proxy and so exposes the destination name to that
  proxy with only the cancel listener remaining. Both are re-checked per browser release by the
  T186 probe modes below, whose destination, system-proxy and resolver surfaces detect either.
- **T157 live evidence (refined attempt, 2026-09-24):** the complete candidate matrix passed
  16/16 scenarios in Mullvad Browser Alpha 16.0a12 / Gecko 153.3.0 with geckodriver 0.37.0.
  These are connection-level observations at independent ordinary-HTTP-proxy, direct-destination
  and SOCKS5 catchers. Each catcher has a browser positive control; the SOCKS catcher records
  accepted connections even when negotiation fails. Negative cases observe all three surfaces.
  The unmodified extension package is
  `c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0`.
  The browser archive is
  `9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab`;
  its executable is `00162321fe062e0ff0fb4160c530e728e1d80a830cd0f1783f754081715dde7f`.
  The geckodriver executable is
  `23c877d64e37e1558ae41fffa1f629a7f937dac45c5accb59e5d2f9c6a9af0e5`.

  The startup scenario uses a separately hashed, instrumented package: an added background script
  wraps the real credential read and proxy callback without replacing their values or decisions.
  The harness stores a valid synthetic device through the extension's own storage API, reloads
  the extension, and holds the fresh initialization read before it can populate the token mirror.
  The recorded sequence is initialization-held → actual protected proxy callback (hardening true,
  gate still held) → explicit release → initialization-returned. All catchers remain empty while
  held; after release the same main request completes through authenticated SOCKS. Releasing before
  issuing the request makes the overlap assertion fail. This establishes an extension-initialization
  boundary under controlled delay; it is not a browser-process launch/session-restore experiment.

  Sidecar availability is tested on the identical protected fetch from the same committed
  `direct.example.com` page. Its positive must complete through SOCKS with the expected host and
  credential. After closing that listener, the same fetch rejects and neither forbidden catcher
  receives it. The earlier `.invalid` fixture could fail context admission and is superseded.
  A separate passive-observer package also passes. Removing only terminal `null` fails the live
  descriptor assertion: its trace shows Firefox trying the configured HTTP proxy, then the
  independent blocking listener canceling that retry. Removing both protections in a labelled
  combined mutant causes the protected path to reach the HTTP catcher. Thus the single-null
  mutation does not demonstrate a network leak with the blocker intact; the combined mutation
  demonstrates that the calibrated network oracle detects fallback.

  The other executed falsifiers authorize an opaque-context request (captured at SOCKS), suppress
  fixture request generation (required markers absent), and admit a forbidden request 1.5 seconds
  after page execution (HTTP capture after the recorded terminal observation). Each turns RED.
  Post-terminal observation lasts 11 seconds. The pinned browser's
  `modules/ProxyChannelFilter.sys.mjs` defines a 10-second extension proxy default, also visible
  in the passive callback trace; the earlier five-second assumption is superseded.
  Round 2 replaces the main-navigation completion oracle: a browser progress listener registered
  before dispatch records a URL-matched `STATE_STOP | STATE_IS_NETWORK` with `NS_ERROR_ABORT`.
  The tested tab is never navigated away from or closed during observation; the popup is read
  in a separate tab and cannot establish completion. The five candidate cancellation events
  occurred in 22–38 ms. A new test-only mutant still publishes `Blocked` but waits six seconds
  before returning a non-canceling response. Its original navigation remains alive and ends
  after 6,099 ms with status `0x804b001e`, not the required abort: the oracle rejects it despite
  the `Blocked` label. No catcher traffic occurred for this mutant, so it proves rejection of
  false UI evidence, not a network leak. The existing delayed-context mutant supplies actual
  delayed HTTP-fallback capture. The earlier same-tab-popup completion evidence is superseded.
  Malformed credentials are written and read back through real extension storage, bypassing only
  form validation. The unreadable-hardening variant removes only the `privacy` permission and
  records the resulting runtime API error in the extension's own audit record. All credentials,
  destinations, timestamps and callback observations below belong to synthetic local tests.

  The original baseline `c57d12f11f4113364932fbb184b276b42fdd355b` passes only the two Direct
  capture controls and fails the other 14 scenarios. Its missing required proxy-listener filter
  explains why intended Tor positives appear at the ordinary proxy and its SOCKS list is empty.
  Baseline replay alone cannot isolate the terminal-null guard; the targeted mutants above do.
  These refined probes add retrospective evidence for the existing repair. They do not replace
  its previously recorded tests-first unit and manifest failures.

  Reproduce with `bash extension/package.sh`, then
  `python3 tests/live-e2e/mullvad-browser-hardening/probe.py --browser <mullvadbrowser>
  --driver <geckodriver> --extension extension/dist/stargate-extension.zip
  --artifact <browser.tar.xz> --report-out <report.json>`.
  The full command, package identities, changed variant members and every scenario observation
  are retained below, including both positive and failed mutation runs. Rebuild the red package
  from the named baseline's `extension/` tree using that tree's `package.sh`.
  The JSON blocks reproduce complete report objects; formatting is compacted per scenario, while
  each listed SHA-256 binds the original pretty-printed report bytes. Their local paths are output
  locations, not prerequisites for inspecting this committed evidence.
  Baseline and full candidate reports below are round-2 reruns with the corrected browser-owned
  terminal oracle. The separately scoped startup, sidecar, context and fixture mutation reports
  are retained from round 1; none of those paths called the replaced popup-completion helper.

  These results establish the refined T157 Alpha-candidate boundaries. T155 still requires stable
  supported-browser launch/session-restore testing, integration, packet/DNS/circuit evidence and
  the release gate. Neither the persistent manifest flag nor this controlled delay claims that
  an unregistered listener can protect an already-dispatched startup request.
  Dispatch paths that reach the blocking listener without a proxy-event record — for example a
  fully cache-served protected subresource — are cancelled fail-closed; no live scenario covers
  cache-served protected requests yet; owner T155.

  <details>
  <summary>T157 complete baseline, candidate, observation and mutation reports</summary>

  **red** — `target/runs/T157-r2-red.json`; original report SHA-256
  `95242f1ec1ed97d93f17fc54c2d9d81c7820a3b1400f8d8d4ccbfd8bf520ad3a`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[1501990] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","target/t157-pre.rLnhU9/extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--report-out","target/runs/T157-r2-red.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "68ad7ef70549b2a3764353fe2c31a82b4bd9d823b92ea8b56153b90f9e146f36",
    "extensionSha256": "68ad7ef70549b2a3764353fe2c31a82b4bd9d823b92ea8b56153b90f9e146f36",
    "failures": ["hardening-failure-no-fallback","subresource-and-retry-no-fallback","redirect-no-fallback","missing-token-no-fallback","malformed-token-no-fallback","unreadable-hardening-api-no-fallback","absent-initiating-context-no-fallback","tor-positive-control","tor-subresource-retry-positive-control","tor-redirect-positive-control","sidecar-reconnect-race-positive-control","startup-initialization-overlap","sidecar-identical-path-positive-control","sidecar-identical-path-unavailable"],
    "mutationName": "none",
    "result": "RED",
    "scenarios": {
      "absent-initiating-context-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/context-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227454.973142,"path":"/marker/context-start"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/opaque-context HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227454.987208,"path":"/opaque-context"},{"firstLine":"GET http://direct.example.com/marker/context-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227454.991713,"path":"/marker/context-done"}],"markersObserved":["/marker/context-done","/marker/context-start"],"passed":false,"requiredMarkers":["/marker/context-done","/marker/context-start"],"socksCaptures":[],"terminal":{"completed":true,"documentURI":"data:text/html,%3Cscript%3Efetch%28%27http%3A//direct.example.com/marker/context-start%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A42561/opaque-context%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//direct.example.com/marker/context-done%27%29%29%29%3C/script%3E","elapsedSeconds":0.128,"observedAtMonotonic":9227455.059106,"readyState":"complete","url":"data:text/html,%3Cscript%3Efetch%28%27http%3A//direct.example.com/marker/context-start%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A42561/opaque-context%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//direct.example.com/marker/context-done%27%29%29%29%3C/script%3E"}},
      "destination-positive-control": {"destinationCaptures":[{"firstLine":"GET /destination-control HTTP/1.1","observedAtMonotonic":9227355.179549,"path":"/destination-control"},{"firstLine":"GET /favicon.ico HTTP/1.1","observedAtMonotonic":9227355.216936,"path":"/favicon.ico"}],"httpCaptures":[],"passed":true,"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://127.0.0.1:42561/destination-control","elapsedSeconds":0.142,"readyState":"complete","url":"http://127.0.0.1:42561/destination-control"}},
      "direct-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/control HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227355.008931,"path":"/control"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227355.058907,"path":"/favicon.ico"}],"passed":true,"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://direct.example.com/control","elapsedSeconds":0.175,"readyState":"complete","url":"http://direct.example.com/control"}},
      "hardening-failure-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/hardening-closed HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227359.989131,"path":"/hardening-closed"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/favicon.ico HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227360.037049,"path":"/favicon.ico"}],"markersObserved":[],"passed":false,"requiredMarkers":[],"socksCaptures":[],"terminal":{"browserProgress":{"events":[{"elapsedMs":10,"flags":983041,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/hardening-closed"},{"elapsedMs":60,"flags":131088,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/hardening-closed"},{"elapsedMs":66,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/hardening-closed"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/hardening-closed","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":66,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/hardening-closed"},"testedTabPreserved":true},"completed":false,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/hardening-closed","elapsedSeconds":0.159,"observedAtMonotonic":9227361.289573,"popupLabel":"Main navigation decision: Unknown Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/hardening-closed"}},
      "malformed-token-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/malformed-token HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227419.700414,"path":"/malformed-token"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/favicon.ico HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227419.785878,"path":"/favicon.ico"}],"markersObserved":[],"passed":false,"requiredMarkers":[],"socksCaptures":[],"storedDevice":{"bearerToken":"not-a-token","name":"corrupt-storage","tokenStoredAt":1},"terminal":{"browserProgress":{"events":[{"elapsedMs":13,"flags":983041,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/malformed-token"},{"elapsedMs":101,"flags":131088,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/malformed-token"},{"elapsedMs":102,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/malformed-token"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/malformed-token","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":102,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/malformed-token"},"testedTabPreserved":true},"completed":false,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/malformed-token","elapsedSeconds":0.206,"observedAtMonotonic":9227421.005882,"popupLabel":"Main navigation decision: Unknown Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/malformed-token"}},
      "missing-token-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/missing-token HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227400.923043,"path":"/missing-token"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/favicon.ico HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227401.164752,"path":"/favicon.ico"}],"markersObserved":[],"passed":false,"requiredMarkers":[],"socksCaptures":[],"terminal":{"browserProgress":{"events":[{"elapsedMs":17,"flags":983041,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/missing-token"},{"elapsedMs":240,"flags":131088,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/missing-token"},{"elapsedMs":241,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/missing-token"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/missing-token","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":241,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/missing-token"},"testedTabPreserved":true},"completed":false,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/missing-token","elapsedSeconds":0.383,"observedAtMonotonic":9227402.405896,"popupLabel":"Main navigation decision: Unknown Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/missing-token"}},
      "redirect-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/redirect HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227383.565054,"path":"/redirect"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/redirect-target HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227383.592486,"path":"/redirect-target"}],"markersObserved":[],"passed":false,"requiredMarkers":[],"socksCaptures":[],"terminal":{"browserProgress":{"events":[{"elapsedMs":26,"flags":983041,"networkStop":false,"status":0,"url":"http://direct.example.com/redirect"},{"elapsedMs":117,"flags":131088,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/redirect-target"},{"elapsedMs":119,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/redirect-target"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/redirect-target","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":119,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/redirect-target"},"testedTabPreserved":true},"completed":false,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/redirect-target","elapsedSeconds":0.194,"observedAtMonotonic":9227385.027244,"popupLabel":"Main navigation decision: Unknown Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/redirect-target"}},
      "sidecar-identical-path-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/sidecar-page HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227531.775795,"path":"/sidecar-page"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227531.826415,"path":"/favicon.ico"},{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227531.96528,"path":"/marker/sidecar-start"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/sidecar-path HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227531.970526,"path":"/sidecar-path"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227531.974834,"path":"/marker/sidecar-done"}],"passed":false,"socksCaptures":[],"terminal":{"completed":true,"outcome":"fulfilled"}},
      "sidecar-identical-path-unavailable": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227532.277109,"path":"/marker/sidecar-start"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/sidecar-path HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227532.279568,"path":"/sidecar-path"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227532.281756,"path":"/marker/sidecar-done"}],"markersObserved":["/marker/sidecar-done","/marker/sidecar-start"],"matchingPositivePassed":false,"passed":false,"requiredMarkers":["/marker/sidecar-done","/marker/sidecar-start"],"socksCaptures":[],"terminal":{"completed":false,"observedAtMonotonic":9227532.285302,"outcome":"fulfilled"}},
      "sidecar-reconnect-race-positive-control": {"acceptedAfterSeconds":10.001,"connectionAcceptedBeforeRelease":false,"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/sidecar-reconnected HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227476.65992,"path":"/sidecar-reconnected"}],"passed":false,"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/sidecar-reconnected","elapsedSeconds":0.046,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/sidecar-reconnected"}},
      "startup-initialization-overlap": {"after":{"events":[{"kind":"initialization-held","sequence":0},{"kind":"initialization-release","sequence":1},{"kind":"initialization-returned","sequence":2}],"hardeningOk":true,"held":true,"released":true,"storedDevice":{"bearerToken":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","name":"live-control","tokenStoredAt":1}},"before":{"events":[{"kind":"initialization-held","sequence":0}],"hardeningOk":true,"held":true,"released":false,"storedDevice":{"bearerToken":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","name":"live-control","tokenStoredAt":1}},"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/startup-held HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227494.618888,"path":"/startup-held"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/favicon.ico HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227494.688736,"path":"/favicon.ico"}],"instrumentation":{"changedMembers":{"background/t157-startup.js":{"afterSha256":"f747c2873be28d8c9248b0ce3f09863b1b51d0e80bed900a4a40729537918e26","beforeSha256":null},"manifest.json":{"afterSha256":"123b516e097745b559ad0ca784198b86ad4870d3066c97bd5db2183f79521d22","beforeSha256":"5bccb72b993118d40216f4520c656742e5c1997996a6f8ea23d43b8b7cedbabf"}},"packageSha256":"012fe6e6200552585fb67a2b60a22e139eaf32fed856ed379a88e936cc6e30fd","sourceSha256":"68ad7ef70549b2a3764353fe2c31a82b4bd9d823b92ea8b56153b90f9e146f36","variant":"startup"},"overlapEstablished":false,"passed":false,"pending":{"events":[{"kind":"initialization-held","sequence":0}],"hardeningOk":true,"held":true,"released":false,"storedDevice":{"bearerToken":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","name":"live-control","tokenStoredAt":1}},"pendingCaptures":{"destination":[],"http":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/startup-held HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227494.618888,"path":"/startup-held"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/favicon.ico HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227494.688736,"path":"/favicon.ico"}],"socks":[]},"socksCaptures":[],"terminal":{"completed":true,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/startup-held"}},
      "subresource-and-retry-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/page HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227372.309032,"path":"/page"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/subresource HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227372.396145,"path":"/subresource"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/retry-one HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227372.396477,"path":"/retry-one"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227372.399141,"path":"/favicon.ico"},{"firstLine":"GET http://direct.example.com/marker/retry-one-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227372.404383,"path":"/marker/retry-one-done"},{"firstLine":"GET http://direct.example.com/marker/subresource-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227372.413943,"path":"/marker/subresource-done"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/retry-two HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227372.474111,"path":"/retry-two"},{"firstLine":"GET http://direct.example.com/marker/retry-two-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227372.476498,"path":"/marker/retry-two-done"}],"markersObserved":["/marker/retry-one-done","/marker/retry-two-done","/marker/subresource-done"],"passed":false,"requiredMarkers":["/marker/retry-one-done","/marker/retry-two-done","/marker/subresource-done"],"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://direct.example.com/page","elapsedSeconds":0.227,"observedAtMonotonic":9227372.526105,"readyState":"complete","url":"http://direct.example.com/page"}},
      "tor-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/tor-positive HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227466.069343,"path":"/tor-positive"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/favicon.ico HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227466.127142,"path":"/favicon.ico"}],"passed":false,"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/tor-positive","elapsedSeconds":0.165,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/tor-positive"}},
      "tor-redirect-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/tor-redirect-start HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227476.334465,"path":"/tor-redirect-start"}],"passed":false,"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/tor-redirect-start","elapsedSeconds":0.103,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/tor-redirect-start"}},
      "tor-subresource-retry-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/tor-page HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227466.240157,"path":"/tor-page"}],"passed":false,"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/tor-page","elapsedSeconds":0.048,"readyState":"complete","url":"about:blank"}},
      "unreadable-hardening-api-no-fallback": {"auditRecord":{"lastAuditResult":{"blockedSurface":"webrtc","pref":"privacy.network.peerConnectionEnabled","readError":"can't access property \"network\", browser.privacy is undefined"},"lastAuditedAt":497289},"destinationCaptures":[],"faultInjection":"privacy permission removed from otherwise identical package","httpCaptures":[{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/unreadable-hardening-api HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227437.861445,"path":"/unreadable-hardening-api"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/favicon.ico HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227438.06129,"path":"/favicon.ico"}],"markersObserved":[],"passed":false,"requiredMarkers":[],"socksCaptures":[],"terminal":{"browserProgress":{"events":[{"elapsedMs":106,"flags":983041,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/unreadable-hardening-api"},{"elapsedMs":321,"flags":131088,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/unreadable-hardening-api"},{"elapsedMs":328,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/unreadable-hardening-api"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/unreadable-hardening-api","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":328,"flags":786448,"networkStop":true,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/unreadable-hardening-api"},"testedTabPreserved":true},"completed":false,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/unreadable-hardening-api","elapsedSeconds":0.359,"observedAtMonotonic":9227439.381958,"popupLabel":"Main navigation decision: Unknown Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:42561/unreadable-hardening-api"}}
    },
    "unknownHardeningFaultExtensionSha256": "6920bea83a388dfed0f0f969a15b45bd99bfec7b277e4439412bad56acf29314"
  }
  ```

  **green** — `target/runs/T157-r2-green.json`; original report SHA-256
  `68b3f45e23b2f6c4fdc52f49508dcd31d3c3613cbf68f2be22a484aead536823`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[1464890] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--report-out","target/runs/T157-r2-green.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "extensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "failures": [],
    "mutationName": "none",
    "result": "GREEN",
    "scenarios": {
      "absent-initiating-context-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/context-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227287.800389,"path":"/marker/context-start"},{"firstLine":"GET http://direct.example.com/marker/context-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227287.809111,"path":"/marker/context-done"}],"markersObserved":["/marker/context-done","/marker/context-start"],"passed":true,"requiredMarkers":["/marker/context-done","/marker/context-start"],"socksCaptures":[],"terminal":{"completed":true,"documentURI":"data:text/html,%3Cscript%3Efetch%28%27http%3A//direct.example.com/marker/context-start%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A38023/opaque-context%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//direct.example.com/marker/context-done%27%29%29%29%3C/script%3E","elapsedSeconds":0.141,"observedAtMonotonic":9227287.89896,"readyState":"complete","url":"data:text/html,%3Cscript%3Efetch%28%27http%3A//direct.example.com/marker/context-start%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A38023/opaque-context%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//direct.example.com/marker/context-done%27%29%29%29%3C/script%3E"}},
      "destination-positive-control": {"destinationCaptures":[{"firstLine":"GET /destination-control HTTP/1.1","observedAtMonotonic":9227176.804583,"path":"/destination-control"},{"firstLine":"GET /favicon.ico HTTP/1.1","observedAtMonotonic":9227176.847959,"path":"/favicon.ico"}],"httpCaptures":[],"passed":true,"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://127.0.0.1:38023/destination-control","elapsedSeconds":0.146,"readyState":"complete","url":"http://127.0.0.1:38023/destination-control"}},
      "direct-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/control HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227176.653796,"path":"/control"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227176.725488,"path":"/favicon.ico"}],"passed":true,"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://direct.example.com/control","elapsedSeconds":0.177,"readyState":"complete","url":"http://direct.example.com/control"}},
      "hardening-failure-no-fallback": {"destinationCaptures":[],"httpCaptures":[],"markersObserved":[],"passed":true,"requiredMarkers":[],"socksCaptures":[],"terminal":{"browserProgress":{"events":[{"elapsedMs":21,"flags":983041,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/hardening-closed"},{"elapsedMs":33,"flags":131088,"networkStop":false,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/hardening-closed"},{"elapsedMs":35,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/hardening-closed"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/hardening-closed","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":35,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/hardening-closed"},"testedTabPreserved":true},"completed":true,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"moz-extension://stargate-test/options/options.html","elapsedSeconds":3.03,"observedAtMonotonic":9227185.42342,"popupLabel":"Main navigation decision: Blocked by Stargate Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"moz-extension://stargate-test/options/options.html"}},
      "malformed-token-no-fallback": {"destinationCaptures":[],"httpCaptures":[],"markersObserved":[],"passed":true,"requiredMarkers":[],"socksCaptures":[],"storedDevice":{"bearerToken":"not-a-token","name":"corrupt-storage","tokenStoredAt":1},"terminal":{"browserProgress":{"events":[{"elapsedMs":17,"flags":983041,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/malformed-token"},{"elapsedMs":33,"flags":131088,"networkStop":false,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/malformed-token"},{"elapsedMs":35,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/malformed-token"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/malformed-token","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":35,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/malformed-token"},"testedTabPreserved":true},"completed":true,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"moz-extension://stargate-test/options/options.html","elapsedSeconds":3.052,"observedAtMonotonic":9227251.437579,"popupLabel":"Main navigation decision: Blocked by Stargate Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"moz-extension://stargate-test/options/options.html"}},
      "missing-token-no-fallback": {"destinationCaptures":[],"httpCaptures":[],"markersObserved":[],"passed":true,"requiredMarkers":[],"socksCaptures":[],"terminal":{"browserProgress":{"events":[{"elapsedMs":15,"flags":983041,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/missing-token"},{"elapsedMs":29,"flags":131088,"networkStop":false,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/missing-token"},{"elapsedMs":30,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/missing-token"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/missing-token","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":30,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/missing-token"},"testedTabPreserved":true},"completed":true,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"about:blank","elapsedSeconds":3.033,"observedAtMonotonic":9227230.590709,"popupLabel":"Main navigation decision: Blocked by Stargate Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"about:blank"}},
      "redirect-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/redirect HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227207.928805,"path":"/redirect"}],"markersObserved":[],"passed":true,"requiredMarkers":[],"socksCaptures":[],"terminal":{"browserProgress":{"events":[{"elapsedMs":6,"flags":983041,"networkStop":false,"status":0,"url":"http://direct.example.com/redirect"},{"elapsedMs":20,"flags":131088,"networkStop":false,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/redirect-target"},{"elapsedMs":22,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/redirect-target"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/redirect-target","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":22,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/redirect-target"},"testedTabPreserved":true},"completed":true,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"http://direct.example.com/page","elapsedSeconds":3.015,"observedAtMonotonic":9227212.038458,"popupLabel":"Main navigation decision: Blocked by Stargate Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"http://direct.example.com/page"}},
      "sidecar-identical-path-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/sidecar-page HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227327.769421,"path":"/sidecar-page"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227327.833579,"path":"/favicon.ico"},{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227327.945207,"path":"/marker/sidecar-start"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227327.968553,"path":"/marker/sidecar-done"}],"passed":true,"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227327.956715,"passwordMatches":true,"path":"/sidecar-path","port":38023,"stage":"request","username":"sg1:aeb85275b1ffe8f63f0fc50157b3e6a7f97760eac08115ef61e947a7d19b405d"}],"terminal":{"completed":true,"outcome":"fulfilled"}},
      "sidecar-identical-path-unavailable": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227328.467548,"path":"/marker/sidecar-start"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227328.488465,"path":"/marker/sidecar-done"}],"markersObserved":["/marker/sidecar-done","/marker/sidecar-start"],"matchingPositivePassed":true,"passed":true,"requiredMarkers":["/marker/sidecar-done","/marker/sidecar-start"],"socksCaptures":[],"terminal":{"completed":true,"observedAtMonotonic":9227328.49268,"outcome":"rejected"}},
      "sidecar-reconnect-race-positive-control": {"acceptedAfterSeconds":0.015,"connectionAcceptedBeforeRelease":true,"destinationCaptures":[],"httpCaptures":[],"passed":true,"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227299.752528,"passwordMatches":true,"path":"/sidecar-reconnected","port":38023,"stage":"request","username":"sg1:9bb303a7f63cd7935e39793145e20e17bebaed21a900e7eb09b6202a7d2c0417"}],"terminal":{"completed":true,"documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/sidecar-reconnected","elapsedSeconds":0.124,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/sidecar-reconnected"}},
      "startup-initialization-overlap": {"after":{"events":[{"kind":"initialization-held","sequence":0},{"hardeningOk":true,"held":true,"kind":"protected-proxy-request","released":false,"requestId":"3","sequence":1,"type":"main_frame"},{"kind":"initialization-release","sequence":2},{"kind":"initialization-returned","sequence":3}],"hardeningOk":true,"held":true,"released":true,"storedDevice":{"bearerToken":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","name":"live-control","tokenStoredAt":1}},"before":{"events":[{"kind":"initialization-held","sequence":0}],"hardeningOk":true,"held":true,"released":false,"storedDevice":{"bearerToken":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","name":"live-control","tokenStoredAt":1}},"destinationCaptures":[],"httpCaptures":[],"instrumentation":{"changedMembers":{"background/t157-startup.js":{"afterSha256":"f747c2873be28d8c9248b0ce3f09863b1b51d0e80bed900a4a40729537918e26","beforeSha256":null},"manifest.json":{"afterSha256":"6b03d599ce352ab79ff1f6e8a1dbf537acb86c190318849dc78e8039bfb24e7e","beforeSha256":"6d6d89a5a0e6844094dd861d208e6182fd172e2ea63207533e44c6c08c92e114"}},"packageSha256":"8b784eb48eb7b61dd6f57fb150fb23107fa00485fe4a0ac32de2a3e8e7ea1276","sourceSha256":"c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0","variant":"startup"},"overlapEstablished":true,"passed":true,"pending":{"events":[{"kind":"initialization-held","sequence":0},{"hardeningOk":true,"held":true,"kind":"protected-proxy-request","released":false,"requestId":"3","sequence":1,"type":"main_frame"}],"hardeningOk":true,"held":true,"released":false,"storedDevice":{"bearerToken":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","name":"live-control","tokenStoredAt":1}},"pendingCaptures":{"destination":[],"http":[],"socks":[]},"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227311.636934,"passwordMatches":true,"path":"/startup-held","port":38023,"stage":"request","username":"sg1:ce17e4cc727528b15f1f7ae9ac56bc1cbadaab59f088a5b299b493dafe23afa1"},{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227311.738319,"passwordMatches":true,"path":"/favicon.ico","port":38023,"stage":"request","username":"sg1:ce17e4cc727528b15f1f7ae9ac56bc1cbadaab59f088a5b299b493dafe23afa1"}],"terminal":{"completed":true,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/startup-held"}},
      "subresource-and-retry-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/page HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227196.557536,"path":"/page"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227196.753874,"path":"/favicon.ico"},{"firstLine":"GET http://direct.example.com/marker/retry-one-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227196.831276,"path":"/marker/retry-one-done"},{"firstLine":"GET http://direct.example.com/marker/subresource-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227196.83438,"path":"/marker/subresource-done"},{"firstLine":"GET http://direct.example.com/marker/retry-two-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9227196.834591,"path":"/marker/retry-two-done"}],"markersObserved":["/marker/retry-one-done","/marker/retry-two-done","/marker/subresource-done"],"passed":true,"requiredMarkers":["/marker/retry-one-done","/marker/retry-two-done","/marker/subresource-done"],"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://direct.example.com/page","elapsedSeconds":0.461,"observedAtMonotonic":9227196.913249,"readyState":"complete","url":"http://direct.example.com/page"}},
      "tor-positive-control": {"destinationCaptures":[],"httpCaptures":[],"passed":true,"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227298.926581,"passwordMatches":true,"path":"/tor-positive","port":38023,"stage":"request","username":"sg1:9bb303a7f63cd7935e39793145e20e17bebaed21a900e7eb09b6202a7d2c0417"},{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227298.988849,"passwordMatches":true,"path":"/favicon.ico","port":38023,"stage":"request","username":"sg1:9bb303a7f63cd7935e39793145e20e17bebaed21a900e7eb09b6202a7d2c0417"}],"terminal":{"completed":true,"documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/tor-positive","elapsedSeconds":0.18,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/tor-positive"}},
      "tor-redirect-positive-control": {"destinationCaptures":[],"httpCaptures":[],"passed":true,"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227299.229273,"passwordMatches":true,"path":"/tor-redirect-start","port":38023,"stage":"request","username":"sg1:9bb303a7f63cd7935e39793145e20e17bebaed21a900e7eb09b6202a7d2c0417"},{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227299.235844,"passwordMatches":true,"path":"/tor-redirect-target","port":38023,"stage":"request","username":"sg1:9bb303a7f63cd7935e39793145e20e17bebaed21a900e7eb09b6202a7d2c0417"}],"terminal":{"completed":true,"documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/tor-redirect-target","elapsedSeconds":0.118,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/tor-redirect-target"}},
      "tor-subresource-retry-positive-control": {"destinationCaptures":[],"httpCaptures":[],"passed":true,"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227299.106466,"passwordMatches":true,"path":"/tor-page","port":38023,"stage":"request","username":"sg1:9bb303a7f63cd7935e39793145e20e17bebaed21a900e7eb09b6202a7d2c0417"},{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227299.141708,"passwordMatches":true,"path":"/tor-subresource","port":38023,"stage":"request","username":"sg1:9bb303a7f63cd7935e39793145e20e17bebaed21a900e7eb09b6202a7d2c0417"},{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9227299.141951,"passwordMatches":true,"path":"/tor-retry","port":38023,"stage":"request","username":"sg1:9bb303a7f63cd7935e39793145e20e17bebaed21a900e7eb09b6202a7d2c0417"}],"terminal":{"completed":true,"documentURI":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/tor-page","elapsedSeconds":0.13,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/tor-page"}},
      "unreadable-hardening-api-no-fallback": {"auditRecord":{"lastAuditResult":{"blockedSurface":"webrtc","pref":"privacy.network.peerConnectionEnabled","readError":"can't access property \"network\", browser.privacy is undefined"},"lastAuditedAt":497289},"destinationCaptures":[],"faultInjection":"privacy permission removed from otherwise identical package","httpCaptures":[],"markersObserved":[],"passed":true,"requiredMarkers":[],"socksCaptures":[],"terminal":{"browserProgress":{"events":[{"elapsedMs":16,"flags":983041,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/unreadable-hardening-api"},{"elapsedMs":34,"flags":131088,"networkStop":false,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/unreadable-hardening-api"},{"elapsedMs":38,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/unreadable-hardening-api"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/unreadable-hardening-api","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":38,"flags":786448,"networkStop":true,"status":2147500036,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:38023/unreadable-hardening-api"},"testedTabPreserved":true},"completed":true,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"moz-extension://stargate-test/options/options.html","elapsedSeconds":3.074,"observedAtMonotonic":9227271.966064,"popupLabel":"Main navigation decision: Blocked by Stargate Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"moz-extension://stargate-test/options/options.html"}}
    },
    "unknownHardeningFaultExtensionSha256": "cd379ba1ef405606d4eced2fbde0ea258b6c44bcc58748439d48b332283d8dbf"
  }
  ```

  **observe** — `target/runs/T157-refined-observe.json`; original report SHA-256
  `7181aeaf4e9a99b2288acf76f2751562f4825f7ba17a55de5167adbca32c7d96`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[603514] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--only","sidecar","--mutation","observe","--report-out","target/runs/T157-refined-observe.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "fb6c0c7b4f377fe7f3f17463564a08d43f852f4a9327bf07c431ea7eb93021aa",
    "extensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "failures": [],
    "mutation": {"changedMembers":{"background/t157-audit.js":{"afterSha256":"28d7aa5bd10552e5b45e520ff0b0cc6fd85d5125c8d2fec99ea94dae894e68cf","beforeSha256":null},"manifest.json":{"afterSha256":"834f816980696d68f6c8a9d595076f99480a6dba3ac4793403362addc6067342","beforeSha256":"6d6d89a5a0e6844094dd861d208e6182fd172e2ea63207533e44c6c08c92e114"}},"packageSha256":"fb6c0c7b4f377fe7f3f17463564a08d43f852f4a9327bf07c431ea7eb93021aa","sourceSha256":"c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0","variant":"observe"},
    "mutationName": "observe",
    "result": "GREEN",
    "scenarios": {
      "live-terminal-chain-contract": {"callbackAudit":[{"name":"proxy","proxyInfo":null,"requestId":"6","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:d8b1ae228b27c8c7a33c28bd3b2c0946aed471388dcdc937464b108459d325ee"},null]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:d8b1ae228b27c8c7a33c28bd3b2c0946aed471388dcdc937464b108459d325ee"},"requestId":"6","result":{}},{"name":"proxy","proxyInfo":null,"requestId":"9","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:d8b1ae228b27c8c7a33c28bd3b2c0946aed471388dcdc937464b108459d325ee"},null]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:d8b1ae228b27c8c7a33c28bd3b2c0946aed471388dcdc937464b108459d325ee"},"requestId":"9","result":{}}],"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223287.536553,"path":"/marker/sidecar-start"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223287.556934,"path":"/marker/sidecar-done"}],"passed":true,"socksCaptures":[]},
      "sidecar-identical-path-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/sidecar-page HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223286.859325,"path":"/sidecar-page"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223286.936134,"path":"/favicon.ico"},{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223287.014434,"path":"/marker/sidecar-start"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223287.033603,"path":"/marker/sidecar-done"}],"passed":true,"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223287.021991,"passwordMatches":true,"path":"/sidecar-path","port":41195,"stage":"request","username":"sg1:d8b1ae228b27c8c7a33c28bd3b2c0946aed471388dcdc937464b108459d325ee"}],"terminal":{"completed":true,"outcome":"fulfilled"}},
      "sidecar-identical-path-unavailable": {"callbackAudit":[{"name":"proxy","proxyInfo":null,"requestId":"6","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:d8b1ae228b27c8c7a33c28bd3b2c0946aed471388dcdc937464b108459d325ee"},null]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:d8b1ae228b27c8c7a33c28bd3b2c0946aed471388dcdc937464b108459d325ee"},"requestId":"6","result":{}},{"name":"proxy","proxyInfo":null,"requestId":"9","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:d8b1ae228b27c8c7a33c28bd3b2c0946aed471388dcdc937464b108459d325ee"},null]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:d8b1ae228b27c8c7a33c28bd3b2c0946aed471388dcdc937464b108459d325ee"},"requestId":"9","result":{}}],"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223287.536553,"path":"/marker/sidecar-start"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223287.556934,"path":"/marker/sidecar-done"}],"markersObserved":["/marker/sidecar-done","/marker/sidecar-start"],"matchingPositivePassed":true,"passed":true,"requiredMarkers":["/marker/sidecar-done","/marker/sidecar-start"],"socksCaptures":[],"terminal":{"completed":true,"observedAtMonotonic":9223287.561393,"outcome":"rejected"}}
    }
  }
  ```

  **terminal-null** — `target/runs/T157-refined-terminal-null.json`; original report SHA-256
  `9275d36da0647879e934eb8472f153886c61046a652699771ed99e2a0c13f8e3`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[607252] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--only","sidecar","--mutation","terminal-null","--report-out","target/runs/T157-refined-terminal-null.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "85426db0bde44c463600d33688e70e87001f6a3934a6fadade25ad3b8ed92555",
    "extensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "failures": ["live-terminal-chain-contract"],
    "mutation": {"changedMembers":{"background/router.js":{"afterSha256":"42ecf2e6b3378ecb6c96907232ebf27d09f16cd9415c9b4c36a890ba76758bed","beforeSha256":"3e7e82b51bad542a1a4dc58615acdd55d6faccf49b3150d347363e4f3cfb251c"},"background/t157-audit.js":{"afterSha256":"28d7aa5bd10552e5b45e520ff0b0cc6fd85d5125c8d2fec99ea94dae894e68cf","beforeSha256":null},"manifest.json":{"afterSha256":"834f816980696d68f6c8a9d595076f99480a6dba3ac4793403362addc6067342","beforeSha256":"6d6d89a5a0e6844094dd861d208e6182fd172e2ea63207533e44c6c08c92e114"}},"packageSha256":"85426db0bde44c463600d33688e70e87001f6a3934a6fadade25ad3b8ed92555","sourceSha256":"c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0","variant":"terminal-null"},
    "mutationName": "terminal-null",
    "result": "RED",
    "scenarios": {
      "live-terminal-chain-contract": {"callbackAudit":[{"name":"proxy","proxyInfo":null,"requestId":"6","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:a9658aee4ebecd7f6982b6a7e547f3e55b184bf5f1fde8f5fdf3ed06eb2c22fb"}]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:a9658aee4ebecd7f6982b6a7e547f3e55b184bf5f1fde8f5fdf3ed06eb2c22fb"},"requestId":"6","result":{}},{"name":"proxy","proxyInfo":null,"requestId":"9","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:a9658aee4ebecd7f6982b6a7e547f3e55b184bf5f1fde8f5fdf3ed06eb2c22fb"}]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:a9658aee4ebecd7f6982b6a7e547f3e55b184bf5f1fde8f5fdf3ed06eb2c22fb"},"requestId":"9","result":{}},{"name":"blocker","proxyInfo":{"connectionIsolationKey":"","failoverTimeout":1800,"host":"127.0.0.1","port":36565,"proxyAuthorizationHeader":"","proxyDNS":false,"type":"http","username":""},"requestId":"9","result":{"cancel":true}}],"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223305.964043,"path":"/marker/sidecar-start"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223305.987833,"path":"/marker/sidecar-done"}],"passed":false,"socksCaptures":[]},
      "sidecar-identical-path-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/sidecar-page HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223305.27018,"path":"/sidecar-page"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223305.359135,"path":"/favicon.ico"},{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223305.437176,"path":"/marker/sidecar-start"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223305.453379,"path":"/marker/sidecar-done"}],"passed":true,"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223305.445507,"passwordMatches":true,"path":"/sidecar-path","port":37873,"stage":"request","username":"sg1:a9658aee4ebecd7f6982b6a7e547f3e55b184bf5f1fde8f5fdf3ed06eb2c22fb"}],"terminal":{"completed":true,"outcome":"fulfilled"}},
      "sidecar-identical-path-unavailable": {"callbackAudit":[{"name":"proxy","proxyInfo":null,"requestId":"6","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:a9658aee4ebecd7f6982b6a7e547f3e55b184bf5f1fde8f5fdf3ed06eb2c22fb"}]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:a9658aee4ebecd7f6982b6a7e547f3e55b184bf5f1fde8f5fdf3ed06eb2c22fb"},"requestId":"6","result":{}},{"name":"proxy","proxyInfo":null,"requestId":"9","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:a9658aee4ebecd7f6982b6a7e547f3e55b184bf5f1fde8f5fdf3ed06eb2c22fb"}]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:a9658aee4ebecd7f6982b6a7e547f3e55b184bf5f1fde8f5fdf3ed06eb2c22fb"},"requestId":"9","result":{}},{"name":"blocker","proxyInfo":{"connectionIsolationKey":"","failoverTimeout":1800,"host":"127.0.0.1","port":36565,"proxyAuthorizationHeader":"","proxyDNS":false,"type":"http","username":""},"requestId":"9","result":{"cancel":true}}],"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223305.964043,"path":"/marker/sidecar-start"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223305.987833,"path":"/marker/sidecar-done"}],"markersObserved":["/marker/sidecar-done","/marker/sidecar-start"],"matchingPositivePassed":true,"passed":true,"requiredMarkers":["/marker/sidecar-done","/marker/sidecar-start"],"socksCaptures":[],"terminal":{"completed":true,"observedAtMonotonic":9223306.011474,"outcome":"rejected"}}
    }
  }
  ```

  **terminal-null-and-blocker** — `target/runs/T157-refined-terminal-null-and-blocker.json`; original report SHA-256
  `f24b157e56cf6253232bb1593d41d13f6cffcc3d63d62c8669ab3127b563bd22`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[611131] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--only","sidecar","--mutation","terminal-null-and-blocker","--report-out","target/runs/T157-refined-terminal-null-and-blocker.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "94922f3896feb041f80cfad462fecd78059f91afcdef7a932b3c450089598c2d",
    "extensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "failures": ["sidecar-identical-path-unavailable","live-terminal-chain-contract"],
    "mutation": {"changedMembers":{"background/router.js":{"afterSha256":"7f7ce067e4b346522e3de3d0738117a4ff45032f5d8ec35fea26d832dacf274a","beforeSha256":"3e7e82b51bad542a1a4dc58615acdd55d6faccf49b3150d347363e4f3cfb251c"},"background/t157-audit.js":{"afterSha256":"28d7aa5bd10552e5b45e520ff0b0cc6fd85d5125c8d2fec99ea94dae894e68cf","beforeSha256":null},"manifest.json":{"afterSha256":"834f816980696d68f6c8a9d595076f99480a6dba3ac4793403362addc6067342","beforeSha256":"6d6d89a5a0e6844094dd861d208e6182fd172e2ea63207533e44c6c08c92e114"}},"packageSha256":"94922f3896feb041f80cfad462fecd78059f91afcdef7a932b3c450089598c2d","sourceSha256":"c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0","variant":"terminal-null-and-blocker"},
    "mutationName": "terminal-null-and-blocker",
    "result": "RED",
    "scenarios": {
      "live-terminal-chain-contract": {"callbackAudit":[{"name":"proxy","proxyInfo":null,"requestId":"6","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:16fdcf7e4f0d35ba3adee662e237f742ca6cb28d462c320ec41d69d49616e3f6"}]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:16fdcf7e4f0d35ba3adee662e237f742ca6cb28d462c320ec41d69d49616e3f6"},"requestId":"6","result":{}},{"name":"proxy","proxyInfo":null,"requestId":"9","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:16fdcf7e4f0d35ba3adee662e237f742ca6cb28d462c320ec41d69d49616e3f6"}]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:16fdcf7e4f0d35ba3adee662e237f742ca6cb28d462c320ec41d69d49616e3f6"},"requestId":"9","result":{}},{"name":"blocker","proxyInfo":{"connectionIsolationKey":"","failoverTimeout":1800,"host":"127.0.0.1","port":40485,"proxyAuthorizationHeader":"","proxyDNS":false,"type":"http","username":""},"requestId":"9","result":{}}],"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223323.260577,"path":"/marker/sidecar-start"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:33893/sidecar-path HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223323.268325,"path":"/sidecar-path"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223323.273625,"path":"/marker/sidecar-done"}],"passed":false,"socksCaptures":[]},
      "sidecar-identical-path-positive-control": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/sidecar-page HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223322.586364,"path":"/sidecar-page"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223322.62618,"path":"/favicon.ico"},{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223322.718817,"path":"/marker/sidecar-start"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223322.733794,"path":"/marker/sidecar-done"}],"passed":true,"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223322.724705,"passwordMatches":true,"path":"/sidecar-path","port":33893,"stage":"request","username":"sg1:16fdcf7e4f0d35ba3adee662e237f742ca6cb28d462c320ec41d69d49616e3f6"}],"terminal":{"completed":true,"outcome":"fulfilled"}},
      "sidecar-identical-path-unavailable": {"callbackAudit":[{"name":"proxy","proxyInfo":null,"requestId":"6","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:16fdcf7e4f0d35ba3adee662e237f742ca6cb28d462c320ec41d69d49616e3f6"}]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:16fdcf7e4f0d35ba3adee662e237f742ca6cb28d462c320ec41d69d49616e3f6"},"requestId":"6","result":{}},{"name":"proxy","proxyInfo":null,"requestId":"9","result":[{"host":"127.0.0.1","password":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","port":8881,"proxyDNS":true,"type":"socks","username":"sg1:16fdcf7e4f0d35ba3adee662e237f742ca6cb28d462c320ec41d69d49616e3f6"}]},{"name":"blocker","proxyInfo":{"connectionIsolationKey":null,"failoverTimeout":10,"host":"127.0.0.1","port":8881,"proxyAuthorizationHeader":null,"proxyDNS":true,"type":"socks","username":"sg1:16fdcf7e4f0d35ba3adee662e237f742ca6cb28d462c320ec41d69d49616e3f6"},"requestId":"9","result":{}},{"name":"blocker","proxyInfo":{"connectionIsolationKey":"","failoverTimeout":1800,"host":"127.0.0.1","port":40485,"proxyAuthorizationHeader":"","proxyDNS":false,"type":"http","username":""},"requestId":"9","result":{}}],"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/sidecar-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223323.260577,"path":"/marker/sidecar-start"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:33893/sidecar-path HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223323.268325,"path":"/sidecar-path"},{"firstLine":"GET http://direct.example.com/marker/sidecar-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223323.273625,"path":"/marker/sidecar-done"}],"markersObserved":["/marker/sidecar-done","/marker/sidecar-start"],"matchingPositivePassed":true,"passed":false,"requiredMarkers":["/marker/sidecar-done","/marker/sidecar-start"],"socksCaptures":[],"terminal":{"completed":false,"observedAtMonotonic":9223323.278479,"outcome":"fulfilled"}}
    }
  }
  ```

  **opaque-context** — `target/runs/T157-refined-opaque-context.json`; original report SHA-256
  `807fb78417cd2cb26fa2a13ca3901e9dd04d1eaa7d0823b438b38b212aadb402`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[614911] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--only","context","--mutation","opaque-context","--report-out","target/runs/T157-refined-opaque-context.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "9151a9375bf53e1fd4693680c09f5883eaa95111b080ec99675494a449e151c2",
    "extensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "failures": ["absent-initiating-context-no-fallback"],
    "mutation": {"changedMembers":{"background/router.js":{"afterSha256":"d3edf3c9eff534ce52a2b17919d7df25508fdfaec69c66102ecf23f0230492cb","beforeSha256":"3e7e82b51bad542a1a4dc58615acdd55d6faccf49b3150d347363e4f3cfb251c"}},"packageSha256":"9151a9375bf53e1fd4693680c09f5883eaa95111b080ec99675494a449e151c2","sourceSha256":"c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0","variant":"opaque-context"},
    "mutationName": "opaque-context",
    "result": "RED",
    "scenarios": {
      "absent-initiating-context-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/context-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223339.708183,"path":"/marker/context-start"},{"firstLine":"GET http://direct.example.com/marker/context-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223339.722647,"path":"/marker/context-done"}],"markersObserved":["/marker/context-done","/marker/context-start"],"passed":false,"requiredMarkers":["/marker/context-done","/marker/context-start"],"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223339.712397,"passwordMatches":true,"path":"/opaque-context","port":35469,"stage":"request","username":"sg1:e74d33469810515b7adeaa1464272648f039cff65aefc10c3c1c7be12a6689b2"}],"terminal":{"completed":true,"documentURI":"data:text/html,%3Cscript%3Efetch%28%27http%3A//direct.example.com/marker/context-start%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A35469/opaque-context%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//direct.example.com/marker/context-done%27%29%29%29%3C/script%3E","elapsedSeconds":0.139,"observedAtMonotonic":9223339.806029,"readyState":"complete","url":"data:text/html,%3Cscript%3Efetch%28%27http%3A//direct.example.com/marker/context-start%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A35469/opaque-context%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//direct.example.com/marker/context-done%27%29%29%29%3C/script%3E"}}
    }
  }
  ```

  **suppress-subrequest** — `target/runs/T157-refined-suppress-subrequest.json`; original report SHA-256
  `ef5fa1a78066de878b7d309c2f6d3281ce9de328e8f6e69646f8b35225e30f2f`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[618383] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--only","fixture","--mutation","suppress-subrequest","--report-out","target/runs/T157-refined-suppress-subrequest.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "extensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "failures": ["subresource-and-retry-no-fallback"],
    "mutationName": "suppress-subrequest",
    "result": "RED",
    "scenarios": {
      "subresource-and-retry-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/page HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223356.183454,"path":"/page"},{"firstLine":"GET http://direct.example.com/favicon.ico HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223356.370623,"path":"/favicon.ico"}],"markersObserved":[],"passed":false,"requiredMarkers":["/marker/retry-one-done","/marker/retry-two-done","/marker/subresource-done"],"socksCaptures":[],"terminal":{"completed":true,"documentURI":"http://direct.example.com/page","elapsedSeconds":0.378,"observedAtMonotonic":9223356.459166,"readyState":"complete","url":"http://direct.example.com/page"}}
    }
  }
  ```

  **delayed-fallback** — `target/runs/T157-refined-delayed-fallback.json`; original report SHA-256
  `c6322ff5780a654dc78b64a9d0b2f1c1f2d8caaaaefbfa7f6437f250ec315ada`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[623809] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--only","context","--mutation","delayed-fallback","--report-out","target/runs/T157-refined-delayed-fallback.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "a799ac9d07e276672d3675127b7121af5d6006308b0111730d3e670391f2a312",
    "extensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "failures": ["absent-initiating-context-no-fallback"],
    "mutation": {"changedMembers":{"background/router.js":{"afterSha256":"f66642cca36558e0bcffdc93b15c64ad982e110ff3137c95c72929864b2e5d69","beforeSha256":"3e7e82b51bad542a1a4dc58615acdd55d6faccf49b3150d347363e4f3cfb251c"}},"packageSha256":"a799ac9d07e276672d3675127b7121af5d6006308b0111730d3e670391f2a312","sourceSha256":"c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0","variant":"delayed-fallback"},
    "mutationName": "delayed-fallback",
    "result": "RED",
    "scenarios": {
      "absent-initiating-context-no-fallback": {"destinationCaptures":[],"httpCaptures":[{"firstLine":"GET http://direct.example.com/marker/context-start HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223382.966292,"path":"/marker/context-start"},{"firstLine":"GET http://direct.example.com/marker/context-done HTTP/1.1","host":"direct.example.com","observedAtMonotonic":9223382.972527,"path":"/marker/context-done"},{"firstLine":"GET http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:45601/delayed-fallback HTTP/1.1","host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223384.456304,"path":"/delayed-fallback"}],"markersObserved":["/marker/context-done","/marker/context-start"],"passed":false,"requiredMarkers":["/marker/context-done","/marker/context-start"],"socksCaptures":[],"terminal":{"completed":true,"documentURI":"data:text/html,%3Cscript%3EsetTimeout%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A45601/delayed-fallback%27%29%2C1500%29%3Bfetch%28%27http%3A//direct.example.com/marker/context-start%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A45601/opaque-context%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//direct.example.com/marker/context-done%27%29%29%29%3C/script%3E","elapsedSeconds":0.149,"observedAtMonotonic":9223383.075237,"readyState":"complete","url":"data:text/html,%3Cscript%3EsetTimeout%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A45601/delayed-fallback%27%29%2C1500%29%3Bfetch%28%27http%3A//direct.example.com/marker/context-start%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion%3A45601/opaque-context%27%29.finally%28%28%29%3D%3Efetch%28%27http%3A//direct.example.com/marker/context-done%27%29%29%29%3C/script%3E"}}
    }
  }
  ```

  **startup-release** — `target/runs/T157-refined-startup-release.json`; original report SHA-256
  `f251126b0874b960cd548061cbf4bccd974182c5c5a67848811904e4a2439e74`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[627307] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--only","startup","--mutation","startup-release","--report-out","target/runs/T157-refined-startup-release.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "extensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "failures": ["startup-initialization-overlap"],
    "mutationName": "startup-release",
    "result": "RED",
    "scenarios": {
      "startup-initialization-overlap": {"after":{"events":[{"kind":"initialization-held","sequence":0},{"kind":"initialization-release","sequence":1},{"kind":"initialization-returned","sequence":2},{"hardeningOk":true,"held":true,"kind":"protected-proxy-request","released":true,"requestId":"3","sequence":3,"type":"main_frame"}],"hardeningOk":true,"held":true,"released":true,"storedDevice":{"bearerToken":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","name":"live-control","tokenStoredAt":1}},"before":{"events":[{"kind":"initialization-held","sequence":0}],"hardeningOk":true,"held":true,"released":false,"storedDevice":{"bearerToken":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","name":"live-control","tokenStoredAt":1}},"destinationCaptures":[],"httpCaptures":[],"instrumentation":{"changedMembers":{"background/t157-startup.js":{"afterSha256":"f747c2873be28d8c9248b0ce3f09863b1b51d0e80bed900a4a40729537918e26","beforeSha256":null},"manifest.json":{"afterSha256":"6b03d599ce352ab79ff1f6e8a1dbf537acb86c190318849dc78e8039bfb24e7e","beforeSha256":"6d6d89a5a0e6844094dd861d208e6182fd172e2ea63207533e44c6c08c92e114"}},"packageSha256":"8b784eb48eb7b61dd6f57fb150fb23107fa00485fe4a0ac32de2a3e8e7ea1276","sourceSha256":"c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0","variant":"startup"},"overlapEstablished":false,"passed":false,"pending":{"events":[{"kind":"initialization-held","sequence":0},{"kind":"initialization-release","sequence":1},{"kind":"initialization-returned","sequence":2},{"hardeningOk":true,"held":true,"kind":"protected-proxy-request","released":true,"requestId":"3","sequence":3,"type":"main_frame"}],"hardeningOk":true,"held":true,"released":true,"storedDevice":{"bearerToken":"0f1e2d3c0f1e2d3c0f1e2d3c0f1e2d3c","name":"live-control","tokenStoredAt":1}},"pendingCaptures":{"destination":[],"http":[],"socks":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223400.599336,"passwordMatches":true,"path":"/startup-held","port":35781,"stage":"request","username":"sg1:a8c22cbcfea52acc79688eb6c6f1f0576048d43395c44addce461be576d5a671"},{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223400.658062,"passwordMatches":true,"path":"/favicon.ico","port":35781,"stage":"request","username":"sg1:a8c22cbcfea52acc79688eb6c6f1f0576048d43395c44addce461be576d5a671"}]},"socksCaptures":[{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223400.599336,"passwordMatches":true,"path":"/startup-held","port":35781,"stage":"request","username":"sg1:a8c22cbcfea52acc79688eb6c6f1f0576048d43395c44addce461be576d5a671"},{"host":"abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion","observedAtMonotonic":9223400.658062,"passwordMatches":true,"path":"/favicon.ico","port":35781,"stage":"request","username":"sg1:a8c22cbcfea52acc79688eb6c6f1f0576048d43395c44addce461be576d5a671"}],"terminal":{"completed":true,"readyState":"complete","url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:35781/startup-held"}}
    }
  }
  ```

  **delayed-main-navigation** — `target/runs/T157-r2-delayed-main-navigation.json`; original report SHA-256
  `8c30d9c040a481e34722062d8db8f4d20e6ea85ef9f02abb9e3b315e9f6127d3`.

  ```json
  {
    "artifactSha256": "9039e153d19c8ec734c985ff3b6f42050edd48b65099dd58d251044c35d183ab",
    "browserVersion": "[1457644] Sandbox: CanCreateUserNamespace() unshare(CLONE_NEWPID): EPERM\nMullvad MullvadBrowser 153.3.0esr",
    "command": ["tests/live-e2e/mullvad-browser-hardening/probe.py","--browser","target/t157-tools/mullvad-browser/Browser/mullvadbrowser","--driver","target/t157-tools/geckodriver","--extension","extension/dist/stargate-extension.zip","--artifact","target/t157-tools/mullvad-browser-linux-x86_64-16.0a12.tar.xz","--only","navigation","--mutation","delayed-main-navigation","--report-out","target/runs/T157-r2-delayed-main-navigation.json"],
    "driverVersion": "geckodriver 0.37.0",
    "executedExtensionSha256": "266544c07a32053f6919ef8bcc547e80be7402a526c6556c39124fd7134cd395",
    "extensionSha256": "c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0",
    "failures": ["hardening-failure-no-fallback"],
    "mutation": {"changedMembers":{"background/router.js":{"afterSha256":"7f2a1f6f1ce0574a7e7fb38cb77152a32cea49bf701d11eff141a175cf681b74","beforeSha256":"3e7e82b51bad542a1a4dc58615acdd55d6faccf49b3150d347363e4f3cfb251c"}},"packageSha256":"266544c07a32053f6919ef8bcc547e80be7402a526c6556c39124fd7134cd395","sourceSha256":"c8d50777be5af64fa2bde10774da3840b5423a8e0674b28fef59bb3fc86161b0","variant":"delayed-main-navigation"},
    "mutationName": "delayed-main-navigation",
    "result": "RED",
    "scenarios": {
      "hardening-failure-no-fallback": {"destinationCaptures":[],"httpCaptures":[],"markersObserved":[],"passed":false,"requiredMarkers":[],"socksCaptures":[],"terminal":{"browserProgress":{"events":[{"elapsedMs":13,"flags":983041,"networkStop":false,"status":0,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:36713/hardening-closed"},{"elapsedMs":6091,"flags":131088,"networkStop":false,"status":2152398878,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:36713/hardening-closed"},{"elapsedMs":6099,"flags":786448,"networkStop":true,"status":2152398878,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:36713/hardening-closed"}],"expected":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:36713/hardening-closed","expectedAbortStatus":2147500036,"terminal":{"elapsedMs":6099,"flags":786448,"networkStop":true,"status":2152398878,"url":"http://abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345abcd2345.onion:36713/hardening-closed"},"testedTabPreserved":true},"completed":false,"completionEvidence":"browser URL-bound STATE_STOP | STATE_IS_NETWORK with NS_ERROR_ABORT","documentURI":"moz-extension://stargate-test/options/options.html","elapsedSeconds":3.097,"observedAtMonotonic":9227148.436538,"popupLabel":"Main navigation decision: Blocked by Stargate Other requests may use different routes. Connection success is not verified.","readyState":"complete","url":"moz-extension://stargate-test/options/options.html"}}
    }
  }
  ```

  </details>
- **T186 live evidence (2026-09-29, review round 2):**
  `tests/live-e2e/mullvad-browser-hardening/probe.py` observes four surfaces per request with no cancel listener: the destination catcher (the name
  mapped to loopback via `network.dns.localDomains`), the configured ordinary HTTP proxy,
  listeners standing at the descriptor's own target, and name resolution (strace of every browser
  socket to port 53 with native resolution, plus MOZ_LOG `nsHostResolver` matched on the looked-up
  host). Each request form uses a fresh random 56-character onion label: `.onion`, `.onion.`,
  mixed-case `.OnIoN.` (all mapped) and an unmapped `.onion.` for DNS. Every request runs in its
  own tab that no later request replaces, must reach a terminal document bound to its label (the
  loaded page, or a browser error page naming that URL), and all tabs stay open at least twelve
  seconds after the last terminal result — past Gecko's ten-second proxy failover bound. A
  negative result also requires that terminal error; an incomplete request fails the probe.
  - `--only descriptor-matrix` (proxy-only test extension; Mullvad Browser 140.16.0esr at
    `/usr/lib/mullvad-browser`, report SHA-256
    `f406b0babe51b88d2143502c792de80aa9749d3ca098b63aa1ad19f4f7bb357c`, and the pinned
    153.3.0esr Alpha, `38336f1973824ef4fa92fbabc23e3a0c7f7d3a8fe5af8d0a408a7d2bb584de98`;
    identical outcomes). Controls: a `null` result for a mapped `.test` name reached the
    destination, `{type:'direct'}` reached the system proxy, and an unmapped `.invalid` name
    appeared both in strace (`sendmmsg(…127.0.0.53:53…)`) and in MOZ_LOG. **D1 `null`:** `.onion`
    was stopped by `network.dns.blockDotOnion`; `.onion.` and mixed-case loaded from the
    destination directly; unmapped `.onion.` was sent to the stub resolver. **D1-style SOCKS
    port:** a fake SOCKS listener received the onion name for all four forms. **D5:** the same
    descriptor pointed at a listening Unix socket delivered every name (support calibrated);
    pointed at the sink, strace shows `connect(AF_UNIX "/dev/null/stargate-blocked") = -1
    ENOTDIR`, every request ended at its own `proxyConnectFailure` page, and all six surfaces were
    empty for all four forms. **D4:** `127.0.0.1:1023` refused; a plain listener received only a
    TLS ClientHello (no name, no `onion` bytes); a self-signed TLS listener saw `bad certificate`
    and no request. Calibration: with certificate errors accepted, that listener decrypted
    `GET http://<label>.onion.:<port>/…`.
  - `--only blocked-proxy` (the real package with only its cancel listener removed; pinned
    153.3.0esr; sessions with a missing token and with hardening closed). **Red** (pre-fix
    package `7e4cc26c…83e9`, report `b547162a5af22ed4ac7dacab0a1e807522b21062b5bd8a8cd798bae05e52d814`):
    in both sessions `.onion.` and mixed-case loaded from the destination and the unmapped
    `.onion.` reached the resolver. **Candidate** (package `727777ce…b89b`, report
    `d82e5bc0752c099529af31a9869f8a770b3ca2ae272956b192fb54c5a1ef9a4e`): every form in both
    sessions reached its own `proxyConnectFailure` page (5.6–8.1 s) with all surfaces empty through
    the observation window and 12 sink connects per session; the controls fired in the same
    sessions. A Tor positive control with valid state delivered `.onion.` and mixed-case names to
    the SOCKS catcher on 8881 with the matching credential. **Probe falsifiers** on the same
    package: `--mutation delayed-null` (the `.onion.` request's proxy result becomes `null` after
    six seconds) is RED — that request loaded from the destination at 14–17 s while the other
    forms stayed clean (report `4e0143c42f64d22e6383e3a5a14e700d0aafa27d13cfa185509a61111ccbb4e7`);
    `--mutation hung-proxy` (that result never arrives) is RED because the request never reaches
    a terminal state (report `cdf44add50e6da30df2b348d9345c30d0e28b04da0041b4457e41131958cda61`).
    The identical-command red/green records are in
    `specs/001-tor-route/evidence/T186-tests-first.json`.
  - With the cancel listener restored, the unchanged T157 full matrix passed 16/16 on the same
    candidate package (report `c812d0f8436f7dc019fa49a52873f5bc9a66eba70fdcce317741e46c2de201c1`).
- **Private-window access and the fail-closed profile baseline (T188, redteam finding
  20260929-006; maintainer-selected option 6).** Mullvad Browser runs every window in private
  browsing (`browser.privatebrowsing.autostart`). A temporarily loaded extension has no
  private-window access, and Gecko never starts the background page of an extension without it in
  permanent private mode (`ext-backgroundPage.js`), so none of the listeners above run. Any request
  the extension does not route with a Tor descriptor, including its unchanged `{type:'direct'}`
  result, follows the browser's own proxy settings; before T188 a protected `.onion` navigation
  then reached a configured ordinary proxy (Constitution III silent fallback), and only
  `network.dns.blockDotOnion` stopped the bare `.onion` form when no proxy was set.
  - *Baseline.* The dedicated profile's `browser-profile/user.js` sets manual SOCKS5 with
    proxy-side DNS to the T186 Unix sink `file:///dev/null/stargate-blocked`, and
    `no_proxies_on` = `<local>` plus one suffix entry per ICANN top-level domain (1,471 labels in
    ASCII form from the Ubuntu `publicsuffix` package 20231001.0357-0.1,
    `/usr/share/publicsuffix/public_suffix_list.dat` SHA-256
    `02074b85e6f1454055b82aa7812bcea05f6afd9076e9a60ae1eb30ad61a26881`; `onion` excluded as the
    protected special-use name, `arpa` as the special-use reverse-mapping/`home.arpa` zone).
    Everything not bypassed — `.onion` in any case or trailing-dot form and any unknown TLD —
    reaches the sink and fails with no local resolution; ICANN clearnet connects directly, as the
    001 extension's Direct route does. The extension's Tor descriptor overrides the baseline; a
    router misclassification of an onion as Direct falls to the baseline and reaches the sink.
    Updating the list is a reviewed promotion (Principle IV); `router.test.js` reproduces it from
    the recorded PSL file when present. Scoped to 001, where only `.onion` is protected: a
    feature that protects clearnet must revisit the blanket clearnet bypass.
  - *Detection where the extension runs.* At startup (the about:addons toggle reloads the
    extension) it reads `extension.isAllowedIncognitoAccess()`; missing, unreadable or pending
    access blocks every protected decision and raises one notification (transient: Firefox rejects
    `requireInteraction` with "Unexpected property"), and the popup persistently shows only the
    unprotected state. Whenever it runs (reading `proxy.settings` needs no private-browsing
    access; Gecko requires it only to set them) it compares them (type, SOCKS host
    and version, proxy DNS, HTTP/SSL/PAC fields, and a 64-bit FNV-1a fingerprint of the passthrough
    list — drift detection, not forgery resistance: whoever can edit prefs can edit the extension)
    with the shipped values at startup and on every popup query, and warns (notification and a
    popup prefix) when they differ or cannot be read. The warning never changes routing.
  - *Residues.* Skipping the profile step reverts to the browser's configured proxy settings. An
    emptied or garbled `network.proxy.socks` makes non-bypassed names (including `.onion.` and
    mixed case) connect directly; the running extension's comparison reports it, but nothing
    reports it while the extension is not running. A TLD delegated after the recorded list, a
    trailing-dot clearnet name and a non-loopback IP literal fail closed in this profile with or
    without the extension (CIDR entries such as `0.0.0.0/0` did not bypass an IP literal). A
    foreign extension with the `proxy` permission can change these settings (§2.7); the comparison
    warns while Stargate runs. The notification and popup cannot appear in permanent private mode
    without access; there the baseline is the enforcement and the quickstart's positive popup check
    the user-visible signal. Rejected designs, all measured live: a full-sink manual baseline
    breaks the Direct route because `{type:'direct'}` resolves through the browser's proxy
    settings and only `null` is a real direct connection; a PAC baseline cannot express the Unix
    sink (Gecko looks up a proxy host named `file`) and a missing, unreadable or syntactically
    broken PAC falls back to DIRECT for `.onion.` and mixed-case names.
- **T188 live evidence (2026-09-29).** `probe.py --only private-access` on the pinned Mullvad
  Browser 153.3.0esr Alpha (archive `9039e153…83ab`), with the template `browser-profile/user.js`
  (`9433de72…31d8`) applied to disposable geckodriver profiles and the T186 per-request tabs,
  twelve-second observation window and destination / ordinary-proxy / SOCKS / resolver
  surfaces (strace port 53 plus MOZ_LOG). Clearnet names use `.com` mapped to the loopback
  destination catcher; the unknown TLD is `.zzqunknown`.
  - Controls fired in-run: ordinary proxy, destination, resolver (`.invalid`). With the sink moved
    to a live Unix SOCKS listener, `.onion`, `.onion.`, `.OnIoN.` and `.zzqunknown` all arrived there
    by name with no resolver hit, while `.com` and `sub.<label>.CoM` loaded directly (suffix
    entries match subdomains case-insensitively). `network.proxy.type`, `socks`,
    `no_proxies_on` and `socks_remote_dns` are not locked; the 11,315-character list is accepted
    (feasibility timing: five `.com` loads 0.76–1.57 s with the full list against 0.44–2.28 s
    with `<local>,.com`).
  - Permanent private mode, no extension, and the real package installed without private-window
    access (background views 0): all four protected forms ended at `proxyConnectFailure` pages
    with every surface empty (4 sink connects each); `.com` and the mixed-case subdomain loaded
    from the destination.
  - Ordinary windows without access: the notification `Stargate: allow "Run in Private Windows"`
    opened, the popup showed the unprotected state, all protected forms stayed off every surface,
    and `proxy.settings.get` was readable (Gecko's `ext-proxy.js` requires private-browsing access
    only for `set`), so the tamper check runs there too. With access, in permanent private and in
    ordinary windows (observed after an extension reload, as after the about:addons toggle; a
    temporary install in ordinary windows first starts once without the grant and shows the access
    notification): `.onion`, `.onion.` and `.OnIoN.` reached the 8881 catcher with the credential
    and no other surface, `.com` loaded directly through `{type:'direct'}`, no notification. With `no_proxies_on` changed, the baseline notification opened and the popup
    carried the warning prefix. A `delayed-fallback` mutant returning Direct for `.onion.` with
    the cancel layer disabled reached the sink (clean); the same mutant under an ordinary proxy
    reached that proxy (calibration).
  - Recorded: an emptied or garbled `network.proxy.socks` let `.onion.`, `.OnIoN.` and the
    unknown TLD load from the destination (bare `.onion` stopped by blockDotOnion) — the
    disclosed residue above. A non-loopback IP literal failed closed with and without
    `0.0.0.0/0,::/0` appended (one sink connect each).
  - Red (template absent, pre-fix package; report `5e61c0c6…dfac`): every baseline scenario
    failed because protected names reached the ordinary proxy, and detection was absent.
    Committed package `fce2d112ffd960761faa86b5954f2dda4bc4effb4cb34992b155454c0a8e7788`, report
    `0c29c84f6433a430de2ea222291bb205aad5b97e4320ba72abbe61317e8d4193`: 10/10 scenarios; it
    supersedes the pre-rename review-round candidate `38751d1f…16f9` (report `7d79f929…5195`,
    also 10/10), which differed only by a behaviour-neutral loop-variable rename. The
    identical-command red/green records for the committed tree are in
    `specs/001-tor-route/evidence/T188-tests-first.json`.
  - Also found live: Firefox rejects `requireInteraction` in `notifications.create`, so the
    existing WebRTC hardening notification (`background/hardening.js`) is never displayed; its
    routing block is unaffected. Pre-existing (T034b/T055), outside T188: reported for remediation.
- The data plane forwards SOCKS5 with the SOCKS5 username set to the
  first-party domain (architecture spec §14.3). For onion services, the
  "first-party domain" is the onion address itself, giving distinct
  circuits per onion service.
- DNS resolution for `.onion` names is **always** Tor-internal — the
  proxy never resolves them locally (Principle III; SOCKS5h enforced).
- **The safe `torrc` is baked into the Tor image at build time** (FR-011,
  amended by T089 / sol-review B2). Compose starts the `tor` service
  before `stargate-control`, so a control-plane-rendered `torrc` would
  be a boot coupling Principle II forbids: Tor could start with the
  Debian default config (no `IsolateSOCKSAuth`, no `SafeLogging 1`,
  `UseBridges` unset) and route traffic before the CP renders the safe
  config — a privacy failure, not just an availability issue. Baking
  the byte-pinned `torrc` into the image (with explicit
  `DataDirectory /var/lib/tor` because the entrypoint does not load
  Debian's `torrc-defaults`) guarantees the privacy directives are
  present at Tor's first boot regardless of CP availability or Compose
  timing. A cold-volume regression test (T087) asserts Docker
  `State.Health.Status == healthy` and the loaded config without
  harness-seeded config. Dynamic (CP-rendered) `torrc` is future work
  for a dynamic-config feature.
- **Tor entry-guard state is persisted across `export`/`import` and
  wiped on `wipe`.** Tor's guard design relies on a small, slowly-
  rotating guard set so the statistical probability of touching a
  malicious guard amortises over months rather than over every install
  [Tor path specification §5, "Guards", at
  https://spec.torproject.org/path-spec/]. Reinstalling Stargate to
  pick fresh guards therefore **degrades** anonymity — it does not
  improve it — because fast-rotating guards see more independent
  observations of the same user. Users who want fresh guards
  intentionally (e.g., they suspect a guard is compromised) must use
  `scripts/stargate wipe` and then `init`, not a simple rebuild.

### 4.3 Tor clearnet exit (port 8881, non-`.onion` host)

**What this provides**: clearnet HTTP/HTTPS connectivity through Tor's
exit relays. Three Tor hops; the third (exit) terminates the user's
Tor-internal layers and speaks the destination protocol [Tor design paper
§4].

**Anonymity property provided** (subject to Tor's design):

- The destination does not learn the user's IP; it sees the exit relay's
  IP.
- The user's ISP does not learn the destination — only that the user is
  using Tor.

**Anonymity property NOT provided**:

- The exit relay sees the cleartext of any non-TLS traffic. **The exit
  relay sees the SNI of TLS traffic** unless TLS ECH is used and the
  destination supports it (§5.6).
- Global passive adversaries can correlate as in §4.2.
- The destination sees a Tor exit IP and may treat the user differently
  (CAPTCHAs, refusal). Stargate does not mitigate destination-side
  blocking of Tor exits; this is by design.

**Observable metadata that leaks**:

- To the exit relay: destination IP, destination port, SNI, request
  bytes (for plaintext) or TLS handshake parameters (for TLS).
- To downstream networks past the exit: as for any normal Internet
  request originating at the exit's IP.
- The TLS SNI is observable to the exit and onwards unless mitigated by
  ECH; see §5.6.

**Side-channel concerns**:

- Tor exits with poor reputation may be blocked at the destination
  (CAPTCHAs, 403s). Repeated retries against the same destination from
  the same circuit create a behavioural fingerprint.
- Some hostile exits inject content, downgrade TLS where possible, or
  log destinations. End-to-end TLS plus Mullvad Browser's HTTPS-Only
  Mode mitigates injection and downgrade; logging by exits is not
  preventable from the user side.

**Trusted parties**: as §4.2 plus the population of exit relays (in
aggregate; no single exit is trusted, but the network's exit selection
algorithm is).

**Stargate-specific notes**:

- Per-first-party stream isolation (§5.10) prevents one site's requests
  from sharing a circuit with another site's requests, which would
  otherwise let either site correlate the user's activity across the
  shared exit.
- The Tor guard set used for clearnet-exit circuits is the same set
  used for onion circuits; the persistence policy in §4.2's "Stargate-
  specific notes" applies identically here.

### 4.4 I2P (`*.i2p`, port 8882)

**What this provides**: garlic-routed communication inside the I2P
overlay, with unidirectional tunnels in each direction [I2P "Tech Intro";
https://geti2p.net/en/docs/how/tech-intro]. Default routing inside I2P
does not exit to clearnet.

**Anonymity property provided** (subject to I2P's design):

- The destination eepsite does not learn the user's IP.
- The user's ISP does not learn the destination eepsite; it sees the
  user is communicating with I2P peers in general.
- Unlinkability between sender and receiver within the limits documented
  by the I2P project [https://geti2p.net/en/comparison/tor — limitations
  and comparison].

**Anonymity property NOT provided**:

- Clearnet exit: i2pd's outproxy feature is not enabled by Stargate in
  v1. `.i2p` traffic does not leave the I2P network. Clearnet-via-I2P is
  out of scope.
- Resistance to global passive adversaries: I2P's anonymity set is
  smaller than Tor's [I2P comparison documentation], and academic
  analysis has documented practical deanonymization attacks against
  the I2P NetDB. Egger, Schlumberger, Kruegel, and Vigna state, in the
  paper's abstract: "we show that an attacker, with relatively limited
  resources, is able to deanonymize a I2P user that accesses a
  resource of interest with high probability" [Egger, Schlumberger,
  Kruegel, Vigna, "Practical Attacks Against The I2P Network," in
  *Proceedings of RAID 2013*, LNCS 8145, pp. 432–451, Springer 2013.
  DOI: 10.1007/978-3-642-41284-4_22]. The paper is from 2013 and the
  network has been actively maintained since, but the structural
  property it exploits — a small, churn-manipulable set of NetDB
  floodfill peers — is an architectural characteristic of I2P, not a
  fixed software bug; readers should weigh the claim as evidence about
  the design class, not about today's specific i2pd build.
- Protection against Sybil attacks on the NetDB — the smaller network
  size makes this more feasible than against Tor.

**Observable metadata that leaks**:

- To the user's ISP: that the user is participating in I2P (UDP and TCP
  patterns characteristic of i2pd; pluggable transports for I2P are not
  shipped by Stargate v1).
- To the destination eepsite: nothing about the user beyond what the
  browser and the I2P tunnel construction reveal.

**Side-channel concerns**:

- I2P performance varies with the NetDB state and reachable peer count;
  cold-start tunnel build times can be minutes (architecture spec §9.1
  bounded init-time readiness window).
- I2P is more vulnerable to academic anonymity attacks than Tor due to
  smaller anonymity set; this is documented honestly here rather than
  obscured.

**Trusted parties**: the i2pd image maintainer, the I2P NetDB's
distributed peer set (in aggregate).

### 4.5 Nym mixnet (port 8884)

**What this provides**: clearnet egress through a Loopix-based mixnet
[Piotrowska et al., "The Loopix Anonymity System," USENIX Security 2017;
https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska],
packet-shuffled at multiple mix layers with Poisson-distributed delays
and chaff at the network level. Packet format is Sphinx [Danezis &
Goldberg, IEEE S&P 2009].

**Anonymity property provided** (subject to Nym's design):

- Strong unlinkability between sender and receiver under the Loopix
  threat model: timing-correlation resistance via per-packet random
  delays and network-level cover traffic.
- The destination sees the IP of the egress Nym gateway, not the user's.
- The user's ISP sees Nym gateway traffic; it does not see destinations.

**Anonymity property NOT provided**:

- Latency for interactive browsing is materially worse than Tor.
  Mixnets trade latency for unlinkability; this is a design choice, not a
  defect.
- Like Tor, vulnerability to traffic-confirmation by an adversary
  observing many points simultaneously is reduced but not eliminated;
  the Loopix paper bounds adversary success probability under stated
  assumptions [Piotrowska et al., §4].
- Resistance to gateway compromise depends on gateway choice; a single
  hostile gateway is one node in the path (see Loopix paper §4).
- SNI is visible to the egress on TLS traffic, exactly as for Tor exits
  (§4.3); the mixnet does not solve the SNI problem.

**Observable metadata that leaks**:

- To the user's ISP: that the user is using Nym. Distinguishing Nym from
  generic UDP/TCP application traffic is achievable for a moderately
  capable observer; pluggable-transport-style obfuscation for Nym is not
  shipped in v1.
- To the destination: the egress gateway's IP plus normal browser
  metadata.

**Side-channel concerns**:

- Cover traffic is generated **at the network level by Nym mix nodes**,
  not by Stargate or the user's endpoint. Stargate explicitly does not
  generate endpoint-side cover traffic (Constitution Principle I — "the
  data plane MUST NOT generate cover, decoy, or chaff traffic").
- Latency variance is high by design; users should expect this for
  interactive workloads.

**Trusted parties**: the Nym client image maintainer, the user-chosen
gateway, and the Nym mixnet operator set in aggregate (Nym uses a
permissionless mix selection model bound to staking; consult the Nym
documentation for current trust assumptions —
https://nymtech.net/docs/).

**Stargate-specific notes**:

- Stargate v1 does not expose mixnet parameters (latency / loop interval
  / hop count) to the user; defaults from the upstream Nym client apply.
  A future feature spec may surface knobs; this is a `NEEDS CLARIFICATION`
  in the architecture spec (§8) for the mixnet-route feature.

---

## 5. Cross-cutting concerns

Failure modes that span routes or modes. Each subsection states the
mechanism that mitigates it (or the residual risk that remains).

### 5.1 Clock skew

**Concern**: Tor relies on the user's clock being close to UTC to
validate relay descriptor signatures, consensus age, and TLS certificate
validity windows. A clock more than approximately 24 hours skewed causes
Tor circuit-build failures that look like generic connectivity errors
[Tor manual: `--Time` related options; Tor design paper §6].

**Mitigation**: The Stargate host runs with NTP enabled (operator
responsibility, documented in install instructions). The isolated observer's
authenticated bootstrap sample (architecture spec §9.1 step 4) can detect
failure to become READY during init. It does not diagnose clock skew or
continuously monitor it. No silent-clock-drift detection in v1.

**Residual risk**: in long-running VPS deployments without NTP, clock drift
may degrade Tor reliability before it is visible to the user. This is
operational, not a privacy leak; documented so users diagnose it
correctly.

### 5.2 DNS leaks

**Concern**: a routed request that triggers a *local* DNS lookup leaks
the destination hostname to the OS resolver and the local DNS provider,
defeating the route's anonymity.

**Mitigation**: SOCKS5h is mandatory for all routed traffic (Constitution
Principle III; architecture spec §14.3 — extension sets `proxyDNS: true`
in the proxy descriptor it returns from `proxy.onRequest`). The data
plane refuses to resolve hostnames; it forwards the unresolved hostname
through the SOCKS5 protocol to the sidecar.

**How SOCKS5h works**: the `h` variant of SOCKS5 specifies that the
target hostname is sent as a string in the SOCKS request, not pre-
resolved by the client. The sidecar (Tor, i2pd, Nym client) performs
resolution on the user's behalf inside its anonymity network.

**Verified by**: the privacy-critical-paths tests-first discipline
(Principle VII) requires a test that demonstrates SOCKS5h is honoured for
each route before implementation lands. `stargate-redteam` checks header
and DNS handling at every milestone (Principle VIII).

**SC-003 observation boundary (T219):** the release-tag T034a measurement may
run the Local profile on the existing Linux x86_64 VPS with a fresh supported
full Mullvad Browser profile and the reviewed extension. Bounded automation
through the ordinary browser interface may repeatedly load only `.onion` content,
but the receipt must show successful loads throughout at least 10 continuous
minutes. Simultaneous complete guest-host loopback and active-egress pcaps,
zero drops/truncation, and safe pre/post DNS query-and-answer positive controls
on each interface make the zero-match assertion meaningful. Never send a real
`.onion` name to a public resolver for calibration. The canonical filter covers
DNS query and answer names in both complete pcaps; `tcpdump` capture with a
grounded pinned `tshark` offline decoder is allowed. This observation covers
decoded DNS on the measured guest interfaces only. It does not prove absence
at a physical NIC, hypervisor, other namespace or inside encrypted DNS; §5.4's
separate external DoH/DoT hardening proof still applies. Record the exact
browser build/channel: an Alpha result supports only that recorded Alpha
environment, not a stable-browser release.

### 5.3 WebRTC leaks

**Concern**: WebRTC's STUN/ICE machinery enumerates the user's local and
public IP addresses via direct UDP outside the browser's HTTP proxy
configuration. A page that loads a WebRTC peer connection can read the
user's real IP even when all HTTP traffic is proxied.

**Mitigation**: the Stargate browser extension reads
`privacy.network.peerConnectionEnabled` via the stable WebExtensions API
and refuses to route non-Direct traffic while it is not `false`
(architecture spec §14.5 Part 2). WebRTC is the one hardening surface
Firefox's stable WebExtensions API truthfully exposes (sol-review B4);
the other hardening prefs (DoH/DoT/HTTP-3) are not extension-readable and
are enforced as an externally verified profile precondition (§5.4, §5.5).
The setting and its values are documented at
[https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/privacy/network].
The hardening audit attempts a transient notification if WebRTC is enabled or its check is unavailable
(Gecko rejects `requireInteraction`, so it is not modal; T195). The routing block is enforced by the
protected-request gate. T205 requires a separate popup paragraph for the volatile result of the latest
runtime hardening check. The existing route paragraph reports a main-navigation decision; neither
paragraph is a history, proof of connection success or verification of the complete browser profile. Mullvad Browser's own default is WebRTC **enabled**:
without the shipped `browser-profile/user.js` (which sets
`media.peerconnection.enabled=false`) every `.onion` request is blocked, so
the failure is fail-closed, not a leak. The live probe starts hardened
sessions from the shipped template's value, never from a pref it injects
itself. The externally verified profile (release-cadence live-e2e test
`tests/live-e2e/mullvad-browser-hardening/`) additionally confirms
`peerConnectionEnabled = false` in a test profile that models the target
browser's hardened defaults.

**T205 required current-state and legacy-storage boundary.** At each background startup, the extension
must remove only the obsolete `storage.local.hardening` key and perform a fresh WebRTC check. Protected
routing must remain closed while initialization is pending or cleanup fails; only successful cleanup
and a measured disabled WebRTC value may open this runtime gate. Cleanup must preserve unrelated
device credentials, profile isolation identity, route settings and other valid client configuration.
The finite enabled, disabled and unknown results must remain in memory; the extension must create no
replacement failure event, event-hour timestamp, raw API-error record or diagnostic error detail.
A later startup must reconstruct its state rather than treating stored success or failure as authority.
Notifications explain failure and do not determine routing authorization. The displayed result describes
the latest check, not continuous monitoring; T205 does not add a per-request re-audit policy. T190
retains that decision and the associated mid-session drift assessment.

Cleanup concerns the key visible through the extension storage API. It does not establish physical disk
erasure or removal from browser journals, backups, OS logs or external copies. T205's focused evidence
must identify the actual package, source, profile and browser processes, demonstrate successful
API-visible removal, preserve unrelated storage through a real browser process restart, and retain
calibrated routing controls. These properties remain required targets until candidate-bound evidence
records their measured outcomes. Mullvad Browser 153.3.0esr development evidence does not certify a
stable release or resolve T200's broader effective-profile and release-verification obligations.
T197 retains the broader inventory/profile/indicator claim reconciliation. T155 retains integrated
foundation closure, and Constitution VIII's ticket, cumulative milestone and external human release
reviews remain required.

**Residual risk**: if the user grants WebRTC permission to a specific
origin, or runs Firefox with a profile that overrides this preference
out from under the extension, the leak returns. Stargate cannot defend
against deliberate override.

**Reference**: Constitution Principle III bullet 3 (as amended by T091,
pre-release) — "Non-Direct routes require a hardened target-browser
configuration that is verified as a release-cadence precondition, not
enforced via the WebExtension API."

### 5.4 DNS-over-HTTPS / DNS-over-TLS leaks

**Concern**: a browser configured with DoH (e.g., Firefox's default TRR
to Cloudflare) resolves hostnames over HTTPS *before* the proxy is
consulted, leaking the lookup to the DoH provider — including for
destinations that would otherwise be looked up inside Tor.

**Mitigation**: the DoH-off guarantee is an **externally verified
precondition** on the target-browser profile, not an extension-API claim.
Stable Firefox WebExtensions do not expose `network.trr.mode` (sol-review
B4), so the extension does NOT claim to read or set it. The profile is
verified out-of-band — `network.trr.mode = 5` (TRR off) is asserted by
the release-cadence live-e2e test `tests/live-e2e/mullvad-browser-hardening/`
against a test profile that models the target browser's hardened defaults
(architecture spec §14.5 Part 1).
As defense-in-depth, `webRequest` rules block *known* DoH endpoints; this
is a secondary net, not the primary guarantee (a custom DoH endpoint not
in the blocklist is caught by the profile precondition, not by the
blocklist). The hardening gate blocks non-Direct routing until the profile
is verified (FR-004).

**Residual risk**: a custom DoH endpoint configured by another extension
or by the user after the live-e2e verification is NOT caught at PR
cadence — only at the next release-cadence live-e2e run or by a fresh
`peerConnectionEnabled`-style runtime gate (which does not exist for DoH
because the API is unavailable). This residue is accepted and documented
here; it is the cost of Firefox not exposing the pref to extensions.
Promoting it to a gated property requires a browser-in-CI, which is out
of scope for v1.

**Reference**: Constitution Principle III bullet 3 (as amended by T091).

### 5.5 QUIC / HTTP/3 fallback

**Concern**: HTTP/3 runs over UDP and bypasses HTTP CONNECT-style proxy
configurations in some browsers. A browser that quietly upgrades to h3
for a destination would leak the connection outside the proxy.

**Mitigation**: like DoH (§5.4), the HTTP/3-off guarantee is an
**externally verified precondition** on the target-browser profile, not an
extension-API claim. Stable Firefox WebExtensions do not expose
`network.http.http3.enable` (sol-review B4), so the extension does NOT
claim to read or set it. The profile is verified out-of-band —
`network.http.http3.enable = false` is asserted by the release-cadence
live-e2e test `tests/live-e2e/mullvad-browser-hardening/` against a test
profile that models the target browser's hardened defaults (architecture
spec §14.5 Part 1). With HTTP/3 off, all routed traffic uses TCP and is
captured by the SOCKS5/HTTP-CONNECT listeners. (Other HTTP/3-related
Firefox prefs such as `network.http.http3.enable_qlog` are not asserted by
the test; if a future release needs them, it adds a grep then.)

**Residual risk**: future browsers may add new transports (e.g., a
WebTransport-over-QUIC variant) that the externally verified profile does
not yet cover; Stargate's live-e2e hardening test must be updated to cover
them at the next release-cadence run. This is a maintenance burden, not a
one-time mitigation, and — like DoH — a post-verification profile change
is not caught at PR cadence (no browser-in-CI in v1).

**Reference**: Constitution Principle III.

### 5.6 SNI leakage to clearnet exits

**Concern**: TLS Server Name Indication carries the destination hostname
in plaintext in the ClientHello. For Tor clearnet exits and Nym egress,
the egress observer and downstream networks can read the SNI and
correlate it with destination IP.

**Partial mitigation**: TLS Encrypted Client Hello (ECH) — RFC drafts
[https://datatracker.ietf.org/doc/draft-ietf-tls-esni/] — encrypts the
ClientHello inner block. ECH requires the destination server to publish
ECH config in DNS and the client to support it; coverage is
incomplete as of 2026.

**What Stargate does**: nothing direct. ECH is a browser-level feature;
Stargate is byte-forwarding (Principle I — "MUST NOT terminate TLS").
Mullvad Browser's ECH support, where available, propagates through
Stargate unchanged.

**Residual risk**: SNI remains visible to the exit and downstream for
the majority of destinations. This is an accepted limitation, documented
here, of any current TLS-based egress. **No Stargate route eliminates
SNI exposure at clearnet exits.**

### 5.7 Browser fingerprinting

**Concern**: browser fingerprinting (canvas, fonts, screen, WebGL,
navigator, behavioural patterns) can identify a user across sessions
regardless of IP-level anonymisation.

**What Stargate does**: nothing. Fingerprinting is a browser-level
concern; the data plane never reads or modifies headers (Principle I).

**What Stargate recommends**: use Mullvad Browser (the constitution's
first-class browser), which ships with `privacy.resistFingerprinting`
enabled and a documented fingerprint anti-uniqueness strategy
[https://mullvad.net/en/browser]. LibreWolf is tested-secondary and has
weaker but non-trivial fingerprinting protections. Chromium browsers
are explicitly unsupported (constitution Tech Stack section).

**Honest note about anonymity-set size**: Tor Browser users form a
single, well-defined fingerprint pool [Perry, Clark, Murdoch, Koppen,
"The Design and Implementation of the Tor Browser",
https://2019.www.torproject.org/projects/torbrowser/design/]. Mullvad
Browser users form a separate pool with its own characteristics. A user
routing Mullvad Browser through Tor is in the Mullvad Browser
fingerprint pool, not the Tor Browser pool. **This is a different
anonymity set, smaller in some respects than Tor Browser's.** Stargate
makes no claim that Mullvad-Browser-via-Tor is equivalent to Tor Browser
for fingerprinting purposes.

### 5.8 Sidecar compromise

**Concern**: a malicious sidecar image runs adversary code with full
network visibility for its route (§2.6).

**Mitigations**:

- **Pinned digests** (Constitution Principle IV; architecture spec §7):
  each sidecar image is referenced by sha256 digest. Silent image swaps
  fail the digest check.
- **Contract test gate** (Principle IV step 2; architecture spec §3):
  sidecar upgrades pass through a CI suite that exercises the narrow
  interface Stargate depends on before a human can merge the digest bump.
- **Read-only root filesystems** (architecture spec §8): sidecar
  containers run with read-only root; the only writable mount is the
  config volume.
- **Per-sidecar Docker volumes**: cross-sidecar disk visibility is
  prevented by per-volume mounts.
- **Required network/capability boundary (T156):** enforce DP→route adapter and
  CP→sanitized observation/lifecycle only. No CP SOCKS egress, full Tor control credentials,
  arbitrary public TCP/UDP/DNS, or unrestricted container-engine access. Sidecar-native
  network maintenance is a distinct route TCB, not an exception for application planes.

**Current implementation gaps:** T162 withdraws T125's no-masquerade and wildcard
posture, and removes CP's full Tor cookie and raw-control path. T163's first
deployment attempts measured a CP startup mount failure, not packet isolation;
T167 repaired the mount and confirmed application-start reachability. T163's
nested-host packet probes passed, but its original rule-absence probe measured
continued SOCKS5 admission. T168 implements mandatory process confinement;
its measured scope and T163's complete VM packet result are recorded in §3.1.
The maintainer-approved VM evidence closes the measured Local embedded-resolver
channel; it makes no physical-NIC or untested-environment claim. T164 adds a
sanitized CP protocol with a signed challenge and finite tokens, but its
observer retained the unrestricted Tor cookie and control socket. A read-only
Unix-socket mount and the shared Tor UID did not constrain that authority to
health operations. T203 removes those observer grants. Mount, PID and network
namespace separation, dropped capabilities, a read-only root and a read-only
finite-health volume enforce the observer boundary outside its application code.
Tor's fixed publisher has no observer/CP input channel, and cannot read their
health fabric or key volumes. The observer cannot write the publication volume.
The publisher's full Tor authority remains a Tor-TCB risk under §2.6.
T165's measured caller matrix and CP packet results are historical. T203 must
record replacement evidence for its exact tested candidate and environment,
including unexecuted checks. T155 still owns feature-wide compliance. A bridge-visible packet alone does not prove
internet exfiltration.

**Residual risks after a compliant repair:** Tor remains trusted for the anonymity protocol,
and a malicious sidecar can misuse its own network channel. Host/kernel compromise can escape
application isolation and is out of scope. Do not broaden this residue to excuse a CP capability
that the deployment is required to deny. Existing accepted decisions remain historical records;
none can waive a constitutional invariant.

### 5.9 Update channel compromise

**Concern**: an attacker who compromises the update channel can deliver
a malicious version of Stargate or a sidecar to all users.

**Mitigations** (Constitution Principle IV):

- All updates land via PR through an automated tracker (Renovate),
  reviewed by a human, gated by contract tests.
- End users apply updates only by explicit action in the admin
  dashboard; no background auto-update.
- Releases are reproducibly built (Principle VI); auditors can verify
  the published artefacts match the source.
- The Tor sidecar's Debian build inputs are pinned to an immutable
  `snapshot.debian.org` run with explicit `=version` pins (T099); the
  snapshot InRelease hash and committed per-arch package closure (T184) make
  any drift between builds — including a replayed older signed index from a
  compromised mirror or on-path attacker — fail the build;
  the trust + rotation procedure is in `SECURITY-DECISIONS.md`.
- CI Action code is selected by full commit identity. The agent workflow
  verifies exact-version CLI archives against recorded publisher digests
  before unpacking them; the contract gate rejects mutable Action references,
  curl pipelines to sh/bash (including line continuations), and unversioned
  npm/pip/go/apt install lines. A reviewer promotes pin changes under
  `CONTRIBUTING.md` §"Updating executable CI inputs".
- The control-plane Maven build (Docker image and `scripts/verify.sh`)
  verifies every resolved artifact — dependencies, plugins, annotation
  processors, build extensions and POMs — against the committed SHA-256 lock
  `control-plane/.mvn/checksums/checksums.sha256` before use, with strict
  transport checksums; a tampered or unlisted artifact fails the build (T185).
  The amd64 closure is build-confirmed. The arm64-only entries were derived by
  aarch64 profile-activation emulation on an amd64 host and are not
  build-confirmed (no arm64 builder); a wrong arm64 entry fails that build
  closed. Refreshing the lock is a deliberate reviewed change (procedure in
  `control-plane/Dockerfile`). Exclusions: remote SNAPSHOT artifacts are not
  checked (only the release-only Maven Central repository is configured);
  repository metadata is not locked, though any version it selects must still
  be in the lock; the lock identifies content but does not authenticate the
  publisher (no PGP check) — recorded bytes are trusted as first fetched from
  Central over HTTPS with matching Central checksums.
- Release artefacts are signed (architecture spec §12.5 — signing tool
  NEEDS CLARIFICATION).

**Residual risk**: compromise of the maintainer's signing key, an upstream
publisher, or the CI runner remains possible. Pinning preserves the reviewed
bytes but does not confine an agent that executes in the runner (T142). External
human security review before tagging `v1.0.0` (Constitution Principle
VIII) is the human-layer mitigation; downstream verification of
reproducible builds is the technical mitigation.

### 5.10 Per-first-party stream isolation

**Required property:** distinct authenticated-device/browser-profile/initiating-site partitions
must not share a Tor circuit. The constitution and feature boundary contract define the scope;
T136 pins suffix/context derivation and the bounded wire representation; T147 handles CONNECT.
No general correlation resistance follows from partitioning, and same-partition sharing is
permitted rather than guaranteed. Missing initiating context must block a protected request.

**Browser SOCKS mechanism:** on Firefox 153 or newer, the extension uses the browser's native
ICANN-and-PRIVATE `publicSuffix.getDomain()` authority to canonicalize DNS sites; unknown and plain
suffixes are unavailable and no list is fetched by the extension at runtime. The manifest rejects
older Gecko versions. Main navigations establish the site directly; frame-zero metadata binds it
to `documentId`, and nested frames or tab-associated workers may inherit only through committed
`documentId`/`parentDocumentId` ancestry. A new top-level commit retires older tab bindings and an
in-flight derivation rechecks its exact binding before returning. Detached workers,
opaque top-level parents and absent state yield no isolation identity; the destination never fills
that gap. A per-profile random id, normal/private and contextual-identity mode, and the site are
encoded under the device bearer with full HMAC-SHA-256 as a fixed 68-byte `sg1:` username. The
bearer remains the DP-facing password and the DP sends Tor an empty password. The pseudonymous
username is stable within the tuple but is not a general unlinkability claim.

**Current evidence and gaps:** T136's Node tests cover native-suffix adapter and browser-event
decisions but do not prove Mullvad Browser's metadata or timing. Mullvad Browser Alpha 16.0a11 /
Gecko 153.2.0 grounds API availability; a stable Gecko-153-or-newer Mullvad release is a v1 release
gate, not an inferred promise. Existing DP tests prove that an opaque username is
forwarded intact and that the bearer/password is not sent upstream. T126/T155 still supply real
same-target/distinct-partition circuit evidence with credential-fusion controls; synthetic
username assertions alone cannot establish the whole browser-to-Tor path.

**HTTP CONNECT refusal (T173):** the production demux closes unsupported `C` input
before authentication, counters or an upstream socket. The obsolete HTTP parser and
`Tor.Dial`/NO_AUTH entry point are removed. The unchanged real-socket regression first
failed through actual upstream admission and request increments, then passed with
same-destination site/profile/device SOCKS controls, intact usernames and empty upstream
passwords. Migrated coverage retains byte integrity, long-lived pipes, CP-outage/advisory
independence, counters, log/leak invariants and upstream-close behavior.

**Forwarding accounting repair (T149):** terminal shutdown now interrupts pending client
I/O and closes the upstream before waiting for both forwarding pumps. Only then is the
complete upstream-read/write total added once to the hourly aggregate. Deterministic
paused-I/O regressions cover the concurrent-close loss, and blocked-read/write probes cover
shutdown in both directions. This preserves the existing upstream-boundary byte definition,
opaque payload handling and listener ownership of client Close; it adds no idle deadline or
request log. This is an implementation repair within the existing transport boundary, not a
new trust boundary. T158 separately repairs current-hour exposure with immutable completed-hour publication. See the
[T149 evidence](specs/001-tor-route/analysis/T149-accounting-evidence.md) for the local evidence layer.

**Upstream deadline (T208):** the data plane waits up to 250 s, previously 30 s, for
the Tor sidecar to answer a connect request, so that it ends fewer connects Tor would
complete. It does not watch the client during that wait. If the user abandons the
request, it stays pending at Tor until Tor answers or the deadline expires, and Tor may
still open the connection to the destination after the user has left. The data plane
sends nothing of its own on that connection. Bytes the client had already sent after
its request can be forwarded when Tor answers; the data plane then closes the
connection. The data plane does not cap pending requests, so a page that starts many
can hold many. This behaviour existed before; T208 lengthens it and adds no new trust
boundary.

The [T173 evidence record](specs/001-tor-route/analysis/T173-connect-refusal-evidence.md)
identifies the tested candidate and distinguishes socket tests from Local deployment proof.
T172 remains the reviewed contract decision; neither it nor a passing unit suite proves
real Tor circuit separation. Clients without trustworthy first-party context remain
unsupported; destination-derived identity and switching to Direct are not migrations.
Stop old admission and restart DP, closing old-process tunnels; no mixed-version safety
claim is made. Bearer credentials, valid auth snapshots, fixed route binding and Tor
configuration need no schema change and remain usable for SOCKS under normal generation
rules. LAN/VPS and post-repair browser/circuit evidence remain T126/T155 obligations.

The future HTTP renderer supports direct calls for AUTH_REQUIRED, ROUTE_DOWN,
ROUTE_REFUSED and ROUTE_TIMEOUT with fixed status/reason, headers, template body and a
fresh 64-bit random reference ID. Direct tests pin all four formats, scan the full response
against the checked-in leak corpus (allowing its `Tor` token only at the validated route-label
position), and sample 1,000 IDs per code with coarse per-position digit bounds. That finite
sample can detect gross bias but cannot establish independence or unlinkability; the renderer
has no request inputs and uses `crypto/rand`. The egress-IP and Tor control-event corpus inputs
require live-stack evidence and are outside these direct calls. No HTML error response is
reachable from Tor port 8881.

T157 now supplies identity-unavailable browser cancellation and Alpha-candidate no-fallback
captures rather than inferring safety from a non-SOCKS descriptor; T186 makes the blocked proxy
result itself fail closed, independent of that cancellation. Stable-target integrated
packet/circuit evidence remains T155.

**Residual limitations:** parties within one defined partition may share circuits. Browser
context fidelity and installed-profile hardening require the stated tests/preconditions. A copied
profile can copy its local profile id, and devices configured with the same bearer represent the
same authenticated-device identity. A browser update can update its suffix authority and thereby
start a new isolation identity for an affected site; that is safer than retaining a stale
delegation, but equality is only promised within one browser suffix-data version. Unknown context
may not silently degrade to destination-only identity or Direct.

### 5.11 Tor bridges and pluggable transports

**Concern**: in censored networks, Tor's distinctive traffic shape can
be detected and blocked. Bridges with pluggable transports (obfs4,
snowflake, webtunnel) obfuscate Tor traffic to look like other protocols.

**What Stargate does**: bridge support is an opt-in feature with bridges
disabled by default (Constitution v1 Scope; architecture spec §6 SQLite
schema includes `tor_bridges` table). Bridge selection and management
live in the admin UI.

**Threat-model statement**: Stargate is **not** marketed or designed as
a censorship-circumvention tool by default (Constitution Non-Goals).
Users in censored networks who enable bridges must understand that
bridge availability is itself an arms race; Stargate forwards what the
Tor sidecar can do, no more.

**Residual risks** specific to bridge users:

- Bridge IPs leak through legitimate distribution channels; the same IP
  used by many users becomes detectable.
- Pluggable-transport fingerprinting is an active research area; today's
  obfs4 may be tomorrow's detected protocol [Tor Project bridge
  documentation: https://bridges.torproject.org/].

### 5.12 Endpoint cover traffic — deliberately absent

**Concern (raised in privacy literature)**: an endpoint that generates
its own cover traffic might frustrate timing-correlation by an observer
of its egress.

**What Stargate does**: nothing. Constitution Principle I forbids the
data plane from generating cover, decoy, or chaff traffic.

**Why**: as the Constitution states, "endpoint-generated cover traffic
provides negligible protection against realistic adversaries while
creating identifiable patterns and a false sense of security." Effective
cover-traffic schemes are network-level properties of mixnets (Nym), not
endpoint hacks. The mitigation against timing-correlation is the
mixnet's own cover, not Stargate's. We state this here to pre-empt
"Stargate should add cover traffic" feature requests.

### Traffic counter publication — T158

The DP keeps the active hour's traffic totals private in process memory. Authenticated
GetStatus exports only completed UTC-hour rows; repeated polls cannot observe within-hour
request/byte increments. One serialized, nondecreasing effective hour prevents wall-clock
rollback or delayed completion from reopening published rows. Bytes are attributed after both
forwarding pumps finish, to the effective completion hour, preserving T149 accounting until
retention expires. No new labels, current totals, metadata fields or traffic logs are added.

Rows expire seven days from bucket start. Reads/writes apply the cutoff; a process-owned worker
also removes expired rows at hour boundaries while idle. Scheduler delay or suspension can delay
physical memory cleanup, but resumed RPC handling cannot return expired rows. A trusted host
clock remains a precondition: forward jumps may finalize/expire early and backward jumps delay
publication; this is no defense against a host controlling time or reading DP memory. Restart
loses active and finalized rows. Disabling traffic counters prevents collection/export for the
boot. Completed hourly totals still disclose aggregate route activity, especially on quiet hosts.

T158's evidence uses authenticated local RPCs, real forwarding sockets, Java/Go decoding and
synthetic traffic clocks; it does not establish a seven-day soak or live anonymity guarantees.
The Java production status poller/SQLite traffic writer remain deferred. Operational logs and
sidecar diagnostics are separate T152 obligations; this change does not claim their remediation.
See [T158 evidence](reviews/T158/README.md) and the
[status transition](specs/001-tor-route/contracts/control-grpc.md#t158-pre-release-status-transition-2026-09-22).

### 5.13 Inter-plane channel authentication and certificate validity

**Concern**: a process that successfully `connect(2)`s to one of the
inter-plane UDS sockets (`/run/stargate/control.sock` or
`/run/stargate/dp.sock`) but is NOT the legitimate peer plane could inject
`ReloadTokens` generations, consume `WatchEvents` streams, or query
`GetStatus` counters if the mode/group dial gate were the only protection.

**Mitigations** (Constitution Principle II; arch §5.4;
`specs/001-tor-route/contracts/wire-auth.md`):

- **Mutual Ed25519 TLS-over-UDS** with self-signed certs derived in-memory
  at plane startup from the on-disk `*.priv` keypairs. Private keys are
  `0600`, owner-read-only; public keys are `0644`, shared via the
  `stargate-ipc` GID.
- **Peer public-key pinning** (not CA-chain, not hostname): the verifier
  byte-equal-compares the peer cert's extracted public key against the
  installed `/etc/stargate/keys/<peer>.pub`. A wrong-key peer is rejected
  at the TLS handshake (`alert: unknown ca`) before any RPC dispatches.
- **Schema-version interceptor**: every RPC carries `x-stargate-proto-major`
  / `-minor` / `-capabilities` gRPC metadata; a server interceptor rejects
  an unknown major with `FailedPrecondition` before invoking application
  behaviour (arch §5.5 row 4).
- **T153 startup rejection:** an authenticated peer's `FailedPrecondition` on
  the startup token push aborts CP bootstrap with `INCOMPATIBLE_PEER_VERSION`
  and tears down its partial services. No peer description, trailers or cause
  are retained in that error; production diagnostic output stays suppressed.
  Temporary transport outages remain contained and DP forwarding is independent.
  `PeerVersionStartupTest` exercises both mismatch directions, compatible dispatch,
  transient failure, redaction and listener cleanup over real mTLS/UDS with a
  Java peer fixture. Missing/invalid token input makes no push and therefore
  discovers no mismatch; retry/reconciliation remains T132's separate work.
- **Mode/group dial gate** (`0660` + `stargate-ipc` GID) is the outer
  defence that keeps the dial surface small in the local profile; the
  mutual-pin is the load-bearing auth gate.

**Current gaps and residual risk (T095 history; T156 requirements)**:

- **T148 implemented policy:** both peers require `NotBefore <= now <= NotAfter` on new
  handshakes; the five-minute issuance backdate is the sole clock allowance. Go retains T135's
  current-pin check on full/resumed handshakes and checks the restored certificate dates.
  Java creates a fresh JDK TLS session context per engine: cached authorization is never reused,
  including when a client offers a ticket. Both peers issue in-memory certificates valid for 30 days and renew them
  when selected with at most 24 hours remaining (or after an idle outage), using the same loaded
  key without CP coordination, disk persistence, network egress or a restart.
- **Established IPC authority is bounded, not instantaneous:** both endpoint roles close local
  transports within 60 seconds of authentication, including active streams and idle channels.
  Pin replacement/removal and certificate expiry can therefore leave at most 60 seconds of
  previously authenticated channel authority. This timing assumes a running process/scheduler
  and trustworthy host clock; suspension and host compromise are outside it. Normal IPC
  reconnection uses fresh authorization. It neither expires retained bearer-token state nor
  closes proxy byte pipes; T132's durable re-push semantics remain separate.
- **Evidence:** `tls_lifecycle_test.go` covers invalid dates, actual Go resumption with an advanced
  verifier clock, renewal before expiry/after CP outage, independently timed closure in both roles,
  and old/new authenticated byte pipes through the production listener/forwarder and a local echo
  sidecar. `CpTlsTest`, `InterPlaneWireTest` and `CrossPlaneTlsTest` cover Java renewal, active/idle
  channel loss and recovery, plus real Go/Java UDS date checks, ticket offers, pin replacement and
  repeated gRPC reconnects. Synthetic-clock and local-fixture evidence does not establish live Tor
  anonymity, host-clock integrity, month-long soak behavior or future LAN/VPS transport guarantees.
- **No automated key rotation in v1.** Replacing the on-disk
  `cp.priv`/`cp.pub` / `dp.priv`/`dp.pub` keypairs is operator-manual
  (write-tmp + rename + plane restart, ordered per `wire-auth.md` §6.2).
  A CP rotation also refreshes the Tor observer's own `cp.pub` copy, which
  `stargate init` re-syncs on every run (T191); until then the observer
  refuses the rotated CP and CP health stays unavailable (advisory only).
  Automated rotation is a future feature with its own threat-model row.
- **A same-host attacker who reads a plane's process memory obtains the
  long-lived private key** (loaded from `*.priv` for handshake signing)
  **and can impersonate the plane indefinitely until the operator manually
  rotates the on-disk keypair.** The 30-day cert-validity window does NOT
  bound this exposure: the attacker possesses the key, not just a derived
  cert, and can mint fresh, currently-valid certs at will. A monthly
  plane restart does NOT help — the same key is re-loaded on restart.
  This is strictly worse than the transient-cert property and is the
  binding residue; the operator's only incident-response lever is keypair
  rotation. In the local profile this is no worse than the §3.1 assumption
  (same-host code execution is game-over); under a future LAN/VPS profile
  that introduces TCP transport for the inter-plane channel, this residue
  MUST be re-reviewed.

### 5.14 Bearer-token verifier key material — install-time pepper (T092)

The bearer-token verifier is `HMAC-SHA-256(pepper, token)` over a 32-byte
install-time pepper shared by the control plane and data plane
(`specs/001-tor-route/data-model.md` §1.5; SECURITY-DECISIONS.md
§"Bearer-token verifier: HMAC-SHA-256 + install-time pepper (T092)"). The
pepper is a new long-lived secret introduced by T092; its residue is
recorded here so it is not silently widened later.

T143 retires the unused Java Argon2id parameter class and its obsolete
assertions left from T011 after T092 superseded the verifier contract.
The active HMAC minter and pepper contract are unchanged. The scoped Java
`RetiredTokenVerifierTest` guards the retired class's absence; it does not
establish historical tests-first compliance or strengthen the protections below.

**Protects.** Per-request authentication with O(1) memory regardless of
token-list size or concurrent flood size — retiring the Argon2id
allocation-DoS path (sol-review B5). A `dp-snapshot.json` leak alone does
NOT let an attacker verify guesses: the snapshot carries verifiers only,
never the pepper, and the pepper never crosses the inter-plane RPC or any
log.

**Does NOT protect against (residue).**

- **Pepper compromise + snapshot leak → offline candidate testing at HMAC
  speed.** An attacker who obtains BOTH `/etc/stargate/keys/pepper.key` AND a
  `dp-snapshot.json` can test candidate tokens offline as fast as they can
  compute HMAC-SHA-256. Mitigation: the bearer token is a uniformly random
  128-bit value, so batch brute-force of the 2^128 space is infeasible even
  at billions of HMAC/sec — the slow-KDF defence Argon2id provided was
  unnecessary for a random token (which is why it was retired). The
  threat-model entry names the residue honestly rather than relying on
  verifier speed for security.
- **Pepper is long-lived.** Like the inter-plane ed25519 keypairs (§5.13),
  the pepper is generated once at `init` and rotated only on explicit
  operator action (re-pepper → re-HMAC every configured token → bump
  generation). A same-host attacker who reads process memory obtains the
  pepper; in the local profile this is no worse than the §3.1 / §2.8
  assumption (same-host code execution is game-over).
- **Pepper loss ≠ safety.** If the operator loses the pepper (no backup of
  `stargate-keys`), every persisted verifier becomes uncomputable and all
  stored tokens effectively revoke — the operator must re-issue tokens.
  Documented in `quickstart.md`; the pepper MUST be in any operator backup.
- **Constant-time comparison** over the verifier set is functionally tested
  (T093); adversarial confirmation of the timing side-channel bound is a
  `stargate-redteam` residue (functional tests do not fully capture timing).

**Ownership / export / wipe.** `/etc/stargate/keys/pepper.key`, mode `0640`,
owned by the reading plane's UID, group `stargate-ipc` (GID 5100) so both
planes read it. `scripts/stargate export` includes it (warns the bundle
carries a secret); `wipe` removes it alongside keys and state. T088 wires
provisioning, export, wipe, and rotation.

---

### 5.15 Auth state during outages and recovery (T156)

**Required behavior and limit:** a DP with valid last acknowledged auth state continues
admitting authenticated requests when CP is unavailable; its state has no expiry solely due
to that outage. A revocation requested while delivery is unavailable remains **pending**, not
effective. An operator must not be told it succeeded before DP acknowledges application.
A client revoked only in the unreachable CP can therefore continue authenticating against
retained DP state until the update arrives. The operator may stop the route to stop access.
After acknowledged revocation, new admissions using that credential are denied; existing
byte pipes may finish. Revocation does not claim to terminate established application sessions.

**Operator-visible delivery state (T187).** The running CP reports one current state for its
credential candidate: `PENDING` until an exact durable acknowledgment, `ACKNOWLEDGED(<generation>)`
after it, or `STALE_CONFLICT` when the DP refuses it as stale. `scripts/stargate status` reads it
through `docker compose exec` from a CP-private tmpfs file (`/tmp/stargate-control/auth-delivery`,
outside the DP-shared IPC volume) and prints only validated vocabulary with distinct exit codes.
`PENDING` is published before the initial RPC; a failed replacement write withdraws the previous
value and is retried, so an obsolete state never reads as current; an absent or unreadable file is
reported as `UNKNOWN` or unavailable, never as a lifecycle claim.
It carries no history, timestamp, label or count and is removed at CP start (Constitution III
current-lifecycle-enum allowance); Docker-daemon access is the operator authentication, and anyone
with it already controls the stack. `enrolled`/`revoked` operational counts are written only on
the exact acknowledgment, never at candidate commit or on a stale refusal, so no persisted trace
claims a pending or refused revocation succeeded. Residue: the status describes this CP process
only. With the CP stopped, `status` reports the CP unavailable rather than the DP's generation, and
a revocation still pending when the CP stops is never counted after restart (the replay has no
diff). The status is advisory: a local process able to write the CP container's private `/tmp` could forge
it, but such a process already has CP authority. `STALE_CONFLICT` is terminal for the CP process;
recovery is the explicit operator procedure below (quickstart §"Stale-conflict recovery"), never
automatic renumbering.

Valid durable snapshots support CP-down restart. Missing/corrupt/incompatible snapshots deny
new admission. Supported crash/restart must not undo an acknowledged revocation, and ordinary
reconnect must not relabel credentials restored from a stale CP backup as fresh authority.
T159 implements this with the versioned `auth-set-v1` verifier commitment and schema-v3 DP
snapshot: file fsync, rename and directory fsync precede the in-memory swap and the exact durable
acknowledgment. Same-generation exact replay rewrites that active snapshot before acknowledgment,
repairing any newer candidate left visible by an ambiguous post-rename failure. Conflicts never
drive CP renumbering. The CP reserves a changed generation before mutating candidate rows; a crash
may consume a number but cannot pair new credential contents with the old number. A coalescing
local-IPC worker redelivers the latest exact pending candidate with capped exponential backoff, so
a DP that returns while the CP remains running reconciles without a CP restart. After exact
acknowledgment, the running CP retains that latest non-stale authority in memory and queues it once
when the authenticated channel becomes READY after a peer-side disconnect. The client's scheduled
55-second credential-lifetime retirement establishes a fresh READY baseline and sends no
`ReloadTokens`, so it causes no periodic DP snapshot rewrite. Thus a DP-only restart that has lost
or rejected its snapshot is reseeded without periodic application RPCs, proxy probes or public-
network traffic.
The pre-release mixed-peer transition is stop-the-world. A new CP exposes only an empty legacy
list to an old DP and cannot recognize its response as durable; a new DP rejects an old CP's
missing durable envelope before mutation. Legacy schema-v2 snapshots deny until matching new
peers reseed, because the old implementation could acknowledge state that was never persisted.

Explicit rollback is offline: stop both planes (terminating byte pipes), preserve the newer
matched state, restore the selected CP database/configuration plus matching pepper/IPC keys, move
the active DP snapshot aside without editing it, then let matching peers reseed through the normal
durable RPC. Admission stays denied until the exact acknowledgment is observed and credential
outcomes are verified. This operator-confirmed procedure can deliberately reauthorize credentials
from the selected backup. A lost response or post-rename storage error can leave application
pending even if candidate bytes reached disk; exact replay rewrites current authority and resolves
that ambiguity. SIGKILL and
local-filesystem probes do not prove every power-loss/filesystem implementation. Host/root or
storage rollback of all trusted authority state remains outside the guarantee.

Verification crosses the production persistence and wire boundaries: production SQLite/JTA child
processes are forcibly killed after generation reservation and after candidate commit for both
revocation and first enrollment from generation zero. Fresh recovery processes reopen each
original database in place, consume reservation gaps safely and replay committed candidates at
their exact generation. A restored stale production CP database/configuration connects over
mTLS/UDS to the production Go server and the real Go verifier still rejects the revoked
credential. Both mixed-peer directions cross serialized RPC boundaries. A shortened-lifetime
production client crosses repeated local channel retirements without a reload, then performs one
exact replay after a real peer restart, including retirement while that outage remains pending.

### 5.16 Verification coverage and review evidence (T139)

Repository changes can otherwise hide regressions by clearing a gate's executable bit,
omitting a mandatory Go module from go.work, or adding source outside the reviewed diff.
Required runners use explicit interpreters; the Go gate cross-checks present mandatory module
substrates while continuing to discover additional workspace modules. Nonzero Go test runs
remain failures and retain test names/assertion output in development verification logs.
These are build/test diagnostics, not permission for deployed per-request logging under III.

The ticket driver refuses non-ignored untracked source before review/commit, counts all changed
paths against budget, and binds approvals to working and staged content. Later source changes
require fresh review. Verdicts identify their reviewed snapshot and round; a delayed approval
for an older handoff cannot authorize a newer candidate. Ignored build products are excluded; intended ignored source must be
explicitly staged. This guards accidental coverage/evidence omissions, not a malicious actor
who can replace the gate, Git configuration or verdict files themselves. Genuine absent
substrate and explicit cadence/tool opt-outs remain reported SKIPs. A local green result does
not establish omitted live/release properties or replace VIII's external human release review.

### 5.17 Native reviewer context separation (T142)

Ticket reviews run as ONE single gate: one fresh OpenCode GLM-5.3-Flash session
at xhigh (provider max) and one fresh Codex Astra session at high, both
covering correctness and adversarial security/privacy in the same pass —
there is no second phase. Separate candidate copies and verdict paths prevent
accidental interference; no implementation chat or peer verdict is supplied.
Source checks and complete, identity-bound verdict imports protect against
stale approvals.

These native same-user processes are not an OS containment boundary. They use
existing host provider authentication. OpenCode uses reviewer deny maps;
Codex runs without an OS sandbox under read-only inspection instructions.
Neither establishes host credential, process or network isolation.
Ordinary OpenCode --auto execution can approve ask rules and is not
constrained by reviewer-role denies. A malicious process with host access or a
write-and-restore attack is outside the snapshot checks' guarantee. No Docker
or replacement containment infrastructure is required for review.

### 5.18 Operational records, diagnostics and legacy cleanup (T152)

**Boundary and information retained.** The CP retains completed UTC-hour category counts,
never an administrative event journal. A database reader can see hourly enrollment/revocation,
configuration-error and sidecar-health counts for up to seven days, but no actor, label,
per-event time, generation or detail. The five-category schema and exact retention/clock rules
are in feature 001 data-model §4. Counts describe CP observations, may lose unpersisted data on
crash, and provide neither browsing anonymity evidence nor an uninterrupted audit trail.

The newest completed hour includes an `enrolled=0` row when appropriate; this is a real zero
aggregate and preserves the restart clock boundary after older counts expire. Clock regression
drops observations until the clock catches up, never reopens a published hour or updates a
previous count. Disabling retention deletes operational state and ends that collection lifetime;
re-enabling starts another. Host/root rollback of all state or operator-supplied false time is
not a tamper-resistant chronology claim. During CP outage no operational aggregation runs;
this cannot gate DP authentication/admission or established pipes (Principle II).

**Implemented boundaries in the T152 candidate.** V002 drops detailed `audit_log` and its
append-only triggers, keeps current manual `(label, verifier)` credentials and auth generation,
and removes revoked credential history and unnecessary lifecycle timestamps. Flyway keeps
schema identity/checksums while installation actor/time/duration become fixed placeholders;
the migration test confirms normal checksum validation still works. The operational
sink holds only category counts, joins JTA at successful completion, publishes immutable closed
hours, retries bounded pending counters, and expires old rows on its one-second worker and at
startup. SQLite must be usable at startup: a failure while loading the persisted
clock boundary can abort CP initialization; the loader's later failure containment does not
promise CP boot availability. The DP continues independently. No production operational export endpoint exists yet; any future reader must enforce
expiry before export. A stopped/unwritable database cannot run cleanup; normal retention is
not a claim of erasure during an outage.

**T178 first-token contention repair.** The loader's credential transaction takes SQLite's
writer reservation before reading or changing `configured_tokens`. The aggregate worker uses
its separate transaction and waits for that reservation; it cannot force a deferred
read-to-write upgrade failure during initial enrollment. Generation reservation still commits
before the credential set, and `ReloadTokens` still follows its commit. An unavailable SQLite
store can still prevent CP enrollment; the DP denies admission without valid authority and
continues using its last valid state during CP failure (Principle II). The aggregate sink
still retains only completed-hour categories under the policy above (Principle III).

| Writer / capture | Enforcement and preserved behavior |
|---|---|
| Java token loader, sidecar monitor, persistence and reload/runtime adapters | No application journal; only fixed categories enter the hourly sink. Current auth/generation behavior remains. |
| Java protocol-version diagnostic / Quarkus/JVM/native output | Production journal sink removed; framework logs disabled; entrypoint redirects both descriptors before JVM startup, clears JVM-option injection variables and disables error/core/heap dump output. Static authenticated IPC failures remain responses. |
| Go proxy/controlclient/snapshot and observer | Event log calls removed; process stdout/stderr descriptors point to `/dev/null` before config/keys/network startup. Snapshot/current-auth and advisory event behavior remain. |
| Tor and shell entrypoint | Tor logs target `/dev/null`; both shell descriptors are discarded before startup/private-state reads. Native protocol state remains separately trusted under §5.8. |
| Docker capture | All four services set logging `none`, core limit zero and healthcheck disabled. Authenticated observer health replaces Docker's timestamped health-probe history. Installer readiness uses the observer's fixed one-shot `--check-ready` mode and requires READY, not merely running containers. |

**Verification layers.** Real SQLite/JTA regressions cover aggregation, commit/rollback,
retention, migration and clock/restart behavior. Go unit and process/socket contracts check
silence while preserving auth, snapshots and rejected-stream closure; former log-based waits
use those behaviors. Launcher probes use controlled writers and a positive capture control;
Docker probes independently verify the capture configuration and empty archives. These are
implementation-boundary tests, not live Tor anonymity, host forensic erasure or LAN/VPS evidence.
Executed commands/results and remaining release-cadence checks belong to reviews/T152/README.md.

The installer invokes the observer inside its existing container/authority with
`--check-ready`. It obtains only exit 0 (READY), 1 (NOT_READY), or 2 (UNAVAILABLE/invalid mode),
never cookie bytes or Tor text. T203 makes each decision a fresh bounded read of the
latest finite publication, with a four-second whole-process bound; the installer retries within one post-Compose readiness window, default
300 seconds with an operator override (T124). This increases cold-start tolerance but
does not guarantee bootstrap on the public Tor network. A sample already in progress
can finish up to four seconds after the window, plus the existing two-second retry interval.
A running DP listener is checked separately and cannot substitute for Tor bootstrap readiness.
T203 preserves the authenticated CP protocol and changes the observer's authority/mounts
as described in §3.1. The Tor-internal publisher starts at most one query at a time,
with a four-second query budget followed by a one-second pause. It timestamps the
attempt start with Linux CLOCK_BOOTTIME. Every consumer decision verifies the
same time-namespace clock domain and accepts only an original age from zero to
strictly less than four seconds; wall-clock and mtime changes or consumer restart
cannot renew READY. Clock/backing uncertainty, malformed or nonregular records,
future/stale samples and late query completion become UNAVAILABLE. The handoff
is a bounded tmpfs with one latest record and at most one replacement file; its
private freshness metadata never enters CP replies or operational records.
The launcher invalidates before Tor startup and stops/reaps the publisher before
final invalidation. Publisher failure cannot stall the SOCKS-link supervision loop
or gate forwarding. Hard death can leave the last sample usable for its original
remaining lease; immediate death detection is not promised. Scheduling delays or
suspend can extend unavailability, never that lease.

This repair is intended to remove an unintended observer capability and adds a named
internal component to Tor's executable TCB. Its code and candidate evidence require the
ordinary independent review gate. The final change also requires the impact assessment
specified by Constitution VIII; this classification does not waive external human review
for a release that adds or materially changes a trust boundary. External human review
remains required before v1.0.0. Ticket completion does not satisfy those release gates
or establish compliance for untested environments.

**T174 live evidence boundary.** The disposable Local test harness uses the same
bounded authenticated readiness query while CP is stopped, then requires actual DP
authentication and Tor-forwarded destination bytes. It checks CP event publication
with a host-side test subscriber using only the disposable project's DP identity,
current CP key pin and certificate validity. The subscriber is not shipped in a
production image, has no Tor authority, and keeps at most 16 finite events in memory
for a non-reconnecting 35-second window. Raw timestamps/details are discarded;
only scenario verdicts and counts survive. Stream failure cannot count as event
silence, and gaps between windows are not continuous-monitoring evidence. Production
DP receipt logging and Docker health history remain disabled. Fresh live results
must identify the source/image candidate; pre-T152 T165 results do not validate this
path. Until those checks and independent review complete, T174/T155 remain pending
validation; unit/fixture passes alone do not close that obligation.

**Legacy cleanup procedure.** Stop old CP instances and any reader/exporter of the old database
before upgrading. Deploy the matching new source/images together; do not roll an old writer
back onto V002. Flyway's V001 checksum remains unchanged and V002 runs before normal CP startup.
It enables SQLite `secure_delete` on its migration connection and drops the detailed tables.
An already-open SQLite reader may still hold its pre-migration snapshot: close it before claiming
live-copy cleanup. Old backups, container archives and volume/filesystem snapshots are not
rewritten by a schema migration and must never be included in a normal aggregate export.

With all writers/readers stopped, run against the affected database using a local SQLite tool:

```sql
PRAGMA wal_checkpoint(TRUNCATE);
VACUUM;
PRAGMA wal_checkpoint(TRUNCATE);
```

Check each checkpoint's busy result is zero. If another connection prevents completion, stop
that connection and retry; do not delete `-wal` or `-shm` by hand because committed auth state
may still depend on them. Verify the active schema has no `audit_log`, current credentials and
generation are intact, and old marker data is absent from the live logical database. Only then
resume the new CP. The migration test exercises V001→V002 with WAL enabled and preserved auth.
SQLite explains [secure deletion and checkpoints](https://www.sqlite.org/pragma.html); these
operations concern SQLite's live files, not all physical copies.

Remove retired Stargate containers through Docker after confirming the replacement works;
changing the logging driver does not sanitize old containers' archives. Delete or explicitly
quarantine old DB exports, filesystem/volume snapshots and log backups under the operator's
backup policy; do not restore them into a new deployment or re-export them as aggregates.
Retain only current credentials/configuration needed for recovery. SSD wear leveling, host
journald/audit facilities, swap, hypervisor snapshots, engine-native lifecycle metadata and
host/root monitoring are outside forensic erasure guarantees. T152 prevents new Stargate
operational journals; it neither erases host observations nor infers a browsing-log leak merely
from old administrative timestamps.

This repair enforces an existing boundary; it introduces no new route, external communication,
cryptographic identity or relaxed guarantee. Ordinary independent ticket reviews remain
required, and Constitution VIII's external human review gate still applies before release.

## 6. What Stargate does not protect against

The Non-Goals from the constitution, restated in user-facing terms. Each
is a class of threat we explicitly do not address.

### 6.1 Whole-system traffic

Stargate is a **browser** proxy. Other software on your device —
mail clients, instant messengers, software update services, Spotify,
the OS itself — does **not** route through Stargate unless you
separately configure it to. If your goal is to anonymise an entire
device, Stargate alone does not do that; you need a system-wide
solution (Whonix, Tails, a VPN at the routing layer).

### 6.2 Hostile destinations

If you visit a website that runs JavaScript to fingerprint you, or an
onion service that serves malicious content, Stargate cannot stop it.
Stargate provides transport; in-page tracking, phishing pages, and
malicious downloads are the browser's and the user's concern. Mullvad
Browser's defaults reduce this surface but do not eliminate it.

### 6.3 Device compromise

If your device runs malware, has a keylogger installed, is being
recorded by a screen-capture tool, or has been physically accessed by
someone who altered it, Stargate provides **no protection**. The
threat is below Stargate's layer.

### 6.4 User behaviour

If you log into an account that identifies you while routed through
Tor or Nym, you have told the destination who you are. Technology does
not reverse this. If you make consistent typing-pattern, language,
schedule, or topic choices across sessions, you may be re-identifiable
through stylometry. Stargate cannot fix social patterns.

### 6.5 Cover traffic from your endpoint

Stargate does not produce cover or decoy traffic. Timing-correlation
resistance is the mixnet's responsibility. See §5.12.

### 6.6 Mobile devices in v1

Stargate v1 supports desktop browsers only. Mobile is a v1.5+
consideration. Do not rely on Stargate for phone or tablet traffic in
v1.

### 6.7 Default censorship circumvention

Tor bridges are supported but disabled by default. If you are on a
censored network and need to reach the Tor network, you must
explicitly enable bridges in the admin dashboard and accept the
arms-race nature of pluggable transports. Stargate is not a turnkey
censorship-circumvention tool.

### 6.8 Availability

Stargate is best-effort software. No uptime, latency, or service-level
guarantee is offered. Anonymity-network availability is determined by
the underlying networks (Tor, I2P, Nym), not by Stargate. If a sidecar
or its upstream network is down, your routes are down.

---

## 7. Comparison with adjacent tools

Honest pros and cons relative to existing tools. The framing is
**different shape, different tradeoffs** — not "Stargate is better".

### 7.1 Tor Browser

- **Tor Browser**: single browser, single route (Tor), tight
  fingerprint discipline, integrated update channel, large and
  well-studied anonymity set. Solves Tor specifically and well.
- **Stargate**: multi-route (Tor / I2P / Nym / Direct), per-domain
  routing, family-shareable LAN/VPS deployment, no opinion on browser
  fingerprint discipline (defers to Mullvad Browser).
- **Trade-off**: Tor Browser's anonymity set for fingerprinting is
  larger than Mullvad-Browser-routed-through-Tor (§5.7). If your only
  goal is Tor browsing and you do not need I2P or Nym, Tor Browser is
  the better choice for that workload.

### 7.2 Mullvad Browser standalone

- **Mullvad Browser**: hardened browser without a proxy; the user
  composes it with whatever transport they choose.
- **Stargate**: provides the proxy and the per-domain routing logic;
  reference browser is Mullvad Browser.
- **Trade-off**: standalone Mullvad Browser without Stargate gives no
  privacy at the network layer (Mullvad Browser does not embed Tor).
  With Stargate it gains Tor / I2P / Nym; without Stargate the user
  must add a VPN or Tor proxy manually.

### 7.3 Raw Tor + Firefox

- **Raw Tor daemon + a configured Firefox**: full control, no
  intermediary, no Stargate-specific bugs.
- **Stargate**: managed sidecar lifecycle, per-domain mapping,
  audited hardening, family deployment.
- **Trade-off**: raw Tor + Firefox is easy to misconfigure (DoH leak,
  WebRTC leak, QUIC fallback, SOCKS4 instead of SOCKS5h). Stargate
  encodes those mitigations in code; the user pays in deployment
  complexity (Docker Compose) and trust (the maintainers).

### 7.4 Nym client standalone

- **Nym client**: a standalone mixnet client. Single-protocol.
- **Stargate**: Nym is one route alongside Tor / I2P / Direct, with
  per-domain selection.
- **Trade-off**: a Nym-only setup is simpler if mixnet is the only
  thing you need. Stargate adds Tor and I2P to that picture and adds
  Docker-managed lifecycle.

### 7.5 Whonix / Tails

- **Whonix / Tails**: whole-OS anonymisation. Higher assurance
  isolation; Whonix uses VM separation between user and Tor gateway.
- **Stargate**: browser-only. Lighter weight, not whole-OS.
- **Trade-off**: Whonix and Tails protect against more classes of
  threat (OS-level leaks; non-browser apps). Stargate does not. If
  your threat model includes any of §6.1 or §6.3, Whonix/Tails is the
  honest answer, not Stargate.

### 7.6 Commercial VPNs (Mullvad VPN, ProtonVPN, etc.)

- **Commercial VPN**: single-hop tunnel to a VPN provider; trust
  centralised in the provider; effectively whole-system.
- **Stargate**: multi-network; trust distributed across anonymity
  networks (Tor, I2P, Nym); browser-only.
- **Trade-off**: a VPN gives whole-system coverage and good
  performance against your local ISP, at the cost of placing full
  trust in one provider. Stargate gives multi-network privacy
  properties at the cost of browser-only scope and higher complexity.

---

## 8. Known weaknesses and open research areas

Honest documentation of where Stargate's design is imperfect. Each item
is an accepted residual risk; mitigations are stated where they exist.

### 8.1 Timing-correlation resistance

Tor explicitly does not defend against a global passive adversary [Tor
design paper, §3]. Nym's Loopix design [Piotrowska et al., 2017] bounds
adversary success under stated assumptions but does not eliminate
correlation. **Stargate inherits these limits and cannot exceed them.**
The protection a route offers against a sufficiently capable global
observer is whatever its underlying network's design provides; Stargate
adds no protection here, and in particular does not add endpoint cover
traffic (§5.12).

### 8.2 Sybil and NetDB attacks against I2P

I2P has a smaller anonymity set than Tor, and published academic work
documents practical attacks on its NetDB [Egger, Schlumberger, Kruegel,
Vigna, "Practical Attacks Against The I2P Network," RAID 2013, LNCS
8145, pp. 432–451, Springer 2013. DOI: 10.1007/978-3-642-41284-4_22 —
see §4.4 for the abstract quote]. Stargate forwards what i2pd does; we
cannot mitigate Sybil attacks from the client side. Users routing
sensitive traffic over I2P should weigh this honestly.

### 8.3 Operator key management

Inter-plane keys live on the Stargate host (architecture spec §4.3).
Admin WebAuthn credentials live on user authenticators; the ed25519
fallback is a private key in a user wallet. Compromise of the host or
of admin credentials gives an attacker the ability to enroll devices,
toggle routes, and read aggregate counters. T152 retains only completed-hour
operational counts (§5.18), in the same DB the attacker can read or wipe.
It provides no tamper-proof administrative chronology.

**Mitigation today**: WebAuthn as the primary admin auth raises the
bar above passwords; aggregate counters at hour resolution mean an
attacker who reads the DB learns route-level traffic shapes, not
destinations (Principle III).

**Open**: a secure-element-backed inter-plane key store is a v1.5+
consideration; v1 accepts the file-on-disk model.

### 8.4 Mullvad Browser fingerprint pool size

As §5.7 notes, routing Mullvad Browser through Tor places the user in
the Mullvad Browser fingerprint pool, not the Tor Browser pool. The
two pools differ. We do not have a public estimate of the Mullvad
Browser pool size; this remains an open observation rather than a
defended position.

### 8.5 Container clock drift

Tor's tolerance for clock skew is bounded by descriptor and consensus
validity windows. Containers without NTP can drift; the failure mode
is silent connectivity loss. Stargate v1 has an authenticated init-time
bootstrap-readiness sample (architecture spec §9.1) but no continuous
clock-drift monitor.

### 8.6 Sidecar maintainer trust

Each sidecar's upstream maintainer is in the privacy TCB (§5.8). The Tor
Project publishes no official container image, so Stargate builds its own
Tor sidecar (`sidecars/tor/Dockerfile`) rather than trusting a third-party
image maintainer: a digest-pinned `debian:12-slim` base, Debian package
inputs pinned to an immutable `snapshot.debian.org` run with explicit
`=version` pins (T099), and the `tor` package itself from the Tor
Project's own apt repository (`deb.torproject.org`), bound to the pinned
Tor Project signing key by fingerprint and verified on every build. The
decision is resolved and recorded — `SECURITY-DECISIONS.md`
§"2026-07-04 — Tor sidecar trust rationale (FR-015)" is the authoritative
rationale, rotation policy, and residual-risk record.

T160 independently checks the Tor artifact against reviewed architecture-specific hashes before
installation, then excludes the mutable Tor source while obtaining dependencies from the Debian
snapshot. The earlier lack of an independent Tor hash check (finding 20260727-002) is repaired by
that implementation, subject to its recorded review/delivery state. It does not make malicious
reviewed upstream code trustworthy. The dated T160 decision supplements the historical rationale.

Remaining obligations:

- The 001 feature-preview carries final Tor and observer image digests in
  separate signed release data; source Compose retains `build:` and is not
  rewritten. Completed-v1 profile artifacts still need their own signed,
  digest-pinned bundles and runtime-verified architecture claims.
- T161 preserves the two failed cold T058 runs and supplies current attributable evidence from
  two new cold distinct-credential passes plus independent configuration/control and fusion
  controls. The earlier failures remain unattributed rather than relabeled. These native Tor
  results do not close T155's integrated foundation validation, final security/performance review,
  final image pinning or native arm64 obligations.

Update-channel compromise of a sidecar is §5.9; the wider sidecar-in-TCB
residuals are §5.8.

### 8.7 Bridge-distribution arms race

Tor bridges depend on a distribution channel that the censor is
actively trying to enumerate. Stargate ships no bridge directory; the
user adds bridges manually. The user inherits the Tor Project's
bridge-distribution properties [https://bridges.torproject.org/].

### 8.8 SNI exposure at clearnet exits

§5.6 covers this; restated here as an open area because ECH adoption
is incomplete in 2026 and is not under Stargate's control. Every
clearnet exit through every route exposes SNI today.

### 8.9 Long-lived VPS identity (VPS profile)

Reusing a single VPS over years creates a stable pseudonymous identity
visible to the VPS provider and observable through long-running egress
flows from a fixed IP. Stargate has no VPS-rotation feature; periodic
fresh provisioning is operational guidance, not enforced behaviour.

### 8.10 Web platform evolution

New browser APIs (WebHID, WebUSB, WebTransport, future fingerprinting
vectors) regularly emerge. Stargate's hardening audit (architecture
spec §14.5) enumerates the surfaces it knows about; new surfaces are
maintenance burden, and the gap between disclosure and audit-rule
update is residual risk for users.

---

## 9. Reporting vulnerabilities

**Do not open a public GitHub issue for security bugs.**

For anything you would not be comfortable making public immediately —
suspected privacy leaks, sidecar compromise, key disclosure — report
privately via **GitHub Security Advisories**:

> `https://github.com/zcat-app/stargate/security/advisories/new`

Non-sensitive issues go through the normal GitHub issue tracker. The
coordinated-disclosure window is documented in `CONTRIBUTING.md`
("Reporting security issues"); if a report shows that a guarantee claimed
in `THREAT-MODEL.md` does not hold, it is handled through the same private
channel, not the public tracker.

Honest note: a project at this stage of development is **not** an
appropriate target for users with state-level threat models. Stargate
v1 has not had external security review. Constitution Principle VIII
requires one external human review before `v1.0.0` ships. Until that
review is on record, treat Stargate as pre-release software for
threat models proportional to that maturity.

---

## Open questions for the maintainer

Items where this document could not be made fully concrete without
maintainer input. Listed here so they are not lost; should be resolved
in subsequent revisions of this file.

1. **Nym default gateway policy** (architecture spec §8). Pinning one
   gateway gives a stable observation point for the gateway's
   operator; rotating gives a different set of trade-offs. §4.5
   currently states this neutrally; once policy is decided, this
   document should state which one and why.
2. **Security contact channel** (§9). The private reporting route is
   GitHub Security Advisories; a PGP / age key fingerprint for
   out-of-band contact is still open. When booked, add the key
   fingerprint to §9 so users can authenticate the channel.
3. **External security reviewer identity** (Constitution Principle
   VIII). When booked, name the reviewer in §9 so users can verify the
   review's provenance at the time of disclosure.
4. **Mullvad Browser fingerprint pool size** (§8.4). If we obtain a
   defensible estimate, update §5.7 to quote it; otherwise leave the
   honest "we do not know" wording.
