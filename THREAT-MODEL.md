# Stargate Threat Model

> **Current compliance status — T156, 2026-09-12.** This document distinguishes required
> protections from known implementation gaps. The constitution and feature 001
> [foundation boundary contract](specs/001-tor-route/contracts/foundation-boundaries.md)
> supersede older topology, operational logging, counter-publication and auth-recovery claims.
> T125 is not constitutionally accepted. T134/T138/T152/T157–T159 and the other foundation
> repairs remain pending; no repaired runtime or live pass is claimed by this amendment.

**Status**: Draft
**Last updated**: 2026-05-17
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

Each sidecar is in the **per-route privacy TCB**. Pinned-digest selection
and the contract-test gate (Principle IV; architecture spec §7) are the
mitigations, but neither eliminates the risk. For the Tor sidecar
specifically, the build inputs are pinned to an immutable
`snapshot.debian.org` run with explicit `=version` pins (T099), so a clean
rebuild selects byte-identical packages and the resolved closure (incl.
`libssl3`) is frozen and auditable — but this makes the binary *auditable*,
not *trustworthy*: the closure still rides Debian's archive key, and a
malicious-but-behaviourally-conforming library is undetected. See §5.8,
§5.9, and `SECURITY-DECISIONS.md` §"Debian archive snapshot pin".

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

**Current gap:** T125 opened a wildcard proxy listener based on an environment flag.
That behavior is not authorized by the constitution. Existing multi-network/no-masquerade
configuration has not proven the required egress boundary. The below protections are target
properties pending T134/T155, not verified claims for the current stack.

**Protects against**:

- Other devices on the same LAN observing Stargate-routed traffic — they
  cannot connect to the proxy ports (loopback-only) and have no in-band
  view of the loopback socket.
- Network-level adversaries (§2.1, §2.3) seeing *plaintext request
  metadata* for routed traffic — they see only the encrypted outer tunnel
  to the chosen anonymity network's first hop.
- Required target: constrain a compromised application plane to its authorized
  adapter/IPC capabilities. Current T125/T094b topology and full CP cookie do not
  establish this property; T134/T138 and §5.8 record the remaining work.

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
  init-time healthcheck).
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
responsibility, documented in install instructions). The Tor sidecar's
healthcheck (architecture spec §9.1 step 4) catches gross failures at
init. No silent-clock-drift detection in v1.

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
The hardening audit displays a blocking dialog if WebRTC is enabled, and
the externally verified profile (release-cadence live-e2e test
`tests/live-e2e/mullvad-browser-hardening/`) additionally confirms
`peerConnectionEnabled = false` in a test profile that models the target
browser's hardened defaults.

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

**Current implementation gaps:** T125 added a no-masquerade attachment; its DNS/UDP egress
properties are not proven by the older three-network structural tests. CP currently receives
Tor's full cookie and can reach its SOCKS port. An in-process command allowlist cannot constrain
a compromised CP holding that cookie. These are unresolved T134/T138 findings, not accepted
conformance. The historical tests/decisions record the old design; T155 requires repaired
packet/capability evidence. A bridge-visible packet alone does not prove internet exfiltration.

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
  `snapshot.debian.org` run with explicit `=version` pins (T099), so a
  compromised mirror cannot drift the resolved package set between builds;
  the trust + rotation procedure is in `SECURITY-DECISIONS.md`.
- Release artefacts are signed (architecture spec §12.5 — signing tool
  NEEDS CLARIFICATION).

**Residual risk**: compromise of the maintainer's signing key. External
human security review before tagging `v1.0.0` (Constitution Principle
VIII) is the human-layer mitigation; downstream verification of
reproducible builds is the technical mitigation.

### 5.10 Per-first-party stream isolation

**Required property:** distinct authenticated-device/browser-profile/initiating-site partitions
must not share a Tor circuit. The constitution and feature boundary contract define the scope;
T136 pins suffix/context derivation and the bounded wire representation; T147 handles CONNECT.
No general correlation resistance follows from partitioning, and same-partition sharing is
permitted rather than guaranteed. Missing initiating context must block a protected request.

**Current gaps:** the audit found suffix collisions and a CONNECT path without isolation
identity. They remain T136/T147 remediation, not proven circuit leakage in every live request.
T126/T155 supply real same-target/distinct-partition evidence with controls; synthetic
username assertions alone cannot establish the whole browser-to-Tor path.

**Residual limitations:** parties within one defined partition may share circuits. Browser
context fidelity and installed-profile hardening require the stated tests/preconditions;
unknown context may not silently degrade to destination-only identity or Direct.

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
- **Mode/group dial gate** (`0660` + `stargate-ipc` GID) is the outer
  defence that keeps the dial surface small in the local profile; the
  mutual-pin is the load-bearing auth gate.

**Current gaps and residual risk (T095 history; T156 requirements)**:

- **Current gap:** certificates use `NotBefore = now − 5 min` and
  `NotAfter = now + 30 days`, but the audit found expiry and resumed-peer pin checks incomplete.
  T135/T148 must enforce current identity and validity on full/resumed handshakes,
  automatically renew certificates before expiry, and specify existing-channel lifecycle.
  Manual monthly restart is not a conforming renewal policy. This amendment does not
  claim the checks already work; key rotation and certificate renewal are distinct.
- **No automated key rotation in v1.** Replacing the on-disk
  `cp.priv`/`cp.pub` / `dp.priv`/`dp.pub` keypairs is operator-manual
  (write-tmp + rename + plane restart, ordered per `wire-auth.md` §6.2).
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

Valid durable snapshots support CP-down restart. Missing/corrupt/incompatible snapshots deny
new admission. Supported crash/restart must not undo an acknowledged revocation, and ordinary
reconnect must not relabel credentials restored from a stale CP backup as fresh authority.
T132/T159 implement and verify this target. Current non-durable success/stale-state renumbering
is a known gap, not an accepted recovery mechanism. Explicit operator rollback recovery has its
own warned procedure; hostile host/root rollback of all trusted state is outside the guarantee.

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
toggle routes, and read aggregate counters. The audit log records
admin actions (architecture spec §6 `audit_log`), but the log lives in
the same DB the attacker can read or wipe.

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
is silent connectivity loss. Stargate v1 has init-time healthchecks
(architecture spec §9.1) but no continuous clock-drift monitor.

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

Two residues stay honestly open here:

- The final composed image digests are not yet pinned; that lands at
  release-tag time with the release workflow (T081). Until then the
  supply chain is base-pinned + snapshot-pinned + key-verified, not
  fully image-pinned.
- The recorded sha256 of the `tor` `.deb` is enforced by no independent
  build step — apt verifies it only against the repository's own signed
  index, so a same-version replacement by a compromised
  `deb.torproject.org` remains maintainer-trust residue. This is tracked
  as open redteam finding 20260727-002 and is not claimed as mitigated.

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
