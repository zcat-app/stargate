# T134 — Constitution-compliant local topology: investigation report

**Ticket:** T134 (`specs/001-tor-route/tickets/T134-investigate-local-topology.md`)
**Candidate source:** commit `c65952dd39a09c34c59b589b5a94e4972e48d1f9` (branch `001-tor-route`)
**Date:** 2026-09-13 · **Driver:** `scripts/run-task.sh T134`
**Finding sources:** `reviews/redteam-20260912-677960b.md` B1 (wildcard exception) and M1
(no-masquerade does not establish the egress boundary); T156 constitution
(`.specify/memory/constitution.md` Deployment Model; Principle III actor/traffic matrix);
`contracts/foundation-boundaries.md` §"Deployment and authority".

**Result: candidate A is recommended** — DP binds the host network namespace's loopback
directly under the strict (exception-free) bind check, sidecar reachability moves to
unix-socket fabric on shared volumes, and DP/CP IP egress is denied at packet level by
host owner-match rules provisioned and verified by the installer. Candidate B
(host-loopback TCP relay → UDS → network-less DP) is viable and remains the documented
fallback; candidate C (repairing the T125 bridge topology) is rejected on evidence.
Implementation is owned by T162 (topology) and T163 (packet-level verification), wired
into T155/T123/T124. No production file was changed by T134.

---

## 1. Method and constraints

All work ran on disposable state: throwaway docker networks/volumes/containers
(`t134*`), a temporary DP binary build, a disposable pepper and a crafted
`dp-snapshot.json`. Nothing touched `compose/`, `data-plane/`, `control-plane/`,
`sidecars/`, `tests/`, or any production contract. Cleanup removes every resource
(trap-based, verified by rerun).

**Environment:** docker 29.1.3, Linux 6.8.0-124-generic, Go 1.26.0 (toolchain pin is
1.26.3 — same known drift the audit recorded; no online promotion), locally built
`stargate/tor:local` (Tor 0.4.9.12-1~d12.bookworm+1, image `ceb3ba3d6aa1`).

**Standing environment assumption (limits of this evidence):** the probe host has no
passwordless sudo, so the "host" of candidate A is simulated by a **privileged container**
(`host-sim`) standing in for the physical host. Kernel-level mechanisms (netfilter
owner-match, tcpdump on the egress interface, unix-socket permissions) are identical in
kind, but this is mechanism-level evidence, not a physical-host proof. The follow-up
verification ticket (T163) must repeat the captures against the real deployment
namespaces, as the foundation contract requires ("Test actual packets in source and
egress namespaces with positive capture controls").

---

## 2. R1 — reproduction of B1: the wildcard exception (preserved evidence)

Built the actual DP binary from the candidate tree
(`go build -o /tmp/t134/dp ./cmd/stargate-proxy`), ran it natively with disposable
pepper/state/IPC dirs, no containers, no tunnels:

```sh
# /tmp/t134/r1/probe.sh (verbatim; DP binary prebuilt)
#!/usr/bin/env bash
set -u
DP="${DP:-/tmp/t134/dp}"
BASE="$(mktemp -d /tmp/t134-r1.XXXXXX)"
run_case() { # name in_container listen_addr
  local name="$1" inc="$2" addr="$3"
  local d="$BASE/$name"; mkdir -p "$d/keys" "$d/state" "$d/ipc"
  head -c 32 /dev/urandom > "$d/keys/pepper.key"; chmod 0600 "$d/keys/pepper.key"
  STARGATE_KEYS_DIR="$d/keys" STARGATE_STATE_DIR="$d/state" STARGATE_IPC_DIR="$d/ipc" \
  STARGATE_IN_CONTAINER="$inc" STARGATE_LISTEN_ADDR="$addr" \
    "$DP" 2>"$d/err.log" &
  local pid=$!
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then
    local listener hostport
    listener="$(grep -o 'listener=[^ ]*' "$d/err.log" | head -1)"
    hostport="${listener#listener=}"
    if [ -n "$listener" ]; then
      local reply
      reply="$(printf '\x05\x01\x02' | timeout 2 nc -q1 127.0.0.1 "${hostport##*:}" | od -An -tx1 | tr -d ' \n')"
      kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
      echo "case=$name in_container=$inc addr=$addr => STARTED ($hostport) socks5_method_reply=$reply"
    else
      kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
      echo "case=$name in_container=$inc addr=$addr => started, no listener line"
    fi
  else
    wait "$pid"; local rc=$?
    echo "case=$name in_container=$inc addr=$addr => REFUSED exit=$rc"
    grep -m1 'reason=' "$d/err.log" | sed 's/^/  /'
  fi
}
echo "== R1: strict native wildcard refusal vs STARGATE_IN_CONTAINER exception =="
run_case native-strict      0 0.0.0.0:0
run_case native-exception   1 0.0.0.0:0
run_case native-exception-lan 1 "$(hostname -I | awk '{print $1}'):0"
run_case native-loopback    1 127.0.0.1:0
run_case native-loopback-noinc 0 127.0.0.1:0
echo "== disposable state root: $BASE (removed at end) =="
rm -rf "$BASE"
```

Observed (2026-09-13, lan address = the probe host's non-loopback interface, redacted from the permanent record):

```text
== R1: strict native wildcard refusal vs STARGATE_IN_CONTAINER exception ==
case=native-strict in_container=0 addr=0.0.0.0:0 => REFUSED exit=1
  level=ERROR msg=shutdown reason="bind refused \"0.0.0.0\": wildcard bind requires the container boundary (STARGATE_IN_CONTAINER=1): BIND_REFUSED"
case=native-exception in_container=1 addr=0.0.0.0:0 => STARTED ([::]:38175) socks5_method_reply=050201ff
case=native-exception-lan in_container=1 addr=<lan-addr>:0 => REFUSED exit=1
  level=ERROR msg=shutdown reason="bind refused \"<lan-addr>\": not loopback: BIND_REFUSED"
case=native-loopback in_container=1 addr=127.0.0.1:0 => STARTED (127.0.0.1:40087) socks5_method_reply=050201ff
case=native-loopback-noinc in_container=0 addr=127.0.0.1:0 => STARTED (127.0.0.1:36717) socks5_method_reply=050201ff
```

**Reading.** B1 is confirmed and sharpened: the boolean alone opens a live SOCKS5
listener on a bare host (`05 02` method reply; `01 ff` is the DP's RFC 1929
sub-negotiation failure on our EOF — a *live* authenticated-handshake-capable listener).
The exception's remaining guard is narrow: a specific non-loopback interface stays
refused even with `STARGATE_IN_CONTAINER=1`, and loopback needs no flag. The
constitutional problem is exactly the wildcard premise: nothing verifies a container
boundary or tunnel, and the constitution authorizes no wildcard "because container".

---

## 3. Tor unix-socket feasibility (new design facts, with failed alternatives)

Tested against the pinned sidecar image (Tor 0.4.9.12) with a `SocksPort unix:` /
`ControlSocket` torrc override:

1. **Tor refuses any unix-socket directory not private to its user.** With the socket
   directory at mode 0750 or 0770 (tor-owned), startup fails closed (this sweep is
   preserved in the driver as phase A.3.0b; the round-1 evidence was an interactive
   probe, now reproduced verbatim in-driver):

   ```text
   [warn] Permissions on directory /fabric/socks are too permissive.
   [warn] Before Tor can create a SOCKS socket in "/fabric/socks/tor-socks.sock", the
          directory "/fabric/socks" needs to exist, and to be accessible only by the
          user account that is running Tor. ...
   [err] Reading config failed--see warnings above.
   dir mode 0700: sockets_created=2  running=true
   dir mode 0750: sockets_created=0  running=false
   dir mode 0770: sockets_created=0  running=false
   ```

   **Failed alternative (recorded):** group-traversable socket directories for the
   cross-uid fabric — rejected by tor itself. Consequence: the DP (a different uid)
   can never traverse to tor's native socket path; the fabric needs a re-exposure
   mechanism owned by the Stargate-built image.

2. **Native socket modes are `srw------- tor:tor` (0600)** for both the SOCKS and
   control unix sockets — re-exposure must also adjust the connect permission.

3. **Hardlink re-exposure works** (same filesystem, same inode): linking the socket
   inode into a traversable directory and chmod'ing it yields a reachable endpoint
   without any bridge process:

   ```text
   10246554 srw-rw-rw- 2 tor tor 0 Sep 13 19:50 /fabric/socks/tor-socks.sock
   10246554 srw-rw-rw- 2 tor tor 0 Sep 13 19:50 /fabric/tor-socks.sock
   ```

   (Production would use mode 0660 with a shared fabric group rather than 0666; the
   probe used 0666 because its cross-container uids are not group-aligned. An
   in-image `socat`-class UDS→UDS bridge is the equivalent alternative; the hardlink
   needs no extra process.)

4. **Minor torrc fact:** `CookieAuthFileGroupReadable 1` has no effect without an
   explicit `CookieAuthFile` path (tor warns). Relevant to T138 (CP observer
   authority), not load-bearing here.

5. **Unprivileged sidecar containers cannot write at filesystem root** — silent
   `>` redirection failures killed two probe helpers before they served anything
   (harness finding; recorded because the same class of silent failure would bite
   any future socket-directory provisioning that assumes root paths).

---

## 4. Prototype P-A (recommended candidate) — design and evidence

**Topology under test** (all disposable):

- `host-sim` — privileged container standing in for the physical host. Identities:
  `dp` (uid 5102, gid 5100, supplementary 5103), `probe` (uid 6000), `relay` (uid 5104).
- Egress rules installed in host-sim (v4+v6), hardened across review rounds:
  `OUTPUT -m owner --uid-owner 5102 -o lo -p tcp --dport 9050 -j ACCEPT` (scoped to
  the prototype's lo:9050 TCP shim — the stand-in for the DP's native AF_UNIX dial;
  **production carries no IP-initiated exception at all**, because the sidecar fabric
  is unix sockets), then `-o lo -m conntrack --ctstate ESTABLISHED,RELATED -j
  ACCEPT` — replies to the DP's own accepted inbound clients, **scoped to loopback**
  (an unrestricted ESTABLISHED rule would let a compromised DP answer an externally
  initiated off-loopback connection: phase A.11 demonstrates that channel CARRYING
  DATA under the round-2 shape and DEAD under this one) — then a **silent** `DROP`.
  Two round-2 properties are load-bearing: **no blanket loopback permission exists**
  (a NEW connection from the DP uid to any loopback address/port — a host forwarding
  resolver on 127.0.0.53, a local forwarder, any intermediary — is dropped, closing
  the mediation path a host-netns DP would otherwise have), and **no LOG target
  exists anywhere** (netfilter's LOG/ULOG writes per-packet src/dst/port records,
  which would violate Constitution III's aggregate-only rule; the DROP rule's own
  packet counters are the kernel-level cross-check and carry no per-packet
  metadata). The candidate-B relay (uid 5104) gets the **same loopback-scoped**
  shape (`lo`-scoped ESTABLISHED,RELATED + silent DROP; its data leg is AF_UNIX),
  and phase A.11 exercises the reverse-initiated channel for BOTH identities:
  falsifier leg under the unrestricted shape, closure leg under the shipped one.
- **Per-consumer socket fabrics (round-2 review F2):** two separate volumes — a DP
  fabric carrying only the SOCKS re-exposure (`/socks` 0700 tor → `/dp/tor-socks.sock`
  0660 gid 5200) and a CP fabric carrying only the control re-exposure
  (`/ctrl` 0700 tor → `/cp/tor-control.sock` 0660 gid 5201). Mount separation
  enforces the caller matrix at the filesystem level: the DP side never sees the
  control socket, the CP side never sees the SOCKS socket, and the re-exposure
  directories additionally group-gate the sockets. Phase A.10 exercises the matrix.
- The **real DP binary** runs as uid 5102 in host-sim with
  `STARGATE_LISTEN_ADDR=127.0.0.1:8881`, `STARGATE_IN_CONTAINER=0` (the strict path),
  a disposable pepper, and a crafted generation-1 `dp-snapshot.json`
  (verifier = `HMAC-SHA256(pepper, token)`, base64 std) so cold-start admission works
  with a known token and no CP anywhere in the prototype.
- Tor runs with the unix-socket torrc plus the hardlink re-exposure loop (§3).
- A **lo:9050 socat shim** in host-sim (TCP loopback → tor UDS) stands in for the
  DP's native unix dial, which is a production change owned by T162
  (`forward/tor.go` pins `proxy.SOCKS5("tcp", …)` at the dial site).
- `fake-internet` — a bridge peer offering TCP/UDP targets, so every capture is
  offline; `192.0.2.10` (documentation address) serves as the DNS-style UDP target.

**Results (transcript abridged to the load-bearing lines; full script in §7):**

```text
  dir mode 0700: sockets=1 running=true
  dir mode 0750: sockets=0 running=false
  dir mode 0770: sockets=0 running=false
PASS: uid 5102 rules: scoped lo:9050, lo-scoped ESTABLISHED,RELATED, silent DROP (v4+v6)
listener=127.0.0.1:8881
1
PASS: DP listening on 127.0.0.1:8881 via the strict bind path (no exception)
PASS: cold start: snapshot restored (generation 1)
PASS: hardlink re-exposure present (same inode as the tor-private socket)
tor-uds method reply: 0502
PASS: tor accepts SOCKS5 over the unix socket (05 02)
e2e reply: 0502010005040001000000000000
PASS: DP method+RFC1929 auth accepted through loopback (05 02 01 00)
PASS: COMPLETE upstream-derived reply (05 04 ROUTE_REFUSED synthesized from tor's SOCKS failure): bytes demonstrably flowed DP->shim->UDS->tor
dead-shim reply: 0502010005030001000000000000
PASS: DISCRIMINATION: accepting-but-silent shim FAILS the complete-reply assertion (would previously pass as auth-only)
shim-stopped reply: 0502010005030001000000000000
PASS: differential: 05 03/06 when fabric down — A.4 bytes demonstrably flowed via the fabric
PASS: host-sim eth0 172.21.0.4:8881: refused
PASS: from fake-internet container: refused
-- attempts as uid 5102:
  tcp->FI: failed
  udp->FI: send denied
  dns53->doc-addr: send denied
  tcp->doc-addr: failed
  capture: ok
  capture packets: 0
  per-class -> tcp: 0  udp-to-FI: 0  udp53-to-doc: 0
  iptables DROP pkts for uid 5102: 6
PASS: A.7 negative capture lifecycle: started, clean exit, decodable pcap
PASS: NEGATIVE: ZERO packets to FI/doc-address emitted by DP uid (capture-verified)
PASS: kernel owner-match DROP counters confirm the attempts were filtered (6 pkts)
PASS: A.7 positive capture lifecycle: ok
PASS: POSITIVE CONTROL: per-class counts all non-zero (capture packets: 11 in the phase)
  per-class -> tcp: 9  udp-to-FI: 1  udp53-to-doc: 1
PASS: POSITIVE CONTROL per class: TCP, UDP-to-FI and UDP/53-shaped packets EACH visible — per-protocol capture validity
PASS: DP restart: listener back, auth state from disk (Principle II cold start preserved)
-- forwarder use attempts as uid 5102:
  tcp-via-forwarder: no data
  udp-via-forwarder: send denied
  host-resolver-style udp/53: send denied
  capture: ok
  eth0 packets to FI (tcp): 0
PASS: DP-uid TCP via lo forwarder: no data returned (NEW flow to lo dropped)
PASS: DP-uid UDP via lo forwarder: denied
PASS: DP-uid host-resolver-style UDP/53 to loopback: denied
PASS: NEGATIVE: ZERO forwarded packets to FI attributable to DP-uid attempts
  tcp-via-forwarder: RECEIVED banner
  eth0 packets to FI (tcp): 8
PASS: POSITIVE CONTROL: unrestricted uid RECEIVED the FI banner through the lo forwarder
PASS: POSITIVE CONTROL: forwarder-mediated packets to FI VISIBLE on eth0 (8)
PASS: host-sim (DP side) has NO cp-fabric mount — control socket unreachable by construction
PASS: cp-sim has NO dp-fabric mount — SOCKS socket unreachable by construction
cp->control PROTOCOLINFO reply: 250-PROTOCOLINFO 1
PASS: CP identity CAN reach the control socket — TRANSPORT/mount evidence only; the sanitized observer boundary is T138 design, not implemented here
dp->socks method reply: 0502
PASS: DP identity CAN reach the SOCKS socket (positive)
probe-uid (no fabric group) -> socks: nc: /fabric/dp/tor-socks.sock: Permission denied
PASS: identity WITHOUT the fabric group gets EACCES on the SOCKS socket (permission-gated; nc exits 0 regardless)
==== phase A.11: reverse-initiated off-loopback channel ====
echo-server up (uid 5102, 0.0.0.0:19191)
old-rule (unrestricted ESTABLISHED) FI-side reply: 'T134-MARKER'
PASS: FALSIFIER: under the round-2 rule shape the reverse-initiated off-loopback channel CARRIES DATA (marker echoed)
lo-scoped-rule FI-side reply: ''
PASS: lo-scoped ESTABLISHED: reverse-initiated off-loopback channel DEAD (no marker; SYN-ACK dropped at OUTPUT)
PASS: loopback SOCKS5 admission still works under the lo-scoped rules (no availability regression)
relay old-rule reply: 'T134-RMARK'
PASS: FALSIFIER (relay): unrestricted ESTABLISHED lets the relay identity exchange data on a reverse-initiated off-loopback channel
relay lo-scoped reply: ''
PASS: relay identity: reverse-initiated off-loopback channel DEAD under lo-scoped rules
PASS: DP stand-in running with network_mode:none, serving UDS
stand-in interfaces: lo 
PASS: structural isolation: stand-in netns has ONLY lo — no IP egress surface exists
PASS: relay up on 127.0.0.1:8882 as uid 5104 (loopback-scoped ESTABLISHED,RELATED + silent DROP only)
relay-path reply: 0502 (attempt 1)
PASS: candidate B fabric: TCP lo -> relay -> UDS -> netns-less stand-in replied 05 02
-- attempts as uid 5104:
  capture: ok
  capture packets: 0
  iptables DROP pkts for uid 5104: 15
PASS: B.2 relay capture lifecycle: ok
PASS: NEGATIVE: ZERO packets to FI/doc-address emitted by the relay uid (capture-verified)
PASS: kernel DROP counters confirm the relay-uid attempts were filtered (15 pkts)
PASS: B.2 positive capture lifecycle: ok
PASS: POSITIVE CONTROL (relay phase) per class: TCP (8), UDP (1), UDP/53 (1) each visible
PASS: relay non-loopback ingress refused (host-sim eth0 172.21.0.4:8882)
unrestricted uid via abstract forwarder: 'T134-FAKE-INTERNET-TCP'
PASS: POSITIVE CONTROL: abstract-UDS forwarder mediates to FI for an unrestricted uid
GAP-DEMONSTRATED: the DP uid CAN mediate egress through a host abstract-socket forwarder
  under the current policy (no per-uid gate exists for AF_UNIX; T162 must close it)
================ T134 prototype summary: FAILS=0 ================
```

The `05 04` in the end-to-end reply is the **DP's synthesized classification** of
an upstream refusal: tor's SOCKS layer answered the CONNECT with a non-zero REP
(no descriptor/circuit for the synthetic onion), x/net surfaces that as
`unknown error <reply>`, and `forward/tor.go`'s `classify()` maps exactly that
wrapper to ROUTE_REFUSED (`listener/socks5.go` then emits the failure reply). The
fabric assertion therefore requires the **complete** 14-byte reply —
authentication-only truncations, ROUTE_TIMEOUT (`05 06`) and dead shims all FAIL
it. Two discriminations pin this: an accepting-but-silent shim (`EXEC:/bin/true`;
EOF → `05 03`) fails the assertion (phase A.4f), and with the shim stopped the
same request yields `05 03` immediately (phase A.5 differential).

**What this establishes, mapped to the acceptance:**

- *Loopback reachability*: browser-style SOCKS5 (method + RFC 1929 with the known
  token + CONNECT) completes through `127.0.0.1:8881` under the **strict** bind path
  with `STARGATE_IN_CONTAINER=0` — no exception exists to abuse.
- *Non-loopback refusal*: natively for the bind (R1), and at runtime the lo-bound
  listener is unreachable from host-sim's eth0 and from a peer container.
- *Packet-level DNS/TCP/UDP isolation with positive capture controls, per
  protocol*: the DP uid's TCP connects fail with **zero** packets on the egress
  interface in every class — TCP, UDP-to-FI and UDP/53-shaped each counted
  separately as zero — kernel DROP counters tick on every attempt, and UDP/53-
  shaped sends are denied; the unrestricted control uid's identical traffic is
  visible **in each class on the same capture** (TCP ≥1, UDP ≥1, UDP/53-shaped ≥1,
  asserted individually) and its TCP connect succeeds — per-protocol capture
  validity, which is precisely what the audit's M1 probe lacked (a TCP-only
  capture cannot satisfy the UDP/DNS controls).
- *Cold start*: first start restores the snapshot generation (A.2: "snapshot
  restored", generation 1, no CP anywhere); the A.8 restart leg asserts re-listen
  under the topology. (Scope note: restart-path snapshot re-restoration is evidenced
  by the A.2/A.8 logs together, not a separate third assertion.)
- *Loopback-forwarder mediation (round-2, review F1)*: an unrestricted forwarder on
  host loopback relaying to the bridge peer is fully usable by the control uid
  (banner received, 8 packets visible) and unusable by the DP uid (TCP: no data;
  UDP and resolver-style UDP/53: denied; zero forwarded packets attributable) —
  the DP cannot launder egress through a local intermediary, which is the hole a
  blanket loopback ACCEPT would have left and the foundation contract's
  "no arbitrary names through a forwarding service resolver" rule demands closing.
- *Socket caller matrix (round-2 review F2; relabeled round-3)*: mount-separated
  per-consumer fabrics give the DP identity its SOCKS socket (05 02) and the CP
  identity transport reachability of its control socket (PROTOCOLINFO 250) —
  **transport/mount evidence only**: each side's cross-socket does not exist in its
  namespace and an identity without the fabric group receives EACCES. What is
  *not* claimed: sanitization of the CP's Tor authority — that boundary is T138's
  unimplemented design; the raw ControlSocket is exactly what T138 exists to narrow.
- *Abstract-socket forwarder channel (round-6 review, open gap honestly labeled)*:
  abstract-namespace unix sockets belong to the network namespace — mount
  separation cannot gate them and netfilter never sees AF_UNIX — and phase A.12
  demonstrates a host abstract-UDS forwarder mediating egress for the DP uid
  UNDER THE CURRENT POLICY (positive control: an unrestricted uid uses the same
  channel). No per-uid enforcement exists for this class with stock kernel tools;
  the specified closure is AppArmor unix mediation (a DP profile allowing exactly
  its pathname fabric sockets, its dp.sock server socket and its control.sock
  client connection — WatchEvents must keep working — while denying abstract
  connects) loaded by the installer
  alongside the firewall rules — enforcement is NOT demonstrated here (the
  privileged-container stand-in cannot load host securityfs profiles) and is a
  mandatory, discriminating regression in T162. If the target deployment cannot
  load AppArmor profiles, the topology decision returns to the maintainer
  (candidate B's netns-less DP is structurally immune to this channel — abstract
  sockets do not cross network namespaces — but B's host relay carries the same
  requirement).
- *Reverse-initiated off-loopback channel (round-3 review F1)*: with an echo server
  bound off-loopback under the DP identity, the round-2 rule shape (unrestricted
  ESTABLISHED,RELATED) lets an external peer complete a handshake and exchange a
  marker — demonstrated, then removed: under the lo-scoped shape the peer gets
  nothing (SYN-ACK dropped at OUTPUT) while authenticated loopback admission still
  works. The DP identity can converse ONLY with its loopback clients and its
  unix-socket sidecars.
- *Candidate B relay identity (round-2, review F4)*: the relay uid's TCP/UDP/DNS
  attempts produce zero captured packets in every class with ticking DROP counters
  (15), the unrestricted control uid is visible per class on the same capture,
  and the relay's listener is refused off loopback — B's enforcement is
  demonstrated for the measured properties, no longer asserted by analogy.

**Limitations recorded (honesty over reach):**

- host-sim is a privileged container, not the physical host (§1).
- IPv6 owner-match rules were installed but the probe bridge carried no IPv6
  traffic; per-family validation belongs to T163 (constitution: "Validate effective
  addresses and reachability in each supported IP family").
- One earlier capture round matched ARP name-resolution frames (who-has for the
  bridge peer) under a bare `host` filter — ARP is not IP egress and cannot carry a
  payload off-link, but the observation is retained: uid-based OUTPUT filtering does
  not gate L2 ARP. The final filter restricts the claim to `tcp or udp`.
- No live Tor circuit was built; the fabric proof is SOCKS5-level (adequate for
  topology properties; circuit-level behaviour is T126/T155 scope).

---

## 5. Prototype P-B (compared alternative) — fabric evidence

Relay (`socat` as uid 5104, host-sim lo:8882, same owner-match treatment) →
UDS → DP stand-in in a `network_mode: none` container:

```text
PASS: DP stand-in running with network_mode:none, serving UDS
stand-in interfaces: lo
PASS: structural isolation: stand-in netns has ONLY lo — no IP egress surface exists
PASS: relay up on 127.0.0.1:8882 as uid 5104 with identical owner-match treatment
relay-path reply: 0502 (attempt 1)
PASS: candidate B fabric: TCP lo -> relay -> UDS -> netns-less stand-in replied 05 02
PASS: relay uid non-lo TCP denied (same packet-level treatment as the DP uid)
```

The B fabric works. Its DP-side isolation is *structural* (no IP stack at all).
What B costs (see §6): a production DP listener refactor (the listener is TCP-only
today, `net.Listen("tcp", …)` in `cmd/stargate-proxy/main.go`), a new always-on
component, and — decisive — **the relay observes the RFC 1929 negotiation bytes**
(bearer token, destination host, isolation username) as a second TCB member beyond
the DP, with no credential-grade gain.

---

## 6. Candidate comparison under the T156 constitution

Axes required by acceptance #2, plus authority and cost.

| Axis | A — host-loopback DP + UDS fabric + owner-match egress (recommended) | B — lo TCP relay → UDS → network-less DP | C — repair the T125 bridge topology |
|---|---|---|---|
| Loopback ingress | DP binds host `127.0.0.1:8881` directly via the strict, exception-free check — the promised startup safety becomes premise-free (B1 closed by construction). No publish, no docker-proxy, no bridge race. | Relay binds host lo; DP never opens a TCP listener. Also premise-free. | Wildcard in the container netns behind an unattestable env boolean (B1 unaddressed); publish depends on non-internal bridge (T125's silent-discard regression class). |
| DP/CP/Tor authority | Tor is the only bridge-attached container; DP/CP attach to **no** docker network. Sidecar reachability is **mount-separated per-consumer UDS fabrics** (DP fabric carries only SOCKS, CP fabric only control; 0660 group-gated re-exposure; A.10: DP→SOCKS ✓, CP→control transport ✓, cross-sockets absent, no-group→EACCES — sanitization is T138's pending design, not claimed here). DP uid IP egress denied packet-level with **loopback-scoped replies** (A.11: the reverse-initiated off-loopback channel is dead); AF_UNIX is untouched by netfilter — the **abstract-socket forwarder channel is demonstrated open (A.12)** and its AppArmor-mediated closure is a mandatory T162 requirement, not a present property. | Same mount-separated sidecar fabrics behind the relay; the relay is a new host-netns process under the **identical loopback-scoped** owner-match treatment — measured for the relay identity itself (B.2 zero-packet capture + counters; A.11 reverse-channel falsifier and closure; refused off-lo) — and it **sees negotiation bytes** (bearer/destination/isolation) — TCB expansion. B's DP is structurally immune to the A.12 abstract channel (own netns); B's relay carries the same AppArmor requirement. | DP sits on a non-internal no-masquerade bridge; embedded-resolver DNS channel persists (accepted T125 residue), enforcement is host state compose does not own. |
| Destination DNS | SOCKS5h unchanged; DP performs no resolution (code-level guarantee: IP-literal parsing only). DP off all docker networks ⇒ Docker's embedded resolver is unreachable; host-loopback forwarders (a local resolver, any intermediary) are unreachable for NEW flows by the scoped rule set (A.9 evidence); even a code regression could not emit off-boundary UDP/53. Residual: replies on the DP's own established inbound connections, and collusion with an unrestricted local process, are outside uid-gating — the §2.8 OS-attacker boundary. | SOCKS5h unchanged; DP has no IP stack — strongest form of the same property (its relay needs ESTABLISHED-only rules; no loopback NEW either). | SOCKS5h unchanged, but the DP's resolver channel (embedded resolver forwarding external names) survives — a documented accepted residue T156 declines to inherit. |
| Cold start | Unchanged semantics: snapshot restore + re-listen observed under the prototype; socket recreation on tor restart degrades per-request to ROUTE_DOWN (fail-closed, FR-009/FR-14 advisory-only semantics preserved). No CP dependency anywhere in the path. | Same, plus a relay restart window (host 8881 briefly refused — same class as today's docker-proxy race). | Unchanged from current stack. |
| Constitution fit | "A shared namespace is a design candidate, not an automatic solution: it must also satisfy the capability/egress matrix" — **measured for the IP boundary** (caps-dropped uid-separated process, silent-DROP owner-match with loopback-scoped replies, per-protocol positive controls) and **pending for full capability confinement**: the A.12 abstract-socket channel stays open until installer-loaded AppArmor unix mediation is enforced and verified (T162), and the observer authority awaits T138. Fit is conditional, not claimed. | Fit for the properties actually measured (B.2 captures, refusal off-lo); the relay's negotiation-byte visibility argues against it under Principle III's spirit ("Management traffic is never a channel for application payloads or per-request observations" — the relay is not management, but the TCB argument carries). | T156 supersedes T125's permission explicitly; keeping it requires a constitution amendment, which T134 may not make. |
| Production cost | Forwarder unix dial (one transport parameter), bind-exception deletion, tor image sockets + re-exposure hook, compose rewire (net modes + fabric volume), installer firewall provisioning + fail-closed verification, contract/spec amendments. | All of A's sidecar/compose work **plus** DP listener transport refactor **plus** a new relay image/service and its review surface. | Least diff, fails the constitution. |

**Recommendation: candidate A.** It resolves B1 by removing the premise (strict
loopback bind, `STARGATE_IN_CONTAINER` deleted outright) and M1 by replacing
"NAT-off + connect-timeout" with kernel-enforced (silent-DROP), capture-verified
packet denial plus mount-separated per-consumer sidecar authority (A.10), plus
the closure of both resolver channels available to a host-netns DP (docker's
embedded resolver — unreachable; host-loopback forwarders — dropped for NEW flows,
A.9). B is the fallback only where host-netns placement of the DP is rejected and
the deployment permits its host relay and required per-UID firewall/AppArmor
enforcement; B does not remove the host firewall or AppArmor prerequisites. Its
fabric and enforcement profile are proven equal by P-B. C is rejected: it retains exactly the unattestable premise and unproven
boundary the audit flagged, and the T156 text already withdraws the permission.

---

## 7. Preserved probe artifacts (verbatim)

The complete prototype driver (P-A + P-B) and its full transcript are reproduced
here so the evidence survives independently of `/tmp`.

### 7.1 SOCKS5 request fixture (exact creation step — embedded in the driver, §7.2)

```sh
if [ ! -s /tmp/t134/pa/socksreq-printf.txt ]; then
python3 - <<'PYFIX' > /tmp/t134/pa/socksreq-printf.txt
token = b"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
uname = b"sg1:" + b"a"*64
host = b"a"*56 + b".onion"
req = b"\x05\x01\x02" + bytes([1, len(uname)]) + uname + bytes([len(token)]) + token + b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x00\x50"
print("printf '" + "".join("\\%03o" % b for b in req) + "'", end="")
PYFIX
fi
```

The driver consumes the file as `SOCKSREQ="$(cat /tmp/t134/pa/socksreq-printf.txt)"`.

### 7.2 Prototype driver `probe-pa.sh`

```sh
#!/usr/bin/env bash
# T134 P-A / P-B — topology prototypes on disposable docker resources. (v10: strict complete-reply assertion + dead-shim discrimination, symmetric lo-scoped rules for DP and relay identities, fail-closed captures)
#
# Candidate A: DP binds host loopback (strict bind path), unix-socket tor fabric,
#              packet-level owner-match egress denial for the DP uid.
# Candidate B: host-loopback TCP relay -> UDS -> network-less DP.
#
# Environment assumptions (reported per ticket acceptance #3):
#   - host-sim is a PRIVILEGED container standing in for the physical host (the probe
#     host has no passwordless sudo); kernel-level evidence is mechanism-level, not a
#     physical-host proof.
#   - tor 0.4.9.12 refuses unix-socket directories not private to its user; the fabric
#     re-exposes the sockets by HARDLINK into a traversable directory (same inode, same
#     filesystem). Production would place this re-exposure in the Stargate-owned image.
#   - The lo:9050 TCP shim inside host-sim stands in for the DP's native unix dial
#     (production change owned by the implementation follow-up).
set -u
FAILS=0
ok()   { echo "PASS: $*"; }
bad()  { echo "FAIL: $*"; FAILS=$((FAILS+1)); }
note() { echo "==== $* ===="; }

NET=t134net; VOL=t134-fabric; VOL2=t134-cpfabric; VOL3=t134-fabric2
HS=t134-hostsim; FI=t134-fakeinet; TOR=t134-toruds; TORP=t134-torperm; DSB=t134-dpstandin; CPS=t134-cpsim
FI_TCP=8080; FI_UDP=5353
# SOCKS request fixture: generated here if absent so the driver is self-contained
# (report section 7.1 preserves this exact generation step).
if [ ! -s /tmp/t134/pa/socksreq-printf.txt ]; then
python3 - <<'PYFIX' > /tmp/t134/pa/socksreq-printf.txt
token = b"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
uname = b"sg1:" + b"a"*64
host = b"a"*56 + b".onion"
req = b"\x05\x01\x02" + bytes([1, len(uname)]) + uname + bytes([len(token)]) + token + b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x00\x50"
print("printf '" + "".join("\\%03o" % b for b in req) + "'", end="")
PYFIX
fi
SOCKSREQ="$(cat /tmp/t134/pa/socksreq-printf.txt)"

cleanup() {
  docker rm -f $HS $FI $TOR $TORP $DSB $CPS >/dev/null 2>&1
  docker network rm $NET >/dev/null 2>&1
  docker volume rm $VOL $VOL2 $VOL3 >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

note "phase 0: disposable resources"
docker network create $NET >/dev/null
docker volume create $VOL >/dev/null
docker volume create $VOL2 >/dev/null
docker volume create $VOL3 >/dev/null
# Per-consumer fabrics (round-2 review F2): the DP fabric volume carries ONLY the
# SOCKS re-exposure; the CP fabric volume carries ONLY the control re-exposure.
# Mount separation enforces the caller matrix at the filesystem level — CP never
# sees the SOCKS socket, DP never sees the control socket. Private dirs are 0700
# tor (tor refuses otherwise); re-exposure dirs are 0750 tor:<consumer-gid> and the
# hardlinked sockets land 0660 tor:<consumer-gid>.
#   VOL  (dp fabric):  /socks (0700 tor)      -> /dp/tor-socks.sock    (gid 5200)
#   VOL2 (cp fabric):  /ctrl (0700 tor)      -> /cp/tor-control.sock  (gid 5201)
#   VOL3 (B stand-in): dpb.sock fabric
docker run --rm -u 0 -v $VOL:/fabric --entrypoint bash stargate/tor:local \
  -c 'mkdir -p /fabric/socks /fabric/dp && chown 5103:5103 /fabric/socks && chmod 0700 /fabric/socks && chown 5103:5200 /fabric/dp && chmod 0750 /fabric/dp && chmod 0777 /fabric' >/dev/null
docker run --rm -u 0 -v $VOL2:/cpfabric --entrypoint bash stargate/tor:local \
  -c 'mkdir -p /cpfabric/ctrl /cpfabric/cp && chown 5103:5103 /cpfabric/ctrl && chmod 0700 /cpfabric/ctrl && chown 5103:5201 /cpfabric/cp && chmod 0750 /cpfabric/cp && chmod 0777 /cpfabric' >/dev/null
docker run --rm -u 0 -v $VOL3:/fabric2 --entrypoint bash stargate/tor:local -c 'chmod 0777 /fabric2' >/dev/null

# fake-internet target (runs as the image's unprivileged tor user; files in /tmp)
docker run -d --name $FI --network $NET --entrypoint bash stargate/tor:local -c "
  printf 'T134-FAKE-INTERNET-TCP\n' > /tmp/tcpbanner
  (while true; do nc -l -p $FI_TCP < /tmp/tcpbanner >/dev/null 2>&1; done) &
  (nc -u -l -p $FI_UDP >/dev/null 2>&1) &
  sleep infinity" >/dev/null
ok "fake-internet target started (TCP $FI_TCP, UDP $FI_UDP on the shared bridge)"

cat > /tmp/t134/pa/torrc-uds <<'EOF'
SocksPort unix:/fabric/socks/tor-socks.sock
ControlSocket /cpfabric/ctrl/tor-control.sock
CookieAuthentication 1
DataDirectory /var/lib/tor
ClientUseIPv6 0
AvoidDiskWrites 1
UseBridges 0
Log notice stdout
SafeLogging 1
EOF

# A.3.0 — tor's NATIVE unix-socket modes (no re-exposure loop): design input.
note "phase A.3.0: native tor unix-socket permissions"
docker run -d --name $TORP --network $NET -v $VOL:/fabric -v $VOL2:/cpfabric -v /tmp/t134/pa/torrc-uds:/etc/tor/torrc-uds:ro \
  --entrypoint tor stargate/tor:local -f /etc/tor/torrc-uds >/dev/null
sleep 5
NATIVE_PERMS=$(docker exec -u 0 $TORP bash -c 'ls -l /fabric/socks/ /cpfabric/ctrl/ 2>/dev/null | grep sock' || echo none)
echo "native socket modes: $NATIVE_PERMS"
docker rm -f $TORP >/dev/null
note "phase A.3.0b: socket-dir mode sweep (preserved from the round-1 interactive probe)"
for MODE in 0700 0750 0770; do
  docker volume rm $VOL >/dev/null 2>&1; docker volume create $VOL >/dev/null
  docker run --rm -u 0 -v $VOL:/fabric --entrypoint bash stargate/tor:local \
    -c "mkdir -p /fabric/socks && chown 5103:5103 /fabric/socks && chmod $MODE /fabric/socks" >/dev/null
  docker run -d --name $TORP --network $NET -v $VOL:/fabric -v $VOL2:/cpfabric \
    -v /tmp/t134/pa/torrc-uds:/etc/tor/torrc-uds:ro \
    --entrypoint tor stargate/tor:local -f /etc/tor/torrc-uds >/dev/null
  sleep 4
  SOCKN=$(docker exec -u 0 $TORP bash -c 'ls /fabric/socks/ 2>/dev/null | grep -c sock' 2>/dev/null || echo 0)
  RUNNING=$(docker inspect $TORP --format '{{.State.Running}}' 2>/dev/null)
  echo "  dir mode $MODE: sockets=$SOCKN running=$RUNNING"
  docker rm -f $TORP >/dev/null
done
docker volume rm $VOL >/dev/null 2>&1; docker volume create $VOL >/dev/null
docker run --rm -u 0 -v $VOL:/fabric --entrypoint bash stargate/tor:local \
  -c 'mkdir -p /fabric/socks /fabric/dp && chown 5103:5103 /fabric/socks && chmod 0700 /fabric/socks && chown 5103:5200 /fabric/dp && chmod 0750 /fabric/dp && chmod 0777 /fabric' >/dev/null
docker run --rm -u 0 -v $VOL:/fabric -v $VOL2:/cpfabric --entrypoint bash stargate/tor:local \
  -c 'rm -f /fabric/socks/* /fabric/dp/* /cpfabric/ctrl/* /cpfabric/cp/* 2>/dev/null; chmod 0700 /fabric/socks /cpfabric/ctrl; true' >/dev/null

# tor + hardlink re-exposure loop (runs as the image's tor user)
docker run -d --name $TOR --network $NET -v $VOL:/fabric -v $VOL2:/cpfabric \
  --group-add 5200 --group-add 5201 \
  -v /tmp/t134/pa/torrc-uds:/etc/tor/torrc-uds:ro \
  --entrypoint bash stargate/tor:local -c '
  tor -f /etc/tor/torrc-uds >/tmp/tor.log 2>&1 & T=$!
  while kill -0 $T 2>/dev/null; do
    if [ -S /fabric/socks/tor-socks.sock ]; then
      ln -f /fabric/socks/tor-socks.sock /fabric/dp/tor-socks.sock 2>/dev/null
      chgrp 5200 /fabric/dp/tor-socks.sock 2>/dev/null
      chmod 0660 /fabric/dp/tor-socks.sock 2>/dev/null
    fi
    if [ -S /cpfabric/ctrl/tor-control.sock ]; then
      ln -f /cpfabric/ctrl/tor-control.sock /cpfabric/cp/tor-control.sock 2>/dev/null
      chgrp 5201 /cpfabric/cp/tor-control.sock 2>/dev/null
      chmod 0660 /cpfabric/cp/tor-control.sock 2>/dev/null
    fi
    sleep 0.2
  done' >/dev/null
ok "tor-uds started (per-consumer fabrics, group-gated 0660 hardlink re-exposure)"

docker run -d --name $HS --privileged --network $NET -v $VOL:/fabric -v $VOL3:/fabric2 -v /tmp/t134:/t134:ro \
  --entrypoint bash stargate/tor:local -c 'sleep infinity' >/dev/null
hs() { docker exec -u 0 $HS bash -c "$*" 2>&1; }

note "phase 0.1: probe tooling inside host-sim (pinned snapshot run, disposable)"
hs 'rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list
    echo "deb http://snapshot.debian.org/archive/debian/20260714T082229Z/ bookworm main" > /etc/apt/sources.list.d/snapshot.list
    apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq --no-install-recommends iptables tcpdump iproute2 socat procps >/dev/null 2>&1' \
  && ok "iptables/tcpdump/iproute2/socat installed" || bad "tooling install"

FI_IP=$(docker inspect $FI --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
HS_IP=$(docker inspect $HS --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
echo "FI_IP=$FI_IP HS_IP=$HS_IP"

note "phase A.0: identities + owner-match egress rules for the DP uid (candidate A mechanism)"
hs 'groupadd -g 5100 sg-ipc; groupadd -g 5200 sg-dpsock 2>/dev/null; useradd -M -u 5102 -g 5100 -G 5200 dp 2>/dev/null; useradd -M -u 6000 probe 2>/dev/null
    for IPT in iptables ip6tables; do
      # scoped shim exception ONLY (prototype stand-in for T162 native AF_UNIX dial);
      # production carries no IP-initiated exception at all
      $IPT -A OUTPUT -m owner --uid-owner 5102 -o lo -p tcp --dport 9050 -j ACCEPT
      # ESTABLISHED,RELATED scoped to lo (round-3 review F1): the DP answers ONLY
      # its loopback clients. An unrestricted ESTABLISHED rule would let a
      # compromised DP answer an externally initiated off-loopback connection.
      # Phase A.11 demonstrates the channel open under the old shape and closed now.
      $IPT -A OUTPUT -m owner --uid-owner 5102 -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
      # silent DROP — no LOG target: per-packet kernel records would violate
      # Constitution III aggregate-only records (round-2 review F1); the DROP
      # DROP-rule counters are the kernel-level cross-check
      $IPT -A OUTPUT -m owner --uid-owner 5102 -j DROP
    done; true' && ok "uid 5102 rules: scoped lo:9050, lo-scoped ESTABLISHED,RELATED, silent DROP (v4+v6)" || bad "rules"

note "phase A.1: cold-start state (disposable pepper + crafted snapshot, known token)"
hs 'mkdir -p /dpwork/keys /dpwork/state /dpwork/ipc
    head -c 32 /dev/urandom > /dpwork/keys/pepper.key; chmod 0600 /dpwork/keys/pepper.key' && ok "state dirs"
docker cp /tmp/t134/dp $HS:/dpwork/dp >/dev/null && ok "DP binary staged"
PEPPER_B64=$(hs 'base64 -w0 /dpwork/keys/pepper.key')
VER_B64=$(python3 -c "import base64,hmac,hashlib; p=base64.b64decode('$PEPPER_B64'); print(base64.b64encode(hmac.new(p,b'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',hashlib.sha256).digest()).decode())")
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '{"schemaVersion":2,"generation":1,"loadedAt":"%s","verifiers":[{"verifier":"%s"}]}' "$NOW" "$VER_B64" > /tmp/t134/pa/dp-snapshot.json
docker cp /tmp/t134/pa/dp-snapshot.json $HS:/dpwork/state/dp-snapshot.json >/dev/null
ok "snapshot staged (generation 1, one verifier, disposable pepper)"

note "phase A.2: DP binds host-sim loopback STRICTLY (STARGATE_IN_CONTAINER=0)"
cat > /tmp/t134/pa/inner-dp.sh <<'EOF'
#!/usr/bin/env bash
chown -R dp:sg-ipc /dpwork
cd /dpwork
setsid setpriv --reuid 5102 --regid 5100 --groups 5200 env \
  STARGATE_LISTEN_ADDR=127.0.0.1:8881 STARGATE_IN_CONTAINER=0 \
  STARGATE_KEYS_DIR=/dpwork/keys STARGATE_STATE_DIR=/dpwork/state STARGATE_IPC_DIR=/dpwork/ipc \
  STARGATE_TOR_SOCKS_ADDR=127.0.0.1:9050 \
  /dpwork/dp > /dpwork/dp.log 2>&1 &
echo $! > /dpwork/dp.pid
EOF
docker exec -u 0 $HS bash /t134/pa/inner-dp.sh; sleep 2
A2=$(hs 'grep -o "listener=[^ ]*" /dpwork/dp.log | head -1; grep -c "snapshot restored" /dpwork/dp.log')
echo "$A2"
echo "$A2" | grep -q "listener=127.0.0.1:8881" && ok "DP listening on 127.0.0.1:8881 via the strict bind path (no exception)" || bad "listener"
echo "$A2" | grep -qx 1 && ok "cold start: snapshot restored (generation 1)" || bad "snapshot restore"

note "phase A.3: lo:9050 -> tor UDS shim (stands in for T162 native unix dial)"
cat > /tmp/t134/pa/inner-shim.sh <<'EOF'
#!/usr/bin/env bash
setsid socat TCP-LISTEN:9050,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/fabric/dp/tor-socks.sock >/dev/null 2>&1 &
echo $! > /dpwork/shim.pid
EOF
docker exec -u 0 $HS bash /t134/pa/inner-shim.sh; sleep 3
FABRIC=$(hs 'ls -li /fabric/dp/tor-socks.sock /fabric/socks/tor-socks.sock 2>&1')
echo "$FABRIC"
echo "$FABRIC" | grep -q "/fabric/dp/tor-socks.sock" && ok "hardlink re-exposure present (same inode as the tor-private socket)" || bad "re-exposure"

note "phase A.3.1: tor unix SOCKS reachable directly over the volume (fabric sanity)"
UDSREPLY=$(hs "printf '\\005\\001\\002' | timeout 3 nc -U -q1 /fabric/dp/tor-socks.sock | od -An -tx1 | tr -d ' \\n'")
echo "tor-uds method reply: $UDSREPLY"
[ "$UDSREPLY" = "0502" ] && ok "tor accepts SOCKS5 over the unix socket (05 02)" || bad "tor UDS ($UDSREPLY)"

note "phase A.4: browser-style SOCKS5 through DP -> shim -> tor UDS (probe uid, loopback)"
cat > /tmp/t134/pa/inner-a4.sh <<EOF
#!/usr/bin/env bash
setpriv --reuid 6000 --clear-groups bash -c "{ $SOCKSREQ; sleep 6; } | timeout 12 nc -q1 127.0.0.1 8881 | od -An -tx1 | tr -d ' \n'"
echo
EOF
# the full 14-byte reply must be present and upstream-derived: the DP synthesizes
# ROUTE_REFUSED (05 04) from tor's own SOCKS failure for the synthetic onion
# (forward/tor.go classify; listener/socks5.go reply). Auth-only (truncated) and
# ROUTE_TIMEOUT (05 06) results FAIL — an accepting-but-dead shim cannot pass.
A4=$(docker exec -u 0 $HS bash /t134/pa/inner-a4.sh)
echo "e2e reply: $A4"
[[ "$A4" == 05020100* ]] && ok "DP method+RFC1929 auth accepted through loopback (05 02 01 00)" || bad "method/auth ($A4)"
[ "$A4" = "0502010005040001000000000000" ] && ok "COMPLETE upstream-derived reply (05 04 ROUTE_REFUSED synthesized from tor's SOCKS failure): bytes demonstrably flowed DP->shim->UDS->tor" || bad "upstream reply incomplete/timeout/dead-shim ($A4)"

note "phase A.4f: dead-shim falsifier — an accepting-but-silent shim must FAIL the fabric assertion"
hs 'pkill -f "TCP-LIS[T]EN:9050" 2>/dev/null; sleep 1
     setsid socat TCP-LISTEN:9050,bind=127.0.0.1,fork,reuseaddr EXEC:/bin/true >/dev/null 2>&1 & echo $! > /dpwork/shim.pid
     sleep 1; true' >/dev/null
A4F=$(docker exec -u 0 $HS bash /t134/pa/inner-a4.sh)
echo "dead-shim reply: $A4F"
[ "$A4F" != "0502010005040001000000000000" ] && ok "DISCRIMINATION: accepting-but-silent shim FAILS the complete-reply assertion (would previously pass as auth-only)" || bad "dead shim passed the fabric assertion ($A4F)"
hs 'kill $(cat /dpwork/shim.pid) 2>/dev/null; pkill -f "TCP-LIS[T]EN:9050" 2>/dev/null; true' >/dev/null
docker exec -u 0 $HS bash /t134/pa/inner-shim.sh; sleep 1
A4R=$(docker exec -u 0 $HS bash /t134/pa/inner-a4.sh)
[ "$A4R" = "0502010005040001000000000000" ] && ok "real shim restored: complete reply returns" || bad "restored shim incomplete ($A4R)"

note "phase A.5: differential — shim stopped must yield immediate ROUTE_DOWN (05 03)"
hs 'kill $(cat /dpwork/shim.pid) 2>/dev/null; pkill -f "TCP-LIS[T]EN:9050" 2>/dev/null; sleep 1; true'
A5=$(docker exec -u 0 $HS bash /t134/pa/inner-a4.sh)
echo "shim-stopped reply: $A5"
[[ "$A5" == 050201000503* || "$A5" == 050201000506* ]] && ok "differential: 05 03/06 when fabric down — A.4 bytes demonstrably flowed via the fabric" || bad "differential ($A5)"
docker exec -u 0 $HS bash /t134/pa/inner-shim.sh; sleep 1

note "phase A.6: non-loopback refusal — the lo-bound listener is unreachable off lo"
hs "nc -z -w2 $HS_IP 8881" >/dev/null 2>&1 && bad "reachable on eth0 $HS_IP:8881" || ok "host-sim eth0 $HS_IP:8881: refused"
docker exec $FI sh -c "nc -z -w2 $HS_IP 8881" >/dev/null 2>&1 && bad "reachable cross-container" || ok "from fake-internet container: refused"

note "phase A.7: packet-level egress isolation with positive capture controls"
cat > /tmp/t134/pa/inner-a7.sh <<EOF
#!/usr/bin/env bash
# \$1 = uid, \$2 = phase label
tcpdump -i eth0 -w /tmp/\$2.pcap -c 400 \(host $FI_IP or host 192.0.2.10\) and \(tcp or udp\) >/dev/null 2>&1 &
TPID=\$!
sleep 1
# fail-closed capture lifecycle (round-3 review F3): a recorder that failed to
# start, died, or produced an undecodable file invalidates the phase — a missing
# pcap must never read as "zero packets".
if ! kill -0 \$TPID 2>/dev/null; then echo "  capture: FAILED-TO-START"; exit 9; fi
echo "-- attempts as uid \$1:"
setpriv --reuid \$1 --clear-groups bash -c "
  timeout 3 nc -z -w2 $FI_IP $FI_TCP && echo '  tcp->FI: connected' || echo '  tcp->FI: failed'
  timeout 3 bash -c 'echo x > /dev/udp/$FI_IP/$FI_UDP' && echo '  udp->FI: send returned' || echo '  udp->FI: send denied'
  timeout 3 bash -c 'echo x > /dev/udp/192.0.2.10/53' && echo '  dns53->doc-addr: send returned' || echo '  dns53->doc-addr: send denied'
  timeout 3 nc -z -w2 192.0.2.10 80 && echo '  tcp->doc-addr: connected' || echo '  tcp->doc-addr: failed'"
sleep 1
kill -INT \$TPID 2>/dev/null
wait \$TPID 2>/dev/null; TRC=\$?
if [ "\$TRC" != "0" ]; then echo "  capture: FAILED (tcpdump exit \$TRC)"; exit 9; fi
if ! tcpdump -r /tmp/\$2.pcap >/dev/null 2>&1; then echo "  capture: FAILED (undecodable pcap)"; exit 9; fi
echo "  capture: ok"
echo "  capture packets: \$(tcpdump -r /tmp/\$2.pcap 2>/dev/null | grep -c .)"
echo "  per-class -> tcp: \$(tcpdump -r /tmp/\$2.pcap tcp 2>/dev/null | grep -c .)  udp-to-FI: \$(tcpdump -r /tmp/\$2.pcap udp and host $FI_IP 2>/dev/null | grep -c .)  udp53-to-doc: \$(tcpdump -r /tmp/\$2.pcap udp and host 192.0.2.10 2>/dev/null | grep -c .)"
echo "  iptables DROP pkts for uid \$1: \$(iptables -L OUTPUT -v -n | awk -v u=\$1 '\$1 ~ /^[0-9]+\$/ && /DROP/ && index(\$0, u) {s+=\$1} END {print s+0}')"
EOF
NEG=$(docker exec -u 0 $HS bash /t134/pa/inner-a7.sh 5102 neg); NEGRCE=$?
echo "$NEG"
if [ $NEGRCE -ne 0 ] || ! echo "$NEG" | grep -q 'capture: ok'; then bad "A.7 negative capture lifecycle failed (fail-closed)"; else ok "A.7 negative capture lifecycle: started, clean exit, decodable pcap"; fi
NEGCNT=$(echo "$NEG" | grep 'capture packets:' | grep -o '[0-9]*')
NEGDROP=$(echo "$NEG" | grep 'DROP pkts' | grep -o '[0-9]*' | tail -1)
[ "${NEGCNT:-1}" = "0" ] && ok "NEGATIVE: ZERO packets to FI/doc-address emitted by DP uid (capture-verified)" || bad "DP-uid packets escaped ($NEGCNT)"
NEGTCP_N=$(echo "$NEG" | grep -o 'per-class -> tcp: [0-9]*' | grep -o '[0-9]*$')
NEGUDP_N=$(echo "$NEG" | grep -o 'udp-to-FI: [0-9]*' | grep -o '[0-9]*$')
NEG53_N=$(echo "$NEG" | grep -o 'udp53-to-doc: [0-9]*' | grep -o '[0-9]*$')
[ "${NEGTCP_N:-1}" = "0" ] && [ "${NEGUDP_N:-1}" = "0" ] && [ "${NEG53_N:-1}" = "0" ] \
  && ok "NEGATIVE per class: zero TCP, zero UDP-to-FI, zero UDP/53-shaped packets from the DP uid" \
  || bad "per-class negative (tcp=$NEGTCP_N udp=$NEGUDP_N udp53=$NEG53_N)"
[ "${NEGDROP:-0}" -ge 3 ] && ok "kernel owner-match DROP counters confirm the attempts were filtered ($NEGDROP pkts)" || bad "drop counters ($NEGDROP)"
echo "$NEG" | grep -q 'tcp->FI: failed' && ok "DP-uid TCP connect did not succeed" || bad "DP-uid TCP connect succeeded"
POS=$(docker exec -u 0 $HS bash /t134/pa/inner-a7.sh 6000 pos); POSRCE=$?
echo "$POS"
if [ $POSRCE -ne 0 ] || ! echo "$POS" | grep -q 'capture: ok'; then bad "A.7 positive capture lifecycle failed (fail-closed)"; else ok "A.7 positive capture lifecycle: ok"; fi
POSCNT=$(echo "$POS" | grep 'capture packets:' | grep -o '[0-9]*')
POSTCP_N=$(echo "$POS" | grep -o 'per-class -> tcp: [0-9]*' | grep -o '[0-9]*$')
POSUDP_N=$(echo "$POS" | grep -o 'udp-to-FI: [0-9]*' | grep -o '[0-9]*$')
POS53_N=$(echo "$POS" | grep -o 'udp53-to-doc: [0-9]*' | grep -o '[0-9]*$')
POSTCP=$(echo "$POS" | grep -q 'tcp->FI: connected' && echo yes || echo no)
[ "${POSTCP_N:-0}" -ge 1 ] && [ "${POSUDP_N:-0}" -ge 1 ] && [ "${POS53_N:-0}" -ge 1 ] \
  && ok "POSITIVE CONTROL per class: TCP ($POSTCP_N), UDP-to-FI ($POSUDP_N) and UDP/53-shaped ($POS53_N) packets EACH visible on eth0 — capture validity proven per protocol" \
  || bad "per-class positive control (tcp=$POSTCP_N udp=$POSUDP_N udp53=$POS53_N)"
[ "$POSTCP" = "yes" ] && ok "positive control TCP connect succeeded (egress path open for unrestricted uid)" || note "positive-control TCP did not connect; packet visibility is the control that matters"

note "phase A.8: cold-start under the topology — restart DP (no CP anywhere in the prototype)"
hs 'kill $(cat /dpwork/dp.pid) 2>/dev/null; pkill -f "/dpwork/d[p]" 2>/dev/null; sleep 1; true'
docker exec -u 0 $HS bash /t134/pa/inner-dp.sh
sleep 2
A8=$(hs 'grep -o "listener=[^ ]*" /dpwork/dp.log | tail -1')
echo "$A8"
echo "$A8" | grep -q "listener=127.0.0.1:8881" && ok "DP restart: listener back, auth state from disk (Principle II cold start preserved)" || bad "restart"

note "phase A.9: loopback-forwarder egress mediation (F1) — DP uid must not reach an unrestricted lo forwarder"
cat > /tmp/t134/pa/inner-a9fwd.sh <<'EOF'
#!/usr/bin/env bash
setsid socat TCP-LISTEN:15353,bind=127.0.0.1,fork,reuseaddr TCP:__FI_IP__:__FI_TCP__ >/dev/null 2>&1 &
echo $! > /dpwork/fwdtcp.pid
setsid socat UDP4-LISTEN:15354,bind=127.0.0.1,fork UDP4:__FI_IP__:__FI_UDP__ >/dev/null 2>&1 &
echo $! > /dpwork/fwdudp.pid
EOF
cat > /tmp/t134/pa/inner-a9.tpl <<'EOF'
#!/usr/bin/env bash
# $1 = uid, $2 = phase label
tcpdump -i eth0 -w /tmp/a9-$2.pcap -c 400 host __FI_IP__ and \(tcp or udp\) >/dev/null 2>&1 &
TPID=$!
sleep 1
if ! kill -0 $TPID 2>/dev/null; then echo "  capture: FAILED-TO-START"; exit 9; fi
echo "-- forwarder use attempts as uid $1:"
setpriv --reuid $1 --clear-groups bash -c '
  BANNER=$(timeout 3 nc -w2 127.0.0.1 15353 </dev/null | head -c 24)
  if [ -n "$BANNER" ]; then echo "  tcp-via-forwarder: RECEIVED banner"; else echo "  tcp-via-forwarder: no data"; fi
  if timeout 3 bash -c "echo x > /dev/udp/127.0.0.1/15354" 2>/dev/null; then echo "  udp-via-forwarder: send returned"; else echo "  udp-via-forwarder: send denied"; fi
  if timeout 3 bash -c "echo x > /dev/udp/127.0.0.53/53" 2>/dev/null; then echo "  host-resolver-style udp/53: send returned"; else echo "  host-resolver-style udp/53: send denied"; fi'
sleep 1
kill -INT $TPID 2>/dev/null
wait $TPID 2>/dev/null; TRC=$?
if [ "$TRC" != "0" ]; then echo "  capture: FAILED (tcpdump exit $TRC)"; exit 9; fi
if ! tcpdump -r /tmp/a9-$2.pcap >/dev/null 2>&1; then echo "  capture: FAILED (undecodable pcap)"; exit 9; fi
echo "  capture: ok"
echo "  eth0 packets to FI (tcp): $(tcpdump -r /tmp/a9-$2.pcap tcp 2>/dev/null | grep -c .)"
echo "  eth0 packets to FI (udp): $(tcpdump -r /tmp/a9-$2.pcap udp 2>/dev/null | grep -c .)"
EOF
sed -e "s/__FI_IP__/$FI_IP/g" -e "s/__FI_TCP__/$FI_TCP/g" -e "s/__FI_UDP__/$FI_UDP/g" /tmp/t134/pa/inner-a9fwd.sh > /tmp/t134/pa/inner-a9fwd-run.sh
sed "s/__FI_IP__/$FI_IP/g" /tmp/t134/pa/inner-a9.tpl > /tmp/t134/pa/inner-a9.sh
docker exec -u 0 $HS bash /t134/pa/inner-a9fwd-run.sh; sleep 1
NEG9=$(docker exec -u 0 $HS bash /t134/pa/inner-a9.sh 5102 neg9); N9RCE=$?
echo "$NEG9"
if [ $N9RCE -ne 0 ] || ! echo "$NEG9" | grep -q 'capture: ok'; then bad "A.9 negative capture lifecycle failed (fail-closed)"; else ok "A.9 negative capture lifecycle: ok"; fi
NEG9C=$(echo "$NEG9" | grep -o 'tcp): [0-9]*' | grep -o '[0-9]*$')
NEG9U=$(echo "$NEG9" | grep -o 'udp): [0-9]*' | grep -o '[0-9]*$')
echo "$NEG9" | grep -q 'tcp-via-forwarder: no data' && ok "DP-uid TCP via lo forwarder: no data returned (NEW flow to lo dropped)" || bad "DP-uid used lo forwarder (TCP)"
echo "$NEG9" | grep -q 'udp-via-forwarder: send denied' && ok "DP-uid UDP via lo forwarder: denied" || bad "DP-uid UDP via lo forwarder"
echo "$NEG9" | grep -q 'host-resolver-style udp/53: send denied' && ok "DP-uid host-resolver-style UDP/53 to loopback: denied" || bad "DP-uid resolver-style path"
[ "${NEG9C:-1}" = "0" ] && [ "${NEG9U:-1}" = "0" ] && ok "NEGATIVE: ZERO forwarded packets to FI attributable to DP-uid attempts (TCP and UDP classes both empty)" || bad "DP-uid reached FI via forwarder (tcp=$NEG9C udp=$NEG9U)"
POS9=$(docker exec -u 0 $HS bash /t134/pa/inner-a9.sh 6000 pos9); P9RCE=$?
echo "$POS9"
if [ $P9RCE -ne 0 ] || ! echo "$POS9" | grep -q 'capture: ok'; then bad "A.9 positive capture lifecycle failed (fail-closed)"; else ok "A.9 positive capture lifecycle: ok"; fi
POS9C=$(echo "$POS9" | grep -o 'tcp): [0-9]*' | grep -o '[0-9]*$')
POS9U=$(echo "$POS9" | grep -o 'udp): [0-9]*' | grep -o '[0-9]*$')
POS9T=$(echo "$POS9" | grep -q 'tcp-via-forwarder: RECEIVED banner' && echo yes || echo no)
[ "$POS9T" = "yes" ] && ok "POSITIVE CONTROL: unrestricted uid RECEIVED the FI banner through the lo forwarder" || bad "forwarder fixture broken (positive control)"
[ "${POS9C:-0}" -ge 1 ] && [ "${POS9U:-0}" -ge 1 ] && ok "POSITIVE CONTROL: forwarder-mediated TCP ($POS9C) AND UDP ($POS9U) packets to FI each VISIBLE on eth0" || bad "forwarder positive capture (tcp=$POS9C udp=$POS9U)"

note "phase A.10: socket caller matrix — mount separation enforces DP->SOCKS, CP->control, and the denials"
docker run -d --name $CPS --network none -v $VOL2:/cpfabric --entrypoint bash stargate/tor:local -c 'sleep infinity' >/dev/null
hs '[ -e /cpfabric ] && echo present || echo absent' > /tmp/t134/pa/a10hs.out
grep -q absent /tmp/t134/pa/a10hs.out && ok "host-sim (DP side) has NO cp-fabric mount — control socket unreachable by construction" || bad "cp fabric visible to DP side"
docker exec -u 0 $CPS bash -c 'groupadd -g 5201 sg-cpobs 2>/dev/null; useradd -M -u 5101 -G 5201 cp 2>/dev/null; ls /fabric 2>&1 | head -1' > /tmp/t134/pa/a10cp.out
grep -qi "No such file" /tmp/t134/pa/a10cp.out && ok "cp-sim has NO dp-fabric mount — SOCKS socket unreachable by construction" || bad "dp fabric visible to CP side"
sleep 3
CPCTL=$(docker exec -u 0 $CPS bash -c "setpriv --reuid 5101 --groups 5201 bash -c \"printf 'PROTOCOLINFO 1\\r\\n' | timeout 3 nc -U -q1 /cpfabric/cp/tor-control.sock | head -c 40\"" 2>&1)
echo "cp->control PROTOCOLINFO reply: $CPCTL"
echo "$CPCTL" | grep -q "250" && ok "CP identity CAN reach the control socket — TRANSPORT/mount evidence only; the sanitized observer boundary is T138 design, not implemented here" || bad "cp->control ($CPCTL)"
DPSOCK=$(hs "setpriv --reuid 5102 --groups 5200 bash -c \"printf '\\005\\001\\002' | timeout 3 nc -U -q1 /fabric/dp/tor-socks.sock | od -An -tx1 | tr -d ' \\n'\"" 2>&1)
echo "dp->socks method reply: $DPSOCK"
[ "$DPSOCK" = "0502" ] && ok "DP identity CAN reach the SOCKS socket (positive)" || bad "dp->socks ($DPSOCK)"
CPSOCK=$(hs "setpriv --reuid 6000 bash -c \"nc -U -w1 /fabric/dp/tor-socks.sock 2>&1; true\"" 2>&1)
echo "probe-uid (no fabric group) -> socks: $CPSOCK"
echo "$CPSOCK" | grep -q "Permission denied" && ok "identity WITHOUT the fabric group gets EACCES on the SOCKS socket (permission-gated; nc exits 0 regardless)" || bad "ungated socket access ($CPSOCK)"

note "phase A.11: reverse-initiated off-loopback channel (round-3 review F1)"
cat > /tmp/t134/pa/inner-a11srv.sh <<'A11EOF'
#!/usr/bin/env bash
# echo-server under the DP identity, bound off-loopback (0.0.0.0 high port)
pkill -f "TCP-LISTEN:19191" 2>/dev/null
setsid setpriv --reuid 5102 --regid 5100 --groups 5200 socat TCP-LISTEN:19191,fork,reuseaddr EXEC:cat >/dev/null 2>&1 &
echo $! > /dpwork/a11srv.pid
sleep 1
ss -tln | grep 19191 >/dev/null && echo "echo-server up (uid 5102, 0.0.0.0:19191)"
A11EOF
# install the ROUND-2 rule shape (unrestricted ESTABLISHED,RELATED for uid 5102)
# to demonstrate the channel it left open, before reinstalling the lo-scoped shape
hs 'for IPT in iptables ip6tables; do $IPT -F OUTPUT; $IPT -A OUTPUT -m owner --uid-owner 5102 -o lo -p tcp --dport 9050 -j ACCEPT; $IPT -A OUTPUT -m owner --uid-owner 5102 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; $IPT -A OUTPUT -m owner --uid-owner 5102 -j DROP; $IPT -A OUTPUT -m owner --uid-owner 5104 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; $IPT -A OUTPUT -m owner --uid-owner 5104 -j DROP; done; true' >/dev/null
docker exec -u 0 $HS bash /t134/pa/inner-a11srv.sh
REPLY_OLD=$(docker exec $FI sh -c "printf 'T134-MARKER' | timeout 4 nc -w3 $HS_IP 19191" 2>&1 || true)
echo "old-rule (unrestricted ESTABLISHED) FI-side reply: '${REPLY_OLD}'"
[ "$REPLY_OLD" = "T134-MARKER" ] && ok "FALSIFIER: under the round-2 rule shape the reverse-initiated off-loopback channel CARRIES DATA (marker echoed)" || bad "old-rule reverse channel did not echo (falsifier not demonstrated)"
hs 'for IPT in iptables ip6tables; do $IPT -F OUTPUT; $IPT -A OUTPUT -m owner --uid-owner 5102 -o lo -p tcp --dport 9050 -j ACCEPT; $IPT -A OUTPUT -m owner --uid-owner 5102 -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; $IPT -A OUTPUT -m owner --uid-owner 5102 -j DROP; $IPT -A OUTPUT -m owner --uid-owner 5104 -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; $IPT -A OUTPUT -m owner --uid-owner 5104 -j DROP; done; true' >/dev/null
REPLY_NEW=$(docker exec $FI sh -c "printf 'T134-MARKER' | timeout 6 nc -w4 $HS_IP 19191" 2>&1 || true)
echo "lo-scoped-rule FI-side reply: '${REPLY_NEW}'"
[ -z "$REPLY_NEW" ] && ok "lo-scoped ESTABLISHED: reverse-initiated off-loopback channel DEAD (no marker; SYN-ACK dropped at OUTPUT)" || bad "reverse channel still open under lo-scoped rules ($REPLY_NEW)"
A4B=$(docker exec -u 0 $HS bash /t134/pa/inner-a4.sh)
[ "$A4B" = "0502010005040001000000000000" ] && ok "loopback SOCKS5 admission still works under the lo-scoped rules (no availability regression)" || bad "loopback admission broke ($A4B)"
cat > /tmp/t134/pa/inner-a11relay.sh <<'A11R'
#!/usr/bin/env bash
pkill -f "TCP-LISTEN:19192" 2>/dev/null
setsid setpriv --reuid 5104 --clear-groups socat TCP-LISTEN:19192,fork,reuseaddr EXEC:cat >/dev/null 2>&1 &
sleep 1
ss -tln | grep 19192 >/dev/null && echo "relay-uid echo-server up (0.0.0.0:19192)"
A11R
# relay falsifier leg: temporarily unrestricted ESTABLISHED for uid 5104
hs 'for IPT in iptables ip6tables; do $IPT -D OUTPUT -m owner --uid-owner 5104 -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; $IPT -I OUTPUT -m owner --uid-owner 5104 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; done; true' >/dev/null
docker exec -u 0 $HS bash /t134/pa/inner-a11relay.sh
RELAY_OLD=$(docker exec $FI sh -c "printf 'T134-RMARK' | timeout 4 nc -w3 $HS_IP 19192" 2>&1 || true)
echo "relay old-rule reply: '$RELAY_OLD'"
[ "$RELAY_OLD" = "T134-RMARK" ] && ok "FALSIFIER (relay): unrestricted ESTABLISHED lets the relay identity exchange data on a reverse-initiated off-loopback channel" || bad "relay old-rule falsifier not demonstrated ($RELAY_OLD)"
# relay closure leg: back to the shipped lo-scoped shape
hs 'for IPT in iptables ip6tables; do $IPT -D OUTPUT -m owner --uid-owner 5104 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; $IPT -I OUTPUT 1 -m owner --uid-owner 5104 -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; done; true' >/dev/null
RELAY_NEW=$(docker exec $FI sh -c "printf 'T134-RMARK' | timeout 6 nc -w4 $HS_IP 19192" 2>&1 || true)
echo "relay lo-scoped reply: '$RELAY_NEW'"
[ -z "$RELAY_NEW" ] && ok "relay identity: reverse-initiated off-loopback channel DEAD under lo-scoped rules" || bad "relay reverse channel open ($RELAY_NEW)"
hs 'pkill -f "TCP-LISTEN:19192" 2>/dev/null; true' >/dev/null

note "phase A.12: abstract-socket forwarder channel (round-5 review F1) — the shared-netns gap"
# An abstract-namespace unix socket belongs to the NETWORK namespace, not the
# filesystem: mount separation cannot gate it and netfilter never sees AF_UNIX.
# Demonstrate the channel OPEN for the DP uid under the current policy (the gap),
# with an unrestricted-uid positive control. The enforced denial (AppArmor unix
# mediation loaded by the installer) requires host securityfs access the
# privileged-container stand-in does not have — it is specified for T162 with a
# mandatory discriminating regression, not claimed here.
cat > /tmp/t134/pa/inner-a12fwd.sh <<'A12F'
#!/usr/bin/env bash
setsid socat ABSTRACT-LISTEN:t134absfwd,fork,reuseaddr TCP:__FI_IP__:__FI_TCP__ >/dev/null 2>&1 &
echo $! > /dpwork/absfwd.pid
A12F
sed -e "s/__FI_IP__/$FI_IP/g" -e "s/__FI_TCP__/$FI_TCP/g" /tmp/t134/pa/inner-a12fwd.sh > /tmp/t134/pa/inner-a12fwd-run.sh
docker exec -u 0 $HS bash /t134/pa/inner-a12fwd-run.sh; sleep 1
ABS_PROBE=$(hs "setpriv --reuid 6000 --clear-groups bash -c \"timeout 3 nc -U -q1 @t134absfwd </dev/null | head -c 24\"" 2>&1)
echo "unrestricted uid via abstract forwarder: '$ABS_PROBE'"
[ -n "$ABS_PROBE" ] && ok "POSITIVE CONTROL: abstract-UDS forwarder mediates to FI for an unrestricted uid" || bad "abstract forwarder fixture broken"
ABS_DP=$(hs "setpriv --reuid 5102 --regid 5100 --groups 5200 bash -c \"timeout 3 nc -U -q1 @t134absfwd </dev/null | head -c 24\"" 2>&1)
echo "DP uid via abstract forwarder: '$ABS_DP'"
[ -n "$ABS_DP" ] && echo "GAP-DEMONSTRATED: the DP uid CAN mediate egress through a host abstract-socket forwarder under the current policy (no per-uid gate exists for AF_UNIX; this is the unresolved shared-netns channel T162 must close via AppArmor unix mediation or equivalent)" || bad "DP uid could not use the abstract forwarder (gap narrower than expected)"
hs 'kill $(cat /dpwork/absfwd.pid) 2>/dev/null; true' >/dev/null

note "phase B: candidate B fabric — lo TCP relay -> UDS -> network-less DP stand-in"
docker run --rm -u 0 -v $VOL3:/fabric2 --entrypoint bash stargate/tor:local -c 'chmod 0777 /fabric2' >/dev/null
docker run -d --name $DSB --network none -v $VOL3:/fabric2 --entrypoint bash stargate/tor:local -c '
  printf "\005\002" > /tmp/reply
  while true; do
    nc -lU /fabric2/dpb.sock < /tmp/reply >/dev/null 2>&1 &
    N=$!; sleep 0.3; chmod 0666 /fabric2/dpb.sock 2>/dev/null
    wait $N
  done' >/dev/null
ok "DP stand-in running with network_mode:none, serving UDS"
IFACES=$(docker exec $DSB sh -c "cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d ' ' | tr '\n' ' '")
echo "stand-in interfaces: ${IFACES}"
[ "$(echo "$IFACES" | wc -w)" -le 1 ] && ok "structural isolation: stand-in netns has ONLY lo — no IP egress surface exists" || bad "stand-in interfaces ($IFACES)"
cat > /tmp/t134/pa/inner-relay.sh <<'EOF'
#!/usr/bin/env bash
useradd -M -u 5104 relay 2>/dev/null
for IPT in iptables ip6tables; do
  $IPT -A OUTPUT -m owner --uid-owner 5104 -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $IPT -A OUTPUT -m owner --uid-owner 5104 -j DROP
done
setsid setpriv --reuid 5104 socat TCP-LISTEN:8882,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/fabric2/dpb.sock >/dev/null 2>&1 &
echo $! > /dpwork/relay.pid
EOF
docker exec -u 0 $HS bash /t134/pa/inner-relay.sh; sleep 2
hs 'ss -tln | grep 8882' >/dev/null 2>&1 && ok "relay up on 127.0.0.1:8882 as uid 5104 (loopback-scoped ESTABLISHED,RELATED + silent DROP only)" || bad "relay up"
cat > /tmp/t134/pa/inner-b1.sh <<'EOF'
#!/usr/bin/env bash
for i in 1 2 3 4 5 6 7 8; do
  R=$(setpriv --reuid 6000 --clear-groups bash -c "printf '\005\001\002' | timeout 2 nc -q1 127.0.0.1 8882" | od -An -tx1 | tr -d ' \n')
  [ "$R" = "0502" ] && { echo "0502 (attempt $i)"; exit 0; }
  sleep 1
done
echo "no-reply"
EOF
B1=$(docker exec -u 0 $HS bash /t134/pa/inner-b1.sh)
echo "relay-path reply: $B1"
[ "$B1" != "no-reply" ] && ok "candidate B fabric: TCP lo -> relay -> UDS -> netns-less stand-in replied 05 02" || bad "B fabric"
RELAYEG=$(hs "setpriv --reuid 5104 --clear-groups timeout 3 nc -z -w2 $FI_IP $FI_TCP" >/dev/null 2>&1; echo rc=$?)
[ "$RELAYEG" = "rc=1" ] && ok "relay uid non-lo TCP denied (same packet-level treatment as the DP uid)" || bad "relay egress ($RELAYEG)"

note "phase B.2: relay-identity packet isolation with capture controls (review: no 'proven equal' without evidence)"
RNEG=$(docker exec -u 0 $HS bash /t134/pa/inner-a7.sh 5104 rneg); RNEGRCE=$?
echo "$RNEG"
if [ $RNEGRCE -ne 0 ] || ! echo "$RNEG" | grep -q 'capture: ok'; then bad "B.2 relay capture lifecycle failed (fail-closed)"; else ok "B.2 relay capture lifecycle: ok"; fi
RNEGC=$(echo "$RNEG" | grep 'capture packets:' | grep -o '[0-9]*')
RNEGD=$(echo "$RNEG" | grep 'DROP pkts' | grep -o '[0-9]*' | tail -1)
[ "${RNEGC:-1}" = "0" ] && ok "NEGATIVE: ZERO packets to FI/doc-address emitted by the relay uid (capture-verified)" || bad "relay-uid packets escaped ($RNEGC)"
[ "${RNEGD:-0}" -ge 3 ] && ok "kernel DROP counters confirm the relay-uid attempts were filtered ($RNEGD pkts)" || bad "relay drop counters ($RNEGD)"
RPOS=$(docker exec -u 0 $HS bash /t134/pa/inner-a7.sh 6000 rpos); RPOSRCE=$?
if [ $RPOSRCE -ne 0 ] || ! echo "$RPOS" | grep -q 'capture: ok'; then bad "B.2 positive capture lifecycle failed (fail-closed)"; else ok "B.2 positive capture lifecycle: ok"; fi
RPOSC=$(echo "$RPOS" | grep 'capture packets:' | grep -o '[0-9]*')
RPTCP_N=$(echo "$RPOS" | grep -o 'per-class -> tcp: [0-9]*' | grep -o '[0-9]*$')
RPUDP_N=$(echo "$RPOS" | grep -o 'udp-to-FI: [0-9]*' | grep -o '[0-9]*$')
RP53_N=$(echo "$RPOS" | grep -o 'udp53-to-doc: [0-9]*' | grep -o '[0-9]*$')
[ "${RPTCP_N:-0}" -ge 1 ] && [ "${RPUDP_N:-0}" -ge 1 ] && [ "${RP53_N:-0}" -ge 1 ] \
  && ok "POSITIVE CONTROL (relay phase) per class: TCP ($RPTCP_N), UDP ($RPUDP_N), UDP/53 ($RP53_N) each visible — capture valid" \
  || bad "relay per-class positive (tcp=$RPTCP_N udp=$RPUDP_N udp53=$RP53_N)"
hs "nc -z -w2 $HS_IP 8882" >/dev/null 2>&1 && bad "relay reachable on eth0 $HS_IP:8882" || ok "relay non-loopback ingress refused (host-sim eth0 $HS_IP:8882)"

echo "================ T134 prototype summary: FAILS=$FAILS ================"
exit $FAILS
```

### 7.3 Full transcript

```text
==== phase 0: disposable resources ====
PASS: fake-internet target started (TCP 8080, UDP 5353 on the shared bridge)
==== phase A.3.0: native tor unix-socket permissions ====
native socket modes: srw------- 1 tor tor 0 Sep 13 22:31 tor-control.sock
/fabric/socks/:
srw------- 1 tor tor 0 Sep 13 22:31 tor-socks.sock
==== phase A.3.0b: socket-dir mode sweep (preserved from the round-1 interactive probe) ====
  dir mode 0700: sockets=1 running=true
  dir mode 0750: sockets=0 running=false
  dir mode 0770: sockets=0 running=false
PASS: tor-uds started (per-consumer fabrics, group-gated 0660 hardlink re-exposure)
==== phase 0.1: probe tooling inside host-sim (pinned snapshot run, disposable) ====
PASS: iptables/tcpdump/iproute2/socat installed
FI_IP=172.21.0.2 HS_IP=172.21.0.4
==== phase A.0: identities + owner-match egress rules for the DP uid (candidate A mechanism) ====
PASS: uid 5102 rules: scoped lo:9050, lo-scoped ESTABLISHED,RELATED, silent DROP (v4+v6)
==== phase A.1: cold-start state (disposable pepper + crafted snapshot, known token) ====
PASS: state dirs
PASS: DP binary staged
PASS: snapshot staged (generation 1, one verifier, disposable pepper)
==== phase A.2: DP binds host-sim loopback STRICTLY (STARGATE_IN_CONTAINER=0) ====
listener=127.0.0.1:8881
1
PASS: DP listening on 127.0.0.1:8881 via the strict bind path (no exception)
PASS: cold start: snapshot restored (generation 1)
==== phase A.3: lo:9050 -> tor UDS shim (stands in for T162 native unix dial) ====
10246693 srw-rw---- 2 tor sg-dpsock 0 Sep 13 22:31 /fabric/dp/tor-socks.sock
10246693 srw-rw---- 2 tor sg-dpsock 0 Sep 13 22:31 /fabric/socks/tor-socks.sock
PASS: hardlink re-exposure present (same inode as the tor-private socket)
==== phase A.3.1: tor unix SOCKS reachable directly over the volume (fabric sanity) ====
tor-uds method reply: 0502
PASS: tor accepts SOCKS5 over the unix socket (05 02)
==== phase A.4: browser-style SOCKS5 through DP -> shim -> tor UDS (probe uid, loopback) ====
e2e reply: 0502010005040001000000000000
PASS: DP method+RFC1929 auth accepted through loopback (05 02 01 00)
PASS: COMPLETE upstream-derived reply (05 04 ROUTE_REFUSED synthesized from tor's SOCKS failure): bytes demonstrably flowed DP->shim->UDS->tor
==== phase A.4f: dead-shim falsifier — an accepting-but-silent shim must FAIL the fabric assertion ====
dead-shim reply: 0502010005030001000000000000
PASS: DISCRIMINATION: accepting-but-silent shim FAILS the complete-reply assertion (would previously pass as auth-only)
PASS: real shim restored: complete reply returns
==== phase A.5: differential — shim stopped must yield immediate ROUTE_DOWN (05 03) ====
shim-stopped reply: 0502010005030001000000000000
PASS: differential: 05 03/06 when fabric down — A.4 bytes demonstrably flowed via the fabric
==== phase A.6: non-loopback refusal — the lo-bound listener is unreachable off lo ====
PASS: host-sim eth0 172.21.0.4:8881: refused
PASS: from fake-internet container: refused
==== phase A.7: packet-level egress isolation with positive capture controls ====
bash: line 1: echo: write error: Operation not permitted
bash: line 1: echo: write error: Operation not permitted
-- attempts as uid 5102:
  tcp->FI: failed
  udp->FI: send denied
  dns53->doc-addr: send denied
  tcp->doc-addr: failed
  capture: ok
  capture packets: 0
  per-class -> tcp: 0  udp-to-FI: 0  udp53-to-doc: 0
  iptables DROP pkts for uid 5102: 6
PASS: A.7 negative capture lifecycle: started, clean exit, decodable pcap
PASS: NEGATIVE: ZERO packets to FI/doc-address emitted by DP uid (capture-verified)
PASS: NEGATIVE per class: zero TCP, zero UDP-to-FI, zero UDP/53-shaped packets from the DP uid
PASS: kernel owner-match DROP counters confirm the attempts were filtered (6 pkts)
PASS: DP-uid TCP connect did not succeed
-- attempts as uid 6000:
  tcp->FI: connected
  udp->FI: send returned
  dns53->doc-addr: send returned
  tcp->doc-addr: failed
  capture: ok
  capture packets: 11
  per-class -> tcp: 9  udp-to-FI: 1  udp53-to-doc: 1
  iptables DROP pkts for uid 6000: 0
PASS: A.7 positive capture lifecycle: ok
PASS: POSITIVE CONTROL per class: TCP (9), UDP-to-FI (1) and UDP/53-shaped (1) packets EACH visible on eth0 — capture validity proven per protocol
PASS: positive control TCP connect succeeded (egress path open for unrestricted uid)
==== phase A.8: cold-start under the topology — restart DP (no CP anywhere in the prototype) ====
listener=127.0.0.1:8881
PASS: DP restart: listener back, auth state from disk (Principle II cold start preserved)
==== phase A.9: loopback-forwarder egress mediation (F1) — DP uid must not reach an unrestricted lo forwarder ====
-- forwarder use attempts as uid 5102:
  tcp-via-forwarder: no data
  udp-via-forwarder: send denied
  host-resolver-style udp/53: send denied
  capture: ok
  eth0 packets to FI (tcp): 0
  eth0 packets to FI (udp): 0
PASS: A.9 negative capture lifecycle: ok
PASS: DP-uid TCP via lo forwarder: no data returned (NEW flow to lo dropped)
PASS: DP-uid UDP via lo forwarder: denied
PASS: DP-uid host-resolver-style UDP/53 to loopback: denied
PASS: NEGATIVE: ZERO forwarded packets to FI attributable to DP-uid attempts (TCP and UDP classes both empty)
-- forwarder use attempts as uid 6000:
  tcp-via-forwarder: RECEIVED banner
  udp-via-forwarder: send returned
  host-resolver-style udp/53: send returned
  capture: ok
  eth0 packets to FI (tcp): 8
  eth0 packets to FI (udp): 1
PASS: A.9 positive capture lifecycle: ok
PASS: POSITIVE CONTROL: unrestricted uid RECEIVED the FI banner through the lo forwarder
PASS: POSITIVE CONTROL: forwarder-mediated TCP (8) AND UDP (1) packets to FI each VISIBLE on eth0
==== phase A.10: socket caller matrix — mount separation enforces DP->SOCKS, CP->control, and the denials ====
PASS: host-sim (DP side) has NO cp-fabric mount — control socket unreachable by construction
PASS: cp-sim has NO dp-fabric mount — SOCKS socket unreachable by construction
cp->control PROTOCOLINFO reply: 250-PROTOCOLINFO 1
250-AUTH METHODS=COO
PASS: CP identity CAN reach the control socket — TRANSPORT/mount evidence only; the sanitized observer boundary is T138 design, not implemented here
dp->socks method reply: 0502
PASS: DP identity CAN reach the SOCKS socket (positive)
probe-uid (no fabric group) -> socks: nc: /fabric/dp/tor-socks.sock: Permission denied
PASS: identity WITHOUT the fabric group gets EACCES on the SOCKS socket (permission-gated; nc exits 0 regardless)
==== phase A.11: reverse-initiated off-loopback channel (round-3 review F1) ====
echo-server up (uid 5102, 0.0.0.0:19191)
old-rule (unrestricted ESTABLISHED) FI-side reply: 'T134-MARKER'
PASS: FALSIFIER: under the round-2 rule shape the reverse-initiated off-loopback channel CARRIES DATA (marker echoed)
lo-scoped-rule FI-side reply: ''
PASS: lo-scoped ESTABLISHED: reverse-initiated off-loopback channel DEAD (no marker; SYN-ACK dropped at OUTPUT)
PASS: loopback SOCKS5 admission still works under the lo-scoped rules (no availability regression)
relay-uid echo-server up (0.0.0.0:19192)
relay old-rule reply: 'T134-RMARK'
PASS: FALSIFIER (relay): unrestricted ESTABLISHED lets the relay identity exchange data on a reverse-initiated off-loopback channel
relay lo-scoped reply: ''
PASS: relay identity: reverse-initiated off-loopback channel DEAD under lo-scoped rules
==== phase A.12: abstract-socket forwarder channel (round-5 review F1) — the shared-netns gap ====
unrestricted uid via abstract forwarder: 'T134-FAKE-INTERNET-TCP'
PASS: POSITIVE CONTROL: abstract-UDS forwarder mediates to FI for an unrestricted uid
DP uid via abstract forwarder: 'T134-FAKE-INTERNET-TCP'
GAP-DEMONSTRATED: the DP uid CAN mediate egress through a host abstract-socket forwarder under the current policy (no per-uid gate exists for AF_UNIX; this is the unresolved shared-netns channel T162 must close via AppArmor unix mediation or equivalent)
==== phase B: candidate B fabric — lo TCP relay -> UDS -> network-less DP stand-in ====
PASS: DP stand-in running with network_mode:none, serving UDS
stand-in interfaces: lo 
PASS: structural isolation: stand-in netns has ONLY lo — no IP egress surface exists
PASS: relay up on 127.0.0.1:8882 as uid 5104 (loopback-scoped ESTABLISHED,RELATED + silent DROP only)
relay-path reply: 0502 (attempt 1)
PASS: candidate B fabric: TCP lo -> relay -> UDS -> netns-less stand-in replied 05 02
PASS: relay uid non-lo TCP denied (same packet-level treatment as the DP uid)
==== phase B.2: relay-identity packet isolation with capture controls (review: no 'proven equal' without evidence) ====
bash: line 1: echo: write error: Operation not permitted
bash: line 1: echo: write error: Operation not permitted
-- attempts as uid 5104:
  tcp->FI: failed
  udp->FI: send denied
  dns53->doc-addr: send denied
  tcp->doc-addr: failed
  capture: ok
  capture packets: 0
  per-class -> tcp: 0  udp-to-FI: 0  udp53-to-doc: 0
  iptables DROP pkts for uid 5104: 15
PASS: B.2 relay capture lifecycle: ok
PASS: NEGATIVE: ZERO packets to FI/doc-address emitted by the relay uid (capture-verified)
PASS: kernel DROP counters confirm the relay-uid attempts were filtered (15 pkts)
PASS: B.2 positive capture lifecycle: ok
PASS: POSITIVE CONTROL (relay phase) per class: TCP (8), UDP (1), UDP/53 (1) each visible — capture valid
PASS: relay non-loopback ingress refused (host-sim eth0 172.21.0.4:8882)
================ T134 prototype summary: FAILS=0 ================
```

---

## 8. Remaining authoritative conflicts (explicit list per acceptance #4)

> **Round-2 revision (2026-09-13, review verdicts `APPROVE-WITH-FIXES`/`REWORK`):**
> F1 — the round-1 rule set carried a blanket loopback ACCEPT that would have let a
> compromised DP launder egress through host-loopback forwarders; the rule set is
> narrowed (scoped shim port + ESTABLISHED,RELATED only) and phase A.9 now proves
> the mediation path closed with positive controls. The overstated
> "eliminated structurally" resolver claim is corrected. F2/F3 — the enforcement
> regression moved into T162 (atomic with its implementation) and T163's
> "blocks/flags" wording is now refusal-only. GLM's minor — the probe host's public
> IP is redacted from the permanent record.
>
> **Round-3 revision (renewed review, same date):** F1′ — the LOG target is removed
> everywhere (production rules are silent DROP; per-packet kernel records would
> violate Constitution III; DROP-rule counters replace them), and T162 gains a
> DeniedEgressNoDetailedLogs regression. F2′ — sidecar authority becomes
> mount-separated per-consumer fabrics with the A.10 caller matrix (CP↛SOCKS,
> DP↛control by construction; group-gated re-exposure), T162 gains a
> SocketCallerMatrix regression and names T138 a prerequisite for the CP-side
> observation surface. F3′ — the THREAT-MODEL mechanism update moves into T162
> (same reviewed change; Constitution V); T163 only updates measured results.
> F4′ — candidate B's relay identity receives its own capture-verified isolation
> probes (B.2) and non-loopback refusal; equivalence claims are restricted to the
> measured properties. GLM minors — the stray trailing code fence is removed and
> the stale §7 line count dropped.
>
> **Round-4 revision (third renewal):** F1″ — the ESTABLISHED,RELATED acceptance is
> scoped to loopback, and phase A.11 demonstrates the reverse-initiated
> off-loopback reply channel carrying a marker under the previous shape and dead
> under the scoped one, with loopback admission preserved. F2″ — the A.10 control
> PASS is relabeled transport/mount evidence; no sanitization is claimed (T138
> owns that boundary, and T162 consumes T138's resolved observer endpoint rather
> than prescribing raw ControlSocket re-exposure). F3′ — every capture phase now
> fails closed (recorder readiness, clean-exit and decode checks; a failed
> recorder prints `capture: FAILED` and invalidates the phase). Minor — the
> SOCKS-request fixture generation is embedded in the driver (§7.1 matches
> verbatim) and the dir-mode sweep is preserved in-driver (A.3.0b), replacing the
> round-1 interactive-only provenance. GLM minors — §4's abridged values mirror
> the preserved run (A.7 counter 6) and the cold-start claim is split (A.2
> snapshot restore; A.8 re-listen).
>
> **Round-5 revision (fourth renewal):** F1‴ — the relay identity's rules moved to
> the same loopback-scoped shape as the DP, and A.11 now demonstrates the
> reverse-initiated channel for both identities (marker exchanged under the
> unrestricted shape; dead under the shipped shape). F2′ — the fabric assertion
> requires the complete 14-byte reply and rejects authentication-only, timeout
> and dead-shim results; phase A.4f preserves the dead-shim discrimination, and
> the `05 04` byte is correctly described as the DP's synthesized classification
> of tor's non-zero REP (`classify()` in `forward/tor.go`), not a captured Tor
> wire byte. Minor — T162's file budget is re-grounded to its actual change
> surface. (Harness note: two probe defects were found and fixed while applying
> these revisions — `pkill` was absent from the tooling image, making earlier
> kill steps silent no-ops, and one `pkill -f` pattern matched its own wrapper;
> both are covered by installing `procps` and the self-exclusion bracket form,
> and the final transcript is from the corrected driver.)
>
> **Round-6 revision (fifth renewal):** per-protocol capture controls — the
> positive/negative assertions now decode and assert TCP, UDP-to-FI and
> UDP/53-shaped counts individually (a TCP-only capture can no longer satisfy the
> UDP/DNS controls; the A.9 forwarder capture covers both TCP and UDP classes),
> and T162's affected-surface inventory is completed (FR-007 endpoint wording,
> architecture spec §4.2, data-model §6 volume identities, and
> `tests/contract/tor/port_exposure_test.go`, which fatally requires the removed
> stargate-internal network) with the file budget re-grounded to 24 against the
> enumerated paths and the report's installer-ownership wording reconciled.
>
> **Round-7 revision (sixth renewal):** abstract-socket channel — phase A.12
> demonstrates a host abstract-UDS forwarder mediating egress for the DP uid
> under the current policy (with an unrestricted-uid positive control); the
> closure is specified as installer-loaded AppArmor unix mediation with a
> mandatory discriminating regression in T162, the compliance claim is qualified
> until enforced, candidate B's DP-side structural immunity is recorded (its
> relay carries the same requirement), and a deployment unable to load profiles
> escalates the topology choice instead of shipping. GLM minor — §4's abridged
> values are now a strict selection of the preserved run (relay DROP counter 15;
> aggregate-only lines removed). T162's inventory is enumerated path-by-path
> against its budget.

> **Round-8 revision (formal round-1 rework):** the Docker-cadence Tor suites
> that still speak TCP 9050/9051 are now explicitly listed as T162-owned
> migration surfaces, and T162's budget is re-grounded to include them. The
> preserved A.7 positive-control transcript is corrected to 11 packets / 9 TCP,
> the complete SOCKS reply is consistently described as 14 bytes, and candidate
> B's fallback condition now states that its host firewall and AppArmor
> prerequisites remain required.

None of these is a conflict **with the constitution**; they are spec/contract/test
surfaces that still describe the superseded topology and must be amended by the
implementation tickets — listed so nothing is silently inherited:

1. `specs/001-tor-route/spec.md` **FR-011** and `contracts/torrc.md` §"Rendered
   file" byte-pin `SocksPort 0.0.0.0:9050` / `ControlPort 0.0.0.0:9051` — T162
   amends both to the unix-socket fabric (spec-level, governed change; FR-012's
   "never host-published" property is strengthened: nothing is published at all).
2. `compose/docker-compose.local.yml` and its structural contract
   (`tests/contract/compose/local_compose_test.sh` M-rules incl. M13 stargate-host
   membership), `tests/contract/compose/network_hardening_test.go` (internal
   split, masquerade, TCP-timeout probe) and `tests/contract/tor/
   port_exposure_test.go` (fatally requires the stargate-internal network that the
   new topology removes) — all pin the T125/T094b shape; T162 rewires them and
   T163 replaces the non-discriminating TCP probe with capture-verified probes.
   The endpoint wording travels with them: spec **FR-007** still binds the upstream
   to `tor:9050` on the compose network, architecture spec §4.2 describes the
   TCP endpoints, and `data-model.md` §6 enumerates the replaced volume set —
   each is amended by T162 in the same change. The Docker-cadence Tor suites
   that also pin the removed TCP endpoints are T162-owned migration surfaces:
   `tests/contract/tor/control_port.go`,
   `tests/contract/tor/control_port_live_test.go`,
   `tests/contract/tor/username_less_isolation_test.go`,
   `tests/contract/torrc/isolate_socks_auth_effect_test.go`,
   `tests/contract/torrc/live_sidecar_test.go`, and
   `tests/contract/tor/control_port_test.go`. Their `nc`/GETCONF/golden
   transport assumptions must move to the landed unix-socket/control-observer
   fabric or be explicitly retired with a discrimination check; T163 owns
   measured production capture evidence, not this transport migration.
3. `THREAT-MODEL.md` §3.1 "Current gap" and §5.8 "Current implementation gaps"
   paragraphs — rewritten when T162/T163 land; until then they correctly describe
   the stack as non-compliant.
4. **Installer-owned host state**: owner-match rules are host firewall state the
   compose file cannot own (uid stability across users/hosts, re-run after reboot,
   fail-closed verification before/at stack start). The deployment contract T162
   writes must define provisioning + verification + refusal semantics, and must pin
   the rule SHAPE proven here: ESTABLISHED,RELATED plus **silent** DROP only — **no
   blanket loopback ACCEPT, no IP-initiated exception, and no LOG target** (the
   prototype's scoped lo:9050 rule exists solely for the shim stand-in and
   disappears with native AF_UNIX dial; per-packet kernel logging would violate
   Constitution III's aggregate-only records — T162 carries a
   DeniedEgressNoDetailedLogs regression). Missing rules must produce an
   observable startup/admission refusal on every supported startup/restart path,
   never a warning-only outcome. The socket authority is owned by the per-consumer
   mount separation (A.10) and its SocketCallerMatrix regression; the CP-side
   observation surface defers to T138's design, which T162 names as a prerequisite
   for that part. Third, the **abstract-socket channel (A.12)**: the installer
   must additionally load an AppArmor profile for the DP mediating AF_UNIX (allow
   exactly its pathname fabric sockets, its dp.sock server socket and its
   control.sock client connection; deny abstract-socket connects) — the channel is
   demonstrated open without it; the requirement and its discriminating
   regression are mandatory in T162, and a deployment that cannot load profiles
   escalates the topology choice to the maintainer rather than shipping. These
   are the main open design constraints of candidate A, not constitutional
   conflicts.
5. **T138 interplay**: the control-socket re-exposure must be gated to the CP only
   (fabric gid), and CP's Tor-protocol authority (full cookie) remains T138's scope
   regardless of transport; a unix ControlSocket does not by itself narrow
   authority.
6. `scripts/stargate init` currently provisions keys/volumes; **T162** extends it
   to install/verify the egress rules and the DP AppArmor profile and to enforce
   the fail-closed startup refusal (atomically with the topology); **T163** only
   extends measurement to production namespaces. The operator path changes
   (quickstart/README wording rides along).

## 9. Follow-up wiring (the planning-refinement obligation)

- **T162 — implement the candidate-A topology** (tests-first; `remediates: T134`):
  forwarder unix dial, bind-exception deletion, tor image socket fabric + re-exposure
  hook, compose rewire, contract/spec amendments, installer rule provisioning.
- **T163 — packet-level topology verification** (tests-first; `remediates: T134`):
  per-class positive-control capture suite against production namespaces (both IP
  families), verification that rule absence is fail-closed in production (the
  provisioning and its fail-closed startup refusal are T162's, shipping atomically
  with the topology), and the threat model's measured-results update.
- Wired into: `T155.blocked_by += [T162, T163]`; `T123/T124.blocked_by += [T162]`
  (deployment bring-up must target the repaired topology). T126/T034a/T034f are
  transitively covered through their existing blockers. STATUS regenerated.
