# Contract — Bearer-Token Auth on Port 8881

> **T172 target update:** every supported ingress requires the isolation partition defined in
> [foundation boundaries](foundation-boundaries.md). T147 selected silent refusal of HTTP
> CONNECT on Tor port 8881. Current code still accepts it until T173; this contract does not
> claim runtime compliance.

**Status**: Phase 1 contract document

**Scope**: defines the precise byte-level behaviour of the data plane's
authentication step on inbound TCP connections to `127.0.0.1:8881`. The
contract tests live under two directories:

- `tests/contract/socks5/` covers supported port-8881 SOCKS5 demux, auth,
  sub-negotiation, counters, forwarding and leak invariants, plus explicit
  silent-refusal tests for HTTP `C`.
- `tests/contract/error-template/` covers renderer-only future HTTP format.
  It has no Tor-port ingress claim. T173 migrates current HTTP fixtures to
  this scope or replaces their ingress assertions with authenticated SOCKS
  tests. See T172's per-file inventory.

**Source FRs**: FR-005, FR-006, FR-007, FR-008.

**Source threat model**: THREAT-MODEL §3.1 Local profile (auth here
protects against same-host non-privileged processes attempting to use
the proxy without the bearer token).

---

## Tor port 8881 ingress

Port 8881 supports authenticated SOCKS5 (RFC 1928 + RFC 1929). HTTP proxy
clients lack the required trustworthy initiating-site/profile partition and
are unsupported on this Tor listener. The listener reads one first byte under
its bounded handshake deadline:

| First byte | Outcome |
|---|---|
| `0x05` | Enter SOCKS5 negotiation. |
| ASCII `C` (`0x43`) | Close with zero response bytes, no auth evaluation, no counter increment and no upstream socket. |
| Anything else | Close without response bytes. |

On `C`, the listener does not parse further HTTP bytes, including claimed
isolation headers. It does not issue HTTP 200, 407 or a route-error template.
There is no HTTP-to-SOCKS conversion, retry, Direct fallback or opt-out.

---

## SOCKS5 path (RFC 1928 + 1929)

### Auth method negotiation

Client sends:

```
VER NMETHODS METHODS...
0x05  0x01    0x02         ← single method offered: USERNAME/PASSWORD
```

The data plane MUST respond:

```
VER METHOD
0x05 0x02         ← USERNAME/PASSWORD selected
```

If the client offers `0x02` (USERNAME/PASSWORD) anywhere in the methods
list, that method is selected. If the client offers ONLY `0x00`
(NO AUTHENTICATION), the data plane MUST respond with `0x05 0xFF`
(no acceptable methods) and close the connection. The data plane MUST
NOT accept unauthenticated SOCKS5 — even though the port is loopback-
bound, the local-process threat model assumes other unprivileged
processes on the same host should not get free proxy access.

### Username/password sub-negotiation (RFC 1929)

Client sends:

```
VER ULEN UNAME PLEN PASSWD
0x01 N   ...   M    ...
```

The data plane MUST:

1. Read `UNAME` (1–255 bytes) as the *first-party domain* string used
   for SOCKS5 stream isolation. It is NOT a credential. It is opaque
   to the auth layer and is passed through verbatim to the upstream
   Tor SOCKS5 connection (FR-007).
2. Read `PASSWD` (1–255 bytes) as the candidate bearer token.
3. Compute `verifier = HMAC-SHA-256(pepper, PASSWD)` under the
   install-time pepper (`/etc/stargate/keys/pepper.key`; data-model.md §1.5,
   amended by T092 — Argon2id is retired, there is no per-token salt).
   Compare the candidate's verifier with
   `crypto/subtle.ConstantTimeCompare` against EVERY verifier in the
   current generation — no short-circuit on first match (the comparison
   loop's timing must be independent of which slot matched).

On auth success, the data plane MUST respond:

```
VER STATUS
0x01 0x00         ← success (RFC 1929 §2)
```

…and proceed to the SOCKS5 request phase (RFC 1928 §4).

#### Auth failure response

On auth failure (`PASSWD` does not match any hash in the current
generation, OR the generation is empty), the data plane MUST respond:

```
VER STATUS
0x01 0xFF         ← failure
```

…and then close the connection. No further bytes are written. This
applies symmetrically to the `AUTH_REQUIRED` case (no token offered,
malformed token, token-list empty); the 2-byte sub-negotiation reply
plus close is the entire SOCKS5-path failure surface — no body, no
template, no distinguishing substring across missing/malformed/empty
cases (FR-006 / FR-009). The invariant tests for this byte sequence
live in the table below (rows "Auth failure response is exactly
`0x01 0xFF`" and "Auth failure does not leak token bytes").

### Invariants enforced by the contract test

| Invariant                                                                          | Test method                                                                                                                                                          |
|------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Methods response is exactly `0x05 0x02` for clients offering `0x02` alone           | Assert exact 2-byte response on input `0x05 0x01 0x02`.                                                                                                              |
| Methods response is exactly `0x05 0x02` for clients offering `[0x00, 0x02]` (mixed) | Assert exact 2-byte response on input `0x05 0x02 0x00 0x02` — USERNAME/PASSWORD selected even when NO_AUTH is also offered. Guards against accidental NO_AUTH acceptance when both methods are present (the realistic-client shape — stock SOCKS5 clients often offer both). |
| Methods response is exactly `0x05 0xFF` for clients offering only `0x00`           | Assert exact 2-byte response. Connection closes after.                                                                                                               |
| Auth failure response is exactly `0x01 0xFF`                                       | Assert exact 2-byte response. Connection closes after.                                                                                                               |
| Auth failure does not leak token bytes                                              | Capture all bytes the data plane writes between the client sending the password and the close. Assert no occurrence of the offered token bytes anywhere in the capture. |
| Constant-time comparison                                                            | Statistical timing test: two distinct invalid passwords, same length, generate close-to-equal latency distributions. (Best-effort — true constant-time verification is hard from userland.) |
| Slot-invariance across the token list (data-model.md §1.5 "constant-time across the full list") | With N=4 stored token hashes, the auth-pass latency distribution is statistically indistinguishable whether the matching token is at slot index 0, 1, 2, or 3 (and against the all-fail case). An early-exit-on-first-match loop would fail this assertion by producing monotonically increasing latency by slot index. |
| No per-request log on auth failure                                                  | Tail the data plane's journal during the test; assert no entry containing the destination, the token, the username, or a per-request timestamp at finer than hour resolution. |
| Same-host processes without a token cannot proxy                                    | Open a loopback TCP connection to 8881, send SOCKS5 with `0x05 0x01 0x00` (NO_AUTH only) → connection rejected.                                                       |

---

## SOCKS5 request-phase failures (post-auth)

After username/password sub-negotiation succeeds, the client sends the
SOCKS5 request (RFC 1928 §4); the data plane dials the Tor sidecar
and bridges. If the upstream connect fails, the data plane MUST reply
with an RFC 1928 §6 SOCKS5 reply with the following mapping:

| Stargate condition                            | RFC 1928 §6 `REP` | Mnemonic              |
|-----------------------------------------------|-------------------|-----------------------|
| `ROUTE_DOWN` (upstream sidecar unreachable — no TCP connection) | `0x03`            | Network unreachable   |
| `ROUTE_REFUSED` (sidecar accepted SOCKS5 but refused the target — e.g. onion service unreachable) | `0x04` | Host unreachable      |
| `ROUTE_TIMEOUT` (upstream dial+I/O deadline exceeded)                               | `0x06`            | TTL expired           |

The reply byte sequence is:

```
VER REP RSV ATYP BND.ADDR     BND.PORT
0x05 <c> 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00
```

— a 10-byte response. `ATYP=0x01` (IPv4); `BND.ADDR=0.0.0.0` and
`BND.PORT=0` are **always zeroed on failure**. The data plane MUST
NOT echo the request's target address, the upstream sidecar's bind
address, or any port-derived value into `BND.ADDR`/`BND.PORT` — those
fields would be a destination-metadata leak on the failure path
(Principle III; FR-008 — no per-request metadata in side channels).

After writing the 10-byte reply, the data plane MUST close the
connection. No further bytes are written. There is no body and no
`X-Stargate-Error` header on the SOCKS5 path — those belong to the
future HTTP-format renderer (`contracts/error-template.md`), which is not
reachable from this Tor listener.

### Deadlines

`ROUTE_TIMEOUT` is driven by **one** bounded deadline, applied to the
dial-and-handshake phase only:

| Phase                                                                                         | Deadline | Mapped to        |
|-----------------------------------------------------------------------------------------------|----------|------------------|
| Open TCP to `tor:9050` + complete SOCKS5 method + auth (if any) + write request + read BND reply | **30 s** | `ROUTE_TIMEOUT`  |
| Post-handshake (BND reply received; data plane is now a byte pipe)                            | **none** | n/a — long-lived |

Rationale: 30 s is generous against Tor's worst-case .onion descriptor
lookup + rendezvous-circuit build (typical: 5–15 s; observed tail: 20–25 s
under guard pressure) while keeping a clearly-finite ceiling so the
forwarding path doesn't queue dead connections. **No idle deadline is
applied after handshake completes** — Principle I requires the data plane
to be a transparent byte pipe (spec §"Edge Cases" — WebSocket upgrade
through the SOCKS CONNECT command; HTTP/2 over the same circuit); pinning a per-frame
idle timeout would close long-lived flows that the upstream is keeping
deliberately quiet. The connection lives until either end closes or the
underlying Tor circuit drops (spec §"Edge Cases" — *Tor circuit failure
mid-request* path, covered by T070a — verifies no synthesised error
bytes leak in that case).

Implementation guidance: the 30 s value is wired as a single named
constant in `data-plane/internal/forward/tor.go` (T072) so any future
re-tuning is one edit; the contract test `request_phase_failures_test.go`
(T067a) drives `fake_socks5_tor.go slow` mode at a delay strictly greater
than this value to deterministically trigger `0x06`.

### Invariants enforced by the contract test

| Invariant                                                                                              | Test method                                                                                                                                                                |
|--------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Upstream-unreachable `ROUTE_DOWN` reply is exactly `05 03 00 01 00 00 00 00 00 00`        | Stop the Tor sidecar; send authenticated SOCKS5 CONNECT; assert byte-exact 10-byte reply, then close. (Admission is not event-gated — data-model.md §2 — so a withheld `HEALTHY` does NOT produce this reply; only an unreachable upstream does.) |
| `ROUTE_REFUSED` reply is exactly `05 04 00 01 00 00 00 00 00 00`                                        | Tor up, target an unreachable `.onion`; assert byte-exact 10-byte reply.                                                                                                   |
| `ROUTE_TIMEOUT` reply is exactly `05 06 00 01 00 00 00 00 00 00`                                        | Substitute the `slow` mode of `tests/integration/fake_socks5_tor.go` (T019a); assert byte-exact 10-byte reply.                                                              |
| `BND.ADDR` and `BND.PORT` never carry destination, sidecar, or token-derived bytes                     | Leak-corpus scan over every reply byte (corpus per `contracts/error-template.md` §"Leak-corpus invariant"); zero hits.                                                     |
| No additional bytes are written after the 10-byte reply, on any of the three failure codes              | Read until EOF after the reply; assert exactly 10 bytes received.                                                                                                          |
| No HTTP-template bytes appear on the SOCKS5 path on any failure code                                    | Scan reply for the literal substring `<!doctype html>` (the template's first bytes per `contracts/error-template.md` §"Response body"); zero hits.                          |

These tests live at `tests/contract/socks5/request_phase_failures_test.go`.

---

## HTTP CONNECT refusal

For any connection whose first byte is ASCII `C` (`0x43`), the data plane
closes without response bytes. It does not evaluate `Proxy-Authorization`,
increment request or byte counters, or open an upstream socket. Missing,
malformed and valid-looking credentials, claimed isolation headers, pipelined
payload, slow or oversized input all have the same outcome. T173 implements
and tests this target; current `listener/connect.go` contradicts it.

---

## Forbidden behaviours (SOCKS authentication)

The data plane MUST NOT, on the auth path:

- Log the offered token, the offered password, or the offered username
  to any persistent store (journal, file, DB, counter row).
- Emit a metric labelled with the destination hostname, the offered
  token, or the offered token's hash.
- Increment the `aggregate_counters` row on an auth-failed request
  (FR-008 keeps counters honest by counting only forwarded requests;
  counting auth failures would create a side channel for guessing
  attacks against the token).
- Use timing-variant comparison primitives (`==` on `[]byte`,
  `bytes.Equal`); the comparison MUST use `crypto/subtle.ConstantTimeCompare`.

Contract tests for each of these live in
`tests/contract/socks5/leak_test.go` and
`tests/contract/socks5/auth_required_test.go`. HTTP refusal is independent of
the authentication path.
