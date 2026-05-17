# Contract — Bearer-Token Auth on Port 8881

**Status**: Phase 1 contract document

**Scope**: defines the precise byte-level behaviour of the data plane's
authentication step on inbound TCP connections to `127.0.0.1:8881`. The
contract tests at `tests/contract/error-template/` (for the CONNECT path)
and `tests/contract/socks5/` (for the SOCKS5 path) implement these.

**Source FRs**: FR-005, FR-006, FR-007, FR-008.

**Source threat model**: THREAT-MODEL §3.1 Local profile (auth here
protects against same-host non-privileged processes attempting to use
the proxy without the bearer token).

---

## Two inbound protocols, one port

Port 8881 accepts both:

1. **SOCKS5** (RFC 1928 + RFC 1929 for user/pass auth).
2. **HTTP `CONNECT host:port HTTP/1.1` framing** (some browsers and
   tools default to HTTP CONNECT when the proxy is configured as HTTP).

The data plane sniffs the first byte to demultiplex:

| First byte             | Interpreted as | Reason                                                |
|------------------------|----------------|--------------------------------------------------------|
| `0x05`                 | SOCKS5         | SOCKS5 version byte; no HTTP method starts with 0x05. |
| ASCII `C` (`0x43`)     | HTTP CONNECT   | First byte of `CONNECT`.                              |
| Anything else          | Reject         | Close connection without sending a body.              |

The "anything else" close is silent — no response template — because the
client is not speaking either supported protocol and there is no
agreed-upon framing in which to deliver an error. This is fine: a
correctly-configured browser never sends "anything else" to a proxy.

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
3. Hash `PASSWD` with argon2id using the parameters in data-model.md
   §1.5 and the salt stored alongside each hash in the current token
   generation. Compare with `crypto/subtle.ConstantTimeCompare`
   against every hash in the generation.

On auth success, the data plane MUST respond:

```
VER STATUS
0x01 0x00         ← success (RFC 1929 §2)
```

…and proceed to the SOCKS5 request phase (RFC 1928 §4).

On auth failure (`PASSWD` does not match any hash in the current
generation, OR the generation is empty), the data plane MUST respond:

```
VER STATUS
0x01 0xFF         ← failure
```

…and then close the connection. No further bytes are written.

### Invariants enforced by the contract test

| Invariant                                                                          | Test method                                                                                                                                                          |
|------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Methods response is exactly `0x05 0x02` for clients offering `0x02`                | Assert exact 2-byte response.                                                                                                                                        |
| Methods response is exactly `0x05 0xFF` for clients offering only `0x00`           | Assert exact 2-byte response. Connection closes after.                                                                                                               |
| Auth failure response is exactly `0x01 0xFF`                                       | Assert exact 2-byte response. Connection closes after.                                                                                                               |
| Auth failure does not leak token bytes                                              | Capture all bytes the data plane writes between the client sending the password and the close. Assert no occurrence of the offered token bytes anywhere in the capture. |
| Constant-time comparison                                                            | Statistical timing test: two distinct invalid passwords, same length, generate close-to-equal latency distributions. (Best-effort — true constant-time verification is hard from userland.) |
| No per-request log on auth failure                                                  | Tail the data plane's journal during the test; assert no entry containing the destination, the token, the username, or a per-request timestamp at finer than hour resolution. |
| Same-host processes without a token cannot proxy                                    | Open a loopback TCP connection to 8881, send SOCKS5 with `0x05 0x01 0x00` (NO_AUTH only) → connection rejected.                                                       |

---

## SOCKS5 request-phase failures (post-auth)

After username/password sub-negotiation succeeds, the client sends the
SOCKS5 request (RFC 1928 §4); the data plane dials the Tor sidecar
and bridges. If the route is DISABLED (`routeEnableMask[TOR]=false`),
or the upstream connect fails, the data plane MUST reply with an
RFC 1928 §6 SOCKS5 reply with the following mapping:

| Stargate condition                            | RFC 1928 §6 `REP` | Mnemonic              |
|-----------------------------------------------|-------------------|-----------------------|
| `ROUTE_DOWN` (sidecar unreachable / unhealthy; `routeEnableMask[TOR]=false`)        | `0x03`            | Network unreachable   |
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
HTTP CONNECT response shape (`contracts/error-template.md`).

### Invariants enforced by the contract test

| Invariant                                                                                              | Test method                                                                                                                                                                |
|--------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Route-disabled `ROUTE_DOWN` reply is exactly `05 03 00 01 00 00 00 00 00 00`                           | Stop the Tor sidecar (or arrange `routeEnableMask[TOR]=false` via withheld HEALTHY event); send authenticated SOCKS5 CONNECT; assert byte-exact 10-byte reply, then close. |
| `ROUTE_REFUSED` reply is exactly `05 04 00 01 00 00 00 00 00 00`                                        | Tor up, target an unreachable `.onion`; assert byte-exact 10-byte reply.                                                                                                   |
| `ROUTE_TIMEOUT` reply is exactly `05 06 00 01 00 00 00 00 00 00`                                        | Substitute the `slow` mode of `tests/integration/fake_socks5_tor.go` (T019a); assert byte-exact 10-byte reply.                                                              |
| `BND.ADDR` and `BND.PORT` never carry destination, sidecar, or token-derived bytes                     | Leak-corpus scan over every reply byte (corpus per `contracts/error-template.md` §"Leak-corpus invariant"); zero hits.                                                     |
| No additional bytes are written after the 10-byte reply, on any of the three failure codes              | Read until EOF after the reply; assert exactly 10 bytes received.                                                                                                          |
| No HTTP-template bytes appear on the SOCKS5 path on any failure code                                    | Scan reply for the literal substring `<!doctype html>` (the template's first bytes per `contracts/error-template.md` §"Response body"); zero hits.                          |

These tests live at `tests/contract/socks5/request_phase_failures_test.go`.

---

## HTTP CONNECT path

The client opens a TCP connection and sends:

```
CONNECT example.onion:443 HTTP/1.1\r\n
Proxy-Authorization: Bearer 9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f\r\n
\r\n
```

The data plane MUST:

1. Parse only the request line and the `Proxy-Authorization` header.
   No other header is read or interpreted (FR-007 — no header
   inspection beyond what auth requires).
2. Extract the token from `Proxy-Authorization: Bearer <token>`.
   Token MUST match `^[0-9a-f]{32}$` syntactically before hashing.
3. Hash + constant-time compare against the current generation.

On auth success: respond `HTTP/1.1 200 Connection Established\r\n\r\n`
and bridge to the upstream SOCKS5 connection (which uses the host
header from the request line as the target).

On auth failure: respond with the **privacy-safe error template** (see
`contracts/error-template.md`) with:

- Status: `HTTP/1.1 407 Proxy Authentication Required`
- `X-Stargate-Error: AUTH_REQUIRED`
- Other headers per the template invariants.

Then close the connection.

### Invariants enforced by the contract test

| Invariant                                                                             | Test method                                                                                                                                                                  |
|---------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Missing `Proxy-Authorization` → 407 + AUTH_REQUIRED template                          | Send CONNECT without the header; assert exact response.                                                                                                                       |
| Malformed token (wrong length, non-hex) → 407 + AUTH_REQUIRED (no distinction from "missing") | Send CONNECT with `Bearer notatoken`; assert response identical to the missing-header case at the byte level (no distinguishing substring).                                  |
| Valid token + dead sidecar → 502 + ROUTE_DOWN template                                | Auth passes; upstream SOCKS5 connect fails; assert 502 + ROUTE_DOWN body and headers.                                                                                          |
| Response NEVER includes the destination host or port                                  | Leak-corpus scan over response bytes; corpus includes the destination string used in the test.                                                                                |
| Response NEVER includes the offered token                                             | Leak-corpus scan over response bytes; corpus includes the offered token.                                                                                                       |

---

## Forbidden behaviours (both paths)

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
`tests/contract/error-template/auth_required_test.go`.
