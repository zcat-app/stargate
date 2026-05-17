# Prompt 06 — First feature spec: Tor route (v1 vertical slice)

Goal: produce `specs/001-tor-route/spec.md` via the `/speckit-specify`
slash command, defining the first vertical slice of Stargate functionality.

## Before you start

Read in order:

1. `.specify/memory/constitution.md` — authoritative.
2. `specs/000-architecture/spec.md` — concrete decisions you must align with.
3. `THREAT-MODEL.md` — Tor-route-specific threats and protections.

If any of these don't exist, complete the earlier prompts first.

## How to invoke

In a fresh Claude Code session in this project, type:

```
/speckit-specify Tor route — v1 vertical slice. Stargate's first end-to-end
working route. Browser extension (Mullvad Browser) routes any request to a
.onion hostname through a dedicated proxy port to the Tor sidecar's SOCKS5
interface, with per-first-party-domain stream isolation. Local deployment
profile only (loopback). No bridges. No Quarkus dashboard UI yet — bearer
token configured manually via config file. Constitution Principles I, II,
III apply in full. Stargate has nothing else routing yet; this is the
proof-of-concept vertical slice that exercises the data plane, the
extension's proxy.onRequest path, sidecar coordination, contract testing,
and the build/release pipeline.
```

The slash command will produce `specs/001-tor-route/spec.md` from the
template. **Iterate on it in the session** to flesh out user stories,
acceptance scenarios, and success criteria specific to this feature.

## Scope checklist (use this to review the generated spec)

The spec should cover:

1. **User Story 1 (P1, MVP)**: a user with Mullvad Browser + Stargate
   extension installed visits a known onion service URL and the page loads
   through Tor.
   - Acceptance: page loads; check.torproject.org via .onion confirms Tor
     usage; no DNS leak detectable via local Wireshark capture.
2. **User Story 2 (P2)**: visiting two different .onion services from
   different tabs uses distinct Tor circuits (stream isolation).
   - Acceptance: Tor control-port query (or log inspection) shows distinct
     circuit IDs for distinct first-party domains.
3. **User Story 3 (P3)**: graceful failure when Tor sidecar is down — user
   sees a privacy-safe error page (no exit IPs, no upstream addresses).
   - Acceptance: stop Tor container; visit .onion; observe template-conformant
     error page; contract test for error template passes.

### Edge cases the spec must address

- Browser requests with `WebSocket` upgrade through CONNECT
- HTTP/2 connections (forced fallback from QUIC)
- Concurrent requests against the same first-party domain (same circuit)
- Tor circuit failure mid-request (timeout, retry policy)
- Bearer token missing or invalid (proxy rejects without leaking *why*
  beyond auth failure)
- Hostname is `.onion` but not reachable / does not exist
- Extension disabled mid-session (proxy still receives requests on port
  8881; what does it do?)

### Functional requirements skeleton

- FR-001: Extension routes requests with `.onion` hostnames to proxy port
  8881 (or whichever port the architecture spec assigns to Tor).
- FR-002: Extension sets SOCKS5 username to the first-party domain for
  stream isolation. **Tests must verify distinct circuits per origin.**
- FR-003: Data plane forwards bytes on port 8881 to Tor SOCKS5 sidecar,
  passing through the SOCKS5h hostname-mode and stream-isolation username.
- FR-004: Bearer token in `Authorization: Bearer <token>` header validated
  on every request; absence/invalid → 407 with privacy-safe body.
- FR-005: Data plane MUST NOT log destination hostname or full URL.
- FR-006: Tor sidecar's SOCKS5 must be reachable only on Docker internal
  network; not exposed to host.
- FR-007: Privacy-safe error template returned on sidecar unreachability,
  conforming to architecture's error-response contract.

### Success criteria skeleton

- SC-001: A first-time user can install Mullvad Browser + extension, paste
  bearer token, and load a known .onion within 5 minutes.
- SC-002: 100 distinct first-party `.onion` visits produce ≥95 distinct
  Tor circuits (allowing some legitimate reuse).
- SC-003: No DNS query for any `.onion` hostname appears in local
  Wireshark capture during a 10-minute Tor browsing session.
- SC-004: Error template contains zero values from the set
  {exit IPs, upstream hostnames, error backtraces, sidecar log fragments}.

### Constraints

- **One vertical slice.** Do not include I2P, Nym, bridges, or the dashboard
  UI in this feature spec. Those are separate `specs/00X-*/` features.
- **Local profile only.** LAN/VPS profiles are out of scope for v1.0.0 of
  this feature (revisited in a later feature spec).
- **Manual bearer-token configuration** for v1 (config file). Enrollment UI
  is a separate feature.

### Definition of done

- File exists at `specs/001-tor-route/spec.md`.
- All template sections filled (User Stories with priorities, Edge Cases,
  Functional Requirements, Key Entities, Success Criteria, Assumptions).
- Spec passes a sanity check against the constitution: no requirement
  violates a principle; any tension is called out explicitly.
- After spec lands, the next session can run `/speckit-plan` against it
  productively.

When done, summarise the feature and list `NEEDS CLARIFICATION` items
(if any) for user resolution before `/speckit-plan`.
