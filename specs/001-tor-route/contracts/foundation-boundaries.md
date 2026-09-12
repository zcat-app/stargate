# Contract — foundation boundaries after T156

Normative for feature 001 after the 2026-09-12 constitution amendment. This replaces the
identified older contract permissions; it is a target, not a claim that current code complies.
No runtime change is made by T156. The implementation owners below remain pending.

## Deployment and authority — T134/T138

DP route and CP admin/health listeners bind loopback in their own namespaces in Local;
host loopback publication alone is insufficient. LAN/VPS require the actual tunnel address
in the listener namespace. Validate IPv4/IPv6, startup, restart and tunnel/address-loss behavior.
Sidecar listeners are separate, unpublished endpoints with enforced permitted callers:
DP to route SOCKS only; CP to sanitized observation/lifecycle only; no CP SOCKS route and
no application-plane unrestricted Tor control cookie. Privilege enforcement must survive
compromise of the CP process. A health helper may not become a generic command proxy.
T134 compares designs satisfying both listener and egress requirements. Shared networking
is not pre-approved: shared egress without independent process controls fails the contract.

Native Tor protocol maintenance belongs to Tor's egress TCB. DP/CP cannot originate public
TCP/UDP/DNS, including arbitrary names through a forwarding service resolver. Local IPC/service
resolution is limited to exact configured identities. Test actual packets in source and egress
namespaces with positive capture controls; NAT absence and connect timeout are insufficient.

## Negotiation and isolation — T136/T147

The CONNECT/SOCKS envelope can parse only authentication, destination and isolation fields
specified in its protocol contract, with bounded input. Payload/TLS/application headers remain
opaque. Generated failures contain fixed public vocabulary and no echoed peer/destination text.
No supported ingress may forward without the required isolation identity. The existing CONNECT
NO_AUTH upstream behavior is a defect, not an exception. T147 must select a bounded identity
transport or explicit refusal/migration; it cannot parse application headers to infer first party.

A partition contains authenticated device identity, browser-profile identity and initiating site.
DNS site boundaries use a pinned offline public/private suffix source (or a documented equivalent
that proves the same boundary); complete onion service identities remain distinct. A deterministic
representation must fit SOCKS credentials without collisions or exposing the bearer token. The
contract refinement in T136 specifies schemes, ports, IP literals, unknown/opaque parents,
redirects, frames, workers, navigation and private browsing. No runtime dependency fetch.
Test same destination under different sites/devices/profiles and unknown-context refusal.
A destination hostname is not a fallback identity; same-partition circuit reuse is permitted,
not guaranteed. No claim of general cross-site anonymity follows from circuit isolation alone.

## Auth state, recovery and peer identity — T132/T135/T148/T159

A valid last acknowledged DP snapshot authorizes cold-start admission while CP is down. Missing,
corrupt or incompatible state denies admission. Snapshot writes are atomic and generation is
monotonic across supported restarts. Reconnect automatically reconciles the current durable CP
state; no periodic expiry is added merely because the CP is down. Revocation remains pending
until DP application is acknowledged; existing tunnels may finish. A stale backup cannot be
renumbered into new authority automatically. Explicit operator recovery is separate and warned.
T159 records the exact recovery transition and wire compatibility/migration before code.

Both IPC roles require private-key possession, current authorized peer key and certificate
NotBefore/NotAfter validity on full and resumed handshakes. Read current pin state for each
handshake. Certificates renew before expiry independently of CP availability; do not require
manual monthly restart. Invalid/missing/unreadable pins fail authentication. T148 specifies
clock tolerance, renewal and established-channel rotation/revocation behavior with bounded,
measurable deadlines before implementation. Do not claim key rotation instantly closes old
channels until that behavior is implemented and verified. Route survival does not waive peer auth.

## Aggregate data policy — T152/T158

Traffic increments are private volatile state until the UTC hour closes. GetStatus and future
UI/storage export only finalized, immutable buckets; repeated polling must never reveal the
current hour's changing request/byte count. An optional current health enum carries no traffic
counts or request-associated timestamps. Late connection completion contributes bytes to its
completion bucket, not a previously published bucket. Define clock regression handling so a
published bucket cannot reopen. T149 owns loss-free accounting; T158 owns exposure/finalization.

Operational aggregation is also hourly. Permitted fields are `hour_bucket`, a fixed `category`
and `count`; categories are `enrolled`, `revoked`, `config_error`, `sidecar_healthy`,
`sidecar_unhealthy`. No labels, actors, generations, per-event times, sequence IDs, reference IDs,
line numbers, details JSON or free text. Persist/export only finalized buckets, with a default
maximum retention of 7 days and deletion of older aggregates; operators may disable retention.
This limit applies to operational aggregates and traffic aggregates in this feature. The seven
day bound is a contract choice, not permission to collect more detailed data for fewer days.

Current static redacted errors and finite health state are direct responses, not persistent
journals. Raw sidecar output and application debug stdout/stderr may not bypass the policy.
T152 inventories and repairs every operational writer, including diagnostic/container capture;
T158 covers traffic counter RPC semantics. Migration stops detailed writes, removes retained
legacy rows and handles SQLite WAL/backups under an explicit operator cleanup procedure. Do
not promise forensic erasure on host storage; report that residue and prevent further exports.
Existing operational rows are a known implementation gap, not constitutional accepted risk.

## Browser failure and truthful UI — T150/T151/T157

Selected protected requests with failed/unknown hardening, missing/invalid credentials, missing
identity, unavailable route or an initialization race must have no Direct/system-route network
fallback. Test both descriptor decisions and real browser packets, including subresources and
redirect/retry paths. Existing explicit Direct requests remain separate. T157 supplies the failure
behavior and real-browser evidence; T155 rechecks integration. A tab indicator identifies main
navigation and mixed-route coverage without claiming a protected tab from one protected image.
DoH/DoT/HTTP-3 checks remain external profile validation; no unsupported WebExtension API claims.

## Compatibility and completion

Before changing any wire shape or behavior, the owning implementation ticket records old/new
peer behavior, synchronized deployment and migration/negative tests. Pre-release v1 amendments
need an explicit transition record; they are not justified by constitution version numbering.
After public release, breaking changes require protocol-major migration. Existing illustrative
v1 message/schema snippets describe the current implementation until their owner refines them;
they cannot authorize behavior forbidden here. T155 cannot pass without these owners and any
required implementation children complete. T078/T079 remain final milestone reviews.
