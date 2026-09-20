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

**T168 Local IP boundary:** before proxy or IPC serving, the pure-Go DP binds an
ordinary TCP loopback listener (MPTCP disabled), rejects other inherited sockets,
anonymous capabilities and devices, then installs Landlock ABI >= 4 TCP bind/connect
denial on every Go thread and a synchronized seccomp filter. The filter permits new
AF_UNIX sockets only and denies message-send/import and io_uring paths; stream
read/write preserves accepted TCP replies and pathname Unix adapter/IPC traffic.
Restrictions are inherited by future threads and descendants. Required feature,
descriptor inventory or installation failure refuses startup with a fixed error.
There is no runtime bypass. Builds with cgo or unsupported architectures refuse;
Linux amd64/arm64 use native syscall numbers. ABI >= 7 disables the domain's
configurable denial auditing, including descendants. Runtime evidence on amd64
does not establish arm64 or newer-kernel conformance.

The installer still requires its IPv4/IPv6 owner rules and enforcing AppArmor
profile. Owner rules are defense in depth: deleting either or both after startup
must preserve safe Unix-adapter service, including Compose DP restart. Re-init
reinstalls them. Missing process confinement instead requires observable refusal
before a SOCKS method or management response. AppArmor and the existing Unix fabric
caller matrix remain required; overriding Docker security policy is unsupported.
Neither the CP nor a per-request host verifier participates in this boundary.
T168 refines T163's former owner-rule-loss admission requirement without expanding
Constitution III's actor/traffic permissions. T163 retains the cumulative and
physical-host packet evidence obligation.

**T138 authority refinement (T162 fabric landed; observer pending T164):** the CP MUST NOT hold the
Tor control cookie, the Tor-cookie supplementary group, or a network path to raw Tor control.
A separate observer owns the Tor-facing credential and raw control session. Its CP-facing
endpoint accepts one bounded health operation with no arguments and returns only the finite
tokens `READY`, `NOT_READY` or `UNAVAILABLE`; it MUST reject arbitrary command text and MUST
not return raw Tor replies. The observer's Tor-facing sequence is fixed to cookie
authentication, `GETINFO status/bootstrap-phase`, and `QUIT`; this application allowlist is
defense-in-depth, while the process/socket/credential separation is the enforcement boundary.
T138's decision record fixes the CP-facing `HEALTH/1` framing and byte/deadline limits,
Tor-reply bounds, exact token meanings and event mapping; T164 MUST implement and test those
bounds and reconcile the emitted `WatchEvents` subset before replacing the current monitor.
An unavailable observer cannot justify a Tor exit or restart claim.
The observer MUST NOT expose stream/circuit status, configuration, event subscriptions,
stream attachment, onion-service creation, signals or a generic command proxy. CP health is
advisory and cannot gate DP admission or select a fallback route. T164/T165 own the
tests-first implementation and deployment evidence. T162 removes the former direct CP cookie
and raw-control path and reserves a CP-only fabric volume; until T164, CP Tor health observation
is unavailable and advisory. The reserved volume is not itself a health endpoint.

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

### Browser SOCKS isolation identity — T136

The browser extension derives one versioned opaque SOCKS username for the tuple
`(authenticated device, browser profile, browser context, initiating top-level site)`:

- Firefox 153's native `publicSuffix.getDomain()` is the sole DNS suffix authority. Its default
  punycode result includes ICANN and PRIVATE rules (including `github.io`) and returns `null` for
  IP addresses, plain suffixes and unknown suffixes; Stargate never enables `allowPlainSuffix` or
  `allowUnknownSuffix`. The browser ships and updates that data without extension runtime network
  I/O. `manifest.json` pins `browser_specific_settings.gecko.strict_min_version` to `153.0`
  and declares the `publicSuffix` API permission — Firefox injects the namespace only when the
  permission is declared, so omitting it makes every DNS-site derivation fail closed in the
  real browser regardless of the version pin.
  Development is grounded against Mullvad Browser Alpha 16.0a11 / Gecko 153.2.0; v1 release is
  gated until the stable Mullvad Browser channel uses Gecko 153 or newer and still supports MV2.
- A DNS site is its registrable domain. A hostname that is itself a public suffix or has no
  registrable label is unavailable. HTTP and HTTPS schemes share a site; explicit/default ports,
  paths, queries, fragments and user information do not enter it. Unsupported schemes and
  hostless/opaque top-level URLs are unavailable. Complete normalized `.onion` hosts and canonical
  IPv4 or bracketed IPv6 literals remain whole and type-distinct; no local DNS lookup occurs.
  These scheme restrictions apply to the initiating site only. Destination selection uses the
  requested hostname: a `.onion` WebSocket request is Tor-routed just like HTTP(S), without a
  scheme-based downgrade.
- A top-level `main_frame` navigation uses its requested URL, including a redirect target. A
  frame-zero subresource uses a present valid `documentUrl` and binds that result to its
  browser-provided `documentId`. `webNavigation.onCommitted` binds each top-level `documentId` to
  its site and lets a child document inherit only through a known `parentDocumentId`; nested-frame
  and tab-associated-worker requests must match that exact document ancestry. A new top-level
  commit retires the tab's older bindings. Bindings are bounded; eviction is identity-unavailable.
  `documentUrl` remains higher precedence than `originUrl`, but `originUrl` alone is insufficient
  because Firefox may report an intermediate CSS resource there. Subresource redirects retain the
  committed top-level site. Detached workers, absent committed context and opaque top-level parents
  return identity-unavailable. T157 owns cancellation and packet-level no-fallback proof for that
  result; T136 does not represent a Direct descriptor as a block. An asynchronous HMAC completion
  rechecks the exact document binding and becomes unavailable if navigation replaced it.
- `storage.local.isolationProfileId` is 32 random bytes encoded as 64 lowercase hex characters,
  generated once per browser profile and stable across background restarts. Missing state is
  initialized through one serialized write; malformed or unwritable state is unavailable, never
  silently rotated. The request context includes normal/private mode and the browser-provided
  `cookieStoreId`, so those contexts do not share an identity.
- The HMAC key is the exact bearer-token string. The UTF-8 message is
  `JSON.stringify(["stargate-isolation-v1", profileId, mode, cookieStoreId, typedSite])`, where
  `mode` is `normal` or `private` and `typedSite` begins `dns:`, `onion:`, `ipv4:` or `ipv6:`.
  The username is `sg1:` followed by the full 64-character lowercase hex HMAC-SHA-256 tag: exactly
  68 ASCII bytes, within RFC 1929's 255-byte limit. A request snapshots token generation and all
  tuple inputs; an asynchronous completion after token change is identity-unavailable. The browser
  still sends the bearer only as the DP-facing password. The DP forwards the username intact and
  an empty password to Tor, so neither the bearer nor its literal bytes cross that boundary.

The fixed reference vector is derived independently of the extension with Python's standard
library. It uses `token = '0f1e2d3c' * 4`, `profileId = '11' * 32`, normal mode,
`firefox-default`, and `typedSite = 'onion:' + ('abcd2345' * 7) + '.onion'`:

```bash
python3 -c "import hashlib,hmac,json; token=('0f1e2d3c'*4).encode(); profile='11'*32; onion='abcd2345'*7+'.onion'; message=json.dumps(['stargate-isolation-v1',profile,'normal','firefox-default','onion:'+onion],separators=(',',':')).encode(); print('sg1:'+hmac.new(token,message,hashlib.sha256).hexdigest())"
```

The required output is
`sg1:1940cde7068246610f120ee0926ad88113942aa2e83d71ba649deab843077a06`.

Different valid tuples must produce different usernames subject to HMAC-SHA-256 collision
resistance; equal tuples are stable but Tor is not required to reuse a circuit. Token rotation
starts a new authenticated-device partition. Reusing one token on multiple devices identifies them
as one authenticated device, and copying a browser profile can copy its profile id; onboarding and
T155 evidence must state those limits.

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
