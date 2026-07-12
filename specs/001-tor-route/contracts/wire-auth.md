# Contract — Inter-Plane Wire Authentication and Versioning

**Status**: Phase 2 foundational contract document (T095). **Binding on T038,
T045, T050, and every later feature that adds an inter-plane RPC.**

**Scope.** This document completes the wire contract that
`contracts/control-grpc.md` and architecture spec §5.4 left underspecified:
Ed25519 X.509 certificate derivation, peer public-key pinning, certificate
validity policy, UDS authority/SAN handling, key ownership, and the
authenticated gRPC metadata carrying protocol major/minor plus capabilities.
It exists because review `sol-review.md` M5 showed the package name
`stargate.v1` is not a runtime version negotiation and T022 marked done while
deferring every load-bearing transport invariant to "impl detail"; without a
pre-implementation contract, T038/T045/T050 would invent the wire shape and
the regression tests would have nothing to pin.

Constitution anchors: **Principle II** (versioned, authenticated inter-plane
contract) and **Principle VII** (contract test-first). Arch anchors: §4.3
(key ownership), §5.3 (versioning), §5.4 (transport and authentication), §5.5
(schema-version handshake row 4).

The contract is **consumed verbatim** by the implementation tickets (T038 §CP
server + ReloadTokensClient, T045 §DP server + WatchEvents client, T050 §DP
main boot order). Those tickets add no wire-shape detail; they reference this
document's section numbers.

---

## 1. Cryptographic primitives

| Primitive | Choice | Source |
|---|---|---|
| Key algorithm | Ed25519 (PKCS#8 PEM, unencrypted) | arch §4.3; `scripts/subcommands/init` |
| Cert signature algorithm | Ed25519 (`cert.SignatureAlgorithm = Ed25519`) | derived from the key |
| Cert chain length | Exactly 1 (self-signed) | §2.2 below |
| Peer trust anchor | The pinned peer public key (`/etc/stargate/keys/<peer>.pub`), **not** a CA / hostname | §3 below |
| Transport | TLS 1.3 over the Unix-domain socket (`unix://<path>`); mutual TLS | arch §5.4 |

Ed25519 is the only signature algorithm on the wire. A future migration (e.g.
to a post-quantum signature) is a `stargate.v2` major-version bump with a
documented migration test (arch §5.3; Constitution Principle II).

---

## 2. X.509 certificate derivation

### 2.1 When and where

Each plane derives its **own** self-signed certificate from its **own**
private key at **process startup**; the certificate is held in process memory
only and is never persisted to disk. This decouples certificate validity from
the long-lived key material in `stargate-keys` (Constitution Principle VI —
the on-disk artefact set stays reproducible and auditable; transient certs do
not enter the named volumes and never need cross-plane synchronisation).

| Plane | Reads at startup | Derives | Hosts TLS on |
|---|---|---|---|
| Control plane | `/etc/stargate/keys/cp.priv` | `cp` self-signed cert | `/run/stargate/control.sock` (the socket it `bind(2)`s per `contracts/control-grpc.md` §"Socket topology") |
| Data plane | `/etc/stargate/keys/dp.priv` | `dp` self-signed cert | `/run/stargate/dp.sock` (the socket it `bind(2)`s) |

Both planes also read the peer's public key from `/etc/stargate/keys/<peer>.pub`
to build the peer-pin verifier (§3).

### 2.2 Certificate fields

The derived certificate is a minimal self-signed X.509 v3 leaf. Fields:

| Field | Value | Why |
|---|---|---|
| `Version` | 3 | X.509 v3 is required for SAN extensions. |
| `SerialNumber` | `0` | Not load-bearing — the peer-pin (§3) is the trust decision, not the serial. Setting a fixed value keeps the derived cert byte-deterministic modulo NotBefore/NotAfter, which simplifies reproducibility auditing (Constitution VI). |
| `SignatureAlgorithm` | `Ed25519` | §1. |
| `Issuer` / `Subject` | `CN=<plane>` (`CN=stargate-cp` or `CN=stargate-dp`) | Self-signed ⇒ `Issuer == Subject`. The CN is informational only; it is NOT the trust anchor (§3). |
| `NotBefore` | `now - 5 min` | 5-minute negative skew window absorbs clock drift between the two containers in the compose stack without widening to a permissive "anytime" window. The window is bounded and named here so a future operator changing it lands in a review, not silently. |
| `NotAfter` | `now + 30 days` | 30-day validity. The cert is re-derived on every plane restart, so the practical lifetime is "until next plane restart, capped at 30 days". Short enough to bound the value of a stolen in-memory cert; long enough that a plane that does not restart for a month still has a valid cert (the §5.5 cold-start path does NOT depend on the CP being up). 30 days < the operator-relevant "I restart my stack roughly monthly" cadence for self-hosted privacy tools. The choice and the rotation residue are recorded in `SECURITY-DECISIONS.md` (T095) and `THREAT-MODEL.md` §5.13. |
| `KeyUsage` | `DigitalSignature` | The only usage Ed25519 keys service on this channel. |
| `ExtKeyUsage` | `ServerAuth, ClientAuth` | Both planes act as TLS client (the dialer) AND TLS server (the listener) on different sockets — each plane's single cert must authorise both roles. |
| `DNSNames` | empty | UDS peer verification does NOT use DNS. |
| `URISANs` | `spiffe://stargate.local/cp` (control plane) / `spiffe://stargate.local/dp` (data plane) | A URI SAN identifying the plane. The `cp`/`dp` token is the same canonical short form used in the keyfile names (`cp.priv`/`dp.priv`, §6.1) and the Subject CN (`CN=stargate-cp`/`CN=stargate-dp`), so every identifier column in this contract names the same entity with the same token. The peer-pin check (§3) is load-bearing; the URI SAN exists so a future weakening that replaced peer-pin with hostname verification would still constrain the accepted identity to the named plane (defence-in-depth against an accidental verifier downgrade). The SVA-1.1 SPIFFE-style scheme is chosen because it carries no DNS meaning and is unambiguous about being a workload identity, not a network name. |

A plane that fails to read its private key, fails to parse the key, or fails
to derive the certificate treats it as a **startup error** (CP) or a
**degraded-mode warning** (DP keeps routing per Constitution Principle II;
the §5.5 cold-start path remains in effect for proxy traffic).

### 2.3 Determinism note (Constitution VI)

Aside from `NotBefore` / `NotAfter`, the derived certificate is byte-identical
across restarts against the same key. An auditor comparing two startup
captures need only account for the validity window; this is the analogue of
`BUILD-DIFFS.md`'s "expected variations" discipline for a runtime artefact.

---

## 3. Peer public-key pinning

### 3.1 The trust decision

Peer authentication is **public-key pinning**, not CA-chain validation, not
hostname verification. The verifier:

1. Receives the peer's TLS cert during the handshake.
2. Extracts the DER `SubjectPublicKeyInfo` from the peer cert and decodes it
   to the raw 32-byte Ed25519 public key.
3. **Re-reads** the pinned peer public key from
   `/etc/stargate/keys/<peer>.pub` (mode `0644`, per arch §4.3 and the
   installer) **fresh from disk on every TLS handshake** — the verifier
   MUST NOT cache the pinned public key across handshakes (closing the
   file handle after each read). This is what makes §6.2 key rotation
   live without a peer-plane restart: after the operator replaces
   `<peer>.pub` and restarts the rotated plane, the peer plane picks up
   the new pin on its very next dial. An implementation that hoists the
   read to process startup and caches the key in the verifier closure
   breaks both the rotation-availability path AND the key-compromise
   incident-response path, and is a contract violation. (Runtime row R9
   in T095 §Notes gates this property once impl lands.)
4. Decodes the PEM-wrapped `SubjectPublicKeyInfo` from `<peer>.pub` to the
   same raw 32-byte Ed25519 public key.
5. Accepts the handshake **iff** the two raw 32-byte keys are byte-equal.

**Encoding pin (avoids DER-vs-PEM comparison ambiguity).** The comparison
is on the **raw 32-byte Ed25519 public key**, not on the DER
`SubjectPublicKeyInfo` wrapper and not on the PEM text. Step 2 extracts
the raw key from the cert's `SubjectPublicKeyInfo`; step 4 PEM-decodes the
on-disk `*.pub` and extracts the raw key from the resulting
`SubjectPublicKeyInfo`; step 5 compares the two 32-byte buffers. Both Go
(`crypto/x509`) and Java (`X509Certificate.getPublicKey().getEncoded()` →
`SubjectPublicKeyInfo`, then Ed25519-specific decode) expose the raw key
bytes; the implementer MUST normalise to the raw 32-byte form on both sides
before the comparison. A comparison of PEM text to DER bytes (always
mismatches → all handshakes fail) or of SPKI wrappers that differ in
tag/length encoding (false mismatch) is an implementation bug.

CA-chain validation (`x509.Verify` with a root pool) is **not** used. Each
side configures its TLS peer verifier with a custom `VerifyPeerCertificate`
hook that performs the byte-equal pin check and ignores system roots
entirely. The single-self-signed-cert design means there is no chain to
build.

### 3.2 Why pin the key, not the cert

A pin on the full DER cert would couple validity to `NotBefore`/`NotAfter`
and the (deterministic but skew-dependent) validity window. Pinning on the
**public key** lets each side rotate its transient in-memory cert on every
restart without coordinating with the peer; the pin holds across restarts as
long as the on-disk keypair is unchanged. Replacing the on-disk keypair is
the operator-visible rotation event — see §6.

### 3.3 Failure behaviour

- A peer cert whose extracted public key does not byte-equal the pinned
  `<peer>.pub`: the TLS handshake is aborted with `alert: unknown ca` (the
  standard TLS alert for cert-validation failure). No application RPC is
  dispatched.
- A missing or unreadable `<peer>.pub`: treated as a startup error (CP) or
  degraded-mode warning (DP). The DP keeps routing against the upstream dial
  (Constitution Principle II); the CP fails fast.
- A pinned-key file that is not a parseable Ed25519 public key: startup
  error (CP) / degraded-mode warning (DP). The installer (`scripts/subcommands/init`)
  owns the format guarantee; the contract test under
  `tests/contract/stargate-cli/init_test.sh` M4 pins the four key filenames.

---

## 4. UDS authority and TLS verification

The dial/listen address is the literal UDS path (`unix:///run/stargate/dp.sock`,
`unix:///run/stargate/control.sock`). TLS configuration:

| Setting | Value | Why |
|---|---|---|
| `ServerName` / `VerifyPeerCertificate` | custom hook (§3); `ServerName` is NOT used for DNS/hostname verification | UDS has no DNS name. The peer-pin hook is the sole trust decision. |
| `InsecureSkipVerify` (Go `crypto/tls`) | **`true`** AND a `VerifyPeerCertificate` (or `VerifyConnection`) callback installed as the sole verifier. In Go's `crypto/tls`, `InsecureSkipVerify=true` disables normal CA-chain + hostname verification **but still invokes `VerifyPeerCertificate`** — that is precisely why the self-signed-no-DNS-SAN design works. The correct configuration is therefore `InsecureSkipVerify=true` + custom verifier, NOT `InsecureSkipVerify=false` (which would reject the self-signed cert at the system-roots check before the custom hook runs). A configuration with `InsecureSkipVerify=true` and **no** `VerifyPeerCertificate`/`VerifyConnection` callback is a **contract violation** — it accepts any in-`stargate-ipc`-group peer without pin validation (silent auth bypass). T038/T045 cite this paragraph verbatim in the TLS-config comment; the structural test gate (§7) asserts every `InsecureSkipVerify` literal in the Go/Java impl source is co-located with a custom-verifier assignment once impl lands (content-gated under the R1-R9 runtime tier). |
| Min TLS version | TLS 1.3 | arch §5.4 implies modern TLS; pinning to 1.3 removes the TLS 1.2 downgrade surface and the suite-negotiation complexity. |
| Client auth | REQUIRED on both sockets (mTLS) | arch §5.4 "mutual auth". A server that does not request a client cert is a contract violation. |

### 4.1 SAN-vs-pin ordering

A future change that introduced hostname verification (e.g. switching to TCP
transport for a remote profile) MUST verify the URI SAN
(`spiffe://stargate.local/cp` or `/dp` per §2.2) OR introduce a DNS SAN
explicitly authorised by this contract. The pin check (§3) remains
load-bearing in either case. Recording this here so a future "we added TCP,
let's just delete the pin and trust the system root store" patch fails
review.

---

## 5. Authenticated gRPC metadata (version + capabilities)

### 5.1 The metadata fields

Every RPC on both sockets carries three gRPC metadata (HTTP/2 header) entries
on **every** call, set by the dialer and verified by a server interceptor
(§5.3):

| Metadata key | Type | Example | Notes |
|---|---|---|---|
| `x-stargate-proto-major` | decimal uint ASCII | `1` | The major version of the `stargate.v<major>` package the caller compiled against. Derived from the proto package name (currently `stargate.v1` → major `1`). |
| `x-stargate-proto-minor` | decimal uint ASCII | `0` | The minor version. Additive — bumped on each additive proto change. Currently `0`. |
| `x-stargate-capabilities` | comma-separated tokens, ASCII, no spaces | `reload-tokens,watch-events,get-status-minimum` | The closed set of RPCs/features the caller exercises. Used for capability negotiation forwards-compat; the v1 server accepts the union and ignores unknown tokens (a future minor may add tokens; a future major may require new tokens). The v1 closed set is enumerated in §5.4. |

Lowercase header names per HTTP/2 (gRPC metadata is automatically lowercased
by both Go and Java gRPC stubs; the implementation MUST NOT rely on case).

### 5.2 Rejection rule (unknown major)

The server interceptor (§5.3) computes the receiver's own major from its
compiled proto package. For an incoming RPC:

- `x-stargate-proto-major` absent → reject with `codes.FailedPrecondition`
  ("stargate: missing x-stargate-proto-major metadata"). No application
  handler runs.
- `x-stargate-proto-major` not parseable as uint → reject with
  `codes.FailedPrecondition`. No application handler runs.
- `x-stargate-proto-major` < receiver major → reject with
  `codes.FailedPrecondition` ("stargate: peer major %d < server major %d").
  This is the backwards-incompatibility gate — an older peer is rejected
  rather than silently downgrading the RPC behaviour. **Note:** this is
  STRICTER than arch §5.3's narrower mandate ("refuses to handshake if the
  control plane reports a HIGHER major version than it understands"), which
  addresses only the newer-peer direction. The stricter bidirectional rule
  is intentional — it blocks silent downgrade during an asymmetric plane
  upgrade, and compose stacks upgrade together so the rolling-upgrade
  window does not arise in the local profile. A future LAN/VPS profile
  that introduces rolling upgrades MUST revisit this rule and arch §5.3
  together; recording the divergence here so a future operator does not
  read §5.3 as authoritative and relax §5.2.
- `x-stargate-proto-major` > receiver major → reject with
  `codes.FailedPrecondition`. This is the **arch §5.5 row 4** schema-version
  mismatch path: a newer CP offering an unknown major is rejected by the DP
  (and vice-versa); the rejection is logged to the journal and, on the CP,
  surfaces as a startup error. On the DP it MUST NOT degrade proxy
  forwarding (Principle II).
- `x-stargate-proto-major` == receiver major → accept regardless of minor
  (additive minor versions are compatible, arch §5.3). The minor is logged
  for diagnostics but is not a gate.

The `x-stargate-capabilities` field is advisory in v1 (the server accepts
the union and never rejects on capability mismatch in v1); the rejection
machinery is reserved for a future major. v1 implementations MUST still send
the field so the v2 cut can start enforcing it without a wire-shape change.

### 5.3 The interceptor

Both server endpoints (`ControlGrpcService` on the CP, the DP's
`controlclient/server.go`) install a gRPC **server interceptor** (unary AND
streaming) that runs the §5.2 check BEFORE any application handler. The
interceptor is the gate; an RPC that bypasses it (e.g. a handler registered
without the interceptor chain) is a contract violation.

Both client stubs (`ReloadTokensClient` on the CP, the DP's WatchEvents
client) install a gRPC **client interceptor** (unary AND streaming) that
sets the three metadata keys from the compiled-in version constants on
every call. The compiled-in constants live in a single source location per
plane so a future `stargate.v2` bump touches exactly one constant per
binary:

- CP (Java/Quarkus): a `StargateProtoVersion` constants class
  (`major=1`, `minor=0`, `capabilities=...`).
- DP (Go): a `protoversion` package with `Major`, `Minor`, `Capabilities`
  constants.

### 5.4 The v1 closed capability set

The `x-stargate-capabilities` closed set for the `stargate.v1` package as
shipped by the Tor-route feature:

```
reload-tokens         // ReloadTokens RPC
watch-events          // WatchEvents RPC
get-status-minimum    // GetStatus RPC, test-harness-only caller in v1
```

Future features that introduce new RPCs add their token to this set in the
same PR that adds the proto service. A future major may move from
advisory to enforced capability rejection.

---

## 6. Key ownership, rotation, and operator visibility

### 6.1 On-disk ownership (binding — arch §4.3)

| File | Owner UID | GID | Mode | Hosts |
|---|---|---|---|---|
| `/etc/stargate/keys/cp.priv` | `5101` (stargate-cp) | `5100` (stargate-ipc) | `0600` | CP private key |
| `/etc/stargate/keys/dp.priv` | `5102` (stargate-dp) | `5100` (stargate-ipc) | `0600` | DP private key |
| `/etc/stargate/keys/cp.pub` | `5101` (stargate-cp) | `5100` (stargate-ipc) | `0644` | CP public key (read by DP for the pin) |
| `/etc/stargate/keys/dp.pub` | `5102` (stargate-dp) | `5100` (stargate-ipc) | `0644` | DP public key (read by CP for the pin) |

The `stargate-keys` named volume is mounted into both plane containers at
`/etc/stargate/keys`. The `stargate-ipc` supplementary GID is the
kernel-enforced "can-read-the-public-keys" gate; private keys are
owner-read-only (`0600`) so the peer plane cannot read them despite the
shared GID.

### 6.2 Certificate vs key rotation

- **Transient cert rotation**: implicit, on every plane restart, per §2.1.
  No operator action. No on-disk artefact changes. The validity window
  (§2.2) bounds the cert lifetime to 30 days from each restart.
- **Key rotation** (the operator-visible event): replacing the on-disk
  `cp.priv`/`cp.pub` / `dp.priv`/`dp.pub` keypairs. This is currently
  operator-manual (no automated rotation in v1 — see §Out-of-scope in the
  T095 ticket and `SECURITY-DECISIONS.md` entry). A rotation MUST replace
  both the private and public file for a plane atomically (write-tmp +
  rename) and MUST be followed by a plane restart so the new key is loaded.
  The peer plane picks up the new pin on its next dial (CP → DP: the CP's
  next `ReloadTokens` push; DP → CP: the DP's next `WatchEvents`
  reconnect) because the verifier re-reads `<peer>.pub` on every handshake
  (§3.1 step 3). **Rotation order** (avoids an availability window where
  the peer re-reads the new pin but the rotated plane still presents the
  old cert): **stop** the rotated plane, **rename** the new keypair into
  the volume atomically (write-tmp + rename both `*.priv` and `*.pub`),
  **start** the rotated plane. The rotated plane must be DOWN during the
  rename so it cannot serve handshakes with the old key while the peer
  already pins the new one. The per-handshake re-read (§3.1 step 3) is
  what makes the rotation live without restarting the peer plane; a
  verifier that cached the pin at startup would require a peer-plane
  restart on every rotation — another reason the cadence is pinned in §3.1.

### 6.3 Operator visibility

The 30-day cert validity window, the 5-minute negative skew window, and the
no-automated-rotation residue are operator-visible facts documented in
`THREAT-MODEL.md` §5.13 and `SECURITY-DECISIONS.md` (T095 entry). An operator
who restarts the stack on a < 30-day cadence never sees a cert expiry; an
operator who runs a stack longer than 30 days without a restart MUST restart
both planes before the oldest in-memory cert expires. There is no in-process
cert-expiry warning in v1 — a follow-up feature may add a status-table row.

---

## 7. Tests (binding)

The compose-level regression tests live at
`tests/contract/compose/inter_plane_wire_test.sh` (T095). They gate both the
structural preconditions (compose-file mounts, Dockerfile UID/GID, key-file
ownership/mode, contract-document cross-consistency) and the runtime
properties (peer-plane dial success, out-of-group `EACCES`, wrong-key
rejection, major-mismatch rejection, minor compatibility, no TCP transport,
CP restart survival). The runtime rows self-skip until the implementation
tickets (T038/T045/T050) land, then self-lift — the same content-gate
discipline T022 used for the local-process tier.

T022's local-process tier (`tests/contract/control-grpc/transport_test.go`)
remains the home for the rows that do NOT need distinct UIDs: row 1 (no TCP
LISTEN beyond the proxy port), row 2 (role separation via `bind(2)`), and
row 10 (production-caller-absent `GetStatus` regression grep). This document
does NOT redefine those rows; it adds the compose-level rows T022 deferred.

---

## 8. Out-of-scope (for T095)

- Remote TCP gRPC transport. The local profile is UDS-only (arch §5.4). A
  LAN/VPS profile may introduce an authenticated TCP surface; that is a
  future feature and a `stargate.v<major+1>` consideration (§4.1).
- Automated certificate rotation. The on-disk keypair is operator-replaced
  (§6.2); an automated-rotation feature (CP-driven key generation + atomic
  install + plane restart) is deferred.
- A `Handshake` RPC. Version + capabilities ride gRPC metadata on every RPC
  (§5) rather than a one-shot handshake call. A separate handshake RPC
  would add a round-trip and a "negotiated then forgot" failure mode; the
  per-RPC metadata is stateless and the §5.3 interceptor is the single
  enforcement point. (review `sol-review.md` M5 recommended "an explicit
  `Handshake` RPC **or** authenticated transport metadata"; this contract
  picks the metadata option and records why here.)
