<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SECURITY-DECISIONS.md

Append-only log of **accepted-finding rationales** and **supply-chain trust
decisions** for Stargate. This file is the durable, human-auditable record
that AGENTS.md, CONTRIBUTING.md §"Review escalations", and THREAT-MODEL.md
§871/§1173 already cite as the canonical home for these decisions.

**Append discipline (binding on every future PR that edits this file):**

- **Ordering.** Dated decision entries are kept in **reverse-chronological
  order (newest first)**, directly below this preamble — a new entry is
  inserted at the top of the dated-decisions region, NOT appended below
  older ones. The "Reserved: adversarial-review findings" section is pinned
  at the **absolute bottom** of the file and is the only non-dated section;
  dated entries never go below it.
- An entry is **never deleted**, and **an entry's body text is immutable once committed**.
  Any change (correction, softening, expansion, or retraction) MUST land as a
  new dated superseding entry with a `Superseded by:` back-link
  from the original, NEVER as an in-place edit of the original body. This
  binds reviewers: a PR that edits a dated entry's body in place (rather than
  superseding) MUST be rejected, even if every contract test stays green.
  When a decision is superseded, the superseding entry adds a
  `Superseded by:` line pointing to the new entry; the original text stays
  verbatim so the audit trail is intact. (Constitution VI — the audit trail's
  integrity against silent weakening cannot rest on the contract tests alone,
  because the tests assert keyword presence + artifact cross-consistency, not
  prose integrity.)
- Every Blocker/Major review or `stargate-redteam`/`stargate-perf` finding
  that is **accepted** (mitigated, risk-accepted, or deferred-with-rationale)
  gets an entry here in the same PR that accepts it (CONTRIBUTING.md §398).
- Factual claims that reference build artifacts (fingerprints, digests) MUST
  match the artifact exactly; the contract tests under
  `tests/contract/security-decisions/` cross-check the load-bearing ones and
  fail the gate on drift.
- This file documents *decisions and their rationale*; it is not a
  duplicate of THREAT-MODEL.md (the model) or the contract tests (the
  enforcement). Where a decision rests on a threat-model row, cite the row.

---

## 2026-07-15 — Bearer-token verifier: HMAC-SHA-256 + install-time pepper (T092)

**Accepted findings:** sol-review **B5** (Blocker — per-request Argon2id is
an allocation-based denial-of-service path) and **M1** (Major — token
lifecycle state is internally inconsistent). Recorded in
`review/sol-review.md` §B5 and §M1.

**Decision.** Replace the Argon2id bearer-token verifier with
**HMAC-SHA-256 over a dedicated 32-byte install-time pepper** shared by the
control plane and data plane. The candidate's tag is computed once per
request and compared with `crypto/subtle.ConstantTimeCompare` against every
verifier in the current generation (no short-circuit). The pepper never
enters `dp-snapshot.json`, the inter-plane RPC, any log, or any audit
`detail_json`. Full contract in `specs/001-tor-route/data-model.md` §1.

**Why this is the right trade (B5).** A bearer token is a uniformly random
128-bit value. Offline brute-force of a 128-bit secret is infeasible at
*any* verifier speed (the 2^128 space dwarfs any feasible guess rate), so
the slow-KDF property Argon2id provides is worthless for a random token —
Argon2id earns its keep on *low-entropy human passwords*, which bearer
tokens are not. Meanwhile the prior 64 MiB / parallelism-4 Argon2id
allocation was an unbounded memory-DoS vector:
`golang.org/x/crypto/argon2.IDKey` allocates its full `memory` block slice
up front, so 200 concurrent one-token auths allocate ~`200 × 64 MiB =
12.8 GiB`, reachable by any local process via the loopback proxy. HMAC auth
makes per-request allocation O(1) regardless of token-list size N or
concurrent flood size. The B5 finding is falsified by **T079a's extended
design (peak-RSS + unauthenticated-flood bounds, not pool-fill timing
alone)** — pinned as a test by T093 before production implementation
resumes (Principle VII). The retired N ≤ 4 cap is gone: HMAC auth is
O(1) hash work per request regardless of N.

**Why the lifecycle fix (M1).** The prior design had no persistent
generation source (a CP restart re-hashed and pushed generation 1, which
would be stale the moment the DP accepted any generation ≥ 1 and silently
revoke every client), treated `tokens.yaml` I/O failure as revoke-all, and
required `enrolled_devices` inserts to carry a nonexistent device public
key. T092 introduces: (a) a persistent `token_generation` record the CP
reads at start to propose `last + 1`; (b) a `ReloadTokens` reconciliation
handshake — a stale proposal returns `APPLY_STATUS_STALE_GENERATION` plus
the DP's `current_generation`, so the CP retries with `current + 1`;
(c) failure semantics where missing/unreadable/invalid/unparseable input
makes the CP **not** call `ReloadTokens` (the DP keeps last-known and keeps
serving — Principle II), and only a successfully-parsed explicit
`tokens: []` is revoke-all; (d) a dedicated `configured_tokens(label,
verifier, …)` entity for the manual-YAML path, leaving `enrolled_devices`
(device pubkey NOT NULL) for the future dashboard-enrollment feature;
(e) a narrowed memory-erasure claim that covers only the mutable HMAC
input `byte[]`, not SnakeYAML-materialized immutable `String` values the
loader cannot reach.

**Breaking pre-release contract change (no `stargate.v2` bump).** The proto
`TokenHash { hash; salt }` becomes `TokenVerifier { verifier }` (the
per-token `salt` field is dropped — a single shared pepper makes it dead)
and `ReloadTokensResponse` gains `current_generation`. Dropping a field
from a proto3 message is a breaking change. Per the **pre-release
amendment doctrine** established by T091 / T099 (constitution
`.specify/memory/constitution.md` Sync Impact Reports): semver-on-
amendments and the 7-day public comment window become BINDING only at
first public release; the project has shipped no binary and has no public
remote with consumers, so the change is recorded HERE as an amendment NOTE
rather than as a `stargate.v2` bump. The formal governance flow (PR +
comment window) applies to the same change once the repo is public. This is
the same boundary used for the Principle III bullet-3 amendment (T091) and
the Principle VI Tor-reproducibility tier (T099); it is not a new
exception. The proto comment block and `contracts/control-grpc.md`
§"ReloadTokens" carry the amendment NOTE in lock-step.

**Residue / supply-chain decision (the pepper is a new secret).**

- **Ownership / mode.** `/etc/stargate/pepper.key`, generated once by
  `scripts/stargate init` (`openssl rand -bytes 32`), mounted from the
  `stargate-keys` volume, owned by the reading plane's UID, group-readable
  by `stargate-ipc` (GID 5100), mode `0640` — the same ownership/mode
  scheme as the ed25519 inter-plane keypairs in that volume.
- **Threat-model row.** Pepper compromise + a `dp-snapshot.json` leak lets
  an attacker test candidate tokens offline at HMAC speed. Mitigated by
  the 128-bit token entropy: even at billions of HMAC/sec, batch
  brute-force of a 128-bit space is infeasible — the property Argon2id
  was over-engineered to defend (needlessly, for a random token). Recorded
  in `THREAT-MODEL.md` §5.14.
- **Constant-time over the verifier set** is functionally tested in T093;
  adversarial confirmation of the timing side-channel bound is a
  `stargate-redteam` residue (functional tests do not fully capture timing).
- **Backup / export / wipe / rotation.** The pepper MUST be in any operator
  backup of `stargate-keys` (without it every persisted verifier is
  uncomputable and all stored tokens effectively revoke); `export` warns
  the bundle now carries a secret; `wipe` removes it alongside keys and
  state; rotation is operator-initiated (re-pepper → re-HMAC every
  configured token → bump generation). T088 wires provisioning, export,
  wipe, and rotation.

**Downstream artefacts amended in lock-step (acceptance #7):**
`data-model.md` §1 (full contract); `spec.md` FR-006/FR-013/FR-017/FR-018;
`contracts/control-grpc.md` §"ReloadTokens"; `proto/stargate/v1/control.proto`;
`plan.md` Constitution Check rows II/V/VII + Scale/Scope + SC-005 model;
arch §6 (configured_tokens + token_generation) + `V001__init.sql`;
`THREAT-MODEL.md` §5.14. Dependent tickets refined: T020/T020a/T035/T035a/
T041/T044/T046/T079a/T088. T093 pins the contract as tests before T035/
T041/T044/T046 resume.

## 2026-07-12 — Tor `torrc` image-baking contract (T089 static-startup amendment)

**Context.** Review `sol-review.md` B2 found that Compose starts the
`tor` service before `stargate-control`, while the Tor entrypoint reads
its config from the shared `stargate-tor-config` volume
(`sidecars/tor/Dockerfile:120-124`). A control-plane-rendered `torrc`
written later does not make a running Tor reload it, so Tor could start
with the Debian default config (no `IsolateSOCKSAuth`, no `SafeLogging 1`)
or fail because the expected file is absent. The last case is a privacy
failure, not just an availability issue. T089 amends the contract so the
static Tor-only slice bakes the exact safe `torrc` into the image at
build time and does not claim the control plane renders it at boot
(Constitution Principle II — Tor startup must not depend on CP
availability or Compose timing).

**Decision (T089 §Acceptance #1–#2, amending FR-011 / `contracts/torrc.md`
/ `data-model.md` §6 / plan Constitution Check / THREAT-MODEL §4.2).**

- The byte-pinned safe `torrc` from `contracts/torrc.md` §"Rendered
  file" is **baked into the Tor image at build time** (`COPY` into
  `/etc/tor/torrc`, T087) and loaded by the entrypoint at container
  start. The control plane does NOT render `torrc` at boot in this slice.
- `DataDirectory /var/lib/tor` is now **explicit** in the byte template
  (contracts/torrc.md invariant #11, flipped from "NO override"). The
  entrypoint runs `tor -f /etc/tor/torrc` WITHOUT
  `--defaults-torrc /etc/tor/torrc-defaults`, so Debian's defaults file
  (which would set `DataDirectory /var/lib/tor`) is never loaded
  (sol-review B2+M3 / T087). Without the explicit directive Tor falls
  back to its compile-time default `$HOME/.tor` = `/var/lib/tor/.tor`,
  landing the control cookie at `/var/lib/tor/.tor/control_auth_cookie`
  — not the `/var/lib/tor/control_auth_cookie` the healthcheck and
  T062's control-port helper assume. Pinning it makes the cookie path
  deterministic.
- Control-plane-rendered `torrc` (atomic write into `stargate-tor-config`
  by `TorrcRenderer`, T037) is **deferred** to a dynamic-config feature
  (bridges toggle, live reload). T037 is deferred with it
  (`deferred_reason: spec-amend`, `deferred_on: T089`). The
  `stargate-tor-config` volume's CP-RW / Tor-RO role is not used for v1
  boot (data-model.md §6 amended).

**Why accepted for the local profile.** Baking the torrc into the image
is the B2 recommendation and is strictly safer than a CP-rendered torrc
under Compose's `tor`-before-`stargate-control` ordering: it removes the
boot-coupling Principle II forbids and guarantees the privacy directives
(`IsolateSOCKSAuth`, `SafeLogging 1`, `UseBridges 0`, no `Bridge` lines)
are present at Tor's first boot. The cost is that a torrc change now
requires an image rebuild (T087's cold-volume regression test gates the
image `/etc/tor/torrc` == golden), which is the right cadence for a
static slice and is no barrier to the future dynamic-config feature
re-introducing CP rendering behind a Tor-depends-on-CP-health ordering.

**Residue / what changes for dynamic config.** A future feature that
re-introduces control-plane-rendered `torrc` MUST (a) re-open the
ownership decision recorded here, (b) remove the Compose cycle per B2's
recommendation (start CP without Tor, make CP healthy only after an
atomic render, make Tor depend on that health condition) rather than
relying on Compose timing, and (c) supersede this entry with a dated
superseding entry + `Superseded by:` back-link. The `config_render`
detail value in `contracts/control-grpc.md`'s `SidecarEvent` vocabulary
is already reserved for the `CONFIG_RELOADED` event that feature will
emit.

**Enforcement cross-reference.**

- Contract document: `specs/001-tor-route/contracts/torrc.md` §"Rendered
  file" + invariant #11 (amended by T089).
- Byte-for-byte gate: `tests/contract/torrc/render_byte_match_test.go`
  (T029) — `wantTorrc` golden updated in lock-step with the contract
  template; `tests/contract/torrc/invariants_test.go` (T030) Row 11
  flipped to assert `DataDirectory /var/lib/tor` present.
- Image-side gate (T087, not yet landed): cold-volume regression test
  reads `/etc/tor/torrc` out of the image without harness-seeded config
  and asserts it equals the golden; also asserts Docker
  `State.Health.Status == healthy` and the authoritative cookie path.
- Threat model: `THREAT-MODEL.md` §4.2 "Stargate-specific notes" (image-
  baked torrc note added by T089).
- Downstream consumers: T087 (implement the amended image, healthcheck,
  cold-volume test), T037 (deferred), T041 (startup sequence no longer
  renders torrc).

---

## 2026-07-12 — Inter-plane X.509 certificate validity policy (T095 wire-auth contract)

**Context.** T095 completed the inter-plane wire contract
(`specs/001-tor-route/contracts/wire-auth.md`) that arch §5.4 had left
underspecified and that review `sol-review.md` M5 flagged as a Major finding
("Inter-plane version/auth claims have no complete wire contract"). The
contract specifies that each plane derives a self-signed X.509 cert from its
on-disk Ed25519 private key at process startup, holds it in memory only, and
re-derives it on every restart. This entry records the accepted policy
decisions around validity and rotation so the residue is operator-visible
per Constitution V.

**Finding (T095 §Analysis residue).** The certificate validity window and
the absence of automated key rotation are operator-visible facts that the
threat model and this log MUST carry — they bound the value of a stolen
in-memory cert and the operator-action cadence for key replacement.

**Accepted policy (T095 §2.2 + §6).**

- `NotBefore = now − 5 min` (negative-skew window for compose-stack clock
  drift), `NotAfter = now + 30 days`. The cert is re-derived on every plane
  restart, so practical lifetime is "until next plane restart, capped at 30
  days".
- Certs are never persisted; the on-disk artefact set stays byte-reproducible
  modulo the keyfiles themselves (Constitution VI).
- Key rotation (replacing `cp.priv`/`cp.pub` / `dp.priv`/`dp.pub` in the
  `stargate-keys` volume) is **operator-manual in v1**. Automated rotation
  (CP-driven key generation + atomic install + plane restart) is explicitly
  out of scope for T095 and for the Tor-route feature; it is a future feature
  with its own threat-model entry.

**Why accepted for the local profile.** THREAT-MODEL §3.1 treats same-host
code execution as game-over; the in-memory cert's 30-day window does not
expand that surface. The pin-on-public-key design (`wire-auth.md` §3) means
a stolen cert without the matching private key is worthless, and a stolen
private key without a plane restart cannot mount a MITM (the peer-pin check
fails on the attacker's key). **The binding residue is key compromise, not
cert compromise**: an attacker who reads a plane's process memory obtains
the long-lived private key (loaded from `*.priv` for handshake signing) and
can impersonate the plane indefinitely — minting fresh, currently-valid
certs from the stolen key — until the operator manually rotates the on-disk
keypair. The 30-day cert-validity window does NOT bound this exposure; a
monthly plane restart does NOT help (the same key is re-loaded). This is no
worse than the §3.1 same-host assumption in the local profile; it is the
operator's keypair-rotation lever (§6.2) that bounds the incident, not the
cert validity window.

**What changes for LAN/VPS.** Under a LAN/VPS profile the inter-plane
channel may cross a network (a future feature, see `wire-auth.md` §4.1 and
§8). The 30-day cert window and the operator-manual rotation cadence MUST
be re-reviewed against a network-positioned adversary at that point; the
current acceptance is local-profile-scoped. A LAN/VPS feature that
introduces TCP transport MUST revisit §4 of `wire-auth.md` (SAN verification
vs pin) and this entry in the same PR.

**Enforcement cross-reference.**

- Contract document: `specs/001-tor-route/contracts/wire-auth.md` (T095).
- Compose-level regression test: `tests/contract/compose/inter_plane_wire_test.sh`
  (T095) gates key-file ownership/mode, peer-plane dial success, out-of-group
  `EACCES`, wrong-key rejection, major mismatch, minor compatibility, no TCP
  transport, and CP-restart survival. Runtime rows self-skip until T038/T045/
  T050 land.
- Threat-model residue: `THREAT-MODEL.md` §5.13.
- Downstream consumers: T038 (CP gRPC server + ReloadTokensClient), T045 (DP
  gRPC server + WatchEvents client), T050 (DP main boot order) — each
  consumes `wire-auth.md` verbatim per T095 §Acceptance #5.

---

## 2026-07-06 — docker-socket-proxy `CONTAINERS=1` read surface (corrective supersession, T019c redteam)

**Corrects (partially supersedes)** the 2026-07-04 entry "docker-socket-proxy
trust rationale (auxiliary container)" below. Scope of the correction: the
characterization of the **read** surface the env-flag filter grants.
Everything else in the 2026-07-04 entry — property bought, residual trust,
exposure surface, `:ro` caveat, mitigations, release-blocker — stands
unchanged.

**Finding (stargate-redteam at T019c, 2026-07-06, major).** The 2026-07-04
entry states the CP "can `GET /events` and `GET /containers/{name}/json`
… and nothing else", and the T019c ticket residue as first drafted narrowed
the `CONTAINERS=1` over-grant to notice-log exposure. Both understate the
granted surface. The proxy's env-flag ACLs are **section- and
method-granular**, not path-granular: `CONTAINERS=1` with `POST=0` allows
**every GET/HEAD under `^(/v[\d.]+)?/containers`**, including:

- `GET /containers/{id}/archive?path=…` — tar-export of any file from ANY
  container's filesystem (e.g. Tor's entry-guard state under `/var/lib/tor`,
  documented sensitive in THREAT-MODEL §4.2);
- `GET /containers/{id}/json` — full inspect (env vars, mounts, network
  config) of every container, not only `tor`;
- `GET /containers/json`, `/top`, `/logs`, `/stats`, `/changes`, `/export`
  and the rest of the read-only containers section.

**Why the local-profile accept still holds.** THREAT-MODEL §3.1: the local
profile assumes same-host code execution is already game-over, and the CP
already mounts the keys volume directly. A CP compromise reading guard state
via `/archive` adds no capability a same-host attacker lacks. The property
the proxy buys — **no write surface, so no host-root pivot** (`POST=0`
denies every non-GET/HEAD verb) — is unaffected and remains runtime-gated
by T019c's `PostSurfaceDenied`.

**What changes for LAN/VPS.** The 2026-07-04 entry's release-blocker
paragraph inherits this correction: under a LAN/VPS profile a CP compromise
is NOT co-located with the host, so "arbitrary container-filesystem read of
every container" (entry-guard state, rendered torrc, CP state DB) is a
materially larger exfiltration surface than "read tor's notice-level
stdout". The mandated LAN/VPS revisit MUST scope against the
section-granular grant, not the two-endpoint shorthand.

**Enforcement cross-reference.** `tests/contract/sidecar-proxy/
lockdown_test.go` (T019c) runtime-gates the deny surface; its
`DenyByDefaultSurface` sub-test was hardened in the same PR to probe an
API-version-prefixed path (`/v1.43/version`) and `HEAD /_ping`, so an
upstream image bump that regresses the version-prefix regex or the method
filter fails the test rather than silently widening the surface (T019c
redteam minor finding, resolved in-code).

## 2026-07-04 — docker-socket-proxy trust rationale (auxiliary container)

**Superseded by:** §"2026-07-06 — docker-socket-proxy `CONTAINERS=1` read
surface (corrective supersession, T019c redteam)" above — read-surface
characterization only; the remainder of this entry stands.

**Decision.** Stargate's local profile runs a digest-pinned
`tecnativa/docker-socket-proxy` container as the **only** service that
mounts `/var/run/docker.sock` from the host. The control plane (CP)
reaches it as `http://docker-socket-proxy:2375` over the compose-internal
network (compose service key `docker-socket-proxy` in
`compose/docker-compose.local.yml`, no host `ports:` mapping). This entry
documents **why a privilege-isolating proxy is used instead of mounting
the docker socket directly into the CP container**, the property the
proxy buys, the residual trust, and the mitigations recorded. The Tor
sidecar entry below (T017) covers a different concern (Tor binary
provenance) and is unaffected by this entry.

**Property bought.** A compromise of the Quarkus control plane (YAML
parser, gRPC server, future admin UI) does NOT escalate to host root,
because the CP holds no `docker.sock` handle and can only invoke the
GET-only surface the proxy exposes (`EVENTS=1`, `CONTAINERS=1`, all
other endpoint flags unset → default-deny; `POST=0` forbids container
spawn/kill/exec). Without the proxy, the CP would hold the host's
`docker.sock` handle directly, and any CP compromise (a malicious YAML
payload reaching a `Process.exec`, a gRPC parsing bug, a future
admin-UI auth bypass) is immediate host root — the Docker daemon runs as
root, and `POST /containers/create` with a bind-mount of `/` is a
one-step pivot. The proxy moves that pivot out of the CP's reach: the
CP can `GET /events` and `GET /containers/{name}/json` (the surface
`SidecarMonitor` per T039 depends on) and nothing else. **The same
property holds for the DP and Tor** (both also on `stargate-internal`,
see "Exposure surface" below) on the same condition — the proxy's
env-flag filter + HAProxy frontend + base closure behave as documented.
**The lockdown is runtime-verified by T019c when it lands; until then
it is asserted statically** by `compose/docker-compose.local.yml`'s
env-block + the `local_compose_test.sh` shape regex (Mitigation #2 +
§Analysis R2).

**Residual trust (Principle V).** The proxy itself IS in the TCB: **any
code-execution inside the proxy container** is host-root-equivalent,
because the proxy holds the `docker.sock` handle and `POST
/containers/create` with a bind of `/` is a one-step pivot — the Docker
daemon does the bind as root regardless of the UID of the process
issuing the call. "Code-execution inside the proxy" is wider than
"bypass of the env-flag filter": the env-flag filter is one layer in a
stack that also includes HAProxy (the proxy's HTTP frontend — verified
at T017a commit time via `docker image inspect` of the pinned image:
entrypoint `docker-entrypoint.sh`, cmd `haproxy -f
/usr/local/etc/haproxy/haproxy.cfg`, HAProxy version `2.2.33`,
`Config.User` empty → root per Mitigation #1 below), the
`docker-entrypoint.sh` shell script, the proxy image's base distribution
(per the upstream Dockerfile's `FROM haproxy:2.2-alpine`, which itself
derives from `alpine:3.x` — illustrative TCB enumeration; not
Stargate-side re-verified), and the transitive dependency closure of
all three. An HAProxy parsing bug, a
request-smuggling flaw, an entrypoint quoting bug, or a vulnerability
in the base image's `libssl`/`musl`/`pcre2`/`zlib`/`lua5.3`/etc.
yields code-exec inside the container without ever touching the
env-flag filter — exactly the way Tor's `libssl3` residual rode on
Debian's archive key (T017 residual bullet, §"Tor's transitive
dependency closure"). The proxy image's own transitive-dependency
closure is therefore part of this entry's TCB and sits OUTSIDE the
env-flag filter: a malicious or vulnerable HAProxy or base-image
component (or, for completeness, a future rebuild of
`tecnativa/docker-socket-proxy:0.3.0` at the same tag but a different
sha256 — pinned against by the digest) defeats the property bought,
with no Stargate-side verification reach. **Mitigation:** the digest
pin (Mitigation #1) means the closure is pinned as long as the digest
is pinned; the PR-cadence gate cannot detect a behaviourally-conforming
malicious component in the proxy's closure (same shape as T017 R4 /
libssl3).

This is **NOT** a defence against a local attacker with arbitrary code
execution on the host — THREAT-MODEL §3.1 ("local profile assumes local
code execution is already game-over") covers that. The residual is the
**narrower** claim that a CP-, DP-, or Tor-process-compromise alone
does not, on the happy path where the proxy's filter + frontend + closure
all behave as documented, pivot to host root through the docker socket:
the attack surface shrinks from "any compose-internal-service bug that
reaches the docker.sock handle directly" down to "either an upstream
proxy-component bug OR a service bug that additionally finds a
filter/frontend bypass."

**Exposure surface — three services can reach the proxy, not only the
CP.** Per `tests/contract/compose/local_compose_test.sh` M13, all four
services (`stargate-dp`, `stargate-control`, `tor`, `docker-socket-proxy`)
are attached to the single `stargate-internal` bridge network; the proxy
at `http://docker-socket-proxy:2375` is reachable from the CP, the DP,
and Tor. The property bought above holds for each of the three on the
same condition (the proxy's filter/frontend/closure behave as
documented). **The DP case is the most concerning pivot** because the
DP is the untrusted-bytes boundary (Constitution Principle I — the DP
parses SOCKS5/CONNECT bytes from the browser): a DP parsing bug →
DP-container code-exec → `docker-socket-proxy:2375` → host root is a
strictly more concerning vector than the CP case this entry leads with,
because the DP faces internet-supplied input the CP does not. Naming
the DP explicitly so an auditor does not conclude "the proxy isolates
only the CP." Tor-side compromise is covered by THREAT-MODEL §2.6
(compromised sidecar in the per-route privacy TCB) for the
anonymness-property side; the §2.6 → host-root-via-`docker.sock` pivot
is a Stargate-specific residual that this entry (not §2.6) carries.

**The `:ro` mount suffix is convention-only, NOT a security boundary.**
The `/var/run/docker.sock:/var/run/docker.sock:ro` mount in compose is
retained to document intent, but AF_UNIX sockets have no
kernel-enforced read/write direction — the proxy can still issue
write-direction Engine API requests (`POST /containers/create` etc.)
regardless of the mount mode. The actual enforcement of "observe but
cannot mutate" is the HTTP-level filter inside the proxy (the env-flag
lockdown below), gated at runtime by T019c. This honesty note mirrors
the comment block in `compose/docker-compose.local.yml`; do NOT rely on
`:ro` for isolation here.

**Mitigations recorded:**

1. **Digest-pinned image (Principle IV).** The image is pinned by
   multi-arch OCI index digest, the closest available analogue to "the
   exact tested bytes" across amd64/arm64 hosts:

   `tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2`

   Resolved via `docker buildx imagetools inspect` at T015 `/start` time.
   **Source of truth:** `compose/env/local.env.example`'s
   `DOCKER_SOCKET_PROXY_IMAGE=` line; `compose/docker-compose.local.yml`
   reads it via `${DOCKER_SOCKET_PROXY_IMAGE}`. Bumping is a manual
   promotion: resolve the new digest, update `compose/env/local.env.example`
   AND this entry in one PR, re-run `scripts/ground-check.sh` ONLINE to
   confirm the registry still serves the digest. The contract test
   `tests/contract/security-decisions/docker_socket_proxy_entry_test.sh`
   (T017a AT-1 M5) cross-checks the two locations and fails on drift.
   **Operator-override caveat:** this is the *example* source of truth;
   `scripts/stargate init` (T016) and the BYO-env path both
   write/let-the-operator-edit a gitignored `compose/env/local.env`. An
   operator who overrides `DOCKER_SOCKET_PROXY_IMAGE` in `local.env`
   runs a different image than the one recorded here, and no contract
   test catches the override. Operators MUST re-record any override as
   a superseding entry in this file before deploying.
   *No defense-in-depth user-isolation control is recorded here.* The
   pinned image's `Config.User` is empty (verified at T017a commit
   time via `docker image inspect
   tecnativa/docker-socket-proxy:0.3.0@sha256:9e4b9e7517a6b660f2cc903a19b257b1852d5b3344794e3ea334ff00ae677ac2
   --format '{{.Config.User}}'` → empty = the proxy runs as **root**
   inside its container). This does NOT reduce the host-root-equivalent
   residual (the `docker.sock` handle is the pivot; Docker binds as
   root regardless of the calling UID — see "Residual trust" above);
   recording it only so an auditor does not assume a non-root proxy
   process. A future image bump that adds a `USER` directive would
   change this — verify at bump time via the same `docker image inspect`
   command and supersede this clause if so.
2. **Lockdown env-block + runtime gate (T019c).** The proxy service is
   locked to `EVENTS=1`, `CONTAINERS=1`, all other endpoint flags unset
   (`tecnativa/docker-socket-proxy` defaults unset flags to deny), and
   `POST=0` to forbid spawn/kill/exec. The compose env-block asserts
   the lockdown statically; the runtime lockdown contract test **T019c**
   (parallel Phase-2 ticket, not yet landed) gates it at compose-up
   time. Until T019c lands, the lockdown is asserted only by
   `docker-compose.local.yml`'s env-block and by the
   `tests/contract/compose/local_compose_test.sh` shape regex — see
   §Analysis R2.
3. **Compose-internal only (not reachable off-host).** The proxy service
   has **no `ports:` key** in `docker-compose.local.yml`; it is
   reachable only from the `stargate-internal` compose network, NOT from
   the host network and not from off-host. A non-routable proxy cannot
   be probed by an external attacker — they would need to first
   compromise a service on the `stargate-internal` network (CP, DP, or
   Tor — see "Exposure surface" above) to reach the proxy at all.

**THREAT-MODEL §3.1 cross-reference.** The residual-risk framing here
matches §3.1's "an attacker who gains local code execution can replace
the data-plane binary on disk, swap a sidecar image, or read the
inter-plane keys" — the local profile already assumes local code
execution is game-over, so the proxy-compromise residual is consistent
with the mode's threat model rather than a new assumption. The proxy
narrows the attack surface within that framing: it removes "CP/DP/Tor
bug → host root via `docker.sock`" from the local-attacker playbook on
the happy path where the proxy's filter + frontend + closure behave as
documented.

**Architecture spec §16.1 cross-reference.** `specs/000-architecture/spec.md`
§16.1 ("Auxiliary Infrastructure Containers") documents the same trust
model and explicitly defers the mitigation record to this entry
("Mitigations recorded in `SECURITY-DECISIONS.md` (entry created by
`specs/001-tor-route/` T017a)"). **The two artifacts have drifted on
two points as of T017a commit time** (this entry is the authoritative
resolution; §16.1 is the stale spec-side anchor pending reconciliation):

1. §16.1's mitigation list still names "proxy runs as the unprivileged
   user its upstream image declares" — verified FALSE at T017a (see
   Mitigation #1: `Config.User` is empty, the proxy runs as root).
2. §16.1's release-blocker sentence is CP-only ("The LAN and VPS
   profiles expose the CP to non-localhost callers…"); this entry
   widens it to CP/DP/Tor (see "Release-blocker" below).

Reconciling §16.1 is filed as follow-up **T018** (the sibling arch-spec
amendment ticket, whose mandate already includes "verify at
implementation time that… T017a's `SECURITY-DECISIONS.md` entry remains
the authoritative rationale"). Until T018 lands, §16.1's stale framing
is a known, filed, tracked gap — same shape as the THREAT-MODEL §8.6
gap T017 left for T082 (Constitution V — the model and the decision log
contradict until the spec sync lands). A future change to the proxy
mechanism MUST be revisited in both artifacts in the same PR
(reviewer-enforced today, not gated by an automated test; a follow-up
could add a contract test that diffs §16.1's `docker-socket-proxy`
block against this entry's prose anchors).

**Release-blocker for any future LAN or VPS profile feature spec.**
This mechanism is sized for the **local profile only** — the proxy is
reachable only from the `stargate-internal` compose network (CP, DP,
and Tor; see "Exposure surface" above), so its exposure surface is
CP/DP/Tor-process-compromise, with the DP the most concerning pivot
since it faces internet-supplied input the CP does not. The local
profile binds no non-loopback interface, so no off-host caller can
reach the proxy. The LAN and VPS profiles expose the CP (and the DP,
under any future split-tunnel configuration) to non-localhost callers
— devices on the household LAN, or anyone with the WireGuard/Tailscale
credential — and shift the compromise-probability calculus materially.
**Any future LAN or VPS profile feature spec MUST revisit this entry
(and likely replace the proxy mechanism — e.g. with a CP→host RPC over
a dedicated UDS with a purpose-built daemon) before that profile's
compose file ships.** §16.1 carries a sibling release-blocker sentence
(this entry + §16.1 are the two anchors that MUST be revisited
together); note that §16.1's release-blocker is currently narrower
(CP-only) than this entry's (CP/DP/Tor) — see "Architecture spec §16.1
cross-reference" above for the drift reconciliation plan under T018.

---

## 2026-07-04 — Tor sidecar trust rationale (FR-015)

**Decision.** Stargate builds its own Tor sidecar image
(`sidecars/tor/Dockerfile`) from a digest-pinned `debian:12-slim` base,
installing the `tor` package from the Tor Project's official Debian apt
repository (`deb.torproject.org`), with the Tor Project signing key pinned by
fingerprint and verified at build time. The image is `stargate/tor` (service
key `tor` in compose, T015). **Only the base image is pinned today** — the
final composed image digest lands at release tag time via T081 (see
"Final-image digest values" below); until then the supply chain is
base-pinned + key-verified, NOT fully image-pinned.

**Resolves (pending T082 amendment of) THREAT-MODEL §8.6 "Sidecar maintainer
trust"** — which currently frames this as an unresolved decision to "choose a
community maintainer." This entry resolves it differently (build in-house
from the Tor Project's own apt repo rather than pick a third-party image
maintainer). THREAT-MODEL §8.6 itself MUST be amended in lock-step to stop
contradicting this entry — that spec edit is filed as follow-up **T082**
(sibling to T018, which amends arch §7 for the same decision). Until T082
lands, §8.6's prose still reads as "unresolved" — this entry is the
authoritative resolution; the model sync follows.

**Rationale — why `deb.torproject.org` over a fork or an upstream image
(THREAT-MODEL §2.6 — the Tor sidecar is in the per-route privacy TCB).**

1. **The Tor Project publishes no official Docker image.** A community
   Docker image (e.g. on Docker Hub) would be a third-party rebuild of
   unknown provenance with no contract binding it to the Tor Project's own
   distribution. Stargate's privacy guarantee depends on the `tor` binary
   being the Tor Project's own build; a third-party image breaks that.
2. **`deb.torproject.org` is the Tor Project's own distribution channel** —
   the same apt repo the Tor Project ships for Debian users. Building from
   it on a pinned Debian-slim base is the closest available analogue to
   "the Tor Project's own distribution" inside a container. The `tor`
   package installed is the Tor Project's signed Debian package, not a
   fork and not a distro-shipped rebuild.
3. **Pinned base + signed-by repo binding** (Principle IV): the Debian-slim
   base is pinned by digest (below); the apt repo is bound to the verified
   Tor Project key via `signed-by=` only — no global `apt-key add`. A
   compromise of the Debian archive key would NOT grant signing trust over
   the Tor repo.
4. **Build-time TOFU resistance.** The Tor Project signing key is fetched
   over TLS from `deb.torproject.org` and verified by fingerprint. To close
   the build-time-MITM bypass (THREAT-MODEL §2.3 — an active adversary on
   the build host's upstream TLS could append a second attacker-controlled
   primary key to the `.asc` file, pass the fingerprint check on the
   legitimate first primary, and gain `signed-by=` trust for malicious
   packages), the Dockerfile asserts `PUB_COUNT==1` — exactly one primary
   key in the fetched file — before dearmoring. Either check failing fails
   the build loudly. See `sidecars/tor/Dockerfile` header comment for the
   full bypass analysis.

**Apt-key fingerprint (pinned, verified at every build):**

`A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`

This is the canonical Tor Project archive-signing key. It is the single
source of truth in `sidecars/tor/apt-key.fingerprint`; this file quotes it
verbatim; `sidecars/tor/Dockerfile` reads it at build time. The contract
test `tests/contract/security-decisions/tor_entry_test.sh` asserts all three
locations agree. **Rotation policy:** the Tor Project rotates this key every
few years. When it does, every Tor-sidecar build fails loudly at the
fingerprint check (intended). The rotation is a **manual, review-driven
update**: in one PR, `sidecars/tor/apt-key.fingerprint`, the fingerprint
quoted here, and (if the Dockerfile's verification logic is affected) the
Dockerfile are updated together, the new fingerprint is confirmed against
the Tor Project's published rotation announcement, and the contract test
goes green again. No automated key refresh — Principle IV's manual-promotion
discipline applies to signing keys exactly as it applies to image digests
(THREAT-MODEL §5.9 — update-channel compromise). **Revocation without
replacement:** if the Tor Project revokes the signing key and ships no
immediate successor, every Tor-sidecar build fails loud and Stargate ships no
Tor-route update until the Tor Project publishes a successor; the new
fingerprint is then sourced from a Tor-Project-issued statement
(`deb.torproject.org` homepage or the `tor-project@lists.torproject.org`
list archive), not from the `.asc` file alone (which an attacker could rotate
to their own key under a revoked-but-still-served key).

**Debian-slim base digest (pinned, both stages):**

`debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df`

Multi-arch OCI index, resolved via `docker buildx imagetools inspect
debian:12-slim` (registry-direct, not local cache). Pinned in BOTH stages of
`sidecars/tor/Dockerfile`; the two stages stay in sync (the contract test
asserts a single distinct digest across the file). The same digest is reused
by `scripts/subcommands/init` (T016) for the key-gen helper container, so
the TCB base is one image, not two. Bumping this digest is a manual
promotion: resolve the new digest online, update both Dockerfile stages +
this entry, run the contract suite.

**Debian archive snapshot pin — T099 (immutable build inputs, Principle IV).**

The base image + signing key are pinned, but until T099 the resolved
*package set* was not: stage 2's `apt-get install tor` resolved tor's
link-time closure (libssl3, libevent-2.1-7, zlib1g, libc6) fresh from
Debian's mutable archive index on every build, so two builds of the same
commit could select different bytes. T099 pins the Debian archive to an
immutable `snapshot.debian.org` run and pins every directly-installed
package to an explicit `=version`:

- **Snapshot run:** `20260714T082229Z` (bookworm 12.15; archive `Date`
  2026-07-11). Pinned in both Dockerfile stages + recorded here; the
  cross-file agreement is gated by
  `tests/contract/security-decisions/tor_build_inputs_test.sh` (B6).
  `snapshot.debian.org`'s InRelease carries no `Valid-Until` (it never
  expires), so no `Check-Valid-Until` defeat is applied; the snapshot is
  buildable indefinitely.
- **Transport — HTTP, not HTTPS.** The base image ships no `ca-certificates`,
  so an HTTPS bootstrap would be circular (ca-certificates is the first
  package installed). Integrity is NOT transport-based: apt verifies the
  InRelease PGP signature (Debian archive keyring, shipped in the base) and
  every `.deb` sha256 against the signed Packages index — a MITM cannot forge
  either, so signed metadata is the load-bearing guarantee (TLS would be
  defense-in-depth only).
- **Pinned packages (sha256 retained for audit):**

  | package | version | sha256 | source |
  |---|---|---|---|
  | ca-certificates | `20230311+deb12u1` | `0d5f444f594e48c1e16a41d8fc628a09b24c658916a1274025c2330f2a802bed` | snapshot (both stages) |
  | curl | `7.88.1-10+deb12u15` | `0dd9b6bf7a0bd11af2d68a52ec44c2a223fa7c11f9104c36ce1047e1137d4a8f` | snapshot (stage 1 only) |
  | gnupg | `2.2.40-1.1+deb12u2` | `d3f860cf16da5d61875a324859045fd1f4a888ed0ddef55d7e9f977dd729a76e` | snapshot (stage 1 only) |
  | netcat-openbsd | `1.219-1` | `85adebc045f48eb9a91515202a49940a0a57eff790223402333253ff121dfbdd` | snapshot (stage 2) |
  | tor | `0.4.9.11-1~d12.bookworm+1` | `1a9fa54dece42c21fffd142963ad5e13eec735654b95f82386d7c18702145d28` | `deb.torproject.org` (Tor Project build — NOT Debian's archive rebuild `0.4.9.11-0+deb12u1`, per FR-015) |

  Transitive deps (libssl3 `3.0.20-1~deb12u2`, libevent-2.1-7
  `2.1.12-stable-8`, …) are frozen by the snapshot and verified by apt; their
  hashes ride the signed Packages index. The gated reproducibility property
  (stable package manifest across cold rebuilds) is asserted by
  `tests/reproducibility/tor_sidecar_manifest_test.sh`.

- **Rotation.** Refreshing the snapshot is a manual, review-driven PR
  (Principle IV): bump the `snapshot.debian.org` run timestamp, every
  `=version` pin, and the sha256 table here in one commit; the contract test
  re-confirms the timestamp agrees cross-file; the reproducibility test
  re-confirms the manifest is stable. The Tor package version rotates when the
  Tor Project ships a new `bookworm` build — caught by the same manual PR.
  `deb.torproject.org` is NOT snapshotted (the Tor Project offers no frozen
  index); its immutability is the `=version` pin + apt's sha256 verification
  against its signed Packages index, with the residual that the Tor Project
  could remove an old `.deb` (a removal fails the build closed → manual
  refresh, exactly the Principle IV promotion discipline).

**Final-image digest values — RELEASE-TAG-TIME (T081), NOT YET PINNED.**

FR-015's literal text requires that "the final composed image MUST be pinned
by sha256 digest in `compose/docker-compose.local.yml`." For the three
Stargate-built images (`stargate/stargate-dp`, `stargate/stargate-control`,
`stargate/tor`) this is **currently unmet and release-blocking**: compose
(T015) ships them as `build:` directives for the Phase-2 scaffolding
horizon, so no final-image digest exists to pin. The gap is closed by
**T081**'s `.github/workflows/release.yml`, which at release tag time:
builds each image, pushes it to GHCR, captures its `sha256:` digest,
**cosign**-signs it keyless (Rekor transparency log entry), emits an **SBOM**
(SPDX), and appends the resolved digest values + signing/SBOM/Rekor
references to this file (and to a sibling `compose/docker-compose.release.yml`
that pins them). Until T081 lands, deployment today is `docker compose build`
from source; the verified-pull path is post-T081. **This entry does NOT
record final-image digests because they do not yet exist; recording a
fabricated value would violate the honest-threat-model Principle V.** The
external-image digest that IS pinned today (the docker-events filter aux
container in compose) is documented by a separate entry (T017a).

**Residual risk (THREAT-MODEL §2.6, §5.8).**

- The Tor sidecar remains in the per-route privacy TCB: a backdoored `tor`
  binary sees SOCKS5 destinations, circuit state, and exit-visible cleartext.
  Pinned-digest selection + build-time key verification + the contract-test
  gate (FR-016) reduce but do not eliminate this. The mitigation is "trust
  the Tor Project's own distribution channel, verified end-to-end at build
  time," not "the sidecar is trusted by construction."
- **Tor's transitive dependency closure rides on Debian's archive trust, not
  the Tor Project's.** The `tor` package's link-time dependencies —
  `libssl3` (OpenSSL; carries Tor's authenticated TLS to guards — the
  literal carrier of circuit-setup and relay-authentication crypto),
  `libevent-2.1`, `zlib1g`, `libc6` — are pulled from Debian's main archive
  under Debian's archive signing key, NOT from `deb.torproject.org` under
  the Tor Project's key. A malicious `libssl3` in Debian's archive (or a
  compromised Debian archive mirror) compromises Tor's guard TLS and defeats
  the core anonymity property the sidecar exists to provide, with no
  Stargate-side verification reach. This is the single most
  security-relevant component of the sidecar's TCB and it sits OUTSIDE the
  fingerprint-verified channel. **T099 closed the reproducibility half of
  this gap** — the Debian archive is now pinned to an immutable
  `snapshot.debian.org` run with every package `=version`-pinned, so the
  closure (libssl3 included) is frozen and auditable: every build selects
  the SAME bytes, and the exact `libssl3` `3.0.20-1~deb12u2` is recorded.
  The TRUST half remains residual: the closure still rides Debian's archive
  signing key (not the Tor Project's), and neither the snapshot pin nor the
  contract-test suite detects a malicious library that conforms
  behaviourfully — the pin makes it auditable, not trustworthy. The
  mitigations are Debian's own archive-signing integrity (out of Stargate's
  control) and the contract-test suite gating Tor's documented behavioural
  invariants. Residual. (THREAT-MODEL §2.6, §5.9.)
- The build-time TLS fetch of the signing key trusts `deb.torproject.org`'s
  TLS at build time (a CA- or BGP-level adversary on the build host's
  upstream could attempt delivery of a malicious key file); the
  `PUB_COUNT==1` assertion plus fingerprint pin closes the documented
  bypass, but a fully compromised CA + a key-collision attack is residual
  (THREAT-MODEL §5.9).
- The Debian base image and the `ca-certificates`/`tor`/`netcat-openbsd`
  packages installed in stage 2 are trusted on Debian's own archive signing
  (out of Stargate's control); Principle IV's contract-test gate catches
  behavioural regressions on Tor's documented invariants but cannot detect a
  malicious Debian package that conforms behaviourally.

---

## Reserved: adversarial-review findings (Phase N+)

This section is reserved for `stargate-redteam` and `stargate-perf` findings
accepted (mitigated, risk-accepted, or deferred-with-rationale) in any phase,
per Constitution Principle VIII. Each accepted finding gets a dated
`##` entry below stating: the finding, the acceptance rationale, the
mitigation or the explicit risk acceptance, and a cross-reference to the
artifact (test, code, or threat-model row) that carries the mitigation.

Initially empty. The end-of-feature `stargate-redteam` + `stargate-perf`
passes against the completed `001-tor-route` feature populate this section;
their findings either resolve in-code (no entry needed) or land here as
accepted-finding rationales.

(No entries yet.)
