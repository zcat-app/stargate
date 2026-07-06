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
  fingerprint-verified channel. **No Stargate-side mitigation reaches the
  runtime `libssl3`:** the digest-pinned Debian base fixes only the base
  layer's contents — stage 2's `apt-get install tor` resolves `libssl3`
  (and the rest of the closure) fresh from Debian's archive index at every
  build, so the runtime copy floats under Debian's archive key, exactly
  the trust gap this bullet documents. The only mitigations are Debian's
  own archive-signing integrity (out of Stargate's control) and the
  contract-test suite gating Tor's documented behavioural invariants —
  neither detects a malicious library that conforms behaviourfully.
  Residual. (THREAT-MODEL §2.6, §5.9.)
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
