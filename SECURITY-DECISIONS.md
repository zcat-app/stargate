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
