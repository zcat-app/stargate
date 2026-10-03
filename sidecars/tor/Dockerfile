# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# sidecars/tor/Dockerfile — Stargate-built Tor sidecar image (FR-015).
#
# Why a Stargate-built image rather than an upstream one (FR-015):
# the Tor Project does not publish an official Docker image, so we build
# one from a digest-pinned Debian-slim base installing `tor` from the
# Tor Project's official Debian repository (deb.torproject.org). The base
# image is pinned by sha256 digest here (Principle IV). The final image is
# NOT digest-pinned anywhere yet: compose/docker-compose.local.yml builds it
# locally from this file (`build:` + `pull_policy: build`, local tag
# stargate/tor:local). Final-image digests are recorded at release time by
# T081's release workflow. The trust rationale (why
# deb.torproject.org over a fork, key rotation policy, residual risk)
# is recorded by T017 in SECURITY-DECISIONS.md.
#
# Multi-stage layout (redteam-driven hardening):
#   - Stage 1 `keyring`: installs ca-certificates + curl + gnupg (build-only
#     tooling), fetches the Tor apt signing key, verifies BOTH (a) the
#     fetched key's primary fingerprint matches the pin in
#     apt-key.fingerprint AND (b) the fetched file contains exactly ONE
#     primary key, then dearmors the verified key to
#     /tmp/torproject-archive-keyring.gpg.
#   - Stage 2 runtime: fresh debian:12-slim. The verified keyring is
#     the ONLY artefact that crosses from stage 1 — curl and gnupg never
#     ship in the runtime image, so a compromised sidecar has none of
#     their attacker utility (THREAT-MODEL §2.6).
#
# Why the PUB_COUNT==1 assertion is load-bearing (redteam Major finding):
# without it, a MITM attacker on deb.torproject.org TLS at build time
# (THREAT-MODEL §2.3 — the exact threat FR-015's TOFU clause exists to
# defeat) could append a second attacker-controlled primary to the .asc
# file, pass the fingerprint check on the legitimate first primary, and
# have gpg --dearmor write BOTH keys into the keyring — at which point
# `signed-by=` trusts the attacker's key for signing malicious `tor`
# packages fetched over the same MITM'd channel. Asserting exactly one
# primary in the file closes that bypass.
#
# Runtime user: drops to a non-root `tor` user before ENTRYPOINT
# (Principle VI — least privilege). The Tor state directory
# /var/lib/tor is pinned explicitly in the image-baked torrc
# (contracts/torrc.md invariant #11 — DataDirectory /var/lib/tor is
# explicit because the entrypoint does not load Debian's torrc-defaults).
#
# T152: current health is served by the authenticated observer. Docker health
# probes retain timestamped history and are disabled; Tor diagnostics are
# discarded in the entrypoint and torrc before any container retention boundary.
#
# Pins resolved empirically at /start from authoritative live sources:
#   - debian:12-slim digest: docker buildx imagetools inspect (registry)
#   - Tor apt key fingerprint: deb.torproject.org/torproject.org/ index
#   - Current Tor (bookworm): 0.4.9.13-1~d12.bookworm+1 (T177, 2026-09-26)
#
# T099 — immutable build inputs (Constitution Principle IV). The Debian
# archive is pinned to a snapshot.debian.org run and every directly installed
# apt package carries an explicit =version pin; apt verifies each .deb sha256
# against the PGP-signed Packages index (a mismatch fails the build closed).
# `tor` stays on deb.torproject.org (FR-015: the Tor Project's own build, NOT
# Debian's archive rebuild). Debian closure resolved at /start 2026-07-15;
# recorded cross-file in SECURITY-DECISIONS.md:
#   - Debian snapshot run: 20260714T082229Z (bookworm 12.15; Date 2026-07-11)
#   - ca-certificates  20230311+deb12u1   sha256 0d5f444f594e48c1e16a41d8fc628a09b24c658916a1274025c2330f2a802bed
#   - curl             7.88.1-10+deb12u15 sha256 0dd9b6bf7a0bd11af2d68a52ec44c2a223fa7c11f9104c36ce1047e1137d4a8f  (stage 1 only)
#   - gnupg            2.2.40-1.1+deb12u2 sha256 d3f860cf16da5d61875a324859045fd1f4a888ed0ddef55d7e9f977dd729a76e  (stage 1 only)
#   - netcat-openbsd   1.219-1           sha256 85adebc045f48eb9a91515202a49940a0a57eff790223402333253ff121dfbdd
# T160: Tor's amd64/arm64 .deb hashes live in tor-packages.sha256 and are
# checked before local-file installation. Its signed mutable Packages index
# authenticates provenance but cannot alone prevent same-version replacement.
#
# T184 — the snapshot URL and =version pins do NOT freeze the closure on their
# own. snapshot.debian.org InRelease files carry no Valid-Until, so over plain
# HTTP an on-path attacker can serve an older, genuinely signed bookworm index
# and apt accepts it (the pins above floor that rollback only at Debian 12.12:
# libssl3 3.0.20 -> 3.0.17). package-closure.lock therefore pins (a) the
# snapshot InRelease SHA-256, checked by verify-closure.sh after EVERY
# `apt-get update` before anything is installed from it, and (b) the golden
# per-arch closure (name, version, arch, archive sha256) of the final image,
# checked after the last install. Either mismatch fails the build. Refresh is a
# manual, review-driven PR (Principle IV): bump the snapshot run, every =version
# pin, the InRelease hash and the lock rows together.

# T203: the fixed publisher is part of Tor's reviewed executable closure.
FROM golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c AS publisher
WORKDIR /src
COPY data-plane/go.mod data-plane/go.sum ./
COPY proto/go.mod proto/go.sum /proto/
COPY data-plane/cmd/tor-health-publisher/ ./cmd/tor-health-publisher/
COPY data-plane/internal/torhealth/ ./internal/torhealth/
ENV CGO_ENABLED=0
RUN go build -trimpath -buildvcs=false -ldflags=-buildid= -o /out/tor-health-publisher ./cmd/tor-health-publisher

# ---------- Stage 1: keyring builder ----------
FROM debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS keyring

# T099: replace the base image's mutable deb.debian.org source with the pinned
# snapshot.debian.org run (Constitution Principle IV). The base image ships
# /etc/apt/sources.list.d/debian.sources (deb822); removing it + sources.list
# ensures ONLY the immutable snapshot is consulted. snapshot.debian.org is
# fetched over HTTP (the base ships no ca-certificates, so an HTTPS bootstrap
# would be circular — ca-certificates is itself the first package installed).
# Integrity is NOT transport-based: apt verifies the InRelease PGP signature
# (Debian archive keyring, shipped in the base) and every .deb sha256 against
# the signed Packages index — a MITM cannot forge either. A signature proves
# origin, not freshness: snapshot.debian.org's InRelease carries no Valid-Until,
# so a MITM CAN replay an older signed index (T184). The InRelease hash pin in
# package-closure.lock refuses that before this stage installs anything; stage 1
# tooling (curl, gnupg) verifies the Tor signing key, so it gets the same pin.
# No Check-Valid-Until defeat is applied.
COPY sidecars/tor/verify-closure.sh sidecars/tor/package-closure.lock /tmp/
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources \
 && echo "deb http://snapshot.debian.org/archive/debian/20260714T082229Z/ bookworm main" \
        > /etc/apt/sources.list.d/snapshot.list \
 && apt-get update \
 && sh /tmp/verify-closure.sh inrelease /tmp/package-closure.lock \
 && apt-get install -y --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
        curl=7.88.1-10+deb12u15 \
        gnupg=2.2.40-1.1+deb12u2 \
 && rm -rf /var/lib/apt/lists/*

COPY sidecars/tor/apt-key.fingerprint /tmp/apt-key.fingerprint

# Fetch + verify + dearmor. Both checks must pass; either failure exits
# the RUN non-zero and fails the build. See header comment for why the
# PUB_COUNT==1 assertion is load-bearing (TOFU resistance).
RUN EXPECTED_FPR="$(tr -d '[:space:]' < /tmp/apt-key.fingerprint)" \
 && curl -fsSL "https://deb.torproject.org/torproject.org/${EXPECTED_FPR}.asc" -o /tmp/torkey.asc \
 && ACTUAL_FPR="$(gpg --show-keys --with-fingerprint --with-colons /tmp/torkey.asc \
        | awk -F: '/^fpr:/ {print $10; exit}')" \
 && PUB_COUNT="$(gpg --show-keys --with-colons /tmp/torkey.asc | grep -c '^pub:')" \
 && if [ "$ACTUAL_FPR" != "$EXPECTED_FPR" ]; then \
        echo "ERROR: Tor apt key fingerprint mismatch — expected ${EXPECTED_FPR}, got ${ACTUAL_FPR}" >&2; \
        exit 1; \
    fi \
 && if [ "$PUB_COUNT" != "1" ]; then \
        echo "ERROR: expected exactly 1 primary key in torkey.asc, got ${PUB_COUNT}" >&2; \
        exit 1; \
    fi \
 && gpg --dearmor < /tmp/torkey.asc > /tmp/torproject-archive-keyring.gpg

# ---------- Stage 2: runtime ----------
FROM debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

# The verified keyring is the ONLY artefact that crosses from stage 1.
# curl and gnupg never ship in the runtime image.
COPY --from=keyring /tmp/torproject-archive-keyring.gpg /usr/share/keyrings/
COPY sidecars/tor/install-tor.sh sidecars/tor/tor-packages.sha256 /tmp/
COPY sidecars/tor/verify-closure.sh sidecars/tor/package-closure.lock /tmp/

# Add the Tor Project apt repo for the bookworm suite (matches the
# Debian 12 base). signed-by= binds the repo to the verified key ONLY;
# no global apt-key add. ca-certificates is needed for apt to validate
# deb.torproject.org's TLS during `apt-get update`; it is a small (~300 KB)
# harmless residual, retained. `apt-transport-https` is NOT installed —
# apt on Debian 12 has native HTTPS support.
#
# T099: the Debian closure resolves from the same snapshot.debian.org run as
# stage 1 (the base's mutable deb.debian.org source is removed first). T184:
# what actually fixes tor's link-time dependencies — libssl3 (OpenSSL; carries
# Tor's authenticated TLS to guards), libevent-2.1-7, zlib1g, libc6 — against a
# replayed older signed index is the InRelease hash pin, re-checked after BOTH
# `apt-get update` runs (the second one re-fetches the snapshot index too), and
# the final closure check against package-closure.lock before the lists are
# removed (SECURITY-DECISIONS.md §T184). The snapshot is fetched over HTTP
# (see stage 1 comment). ca-certificates + netcat-openbsd install
# from the snapshot FIRST; then the deb.torproject.org repo (HTTPS, now that
# ca-certificates is present) is added and `tor` is version-pinned from it
# (NOT a Debian archive rebuild — FR-015). apt verifies every download against
# signed metadata; T160 additionally verifies the Tor artifact's reviewed hash
# and installs that exact local file. Only the Debian snapshot source is enabled
# for dependency resolution and installation; Tor's mutable index cannot replace
# that closure. The build helpers are removed afterward.
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources \
 && echo "deb http://snapshot.debian.org/archive/debian/20260714T082229Z/ bookworm main" \
        > /etc/apt/sources.list.d/snapshot.list \
 && apt-get update \
 && sh /tmp/verify-closure.sh inrelease /tmp/package-closure.lock \
 && apt-get install -y --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
        netcat-openbsd=1.219-1 \
 && echo "deb [signed-by=/usr/share/keyrings/torproject-archive-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main" \
        > /etc/apt/sources.list.d/tor.list \
 && apt-get update \
 && sh /tmp/verify-closure.sh inrelease /tmp/package-closure.lock \
 && sh /tmp/install-tor.sh 0.4.9.13-1~d12.bookworm+1 /tmp/tor-packages.sha256 \
 && sh /tmp/verify-closure.sh closure /tmp/package-closure.lock \
 && rm -f /tmp/install-tor.sh /tmp/tor-packages.sha256 \
 && rm -f /tmp/verify-closure.sh /tmp/package-closure.lock \
 && rm -rf /var/lib/apt/lists/*

# Non-root `tor` user (T015 prose: "The Tor container drops to its own
# `tor` user per T014"). system user, no shell, home at the Tor state
# directory. The image-baked torrc pins DataDirectory /var/lib/tor
# (contracts/torrc.md invariant #11 — explicit because the entrypoint does
# not load Debian's torrc-defaults, so without the directive Tor would
# fall back to $HOME/.tor = /var/lib/tor/.tor and land the control cookie
# at the wrong path); we pre-create /var/lib/tor owned by tor so the
# cookie file lands in the right place.
#
# UID/GID 5103 (T039): numeric pin following the 5100–5102 plane scheme.
# CookieAuthFileGroupReadable 1 (torrc invariant #4) creates the cookie
# 0640 tor:tor. CP and observer have no Tor-state mount. Only the Tor-internal
# publisher holds native control authority (T203).
RUN groupadd --system --gid 5103 tor \
 && groupadd --system --gid 5200 stargate-tor-dp \
 && useradd --system --uid 5103 --gid 5103 --home /var/lib/tor --shell /usr/sbin/nologin tor \
 && install -d -o tor -g tor -m 0700 /var/lib/tor /var/lib/tor/control \
 && install -d -o tor -g stargate-tor-dp -m 0750 /run/tor-fabric \
 && install -d -o tor -g tor -m 0700 /run/tor-fabric/private

# Image-baked torrc (T087 / FR-011 amended by T089): the safe torrc is
# COPY'd into the image at build time so Tor startup never waits for the
# control plane to render config (Constitution Principle II / sol-review
# B2 — Compose starts Tor before the CP can render a torrc, so a CP-rendered
# torrc would be a boot-coupling the principle forbids). The file is the
# byte-pinned golden from contracts/torrc.md §"Rendered file"; T087's
# cold-volume regression test verifies image /etc/tor/torrc == wantTorrc
# without harness-seeded config. Explicit chmod 0644 so USER tor can read
# it regardless of the source checkout's file mode (redteam m1).
COPY sidecars/tor/torrc /etc/tor/torrc
COPY sidecars/tor/entrypoint.sh /usr/local/bin/stargate-tor-entrypoint
RUN chmod 0644 /etc/tor/torrc && chmod 0755 /usr/local/bin/stargate-tor-entrypoint

COPY --from=publisher /out/tor-health-publisher /usr/local/bin/tor-health-publisher

USER tor

# The image-baked /etc/tor/torrc is loaded directly by the entrypoint —
# no stargate-tor-config volume mount (T087 dropped the tor service's
# mount; a :ro mount at /etc/tor would shadow the image-baked torrc).
# `tor -f /etc/tor/torrc` loads the baked config at container start.
ENTRYPOINT ["/usr/local/bin/stargate-tor-entrypoint"]

# Constitution III: no timestamped Docker health-probe journal.
HEALTHCHECK NONE
