# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# sidecars/tor/Dockerfile — Stargate-built Tor sidecar image (FR-015).
#
# Why a Stargate-built image rather than an upstream one (FR-015):
# the Tor Project does not publish an official Docker image, so we build
# one from a digest-pinned Debian-slim base installing `tor` from the
# Tor Project's official Debian repository (deb.torproject.org). Both
# the base AND the final composed image are pinned by sha256 digest per
# Principle IV — the base here, the final image in
# compose/docker-compose.local.yml (T015). The trust rationale (why
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
# /var/lib/tor is the Debian package default (contracts/torrc.md
# invariant #11 — no DataDirectory override).
#
# HEALTHCHECK design note: contracts/torrc.md invariant #8 renders
# `Log notice stdout`. The task body phrases the healthcheck as
# "parsing for 'Bootstrapped 100%' against `Log notice stdout`". A
# literal stdout-grep is NOT viable inside the container: /proc/1/fd/1
# yields only NEW log lines after the reader opens, so once Tor has
# finished bootstrapping and goes idle the healthcheck would silently
# fail forever. The robust in-container probe is the control port
# (`GETINFO status/bootstrap-phase` over cookie auth), which the
# contract already enables (ControlPort 0.0.0.0:9051,
# CookieAuthentication 1, CookieAuthFileGroupReadable 1). The control
# port is the authoritative source Tor itself uses to report bootstrap
# state; the stdout `Bootstrapped 100%` line is derived from the same
# internal state, so probing the control port is at least as strong.
# The contract's stdout logging is preserved unchanged — it remains
# the source of operator-visible logs via `docker logs`.
#
# Pins resolved empirically at /start from authoritative live sources:
#   - debian:12-slim digest: docker buildx imagetools inspect (registry)
#   - Tor apt key fingerprint: deb.torproject.org/torproject.org/ index
#   - Current Tor (bookworm): 0.4.9.11-1~d12.bookworm+1 (2026-07-03)

# ---------- Stage 1: keyring builder ----------
FROM debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS keyring

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && rm -rf /var/lib/apt/lists/*

COPY apt-key.fingerprint /tmp/apt-key.fingerprint

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

# Add the Tor Project apt repo for the bookworm suite (matches the
# Debian 12 base). signed-by= binds the repo to the verified key ONLY;
# no global apt-key add. ca-certificates is needed for apt to validate
# deb.torproject.org's TLS during `apt-get update`; it is a small (~300 KB)
# harmless residual, retained. `apt-transport-https` is NOT installed —
# apt on Debian 12 has native HTTPS support.
RUN echo "deb [signed-by=/usr/share/keyrings/torproject-archive-keyring.gpg] https://deb.torproject.org/torproject.org bookworm main" \
        > /etc/apt/sources.list.d/tor.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tor netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

# Non-root `tor` user (T015 prose: "The Tor container drops to its own
# `tor` user per T014"). system user, no shell, home at the Tor state
# directory. The Debian tor package's default DataDirectory is
# /var/lib/tor (contracts/torrc.md invariant #11 — no override); we
# pre-create it owned by tor so the cookie file lands in the right place.
RUN useradd --system --home /var/lib/tor --shell /usr/sbin/nologin tor \
 && install -d -o tor -g tor -m 0700 /var/lib/tor

USER tor

# The control-plane renders /etc/tor/torrc into the stargate-tor-config
# named volume at startup (contracts/torrc.md). `tor -f /etc/tor/torrc`
# loads the rendered config; the volume mount (T015) makes the path
# resolve at container start.
ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]

# Health: probe the control port for bootstrap completion. Reads the
# auth cookie (owned by `tor`, so USER tor can read it directly),
# AUTHENTICATEs, asks GETINFO status/bootstrap-phase, and greps the
# response for PROGRESS=100. Exits non-zero if Tor is not yet (or no
# longer) bootstrapped. start-period=60s gives Tor room to bootstrap
# before the first unhealthy verdict.
#
# Runtime deps: nc (from netcat-openbsd, explicitly installed above) +
# od/tr/printf/grep (from coreutils, shipped by the debian:12-slim base).
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD COOKIE_HEX="$(od -An -tx1 /var/lib/tor/control_auth_cookie | tr -d ' \n')" \
        && { printf 'AUTHENTICATE %s\r\n' "$COOKIE_HEX"; \
             printf 'GETINFO status/bootstrap-phase\r\n'; \
             printf 'QUIT\r\n'; \
           } | nc 127.0.0.1 9051 | grep -q 'BOOTSTRAP.*PROGRESS=100'
