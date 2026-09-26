<!-- Copyright 2026 The Stargate Authors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# T177 Tor package promotion evidence

## Decision and source

Tor's [2026-09-23 announcement](https://forum.torproject.org/t/security-release-0-4-9-13/22178) describes 0.4.9.13 as a high-severity security release affecting clients, onion services and relays. It recommends prompt updating; the public announcement does not yet give a complete issue-level account. T124's fresh-volume `init` could not rebuild the previous 0.4.9.12 pin because it was absent from the current Bookworm package index. The maintainer authorized this separate, reviewed update. No running installation or published image was changed by this ticket.

## Authenticated package grounding, 2026-09-26

- Official [Bookworm InRelease](https://deb.torproject.org/torproject.org/dists/bookworm/InRelease): SHA-256 `a59297db130632cdd06cd4adf61dd28922a157b0fa382756c0ae9890c0e29323`. `gpgv` returned 0 and a `VALIDSIG` for signing subkey `2265EB4CB2BF88D900AE8D1B74A941BA219EC810` under the existing pinned primary fingerprint `A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89`; the downloaded key file contained exactly one primary key. The signed Date is 2026-09-25 11:28:01 UTC and Valid-Until is 2026-11-04 11:28:01 UTC; the current UTC time fell within that interval.
- Actual [amd64 Packages](https://deb.torproject.org/torproject.org/dists/bookworm/main/binary-amd64/Packages): 5165 bytes, SHA-256 `b079631dd7c6fe214d97df515628d2a4aec6322f82e0e80709fd2e56c63a67a9`, matching the signed InRelease row. Its sole `tor` stanza selects `0.4.9.13-1~d12.bookworm+1` and identifies [the amd64 `.deb`](https://deb.torproject.org/torproject.org/pool/main/t/tor/tor_0.4.9.13-1~d12.bookworm+1_amd64.deb): 2093596 bytes, SHA-256 `6dd261277646e309cb9571861722862fe646c76bb5f0b7b72ee1e6ab2fd1c01a`. The downloaded bytes matched both the size and hash.
- Actual [arm64 Packages](https://deb.torproject.org/torproject.org/dists/bookworm/main/binary-arm64/Packages): 5132 bytes, SHA-256 `d806dc04650cc4c9a70c8a9e85a95be52f2c5ce50bfa90e3a99c1c3d7f216b55`, matching the signed InRelease row. Its sole `tor` stanza selects the same version and identifies [the arm64 `.deb`](https://deb.torproject.org/torproject.org/pool/main/t/tor/tor_0.4.9.13-1~d12.bookworm+1_arm64.deb): 2008172 bytes, SHA-256 `db443c92ed416a1f06f8a7c8f538642a641d6c96c6a98402134f9467369d0ff9`. The downloaded bytes matched both the size and hash.
- The independent content-lock rows use those two downloaded-artifact hashes. The repository index authenticates origin; the independent lock detects subsequent same-version replacement. These are separate checks. The key fingerprint, Debian snapshot, base digest, checked installer, dependency source isolation and torrc bytes were not changed.

## Native build and focused checks

The no-cache `docker build --progress plain -t stargate/tor:t177 sidecars/tor` completed with image config ID `sha256:6d707165dcf685619d8bf99b6410d40857c426c8a905341a9d419393b67f298d`. Inside the image, `dpkg-query -W tor` returned `0.4.9.13-1~d12.bookworm+1`, `tor --version` returned `Tor version 0.4.9.13`, runtime UID/GID were `5103/5103`, the build helper and hash-lock files were absent, and `/etc/tor/torrc` matched the source hash `9f127c2c51019b10a7272ea8cb3a389ef55eab057c4ca1bed5b2b02f8ab51924`. Docker image health history was disabled (`Healthcheck.Test=[NONE]`). `tor --verify-config -f /etc/tor/torrc` returned 0. It emitted a `CookieAuthFileGroupReadable` warning; current live cookie/observer behavior requires separate measurement.

The package-integrity contract passed its amd64/arm64 positive cases and its existing same-version replacement, missing-pin, failed-download, unsupported-architecture and hostile dependency-source controls. The T099 build-input contract also passed. The T177 tests-first record retains the expected failure on the old Dockerfile and the identical probe on the implemented candidate.

The Docker-tagged `TestLiveSidecarGETCONFSocksPort` passed on the new image from a cold Tor volume: authenticated bootstrap reached 100%, the control cookie was at `/var/lib/tor/control_auth_cookie`, Docker had no health history, the image torrc matched the source golden, and authenticated GETCONF returned every expected directive including `IsolateSOCKSAuth`. `TestIsolateSOCKSAuthDistinctCircuits` passed on a separate cold project: two same-destination streams with distinct SOCKS usernames attached to distinct Tor circuits. Both tests used only fixed test identities and cleaned up their Compose projects. They establish those two measured native amd64 properties for this run, not whole-stack privacy or future Tor-network availability.

The release-cadence `tor_sidecar_manifest_test.sh` completed two no-cache builds and compared the installed package sets: both contained the same 96 `name=version` rows, including `tor=0.4.9.13-1~d12.bookworm+1` and `libssl3:amd64=3.0.20-1~deb12u2`. This is package-manifest stability, not byte-identical final images.

Native amd64 execution and authenticated arm64 package bytes do not establish arm64 runtime behavior. The Tor-only live tests do not establish the integrated installer/observer result or future Tor-network availability. T124's fresh-volume integrated READY run remains a separate required gate.
