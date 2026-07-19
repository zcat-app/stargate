#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/reproducibility/tor_sidecar_manifest_test.sh — T099 acceptance #3.
#
# Rebuilds the Tor sidecar image twice from a cold cache and asserts the
# resolved package set (name=version for every installed package) is
# byte-identical across the two builds. This is the gated reproducibility
# property: the snapshot.debian.org pin + explicit =version pins freeze the
# resolved set, including tor's link-time closure (libssl3, libevent-2.1-7,
# zlib1g, libc6) that previously floated fresh from Debian's archive.
#
# What is gated: package-MANIFEST stability (Constitution Principle IV —
# "Pinned, Tested, Manually Promoted"; the downscoped acceptance #3 per T099
# grounding). What is NOT gated: a byte-stable final image DIGEST. apt
# postinst scripts, dpkg status mtimes, and Docker layer `created` timestamps
# make byte-identity non-automatic; that variance (if any) is recorded in
# BUILD-DIFFS.md, not failed here.
#
# Release cadence: opt-in via STARGATE_VERIFY_REPRO=1 (scripts/verify.sh
# Gate 5). Two cold builds are network- and time-heavy (~minutes each); they
# do not run in the default PR gate. The hermetic structural pinning gate
# (no unversioned installs, snapshot pinned, fail-closed) lives in
# tests/contract/security-decisions/tor_build_inputs_test.sh and DOES run in
# the default gate.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

CONTEXT="sidecars/tor"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; docker rmi -f stargate/tor:repro-a stargate/tor:repro-b >/dev/null 2>&1 || true' EXIT

command -v docker >/dev/null 2>&1 || { echo "SKIP: docker not available"; exit 0; }
docker info >/dev/null 2>&1 || { echo "SKIP: docker daemon unreachable"; exit 0; }

extract_manifest() {
  # Emit a sorted `name=version` line for every installed package.
  docker run --rm --entrypoint dpkg-query "$1" -W -f='${binary:Package}=${Version}\n' \
    | LC_ALL=C sort
}

echo ">>> cold build #1 (stargate/tor:repro-a) — no cache"
docker build --no-cache --quiet -t stargate/tor:repro-a "$CONTEXT" >/dev/null \
  || { echo "FAIL: cold build #1 failed" >&2; exit 1; }
extract_manifest stargate/tor:repro-a > "$WORK/manifest-a.txt"
echo ">>> cold build #2 (stargate/tor:repro-b) — no cache"
docker build --no-cache --quiet -t stargate/tor:repro-b "$CONTEXT" >/dev/null \
  || { echo "FAIL: cold build #2 failed" >&2; exit 1; }
extract_manifest stargate/tor:repro-b > "$WORK/manifest-b.txt"

if diff -u "$WORK/manifest-a.txt" "$WORK/manifest-b.txt" > "$WORK/diff.txt"; then
  n=$(wc -l < "$WORK/manifest-a.txt" | tr -d ' ')
  tor_v=$(grep -E '^tor(:amd64)?=' "$WORK/manifest-a.txt" | head -1)
  ssl_v=$(grep -E '^libssl3(:amd64)?=' "$WORK/manifest-a.txt" | head -1)
  echo "OK: package manifest stable across cold rebuilds ($n packages, byte-identical)"
  echo "    ($tor_v)"
  echo "    ($ssl_v)"
  exit 0
else
  echo "FAIL: package manifest drifted between cold rebuilds (T099 acceptance #3):" >&2
  cat "$WORK/diff.txt" >&2
  exit 1
fi
