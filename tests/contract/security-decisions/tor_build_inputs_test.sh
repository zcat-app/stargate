#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/security-decisions/tor_build_inputs_test.sh — structural +
# cross-file contract test for the Tor sidecar's build-input pinning (T099).
#
# Why this is structural (no runtime bring-up): the immutability property
# (Constitution Principle IV) lives in the Dockerfile's apt configuration, not
# in Tor's runtime behaviour. The CONTRACT is (a) every apt package is
# resolved from an immutable snapshot.debian.org run with an explicit
# `=version` pin (so a clean rebuild selects the SAME bytes, freezing Tor's
# transitive closure — libssl3 et al., the residual named in
# SECURITY-DECISIONS.md §"Residual risk"), (b) the Tor package itself stays
# on deb.torproject.org under the fingerprint-verified key (FR-015 — a Debian
# archive rebuild would break the trust rationale), (c) fail-closed is
# preserved (no `Check-Valid-Until false` defeating apt's metadata checks),
# and (d) the resolved snapshot timestamp + retained hashes recorded in
# SECURITY-DECISIONS.md do not drift from the Dockerfile.
#
# Properties gated (T099 §Acceptance):
#   - B1 every `apt-get install` package token carries an explicit `=version`.
#   - B2 snapshot.debian.org is the Debian archive source (immutable run).
#   - B3 no mutable `deb.debian.org` main source remains.
#   - B4 `Acquire::Check-Valid-Until ... false` is absent (fail-closed kept).
#   - B5 `tor` is still resolved from deb.torproject.org (not Debian archive).
#   - B6 snapshot timestamp pinned in the Dockerfile appears in
#        SECURITY-DECISIONS.md (cross-file drift detection).
#
# Hermetic: file reads + grep + awk only. No network, no daemon. Runs in the
# default `scripts/verify.sh` Gate 4 (PR cadence). The behavioural rebuild
# gate (acceptance #3, cold-cache package-manifest stability) lives in
# tests/reproducibility/ and runs at release cadence (STARGATE_VERIFY_REPRO=1).

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

TOR_DOCKERFILE="sidecars/tor/Dockerfile"
SD="SECURITY-DECISIONS.md"

errs=()
bail() { errs+=("$*"); }

[ -f "$TOR_DOCKERFILE" ] || { echo "FAIL: $TOR_DOCKERFILE missing" >&2; exit 1; }
[ -f "$SD" ]             || { echo "FAIL: $SD missing" >&2; exit 1; }
command -v grep  >/dev/null 2>&1 || { echo "FAIL: grep missing" >&2; exit 1; }
command -v awk  >/dev/null 2>&1 || { echo "FAIL: awk missing" >&2; exit 1; }

# Collapse backslash line continuations into single logical lines so that a
# multi-line `apt-get install \` block reads as one statement, then capture
# the install verb's arguments up to the `&&` that terminates the command.
# A token is version-pinned iff it contains '='; a bare package name is
# exactly what T099 forbids. Flags (-y, --no-install-recommends, ...) and
# env assignments (KEY=val) are filtered out.
unversioned=$(awk '
  /\\[[:space:]]*$/ { sub(/\\[[:space:]]*$/,""); printf "%s", $0; next }
  { printf "%s\n", $0 }
  END { printf "\n" }
' "$TOR_DOCKERFILE" \
  | grep -oE 'apt-get install [^&]*' \
  | sed 's/apt-get install//' \
  | tr ' ' '\n' \
  | grep -vE '^(-y|--no-install-recommends|--no-install-suggests|--allow-downgrades|[A-Za-z_][A-Za-z0-9_]*=.*)$' \
  | grep -vE '=' \
  | grep -vE '^$' \
  || true)
if [ -n "$unversioned" ]; then
  bail "B1: unversioned apt package(s) in $TOR_DOCKERFILE (every package must be name=version):
$(echo "$unversioned" | sed 's/^/    - /')"
fi

# --- B2: snapshot.debian.org is the Debian archive source -------------------
grep -q 'snapshot.debian.org/archive/debian' "$TOR_DOCKERFILE" \
  || bail "B2: $TOR_DOCKERFILE must resolve Debian packages from snapshot.debian.org (immutable run)"

# --- B3: no mutable deb.debian.org main source ------------------------------
# A pinned snapshot must REPLACE the mutable default, not sit alongside it.
# (deb.debian.org may still appear in comments explaining what the snapshot
# freezes; a live deb-src/deb line for the main archive is what we forbid.)
grep -nE '^[^#]*deb[[:space:]]+(https?://deb\.debian\.org|http://deb\.debian\.org)' "$TOR_DOCKERFILE" >/dev/null 2>&1 \
  && bail "B3: $TOR_DOCKERFILE still references the mutable deb.debian.org main archive (use the pinned snapshot)"

# --- B4: fail-closed preserved (no Check-Valid-Until defeat) ----------------
grep -nEi 'Check-Valid-Until[[:space:]]*"?false' "$TOR_DOCKERFILE" >/dev/null 2>&1 \
  && bail "B4: $TOR_DOCKERFILE must not disable apt's Valid-Until check (acceptance #2: fail-closed on expired/missing metadata)"

# --- B5: tor stays on deb.torproject.org (FR-015 trust rationale) -----------
# Switching tor to the Debian archive (0.4.9.11-0+deb12u1, a Debian rebuild)
# would break FR-015's "Tor Project's own distribution" guarantee. The tor
# repo line must be present. T160 downloads by version through apt, checks an
# independent content pin and installs the exact local file. Its executable
# rejection fixtures live in tor_package_integrity_test.sh.
grep -q 'deb.torproject.org' "$TOR_DOCKERFILE" \
  || bail "B5: $TOR_DOCKERFILE must keep tor on deb.torproject.org (FR-015 — Debian archive rebuild would break the trust rationale)"

# --- B6: snapshot timestamp cross-file agreement (Dockerfile ↔ SD) ----------
# Extract the pinned snapshot run timestamp (YYYYMMDDTHHMMSSZ) from the
# Dockerfile and assert the SAME timestamp is recorded in SECURITY-DECISIONS.md.
# A snapshot refresh that updates one but not the other fails here.
ts=$(grep -oE 'snapshot.debian.org/archive/debian/[0-9]{8}T[0-9]{6}Z' "$TOR_DOCKERFILE" \
   | sed -E 's#.*/##' | sort -u)
[ -n "$ts" ] || bail "B6: no snapshot.debian.org run timestamp found in $TOR_DOCKERFILE"
n_ts=$(echo "$ts" | wc -l | tr -d ' ')
[ "$n_ts" -eq 1 ] || bail "B6: $TOR_DOCKERFILE pins $n_ts distinct snapshot timestamps (stages must agree): $ts"
grep -qF "$ts" "$SD" \
  || bail "B6: snapshot timestamp $ts (from $TOR_DOCKERFILE) not recorded in $SD — trust log drifted from build"

# --- report ----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T099 Tor build-inputs contract test (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T099 Tor build-inputs contract test (snapshot-pinned, version-pinned, fail-closed, cross-file)"
exit 0
