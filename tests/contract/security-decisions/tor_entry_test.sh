#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/security-decisions/tor_entry_test.sh — structural + cross-file
# contract test for SECURITY-DECISIONS.md (T017).
#
# Why this is structural (no runtime bring-up): SECURITY-DECISIONS.md is a
# documentation artifact. Its CONTRACT is (a) it exists at the repo root,
# (b) it carries the FR-015 Tor sidecar trust rationale with specific factual
# claims, and (c) those factual claims MUST NOT drift from the build
# artifacts they describe (`sidecars/tor/apt-key.fingerprint`,
# `sidecars/tor/Dockerfile`). The cross-file checks are the load-bearing part:
# they promote drift-detection into the PR-cadence gate. Without them, an
# apt-key rotation or base-digest bump that updates the Dockerfile but not
# SECURITY-DECISIONS.md (or vice versa) would silently desync the trust
# record from the actual build.
#
# Properties gated (M-numbers reference T017 §Analysis):
#   - M1 file exists at repo root + SPDX header.
#   - M2 append-only preamble present.
#   - M3 Tor rationale: deb.torproject.org + build-vs-fork reasoning.
#   - M4 apt-key fingerprint present AND == sidecars/tor/apt-key.fingerprint.
#   - M5 debian:12-slim base digest present AND == sidecars/tor/Dockerfile FROM.
#   - M6 final-image digest honesty: references T081/release-tag; does NOT
#         present a fabricated final-image sha256 pin as current.
#   - M7 reserved adversarial-review section heading present.
#   - M8 (T017's original scope-boundary assertion) was REMOVED in T017a:
#         T017a appends the docker-socket-proxy entry, so the
#         "lacks docker-socket-proxy" assertion is obsolete. The positive
#         assertions for the docker-socket-proxy entry live in
#         tests/contract/security-decisions/docker_socket_proxy_entry_test.sh
#         (T017a AT-1).
#
# Hermetic: file reads + grep only. No network, no daemon.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

SD="SECURITY-DECISIONS.md"
FPR_FILE="sidecars/tor/apt-key.fingerprint"
TOR_DOCKERFILE="sidecars/tor/Dockerfile"

errs=()
bail() { errs+=("$*"); }

[ -f "$SD" ]         || { echo "FAIL: $SD missing" >&2; exit 1; }
[ -f "$FPR_FILE" ]   || { echo "FAIL: $FPR_FILE missing" >&2; exit 1; }
[ -f "$TOR_DOCKERFILE" ] || { echo "FAIL: $TOR_DOCKERFILE missing" >&2; exit 1; }
command -v grep >/dev/null 2>&1 || { echo "FAIL: grep not installed" >&2; exit 1; }

# has <pattern> <label> — grep -Ei on SECURITY-DECISIONS.md.
has() { grep -Ei -- "$1" "$SD" >/dev/null 2>&1 || bail "$2 (pattern '$1' not found in $SD)"; }
lacks() { grep -Ei -- "$1" "$SD" >/dev/null 2>&1 && bail "$2 (forbidden pattern '$1' found in $SD)"; }

# --- M1: file exists at root + SPDX header ---------------------------------
head -5 "$SD" | grep -qi "Copyright 2026 The Stargate Authors" \
  || bail "M1: SPDX copyright header missing in $SD"
head -5 "$SD" | grep -qi "SPDX-License-Identifier: Apache-2.0" \
  || bail "M1: SPDX-License-Identifier line missing in $SD"

# --- M2: append-only preamble + entry-body immutability --------------------
has "append-only|append[ -]only" "M2: append-only purpose statement missing"
# Constitution VI: the preamble MUST bind entry-body immutability (a future
# PR must not silently edit a dated entry's body in place — it must supersede).
# Without this clause the keyword/cross-file gates do not catch a softening
# edit (redteam MAJOR: append-only preamble permitted silent weakening). We
# assert BOTH the immutability claim AND the binding-reviewer language
# ("MUST be rejected") so a keyword-preserving softening of the preamble
# itself also fails the gate (redteam MINOR: the clause protects dated
# entries but was not self-protecting).
has "immutable once committed" "M2: entry-body immutability clause missing from preamble (Constitution VI)"
grep -Ei "MUST be rejected" "$SD" >/dev/null 2>&1 \
  || bail "M2: preamble must bind reviewers to reject in-place body edits (the 'MUST be rejected' clause is missing)"

# --- M3: Tor rationale (FR-015) --------------------------------------------
has "deb\.torproject\.org" "M3: Tor entry must reference deb.torproject.org"
# The build-vs-fork/upstream choice must be discussed. Accept any of the
# reasoned keyword clusters; the prose correctness is redteam's job (R1).
has "(official (debian )?apt repositor|tor project publishes no|no official docker image|build.*from.*pinned debian)" \
  "M3: Tor entry must explain the build-vs-fork/upstream choice"

# --- M4: apt-key fingerprint + cross-file ----------------------------------
FPR="$(tr -d '[:space:]' < "$FPR_FILE")"
[ -n "$FPR" ] || { echo "FAIL: $FPR_FILE is empty" >&2; exit 1; }
has "$FPR" "M4: apt-key fingerprint ($FPR) from $FPR_FILE missing in $SD"
# Rotation policy stated.
has "(rotation|rotate|key rotation|signing key)" "M4: apt-key rotation policy missing"

# --- M5: debian:12-slim base digest + cross-file ---------------------------
# Extract the debian:12-slim@sha256:<64hex> digest pinned in the Tor Dockerfile
# (both stages use it; head -1 takes the first occurrence — the test below
# asserts both stages agree by checking the count separately).
TOR_BASE_DIGEST="$(grep -Eo 'debian:12-slim@sha256:[0-9a-f]{64}' "$TOR_DOCKERFILE" | head -1)"
[ -n "$TOR_BASE_DIGEST" ] \
  || { echo "FAIL: no debian:12-slim@sha256 digest in $TOR_DOCKERFILE" >&2; exit 1; }
# Both stages MUST pin the SAME digest (the Dockerfile comment says they stay
# in sync by convention; assert it here so a drift in stage 2 fails the gate).
TOR_DIGEST_COUNT="$(grep -Eo 'debian:12-slim@sha256:[0-9a-f]{64}' "$TOR_DOCKERFILE" | sort -u | wc -l | tr -d ' ')"
[ "$TOR_DIGEST_COUNT" -eq 1 ] \
  || bail "M5: $TOR_DOCKERFILE pins $TOR_DIGEST_COUNT distinct debian:12-slim digests (stages drifted)"
has "${TOR_BASE_DIGEST#*@}" "M5: base digest ${TOR_BASE_DIGEST#*@} (from $TOR_DOCKERFILE) missing in $SD"

# --- M6: final-image digest honesty ----------------------------------------
# The entry must reference T081 / release-tag-time pinning (the gap is real
# and release-blocking per FR-015 literal text).
has "(T081|release[ -]tag|release\.yml|final[ -]image.*pin|GHCR)" \
  "M6: final-image digest entry must reference T081 / release-tag-time pinning"
# It must NOT present a fabricated final-image sha256 pin as current. The
# compose file (T015) uses build: directives, not image@sha256 for the three
# Stargate-built images. A line asserting e.g. "stargate/tor@sha256:..." as a
# CURRENT pin would be a false claim. Allow the literal word "sha256" in
# prose (it appears for the base digest); forbid a `<repo>/<image>@sha256:`
# final-image form presented as pinned. We approximate by forbidding the
# Stargate-built image names followed by @sha256:.
# NOTE: when T081 lands and appends the REAL final-image digests
# (`ghcr.io/zcat-app/stargate-{dp,control,tor}@sha256:...`), this pattern
# MUST be relaxed to scope the prohibition to "current pin" framing (e.g.
# forbid the bare `stargate/tor@sha256:` form without the `ghcr.io/`
# registry prefix, or re-anchor the assertion to the release variant
# compose file). T081 owns that test edit; until then the fabrication guard
# is load-bearing.
lacks "(stargate-dp|stargate-control|stargate/tor)@sha256:[0-9a-f]{64}" \
  "M6: $SD must not present a fabricated final-image digest as currently pinned (T081 produces these at release tag)"

# --- M7: reserved adversarial-review section -------------------------------
has "(adversarial[ -]review|redteam|stargate-redteam|stargate-perf|accepted[ -]finding)" \
  "M7: reserved adversarial-review / accepted-findings section missing"

# --- M9: THREAT-MODEL §8.6 resolution citation (redteam MAJOR 2) -----------
# The Tor entry resolves §8.6's "unresolved trust decision" by building
# in-house; the entry MUST cite §8.6 so an auditor reading the model + the
# log together can reconstruct the decision. The §8.6 spec edit itself is
# the T082 follow-up (sibling to T018); the citation here is T017's half.
has "8\.6" "M9: Tor entry must cite THREAT-MODEL §8.6 (resolves its 'unresolved trust decision')"

# --- M10: transitive-dependency residual (redteam MAJOR 1) -----------------
# Tor's link-time closure (libssl3 et al.) rides on Debian's archive key,
# not the Tor Project's. This is the single most security-relevant residual
# and MUST appear in the residual-risk section (Constitution V).
has "libssl3" "M10: residual-risk section must name libssl3 (Tor's TLS crypto dep) — transitive-deps trust residual"

# --- M8: REMOVED in T017a ---------------------------------------------------
# T017's original M8 (`lacks "docker-socket-proxy"`) was a scope-boundary
# signal: T017 established the file + the Tor entry only, and T017a was
# the follow-up that appends the docker-socket-proxy rationale. T017a
# landed that entry (directly above the Tor entry, per the preamble's
# newest-first ordering), so the absence-assertion is obsolete — keeping
# it would fail the gate the moment the docker-socket-proxy entry landed.
# The positive assertions for that entry live in
# tests/contract/security-decisions/docker_socket_proxy_entry_test.sh
# (T017a AT-1). This block is retained as a marker so future readers
# don't re-introduce an M8 absence-assertion here.

# --- report ----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T017 SECURITY-DECISIONS.md contract test (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T017 SECURITY-DECISIONS.md contract test (Tor entry + cross-file fingerprint/digest invariants)"
exit 0
