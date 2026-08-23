#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/threat-model/local_stack_consistency_test.sh — structural
# contract test for THREAT-MODEL.md's load-bearing facts about the local
# stack (T082).
#
# Why structural-only: T082 is a doc-sync amendment. The facts it pins are
# the ones a silent edit could regress without any code changing:
#   - §8.6 records the sidecar-maintainer decision as RESOLVED (in-house
#     build from deb.torproject.org) and cites the authoritative entry in
#     SECURITY-DECISIONS.md — not "unresolved / choose a community
#     maintainer" (Constitution V: the model must not contradict the
#     decision log), and must not claim final image digests are already
#     pinned (they are release-time, T081).
#   - §2.6's sidecar-residual pointer cites §5.8 (Sidecar compromise),
#     not §5.7 (Browser fingerprinting) — the pre-existing dead pointer.
#   - No stale-authorship markers ("once authored" / "not yet authored")
#     remain: SECURITY-DECISIONS.md and CONTRIBUTING.md both exist now.
#   - §9 names the concrete private reporting channel (GitHub Security
#     Advisories), matching CONTRIBUTING.md "Reporting security issues".
#
# Deliberately NOT asserted: incidental wording of any paragraph. These are
# focused, load-bearing assertions only (T082 acceptance #5); prose may be
# reworded freely as long as these properties hold.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

TM="THREAT-MODEL.md"
SD="SECURITY-DECISIONS.md"
CT="CONTRIBUTING.md"
errs=()
bail() { errs+=("$*"); }

[ -f "$TM" ] || { echo "FAIL: $TM missing" >&2; exit 1; }

section() { # section <from-heading-regex> — print one ### block to stdout
  awk -v pat="$1" '
    $0 ~ pat {insec=1; next}
    /^### / && insec {insec=0}
    insec {print}
  ' "$TM"
}

S26=$(section '^### 2[.]6 ')
S86=$(section '^### 8[.]6 ')
S59=$(section '^### 5[.]9 ')
S9=$(awk '/^## 9\. /{insec=1; next} /^## /&&insec{insec=0} insec{print}' "$TM")

# --- M1: §8.6 states the resolved decision and cites its record -----------
printf '%s' "$S86" | grep -qi 'unresolved trust decision' \
  && bail "T082/M1: §8.6 still calls the sidecar-maintainer decision unresolved; SECURITY-DECISIONS.md resolves it (2026-07-04 entry)."
printf '%s' "$S86" | grep -qi 'choose a community maintainer' \
  && bail "T082/M1: §8.6 still prescribes choosing a community maintainer; the delivered topology builds the Tor sidecar in-house."
printf '%s' "$S86" | grep -q '2026-07-04 — Tor sidecar trust rationale (FR-015)' \
  || bail "T082/M1: §8.6 must cite SECURITY-DECISIONS.md §\"2026-07-04 — Tor sidecar trust rationale (FR-015)\" as the authoritative record."
grep -q '^## 2026-07-04 — Tor sidecar trust rationale (FR-015)' "$SD" \
  || bail "T082/M1: the cited SECURITY-DECISIONS.md entry is missing — §8.6 would point at nothing."
printf '%s' "$S86" | grep -Eiq 'final.{0,60}digests? (is|are) pinned[^.]*(yet|not)' \
  || printf '%s' "$S86" | grep -Eiq 'digests? (is|are) not yet pinned|not yet pinned' \
  || bail "T082/M1: §8.6 must state honestly that final composed image digests are not yet pinned (release-time, T081) — Constitution V."

# --- M2: §2.6's sidecar residual points at §5.8, not §5.7 -----------------
printf '%s' "$S26" | grep -q '§5\.7' \
  && bail "T082/M2: §2.6 cites §5.7 (Browser fingerprinting) where the sidecar-compromise residual lives in §5.8."
printf '%s' "$S26" | grep -q '§5\.8' \
  || bail "T082/M2: §2.6 lost its §5.8 cross-reference entirely."

# --- M3/acc#3: stale-authorship markers are gone ---------------------------
grep -n 'once authored' "$TM" \
  && bail "T082/acc3: THREAT-MODEL.md still contains \"(once authored)\" — SECURITY-DECISIONS.md exists; cite it concretely."
grep -n 'not yet authored' "$TM" \
  && bail "T082/acc3: THREAT-MODEL.md still contains \"not yet authored\" — CONTRIBUTING.md exists; cite it concretely."

# --- acc#4: §9 names the concrete private channel --------------------------
[ -f "$CT" ] || bail "T082/acc4: CONTRIBUTING.md missing — §9 rewrite assumes it exists."
printf '%s' "$S9" | grep -Eq '/security/advisories' \
  || bail "T082/acc4: §9 must name the GitHub Security Advisory private-reporting route (see CONTRIBUTING.md)."

# --- acc#6: §5.9's update-channel text agrees with the snapshot pin --------
printf '%s' "$S59" | grep -q 'snapshot.debian.org' \
  || bail "T082/acc6: §5.9 no longer mentions the snapshot.debian.org pin (T099) — model and decision log drifted."

# === Report ================================================================
if (( ${#errs[@]} > 0 )); then
  printf 'FAIL: %d assertion(s) failed:\n' "${#errs[@]}" >&2
  for e in "${errs[@]}"; do printf '  - %s\n' "$e" >&2; done
  exit 1
fi
echo "OK: THREAT-MODEL.md local-stack facts pass all T082 structural assertions (§8.6 resolved + cited, §2.6→§5.8, no stale authorship, §9 advisory route)."
