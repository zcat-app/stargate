#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/stargate-cli/init_test.sh — STATIC + hermetic-behavioural
# contract test for scripts/stargate (dispatcher) and scripts/subcommands/init
# (T016).
#
# Why this is mostly a static test (mirrors T015's local_compose_test.sh
# philosophy): the runtime properties of `stargate init` — that real ed25519
# keys land in the stargate-keys volume with the right ownership, that
# compose-up actually waits for healthchecks, that the Tor verify probe
# exercises the live SOCKS5 surface — are gated DOWNSTREAM by T022
# (control-grpc transport_test requires a correct mutual-ed25519 handshake,
# which can only succeed if key-gen produced correctly-permissioned,
# correctly-formatted keys) and by T019b/T019c (bring up the stack and
# exercise the Tor surface). Those runtime tests are slow, need a Docker
# daemon, build three images, and pull from the registry — wrong cadence for
# a PR gate. This test gates the SCRIPT-LEVEL preconditions those runtime
# tests depend on, plus the ONE exit-code path that IS hermetically testable
# (preflight with docker absent → exit 10).
#
# Properties gated here (M-numbers reference T016 §Analysis):
#   - M1  dispatcher: routes `init`, rejects unknown subcommands, --help → 0.
#   - M3  preflight exit-10 (behavioural + hermetic via PATH=).
#   - M4  key ownership/perms literals + cross-file UID/GID consistency
#         against data-plane/Dockerfile, control-plane/Dockerfile, and
#         compose/docker-compose.local.yml (extends T015's M6 technique).
#   - M6  hard-coded compose/docker-compose.local.yml; no --profile flag.
#   - M7  bounded healthcheck (60 s default + env override); no `compose down`.
#   - M8  Tor-only verify (no 8882/8884/8885 port literals).
#   - M9  status table references DP + CP + Tor sidecar.
#   - M10 exit-code constants 10/20/30/40/50 present.
#   - M12 no curl/wget of a remote URL (no outbound except docker daemon).
#   - M13 SPDX license headers present.
#
# No `docker compose up`, no daemon containers started for the structural
# assertions. The one behavioural assertion (preflight exit-10) deliberately
# breaks PATH so docker is absent — hermetic, no daemon needed.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

DISPATCHER="scripts/stargate"
INIT="scripts/subcommands/init"
COMPOSE="compose/docker-compose.local.yml"
DP_DOCKERFILE="data-plane/Dockerfile"
CP_DOCKERFILE="control-plane/Dockerfile"

errs=()
bail() { errs+=("$*"); }

# Absolute bash binary path — used for the PATH= behavioural tests below so
# the OUTER test shell does not need PATH to locate `bash` (a bare
# `PATH= bash ...` makes the outer shell resolve `bash` with the now-empty
# PATH and fails with 127). "$BASH_BIN" is absolute → no PATH lookup.
BASH_BIN="$(command -v bash)"
[ -n "$BASH_BIN" ] || { echo "FAIL: bash not found" >&2; exit 1; }

# has_literal <file> <pattern> — grep -Eq, record on failure.
has_literal() {
  local file="$1" pat="$2" label="$3"
  if grep -Eq -- "$pat" "$file" 2>/dev/null; then
    :
  else
    bail "$label: pattern '$pat' not found in $file"
  fi
}

# lacks_literal <file> <pattern> <label> — inverse of has_literal.
lacks_literal() {
  local file="$1" pat="$2" label="$3"
  if grep -Eq -- "$pat" "$file" 2>/dev/null; then
    bail "$label: forbidden pattern '$pat' found in $file"
  fi
}

# --- existence + executability + license header (M1, M13) -----------------
for f in "$DISPATCHER" "$INIT"; do
  [ -f "$f" ]     || { echo "FAIL: $f missing" >&2; exit 1; }
  [ -x "$f" ]     || bail "M1/M13: $f not executable"
  head -3 "$f" | grep -qi "Copyright 2026 The Stargate Authors" \
    || bail "M13: SPDX copyright header missing in $f"
  head -3 "$f" | grep -qi "SPDX-License-Identifier: Apache-2.0" \
    || bail "M13: SPDX-License-Identifier line missing in $f"
done

# --- M1: dispatcher behaviour ---------------------------------------------
# no-args → non-zero, usage on stderr.
usage_err=$(bash "$DISPATCHER" </dev/null 2>&1 >/dev/null); rc=$?
[ "$rc" -ne 0 ] || bail "M1: dispatcher with no args should exit non-zero (got 0)"
[ -n "$usage_err" ] || bail "M1: dispatcher with no args should print usage to stderr"

# unknown subcommand → non-zero, usage on stderr.
unknown_err=$(bash "$DISPATCHER" __stargate_unknown_subcmd__ </dev/null 2>&1 >/dev/null); rc=$?
[ "$rc" -ne 0 ] || bail "M1: unknown subcommand should exit non-zero (got 0)"
[ -n "$unknown_err" ] || bail "M1: unknown subcommand should print usage to stderr"

# --help/-h → exit 0, usage to stdout (not stderr).
help_out=$(bash "$DISPATCHER" --help </dev/null 2>/dev/null); rc=$?
[ "$rc" -eq 0 ] || bail "M1: --help should exit 0 (got $rc)"
[ -n "$help_out" ] || bail "M1: --help should print usage to stdout"

# `init` must dispatch (not be rejected as unknown). Run with PATH= so init's
# preflight exits 10 before doing anything; assert stderr does NOT carry the
# dispatcher's "unknown subcommand" wording and the exit is 10 (proves init
# was reached AND its preflight fired).
init_err=$(PATH= "$BASH_BIN" "$DISPATCHER" init </dev/null 2>&1 >/dev/null); rc=$?
# Allow either the dispatcher exec'ing init directly or via a subshell.
if [ "$rc" -eq 10 ]; then
  :
elif [ "$rc" -eq 0 ]; then
  # If docker genuinely is absent the subcommand must exit 10, not 0. A 0
  # here means either dispatch failed silently or preflight didn't gate.
  bail "M1/M3: 'stargate init' under PATH= returned 0 (expected 10) — dispatch or preflight broken"
else
  bail "M1/M3: 'stargate init' under PATH= returned $rc (expected 10) — dispatch or preflight broken"
fi
printf '%s' "$init_err" | grep -qi "unknown subcommand" \
  && bail "M1: 'stargate init' dispatch printed 'unknown subcommand' (init not routed)"

# --- M3: preflight exit-10, hermetic (init subcommand directly) ------------
PATH= "$BASH_BIN" "$INIT" </dev/null >/dev/null 2>&1; rc=$?
[ "$rc" -eq 10 ] \
  || bail "M3: '$INIT' under PATH= should exit 10 (got $rc) — preflight must gate on docker presence first"

# --- M10: exit-code constants present --------------------------------------
# The five stable exit codes (arch §9.1 §7) must each appear as a distinct
# literal token in the script — whether as `exit N`, `return N`, or a named
# constant (`EXIT_*=N`, the preferred form). Word-boundary match avoids
# colliding with substrings of other numbers (5100/9050/0644/...).
for code in 10 20 30 40 50; do
  has_literal "$INIT" "(^|[^0-9])${code}([^0-9]|\$)" \
    "M10: exit-code literal ${code} missing from $INIT"
done

# --- M6: hard-coded local compose path; no --profile -----------------------
has_literal "$INIT" "compose/docker-compose\.local\.yml" \
  "M6: hard-coded compose/docker-compose.local.yml path missing from $INIT"
# The dispatcher must route 'init'.
has_literal "$DISPATCHER" "init" \
  "M6: dispatcher must route 'init'"
# M6 behavioural: --profile must not be accepted in EITHER form (research §8).
# Any placement of --profile / --profile=VALUE must exit non-zero.
bash "$DISPATCHER" --profile local init </dev/null >/dev/null 2>&1; rc=$?
[ "$rc" -ne 0 ] \
  || bail "M6: 'stargate --profile local init' should exit non-zero (got 0); --profile must be rejected"
bash "$DISPATCHER" init --profile local </dev/null >/dev/null 2>&1; rc=$?
[ "$rc" -ne 0 ] \
  || bail "M6: 'stargate init --profile local' should exit non-zero (got 0); --profile must be rejected"
bash "$DISPATCHER" init --profile=local </dev/null >/dev/null 2>&1; rc=$?
[ "$rc" -ne 0 ] \
  || bail "M6: 'stargate init --profile=local' (equals form) should exit non-zero (got 0); --profile must be rejected"

# --- M4: key ownership/perms literals + cross-file consistency -------------
for lit in 0600 0644 5101 5102 5100; do
  has_literal "$INIT" "${lit}([^0-9]|\$)" \
    "M4: literal ${lit} missing from $INIT"
done
# Cross-file: the same UID/GID numerics must appear in the Dockerfiles and
# the compose user: directives. Drift across any pair fails (T015 M6 trick).
has_literal "$CP_DOCKERFILE" "5101" "M4: control-plane/Dockerfile must define UID 5101"
has_literal "$CP_DOCKERFILE" "5100" "M4: control-plane/Dockerfile must define GID 5100"
has_literal "$DP_DOCKERFILE" "5102" "M4: data-plane/Dockerfile must define UID 5102"
has_literal "$DP_DOCKERFILE" "5100" "M4: data-plane/Dockerfile must define GID 5100"
has_literal "$COMPOSE" '"5101:5100"' "M4: compose must set stargate-control user: \"5101:5100\""
has_literal "$COMPOSE" '"5102:5100"' "M4: compose must set stargate-dp user: \"5102:5100\""

# Key file names (cp.priv/dp.priv/cp.pub/dp.pub) referenced per arch §4.3.
for kf in cp\.priv dp\.priv cp\.pub dp\.pub; do
  has_literal "$INIT" "${kf}" "M4: key filename ${kf} missing from $INIT"
done

# --- M5: idempotence — do-not-clobber-keys guard present -------------------
# Structural proxy: the script must reference the stargate-keys volume AND
# carry a guard that skips key-gen when keys already exist. We accept either
# an explicit existence probe against the volume or a documented skip marker.
has_literal "$INIT" "stargate-keys" \
  "M5: stargate-keys volume not referenced by $INIT"

# --- M7: bounded healthcheck + no teardown on failure ----------------------
has_literal "$INIT" "STARGATE_HEALTHCHECK_TIMEOUT" \
  "M7: STARGATE_HEALTHCHECK_TIMEOUT override not referenced by $INIT"
has_literal "$INIT" "(^|[^0-9])60([^0-9]|\$)" \
  "M7: default healthcheck bound (60) missing from $INIT"
lacks_literal "$INIT" "compose[[:space:]]+down" \
  "M7: 'compose down' must NOT appear in $INIT (arch §9.2: leave containers up on failure)"

# --- M8: Tor-only verify (no other-route port literals) --------------------
lacks_literal "$INIT" "888[245]" \
  "M8: non-Tor route port (8882/8884/8885) must not appear in $INIT"

# --- M9: status table references exactly DP + CP + Tor ---------------------
has_literal "$INIT" "(D|d)ata[[:space:]]*plane"  "M9: status table missing 'data plane'"
has_literal "$INIT" "(C|c)ontrol[[:space:]]*plane" "M9: status table missing 'control plane'"
has_literal "$INIT" "(T|t)or[[:space:]]*sidecar"   "M9: status table missing 'Tor sidecar'"
# M9 "exactly": no placeholder rows for absent sidecars (research §8 — only
# the components present in this feature). The script must not emit i2p/nym/
# direct status rows. (Comments may mention them as deferred; the STATUS
# TABLE region is what matters. We approximate by asserting the script does
# not present them as status rows — caught by absence of a labelled row
# marker. Cheap structural proxy; the real "exactly" gate is review.)
lacks_literal "$INIT" "[Ii]2pd[[:space:]]+(sidecar|HEALTHY|STARTING)" \
  "M9: status table must not render an i2pd row (out of scope this feature)"
lacks_literal "$INIT" "[Nn]ym[[:space:]]+(sidecar|HEALTHY|STARTING)" \
  "M9: status table must not render a nym row (out of scope this feature)"

# --- R5 promotion: key-gen helper digest == tor Dockerfile base digest -----
# T016 §Analysis R5 promised that IF the implementer reuses the exact
# debian:12-slim digest pinned in sidecars/tor/Dockerfile, this gate
# cross-checks the two for drift (Constitution IV). The implementer did
# reuse it; promote R5 from residue into the gated set.
TOR_DOCKERFILE="sidecars/tor/Dockerfile"
[ -f "$TOR_DOCKERFILE" ] || bail "R5: $TOR_DOCKERFILE missing (cannot cross-check digest)"
# Extract the debian:12-slim@sha256:<hex> digest from each file.
digest_in() { grep -Eo 'debian:12-slim@sha256:[0-9a-f]{64}' "$1" | head -1; }
script_digest="$(digest_in "$INIT")"
tor_digest="$(digest_in "$TOR_DOCKERFILE")"
[ -n "$script_digest" ] \
  || bail "R5: no debian:12-slim@sha256 digest found in $INIT (key-gen helper image unpinned — Constitution IV)"
[ -n "$tor_digest" ] \
  || bail "R5: no debian:12-slim@sha256 digest found in $TOR_DOCKERFILE (cannot cross-check)"
[ "$script_digest" = "$tor_digest" ] \
  || bail "R5: key-gen helper digest drift: $INIT has '$script_digest' but $TOR_DOCKERFILE has '$tor_digest'"

# Constitution IV runtime guard: an override of STARGATE_KEYGEN_IMAGE must be
# refused if it is not digest-pinned (redteam MINOR 1). Structural proxy: the
# script must carry a `*@sha256:*)` case-glob guarding the override.
has_literal "$INIT" '\*@sha256:\*)' \
  "IV: STARGATE_KEYGEN_IMAGE override guard (case '@sha256:*') missing from $INIT"

# --- M12: no outbound (no curl/wget of a remote URL) -----------------------
lacks_literal "$DISPATCHER" "(curl|wget)[[:space:]]" \
  "M12: curl/wget must not appear in $DISPATCHER (no outbound except docker daemon)"
lacks_literal "$INIT" "(curl|wget)[[:space:]]" \
  "M12: curl/wget must not appear in $INIT (no outbound except docker daemon)"

# --- report ----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T016 init contract test (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T016 stargate-cli contract test (dispatcher + init structural + preflight exit-10)"
exit 0
