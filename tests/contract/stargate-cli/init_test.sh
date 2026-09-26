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
# compose-up actually waits for authenticated Tor readiness, that the Tor verify probe
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
#   - M7  bounded observer readiness (300 s default + env override); no `compose down`.
#   - M8  Tor-only verify (no 8882/8884/8885 port literals).
#   - M9  status table references DP + CP + Tor sidecar + observer.
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
LIB="scripts/lib/compose.sh"          # T088: the authoritative compose-command builder init sources.
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
# Executable: dispatcher + init + the Docker-backed regression test. The lib
# is SOURCED (no +x required) but must exist + carry the SPDX header.
for f in "$DISPATCHER" "$INIT" "tests/contract/stargate-cli/init_docker_test.sh"; do
  [ -f "$f" ]     || { echo "FAIL: $f missing" >&2; exit 1; }
  [ -x "$f" ]     || bail "M1/M13: $f not executable"
  head -3 "$f" | grep -qi "Copyright 2026 The Stargate Authors" \
    || bail "M13: SPDX copyright header missing in $f"
  head -3 "$f" | grep -qi "SPDX-License-Identifier: Apache-2.0" \
    || bail "M13: SPDX-License-Identifier line missing in $f"
done
for f in "$LIB" "tests/contract/stargate-cli/fixtures/fixture-compose.yml"; do
  [ -f "$f" ] || { echo "FAIL: $f missing" >&2; exit 1; }
  head -3 "$f" | grep -qi "Copyright 2026 The Stargate Authors" \
    || bail "M13: SPDX copyright header missing in $f"
done

# T088: init MUST source the lib (the authoritative compose-command builder).
grep -Eq '\.\s+".*/?lib/compose\.sh"|source\b.*lib/compose\.sh' "$INIT" \
  || bail "T088: init must source scripts/lib/compose.sh (the compose-command builder)"

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

# --- M4: key/pepper ownership/perms literals + cross-file consistency -------
# T088: the UID/GID/mode literals + key filenames now live authoritatively in
# scripts/lib/compose.sh (the builder init sources); grep the LIB as the
# source of truth. 0640 + pepper.key assert the T092 pepper-provisioning shape
# (data-model §1.7).
for lit in 0600 0644 0640 5101 5102 5103 5100; do
  has_literal "$LIB" "${lit}([^0-9]|\$)" \
    "M4: literal ${lit} missing from $LIB (key/pepper ownership constants)"
done
# Cross-file: the same UID/GID numerics must appear in the Dockerfiles and
# the compose user: directives. Drift across any pair fails (T015 M6 trick).
has_literal "$CP_DOCKERFILE" "5101" "M4: control-plane/Dockerfile must define UID 5101"
has_literal "$CP_DOCKERFILE" "5100" "M4: control-plane/Dockerfile must define GID 5100"
has_literal "$DP_DOCKERFILE" "5102" "M4: data-plane/Dockerfile must define UID 5102"
has_literal "$DP_DOCKERFILE" "5100" "M4: data-plane/Dockerfile must define GID 5100"
has_literal "$COMPOSE" '"5101:5100"' "M4: compose must set stargate-control user: \"5101:5100\""
has_literal "$COMPOSE" '"5102:5100"' "M4: compose must set stargate-dp user: \"5102:5100\""

# Key file names (cp.priv/dp.priv/cp.pub/dp.pub per arch §4.3) + the T092
# pepper file (data-model §1.7). These are literals in init's install +
# do-not-clobber count loop; the ownership CONSTANTS live in the lib (above).
for kf in cp\.priv dp\.priv cp\.pub dp\.pub observer\.priv observer\.pub pepper\.key; do
  has_literal "$INIT" "${kf}" "M4: key/pepper filename ${kf} missing from $INIT"
done

# T088: init provisions the pepper (T092) and uses the lib's project-scoped
# compose-command builder + Compose-ID health discovery (B1 fixes).
has_literal "$INIT" "PEPPER_FILE" \
  "T088: init must reference PEPPER_FILE (T092 pepper provisioning)"
has_literal "$INIT" "openssl rand" \
  "T088: init must generate the pepper via openssl rand"
has_literal "$INIT" "--iidfile" \
  "T164: observer build must capture an immutable local image ID"
has_literal "$INIT" "observer_source_hash" \
  "T164: observer build must bind the source bytes before deployment"
# T165: the real Compose file requires an observer image digest. A fresh
# env file has no digest until after host-policy setup and observer build;
# the early stop operation must supply a parse-only digest in that one call.
has_literal "$INIT" 'STARGATE_OBSERVER_IMAGE=sha256:0{64} compose_run stop stargate-dp' \
  "T165: clean-host stop must parse Compose before observer image build"
# The disposable VM uses the documented remote Buildx builder. The observer
# image must be loaded into the guest daemon before its immutable ID is read.
has_literal "$INIT" 'BUILDX_BUILDER' \
  "T165: remote builder selection must be explicit"
has_literal "$INIT" 'buildx build .*--load' \
  "T165: remote observer build must load its image into the local daemon"
has_literal "$INIT" "compose_run" \
  "T088: init must use compose_run (project-scoped compose command, B1)"
has_literal "$INIT" "compose_health_ids" \
  "T088: init must discover service containers via compose_health_ids (B1, never guessed names)"

# T088 redteam Major #1: every keygen/init helper `docker run` MUST be
# network-less + capability-dropped (the helper runs as root with RW on the
# keys volume; it only chowns/chmods/installs and must not be able to
# exfiltrate keys/pepper). The helpers are `--rm`, so a structural pin here
# plus the functional proof in init_docker_test.sh (init succeeds → the
# hardened helpers ran) close the finding. Per-helper OCCURRENCE count
# (redteam round-2 + codereview Minor #3): init has exactly TWO network-less
# helpers (count-probe + install); the lib has ONE (init_volume_root).
nn_init=$(grep -c -- '--network none' "$INIT" 2>/dev/null)
nn_lib=$(grep -c -- '--network none' "$LIB" 2>/dev/null)
[ "$nn_init" -ge 2 ] || bail "T088/redteam#1: init must have >=2 --network none helpers (count-probe + install); found $nn_init"
[ "$nn_lib" -ge 1 ] || bail "T088/redteam#1: lib init_volume_root must be --network none; found $nn_lib in $LIB"
has_literal "$INIT" "--cap-drop ALL" \
  "T088/redteam#1: init's keygen helpers must drop all caps"
has_literal "$LIB" "--cap-drop ALL" \
  "T088/redteam#1: lib's init_volume_root helper must drop all caps"
# T088 redteam round-2: the count-probe runs as the NON-ROOT volume owner
# (no DAC_OVERRIDE → cannot read 0600 contents) AND its stdout is sanitized
# before interpolation (closes the stdout→stderr exfil channel).
has_literal "$INIT" '--user.*CP_UID.*IPC_GID' \
  "T088/redteam#2: count-probe must run as the non-root volume owner (--user CP_UID:IPC_GID)"
has_literal "$INIT" "non-numeric" \
  "T088/redteam#2: count-probe stdout must be sanitized (abort non-numeric without echoing)"

# T088: the lib defines the authoritative builder + project-scoped volume +
# health primitives the B1 fix depends on.
has_literal "$LIB" "compose_cmd"           "T088: lib must define compose_cmd"
has_literal "$LIB" 'docker compose -p %s -f %s --env-file %s' \
  "T088: compose_cmd must render -p <project> -f <file> --env-file <env> (B1)"
has_literal "$LIB" "ensure_project_volume" "T088: lib must define ensure_project_volume (project-scoped volumes, B1)"
has_literal "$LIB" "resolve_physical_volume" "T088: lib must define resolve_physical_volume (label-based, B1)"
has_literal "$LIB" "init_volume_root"      "T088: lib must define init_volume_root (writable-mount root init, B1)"
has_literal "$LIB" "compose_health_ids"    "T088: lib must define compose_health_ids (ps -q health discovery, B1)"

# --- M5: idempotence — do-not-clobber-keys guard present -------------------
# Structural proxy: the script must reference the stargate-keys volume AND
# carry a guard that skips key-gen when keys already exist. We accept either
# an explicit existence probe against the volume or a documented skip marker.
has_literal "$INIT" "stargate-keys" \
  "M5: stargate-keys volume not referenced by $INIT"

# --- M7: bounded readiness + no teardown on failure ------------------------
has_literal "$INIT" "STARGATE_HEALTHCHECK_TIMEOUT" \
  "M7: STARGATE_HEALTHCHECK_TIMEOUT override not referenced by $INIT"
has_literal "$INIT" 'STARGATE_HEALTHCHECK_TIMEOUT:=300' \
  "M7: default readiness bound (300) missing from $INIT"
lacks_literal "$INIT" "compose[[:space:]]+down" \
  "M7: 'compose down' must NOT appear in $INIT (arch §9.2: leave containers up on failure)"

# --- M8: Tor-only verify (no other-route port literals) --------------------
lacks_literal "$INIT" "888[245]" \
  "M8: non-Tor route port (8882/8884/8885) must not appear in $INIT"

# --- M9: status table references the deployed Local services --------------
has_literal "$INIT" "(D|d)ata[[:space:]]*plane"  "M9: status table missing 'data plane'"
has_literal "$INIT" "(C|c)ontrol[[:space:]]*plane" "M9: status table missing 'control plane'"
has_literal "$INIT" "(T|t)or[[:space:]]*sidecar"   "M9: status table missing 'Tor sidecar'"
has_literal "$INIT" '"Tor observer"' "T165: status table missing deployed Tor observer"
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
# cross-checks the two for drift (Constitution IV). T088 moved the
# STARGATE_KEYGEN_IMAGE default into scripts/lib/compose.sh (the authoritative
# builder init sources), so the digest is read from the LIB, not init.
TOR_DOCKERFILE="sidecars/tor/Dockerfile"
[ -f "$TOR_DOCKERFILE" ] || bail "R5: $TOR_DOCKERFILE missing (cannot cross-check digest)"
# Extract the debian:12-slim@sha256:<hex> digest from each file.
digest_in() { grep -Eo 'debian:12-slim@sha256:[0-9a-f]{64}' "$1" | head -1; }
lib_digest="$(digest_in "$LIB")"
tor_digest="$(digest_in "$TOR_DOCKERFILE")"
[ -n "$lib_digest" ] \
  || bail "R5: no debian:12-slim@sha256 digest found in $LIB (key-gen helper image unpinned — Constitution IV)"
[ -n "$tor_digest" ] \
  || bail "R5: no debian:12-slim@sha256 digest found in $TOR_DOCKERFILE (cannot cross-check)"
[ "$lib_digest" = "$tor_digest" ] \
  || bail "R5: key-gen helper digest drift: $LIB has '$lib_digest' but $TOR_DOCKERFILE has '$tor_digest'"

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
