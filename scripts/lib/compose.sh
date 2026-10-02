#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# scripts/lib/compose.sh — the authoritative Compose-command builder for
# Stargate's operator scripts (T088). Single source of truth for project
# name, compose file, and env file, so `init` and the quickstart
# instructions (and, when they ship, export/import/wipe) all use the SAME
# project-scoped identity. This is the B1 fix (review/sol-review.md#B1):
# the shipped installer previously ran `docker compose -f ... up` with no
# `--env-file`, wrote to literal volume `stargate-keys` (Compose renders
# that as `<project>_stargate-keys`, so keys landed in an unused volume),
# and guessed container names (`docker inspect stargate-dp`) that never
# matched Compose's `<project>-stargate-dp-1` naming.
#
# Sourceable: defines functions + tunables only; no side effects on source.
# Callers: scripts/subcommands/init (T016/T088),
# tests/contract/stargate-cli/init_docker_test.sh. The tests point the
# tunables at a tiny fixture stack (no Stargate build) per B1's
# recommendation.
#
# No outbound network. These helpers invoke `docker`/`docker compose`
# against the local daemon only (Constitution III).
#
# Constitution principles landing here:
#   II  — the builder provisions install-time state only; it never sits in
#          the request path and introduces no CP→DP startup coupling.
#   III — no outbound except the docker daemon socket.
#   IV  — the keygen/init helper image is digest-pinned and a `*@sha256:*`
#          case-glob guards any override (T016 R5 + Constitution IV gate).

# Avoid double-evaluation when sourced alongside init (which also sets -u).
if [ -n "${BASH_SOURCE[0]:-}" ]; then
  # Resolve the repo root from this file's location so the defaults below
  # resolve regardless of the caller's CWD (the tests invoke init from a
  # temp dir; init must still find compose/ and compose/env/).
  case "${BASH_SOURCE[0]}" in
    */*) _SG_LIB_DIR="${BASH_SOURCE[0]%/*}" ;;
    *)   _SG_LIB_DIR="." ;;
  esac
  case "$_SG_LIB_DIR" in
    /*) : ;;
    *)  _SG_LIB_DIR="$(cd "$_SG_LIB_DIR" && pwd)" ;;
  esac
  _SG_REPO_ROOT="$(cd "$_SG_LIB_DIR/../.." && pwd)"
else
  _SG_REPO_ROOT="$(pwd)"
fi

# ---- tunables (env-overridable; tests point these at fixtures) -------------
: "${STARGATE_PROJECT:=stargate}"
: "${STARGATE_COMPOSE_FILE:=$_SG_REPO_ROOT/compose/docker-compose.local.yml}"
: "${STARGATE_ENV_DIR:=$_SG_REPO_ROOT/compose/env}"
: "${STARGATE_ENV_EXAMPLE:=$STARGATE_ENV_DIR/local.env.example}"
: "${STARGATE_ENV_FILE:=$STARGATE_ENV_DIR/local.env}"

# The throwaway helper image used to install keys/pepper and initialize
# volume ownership (named volumes are not host-writable at arbitrary UID).
# Digest-pinned per Constitution IV; MUST match the base-image pin in
# sidecars/tor/Dockerfile — the T016 init_test.sh R5 gate cross-checks the
# two for drift. An override MUST be `*@sha256:*` (guarded in init; the
# lib itself only echoes the value so tests can point it at a fixture).
STARGATE_KEYGEN_IMAGE_DEFAULT="debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df"
: "${STARGATE_KEYGEN_IMAGE:=$STARGATE_KEYGEN_IMAGE_DEFAULT}"

# Inter-plane key/pepper ownership (arch §4.3 + data-model §1.7). Numerics
# match the Dockerfiles and the compose `user:` directives — T016 M4
# cross-checks all three sources for drift.
CP_UID=5101          # stargate-cp (control-plane/Dockerfile useradd --uid 5101)
DP_UID=5102          # stargate-dp (data-plane/Dockerfile: stargate-dp:x:5102)
OBSERVER_UID=5103    # observer has Tor's UID only inside its distinct container
IPC_GID=5100         # stargate-ipc (both Dockerfiles groupadd --gid 5100)
OBSERVER_FABRIC_GID=5100 # CP's GID may connect; only observer writes the mounted fabric
KEY_PRIVATE_MODE=0600
KEY_PUBLIC_MODE=0644
PEPPER_MODE=0640     # data-model §1.7: pepper is group-readable by stargate-ipc

# Named volumes this project initialises at install time (data-model §6).
# stargate-keys carries the ed25519 keypairs + the pepper (T092); the others
# are runtime-writable mounts whose ROOTS must be chowned to the non-root
# service UID/GID before the planes start (B1: empty named-volume roots are
# root-owned, so UID 5101/5102 cannot create their UDS / SQLite / snapshot
# files there). The set mirrors compose/docker-compose.local.yml exactly.
KEYS_VOLUME="stargate-keys"
OBSERVER_KEYS_VOLUME="stargate-observer-keys"
OBSERVER_FABRIC_VOLUME="stargate-tor-cp-fabric"
IPC_VOLUME="stargate-ipc"
CONTROL_STATE_VOLUME="stargate-control-state"
CONTROL_CONFIG_VOLUME="stargate-control-config"
DP_STATE_VOLUME="stargate-dp-state"
PEPPER_FILE="pepper.key"   # co-located with the keypairs in stargate-keys

# ---- helpers --------------------------------------------------------------
_compose_say()  { printf '%s\n' "$*" >&2; }
_compose_note() { printf 'stargate: %s\n' "$*" >&2; }

# compose_env_file — ensure the env file exists (create from the example if
# absent; an empty file if the example is missing too). Idempotent. Echoes
# the env-file path on stdout. B1: init always supplies the env file; the
# file is gitignored (.gitignore:37 compose/env/*.env). Post-T094a the
# compose file has NO `${...}` substitutions, so this file is currently
# functionally empty — the convention is established per acceptance #2 and
# future-proofs the surface (T088 grounding decision).
compose_env_file() {
  if [ ! -f "$STARGATE_ENV_FILE" ]; then
    if [ -f "$STARGATE_ENV_EXAMPLE" ]; then
      cp -- "$STARGATE_ENV_EXAMPLE" "$STARGATE_ENV_FILE" 2>/dev/null \
        || { : > "$STARGATE_ENV_FILE"; }
    else
      : > "$STARGATE_ENV_FILE"
    fi
  fi
  printf '%s' "$STARGATE_ENV_FILE"
}

# compose_cmd — echo the authoritative compose invocation PREFIX:
#   docker compose -p <project> -f <file> --env-file <env>
# Caller appends the subcommand + args. Ensures the env file exists first.
# This is the single render the regression test asserts against (B1).
compose_cmd() {
  local env_file
  env_file="$(compose_env_file)"
  printf 'docker compose -p %s -f %s --env-file %s' \
    "$STARGATE_PROJECT" "$STARGATE_COMPOSE_FILE" "$env_file"
}

# compose_run — run a compose subcommand with the authoritative identity.
# Usage: compose_run up -d --build   |   compose_run ps -q stargate-dp
compose_run() {
  local env_file
  env_file="$(compose_env_file)"
  docker compose -p "$STARGATE_PROJECT" -f "$STARGATE_COMPOSE_FILE" \
    --env-file "$env_file" "$@"
}

# resolve_physical_volume <logical> — echo the physical volume name for a
# logical Compose volume under the current project, discovered by Compose
# LABEL (B1: resolve by Compose labels, never assume a literal `stargate-*`
# physical name). Empty if the volume does not yet exist.
resolve_physical_volume() {
  local logical="$1"
  docker volume ls \
    --filter "label=com.docker.compose.project=$STARGATE_PROJECT" \
    --filter "label=com.docker.compose.volume=$logical" \
    --format '{{.Name}}' 2>/dev/null \
    | head -n1
}

# ensure_project_volume <logical> — create the project-scoped volume (with
# Compose labels so a subsequent `compose up` reuses it by name) if absent;
# echo the physical name. Idempotent. B1: create the project volumes first,
# resolve physical names by Compose labels, then initialise their roots.
# The physical-name convention is `<project>_<volume>`; the labels are what
# `compose up` matches on to reuse a pre-created volume rather than make a
# fresh one (verified empirically for compose v5.x in T088 grounding).
ensure_project_volume() {
  local logical="$1"
  local phys
  phys="$(resolve_physical_volume "$logical")"
  if [ -z "$phys" ]; then
    phys="${STARGATE_PROJECT}_${logical}"
    if ! docker volume create \
        --label "com.docker.compose.project=$STARGATE_PROJECT" \
        --label "com.docker.compose.volume=$logical" \
        "$phys" >/dev/null 2>&1; then
      phys=""
    fi
  fi
  printf '%s' "$phys"
}

# init_volume_root <physical-volume> <owner-uid> <gid> <mode> — initialise a
# named volume's root directory ownership/mode via a throwaway digest-pinned
# helper container (named volumes are not host-writable at arbitrary UID).
# Non-recursive (root only): the three state volumes (ipc/control-state/
# dp-state) are empty at install time, and stargate-keys gets its
# per-file ownership/mode from the subsequent key+pepper install step. B1:
# empty named-volume roots are root-owned, so the non-root service UIDs
# cannot create their files there. The helper image MUST be `*@sha256:*`
# (Constitution IV).
init_volume_root() {
  local vol="$1" uid="$2" gid="$3" mode="$4"
  case "$STARGATE_KEYGEN_IMAGE" in
    *@sha256:*) : ;;
    *) _compose_note "init_volume_root: STARGATE_KEYGEN_IMAGE must be digest-pinned; refusing: $STARGATE_KEYGEN_IMAGE"
       return 1 ;;
  esac
  # HARDENED (redteam Major #1): the helper runs as root with RW on the
  # volume, so it gets NO network (--network none — it only chowns/chmods,
  # never dials out), ALL capabilities dropped except the two chown/chmod
  # need (CAP_CHOWN, CAP_FOWNER), a read-only rootfs, and a tmpfs /tmp for
  # any scratch. A digest-pinned-but-backdoored helper or a *@sha256:*
  # operator override thus cannot exfiltrate the keys/pepper it touches.
  docker run --rm --network none --cap-drop ALL --cap-add CHOWN --cap-add FOWNER \
    --read-only --tmpfs /tmp -v "${vol}:/v" "$STARGATE_KEYGEN_IMAGE" \
    sh -c "chown '${uid}:${gid}' /v && chmod '${mode}' /v" >/dev/null 2>&1
}

# T167 / Principle VII: the keys volume is mounted below the read-only
# control-config volume. Docker cannot create that child mountpoint once the
# parent has been mounted read-only, so provision the directory in the named
# config volume before Compose starts CP. The helper sees no keys or network.
init_control_config_mountpoint() {
  local vol="$1"
  case "$STARGATE_KEYGEN_IMAGE" in
    *@sha256:*) : ;;
    *) _compose_note "init_control_config_mountpoint: STARGATE_KEYGEN_IMAGE must be digest-pinned"
       return 1 ;;
  esac
  docker run --rm --network none --cap-drop ALL --cap-add DAC_OVERRIDE \
    --read-only --tmpfs /tmp -v "${vol}:/v" "$STARGATE_KEYGEN_IMAGE" \
    sh -c 'if [ -L /v/keys ]; then exit 1; fi; if [ -e /v/keys ]; then test -d /v/keys; else mkdir -m 0755 /v/keys; fi' \
    >/dev/null 2>&1
}

# refresh_observer_cp_pub <keys-phys> <observer-keys-phys> — copy the CP's
# current public key from stargate-keys into the observer's own key volume,
# atomically (write-tmp + rename in the same directory). T191 item 1: the
# observer authenticates the CP against this copy (re-read per authentication,
# foundation-boundaries.md T164), so after a CP key rotation (wire-auth.md
# §6.2) a stale copy keeps CP health dark. init calls this on every run; the
# rotation procedure calls it before restarting the CP. The helper runs as the
# observer UID with the stargate-ipc group: it can read the 0644 public key
# through the 0750 keys root and write only its own 0700 volume, so it needs
# no capability, no root and no network, and it never sees a private key's
# contents (cp.priv/dp.priv are 0600 to other owners).
refresh_observer_cp_pub() {
  local keys="$1" observer="$2"
  case "$STARGATE_KEYGEN_IMAGE" in
    *@sha256:*) : ;;
    *) _compose_note "refresh_observer_cp_pub: STARGATE_KEYGEN_IMAGE must be digest-pinned"
       return 1 ;;
  esac
  docker run --rm --network none --cap-drop ALL --read-only \
    --user "$OBSERVER_UID:$OBSERVER_UID" --group-add "$IPC_GID" \
    -v "${keys}:/keys:ro" -v "${observer}:/observer" "$STARGATE_KEYGEN_IMAGE" \
    sh -c 'set -e
      install -m '"$KEY_PUBLIC_MODE"' /keys/cp.pub /observer/.cp.pub.new
      mv -f /observer/.cp.pub.new /observer/cp.pub' >/dev/null 2>&1
}

# compose_health_ids <service...> — echo each service's container id (via
# `compose ps -q <svc>`) against the project, one per line. Empty lines are
# preserved positionally; callers test each for non-empty + running. B1:
# health uses Compose service IDs, never guessed names like
# `compose-stargate-dp-1`.
compose_health_ids() {
  local svc
  for svc in "$@"; do
    compose_run ps -q "$svc" 2>/dev/null || true
  done
}
