#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/compose/local_compose_test.sh — STATIC structural contract
# test for compose/docker-compose.local.yml (T015).
#
# Why this is a static test (not a runtime bring-up): the runtime properties
# (Tor port exposure from the host, inter-plane UDS topology) are gated by
# T019b and T022, which bring up the compose stack. This test gates the
# compose-FILE preconditions those runtime tests depend on — properties a
# silent compose-file edit could regress between runtime-test runs:
#   - DP port 8881 bound to loopback only (FR-005; FR-012-in-spirit).
#   - Tor SocksPort/ControlPort never host-published (FR-012).
#   - NO service mounts /var/run/docker.sock (Constitution Principle III).
#   - UID/GID numerics match the Dockerfiles exactly (control-grpc.md
#     §"Socket topology").
#   - Exactly the seven named volumes from data-model.md §6.
#   - DP has no depends_on (Constitution Principle II — DP keeps routing
#     if CP is unreachable).
#
# T094a removed the docker-socket-proxy auxiliary container: the CP now
# observes Tor lifecycle via the cookie-authenticated ControlPort
# (tor:9051), NOT a Docker Engine observer. This file's prior proxy-
# specific assertions (docker.sock sole-mounter == docker-socket-proxy,
# the proxy env lockdown EVENTS=1/CONTAINERS=1/POST=0, the proxy image
# digest shape) are moot now that the proxy is gone, and the runtime
# lockdown contract test tests/contract/sidecar-proxy/ was removed in the
# same ticket. The old "sole-mounter == docker-socket-proxy" check is
# inverted here to the load-bearing "ZERO docker.sock mounters" property
# (Principle III — no auxiliary host-root-pivot surface). The network-split
# + per-container hardening landed in T094b: M13 now asserts the split
# topology statically (3 nets, internal:true flags, per-service membership,
# Tor as sole egress attachee); the runtime reachability + hardening is
# gated by tests/contract/compose/network_hardening_test.go (//go:build
# docker, T094b, run via STARGATE_TEST_TAGS=docker).
#
# Mechanism: `docker compose -f <file> --env-file <env> config --format json`
# renders the compose file to canonical JSON (long-form schema: ports use
# host_ip/target/published/protocol; volumes are {type,source,target,read_only});
# jq asserts the properties above. No `docker compose up` — no daemon
# containers are started. Fast, hermetic, runs at PR cadence under verify.sh
# gate 4.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

COMPOSE_FILE="compose/docker-compose.local.yml"
ENV_FILE="compose/env/local.env.example"
errs=()
bail() { errs+=("$*"); }

[ -f "$COMPOSE_FILE" ] || { echo "FAIL: $COMPOSE_FILE missing" >&2; exit 1; }
[ -f "$ENV_FILE" ]     || { echo "FAIL: $ENV_FILE missing"     >&2; exit 1; }
command -v jq >/dev/null 2>&1     || { echo "FAIL: jq not installed"     >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "FAIL: docker not installed" >&2; exit 1; }

RENDER="$(mktemp)"
trap 'rm -f "$RENDER"' EXIT
if ! docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" config --format json >"$RENDER" 2>/tmp/T015.compose.err; then
  echo "FAIL: 'docker compose config' did not render cleanly:" >&2
  cat /tmp/T015.compose.err >&2
  exit 1
fi
rm -f /tmp/T015.compose.err

# q <filter> — print jq output (single line expected).
q() { jq -r "$1" "$RENDER"; }

# --- M11: exactly three services (T094a dropped docker-socket-proxy) -----
ALL_SVCS="$(q '.services | keys_unsorted | sort | join(",")')"
[ "$ALL_SVCS" = "stargate-control,stargate-dp,tor" ] \
  || bail "M11: expected exactly 3 services (stargate-control,stargate-dp,tor — docker-socket-proxy removed by T094a); got: $ALL_SVCS"

# --- M1: DP port 8881 loopback-only, no 0.0.0.0 short form ------------------
# Long-form schema: ports[] = {host_ip, target, published, protocol}.
DP_PORT_COUNT="$(q '.services["stargate-dp"].ports | length')"
[ "$DP_PORT_COUNT" = "1" ] || bail "M1: stargate-dp must publish exactly one port; got $DP_PORT_COUNT"
DP_PUB_HOST="$(q '.services["stargate-dp"].ports[0].host_ip // ""')"
DP_PUB_PORT="$(q '.services["stargate-dp"].ports[0].published // ""')"
DP_TGT="$(q '.services["stargate-dp"].ports[0].target // ""')"
DP_PROTO="$(q '.services["stargate-dp"].ports[0].protocol // ""')"
[ "$DP_PUB_HOST" = "127.0.0.1" ] || bail "M1: stargate-dp port host_ip must be '127.0.0.1' (FR-005); got: '$DP_PUB_HOST' (empty/0.0.0.0 means short-form binding)"
[ "$DP_PUB_PORT" = "8881" ]      || bail "M1: stargate-dp published port must be 8881; got: '$DP_PUB_PORT'"
[ "$DP_TGT" = "8881" ]           || bail "M1: stargate-dp target port must be 8881; got: '$DP_TGT'"
[ "$DP_PROTO" = "tcp" ]          || bail "M1: stargate-dp protocol must be tcp; got: '$DP_PROTO'"

# --- M2: Tor has NO host port mapping (FR-012) -----------------------------
TOR_PORTS_RAW="$(q '.services["tor"].ports // "" | tostring')"
[ "$TOR_PORTS_RAW" = "null" ] || [ "$TOR_PORTS_RAW" = "" ] \
  || bail "M2: tor must have NO ports key (FR-012); got: $TOR_PORTS_RAW"

# --- M4 (Principle III): NO service mounts /var/run/docker.sock ------------
# T094a removed the docker-socket-proxy; the CP observes Tor via the
# cookie-authenticated ControlPort (tor:9051), NOT a Docker Engine observer.
# Zero docker.sock mounters is the load-bearing invariant (no auxiliary
# host-root-pivot surface). The prior "sole-mounter == docker-socket-proxy"
# check is inverted to "no mounter at all."
SOCK_MOUNTERS="$(q '[.services | to_entries[] | {key: .key, vols: (.value.volumes // [])} | select(.vols | any((.type == "bind") and (.source == "/var/run/docker.sock"))) | .key] | join(",")')"
[ "$SOCK_MOUNTERS" = "" ] \
  || bail "M4: NO service may mount /var/run/docker.sock (Principle III; docker-socket-proxy removed by T094a); mounters: '$SOCK_MOUNTERS'"

# --- M6: UID/GID user directives match Dockerfiles exactly -----------------
CP_USER="$(q '.services["stargate-control"].user // "?"')"
DP_USER="$(q '.services["stargate-dp"].user // "?"')"
[ "$CP_USER" = "5101:5100" ] || bail "M6: stargate-control.user must be '5101:5100' (got: $CP_USER) — must match control-plane/Dockerfile UID 5101 + supplementary GID 5100"
[ "$DP_USER" = "5102:5100" ] || bail "M6: stargate-dp.user must be '5102:5100' (got: $DP_USER) — must match data-plane/Dockerfile UID 5102 + supplementary GID 5100"

# M6 cross-file guard: the compose `user:` literals must agree with the
# numerics hard-coded in the Stargate-built Dockerfiles. A future Dockerfile
# refactor that drifts the UID/GID would silently break the 0660 + GID 5100
# IPC mode scheme (contracts/control-grpc.md §"Socket topology") — the
# runtime gate (T022) catches it only at compose-up time. This static check
# catches the drift pre-runtime. (redteam finding m2.)
[ -f data-plane/Dockerfile ]     || bail "M6: data-plane/Dockerfile missing — cannot cross-check UID/GID"
[ -f control-plane/Dockerfile ]  || bail "M6: control-plane/Dockerfile missing — cannot cross-check UID/GID"
# data-plane/Dockerfile synthesises passwd: "stargate-dp:x:5102:5100:..." and
# group: "stargate-ipc:x:5100:...". We grep for the UID:GID literal.
grep -qE 'stargate-dp:x:5102:5100' data-plane/Dockerfile \
  || bail "M6: data-plane/Dockerfile no longer declares UID 5102 + GID 5100 for stargate-dp — compose user:$DP_USER and Dockerfile have drifted"
# control-plane/Dockerfile uses `groupadd --gid 5100 stargate-ipc` and
# `useradd --uid 5101 --gid stargate-ipc ... stargate-cp` (split across
# continuation lines). Grep the two numeric anchors independently.
grep -qE -- '--gid 5100 stargate-ipc' control-plane/Dockerfile \
  || bail "M6: control-plane/Dockerfile no longer declares GID 5100 for stargate-ipc — drifted from compose user:$CP_USER"
grep -qE -- '--uid 5101 ' control-plane/Dockerfile \
  || bail "M6: control-plane/Dockerfile no longer declares UID 5101 for stargate-cp — drifted from compose user:$CP_USER"

# --- M7: exactly seven named volumes + key mount semantics -----------------
VOLS="$(q '.volumes | keys | sort | join(",")')"
[ "$VOLS" = "stargate-control-config,stargate-control-state,stargate-dp-state,stargate-ipc,stargate-keys,stargate-tor-config,stargate-tor-state" ] \
  || bail "M7: volumes must be exactly the seven from data-model.md §6; got: $VOLS"

# stargate-ipc mounted into both planes at /run/stargate.
ipc_into_dp="$(q '[.services["stargate-dp"].volumes[] | select(.source == "stargate-ipc") | .target] | join(",")')"
[ "$ipc_into_dp" = "/run/stargate" ] || bail "M7: stargate-ipc must be mounted into stargate-dp at /run/stargate (got: $ipc_into_dp)"
ipc_into_cp="$(q '[.services["stargate-control"].volumes[] | select(.source == "stargate-ipc") | .target] | join(",")')"
[ "$ipc_into_cp" = "/run/stargate" ] || bail "M7: stargate-ipc must be mounted into stargate-control at /run/stargate (got: $ipc_into_cp)"

# stargate-tor-config NOT mounted into tor for v1 (image-baked torrc, T087 /
# FR-011 amended by T089): a :ro mount at /etc/tor would shadow the
# image-baked /etc/tor/torrc. RW into stargate-control (dormant, for future
# T037 TorrcRenderer — data-model.md §6 says the volume stays declared but
# v1 boot does not depend on it).
tor_cfg_into_tor="$(q '[.services["tor"].volumes[] | select(.source == "stargate-tor-config")] | length | tostring')"
[ "$tor_cfg_into_tor" = "0" ] || bail "M7: tor must NOT mount stargate-tor-config for v1 (image-baked torrc, T087 — a :ro mount at /etc/tor would shadow /etc/tor/torrc); got $tor_cfg_into_tor mount(s)"
tor_cfg_cp_present="$(q '[.services["stargate-control"].volumes[] | select(.source == "stargate-tor-config")] | length | tostring')"
[ "$tor_cfg_cp_present" = "1" ] || bail "M7: stargate-tor-config must be mounted into stargate-control (dormant RW, for future T037 TorrcRenderer)"

# --- M8: tor service exists (compose DNS name 'tor') -----------------------
TOR_PRESENT="$(q '.services["tor"] | type')"
[ "$TOR_PRESENT" = "object" ] || bail "M8: tor service missing — FR-007/T047 dial target tor:9050 depends on this service key"

# --- M10: DP has no depends_on (Constitution Principle II) -----------------
DP_DEPS="$(q '.services["stargate-dp"].depends_on // "" | tostring')"
[ "$DP_DEPS" = "null" ] || [ "$DP_DEPS" = "" ] \
  || bail "M10: stargate-dp MUST NOT declare depends_on (Constitution II — DP keeps routing if CP/sidecars are unreachable); got: $DP_DEPS"

# --- M13: split networks, internal flags, membership, Tor sole egress (T094b) --
# T094b split the stack into three networks so only Tor has egress:
#   stargate-egress   (NOT internal) — tor only; Tor's sole NAT route.
#   stargate-internal (internal:true) — stargate-dp + tor (DP→tor:9050, FR-007).
#   stargate-cp-tor   (internal:true) — stargate-control + tor (CP→tor:9051).
# DP and CP share no network → mutually unreachable at L3. The runtime
# reachability + per-container hardening is gated by
# tests/contract/compose/network_hardening_test.go (//go:build docker);
# this is the static topology gate that runs at PR cadence (no daemon).
NET_COUNT="$(q '.networks | length | tostring')"
[ "$NET_COUNT" = "3" ] || bail "M13: expected exactly 3 networks (stargate-egress, stargate-internal, stargate-cp-tor — T094b split); got: $NET_COUNT"
NET_NAMES="$(q '.networks | keys | sort | join(",")')"
[ "$NET_NAMES" = "stargate-cp-tor,stargate-egress,stargate-internal" ] \
  || bail "M13: network set must be {stargate-egress, stargate-internal, stargate-cp-tor}; got: $NET_NAMES"

# internal flags: egress NOT internal (Tor's route out); transport nets internal:true.
EGRESS_INTERNAL="$(q '.networks["stargate-egress"].internal // false')"
[ "$EGRESS_INTERNAL" = "false" ] || bail "M13: stargate-egress must NOT be internal (Tor's sole egress path); internal=$EGRESS_INTERNAL"
DPTOR_INTERNAL="$(q '.networks["stargate-internal"].internal // false')"
[ "$DPTOR_INTERNAL" = "true" ] || bail "M13: stargate-internal must be internal:true (DP has no public egress); internal=$DPTOR_INTERNAL"
CPTOR_INTERNAL="$(q '.networks["stargate-cp-tor"].internal // false')"
[ "$CPTOR_INTERNAL" = "true" ] || bail "M13: stargate-cp-tor must be internal:true (CP has no public egress); internal=$CPTOR_INTERNAL"

# Per-service membership. .services[svc].networks renders as an object keyed
# by network name; its keys are exactly the nets the service attaches to.
svc_nets() { q ".services[\"$1\"].networks | keys | sort | join(\",\")"; }
[ "$(svc_nets stargate-dp)" = "stargate-internal" ] \
  || bail "M13: stargate-dp must be attached ONLY to stargate-internal (DP↔tor:9050, FR-007); got: $(svc_nets stargate-dp)"
[ "$(svc_nets stargate-control)" = "stargate-cp-tor" ] \
  || bail "M13: stargate-control must be attached ONLY to stargate-cp-tor (CP↔tor:9051, T094a); got: $(svc_nets stargate-control)"
[ "$(svc_nets tor)" = "stargate-cp-tor,stargate-egress,stargate-internal" ] \
  || bail "M13: tor must be attached to all three networks (sole egress + the two transport nets); got: $(svc_nets tor)"

# Tor is the sole egress attachee: stargate-egress has exactly one member
# (tor). DP and CP are not on it → they have no egress path.
for svc in stargate-dp stargate-control; do
  on_egress="$(q ".services[\"$svc\"].networks[\"stargate-egress\"] | type")"
  [ "$on_egress" = "null" ] \
    || bail "M13: service '$svc' must NOT be attached to stargate-egress (only Tor has egress); got type: '$on_egress'"
done

# === Report ================================================================
if (( ${#errs[@]} > 0 )); then
  printf 'FAIL: %d assertion(s) failed:\n' "${#errs[@]}" >&2
  for e in "${errs[@]}"; do printf '  - %s\n' "$e" >&2; done
  exit 1
fi
echo "OK: compose/docker-compose.local.yml passes all T015 structural assertions (T094a: 3 services, no docker.sock mounter)."
