#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/compose/local_compose_test.sh — STATIC structural contract
# test for compose/docker-compose.local.yml (T015).
#
# Why this is a static test (not a runtime bring-up): the runtime properties
# (Tor port exposure from the host, docker-socket-proxy POST=0 lockdown over
# HTTP, peer-dial UID/GID semantics) are gated by T019b, T019c, and T022
# respectively, which bring up the compose stack. This test gates the
# compose-FILE preconditions those runtime tests depend on — properties a
# silent compose-file edit could regress between runtime-test runs:
#   - DP port 8881 bound to loopback only (FR-005; FR-012-in-spirit).
#   - Tor SocksPort/ControlPort never host-published (FR-012).
#   - docker-socket-proxy never host-published (T017a trust surface).
#   - /var/run/docker.sock mounted by docker-socket-proxy ONLY, read-only.
#   - Proxy env lockdown (EVENTS=1, CONTAINERS=1, POST=0; no other grant).
#   - UID/GID numerics match the Dockerfiles exactly (control-grpc.md
#     §"Socket topology").
#   - Exactly the seven named volumes from data-model.md §6.
#   - docker-socket-proxy image pinned by sha256 digest (Principle IV).
#   - DP has no depends_on (Constitution Principle II — DP keeps routing
#     if CP is unreachable).
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

# --- M11: exactly four services --------------------------------------------
ALL_SVCS="$(q '.services | keys_unsorted | sort | join(",")')"
[ "$ALL_SVCS" = "docker-socket-proxy,stargate-control,stargate-dp,tor" ] \
  || bail "M11: expected exactly 4 services (docker-socket-proxy,stargate-control,stargate-dp,tor); got: $ALL_SVCS"

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

# --- M3: docker-socket-proxy has NO host port mapping ----------------------
PROXY_PORTS_RAW="$(q '.services["docker-socket-proxy"].ports // "" | tostring')"
[ "$PROXY_PORTS_RAW" = "null" ] || [ "$PROXY_PORTS_RAW" = "" ] \
  || bail "M3: docker-socket-proxy must have NO ports key; got: $PROXY_PORTS_RAW"

# --- M4: /var/run/docker.sock mounted ONLY by docker-socket-proxy, RO -----
# Long-form volume schema: {type: bind, source: "/var/run/docker.sock", target: ..., read_only: bool}.
# Iterate every service's volumes and find which services bind-source /var/run/docker.sock.
SOCK_MOUNTERS="$(q '[.services | to_entries[] | {key: .key, vols: (.value.volumes // [])} | select(.vols | any((.type == "bind") and (.source == "/var/run/docker.sock"))) | .key] | join(",")')"
[ "$SOCK_MOUNTERS" = "docker-socket-proxy" ] \
  || bail "M4: /var/run/docker.sock must be mounted ONLY by docker-socket-proxy; mounters: '$SOCK_MOUNTERS'"
PROXY_SOCK_RO="$(q '[.services["docker-socket-proxy"].volumes[] | select(.source == "/var/run/docker.sock") | (.read_only // false) | tostring] | join(",")')"
[ "$PROXY_SOCK_RO" = "true" ] || bail "M4: docker-socket-proxy's docker.sock mount must be read_only:true (got: $PROXY_SOCK_RO)"

# --- M5: proxy env lockdown (EVENTS=1, CONTAINERS=1, POST=0; no other grant)
PROXY_EV="$(q '.services["docker-socket-proxy"].environment.EVENTS // "?"')"
PROXY_CN="$(q '.services["docker-socket-proxy"].environment.CONTAINERS // "?"')"
PROXY_PO="$(q '.services["docker-socket-proxy"].environment.POST // "?"')"
[ "$PROXY_EV" = "1" ] || bail "M5: docker-socket-proxy.EVENTS must be '1' (got: $PROXY_EV)"
[ "$PROXY_CN" = "1" ] || bail "M5: docker-socket-proxy.CONTAINERS must be '1' (got: $PROXY_CN)"
[ "$PROXY_PO" = "0" ] || bail "M5: docker-socket-proxy.POST must be '0' (got: $PROXY_PO)"
# VERSION and PING must be EXPLICITLY 0: the pinned upstream image defaults
# both to ALLOW (probed empirically at T019c /start), so "unset means deny"
# does not hold for these two flags. Removing either line would silently
# reopen the endpoint until the runtime test (sidecar-proxy/lockdown_test.go,
# container-validation cadence) next runs — this static check is the
# PR-cadence gate.
PROXY_VS="$(q '.services["docker-socket-proxy"].environment.VERSION // "?"')"
PROXY_PG="$(q '.services["docker-socket-proxy"].environment.PING // "?"')"
[ "$PROXY_VS" = "0" ] || bail "M5: docker-socket-proxy.VERSION must be explicitly '0' — upstream defaults it to allow; T019c (got: $PROXY_VS)"
[ "$PROXY_PG" = "0" ] || bail "M5: docker-socket-proxy.PING must be explicitly '0' — upstream defaults it to allow; T019c (got: $PROXY_PG)"
# Collect all proxy env keys set to "1"; only EVENTS and CONTAINERS are allowed.
GRANT_HITS="$(q '[.services["docker-socket-proxy"].environment // {} | to_entries[] | select((.value | tostring) == "1") | .key] | join(",")')"
BAD_GRANTS="$(echo "$GRANT_HITS" | tr ',' '\n' | grep -vE '^(EVENTS|CONTAINERS)$' | paste -sd, -)"
[ -z "$BAD_GRANTS" ] || bail "M5: docker-socket-proxy has grant flags set to 1 beyond EVENTS/CONTAINERS: $BAD_GRANTS"

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

# stargate-tor-config :ro into tor; RW into stargate-control (rendered torrc).
tor_cfg_ro="$(q '[.services["tor"].volumes[] | select(.source == "stargate-tor-config") | (.read_only // false) | tostring] | join(",")')"
[ "$tor_cfg_ro" = "true" ] || bail "M7: stargate-tor-config must be read_only:true into tor (got: $tor_cfg_ro)"
tor_cfg_cp_present="$(q '[.services["stargate-control"].volumes[] | select(.source == "stargate-tor-config")] | length | tostring')"
[ "$tor_cfg_cp_present" = "1" ] || bail "M7: stargate-tor-config must also be mounted into stargate-control (RW for rendered torrc)"

# --- M8: tor service exists (compose DNS name 'tor') -----------------------
TOR_PRESENT="$(q '.services["tor"] | type')"
[ "$TOR_PRESENT" = "object" ] || bail "M8: tor service missing — FR-007/T047 dial target tor:9050 depends on this service key"

# --- M9: docker-socket-proxy image is digest-pinned ------------------------
PROXY_IMG="$(q '.services["docker-socket-proxy"].image // "?"')"
echo "$PROXY_IMG" | grep -qE '^tecnativa/docker-socket-proxy:[^@]+@sha256:[0-9a-f]{64}$' \
  || bail "M9: docker-socket-proxy.image must be '<tag>@sha256:<64hex>' (Principle IV); got: $PROXY_IMG"

# --- M10: DP has no depends_on (Constitution Principle II) -----------------
DP_DEPS="$(q '.services["stargate-dp"].depends_on // "" | tostring')"
[ "$DP_DEPS" = "null" ] || [ "$DP_DEPS" = "" ] \
  || bail "M10: stargate-dp MUST NOT declare depends_on (Constitution II — DP keeps routing if CP/sidecars are unreachable); got: $DP_DEPS"

# --- M13: exactly one network, all four services attached ------------------
NET_COUNT="$(q '.networks | length | tostring')"
[ "$NET_COUNT" = "1" ] || bail "M13: exactly one network expected (FR-005 'single compose-internal bridge'); got: $NET_COUNT"
NET_NAME="$(q '.networks | keys | join(",")')"
[ -n "$NET_NAME" ] || bail "M13: network key missing"
for svc in stargate-dp stargate-control tor docker-socket-proxy; do
  attached="$(q ".services[\"$svc\"].networks | type")"
  [ "$attached" = "object" ] || bail "M13: service '$svc' must be attached to the '$NET_NAME' network (FR-012 requires all four services on the shared compose-internal bridge so DP↔tor:9050, CP↔docker-socket-proxy:2375, and CP↔tor render paths resolve); got networks type: '$attached'"
done

# === Report ================================================================
if (( ${#errs[@]} > 0 )); then
  printf 'FAIL: %d assertion(s) failed:\n' "${#errs[@]}" >&2
  for e in "${errs[@]}"; do printf '  - %s\n' "$e" >&2; done
  exit 1
fi
echo "OK: compose/docker-compose.local.yml passes all T015 structural assertions."
