#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T167: exercise the real CP image with the effective Local Compose volume
# set. A nested keys mount must work while the config parent remains read-only.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if ! command -v docker >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  echo "SKIP: Docker or jq unavailable; CP mount startup unmeasured"
  exit 0
fi
if ! docker info >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "SKIP: Docker daemon or Compose unavailable; CP mount startup unmeasured"
  exit 0
fi

project="t167-mount-$$-$(date +%s)"
compose="compose/docker-compose.local.yml"
env_file="compose/env/local.env.example"
render="$(mktemp)" || exit 1
build_log="$(mktemp)" || exit 1
startup_db="$(mktemp)" || exit 1
volumes=()
cleanup() {
  docker rm -f "${project}-full" "${project}-keys" >/dev/null 2>&1 || true
  if (( ${#volumes[@]} )); then docker volume rm "${volumes[@]}" >/dev/null 2>&1 || true; fi
  rm -f "$render" "$build_log" "$startup_db"
}
trap cleanup EXIT INT TERM
fail() { echo "FAIL: T167 CP mount: $*" >&2; exit 1; }
app_started() {
  local name="$1" attempt
  # The startup banner is forbidden by Constitution III. A completed Flyway
  # migration proves the real Quarkus application reached persistence startup.
  # Each disposable container uses a distinct DB in its writable fixture mount;
  # missing auth provisioning may then terminate it, as in the original probe.
  for attempt in {1..120}; do
    if docker cp "$name:/etc/stargate/keys/$name.db" "$startup_db" >/dev/null 2>&1; then
      if python3 - "$startup_db" <<'CHECK'
import sqlite3, sys
try:
    with sqlite3.connect('file:' + sys.argv[1] + '?mode=ro', uri=True) as conn:
        row = conn.execute("SELECT success FROM flyway_schema_history WHERE version='002'").fetchone()
        sys.exit(0 if row and row[0] else 1)
except sqlite3.Error:
    sys.exit(1)
CHECK
      then
        [ -z "$(docker logs "$name" 2>&1)" ] || fail "actual CP launcher exported diagnostics"
        return 0
      fi
    fi
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" = true ] || return 1
    sleep 0.5
  done
  return 1
}

docker compose -p "$project" -f "$compose" --env-file "$env_file" \
  config --format json >"$render" || fail "effective Compose config unavailable"
cp_config='.services["stargate-control"]'
jq -e "$cp_config.network_mode == \"none\" and $cp_config.read_only == true" "$render" >/dev/null \
  || fail "CP network or rootfs boundary changed"
jq -e '[.services["stargate-control"].volumes[] | select(.source == "stargate-control-config" and .target == "/etc/stargate" and .read_only == true)] | length == 1' "$render" >/dev/null \
  || fail "read-only config parent mount missing or writable"
jq -e '[.services["stargate-control"].volumes[] | select(.source == "stargate-keys" and .target == "/etc/stargate/keys" and (.read_only // false) == false)] | length == 1' "$render" >/dev/null \
  || fail "writable keys child mount missing"
jq -e '[.services["stargate-control"].volumes[] | select(.source == "stargate-tor-cp-fabric" and .target == "/run/stargate-tor-observer" and .read_only == true)] | length == 1' "$render" >/dev/null \
  || fail "read-only reserved observer fabric missing"
jq -e '[.services["stargate-control"].volumes[] | select(.source == "stargate-tor-state" or .source == "stargate-tor-dp-fabric" or .target == "/var/run/docker.sock")] | length == 0' "$render" >/dev/null \
  || fail "CP gained Tor state, SOCKS fabric, or Docker socket"

if ! docker compose -p "$project" -f "$compose" --env-file "$env_file" \
    build stargate-control >"$build_log" 2>&1; then
  tail -30 "$build_log" >&2
  fail "real CP image build failed"
fi
image="$(jq -r '.services["stargate-control"].image' "$render")"
docker image inspect "$image" >/dev/null 2>&1 || fail "built CP image unavailable"

base_args=(--detach --network none --read-only --user 5101:5100
  --cap-drop ALL --security-opt no-new-privileges:true
  --tmpfs /tmp:rw,exec --tmpfs /run)
run_args=("${base_args[@]}")
keys_mount=""
config_physical=""
while IFS=$'\t' read -r source target read_only; do
  physical="$(jq -r --arg source "$source" '.volumes[$source].name // empty' "$render")"
  [ -n "$physical" ] || fail "no effective volume name for $source"
  docker volume create "$physical" >/dev/null || fail "create $physical"
  volumes+=("$physical")
  mount="type=volume,source=$physical,target=$target"
  if [ "$read_only" = true ]; then mount+=",readonly"; fi
  run_args+=(--mount "$mount")
  if [ "$source" = stargate-keys ]; then keys_mount="$mount"; fi
  if [ "$source" = stargate-control-config ]; then config_physical="$physical"; fi
done < <(jq -r '.services["stargate-control"].volumes[] | [.source,.target,(.read_only // false | tostring)] | @tsv' "$render")
[ -n "$keys_mount" ] || fail "effective keys mount unavailable"
[ -n "$config_physical" ] || fail "effective config mount unavailable"

# Fixture provisioning only: permit the unprivileged CP to create its migration
# evidence in these disposable keys volumes. No real auth material is mounted.
docker run --rm --network none --read-only --user 0 --cap-drop ALL --cap-add CHOWN \
  --security-opt no-new-privileges:true --mount "$keys_mount" --entrypoint sh "$image" \
  -c 'chown 5101:5100 /etc/stargate/keys' || fail "fixture keys ownership"

# The keys-only control proves this image can launch its actual Java entrypoint
# with a read-only rootfs; it discriminates the nested mount from image failure.
keys_result="$(docker run "${base_args[@]}" --mount "$keys_mount" \
  -e "QUARKUS_DATASOURCE_JDBC_URL=jdbc:sqlite:/etc/stargate/keys/${project}-keys.db" \
  --name "${project}-keys" "$image" 2>&1)"; keys_rc=$?
[ "$keys_rc" -eq 0 ] || fail "keys-only control did not launch (exit $keys_rc): $keys_result"
keys_started="$(docker inspect -f '{{.State.StartedAt}}' "${project}-keys")"
[ "$keys_started" != '0001-01-01T00:00:00Z' ] || fail "keys-only application process never started"
app_started "${project}-keys" || fail "keys-only CP never reached Quarkus startup"
echo "T167 keys-only control: Docker start succeeded; Quarkus migration reached ($keys_started)"

# Reproduce the install-time provisioning against the disposable Compose
# volume. On the pre-fix tree the helper is absent, leaving the falsifier's
# read-only-parent failure intact; the fixture init test checks its wiring.
. scripts/lib/compose.sh
if declare -F init_control_config_mountpoint >/dev/null; then
  init_control_config_mountpoint "$config_physical" \
    || fail "config volume mountpoint provisioning failed"
fi
full_result="$(docker run "${run_args[@]}" \
  -e "QUARKUS_DATASOURCE_JDBC_URL=jdbc:sqlite:/etc/stargate/keys/${project}-full.db" --name "${project}-full" "$image" 2>&1)"; full_rc=$?
if [ "$full_rc" -ne 0 ]; then
  echo "T167 full CP mount exit=$full_rc: $full_result" >&2
  if [ "$full_rc" -eq 125 ] && [[ "$full_result" == *'/etc/stargate/keys'*'read-only file system'* ]]; then
    echo "T167 pre-fix signature: exit 125 at /etc/stargate/keys (read-only file system)" >&2
  fi
  fail "full production CP mount set did not start"
fi

actual="$(docker inspect -f '{{json .Mounts}}' "${project}-full")" || fail "inspect full CP mounts"
while IFS=$'\t' read -r source target read_only; do
  physical="$(jq -r --arg source "$source" '.volumes[$source].name' "$render")"
  expected_rw=true
  [ "$read_only" = true ] && expected_rw=false
  jq -e --arg name "$physical" --arg target "$target" --argjson rw "$expected_rw" \
    '[.[] | select(.Name == $name and .Destination == $target and .RW == $rw)] | length == 1' \
    <<<"$actual" >/dev/null || fail "actual mount $source at $target has wrong source or mode"
done < <(jq -r '.services["stargate-control"].volumes[] | [.source,.target,(.read_only // false | tostring)] | @tsv' "$render")
full_started="$(docker inspect -f '{{.State.StartedAt}}' "${project}-full")"
[ "$full_started" != '0001-01-01T00:00:00Z' ] || fail "full CP application process never started"
app_started "${project}-full" || fail "full CP never reached Quarkus startup"
actual_network="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "${project}-full")"
[ "$actual_network" = none ] || fail "CP actual network mode is $actual_network"
declare -F init_control_config_mountpoint >/dev/null || fail "installer has no config mountpoint provisioner"
echo "OK: T167 full CP mount set reached Quarkus migration with actual sources, targets, and modes; no process output"
