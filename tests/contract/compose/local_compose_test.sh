#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T162 static Local topology gate. The test renders Compose before checking
# effective values so aliases, defaults and short forms cannot hide exposure.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

command -v docker >/dev/null 2>&1 || { echo "FAIL: docker absent" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "FAIL: jq absent" >&2; exit 1; }
render="$(mktemp)" || exit 1
errfile="$(mktemp)" || exit 1
trap 'rm -f "$render" "$errfile"' EXIT
if ! docker compose -f compose/docker-compose.local.yml \
    --env-file compose/env/local.env.example config --format json >"$render" 2>"$errfile"; then
    echo "FAIL: compose config" >&2
    sed -n '1,20p' "$errfile" >&2
    exit 1
fi

q() { jq -r "$1" "$render"; }
errors=()
check() {
    local actual="$1" expected="$2" property="$3"
    [ "$actual" = "$expected" ] || errors+=("$property: got '$actual', want '$expected'")
}

check "$(q '.services | keys | sort | join(",")')" \
    "stargate-control,stargate-dp,tor,tor-observer" "sanitized observer service exists"
check "$(q '.services["stargate-dp"].network_mode // ""')" host "DP network mode"
check "$(q '.services["stargate-control"].network_mode // ""')" none "CP network mode"
check "$(q '.services["stargate-dp"].ports // [] | length')" 0 "DP published ports"
check "$(q '.services.tor.ports // [] | length')" 0 "Tor published ports"
check "$(q '.services["stargate-dp"].environment.STARGATE_LISTEN_ADDR')" \
    "127.0.0.1:8881" "strict host-loopback listener"
check "$(q '.services["stargate-dp"].environment.STARGATE_TOR_SOCKS_ADDR')" \
    "unix:///run/stargate-tor/tor-socks.sock" "fixed AF_UNIX upstream"
check "$(q '.services["stargate-dp"].environment | has("STARGATE_IN_CONTAINER")')" \
    false "container wildcard flag absent"
check "$(q '.services["stargate-dp"].user')" "5102:5100" "DP user"
check "$(q '.services["stargate-control"].user')" "5101:5100" "CP user"
check "$(q '.services["tor-observer"].user')" "5103:5100" "observer socket is CP-group accessible"
check "$(q '.services["stargate-dp"].group_add // [] | join(",")')" \
    5200 "DP SOCKS group"
check "$(q '.services.tor.group_add // [] | join(",")')" \
    5200 "Tor fabric group"
check "$(q '.services["stargate-control"].group_add // [] | index("5103") == null')" \
    true "CP lacks Tor cookie group"
check "$(q '.services["stargate-dp"].security_opt // [] | index("apparmor=stargate-dp") != null')" \
    true "DP AppArmor profile"
check "$(q '.services["stargate-dp"].restart')" no "DP restart through checked installer only"
check "$(q '.services["stargate-dp"].depends_on // {} | length')" 0 "DP independent of CP"

# Each side sees only its authorized fabric. Tor's raw control endpoint and
# cookie live inside its state volume; CP has no mount of that volume.
mounts() { q "[.services[\"$1\"].volumes[] | select(.source == \"$2\") | .target] | join(\",\")"; }
check "$(mounts stargate-dp stargate-tor-dp-fabric)" /run/stargate-tor "DP SOCKS fabric"
check "$(mounts tor stargate-tor-dp-fabric)" /run/tor-fabric "Tor SOCKS fabric"
check "$(mounts stargate-control stargate-tor-dp-fabric)" "" "CP has no SOCKS fabric"
check "$(mounts stargate-control stargate-tor-cp-fabric)" \
    /run/stargate-tor-observer "reserved CP observer fabric"
check "$(mounts stargate-dp stargate-tor-cp-fabric)" "" "DP has no CP fabric"
check "$(mounts tor stargate-tor-cp-fabric)" "" "Tor has no CP observer fabric"
check "$(mounts stargate-control stargate-tor-state)" "" "CP has no cookie or guard-state mount"
check "$(mounts stargate-dp stargate-tor-state)" "" "DP has no control mount"
check "$(mounts tor stargate-tor-state)" /var/lib/tor "Tor private state"
check "$(mounts tor-observer stargate-tor-state)" /run/tor-control "observer narrow Tor control mount"
check "$(q '[.services["tor-observer"].volumes[] | select(.source == "stargate-tor-state") | .volume.subpath] | join(",")')" \
    control "observer sees only control subpath"
check "$(mounts tor-observer stargate-tor-cp-fabric)" /run/stargate-tor-observer "observer CP health socket"
check "$(mounts tor-observer stargate-tor-dp-fabric)" "" "observer lacks SOCKS fabric"
check "$(mounts stargate-control stargate-observer-keys)" "" "CP lacks observer private key"
check "$(mounts tor-observer stargate-observer-keys)" /etc/stargate/observer-keys "observer isolated key volume"
check "$(mounts stargate-dp stargate-ipc)" /run/stargate "DP IPC"
check "$(mounts stargate-control stargate-ipc)" /run/stargate "CP IPC"
check "$(q '[.services["stargate-dp"].volumes[] | select(.source == "stargate-tor-dp-fabric") | .read_only] | join(",")')" \
    true "DP fabric read-only mount"
check "$(q '[.services["stargate-control"].volumes[] | select(.source == "stargate-tor-cp-fabric") | .read_only] | join(",")')" \
    true "CP observer fabric read-only mount"

check "$(q '.networks | keys | join(",")')" stargate-egress "sole Docker network"
check "$(q '.networks["stargate-egress"].internal // false')" false "Tor egress network"
check "$(q '.services.tor.networks | keys | join(",")')" stargate-egress "Tor sole bridge attachment"
check "$(q '.services["stargate-dp"].networks // {} | length')" 0 "DP no Docker network"
check "$(q '.services["stargate-control"].networks // {} | length')" 0 "CP no Docker network"
check "$(q '.services["tor-observer"].network_mode // ""')" none "observer no Docker network"
check "$(q '.services["tor-observer"] | has("build")')" false "observer deploys a prebuilt digest"
check "$(q '.services["tor-observer"].image | test("^sha256:[a-f0-9]{64}$")')" \
    true "observer image uses immutable local ID"
check "$(q '.volumes | keys | sort | join(",")')" \
    "stargate-control-config,stargate-control-state,stargate-dp-state,stargate-ipc,stargate-keys,stargate-observer-keys,stargate-tor-cp-fabric,stargate-tor-dp-fabric,stargate-tor-state" \
    "named volume set"
# T198 (A3-m5): the quickstart's install facts must match what this file and
# the installer define: the volume count its teardown names, the key and
# pepper modes init installs, and the Docker Engine floor for subpath mounts.
qs=specs/001-tor-route/quickstart.md
qs_text="$(tr '\n' ' ' < "$qs" | tr -s ' ')"
count_words=(zero one two three four five six seven eight nine ten eleven twelve)
volume_word="${count_words[$(q '.volumes | length')]:-}"
count_re="($(IFS='|'; echo "${count_words[*]}")|[0-9]+) named volumes"
check "$(grep -oE "$count_re" <<< "$qs_text" | sort -u | tr '\n' ',')" \
    "$volume_word named volumes," "quickstart named volume count"
mode_of() { sed -n "s/^$1=\\([0-7]\\{4\\}\\).*/\\1/p" scripts/lib/compose.sh; }
key_step="$(sed -n '/^3\. Generates/,/^4\. /p' "$qs" | sed '$d')"
check "$(grep -oE '\b0[0-7]{3}\b' <<< "$key_step" | sort -u | tr '\n' ',')" \
    "$(printf '%s\n' "$(mode_of KEY_PRIVATE_MODE)" "$(mode_of KEY_PUBLIC_MODE)" "$(mode_of PEPPER_MODE)" | sort -u | tr '\n' ',')" \
    "quickstart key and pepper modes"
if [ "$(q '[.services[].volumes[]? | select(.volume.subpath? != null)] | length')" -gt 0 ]; then
    engine="$(grep -m1 -oE 'Docker Engine[^0-9]*[0-9]+' "$qs" | grep -oE '[0-9]+$')"
    check "$([ "${engine:-0}" -ge 26 ] && echo ok || echo "Engine ${engine:-unstated}")" ok \
        "quickstart Engine floor for volume subpath (Engine 26)"
fi

# T191 item 7: Tor's torrc is baked into its image (T089); the CP has no
# writable Tor configuration mount.
check "$(q '[.services["stargate-control"].volumes[] | select(.target == "/etc/tor")] | length')" \
    0 "CP has no Tor config mount"

# T191 item 11 (A3-M1): a service that builds a local image must never pull
# its unqualified `stargate/<name>:local` name from a registry. Without
# pull_policy: build, a plain `up`/`pull` asks docker.io for an unrelated
# third-party account's image.
while IFS= read -r svc; do
    check "$(q ".services[\"$svc\"].pull_policy // \"\"")" build "$svc builds, never pulls, its local image"
done < <(q '.services | to_entries[] | select(.value | has("build")) | .key')
check "$(q '[.services[] | select(has("build"))] | length')" 3 "services that build locally"

for svc in stargate-dp stargate-control tor; do
    check "$(q ".services[\"$svc\"].read_only")" true "$svc read-only rootfs"
    check "$(q ".services[\"$svc\"].cap_drop // [] | join(\",\")")" ALL "$svc caps dropped"
    check "$(q ".services[\"$svc\"].security_opt // [] | index(\"no-new-privileges:true\") != null")" \
        true "$svc no-new-privileges"
    check "$(q "[.services[\"$svc\"].volumes[] | select(.target == \"/var/run/docker.sock\")] | length")" \
        0 "$svc no Docker socket"
done

if (( ${#errors[@]} > 0 )); then
    printf 'FAIL: %d T162 Compose assertion(s) failed:\n' "${#errors[@]}" >&2
    printf '  - %s\n' "${errors[@]}" >&2
    exit 1
fi
echo "OK: Local Compose host-loopback and per-consumer fabric shape"
