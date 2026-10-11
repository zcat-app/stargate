#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T162: the operator startup must fail closed before admitting the DP.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

profile=compose/apparmor/stargate-dp
init=scripts/subcommands/init

[ -f "$profile" ] || { echo "FAIL: DP AppArmor profile absent" >&2; exit 1; }
command -v apparmor_parser >/dev/null && apparmor_parser -T -Q "$profile"

# T191 item 2 (A3-M7): the DP runs in the host network namespace, so any
# /proc/<pid>/net file it can read is the HOST's socket, ARP and route table.
# The profile grants only the procfs reads the static Go DP performs and
# denies the net tables explicitly (process and per-thread views).
profile_rules="$(grep -vE '^[[:space:]]*(#|$)' "$profile")"
if grep -qE '^[[:space:]]*/proc/\*\*[[:space:]]+[a-z]*r' <<< "$profile_rules"; then
  echo "FAIL: DP profile grants blanket /proc/** read" >&2; exit 1
fi
for rule in 'deny /proc/*/net/** r,' 'deny /proc/*/task/*/net/** r,'; do
  grep -qxF "  $rule" <<< "$profile_rules" || { echo "FAIL: DP profile lacks '$rule'" >&2; exit 1; }
done
# `*` matches any one path component, so the deny also covers /proc/sys/net/**
# and an explicit deny wins over any allow: an allow there is dead text that
# documents a grant the DP does not have (T191 round 2, GLM R1 Minor).
if grep -E '^[[:space:]]*/proc/[^/[:space:]]+/net/' <<< "$profile_rules"; then
  echo "FAIL: DP profile allows a /proc/<x>/net path that its net deny overrides" >&2; exit 1
fi

grep -q 'install_host_boundary' "$init" || { echo "FAIL: init has no host-boundary installation" >&2; exit 1; }
grep -q 'verify_host_boundary' "$init" || { echo "FAIL: init has no host-boundary verification" >&2; exit 1; }
grep -q -- '--uid-owner.*5102\|--uid-owner.*DP_UID' "$init" || { echo "FAIL: no DP uid owner rule" >&2; exit 1; }
grep -q 'ip6tables' "$init" || { echo "FAIL: no IPv6 owner rule" >&2; exit 1; }
grep -q 'ESTABLISHED,RELATED' "$init" || { echo "FAIL: no loopback reply rule" >&2; exit 1; }

# A failing host-policy loader must stop an already running DP and never call
# Compose up. Stub only the external host/daemon commands; run the REAL init
# entrypoint so this checks its ordering and exit code, not a copied helper.
hermetic_tmp="$(mktemp -d)"
trap 'rm -rf -- "$hermetic_tmp"' EXIT
mkdir -p "$hermetic_tmp/bin"
export T162_FAKE_DOCKER_LOG="$hermetic_tmp/docker.log"
# The generated stub expands these variables when init invokes it, not here.
# shellcheck disable=SC2016
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$T162_FAKE_DOCKER_LOG"\ncase "$*" in\n  "context show") printf "default\\n" ;;\n  "context inspect default --format "*) printf "\\"unix:///var/run/docker.sock\\"\\n" ;;\n  "info --format "*) printf "[\\"name=seccomp,profile=builtin\\"]\\n" ;;\nesac\nexit 0\n' > "$hermetic_tmp/bin/docker"
printf '#!/bin/sh\nexit 1\n' > "$hermetic_tmp/bin/sudo"
printf '#!/bin/sh\nexit 1\n' > "$hermetic_tmp/bin/apparmor_parser"
chmod +x "$hermetic_tmp/bin/docker" "$hermetic_tmp/bin/sudo" "$hermetic_tmp/bin/apparmor_parser"
if STARGATE_PROJECT="t162-hermetic-$$" \
  STARGATE_COMPOSE_FILE="$PWD/compose/docker-compose.local.yml" \
  STARGATE_ENV_DIR="$hermetic_tmp" STARGATE_ENV_FILE="$hermetic_tmp/local.env" \
  PATH="$hermetic_tmp/bin:$PATH" bash "$init" >/dev/null 2>&1; then
  hermetic_rc=0
else
  hermetic_rc=$?
fi
[ "$hermetic_rc" -eq 60 ] || { echo "FAIL: missing host policy returned $hermetic_rc, want 60" >&2; exit 1; }
grep -q ' stop stargate-dp' "$T162_FAKE_DOCKER_LOG" || {
  echo 'FAIL: init did not stop DP before host policy installation' >&2; exit 1;
}
if grep -Eq '(^| )up( |$)' "$T162_FAKE_DOCKER_LOG"; then
  echo 'FAIL: init started DP after host policy load failure' >&2; exit 1
fi

# A host tool that acknowledges every write but reports an ineffective
# wrong-owner OUTPUT jump must also be rejected before Compose admission.
# The real-socket wrong-owner leg below proves why this shape is ineffective.
# AppArmor af_unix mediation is present and the stub compile keeps the unix
# denies, so the T198 gate passes and the owner-rule check is what refuses.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' \
  '[ "$1" = -n ] && shift' \
  '[ "$1" = -- ] && shift' \
  '[ "$1" = cat ] && { echo yes; exit 0; }' \
  '[ "$1 $2" = "apparmor_parser -Q" ] && { for arg; do file="$arg"; done; cksum < "$file"; exit 0; }' \
  'case "$1:$2 $3 $4" in' \
  '  "iptables:-w -S OUTPUT"|"ip6tables:-w -S OUTPUT")' \
  '    printf "%s\n" "-P OUTPUT ACCEPT" "-A OUTPUT -m owner --uid-owner 9999 -j STARGATE_DP_OUT"; exit 0 ;;' \
  '  "iptables:-w -S STARGATE_DP_OUT"|"ip6tables:-w -S STARGATE_DP_OUT")' \
  '    printf "%s\n" "-N STARGATE_DP_OUT" "-A STARGATE_DP_OUT -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" "-A STARGATE_DP_OUT -j DROP"; exit 0 ;;' \
  '  "iptables:-w -C OUTPUT"*|"ip6tables:-w -C OUTPUT"*) exit 1 ;;' \
  'esac' \
  'exit 0' > "$hermetic_tmp/bin/sudo"
chmod +x "$hermetic_tmp/bin/sudo"
: > "$T162_FAKE_DOCKER_LOG"
if STARGATE_PROJECT="t162-hermetic-$$" \
  STARGATE_COMPOSE_FILE="$PWD/compose/docker-compose.local.yml" \
  STARGATE_ENV_DIR="$hermetic_tmp" STARGATE_ENV_FILE="$hermetic_tmp/local.env" \
  PATH="$hermetic_tmp/bin:$PATH" bash "$init" >"$hermetic_tmp/owner.out" 2>&1; then
  hermetic_rc=0
else
  hermetic_rc=$?
fi
[ "$hermetic_rc" -eq 60 ] || { echo "FAIL: ineffective host policy returned $hermetic_rc, want 60" >&2; exit 1; }
grep -q 'host boundary missing or ineffective' "$hermetic_tmp/owner.out" || {
  echo 'FAIL: wrong-owner leg was refused before the owner-rule check' >&2; exit 1;
}
grep -q ' stop stargate-dp' "$T162_FAKE_DOCKER_LOG" || {
  echo 'FAIL: init did not stop DP before checking ineffective host policy' >&2; exit 1;
}
if grep -Eq '(^| )up( |$)' "$T162_FAKE_DOCKER_LOG"; then
  echo 'FAIL: init started DP after ineffective host policy' >&2; exit 1
fi

# T191 F1: Compose interpolation prefers the shell environment over the env
# file, so a STARGATE_OBSERVER_IMAGE exported where init runs would replace
# the observer image ID init built and checked. init must refuse with the
# preflight code before it touches host policy, volumes or any container. The
# two legs above are the positive control: without the variable, init passes
# this check and reaches the host-boundary phase.
: > "$T162_FAKE_DOCKER_LOG"
if STARGATE_OBSERVER_IMAGE=sha256:1111111111111111111111111111111111111111111111111111111111111111 \
  STARGATE_PROJECT="t162-hermetic-$$" \
  STARGATE_COMPOSE_FILE="$PWD/compose/docker-compose.local.yml" \
  STARGATE_ENV_DIR="$hermetic_tmp" STARGATE_ENV_FILE="$hermetic_tmp/local.env" \
  PATH="$hermetic_tmp/bin:$PATH" bash "$init" >"$hermetic_tmp/override.out" 2>&1; then
  hermetic_rc=0
else
  hermetic_rc=$?
fi
[ "$hermetic_rc" -eq 10 ] || { echo "FAIL: observer image override returned $hermetic_rc, want 10" >&2; exit 1; }
grep -q 'STARGATE_OBSERVER_IMAGE' "$hermetic_tmp/override.out" || {
  echo 'FAIL: observer image override refusal does not name the variable' >&2; exit 1;
}
if grep -Eq '(^| )(stop|up|run|build|volume)( |$)' "$T162_FAKE_DOCKER_LOG"; then
  echo 'FAIL: init acted on Docker before refusing the observer image override' >&2; exit 1
fi
rm -rf -- "$hermetic_tmp"
trap - EXIT

if [[ "${STARGATE_TEST_TAGS:-}" != *docker* ]]; then
  # T191 item 3: a line-start SKIP: is verify.sh's skip sentinel. Without it
  # this gate was recorded PASS although the falsifiers below never ran.
  echo 'OK: T162 host-boundary structure'
  echo 'SKIP: T162 docker packet and AppArmor profile falsifiers (run with STARGATE_TEST_TAGS=docker)'
  exit 0
fi

if ! command -v docker >/dev/null || ! docker info >/dev/null 2>&1; then
  echo 'FAIL: Docker job cannot reach daemon' >&2
  exit 1
fi
for tool in iptables ip6tables tcpdump nc; do
  command -v "$tool" >/dev/null || { echo "FAIL: $tool absent on Docker host" >&2; exit 1; }
done

# All firewall changes happen inside a disposable host-simulation network
# namespace, never the host OUTPUT chain. The second container is a positive
# packet sink on the same private Docker bridge; --internal prevents public
# egress even if the rule fixture itself regresses.
suffix="$$-$(date +%s)"
net="t162-policy-$suffix"
hostsim="t162-hostsim-$suffix"
sink="t162-sink-$suffix"
tmpdir="$(mktemp -d)"
profile_project="t162-profile-$suffix"
abstract_server="t162-abstract-$suffix"
control_server="t162-control-$suffix"
ipc_volume="t162-ipc-$suffix"
profile_name="stargate-dp-t162-$suffix"
profile_loaded=false
cleanup() {
  docker rm -f "$hostsim" "$sink" "$abstract_server" "$control_server" >/dev/null 2>&1 || true
  docker compose -p "$profile_project" -f compose/docker-compose.local.yml \
    --env-file compose/env/local.env.example down -v --remove-orphans >/dev/null 2>&1 || true
  docker volume rm "$ipc_volume" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  if "$profile_loaded"; then
    docker run --rm --privileged --network none "${policy_mounts[@]}" \
      --entrypoint /usr/sbin/apparmor_parser "$image" -T -R /policy >/dev/null 2>&1 || true
  fi
  rm -rf -- "$tmpdir"
}
trap cleanup EXIT INT TERM

image='debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df'
mounts=(
  --mount 'type=bind,src=/usr,dst=/usr,readonly'
  --mount 'type=bind,src=/lib,dst=/lib,readonly'
  --mount 'type=bind,src=/lib64,dst=/lib64,readonly'
  --mount 'type=bind,src=/etc/alternatives,dst=/etc/alternatives,readonly'
)
docker network create --internal "$net" >/dev/null
docker run -d --name "$sink" --network "$net" "${mounts[@]}" --entrypoint /bin/sh "$image" \
  -c 'nc -lk -p 9999 >/dev/null & nc -luk -p 9998 >/dev/null' >/dev/null
docker run -d --name "$hostsim" --privileged --network "$net" "${mounts[@]}" \
  --mount "type=bind,src=$PWD,dst=/repo,readonly" \
  --mount "type=bind,src=$tmpdir,dst=/tmp/t162-fixtures" \
  --entrypoint /bin/sh "$image" -c 'sleep 3600' >/dev/null
sink_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$sink")"
hostsim_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$hostsim")"
[[ "$sink_ip" =~ ^[0-9.]+$ && "$hostsim_ip" =~ ^[0-9.]+$ ]] || {
  echo 'FAIL: test bridge has no IPv4 peer addresses' >&2; exit 1;
}

# Two falsifier legs: absent rules and wrong-owner rules permit the exact DP
# UID to reach the sink. Neither is treated as an acceptable warning.
docker exec -u 5102 "$hostsim" nc -z -w 1 "$sink_ip" 9999 >/dev/null 2>&1 || {
  echo 'FAIL: missing-rule falsifier has no reachable positive target' >&2; exit 1;
}
docker exec "$hostsim" iptables -N STARGATE_DP_OUT
docker exec "$hostsim" iptables -A STARGATE_DP_OUT -j DROP
docker exec "$hostsim" iptables -I OUTPUT 1 -m owner --uid-owner 9999 -j STARGATE_DP_OUT
docker exec -u 5102 "$hostsim" nc -z -w 1 "$sink_ip" 9999 >/dev/null 2>&1 || {
  echo 'FAIL: ineffective-rule falsifier did not stay reachable' >&2; exit 1;
}
docker exec "$hostsim" iptables -D OUTPUT -m owner --uid-owner 9999 -j STARGATE_DP_OUT

# Exercise the REAL installer in the disposable namespace. Only Docker and
# AppArmor host integrations are stubs: Docker has no daemon socket here,
# while AppArmor is host-global and is tested separately below. iptables and
# ip6tables are the actual host tools operating on this container's netns.
# An intentionally unpinned keygen image stops init at supply_chain_guard,
# after successful host-boundary install/verification but before any volumes
# or real Compose up. Exit 20 (not 60) proves that boundary phase passed.
mkdir -p "$tmpdir/bin"
printf '#!/bin/sh\nexit 0\n' > "$tmpdir/bin/docker"
# T198: the compile stub keeps the unix denies observable (content-dependent
# output) and the feature read reports af_unix mediation; the real parser and
# feature file are exercised by init_t198_test.sh and the live run.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' 'case "$1" in -Q) for arg; do file="$arg"; done; cksum < "$file" ;; esac' \
  'exit 0' > "$tmpdir/bin/apparmor_parser"
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' \
  'if [ "$1" = -Fxq ] && [ "$2" = "stargate-dp (enforce)" ]; then exit 0; fi' \
  'exec /usr/bin/grep "$@"' > "$tmpdir/bin/grep"
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' \
  'if [ "$1" = /sys/kernel/security/apparmor/features/network/af_unix ]; then echo yes; exit 0; fi' \
  'exec /usr/bin/cat "$@"' > "$tmpdir/bin/cat"
chmod +x "$tmpdir/bin/docker" "$tmpdir/bin/apparmor_parser" "$tmpdir/bin/grep" "$tmpdir/bin/cat"
if docker exec \
  -e PATH=/tmp/t162-fixtures/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -e STARGATE_COMPOSE_FILE=/repo/compose/docker-compose.local.yml \
  -e STARGATE_ENV_FILE=/tmp/t162-fixtures/local.env \
  -e STARGATE_KEYGEN_IMAGE=not-digest-pinned \
  "$hostsim" /bin/bash /repo/scripts/subcommands/init \
  >"$tmpdir/installer.out" 2>&1; then
  installer_rc=0
else
  installer_rc=$?
fi
[ "$installer_rc" -eq 20 ] || {
  echo "FAIL: production installer did not pass host-boundary phase (rc=$installer_rc)" >&2
  tail -20 "$tmpdir/installer.out" >&2
  exit 1
}

capture() {
  local name="$1"; shift
  : > "$tmpdir/$name.stderr"
  docker exec "$hostsim" timeout -s INT 5 tcpdump -Z root -i eth0 -U -n \
    -w "/tmp/t162-$name.pcap" "host $sink_ip and (tcp port 9999 or udp port 9998)" \
    >"$tmpdir/$name.stdout" 2>"$tmpdir/$name.stderr" &
  local recorder=$! ready=false
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if grep -q 'listening on eth0' "$tmpdir/$name.stderr"; then ready=true; break; fi
    kill -0 "$recorder" 2>/dev/null || break
    sleep 0.1
  done
  "$ready" || { echo "FAIL: $name recorder did not become ready" >&2; return 1; }
  "$@"
  local rc=0
  wait "$recorder" || rc=$?
  [ "$rc" -eq 124 ] || { echo "FAIL: $name recorder exit $rc" >&2; return 1; }
  grep -q 'packets captured' "$tmpdir/$name.stderr" || {
    echo "FAIL: $name recorder did not exit cleanly" >&2; return 1;
  }
  docker exec "$hostsim" tcpdump -Z root -n -r "/tmp/t162-$name.pcap" 2>/dev/null
}
positive_probe() {
  docker exec -u 6000 "$hostsim" nc -z -w 1 "$sink_ip" 9999 >/dev/null 2>&1
}
denied_probe() {
  docker exec -u 5102 "$hostsim" nc -z -w 1 "$sink_ip" 9999 >/dev/null 2>&1 && {
    echo 'FAIL: DP UID reached off-loopback TCP sink' >&2; return 1;
  }
  docker exec -u 5102 "$hostsim" bash -c "printf x | nc -u -w 1 '$sink_ip' 9998" >/dev/null 2>&1
}
positive_packets="$(capture positive positive_probe)"
[ -n "$positive_packets" ] || { echo 'FAIL: positive capture control was empty' >&2; exit 1; }
required_log() {
  local source="$1" output; shift
  if output="$("$@")"; then
    printf '%s' "$output"
  else
    echo "FAIL: $source log reader failed" >&2
    return 1
  fi
}
# A reader that returns empty output with a failed status must not count as
# evidence of zero denied-packet records, for any of the three log sources.
for source in kernel journal container; do
  if required_log "$source" /bin/false >/dev/null 2>&1; then
    echo "FAIL: $source failed-reader falsifier was accepted" >&2; exit 1
  fi
done
dmesg_before="$(required_log kernel docker exec "$hostsim" dmesg)" || exit 1
journal_since="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
denied_packets="$(capture denied denied_probe)"
[ -z "$denied_packets" ] || { echo 'FAIL: denied DP TCP/UDP escaped eth0' >&2; exit 1; }
for fw in iptables ip6tables; do
  installed_rules="$(docker exec "$hostsim" "$fw" -S STARGATE_DP_OUT)" || {
    echo "FAIL: cannot inspect production-installed $fw rules" >&2; exit 1;
  }
  if grep -q -- '-j LOG' <<< "$installed_rules"; then
    echo "FAIL: production-installed $fw has a per-packet LOG target" >&2; exit 1
  fi
done
dmesg_after="$(required_log kernel docker exec "$hostsim" dmesg)" || exit 1
dmesg_before_count="$(awk -v needle="$sink_ip" 'index($0, needle) { n++ } END { print n+0 }' <<< "$dmesg_before")"
dmesg_after_count="$(awk -v needle="$sink_ip" 'index($0, needle) { n++ } END { print n+0 }' <<< "$dmesg_after")"
[ "$dmesg_after_count" = "$dmesg_before_count" ] || {
  echo 'FAIL: denied packet metadata reached kernel log' >&2; exit 1;
}
command -v journalctl >/dev/null || { echo 'FAIL: journalctl unavailable' >&2; exit 1; }
journal_layouts=()
if [ -d /var/log/journal ]; then
  journal_layouts+=('type=bind,src=/var/log/journal,dst=/var/log/journal,readonly')
fi
if [ -d /run/log/journal ]; then
  journal_layouts+=('type=bind,src=/run/log/journal,dst=/run/log/journal,readonly')
fi
[ "${#journal_layouts[@]}" -gt 0 ] || { echo 'FAIL: no kernel journal source available' >&2; exit 1; }
# Query each available layout independently. A persistent-only or runtime-only
# host is therefore inspected, and a host with both exercises both paths.
for journal_layout in "${journal_layouts[@]}"; do
  journal_text="$(required_log journal docker run --rm --privileged --network none "${mounts[@]}" \
    --mount "$journal_layout" \
    --mount 'type=bind,src=/etc/machine-id,dst=/etc/machine-id,readonly' \
    --entrypoint /usr/bin/journalctl "$image" -k --since "$journal_since" \
    --no-pager -q -o cat)" || exit 1
  if grep -Fq "$sink_ip" <<< "$journal_text"; then
    echo 'FAIL: denied packet metadata reached kernel journal' >&2; exit 1
  fi
done
container_log="$(required_log container docker logs "$hostsim")" || exit 1
if grep -Fq "$sink_ip" <<< "$container_log"; then
  echo 'FAIL: denied packet metadata reached container log' >&2; exit 1;
fi

# Reverse-channel falsifier: unrestricted ESTABLISHED admits replies from an
# off-loopback listener; the shipped lo-scoped rule refuses them, while the
# same UID still answers a browser-style loopback client.
docker exec -d -u 5102 "$hostsim" nc -lk -p 9997
docker exec -d -u 5102 "$hostsim" nc -lk -s 127.0.0.1 -p 9995
docker exec -u 6000 "$hostsim" nc -z -w 1 127.0.0.1 9995 >/dev/null 2>&1 || {
  echo 'FAIL: loopback admission broke under DP owner rules' >&2; exit 1;
}
docker exec "$sink" nc -z -w 1 "$hostsim_ip" 9997 >/dev/null 2>&1 && {
  echo 'FAIL: reverse off-loopback channel open under scoped rule' >&2; exit 1;
}
docker exec "$hostsim" iptables -D STARGATE_DP_OUT -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
docker exec "$hostsim" iptables -I STARGATE_DP_OUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
docker exec "$sink" nc -z -w 1 "$hostsim_ip" 9997 >/dev/null 2>&1 || {
  echo 'FAIL: unrestricted-ESTABLISHED falsifier did not open reverse channel' >&2; exit 1;
}
docker exec "$hostsim" iptables -D STARGATE_DP_OUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
docker exec "$hostsim" iptables -I STARGATE_DP_OUT 1 -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
docker exec "$sink" nc -z -w 1 "$hostsim_ip" 9997 >/dev/null 2>&1 && {
  echo 'FAIL: reverse channel survived restored scoped rule' >&2; exit 1;
}
for fw in iptables ip6tables; do
  docker exec "$hostsim" "$fw" -C OUTPUT -m owner --uid-owner 5102 -j STARGATE_DP_OUT || {
    echo "FAIL: production installer did not install $fw DP jump" >&2; exit 1;
  }
  docker exec "$hostsim" "$fw" -C STARGATE_DP_OUT -o lo -m conntrack \
    --ctstate ESTABLISHED,RELATED -j ACCEPT || {
      echo "FAIL: production installer did not scope $fw replies to lo" >&2; exit 1;
    }
  docker exec "$hostsim" "$fw" -C STARGATE_DP_OUT -j DROP || {
    echo "FAIL: production installer did not install $fw silent DROP" >&2; exit 1;
  }
done

echo 'OK: T162 absent/ineffective rule, zero-packet denial, loopback and reverse-channel falsifiers'

# A unique copy of the production AppArmor policy avoids replacing an
# operator's stargate-dp profile on the Docker host. The privileged helper
# loads only that policy; both application probes run without privilege.
policy_file="$tmpdir/stargate-dp-test"
sed "s/profile stargate-dp flags=/profile $profile_name flags=/" "$profile" > "$policy_file"
apparmor_parser -T -Q "$policy_file"
policy_mounts=(
  "${mounts[@]}"
  --mount 'type=bind,src=/sys/kernel/security,dst=/sys/kernel/security'
  --mount "type=bind,src=$policy_file,dst=/policy,readonly"
)
docker run --rm --privileged --network none "${policy_mounts[@]}" \
  --entrypoint /usr/sbin/apparmor_parser "$image" -T -r /policy >/dev/null
profile_loaded=true
CGO_ENABLED=0 go build -trimpath -o "$tmpdir/profileprobe" ./tests/contract/compose/profileprobe
docker compose -p "$profile_project" -f compose/docker-compose.local.yml \
  --env-file compose/env/local.env.example up -d --build tor >/dev/null
tor_fabric="$(docker volume ls \
  --filter "label=com.docker.compose.project=$profile_project" \
  --filter 'label=com.docker.compose.volume=stargate-tor-dp-fabric' \
  --format '{{.Name}}')"
[ -n "$tor_fabric" ] || { echo 'FAIL: Tor fabric volume absent' >&2; exit 1; }
probe_container() {
  local apparmor="$1"; shift
  docker run --rm --network host --user 5102:5100 --group-add 5200 \
    --cap-drop ALL --security-opt "apparmor=$apparmor" \
    --entrypoint /opt/stargate/stargate-proxy \
    -v "$tmpdir/profileprobe:/opt/stargate/stargate-proxy:ro" \
    -v "$tor_fabric:/run/stargate-tor:ro" \
    stargate/tor:local "$@"
}
tor_ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if probe_container "$profile_name" socks /run/stargate-tor/tor-socks.sock \
    >"$tmpdir/socks.out" 2>&1; then tor_ready=true; break; fi
  sleep 0.5
done
"$tor_ready" || { echo 'FAIL: profile denied authorized Tor SOCKS dial' >&2; exit 1; }

# T191 item 2 (A3-M7): under the profile, UID 5102 in the host network
# namespace cannot read the host's procfs socket tables, for the process or a
# thread view. The unconfined control proves the same read otherwise succeeds,
# so the denial is the profile's and not a missing file. Only byte counts and
# error text are recorded, never table content.
probe_container unconfined read /proc/self/net/tcp >"$tmpdir/procnet-open.out" 2>&1 || {
  echo 'FAIL: unconfined /proc/self/net/tcp positive control could not read' >&2; exit 1;
}
for procnet in /proc/self/net/tcp /proc/thread-self/net/tcp; do
  if probe_container "$profile_name" read "$procnet" >"$tmpdir/procnet.out" 2>&1; then
    echo "FAIL: profiled DP read host socket table $procnet" >&2; exit 1
  fi
  grep -q 'permission denied' "$tmpdir/procnet.out" || {
    echo "FAIL: $procnet denial was not policy-mediated" >&2; exit 1;
  }
done

abstract_name="t162-abstract-$suffix"
docker run -d --name "$abstract_server" --network host \
  -v "$tmpdir/profileprobe:/probe:ro" --entrypoint /probe "$image" \
  abstract-serve "$abstract_name" >/dev/null
abstract_ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if grep -Fq "@$abstract_name" /proc/net/unix; then abstract_ready=true; break; fi
  sleep 0.1
done
"$abstract_ready" || { echo 'FAIL: abstract forwarder fixture not listening' >&2; exit 1; }
if probe_container "$profile_name" abstract-dial "$abstract_name" >"$tmpdir/abstract.out" 2>&1; then
  echo 'FAIL: profiled DP reached host abstract Unix socket' >&2; exit 1
fi
grep -q 'permission denied' "$tmpdir/abstract.out" || {
  echo 'FAIL: abstract denial was not policy-mediated' >&2; exit 1;
}
probe_container unconfined abstract-dial "$abstract_name" >/dev/null || {
  echo 'FAIL: unconfined abstract-socket positive control could not exchange bytes' >&2; exit 1;
}
docker run --rm --network none --user 5102:5100 --cap-drop ALL \
  --security-opt "apparmor=$profile_name" \
  --tmpfs /run/stargate:rw,mode=0770,uid=5102,gid=5100 \
  --entrypoint /opt/stargate/stargate-proxy \
  -v "$tmpdir/profileprobe:/opt/stargate/stargate-proxy:ro" \
  stargate/tor:local listen /run/stargate/dp.sock >/dev/null || {
    echo 'FAIL: profile denied dp.sock server bind' >&2; exit 1;
  }

docker volume create "$ipc_volume" >/dev/null
docker run --rm --network none --cap-drop ALL --cap-add CHOWN --cap-add FOWNER \
  -v "$ipc_volume:/run/stargate" --entrypoint /bin/sh "$image" \
  -c 'chown 5101:5100 /run/stargate && chmod 0770 /run/stargate' >/dev/null
docker run -d --name "$control_server" --network none --user 5101:5100 \
  -v "$ipc_volume:/run/stargate" -v "$tmpdir/profileprobe:/probe:ro" \
  --entrypoint /probe "$image" serve /run/stargate/control.sock >/dev/null
control_ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if docker run --rm --network none -v "$ipc_volume:/run/stargate:ro" \
    --entrypoint /bin/sh "$image" -c '[ -S /run/stargate/control.sock ]' >/dev/null 2>&1; then
    control_ready=true; break
  fi
  sleep 0.1
done
"$control_ready" || { echo 'FAIL: control.sock fixture not listening' >&2; exit 1; }
docker run --rm --network none --user 5102:5100 --cap-drop ALL \
  --security-opt "apparmor=$profile_name" \
  -v "$ipc_volume:/run/stargate" \
  -v "$tmpdir/profileprobe:/opt/stargate/stargate-proxy:ro" \
  --entrypoint /opt/stargate/stargate-proxy stargate/tor:local \
  dial /run/stargate/control.sock >/dev/null || {
    echo 'FAIL: profile denied control.sock client dial' >&2; exit 1;
  }

# Run the production Go gRPC transport tests under the SAME loaded profile:
# authenticated WatchEvents delivery after a server-side close/reconnect,
# and a mutual-ed25519 ReloadTokens RPC over a dp.sock Unix listener.
(cd data-plane && CGO_ENABLED=0 go test -c -o "$tmpdir/controlclient.test" ./internal/controlclient)
docker run --rm --network none --user 5102:5100 --cap-drop ALL \
  --security-opt "apparmor=$profile_name" --tmpfs /tmp:rw,mode=1777 \
  -v "$tmpdir/controlclient.test:/opt/stargate/stargate-proxy:ro" \
  --entrypoint /opt/stargate/stargate-proxy stargate/tor:local \
  -test.run '^(TestClientReconnectsAfterServerClose|TestGRPCServerServesMTLSOverUDS)$' \
  -test.timeout 30s >"$tmpdir/grpc.out" 2>&1 || {
    tail -20 "$tmpdir/grpc.out" >&2
    echo 'FAIL: profiled authenticated gRPC WatchEvents/ReloadTokens regression' >&2; exit 1;
  }

# T178: a successful rename alone is insufficient. The production writer must
# open and fsync the deployment directory before auth becomes durable (II).
docker run --rm --network none --user 5102:5100 --cap-drop ALL \
  --security-opt "apparmor=$profile_name" --security-opt no-new-privileges:true \
  --tmpfs /tmp:rw,mode=1777 --tmpfs /var/lib/stargate:rw,uid=5102,gid=5100,mode=0750 \
  -e STARGATE_TEST_DEPLOYMENT_STATE=1 \
  -v "$tmpdir/controlclient.test:/opt/stargate/stargate-proxy:ro" \
  --entrypoint /opt/stargate/stargate-proxy stargate/tor:local \
  -test.run '^TestDeploymentSnapshotCommitAndRestore$' -test.timeout 30s \
  >"$tmpdir/snapshot.out" 2>&1 || {
    tail -20 "$tmpdir/snapshot.out" >&2
    echo 'FAIL: profiled deployment snapshot commit/restore regression' >&2; exit 1;
  }

docker run --rm --privileged --network none "${policy_mounts[@]}" \
  --entrypoint /bin/bash "$image" -c \
  'apparmor_parser -T -R /policy && ! grep -Fq "$1 (enforce)" /sys/kernel/security/apparmor/profiles' \
  profile-unload "$profile_name" >/dev/null || {
    echo 'FAIL: temporary AppArmor profile could not be removed' >&2; exit 1;
  }
profile_loaded=false

echo 'OK: T162 profiled SOCKS, dp.sock, control.sock, authenticated gRPC; abstract channel denied with byte-exchange positive control'
