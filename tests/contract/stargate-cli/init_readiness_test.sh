#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T152: running containers and a reachable DP must not substitute for Tor readiness.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
probe="$(mktemp -d)"
trap 'rm -rf "$probe"' EXIT
# Exercise the installer's real wait function without provisioning a host stack.
sed -n '/^wait_healthy() {/,/^# ---- 6\./p' scripts/subcommands/init > "$probe/wait.sh"
# shellcheck disable=SC1091
. "$probe/wait.sh"
SERVICES=(stargate-dp stargate-control tor tor-observer)
STARGATE_HEALTHCHECK_TIMEOUT=3
EXIT_HEALTHCHECK=40
note() { :; }
# Deterministic deadline: command substitutions run in subshells, so keep the
# fake clock in the fixture directory rather than in a shell-local variable.
date() {
  local tick
  read -r tick < "$probe/time"
  printf '%s\n' "$((tick+1))" > "$probe/time"
  printf '%s\n' "$tick"
}
sleep() { :; }
compose_cmd() { echo fixture; }
compose_health_ids() { echo "running-$1"; }
docker() {
  case "$*" in
    *State.Running*) echo true ;;
    *State.Health*) echo none ;;
    *) return 1 ;;
  esac
}
compose_run() {
  [ "$*" = 'exec -T tor-observer /opt/stargate/tor-observer --check-ready' ] || return 99
  echo sampled >> "$probe/calls"
  cat > "$probe/input"
  if [ -s "$probe/input" ]; then touch "$probe/leaked-input"; fi
  return "$sample_rc"
}
for sample_rc in 1 2 125 0; do
  : > "$probe/calls"
  echo 0 > "$probe/time"
  if wait_healthy <<<'T152-private-caller-input'; then actual=0; else actual=$?; fi
  expected=40
  [ "$sample_rc" -eq 0 ] && expected=0
  [ "$actual" -eq "$expected" ] || { echo "FAIL: readiness exit $sample_rc yielded init $actual, expected $expected" >&2; exit 1; }
  [ ! -f "$probe/leaked-input" ] || { echo 'FAIL: readiness command consumed caller input' >&2; exit 1; }
  [ -s "$probe/calls" ] || { echo 'FAIL: authenticated current readiness was never sampled' >&2; exit 1; }
  [ "$(cat "$probe/time")" -le 4 ] || { echo 'FAIL: readiness wait exceeded its deadline' >&2; exit 1; }
done
echo 'PASS: running/no-health containers require current READY; NOT_READY, UNAVAILABLE and exec failure time out'
