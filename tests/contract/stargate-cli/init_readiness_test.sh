#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T152/T124: running containers and a reachable DP cannot substitute for Tor READY.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
probe="$(mktemp -d)"
trap 'rm -rf "$probe"' EXIT
# Exercise the installer's real wait function without provisioning a host stack.
sed -n '/^wait_healthy() {/,/^# ---- 6\./p' scripts/subcommands/init > "$probe/wait.sh"
# shellcheck disable=SC1091
. "$probe/wait.sh"
SERVICES=(stargate-dp stargate-control tor tor-observer)
# Source the production default itself: a copied literal would miss default drift.
unset STARGATE_HEALTHCHECK_TIMEOUT
# shellcheck disable=SC1090,SC2016 -- literal ${...} selects the default assignment
. <(sed -n '/^: "${STARGATE_HEALTHCHECK_TIMEOUT:=/p' scripts/subcommands/init)
default_timeout="$STARGATE_HEALTHCHECK_TIMEOUT"
EXIT_HEALTHCHECK=40
note() { :; }
# Command substitutions run in subshells, so the fake clock lives in a file.
date() { cat "$probe/time"; }
sleep() {
  local tick
  read -r tick < "$probe/time"
  printf '%s\n' "$((tick + $1))" > "$probe/time"
}
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
  local tick
  read -r tick < "$probe/time"
  if [ "$ready_at" -ge 0 ] && [ "$tick" -ge "$ready_at" ]; then return 0; fi
  return "$sample_rc"
}
for scenario in ready_immediately delayed_ready_default short_override_timeout \
                long_override_delayed_ready never_ready_timeout \
                unavailable_timeout exec_failure_timeout; do
  STARGATE_HEALTHCHECK_TIMEOUT="$default_timeout"
  ready_at=-1
  sample_rc=1
  expected=40
  case "$scenario" in
    ready_immediately) ready_at=0; expected=0 ;;
    delayed_ready_default) ready_at=90; expected=0 ;;
    short_override_timeout) STARGATE_HEALTHCHECK_TIMEOUT=60; ready_at=90 ;;
    long_override_delayed_ready)
      STARGATE_HEALTHCHECK_TIMEOUT=400; ready_at=320; expected=0 ;;
    never_ready_timeout) : ;;
    unavailable_timeout) sample_rc=2 ;;
    exec_failure_timeout) sample_rc=125 ;;
  esac
  : > "$probe/calls"
  echo 0 > "$probe/time"
  if wait_healthy <<<'T124-private-caller-input'; then actual=0; else actual=$?; fi
  [ "$actual" -eq "$expected" ] || {
    echo "FAIL: $scenario yielded init $actual at simulated second $(cat "$probe/time"), expected $expected" >&2
    exit 1
  }
  [ ! -f "$probe/leaked-input" ] || { echo "FAIL: $scenario consumed caller input" >&2; exit 1; }
  [ -s "$probe/calls" ] || { echo "FAIL: $scenario never sampled observer readiness" >&2; exit 1; }
  tick="$(cat "$probe/time")"
  if [ "$expected" -eq 0 ]; then
    [ "$tick" -eq "$ready_at" ] || { echo "FAIL: $scenario delayed success until $tick" >&2; exit 1; }
  else
    [ "$tick" -eq "$STARGATE_HEALTHCHECK_TIMEOUT" ] || {
      echo "FAIL: $scenario expired at $tick, expected $STARGATE_HEALTHCHECK_TIMEOUT" >&2
      exit 1
    }
  fi
done
echo 'PASS: current READY succeeds within the configured window; incomplete/unavailable samples time out'
