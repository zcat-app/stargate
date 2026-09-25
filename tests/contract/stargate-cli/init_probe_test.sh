#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T146: a bounded TCP timeout establishes only that readiness was not observed.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

probe="$(mktemp -d)"
trap 'rm -rf "$probe"' EXIT
sed -n '/^tor_probe_port() {/,/^# ---- 7\./p' scripts/subcommands/init > "$probe/verify.sh"
# shellcheck disable=SC1091
. "$probe/verify.sh"
STARGATE_PROBE_TIMEOUT=1
EXIT_VERIFY=50
_SG_REPO_ROOT="$PWD"
STARGATE_COMPOSE_FILE="$PWD/compose/docker-compose.local.yml"
note() { printf '%s\n' "$*" >&2; }
timeout() { return 124; }

if verify_tor 2>"$probe/diagnosis"; then
  echo 'FAIL: timed-out probe was accepted' >&2
  exit 1
else
  rc=$?
fi
[ "$rc" -eq 50 ] || { echo "FAIL: timeout returned $rc, expected 50" >&2; exit 1; }
grep -q '127.0.0.1:8881 timed out' "$probe/diagnosis" || {
  echo 'FAIL: timeout observation missing' >&2; exit 1;
}
if grep -Eq 'port published|nothing accepting|data plane listener did not come up|VPN|firewall' "$probe/diagnosis"; then
  echo 'FAIL: timeout diagnosis asserted an unobserved cause' >&2
  exit 1
fi
echo 'PASS: init timeout reports the failed readiness observation without a cause claim'
