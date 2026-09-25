#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T120: default verify runs serialize, and the driver reports its own result.

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
verify_source="${T120_VERIFY_SOURCE:-$repo_root/scripts/verify.sh}"
driver_source="${T120_DRIVER_SOURCE:-$repo_root/scripts/run-task.sh}"
sandbox="$(mktemp -d -t stargate-t120-XXXXXX)"
cleanup() {
  [ -z "${a_pid:-}" ] || kill "$a_pid" 2>/dev/null || true
  [ -z "${b_pid:-}" ] || kill "$b_pid" 2>/dev/null || true
  rm -rf "$sandbox"
}
trap cleanup EXIT
fail() { echo "FAIL: T120 verify concurrency — $*" >&2; exit 1; }

# Assemble a short gate from verify.sh's own setup and summary. The first
# invocation waits inside its gate while the second tries to enter. Without
# the lock, b enters before a is released; with it, b waits outside the log.
collision="$sandbox/collision"
mkdir -p "$collision/target"
git -C "$collision" init -q
awk '/^# === Gate 1:/{exit} {print}' "$verify_source" > "$collision/probe.sh"
cat >> "$collision/probe.sh" <<'FIXTURE'
say ">>> fixture-${T120_PROBE_ID}"
if [ "$T120_PROBE_ID" = a ]; then
  touch target/a.ready
  while [ ! -e target/release ]; do sleep 0.02; done
else
  touch target/b.entered
fi
record "fixture-${T120_PROBE_ID}" PASS
FIXTURE
awk '/^# === Summary/{found=1} found {print}' "$verify_source" >> "$collision/probe.sh"

# The timeout is only a runaway guard; it must outlast a busy CI host's
# scheduling delay while the controller starts b and releases a.
# A driver-run outer verify exports STARGATE_VERIFY_LOG; clear it here so
# both fixtures exercise the default log and its lock in either entry path.
(cd "$collision" && env -u STARGATE_VERIFY_LOG T120_PROBE_ID=a timeout 60 bash probe.sh > a.out 2>&1) & a_pid=$!
for _ in {1..250}; do
  [ ! -e "$collision/target/a.ready" ] || break
  sleep 0.02
done
[ -e "$collision/target/a.ready" ] || fail 'first gate did not start'
(cd "$collision" && env -u STARGATE_VERIFY_LOG T120_PROBE_ID=b timeout 60 bash probe.sh > b.out 2>&1) & b_pid=$!
sleep 2
if [ -e "$collision/target/b.entered" ]; then
  touch "$collision/target/release"
  if ! kill -0 "$a_pid" 2>/dev/null; then
    fail 'first fixture exited before the lock probe could finish'
  fi
  fail 'second gate entered while the first held the default-log lock'
fi
touch "$collision/target/release"
wait "$a_pid" || fail 'first verify invocation failed'
wait "$b_pid" || fail 'second verify invocation failed'
a_pid=""; b_pid=""
for out in a.out b.out; do
  [ "$(grep -c '^RESULT: GREEN' "$collision/$out")" -eq 1 ] || fail "$out lacks one GREEN result"
done
[ "$(grep -c '^RESULT:' "$collision/target/verify.log")" -eq 1 ] || fail 'shared log has multiple results'
[ "$(grep -c '^Stargate verify' "$collision/target/verify.log")" -eq 1 ] || fail 'shared log has multiple headers'
[ "$(grep -c '^>>> fixture-' "$collision/target/verify.log")" -eq 1 ] || fail 'shared log has mixed gate output'

# Minimal git fixture for the real driver. The review handoff must use the
# ticket-local GREEN despite a foreign RED in the default log. Then the own
# gate fails despite a foreign GREEN, leaving the ticket in progress.
driver="$sandbox/driver"
mkdir -p "$driver/scripts" "$driver/.specify" "$driver/specs/001-fixture/tickets" "$driver/target/runs"
git -C "$driver" init -q -b 001-fixture
git -C "$driver" config user.name 'T120 Probe'
git -C "$driver" config user.email 't120@test.local'
cp "$driver_source" "$driver/scripts/run-task.sh"
cp "$repo_root/scripts/review-matrix.json" "$driver/scripts/review-matrix.json"
printf '{"feature_directory":"specs/001-fixture"}\n' > "$driver/.specify/feature.json"
printf 'target/\n' > "$driver/.gitignore"
cat > "$driver/scripts/verify.sh" <<'VERIFY_STUB'
#!/usr/bin/env bash
mkdir -p target/runs
printf 'RESULT: RED — own failed gate\n' > "${STARGATE_VERIFY_LOG:-target/verify.log}"
exit 1
VERIFY_STUB
cat > "$driver/specs/001-fixture/tickets/T999-fixture.md" <<'TICKET'
---
id: T999
title: 'T120 driver log fixture'
status: in-review
privacy_critical: false
files_budget: 1
round_cap: 2
---
# T999 fixture
TICKET
git -C "$driver" add .
git -C "$driver" commit -q -m fixture
printf 'RESULT: RED — foreign stale gate\n' > "$driver/target/verify.log"
printf 'RESULT: GREEN — own completed gate\n' > "$driver/target/runs/T999.verify.log"
(cd "$driver" && bash scripts/run-task.sh T999 > target/handoff.out) || fail 'review handoff failed'
grep -q 'verify log:.*T999.verify.log.*RESULT: GREEN — own completed gate' "$driver/target/handoff.out" \
  || fail 'review handoff did not report the own GREEN result'
sed -i 's/^status: in-review$/status: in-progress/' "$driver/specs/001-fixture/tickets/T999-fixture.md"
touch "$driver/target/runs/T999.verified"
printf 'RESULT: GREEN — foreign stale gate\n' > "$driver/target/verify.log"
if (cd "$driver" && bash scripts/run-task.sh T999 > target/failed.out 2>&1); then
  fail 'driver advanced after its own verify failed'
fi
grep -q '^status: in-progress$' "$driver/specs/001-fixture/tickets/T999-fixture.md" \
  || fail 'failing own verify changed ticket status'
grep -q '^RESULT: RED — own failed gate$' "$driver/target/runs/T999.verify.log" \
  || fail 'driver did not write its own failing log'

echo 'PASS: T120 default-log serialization and driver-owned result attribution'
