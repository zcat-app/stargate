#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/stargate-cli/init_countprobe_test.sh — T106 focused
# regression test: the init count-probe failure path MUST fail-closed.
#
# WHAT THIS GATES (T106 §Acceptance #1 + #3):
#   scripts/subcommands/init generate_keys runs a hardened helper container
#   to count the existing key+pepper files in stargate-keys before deciding
#   whether to generate fresh keys (arch §9.3 do-not-clobber / M5). T106
#   flips the capture from fail-OPEN (`|| existing="0"` → a transient
#   helper crash silently regenerates ed25519 keys + pepper over existing
#   ones, invalidating every enrolled device) to fail-CLOSED (non-zero
#   exit from the count-probe → EXIT_KEYGEN, never "fresh volume").
#
# WHY A FOCUSED UNIT ASSERTION, not the Docker-backed init_docker_test.sh:
#   T106 §Acceptance #3 suggests "point STARGATE_KEYGEN_IMAGE at a
#   non-existent digest-pinned image so the count-probe fails." Grounding
#   proved that suggestion VACUOUS: supply_chain_guard (init's pre-pull,
#   lines 178-184) and ensure_volumes (init_volume_root uses the SAME
#   image) both run BEFORE generate_keys' count-probe — a bad image fails
#   at supply_chain_guard / ensure_volumes and the count-probe is never
#   reached, so the assertion passes identically before and after the fix.
#   The acceptance explicitly allows "or a focused unit assertion"; this
#   is it.
#
# APPROACH: run the REAL init end-to-end against a stub `docker` on PATH
#   whose ONLY failure is the count-probe invocation (detected by its
#   `-v <vol>:/keys:ro` mount — unique to that call). No Docker daemon
#   is needed; every other docker subcommand is stubbed to succeed. The
#   install step (`-v <tmp>:/src:ro`) logs to DOCKER_LOG, proving whether
#   key+pepper generation proceeded past the count-probe.
#
# FAIL-THEN-PASS (Principle VII, no AI exception):
#   BEFORE the fix: count-probe fails → `|| existing="0"` → fresh →
#     generate_keys proceeds → install step runs (logged) → returns 0 →
#     compose_up runs (stubbed to fail) → init exits 30. Keys WOULD be
#     clobbered. Test FAILS on both "exit 20" and "install not invoked".
#   AFTER  the fix: count-probe fails → return EXIT_KEYGEN → init exits
#     20 immediately. Install step never runs. Test PASSES.
#
# Self-SKIPs (exit 0 + SKIP notice) when openssl is absent (init's real
# keygen needs it for the before-fix path). Hermetic otherwise: no daemon,
# no network, no fixture images.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

INIT="scripts/subcommands/init"

# init's generate_keys runs real openssl genpkey/pkey/rand in the before-fix
# path (to prove the install step is reached). openssl is the only real
# binary this test needs.
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not on PATH (init_countprobe_test needs it for the fail-open path)."; exit 0; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

FAKE_BIN="$TMP/bin"
mkdir -p "$FAKE_BIN"
export DOCKER_LOG="$TMP/docker.log"
: > "$DOCKER_LOG"

# Stub `docker`. Routes by subcommand + mount spec. The count-probe
# (`*:/keys:ro`) is the ONLY failure — simulating the transient helper
# crash (daemon hiccup / OOM / SIGKILL) described in T106 §Context. The
# install step (`*:/src:ro`) logs INSTALL_INVOKED and succeeds, so the
# before-fix path proceeds past generate_keys (exposing the clobber) and
# the test can detect it. compose `up` is stubbed to fail, bounding the
# before-fix run to compose_up (exit 30) so wait_healthy / verify_tor
# never run — keeps the test fast and daemon-free.
cat > "$FAKE_BIN/docker" <<'SCRIPT_END'
#!/usr/bin/env bash
case "$1" in
  context)
    case "$2" in
      show) printf 'default\n' ;;
      inspect) printf '"unix:///var/run/docker.sock"\n' ;;
      *) exit 1 ;;
    esac ;;
  info)
    if [ "${2:-}" = --format ]; then printf '["name=seccomp,profile=builtin"]\n'; fi
    exit 0 ;;
  image|pull)
    exit 0 ;;
  compose)
    # `version` (preflight) and `ps -q` (health) succeed; `up` fails to
    # bound the before-fix path to compose_up (exit 30) — after-fix never
    # reaches compose.
    for a in "$@"; do
      case "$a" in up) exit 1 ;; esac
    done
    exit 0 ;;
  volume)
    # resolve_physical_volume (ls → empty) + ensure_project_volume (create).
    exit 0 ;;
  inspect)
    exit 0 ;;
  run)
    # Route by the volume mount spec (unique per call site in init):
    #   count-probe : -v <keys_phys>:/keys:ro   → FAIL (the scenario)
    #   install step : -v <KEYS_TMP>:/src:ro     → log + succeed
    #   init_volume_root + anything else         → succeed
    for a in "$@"; do
      case "$a" in *:/keys:ro) exit 1 ;; esac
    done
    for a in "$@"; do
      case "$a" in *:/src:ro) printf 'INSTALL_INVOKED\n' >> "$DOCKER_LOG"; exit 0 ;; esac
    done
    exit 0 ;;
  *)
    exit 0 ;;
esac
SCRIPT_END
chmod +x "$FAKE_BIN/docker"

errs=()
bail() { errs+=("$*"); }

PROJ="t106-$$-$(date +%s)"

# Run the REAL init with the stub docker first on PATH. STARGATE_* tunables
# are pointed at temp paths so no repo state is touched; the after-fix path
# exits at generate_keys (exit 20) before any compose/file work, and the
# before-fix path exits at compose_up (exit 30).
env -u STARGATE_KEYGEN_IMAGE \
  STARGATE_PROJECT="$PROJ" \
  STARGATE_COMPOSE_FILE="$PWD/tests/contract/stargate-cli/fixtures/fixture-compose.yml" \
  STARGATE_ENV_DIR="$TMP" \
  STARGATE_ENV_EXAMPLE="$TMP/no-such-example.env" \
  STARGATE_ENV_FILE="$TMP/$PROJ.env" \
  STARGATE_HEALTHCHECK_TIMEOUT=1 \
  PATH="$FAKE_BIN:$PATH" \
  bash "$INIT" >/dev/null 2>&1
rc=$?

# Acceptance #1: count-probe failure → EXIT_KEYGEN (20), never "fresh".
[ "$rc" -eq 20 ] \
  || bail "init exited $rc on count-probe failure (expected 20 / EXIT_KEYGEN); the capture is still fail-open"

# Acceptance #3 proxy: the install step MUST NOT have run — if it did, key
# + pepper generation proceeded past the count-probe and would clobber the
# existing volume (the T066 / T088-M5 regression). Byte-identity of real
# keys is demonstrated by "install never invoked": no install → no write.
if grep -q INSTALL_INVOKED "$DOCKER_LOG"; then
  bail "count-probe failure led to the key+pepper install step (fail-OPEN: existing keys would be clobbered)"
fi

# Structural belt-and-suspenders: the fail-open literal must be gone. After
# the fix the count-probe failure returns EXIT_KEYGEN instead of defaulting
# existing to "0". (`${existing:-0}` on the decision branch is unrelated.)
grep -q 'existing="0"' "$INIT" \
  && bail "fail-open 'existing=\"0\"' default still present in init (expected fail-closed return on count-probe failure)"

if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T106 init_countprobe_test (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T106 count-probe fail-closed (init exits 20 on helper failure; key+pepper install never reached)"
exit 0
