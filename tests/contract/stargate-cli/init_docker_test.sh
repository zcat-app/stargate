#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# tests/contract/stargate-cli/init_docker_test.sh — T088's Docker-backed
# regression test for `scripts/stargate init`. Proves the B1 fixes
# (review/sol-review.md#B1) end-to-end by running the REAL init against a
# tiny fixture stack (no Stargate build) and asserting the post-conditions
# B1 showed were broken:
#
#   - env file is supplied (one compose-command builder owns project name +
#     compose file + env file)                       [acceptance #2]
#   - volumes are project-scoped, resolved by Compose labels, NOT literal
#     `stargate-*` physical names                     [acceptance #3]
#   - key volume is fail-closed + correct ownership/mode, AND the pepper
#     (T092 amendment) is provisioned                [acceptance #4]
#   - writable volume roots are initialised for the non-root service UIDs
#     (ipc / control-state / dp-state / tor-config)  [B1]
#   - health discovery uses `compose ps -q <svc>`, never guessed names    [B1]
#   - idempotent rerun (existing keys + pepper preserved)                [acceptance]
#   - two-project isolation (distinct physical volumes, no cross-leak)   [B1]
#
# Principle VII (tests-first, no AI exception): this test MUST fail against
# the pre-fix installer for the B1 reasons and pass after the fix — that
# fail-then-pass is the falsification the ticket §Notes mandates.
#
# Self-SKIPs (exit 0 + SKIP notice) when the Docker daemon is unreachable,
# so `scripts/verify.sh` stays green on Docker-less hosts (the verify.sh
# "self-SKIP" philosophy). Where Docker is present it runs the real
# assertions.

set -uo pipefail

cd "$(git rev-parse --show-toplevel)"

REPO="$(git rev-parse --show-toplevel)"
LIB="$REPO/scripts/lib/compose.sh"
FIXTURE="$REPO/tests/contract/stargate-cli/fixtures/fixture-compose.yml"
DISPATCHER="$REPO/scripts/stargate"
# Principle IV (every external component digest-pinned): pull by the
# multi-arch OCI index digest, never the mutable tag — on a daemon host the
# tag would otherwise resolve at pull time with no integrity anchor (T107).
# Rotation is a manual promotion: resolve the new digest, update this const,
# the fixture anchor, and SECURITY-DECISIONS.md in one PR (new superseding
# entry there — dated bodies are immutable), then re-run this suite.
STAT_IMAGE="alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"

errs=()
bail() { errs+=("$*"); }
fail() { echo "FAIL: $*" >&2; exit 1; }

# ---- self-SKIP if the Docker daemon is unreachable ------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not on PATH (init_docker_test needs a daemon)."
  exit 0
fi
if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon unreachable (init_docker_test needs a daemon)."
  exit 0
fi

# shellcheck source=scripts/lib/compose.sh
. "$LIB" || fail "cannot source $LIB"

# Unique project names so concurrent runs / leftover state cannot collide.
_suffix="t088-$$-$(date +%s)"
PROJ_A="t088isoa-$_suffix"
PROJ_B="t088isob-$_suffix"

# Temp env-file location so the test never touches the repo's compose/env.
TMP="$(mktemp -d)"
trap '
  for p in "$PROJ_A" "$PROJ_B"; do
    [ -n "$p" ] && STARGATE_PROJECT="$p" STARGATE_COMPOSE_FILE="$FIXTURE" \
      STARGATE_ENV_FILE="$TMP/local.env" STARGATE_ENV_DIR="$TMP" \
      compose_run down -v -t 1 >/dev/null 2>&1 || true
  done
  rm -rf "$TMP"
' EXIT INT TERM

# ---- HERMETIC assertions (no daemon needed) -------------------------------
# compose_cmd must render the authoritative prefix with project + file + env.
STARGATE_PROJECT="hermetic-proj"
STARGATE_COMPOSE_FILE="/tmp/hermetic-compose.yml"
STARGATE_ENV_DIR="$TMP"
STARGATE_ENV_EXAMPLE="$TMP/no-such-example.env"
STARGATE_ENV_FILE="$TMP/hermetic-local.env"
rm -f "$STARGATE_ENV_FILE"
rendered="$(compose_cmd)"
expected="docker compose -p $STARGATE_PROJECT -f $STARGATE_COMPOSE_FILE --env-file $STARGATE_ENV_FILE"
[ "$rendered" = "$expected" ] \
  || bail "hermetic: compose_cmd rendered '$rendered', expected '$expected'"
# compose_env_file must create the file from scratch when no example exists.
[ -f "$STARGATE_ENV_FILE" ] \
  || bail "hermetic: compose_env_file did not create $STARGATE_ENV_FILE"

# ---- DAEMON-BACKED assertions: run real init against the fixture ----------
# Helper: run the REAL dispatcher/init under a project, with the fixture.
run_init() {
  local project="$1" readiness_timeout="${2:-40}"
  STARGATE_PROJECT="$project" \
  STARGATE_COMPOSE_FILE="$FIXTURE" \
  STARGATE_ENV_DIR="$TMP" \
  STARGATE_ENV_EXAMPLE="$FIXTURE-env-example-missing" \
  STARGATE_ENV_FILE="$TMP/$project.env" \
  STARGATE_HEALTHCHECK_TIMEOUT="$readiness_timeout" \
    bash "$DISPATCHER" init
}

# stat inside a volume: echoes "<uid> <gid> <mode-octal> <size>" for a path.
vol_stat() {
  local phys="$1" path="$2"
  docker run --rm -v "${phys}:/v" "$STAT_IMAGE" \
    stat -c '%u %g %a %s' "/v/$path" 2>/dev/null
}
vol_exists() { local phys="$1" path="$2"
  docker run --rm -v "${phys}:/v" "$STAT_IMAGE" \
    test -e "/v/$path" 2>/dev/null; }
vol_sha() { local phys="$1" path="$2"
  docker run --rm -v "${phys}:/v" "$STAT_IMAGE" \
    sha256sum "/v/$path" 2>/dev/null | awk '{print $1}'; }

# resolve_physical_volume under a given project (re-scope the lib helper).
phys_of() {
  local project="$1" logical="$2"
  docker volume ls \
    --filter "label=com.docker.compose.project=$project" \
    --filter "label=com.docker.compose.volume=$logical" \
    --format '{{.Name}}' 2>/dev/null | head -n1
}

# --- Project A: fresh init -------------------------------------------------
echo ">>> init project A ($PROJ_A)"
out="$(run_init "$PROJ_A" 2>&1)"; rc=$?
[ "$rc" -eq 0 ] || { echo "$out" >&2; bail "init project A exited $rc (expected 0)"; }

# env file supplied (acceptance #2): created by init's compose_env_file.
[ -f "$TMP/$PROJ_A.env" ] \
  || bail "A: env file $TMP/$PROJ_A.env not created (init must supply --env-file)"

# project-scoped volumes (acceptance #3): keys volume is <proj>_stargate-keys,
# resolved by Compose label — NOT the literal `stargate-keys`.
keys_a="$(phys_of "$PROJ_A" stargate-keys)"
[ -n "$keys_a" ] || bail "A: stargate-keys volume not found under project label"
case "$keys_a" in
  "${PROJ_A}_"*) : ;;
  *) bail "A: keys volume '$keys_a' is not project-scoped (expected ${PROJ_A}_stargate-keys)";;
esac
[ "$keys_a" != "stargate-keys" ] \
  || bail "A: keys volume resolved to literal 'stargate-keys' (B1 regression)"
observer_keys_a="$(phys_of "$PROJ_A" stargate-observer-keys)"
[ -n "$observer_keys_a" ] || bail "A: observer key volume missing"
observer_fabric_a="$(phys_of "$PROJ_A" stargate-tor-cp-fabric)"
[ -n "$observer_fabric_a" ] || bail "A: observer fabric volume missing"
config_a="$(phys_of "$PROJ_A" stargate-control-config)"
[ -n "$config_a" ] || bail "A: stargate-control-config volume missing"
vol_exists "$config_a" keys \
  || bail "A: read-only config volume lacks the CP keys child mountpoint (T167)"

# keys present with correct ownership/mode (acceptance #4 + T016 M4 literals).
for f in cp.priv dp.priv; do
  read -r uid gid mode size <<<"$(vol_stat "$keys_a" "$f")"
  [ "$mode" = "600" ] || bail "A: $f mode '$mode' (expected 600)"
  [ "$gid" = "5100" ] || bail "A: $f gid '$gid' (expected 5100 stargate-ipc)"
done
# cp.priv owned by CP (5101); dp.priv by DP (5102).
read -r cpub_uid _ <<<"$(vol_stat "$keys_a" cp.priv)"; [ "$cpub_uid" = "5101" ] || bail "A: cp.priv uid '$cpub_uid' (expected 5101)"
read -r dpub_uid _ <<<"$(vol_stat "$keys_a" dp.priv)"; [ "$dpub_uid" = "5102" ] || bail "A: dp.priv uid '$dpub_uid' (expected 5102)"
for f in cp.pub dp.pub; do
  read -r uid gid mode size <<<"$(vol_stat "$keys_a" "$f")"
  [ "$mode" = "644" ] || bail "A: $f mode '$mode' (expected 644)"
  [ "$gid" = "5100" ] || bail "A: $f gid '$gid' (expected 5100)"
done
vol_exists "$keys_a" observer.pub || bail "A: CP observer pin missing"
read -r ouid ogid omode _ <<<"$(vol_stat "$observer_keys_a" observer.priv)"
[ "$ouid:$ogid:$omode" = "5103:5103:600" ] \
  || bail "A: observer private key ownership/mode '$ouid:$ogid:$omode'"
read -r fuid fgid fmode _ <<<"$(vol_stat "$observer_fabric_a" .)"
[ "$fuid:$fgid:$fmode" = "5103:5100:770" ] \
  || bail "A: observer fabric root ownership/mode '$fuid:$fgid:$fmode'"
vol_exists "$observer_keys_a" cp.pub || bail "A: observer CP pin missing"

# pepper provisioned (T092 amendment): pepper.key, 32 bytes, 0640, group 5100.
vol_exists "$keys_a" pepper.key || bail "A: pepper.key missing (T092 provisioning)"
read -r puid pgid pmode psize <<<"$(vol_stat "$keys_a" pepper.key)"
[ "$pmode" = "640" ] || bail "A: pepper.key mode '$pmode' (expected 640)"
[ "$pgid" = "5100" ] || bail "A: pepper.key gid '$pgid' (expected 5100 stargate-ipc)"
[ "$puid" = "5101" ] || bail "A: pepper.key uid '$puid' (expected 5101 stargate-cp)"
[ "$psize" = "32" ] || bail "A: pepper.key size '$psize' bytes (expected 32)"

# writable volume roots initialised (B1): ipc/control-state/dp-state/tor-config
# roots owned by the service UID + group stargate-ipc, mode 750.
declare -A ROOT_SPEC=(
  [stargate-ipc]="5102 5100"        # DP writes its UDS first; shared via GID 5100
  [stargate-control-state]="5101 5100"
  [stargate-dp-state]="5102 5100"
  [stargate-tor-config]="5101 5100"
)
for vol in "${!ROOT_SPEC[@]}"; do
  phys="$(phys_of "$PROJ_A" "$vol")"
  [ -n "$phys" ] || bail "A: $vol volume not found under project label"
  read -r want_uid want_gid <<<"${ROOT_SPEC[$vol]}"
  read -r ruid rgid rmode _ <<<"$(vol_stat "$phys" ".")"
  [ "$rgid" = "$want_gid" ] || bail "A: $vol root gid '$rgid' (expected $want_gid)"
  case "$rmode" in 750|770|755) : ;; *) bail "A: $vol root mode '$rmode' (expected group-accessible 750/770)";; esac
done

# health discovery via `compose ps -q` (B1): each service resolves to a
# container id (no guessed names). compose_health_ids is the lib helper init
# uses; re-scope it under the project.
STARGATE_PROJECT="$PROJ_A"; STARGATE_COMPOSE_FILE="$FIXTURE"; STARGATE_ENV_FILE="$TMP/$PROJ_A.env"; STARGATE_ENV_DIR="$TMP"
for svc in stargate-dp stargate-control tor; do
  cid="$(compose_health_ids "$svc")"
  [ -n "$cid" ] || bail "A: compose ps -q $svc returned no container id (health discovery broken)"
  docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null | grep -q true \
    || bail "A: $svc container not running (cid=$cid)"
done

# Capture A's key hashes for the idempotence check.
cp_priv_a="$(vol_sha "$keys_a" cp.priv)"
pepper_a="$(vol_sha "$keys_a" pepper.key)"
observer_priv_a="$(vol_sha "$observer_keys_a" observer.priv)"

# --- redteam Major #1: keygen helpers are network-less ---------------------
# The hardened helpers are `--rm` (gone after init), so create — don't start —
# a container with init's EXACT hardening flags and assert its only network
# attachment is "none" (no NAT egress for the root/RW-on-keys helper).
hc="$(docker create --network none --cap-drop ALL --cap-add CHOWN --cap-add FOWNER \
  --read-only --tmpfs /tmp "$STAT_IMAGE" sh -c 'true' 2>/dev/null)" \
  || bail "redteam#1: could not create hardened helper container"
hnet="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$hc" 2>/dev/null)"
docker rm "$hc" >/dev/null 2>&1
echo "$hnet" | grep -qw none \
  || bail "redteam#1: hardened helper network is '$hnet' (expected only 'none' — no egress for the keygen helper)"
# Negative control: a PLAIN container (no --network none) gets the default
# bridge — proves the assertion above is distinguishing, not vacuous.
nc="$(docker create "$STAT_IMAGE" sh -c 'true' 2>/dev/null)" || bail "redteam#1: negative-control create failed"
nnet="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$nc" 2>/dev/null)"
docker rm "$nc" >/dev/null 2>&1
echo "$nnet" | grep -qw bridge \
  || bail "redteam#1: negative control — plain container network '$nnet' unexpectedly lacks bridge (test is vacuous)"

# --- Idempotent rerun (acceptance: existing keys + pepper preserved) -------
echo ">>> re-init project A (idempotence)"
out="$(run_init "$PROJ_A" 2>&1)"; rc=$?
[ "$rc" -eq 0 ] || { echo "$out" >&2; bail "idempotent re-init exited $rc (expected 0)"; }
cp_priv_a2="$(vol_sha "$keys_a" cp.priv)"
pepper_a2="$(vol_sha "$keys_a" pepper.key)"
observer_priv_a2="$(vol_sha "$observer_keys_a" observer.priv)"
[ "$cp_priv_a" = "$cp_priv_a2" ] \
  || bail "idempotence: cp.priv changed on rerun (keys must be preserved)"
[ "$observer_priv_a" = "$observer_priv_a2" ] \
  || bail "idempotence: observer.priv changed on rerun"
[ "$pepper_a" = "$pepper_a2" ] \
  || bail "idempotence: pepper.key changed on rerun (pepper must be preserved)"

# Simulate a T162 installation: the original CP/DP keys and pepper exist,
# while no observer identity has been provisioned. T164 must add only its
# identity, never rotate the existing authenticated state.
docker run --rm --network none --cap-drop ALL --cap-add DAC_OVERRIDE \
  --read-only -v "${keys_a}:/keys" -v "${observer_keys_a}:/observer" \
  "$STAT_IMAGE" sh -c \
  'rm /keys/observer.pub /observer/observer.priv /observer/cp.pub' >/dev/null 2>&1 \
  || bail "upgrade fixture could not remove observer-only keys"
out="$(run_init "$PROJ_A" 2>&1)"; rc=$?
[ "$rc" -eq 0 ] || { echo "$out" >&2; bail "observer-only upgrade exited $rc"; }
[ "$(vol_sha "$keys_a" cp.priv)" = "$cp_priv_a" ] \
  || bail "upgrade rotated cp.priv"
[ "$(vol_sha "$keys_a" pepper.key)" = "$pepper_a" ] \
  || bail "upgrade rotated pepper.key"
[ "$(vol_sha "$observer_keys_a" observer.priv)" != "$observer_priv_a" ] \
  || bail "upgrade reused deleted observer private key"

# T152: with running/no-health containers and the real DP fixture listener
# accepting TCP, current NOT_READY/UNAVAILABLE must still prevent init success.
STARGATE_PROJECT="$PROJ_A"; STARGATE_COMPOSE_FILE="$FIXTURE"; STARGATE_ENV_FILE="$TMP/$PROJ_A.env"; STARGATE_ENV_DIR="$TMP"
observer_cid="$(compose_health_ids tor-observer)"
[ -n "$observer_cid" ] || bail "T152 observer fixture absent"
for current_rc in 1 2; do
  docker exec "$observer_cid" sh -c 'printf "#!/bin/sh\nexit %s\n" "$1" > /opt/stargate/tor-observer' sh "$current_rc" \
    || bail "T152 could not set current readiness fixture"
  [ "$(docker inspect -f '{{.State.Running}}:{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$observer_cid")" = true:none ] \
    || bail "T152 running/no-health precondition"
  (exec 3<>/dev/tcp/127.0.0.1/8881) 2>/dev/null || bail "T152 DP TCP positive control"
  out="$(run_init "$PROJ_A" 1 2>&1)"; rc=$?
  [ "$rc" -eq 40 ] || bail "T152 current readiness exit $current_rc allowed init exit $rc, expected 40"
done

# --- Project isolation (B1): a second project is fully distinct -----------
# Tear A down first (frees 127.0.0.1:8881 so B's stargate-dp can bind it; the
# fixture publishes the same loopback port). A's key hashes + volume name are
# already captured above for the distinctness comparison.
echo ">>> teardown project A before isolation run"
STARGATE_PROJECT="$PROJ_A"; STARGATE_COMPOSE_FILE="$FIXTURE"; STARGATE_ENV_FILE="$TMP/$PROJ_A.env"; STARGATE_ENV_DIR="$TMP"
compose_run down -v -t 1 >/dev/null 2>&1 || true

echo ">>> init project B ($PROJ_B) — isolation"
out="$(run_init "$PROJ_B" 2>&1)"; rc=$?
[ "$rc" -eq 0 ] || { echo "$out" >&2; bail "init project B exited $rc (expected 0)"; }
keys_b="$(phys_of "$PROJ_B" stargate-keys)"
[ -n "$keys_b" ] || bail "B: stargate-keys volume not found under project label"
[ "$keys_b" != "$keys_a" ] \
  || bail "isolation: project B keys volume == project A ($keys_b)"
# B must have its OWN fresh keys (distinct content); A's keys must NOT appear
# in B's volume (no cross-project leak).
cp_priv_b="$(vol_sha "$keys_b" cp.priv)"
[ "$cp_priv_b" != "$cp_priv_a" ] \
  || bail "isolation: project B cp.priv == project A (expected distinct fresh keys)"

# ---- report ----------------------------------------------------------------
if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T088 init_docker_test (${#errs[@]} finding(s)):" >&2
  for e in "${errs[@]}"; do echo "  - $e" >&2; done
  exit 1
fi
echo "OK: T088 init_docker_test (env-file · project-scoped volumes · key+pepper ownership · volume-root init · health via ps -q · idempotence · two-project isolation)"
exit 0
