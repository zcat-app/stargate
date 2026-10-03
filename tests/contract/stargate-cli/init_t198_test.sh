#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T198 / Constitution III and V: `init` must refuse a host that cannot enforce
# the DP's abstract-socket boundary, and must print only facts it checked.
#
# The DP shares the host network namespace, and only the AppArmor `deny unix`
# rules in compose/apparmor/stargate-dp keep it from a host abstract-socket
# relay (the DP's Landlock ruleset and seccomp filter do not cover AF_UNIX
# connect). On a kernel without AppArmor af_unix mediation the parser still
# accepts the profile, but the unix allow becomes a generic network rule and
# both denies are dropped from the compiled policy.
#
# The hermetic legs run the REAL init entrypoint with only the external
# host/daemon commands stubbed: one fixture per refusal shape (feature file
# unreadable, not `yes`, a compile that drops the denies, and a comparison
# that errors or has no cmp) plus a positive control; the real status function; and the key-generation note for a fresh
# install and an observer-only upgrade. The parser leg runs init's own compile
# check against the installed apparmor_parser with a copy of this kernel's
# AppArmor features, unchanged (positive control) and with network/af_unix
# removed (the downgrade). Every leg runs and every failure is reported.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

init=scripts/subcommands/init
feature=/sys/kernel/security/apparmor/features/network/af_unix

# Resolve the real parser and cmp before PATH is narrowed to the stubs below.
real_parser="$(command -v apparmor_parser || true)"
real_cmp="$(command -v cmp)"

tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin"
export T198_LOG="$tmp/calls.log"
errors=()
fail() { errors+=("$*"); }

# docker: record every call and succeed. The key-volume count probes answer
# T198_KEYS / T198_OBSERVER; left empty they stop a passing run at key
# generation (exit 20), after the host boundary. With counts, the run stops at
# the observer build (no image ID, exit 30). Nothing reaches Compose up.
# shellcheck disable=SC2016 # the stubs expand their variables when init runs them
printf '%s\n' '#!/bin/sh' 'printf "docker %s\n" "$*" >> "$T198_LOG"' \
  'case "$*" in' \
  '  "volume inspect --format "*"_stargate-tor-health") printf "%s\n" "local|tmpfs|tmpfs|size=64k,uid=5103,gid=5103,mode=0700,noexec,nosuid,nodev" ;;' \
  '  *"for f in cp.priv"*) printf "%s\n" "${T198_KEYS:-}" ;;' \
  '  *"for f in observer.priv"*) printf "%s\n" "${T198_OBSERVER:-}" ;;' \
  'esac' 'exit 0' > "$tmp/bin/docker"
# Presence-only stand-ins: init runs the firewall tools through sudo.
for tool in iptables ip6tables; do
  printf '#!/bin/sh\nexit 97\n' > "$tmp/bin/$tool"
done
# cmp: T198_CMP forces an exit status (2 = comparison error, 127 = the shell's
# command-not-found status); otherwise the real cmp runs.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' '[ -n "${T198_CMP:-}" ] && exit "$T198_CMP"' "exec $real_cmp \"\$@\"" > "$tmp/bin/cmp"
# Presence-only stand-in: init runs the parser through sudo.
printf '#!/bin/sh\nexit 97\n' > "$tmp/bin/apparmor_parser"
# sudo: the fixture selects the af_unix feature file and the compile result
# (-Q ... -S <file>): the clean fixture emits a content-dependent policy, the
# downgrade fixture the same policy with or without the deny-unix lines, as
# the real parser does without af_unix. The firewall answers describe a
# correctly installed owner-rule set, so the only variable in each leg is
# AppArmor unix mediation.
# shellcheck disable=SC2016
printf '%s\n' '#!/bin/sh' \
  '[ "$1" = -n ] && shift' \
  '[ "$1" = -- ] && shift' \
  'printf "sudo %s\n" "$*" >> "$T198_LOG"' \
  'case "$1" in' \
  '  cat)' \
  '    [ "$2" = '"$feature"' ] || exit 98' \
  '    case "$T198_FEATURE" in' \
  '      absent) echo "cat: $2: No such file or directory" >&2; exit 1 ;;' \
  '      *) printf "%s\n" "$T198_FEATURE"; exit 0 ;;' \
  '    esac ;;' \
  '  apparmor_parser)' \
  '    [ "$2" = -Q ] || exit 0' \
  '    for arg; do file="$arg"; done' \
  '    case "$T198_PARSER" in' \
  '      downgrade) echo "policy without unix denies" ;;' \
  '      *) cksum < "$file" ;;' \
  '    esac' \
  '    exit 0 ;;' \
  '  grep) exit 0 ;;' \
  'esac' \
  'case "$2 $3 $4" in' \
  '  "-w -C OUTPUT") exit 1 ;; # nothing stale to delete before the insert' \
  'esac' \
  'case "$2 $3" in' \
  '  "-w -S")' \
  '    case "$4" in' \
  '      OUTPUT) printf "%s\n" "-P OUTPUT ACCEPT" "-A OUTPUT -m owner --uid-owner 5102 -j STARGATE_DP_OUT" ;;' \
  '      STARGATE_DP_OUT) printf "%s\n" "-N STARGATE_DP_OUT" "-A STARGATE_DP_OUT -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" "-A STARGATE_DP_OUT -j DROP" ;;' \
  '    esac ;;' \
  'esac' \
  'exit 0' > "$tmp/bin/sudo"
chmod +x "$tmp/bin/"*

run_init() { # run_init <feature-content|absent> <clean|downgrade> <output-file>
  : > "$T198_LOG"
  if T198_FEATURE="$1" T198_PARSER="$2" \
    STARGATE_PROJECT="t198-hermetic-$$" \
    STARGATE_COMPOSE_FILE="$PWD/compose/docker-compose.local.yml" \
    STARGATE_ENV_DIR="$tmp" STARGATE_ENV_FILE="$tmp/local.env" \
    PATH="$tmp/bin:$PATH" bash "$init" >"$3" 2>&1; then
    rc=0
  else
    rc=$?
  fi
}

refuses() { # refuses <label> <feature-content|absent> <clean|downgrade> <reason>
  run_init "$2" "$3" "$tmp/$1.out"
  grep -qF "$4" "$tmp/$1.out" || fail "$1: refusal does not say '$4'"
  [ "$rc" -eq 60 ] || { fail "$1: init returned $rc, want 60: $(head -c 300 "$tmp/$1.out")"; return; }
  grep -q ' stop stargate-dp' "$T198_LOG" || fail "$1: running DP was not stopped first"
  if grep -Eq '^docker .* (up|image|run|volume|build)( |$)' "$T198_LOG"; then
    fail "$1: init went past the host boundary"
  fi
  if grep -q '^sudo apparmor_parser -T -r ' "$T198_LOG"; then
    fail "$1: profile loaded although its unix denies cannot be enforced"
  fi
  grep -q 'af_unix' "$tmp/$1.out" || fail "$1: refusal does not name AppArmor af_unix mediation"
}

# Acceptance 1 fixtures: feature file absent, present but not `yes`, and a
# profile whose compiled policy is unchanged by its unix denies.
refuses feature-absent absent clean "cannot read $feature"
refuses feature-no no clean "is not 'yes'"
refuses feature-empty '' clean "is not 'yes'"
refuses load-downgrades yes downgrade 'drops the DP profile'"'"'s af_unix deny rules'
# Round-2 REWORK (Astra Major): only a completed comparison that found a
# difference may pass. A comparison error or a missing cmp refuses.
T198_CMP=2 refuses cmp-error yes clean 'cannot compile and compare'
T198_CMP=127 refuses cmp-missing yes clean 'cannot compile and compare'

# Positive control: mediation present and denies that change the compiled
# policy pass the host boundary (the stub stops the run later, at keygen).
run_init yes clean "$tmp/positive.out"
if [ "$rc" -eq 60 ]; then
  fail "positive control refused at the host boundary: $(head -c 300 "$tmp/positive.out")"
fi
grep -q "^sudo cat $feature\$" "$T198_LOG" || fail 'positive control never read the af_unix feature'
grep -q '^sudo apparmor_parser -Q ' "$T198_LOG" || fail 'positive control never compiled the profile'
grep -q '^sudo apparmor_parser -T -r ' "$T198_LOG" || fail 'positive control never loaded the profile'
grep -q '^docker image inspect' "$T198_LOG" || fail 'positive control did not pass the host boundary'

# T198 (F1, folded): the key-generation note must say what happened. A fresh
# install (no keys, no observer identity) generates the CP/DP keys and the
# pepper; only the pre-observer upgrade (five inter-plane files) keeps them.
keygen_note() { # keygen_note <label> <keys-count> <observer-count>
  T198_KEYS="$2" T198_OBSERVER="$3" run_init yes clean "$tmp/$1.out"
  [ "$rc" -eq 30 ] || fail "$1: init returned $rc, want 30 (past key generation): $(head -c 300 "$tmp/$1.out")"
}
keygen_note keygen-fresh 0 0
if grep -q 'without replacing existing' "$tmp/keygen-fresh.out"; then
  fail 'keygen-fresh: fresh install claims it kept existing CP/DP keys or pepper'
fi
grep -q 'generated new CP/DP keys, pepper and observer identity' "$tmp/keygen-fresh.out" ||
  fail 'keygen-fresh: no note that CP/DP keys, pepper and observer identity were generated'
keygen_note keygen-upgrade 5 0
grep -q 'provisioned observer identity without replacing existing CP/DP keys or pepper' "$tmp/keygen-upgrade.out" ||
  fail 'keygen-upgrade: no note that existing CP/DP keys and pepper were kept'
if grep -q 'generated new CP/DP keys' "$tmp/keygen-upgrade.out"; then
  fail 'keygen-upgrade: upgrade claims it generated new CP/DP keys'
fi

# Acceptance 2: run the installer's real status function. Every state must be
# one this run observed, and the control plane (network_mode: none) reports
# no network bind.
sed -n '/^print_status() {/,/^}/p' "$init" > "$tmp/status.sh"
if [ -s "$tmp/status.sh" ]; then
  table="$(
    # shellcheck disable=SC1091
    . "$tmp/status.sh"
    # shellcheck disable=SC2034 # read by the sourced print_status
    STARGATE_PROJECT=t198 VERIFIED_TOR_PORT=8881
    # shellcheck disable=SC2317 # called by the sourced print_status
    compose_health_ids() { echo "cid-$1"; }
    # shellcheck disable=SC2317
    docker() { [ "$*" = 'inspect -f {{.HostConfig.NetworkMode}} cid-stargate-control' ] && echo none; }
    print_status
  )"
  if grep -q 'HEALTHY' <<< "$table"; then
    fail 'status table claims HEALTHY; init checks no such state'
  fi
  cp_row="$(grep -E '^ +control plane ' <<< "$table" || true)"
  read -r _ _ cp_state cp_bind _ <<< "${cp_row:-x x}"
  [ "${cp_state:-}" = RUNNING ] || fail "control plane state '${cp_state:-}', want RUNNING"
  [ "${cp_bind:-}" = none ] || fail "control plane bind '${cp_bind:-}', want none"
  if grep -q '127\.0\.0\.1' <<< "$cp_row"; then fail 'control plane row claims a loopback bind'; fi
  grep -Eq '^ +data plane +RUNNING +127\.0\.0\.1 .*127\.0\.0\.1:8881' <<< "$table" ||
    fail 'data plane row does not report the observed loopback connect'
  grep -Eq '^ +Tor observer +READY ' <<< "$table" || fail 'observer READY row missing'
else
  fail 'print_status not found'
fi

# Parser leg: init's own compile check against the installed parser.
parser_leg=skipped
if [ -n "$real_parser" ] && [ -r "$feature" ]; then
  parser_leg=ran
  sed -n '/^unix_denies_compiled() {/,/^}/p' "$init" > "$tmp/compiled.sh"
  if [ -s "$tmp/compiled.sh" ]; then
    # shellcheck disable=SC2317 # called by the sourced unix_denies_compiled
    host_root() { "$@"; } # the compile needs no privilege here
    # shellcheck disable=SC1091
    . "$tmp/compiled.sh"
    cp -r /sys/kernel/security/apparmor/features "$tmp/live"
    cp -r "$tmp/live" "$tmp/no-af-unix"
    rm -f "$tmp/no-af-unix/network/af_unix"
    mkdir -p "$tmp/real"
    # -M sets both compile and kernel features to the given copy.
    # shellcheck disable=SC2016
    printf '%s\n' '#!/bin/sh' 'exec "$T198_REAL_PARSER" -M "$T198_FEATURES" "$@"' > "$tmp/real/apparmor_parser"
    chmod +x "$tmp/real/apparmor_parser"
    export T198_REAL_PARSER="$real_parser"
    compiled_with() { # compiled_with <features-copy>
      PATH="$tmp/real:$PATH" T198_FEATURES="$1" unix_denies_compiled compose/apparmor/stargate-dp
    }
    compiled_with "$tmp/live" ||
      fail 'unix denies do not change the compiled policy on this kernel (positive control)'
    if compiled_with "$tmp/no-af-unix"; then
      fail 'compile check accepted features without af_unix mediation'
    fi
  else
    fail 'unix_denies_compiled not found'
  fi
fi

if (( ${#errors[@]} > 0 )); then
  printf 'FAIL: %d T198 init assertion(s) failed:\n' "${#errors[@]}" >&2
  printf '  - %s\n' "${errors[@]}" >&2
  exit 1
fi
if [ "$parser_leg" = skipped ]; then
  echo 'OK: T198 af_unix gate fixtures, key-generation notes and observed-only status table'
  echo 'SKIP: T198 real apparmor_parser leg (needs apparmor_parser and AppArmor af_unix features)'
  exit 0
fi
echo 'OK: T198 af_unix gate fixtures, key-generation notes, observed-only status table and real parser compile check'
