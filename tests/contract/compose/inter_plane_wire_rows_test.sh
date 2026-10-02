#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# inter_plane_wire_rows_test.sh: hermetic fixtures for the decision rules of
# the RUNTIME rows in inter_plane_wire_test.sh (T196 Acceptance 1).
#
# Why: the runtime rows were lifted by T045 but never ran against a live stack
# until the T155 pass, which found that R2/R3 opened Unix sockets with bash
# `exec 3<>`, which always fails with ENXIO (R2 could never pass and R3 could
# never fail), that R5 read wireprobe's exit 0 ("the bad major was rejected") as
# "accepted", that R7 read the host-network DP's /proc/<pid>/net and blamed the DP
# for every host listener, and that every row printed PASS after a finding. A
# live run alone cannot show that a row's verdict can fail, so these fixtures run
# the REAL gate script, black-box, against a stub `docker` with discriminating
# negative controls.
#
# Mechanics: the gate runs from a symlink farm of the repository (so its build
# placeholder lands in a private target/), with stub `docker` and `git` first on
# PATH. The stub executes each `docker run` command LOCALLY, rewriting
# /run/stargate to a fixture directory: in-group UIDs (5101/5102/0) see
# ingroup/, any other UID sees outgroup/. The fixture sets each directory's
# socket modes to model what the kernel tells that caller (0660 connects, 0000
# is EACCES, 0666 is a world-dialable socket). The dialer program itself is the
# gate's, unmodified; only its container is emulated. wireprobe verdicts come
# from a per-scenario exit-code table, and `docker inspect` returns the pid of a
# fixture "DP" process whose TCP listeners the fixture controls, beside a
# foreign listener in the same network namespace that R7 must not attribute.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
GATE="$REPO_ROOT/tests/contract/compose/inter_plane_wire_test.sh"
for tool in python3 perl jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL: $tool is required by the wire-row fixtures" >&2; exit 1; }
done
if [ "$(id -u)" -eq 0 ]; then
  # Root bypasses the file-mode checks the EACCES fixtures depend on.
  echo "FAIL: run inter_plane_wire_rows_test.sh as an unprivileged user" >&2
  exit 1
fi

FX="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; done
  rm -rf "$FX"
}
trap cleanup EXIT

errs=()
bail() { errs+=("$*"); }

# --- symlink farm: real sources, private target/ -----------------------------
mkdir -p "$FX/root/target" "$FX/bin" "$FX/ingroup" "$FX/outgroup"
for entry in "$REPO_ROOT"/* "$REPO_ROOT"/.[!.]*; do
  name="$(basename "$entry")"
  case "$name" in target|.git|'.[!.]*') continue ;; esac
  ln -s "$entry" "$FX/root/$name"
done

cat > "$FX/compose.json" <<'EOF'
{"volumes": {"stargate-ipc": {"name": "fx_stargate-ipc"}, "stargate-keys": {"name": "fx_stargate-keys"}},
 "services": {"stargate-control": {"volumes": [{"source": "stargate-keys", "target": "/etc/stargate/keys"}]},
              "stargate-dp": {"volumes": [{"source": "stargate-keys", "target": "/etc/stargate/keys"}]}}}
EOF

cat > "$FX/bin/git" <<EOF
#!/usr/bin/env bash
if [ "\$*" = "rev-parse --show-toplevel" ]; then echo "$FX/root"; exit 0; fi
exec "$(command -v git)" "\$@"
EOF

cat > "$FX/bin/docker" <<'EOF'
#!/usr/bin/env bash
# Stub Docker for the wire-row fixtures. Unknown shapes fail loudly (97) so a
# gate change cannot silently stop exercising the fixtures.
set -uo pipefail
case "${1:-}" in
  compose)
    shift
    while [ $# -gt 0 ]; do case "$1" in -f|--env-file|-p) shift 2 ;; *) break ;; esac; done
    case "$*" in
      "config --format json") cat "$WIRE_FX/compose.json" ;;
      "ps --status running --services") printf 'stargate-dp\nstargate-control\n' ;;
      "ps -q stargate-dp") echo fxdpcid ;;
      *) echo "stub docker: unhandled compose $*" >&2; exit 97 ;;
    esac ;;
  inspect)
    [ "$*" = "inspect -f {{.State.Pid}} fxdpcid" ] || { echo "stub docker: unhandled $*" >&2; exit 97; }
    cat "$WIRE_FX/dp.pid" ;;
  run)
    shift
    user=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --rm) shift ;;
        --user|-v|-w|--network) [ "$1" = "--user" ] && user="$2"; shift 2 ;;
        *) break ;;
      esac
    done
    shift # image
    case "$user" in 5101:*|5102:*|0:*|"") ipc="$WIRE_FX/ingroup" ;; *) ipc="$WIRE_FX/outgroup" ;; esac
    args=()
    for a in "$@"; do a="${a//\/run\/stargate/$ipc}"; a="${a//\/src\//$PWD/}"; args+=("$a"); done
    case "${args[0]}" in
      stat)
        case "${args[-1]}" in
          */dp.sock) echo "660 5102 5100" ;;
          */control.sock) echo "660 5101 5100" ;;
          *) exit 97 ;;
        esac ;;
      go)
        out=""
        for ((i = 0; i < ${#args[@]}; i++)); do [ "${args[$i]}" = "-o" ] && out="${args[$((i + 1))]}"; done
        [ -n "$out" ] || exit 97
        printf '#!/bin/sh\nexit 97\n' > "$out" ;;
      */stargate-wireprobe)
        key="${args[1]}"
        for ((i = 2; i < ${#args[@]}; i++)); do
          case "${args[$i]}" in -major|-minor) key="$key:${args[$((i + 1))]}" ;; esac
        done
        code="$(awk -v k="$key" '$1 == k { print $2 }' "$WIRE_FX/probe.table")"
        exit "${code:-0}" ;;
      *) exec "${args[@]}" ;;
    esac ;;
  *) echo "stub docker: unhandled $*" >&2; exit 97 ;;
esac
EOF
chmod 0755 "$FX/bin/git" "$FX/bin/docker"

# --- fixture processes -----------------------------------------------------
# Unix listeners: connect(2) completes against the backlog without accept().
# A path in $SATURATE_FX gets a zero backlog that one held connection fills,
# so a further blocking connect(2) never completes (a wedged peer).
start_uds() {
  SATURATE_FX="${SATURATE_FX:-}" python3 -c '
import os, socket, sys, time
held = []
saturate = os.environ["SATURATE_FX"].split()
for path in sys.argv[1:]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.listen(0 if path in saturate else 16)
    held.append(s)
    if path in saturate:
        filler = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        filler.connect(path)
        held.append(filler)
print("READY", flush=True)
time.sleep(3600)
' "$@" > "$FX/uds.ready" &
  PIDS+=("$!")
}
# TCP listeners on ephemeral loopback ports; prints the ports it holds.
start_tcp() { # start_tcp <count> <portfile>
  python3 -c '
import socket, sys, time
held = []
for _ in range(int(sys.argv[1])):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(4)
    held.append(s)
print(" ".join(str(s.getsockname()[1]) for s in held), flush=True)
time.sleep(3600)
' "$1" > "$2" &
  PIDS+=("$!")
  LAST_PID="$!"
}
await_file() { # await_file <file>
  local i=0
  while [ ! -s "$1" ] && [ "$i" -lt 100 ]; do sleep 0.05; i=$((i + 1)); done
  [ -s "$1" ] || { echo "FAIL: fixture process did not start ($1)" >&2; exit 1; }
}
stop_all() {
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; done
  PIDS=()
  rm -f "$FX"/ingroup/*.sock "$FX"/outgroup/*.sock "$FX"/*.ready "$FX"/*.ports "$FX/dp.pid"
}

# setup <outgroup-mode|missing> <ingroup-control-mode> <dp-listener-count> <probe-table>
setup() {
  stop_all
  start_uds "$FX/ingroup/dp.sock" "$FX/ingroup/control.sock" "$FX/outgroup/dp.sock" "$FX/outgroup/control.sock"
  await_file "$FX/uds.ready"
  chmod 0660 "$FX/ingroup/dp.sock"
  chmod "$2" "$FX/ingroup/control.sock"
  if [ "$1" = missing ]; then
    rm -f "$FX/outgroup/dp.sock"
    chmod 0000 "$FX/outgroup/control.sock"
  else
    chmod "$1" "$FX/outgroup/dp.sock" "$FX/outgroup/control.sock"
  fi
  start_tcp 1 "$FX/foreign.ports"   # another process's listener in this namespace
  await_file "$FX/foreign.ports"
  start_tcp "$3" "$FX/dp.ports"
  DP_PID="$LAST_PID"
  if [ "$3" -gt 0 ]; then await_file "$FX/dp.ports"; else sleep 0.3; fi
  echo "$DP_PID" > "$FX/dp.pid"
  # The "proxy port" is the DP fixture's first listener (8881 may be in use here).
  PROXY_PORT_FX="$(cut -d' ' -f1 "$FX/dp.ports" 2>/dev/null)"
  printf '%s\n' "$4" | tr ',' '\n' | sed 's/=/ /' > "$FX/probe.table"
}

run_gate() { # run_gate <label>; a hung gate (exit 124) fails the scenario
  GATE_OUT="$(cd "$FX/root" && PATH="$FX/bin:$PATH" WIRE_FX="$FX" \
    STARGATE_WIRE_PROXY_PORT="${PROXY_PORT_FX:-1}" timeout 180 bash "$GATE" 2>&1)"
  GATE_RC=$?
  printf '%s\n' "$GATE_OUT" > "$FX/$1.log"
}
expect_rc() { [ "$GATE_RC" -eq "$2" ] || bail "[$1] gate exit $GATE_RC, want $2"; }
# Here-strings, not `printf | grep -q`: under pipefail an early grep exit can
# SIGPIPE the writer and flip the verdict.
expect_line() { grep -qE "$2" <<< "$GATE_OUT" || bail "[$1] missing /$2/ in gate output"; }
expect_no_line() { ! grep -qE "$2" <<< "$GATE_OUT" || bail "[$1] unexpected /$2/ in gate output"; }
show_on_failure() { [ "${#errs[@]}" -eq "$2" ] || { echo "--- [$1] gate output ---" >&2; cat "$FX/$1.log" >&2; }; }

# --- S1 positive control: every runtime row must be able to PASS -----------
n="${#errs[@]}"
setup 0000 0660 1 ""
run_gate s1
expect_rc s1 0
for row in R1 R2 R3 R4 R5 R6 R7; do
  expect_line s1 "^$row: PASS"
  expect_no_line s1 "^$row: FAIL"
done
expect_line s1 '^R8: SKIP'
expect_line s1 '^R9: SKIP'
foreign="$(cat "$FX/foreign.ports")"
expect_no_line s1 "R7: .*\\b$foreign\\b"
show_on_failure s1 "$n"

# --- S2 R3 negative control: a world-dialable socket must fail R3 ----------
n="${#errs[@]}"
setup 0666 0660 1 ""
run_gate s2
expect_rc s2 1
expect_line s2 '^R3: FAIL'
expect_no_line s2 '^R3: PASS'
expect_line s2 '^R2: PASS'
show_on_failure s2 "$n"

# --- S3 R3: a refusal that is not EACCES (missing socket) is not a PASS ----
n="${#errs[@]}"
setup missing 0660 1 ""
run_gate s3
expect_rc s3 1
expect_line s3 '^R3: FAIL'
expect_no_line s3 '^R3: PASS'
show_on_failure s3 "$n"

# --- S4 R2 negative control: the peer UID cannot dial its socket ----------
n="${#errs[@]}"
setup 0000 0000 1 ""
run_gate s4
expect_rc s4 1
expect_line s4 '^R2: FAIL'
expect_no_line s4 '^R2: PASS'
show_on_failure s4 "$n"

# --- S5 R5: wireprobe exit 0 means the rule held; non-zero must fail -------
for table in "major:2=1" "major:0=1" "major:1=1" "nomajor=1"; do
  label="s5-${table%%=*}"
  label="${label//:/-}"
  n="${#errs[@]}"
  setup 0000 0660 1 "$table"
  run_gate "$label"
  expect_rc "$label" 1
  expect_line "$label" '^R5: FAIL'
  expect_no_line "$label" '^R5: PASS'
  expect_line "$label" '^R6: PASS'
  show_on_failure "$label" "$n"
done

# --- S6 R7: a second DP listener must fail; the foreign one never counts ---
n="${#errs[@]}"
setup 0000 0660 2 ""
run_gate s6
expect_rc s6 1
expect_line s6 '^R7: FAIL'
expect_no_line s6 '^R7: PASS'
second="$(cut -d' ' -f2 "$FX/dp.ports")"
expect_line s6 "R7: .*\\b$second\\b"
show_on_failure s6 "$n"

# --- S7 R7: a DP with no TCP listener is a sanity failure, not a PASS ------
n="${#errs[@]}"
setup 0000 0660 0 ""
run_gate s7
expect_rc s7 1
expect_line s7 '^R7: FAIL'
expect_no_line s7 '^R7: PASS'
show_on_failure s7 "$n"

# --- S8 R2: a wedged peer (full accept queue) is a bounded FAIL, not a hang --
n="${#errs[@]}"
SATURATE_FX="$FX/ingroup/control.sock" setup 0000 0660 1 ""
run_gate s8
expect_rc s8 1
expect_line s8 '^R2: FAIL'
expect_no_line s8 '^R2: PASS'
expect_line s8 'R2: uid 5102 .*exit 124'
show_on_failure s8 "$n"

# --- S9 R3: a dial timeout never counts as EACCES ---------------------------
n="${#errs[@]}"
SATURATE_FX="$FX/outgroup/dp.sock $FX/outgroup/control.sock" setup 0666 0660 1 ""
run_gate s9
expect_rc s9 1
expect_line s9 '^R3: FAIL'
expect_no_line s9 '^R3: PASS'
expect_line s9 'R3: .*exit 124, not EACCES'
show_on_failure s9 "$n"

stop_all
if [ "${#errs[@]}" -gt 0 ]; then
  printf 'FAIL: inter_plane_wire_rows_test.sh: %d assertion(s) failed:\n' "${#errs[@]}" >&2
  for e in "${errs[@]}"; do printf '  - %s\n' "$e" >&2; done
  exit 1
fi
echo "PASS: inter_plane_wire_rows_test.sh: R2/R3 bounded real dialer, R5 exit semantics, R7 process attribution and per-row PASS discipline hold."
exit 0
