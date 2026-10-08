#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# Single-gate reviewer regression for T142; deterministic CLI stand-ins, no
# provider calls. One launcher invocation runs both reviewers (OpenCode GLM
# and Codex Astra) over the same pass; there is no second phase.

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
RUNNER="$REPO_ROOT/scripts/review-task.sh"
MATRIX="$REPO_ROOT/scripts/review-matrix.json"
SANDBOX="$(mktemp -d -t stargate-t142-XXXXXX)"
declare -a OWNED_SUPERVISOR_ROWS=()
OWNER_RECEIPT_DIR=""
HANDOFF_ACTIVE=0
CLEANUP_IN_PROGRESS=0
PENDING_EXIT_STATUS=0
LAUNCH_UNCERTAIN=0
LAUNCH_PENDING_CASE=""
LAUNCH_PENDING_CONTROL=""
LAUNCH_PENDING_LOG=""
LAUNCH_PENDING_PID=""
LAUNCH_PENDING_START=""
LAUNCH_CAPTURE_ERROR=""
T211_S14_LATE_ONLY=0
[ "${1:-}" = "--t211-s14-late-only" ] && T211_S14_LATE_ONLY=1
T211_REWORK_PROBE=0
[ "${1:-}" = "--t211-rework-probe" ] && { T211_REWORK_PROBE=1; T211_S14_LATE_ONLY=1; }
T211_FAILED_RECEIPT_ONLY=0
[ "${1:-}" = "--t211-failed-receipt-only" ] && { T211_FAILED_RECEIPT_ONLY=1; T211_S14_LATE_ONLY=1; }
T211_HANDOFF_ONLY=""
case "${1:-}" in
  --t211-handoff-driver-only) T211_HANDOFF_ONLY=driver; T211_S14_LATE_ONLY=1 ;;
  --t211-handoff-foreign-only) T211_HANDOFF_ONLY=foreign; T211_S14_LATE_ONLY=1 ;;
  --t211-handoff-owner-only) T211_HANDOFF_ONLY=owner; T211_S14_LATE_ONLY=1; export STARGATE_T211_HOLD_OWNER_READY=1 ;;
esac

# Linux process observations are scoped by the fixture-created session root and
# bind every signal to the recorded start time. This controller is an
# independent test observer; it never uses process names or a host-wide pgrep.
PROC_CONTROL="$SANDBOX/proc-control.py"
cat > "$PROC_CONTROL" <<'PY'
import json, os, signal, sys, time

def read(pid):
    try:
        text = open(f"/proc/{pid}/stat").read()
        tail = text[text.rfind(")") + 2:].split()
        return {"pid": pid, "state": tail[0], "ppid": int(tail[1]),
                "pgid": int(tail[2]), "sid": int(tail[3]),
                "start": int(tail[19])}
    except (FileNotFoundError, ProcessLookupError):
        return None

def members(sid):
    found = []
    for entry in os.scandir("/proc"):
        if entry.name.isdigit():
            row = read(int(entry.name))
            if row and row["sid"] == sid:
                found.append(row)
    return sorted(found, key=lambda row: row["pid"])

mode, sid_text, root_text, start_text = sys.argv[1:]
sid, root, start = int(sid_text), int(root_text), int(start_text)
identity = read(root)
if identity and (identity["start"] != start or identity["sid"] != sid):
    raise SystemExit("owned session root identity mismatch; refusing signal")
if mode == "snapshot":
    rows = [row for row in members(sid) if not (row["pid"] == root and row["state"] == "Z")]
    print(json.dumps(rows, sort_keys=True))
else:
    raise SystemExit("unknown proc-control mode")
PY

OWNED_SUPERVISOR="$SANDBOX/owned-supervisor.py"
cat > "$OWNED_SUPERVISOR" <<'PY'
import ctypes, errno, json, os, pathlib, signal, subprocess, sys, time

PR_SET_CHILD_SUBREAPER = 36
libc = ctypes.CDLL(None, use_errno=True)

def proc(pid):
    try:
        raw = pathlib.Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return None
    tail = raw[raw.rfind(")") + 2:].split()
    return {"pid": pid, "state": tail[0], "ppid": int(tail[1]),
            "pgid": int(tail[2]), "sid": int(tail[3]),
            "start": int(tail[19])}

def rows():
    found = []
    for ent in os.scandir("/proc"):
        if ent.name.isdigit():
            row = proc(int(ent.name))
            if row:
                found.append(row)
    return found

def identity(pid, start):
    row = proc(pid)
    if row is None:
        print("gone")
        return 0
    if row["start"] != start:
        print(f"reused:{row['start']}")
        return 2
    print(row["state"])
    return 0

def signal_identity(pid, start, sig):
    before = proc(pid)
    if before is None:
        return "already-exited"
    if before["start"] != start:
        raise RuntimeError(f"PID identity changed: expected {start}, observed {before['start']}")
    try:
        fd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return "already-exited"
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return "already-exited"
        raise
    try:
        after = proc(pid)
        if after is None:
            return "already-exited"
        if (after["start"], after["pgid"], after["sid"]) != \
                (before["start"], before["pgid"], before["sid"]):
            raise RuntimeError(f"identity changed while opening pidfd: {before} -> {after}")
        try:
            signal.pidfd_send_signal(fd, sig)
            return "sent"
        except ProcessLookupError:
            return "already-exited"
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return "already-exited"
            raise
    finally:
        os.close(fd)

def atomic(path, value):
    path = pathlib.Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, sort_keys=True) + "\n")
    os.replace(tmp, path)

def bounded_direct_wait(child, seconds):
    try:
        return child.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        return None

def run(case, control, log, command):
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
    case, control = pathlib.Path(case), pathlib.Path(control)
    control.mkdir(parents=True, exist_ok=True)
    log_file = open(log, "ab", buffering=0)
    child = subprocess.Popen(command, cwd=case, start_new_session=True,
                             stdout=log_file, stderr=subprocess.STDOUT)
    first = proc(child.pid)
    if first is None:
        raise RuntimeError("owned child exited before identity capture")
    registry = {}
    signals = []
    waits = []
    termination_requested = False

    def request_termination(signum, frame):
        nonlocal termination_requested
        termination_requested = True

    signal.signal(signal.SIGTERM, request_termination)
    signal.signal(signal.SIGINT, request_termination)

    def pin(row):
        key = (row["pid"], row["start"])
        if key in registry:
            return True
        try:
            fd = os.pidfd_open(row["pid"], 0)
        except ProcessLookupError:
            return False
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                return False
            raise
        now = proc(row["pid"])
        if now is None:
            os.close(fd)
            return False
        if (now["start"], now["pgid"], now["sid"]) != \
                (row["start"], row["pgid"], row["sid"]):
            os.close(fd)
            raise RuntimeError(f"identity changed while pinning: {row} -> {now}")
        registry[key] = {"row": row, "fd": fd, "waited": False}
        return True

    pin(first)
    root_key = (child.pid, first["start"])
    atomic(control / "ready.json", {
        "pid": child.pid, "start": first["start"], "pgid": first["pgid"],
        "sid": first["sid"], "supervisor_pid": os.getpid(),
        "supervisor_start": proc(os.getpid())["start"],
        "control": str(control), "case_dir": str(case)})

    def scan():
        current = rows()
        by_pid = {row["pid"]: row for row in current}
        known = {}
        for (pid, start), rec in registry.items():
            row = by_pid.get(pid)
            if row and row["start"] == start:
                known[pid] = start
        root = by_pid.get(child.pid)
        if root and root["start"] == root_key[1]:
            if pin(root):
                known[child.pid] = root_key[1]
        changed = True
        while changed:
            changed = False
            for row in current:
                parent = by_pid.get(row["ppid"])
                adopted = row["ppid"] == os.getpid() and row["pid"] != os.getpid()
                inherited = row["ppid"] in known and parent and \
                    parent["start"] == known[row["ppid"]]
                if (adopted or inherited) and (row["pid"], row["start"]) not in registry:
                    if pin(row):
                        known[row["pid"]] = row["start"]
                        changed = True
        return current

    def reap():
        for (pid, start), rec in list(registry.items()):
            if (pid, start) == root_key or rec["waited"]:
                continue
            row = proc(pid)
            if row is None:
                try:
                    got, status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    waits.append({"pid": pid, "start": start, "result": "not-waitable-after-exit"})
                    rec["waited"] = True
                else:
                    if got == pid:
                        waits.append({"pid": pid, "start": start, "result": "waitpid", "status": status})
                        rec["waited"] = True
                continue
            if row["start"] != start or row["ppid"] != os.getpid() or row["state"] != "Z":
                continue
            try:
                got, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            if got == pid:
                waits.append({"pid": pid, "start": start, "result": "waitpid", "status": status})
                rec["waited"] = True

    def live():
        found = []
        for (pid, start), rec in registry.items():
            row = proc(pid)
            if row and row["start"] == start:
                found.append(row)
        return sorted(found, key=lambda r: r["pid"])

    def signal_all(sig, only_root=False, skip_root=False):
        current = {r["pid"]: r for r in rows()}
        def depth(pid):
            n, seen, row = 0, {pid}, current.get(pid)
            while row and row["ppid"] in current and row["ppid"] not in seen:
                parent = current[row["ppid"]]
                parent_key = next((key for key in registry if key[0] == parent["pid"]), None)
                if parent_key is None or parent["start"] != parent_key[1]:
                    break
                seen.add(parent["pid"])
                n += 1
                row = parent
            return n
        items = sorted(registry.items(), key=lambda item: depth(item[0][0]), reverse=True)
        for (pid, start), rec in items:
            if only_root and (pid, start) != root_key:
                continue
            if skip_root and (pid, start) == root_key:
                continue
            row = proc(pid)
            if row is None or row["start"] != start or row["state"] == "Z":
                result = "already-exited"
            else:
                try:
                    signal.pidfd_send_signal(rec["fd"], sig)
                    result = "sent"
                except ProcessLookupError:
                    result = "already-exited"
                except OSError as exc:
                    if exc.errno == errno.ESRCH:
                        result = "already-exited"
                    else:
                        raise
            original = rec["row"]
            signals.append({"pid": pid, "start": start, "pgid": original["pgid"],
                            "sid": original["sid"], "signal": sig, "result": result})

    def wait_clean(seconds):
        deadline = time.monotonic() + seconds
        while True:
            scan()
            reap()
            child.poll()
            if not live():
                return
            if time.monotonic() >= deadline:
                return
            time.sleep(0.025)

    def release():
        target = case / "target"
        if target.is_dir():
            (target / "abort-commit").touch()
            (target / "release-commit").touch()

    def clean_owned():
        # Failure/EXIT ordering is contractual: unblock the shim before TERM.
        release()
        scan()
        signal_all(signal.SIGTERM, only_root=True)
        time.sleep(0.05)
        scan()
        signal_all(signal.SIGTERM, skip_root=True)
        wait_clean(5)
        if live():
            scan()
            signal_all(signal.SIGKILL)
            wait_clean(5)
        scan()
        reap()
        child.poll()
        return live()

    cleanup_requested = False
    while True:
        scan()
        reap()
        req = control / "signal-driver.json"
        if req.exists():
            request = json.loads(req.read_text())
            if (request.get("pid"), request.get("start")) != root_key:
                raise RuntimeError("driver signal request identity mismatch")
            signal_all(signal.SIGTERM, only_root=True)
            result = signals[-1]["result"]
            atomic(control / "signal-driver-ack.json", {"request": request, "result": result})
            req.unlink()
        if (control / "cleanup.request").exists():
            (control / "cleanup.request").unlink()
            cleanup_requested = True
            remaining = clean_owned()
            break
        if termination_requested:
            cleanup_requested = True
            remaining = clean_owned()
            break
        if child.poll() is not None:
            wait_clean(0.5)
            if live():
                remaining = clean_owned()
                cleanup_requested = True
            else:
                remaining = []
            break
        time.sleep(0.025)

    # clean_owned() already spent the full TERM+KILL envelope. This final
    # nonblocking wait records an exited root without extending that bound.
    child_rc = bounded_direct_wait(child, 0)
    if child_rc is None:
        scan()
        reap()
        remaining = live()
        for rec in registry.values():
            os.close(rec["fd"])
        atomic(control / "reap.json", {
            "child_pid": child.pid, "child_start": root_key[1],
            "direct_wait": {"owner": "Popen.wait", "status": "timeout"},
            "child_exit": None, "cleanup_requested": cleanup_requested,
            "signals": signals, "waits": waits, "remaining": remaining})
        atomic(control / "done.json", {"child_exit": None, "remaining": remaining,
                                       "direct_wait": "timeout"})
        log_file.close()
        return 125
    scan()
    reap()
    remaining = live()
    for rec in registry.values():
        os.close(rec["fd"])
    receipt = {"child_pid": child.pid, "child_start": root_key[1],
               "direct_wait": {"owner": "Popen.wait", "status": child_rc},
               "child_exit": child_rc, "cleanup_requested": cleanup_requested,
               "signals": signals, "waits": waits, "remaining": remaining}
    atomic(control / "reap.json", receipt)
    atomic(control / "done.json", {"child_exit": child_rc, "remaining": remaining})
    log_file.close()
    if remaining:
        return 125
    return 128 - child_rc if child_rc < 0 else child_rc

if sys.argv[1] == "wait-bound-control":
    child = subprocess.Popen(["/bin/sleep", "30"])
    before = time.monotonic()
    result = bounded_direct_wait(child, 0.05)
    elapsed = time.monotonic() - before
    child.kill()
    child.wait(timeout=2)
    if result is not None or elapsed >= 1:
        raise SystemExit(f"bounded wait control failed: result={result}, elapsed={elapsed}")
    print(json.dumps({"result": "timeout", "elapsed": elapsed}))
    raise SystemExit(0)
if sys.argv[1] == "wait-bound-mutation-control":
    class BlockingWait:
        def wait(self, timeout=None):
            if timeout is None:
                time.sleep(30)
            raise subprocess.TimeoutExpired("blocking-wait-probe", timeout)
    result = bounded_direct_wait(BlockingWait(), 0.05)
    if result is not None:
        raise SystemExit(f"fake timeout control returned unexpectedly: {result}")
    print(json.dumps({"result": "bounded-timeout"}))
    raise SystemExit(0)
if sys.argv[1] == "fake-timeout-control":
    class BlockingWait:
        def wait(self, timeout=None):
            if timeout is None:
                time.sleep(30)
            raise subprocess.TimeoutExpired("blocking-wait-probe", timeout)
    result = bounded_direct_wait(BlockingWait(), 0.05)
    if result is not None:
        raise SystemExit(f"fake bounded control returned unexpectedly: {result}")
    print(json.dumps({"result": "bounded-timeout"}))
    raise SystemExit(0)
if sys.argv[1] == "identity":
    raise SystemExit(identity(int(sys.argv[2]), int(sys.argv[3])))
if sys.argv[1] == "start":
    row = proc(int(sys.argv[2]))
    if row is None:
        raise SystemExit("process vanished before start identity capture")
    print(row["start"])
    raise SystemExit(0)
if sys.argv[1] == "signal":
    sig = signal.SIGTERM if sys.argv[4] == "TERM" else signal.SIGKILL
    print(signal_identity(int(sys.argv[2]), int(sys.argv[3]), sig))
    raise SystemExit(0)
if sys.argv[1] == "run":
    marker = sys.argv.index("--", 5)
    raise SystemExit(run(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[marker + 1:]))
raise SystemExit("unknown owned supervisor operation")
PY

errs=()
bail() { errs+=("$*"); }

request_fixture_exit() {
  local requested=143
  [ "${1:-TERM}" = INT ] && requested=130
  if [ "$PENDING_EXIT_STATUS" -eq 0 ]; then PENDING_EXIT_STATUS=$requested; fi
  if [ "$HANDOFF_ACTIVE" -eq 1 ] || [ "$CLEANUP_IN_PROGRESS" -eq 1 ]; then return 0; fi
  exit "$PENDING_EXIT_STATUS"
}

wait_fixture_supervisor() {
  local label="$1" control="$2" pid="$3" start="$4" direct="${5:-yes}"
  local deadline state identity_rc wait_status=0 expected_wait cleanup_valid=1
  FIXTURE_SUPERVISOR_RC=125
  deadline=$((SECONDS + 12))
  while [ ! -s "$control/done.json" ] && [ "$SECONDS" -lt "$deadline" ]; do
    state="$(python3 "$OWNED_SUPERVISOR" identity "$pid" "$start" 2>&1)"; identity_rc=$?
    [ "$identity_rc" -eq 0 ] || { bail "$label: supervisor identity changed: $state"; return 1; }
    [ "$state" = gone ] || [ "$state" = Z ] || { sleep 0.05; continue; }
    break
  done
  if [ ! -s "$control/done.json" ]; then
    python3 "$OWNED_SUPERVISOR" signal "$pid" "$start" TERM >/dev/null 2>&1 ||
      bail "$label: PIDFD TERM of stuck supervisor failed"
    deadline=$((SECONDS + 5))
    while [ "$SECONDS" -lt "$deadline" ]; do
      state="$(python3 "$OWNED_SUPERVISOR" identity "$pid" "$start" 2>&1)"; identity_rc=$?
      [ "$identity_rc" -eq 0 ] || break
      [ "$state" = gone ] || [ "$state" = Z ] && break
      sleep 0.05
    done
    if [ "$state" != gone ] && [ "$state" != Z ]; then
      python3 "$OWNED_SUPERVISOR" signal "$pid" "$start" KILL >/dev/null 2>&1 ||
        bail "$label: PIDFD KILL of stuck supervisor failed"
      deadline=$((SECONDS + 5))
      while [ "$SECONDS" -lt "$deadline" ]; do
        state="$(python3 "$OWNED_SUPERVISOR" identity "$pid" "$start" 2>&1)"; identity_rc=$?
        [ "$identity_rc" -eq 0 ] || break
        [ "$state" = gone ] || [ "$state" = Z ] && break
        sleep 0.05
      done
    fi
    [ -s "$control/done.json" ] || { bail "$label: bounded supervisor cleanup produced no reap receipt"; return 1; }
  fi
  # done.json is written immediately before the supervisor returns. It is a
  # receipt, not proof that the process exited; establish exit before shell wait.
  deadline=$((SECONDS + 2))
  while [ "$SECONDS" -lt "$deadline" ]; do
    state="$(python3 "$OWNED_SUPERVISOR" identity "$pid" "$start" 2>&1)"; identity_rc=$?
    [ "$identity_rc" -eq 0 ] || { bail "$label: supervisor identity changed after done receipt: $state"; return 1; }
    [ "$state" = gone ] || [ "$state" = Z ] && break
    sleep 0.025
  done
  if [ "$state" != gone ] && [ "$state" != Z ]; then
    python3 "$OWNED_SUPERVISOR" signal "$pid" "$start" TERM >/dev/null 2>&1 ||
      bail "$label: PIDFD TERM failed after supervisor done receipt"
    deadline=$((SECONDS + 2))
    while [ "$SECONDS" -lt "$deadline" ]; do
      state="$(python3 "$OWNED_SUPERVISOR" identity "$pid" "$start" 2>&1)"; identity_rc=$?
      [ "$identity_rc" -eq 0 ] || break
      [ "$state" = gone ] || [ "$state" = Z ] && break
      sleep 0.025
    done
  fi
  if [ "$state" != gone ] && [ "$state" != Z ]; then
    python3 "$OWNED_SUPERVISOR" signal "$pid" "$start" KILL >/dev/null 2>&1 ||
      bail "$label: PIDFD KILL failed after supervisor done receipt"
    deadline=$((SECONDS + 2))
    while [ "$SECONDS" -lt "$deadline" ]; do
      state="$(python3 "$OWNED_SUPERVISOR" identity "$pid" "$start" 2>&1)"; identity_rc=$?
      [ "$identity_rc" -eq 0 ] || break
      [ "$state" = gone ] || [ "$state" = Z ] && break
      sleep 0.025
    done
  fi
  if [ "$state" != gone ] && [ "$state" != Z ]; then
    bail "$label: supervisor remained live after bounded TERM/KILL; refusing shell wait"
    return 1
  fi
  if [ "$direct" = yes ]; then
    wait "$pid"; wait_status=$?
    : > "$control/shell-reaped"
    if [ "${STARGATE_T211_INVALID_REAP_RECEIPT:-0}" = 1 ]; then
      python3 - "$control/reap.json" <<'INVALID_RECEIPT'
import json, sys
path=sys.argv[1]
row=json.load(open(path))
row["remaining"]=[{"pid": -1, "start": -1, "state": "synthetic-invalid-receipt"}]
with open(path, "w") as stream:
    json.dump(row, stream, sort_keys=True)
    stream.write("\n")
INVALID_RECEIPT
      python3 - "$STARGATE_T211_OBSERVER_DIR/failed-receipt-invalidated.json" \
        "$SANDBOX" "$control" "$wait_status" <<'INVALID_EVENT'
import json, os, sys, time
path, sandbox, control, wait_status = sys.argv[1:]
row = json.load(open(control + "/reap.json"))
tmp = path + ".tmp"
with open(tmp, "w") as stream:
    json.dump({"sandbox": sandbox, "control": control, "wait_status": int(wait_status),
               "receipt": row, "monotonic": time.monotonic()}, stream, sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(tmp, path)
INVALID_EVENT
    fi
  fi
  FIXTURE_SUPERVISOR_RC="$(python3 - "$control/done.json" <<'STATUS'
import json, sys
print(json.load(open(sys.argv[1]))["child_exit"])
STATUS
)"
  expected_wait="$(python3 - "$FIXTURE_SUPERVISOR_RC" <<'STATUS'
import sys
status=int(sys.argv[1]); print(128-status if status < 0 else status)
STATUS
)"
  python3 - "$control/done.json" <<'CLEAN'
import json, sys
row = json.load(open(sys.argv[1]))
raise SystemExit(bool(row.get("remaining")))
CLEAN
  local cleanup_rc=$?
  python3 - "$control/reap.json" <<'REAP'
import json, sys
row=json.load(open(sys.argv[1]))
if row.get("remaining") or row.get("direct_wait",{}).get("owner") != "Popen.wait":
    raise SystemExit("missing direct-child wait or zero-residue reap receipt")
REAP
  local reap_rc=$?
  if [ "${STARGATE_T211_INVALID_REAP_RECEIPT:-0}" = 1 ]; then
    python3 - "$STARGATE_T211_OBSERVER_DIR/failed-receipt-rejected.json" \
      "$control" "$SANDBOX" "$cleanup_rc" "$reap_rc" <<'REJECTED_EVENT'
import json, os, sys, time
path, control, sandbox, cleanup_rc, reap_rc = sys.argv[1:]
tmp = path + ".tmp"
with open(tmp, "w") as stream:
    json.dump({"shell_reaped": os.path.isfile(control + "/shell-reaped"),
               "cleanup_rc": int(cleanup_rc), "reap_rc": int(reap_rc),
               "sandbox_exists_before_exit_cleanup": os.path.isdir(sandbox),
               "monotonic": time.monotonic()}, stream, sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(tmp, path)
REJECTED_EVENT
  fi
  [ "$cleanup_rc" -eq 0 ] || bail "$label: supervisor reap receipt has owned residue"
  [ "$reap_rc" -eq 0 ] || bail "$label: supervisor omitted direct/adopted reap evidence"
  [ "$wait_status" -eq "$expected_wait" ] || [ "$direct" != yes ] || bail "$label: supervisor wait status $wait_status != expected $expected_wait"
  [ "$cleanup_rc" -eq 0 ] || cleanup_valid=0
  [ "$reap_rc" -eq 0 ] || cleanup_valid=0
  [ "$direct" != yes ] || [ "$wait_status" -eq "$expected_wait" ] || cleanup_valid=0
  if [ "$direct" = yes ] && [ "$cleanup_valid" -eq 1 ]; then
    : > "$control/cleanup-proved"
  else
    rm -f "$control/cleanup-proved"
  fi
  [ "$cleanup_valid" -eq 1 ]
}

wait_bound_nonvacuity_control() {
  local positive fake mutant rc case_dir control log
  case_dir="$SANDBOX/wait-bound-case"; control="$SANDBOX/wait-bound-control"; log="$SANDBOX/wait-bound.log"
  mkdir -p "$case_dir" "$control"
  start_owned_supervisor "$case_dir" "$control" "$log" none \
    python3 "$OWNED_SUPERVISOR" wait-bound-control || return 1
  wait_fixture_supervisor "wait-bound control" "$control" "$FIXTURE_SUPERVISOR_PID" \
    "$FIXTURE_SUPERVISOR_START" yes || bail "wait-bound control: owned real Popen wait failed"
  positive="$(cat "$log")"; rc=$?
  [ "$rc" -eq 0 ] && [[ "$positive" = *'"result": "timeout"'* ]] ||
    bail "wait-bound control: real Popen did not return through its timeout path: rc=$rc $positive"
  fake="$(python3 "$OWNED_SUPERVISOR" fake-timeout-control 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] && [[ "$fake" = *'"result": "bounded-timeout"'* ]] ||
    bail "wait-bound control: unmutated fake bounded-wait assertion failed: rc=$rc $fake"
  mutant="$SANDBOX/owned-supervisor-unbounded-mutant.py"
  python3 - "$OWNED_SUPERVISOR" "$mutant" <<'MUT'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
bounded = 'return child.wait(timeout=seconds)'
assert source.count(bounded) == 1
Path(sys.argv[2]).write_text(source.replace(bounded, 'return child.wait()', 1))
MUT
  timeout 1 python3 "$mutant" wait-bound-mutation-control >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 124 ] || bail "wait-bound mutation control: unconditional wait escaped the 1s observer (rc=$rc)"
  printf 'T211_CONTROL_PASS wait-bound real-Popen timeout and unbounded-wait mutation (mutation rc=%s)\n' "$rc"
}

request_fixture_signal() {
  local control="$1" pid="$2" start="$3" token="$$-$RANDOM" deadline
  python3 - "$control/signal-driver.json" "$token" "$pid" "$start" <<'REQUEST'
import json, os, sys
path, token, pid, start = sys.argv[1:]
tmp = path + ".tmp"
with open(tmp, "w") as stream:
    json.dump({"token": token, "pid": int(pid), "start": int(start)}, stream)
os.replace(tmp, path)
REQUEST
  deadline=$((SECONDS + 5))
  while [ ! -s "$control/signal-driver-ack.json" ] && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.025; done
  python3 - "$control/signal-driver-ack.json" "$token" "$pid" "$start" <<'ACK'
import json, sys
row = json.load(open(sys.argv[1]))
if row["request"].get("token") != sys.argv[2]:
    raise SystemExit("signal acknowledgement token mismatch")
if (row["request"].get("pid"), row["request"].get("start")) != (int(sys.argv[3]), int(sys.argv[4])):
    raise SystemExit("signal acknowledgement identity mismatch")
if row["result"] not in ("sent", "already-exited"):
    raise SystemExit("driver TERM was not acknowledged")
ACK
  local rc=$?
  [ "$rc" -eq 0 ] || bail "fixture driver TERM did not receive its PIDFD acknowledgement"
}

cleanup_owned_session() {
  local case_dir="$1" control="$2" supervisor="$3" supervisor_start="$4" direct="${5:-yes}"
  if [ -d "$case_dir/target" ]; then
    : > "$case_dir/target/abort-commit"
    : > "$case_dir/target/release-commit"
  fi
  : > "$control/cleanup.request"
  wait_fixture_supervisor "owned cleanup" "$control" "$supervisor" "$supervisor_start" "$direct"
}

cleanup() {
  local original_rc="${CLEANUP_ORIGINAL_RC:-0}" row case_dir control supervisor supervisor_start failures=0 metadata_path
  CLEANUP_IN_PROGRESS=1
  trap - EXIT
  if [ "$LAUNCH_UNCERTAIN" -eq 1 ]; then
    # Reconciliation is bounded. Failure leaves a pending descriptor and
    # forces sandbox retention while already registered rows are still drained.
    reconcile_pending_launch || :
  fi
  for row in "${OWNED_SUPERVISOR_ROWS[@]}"; do
    IFS=: read -r case_dir control supervisor supervisor_start <<< "$row"
    if [ -s "$control/owner-metadata-path" ]; then
      metadata_path="$(cat "$control/owner-metadata-path")"
      if [ -s "$metadata_path" ]; then
        case_dir="$(python3 - "$metadata_path" <<'OWNER_CASE'
import json, sys
print(json.load(open(sys.argv[1]))["case_dir"])
OWNER_CASE
)"
      else
        case_dir="$control/unresolved-owner-case"
      fi
    fi
    if [ -e "$control/shell-reaped" ]; then
      [ -e "$control/cleanup-proved" ] || failures=1
      continue
    fi
    cleanup_owned_session "$case_dir" "$control" "$supervisor" "$supervisor_start" yes || failures=1
    if [ -n "$OWNER_RECEIPT_DIR" ] && [ -s "$control/reap.json" ]; then
      cp "$control/reap.json" "$OWNER_RECEIPT_DIR/reap.json" || failures=1
    fi
    if [ -n "${STARGATE_T211_OUTER_PROBE_DIR:-}" ] && [ -s "$control/reap.json" ]; then
      cp "$control/reap.json" "$STARGATE_T211_OUTER_PROBE_DIR/reap-$supervisor.json" || failures=1
    fi
  done
  if [ "$LAUNCH_UNCERTAIN" -eq 1 ]; then
    if [ -n "$LAUNCH_PENDING_CONTROL" ] && [ -e "$LAUNCH_PENDING_CONTROL/cleanup-proved" ]; then
      LAUNCH_UNCERTAIN=0
      persist_pending_launch reconciled-and-reaped || failures=1
    else
      failures=1
      persist_pending_launch unresolved || :
    fi
  fi
  if [ -n "${STARGATE_T211_OUTER_PROBE_DIR:-}" ] && \
      [ -s "$STARGATE_T211_OUTER_PROBE_DIR/s13-term-request.json" ]; then
    python3 - "$STARGATE_T211_OUTER_PROBE_DIR/s13-term-request.json" \
      "$STARGATE_T211_OUTER_PROBE_DIR/s13-before-sandbox-delete.json" "$SANDBOX" "$$" <<'DELETE_ORDER'
import json, os, pathlib, sys, time
request_path, out, sandbox, outer_pid_text = sys.argv[1:]
outer_pid = int(outer_pid_text)
request = json.load(open(request_path))
if request["outer_pid"] != outer_pid or request["sandbox"] != sandbox:
    raise SystemExit(0)
raw = pathlib.Path(f"/proc/{outer_pid}/stat").read_text()
tail = raw[raw.rfind(")") + 2:].split()
outer_start = int(tail[19])
if request["outer_starttime"] != outer_start:
    raise SystemExit("outer fixture identity changed before deletion witness")
before_path = pathlib.Path(request["owned_before_term_path"])
before = json.load(open(before_path))
remaining = []
states = []
for item in before["processes"]:
    member_pid, member_start = int(item["pid"]), int(item["start"])
    try:
        raw = pathlib.Path(f"/proc/{member_pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        states.append({"pid": member_pid, "start": member_start, "state": "gone"})
        continue
    tail = raw[raw.rfind(")") + 2:].split()
    row = {"pid": member_pid, "start": int(tail[19]), "state": tail[0]}
    if row["start"] == member_start and row["state"] != "Z":
        remaining.append(row)
    elif row["start"] == member_start and row["state"] == "Z":
        remaining.append(row)
    states.append(row)
if request["term_monotonic"] > time.monotonic():
    raise SystemExit("deletion witness preceded the parent-issued TERM")
deleted_at = time.monotonic()
tmp = out + ".tmp"
with open(tmp, "w") as stream:
    json.dump({"stage": "before-sandbox-delete", "monotonic": deleted_at,
               "outer_pid": outer_pid, "outer_starttime": outer_start,
               "term_nonce": request["nonce"], "term_monotonic": request["term_monotonic"],
               "sandbox": sandbox,
               "sandbox_exists": os.path.isdir(sandbox), "target_tree": before["processes"],
               "states": states, "remaining": remaining}, stream, sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(tmp, out)
DELETE_ORDER
  fi
  if [ "$failures" -eq 0 ]; then
    rm -rf "$SANDBOX"
  else
    printf 'FAIL: owned cleanup uncertain; preserving sandbox %s\n' "$SANDBOX" >&2
  fi
  if [ "$original_rc" -ne 0 ]; then exit "$original_rc"; fi
  if [ "$PENDING_EXIT_STATUS" -ne 0 ]; then exit "$PENDING_EXIT_STATUS"; fi
  [ "$failures" -eq 0 ] || exit 1
  exit 0
}

trap 'CLEANUP_ORIGINAL_RC=$?; CLEANUP_IN_PROGRESS=1; cleanup' EXIT
trap 'request_fixture_exit INT' INT
trap 'request_fixture_exit TERM' TERM

t211_pause_before_registration() {
  local kind="$1" control="$2" ready_file="$3" i
  [ "${STARGATE_T211_HANDOFF_KIND:-}" = "$kind" ] || return 0
  [ -n "${STARGATE_T211_HANDOFF_PROBE_DIR:-}" ] || return 0
  for i in $(seq 1 200); do [ -s "$ready_file" ] && break; sleep 0.025; done
  [ -s "$ready_file" ] || { bail "T211 handoff probe: $kind supervisor did not publish readiness"; return 1; }
  python3 - "$STARGATE_T211_HANDOFF_PROBE_DIR/handoff-pending.json" "$ready_file" \
    "$control" "$SANDBOX" "$kind" "$$" "${STARGATE_T211_HANDOFF_TOKEN:-}" <<'HANDOFF_EVENT'
import json, os, pathlib, sys, time
path, ready_path, control, sandbox, kind, outer_pid, token = sys.argv[1:]
ready=json.load(open(ready_path))
if ready.get("control") != control or ready.get("case_dir") is None:
    raise SystemExit("handoff readiness identity does not match its control directory")
deadline=time.monotonic()+15
actual_hold=False
hold_details={}
if kind == "driver":
    target=pathlib.Path(ready["case_dir"])/"target"
    committing=target/"committing"
    while time.monotonic()<deadline and not committing.exists(): time.sleep(0.025)
    actual_hold=committing.exists() and not (target/"abort-commit").exists() and not (target/"release-commit").exists()
    hold_details={"committing":committing.exists(),"abort":(target/"abort-commit").exists(),"release":(target/"release-commit").exists()}
elif kind == "foreign":
    pid=int(ready["pid"]); start=int(ready["start"])
    while time.monotonic()<deadline:
        try:
            raw=pathlib.Path(f"/proc/{pid}/stat").read_text(); tail=raw[raw.rfind(")")+2:].split()
            cmd=pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0",b" ").decode(errors="replace")
            actual_hold=(int(tail[19])==start and tail[0]!="Z" and cmd.endswith("sleep 300 "))
            if actual_hold: break
        except (FileNotFoundError,ProcessLookupError): pass
        time.sleep(0.025)
    hold_details={"pid":pid,"start":start,"command":cmd if "cmd" in locals() else ""}
elif kind == "owner":
    metadata_path=pathlib.Path(control)/"owner-metadata-path"
    if not metadata_path.is_file(): raise SystemExit("nested owner metadata path was not prepared")
    owner_path=pathlib.Path(metadata_path.read_text().strip())
    owner_control=owner_path.parent
    while time.monotonic()<deadline and not owner_path.is_file(): time.sleep(0.025)
    if owner_path.is_file():
        owner=json.load(open(owner_path)); target=pathlib.Path(owner["case_dir"])/"target"
        committing=target/"committing"; not_ready=owner_control/"owner-not-ready"
        ready_marker=owner_control/"ready"
        while time.monotonic()<deadline and not not_ready.exists(): time.sleep(0.025)
        actual_hold=not_ready.exists() and not ready_marker.exists() and committing.exists()
        hold_details={"owner":owner,"owner_not_ready":not_ready.exists(),
                      "owner_ready":ready_marker.exists(),"committing":committing.exists()}
raw=pathlib.Path(f"/proc/{outer_pid}/stat").read_text()
tail=raw[raw.rfind(")")+2:].split()
row={"event":"supervisor-before-registration","kind":kind,
     "monotonic":time.monotonic(),"outer_pid":int(outer_pid),
     "outer_starttime":int(tail[19]),"sandbox":sandbox,
     "control":control,"ready":ready,"token":token,
     "actual_hold":actual_hold,"hold_details":hold_details}
tmp=path+".tmp"
with open(tmp,"w") as stream:
    json.dump(row,stream,sort_keys=True); stream.write("\n")
    stream.flush(); os.fsync(stream.fileno())
os.replace(tmp,path)
HANDOFF_EVENT
  [ "$?" -eq 0 ] || { bail "T211 handoff probe: failed to publish $kind readiness event"; return 1; }
  for i in $(seq 1 600); do
    [ -e "$STARGATE_T211_HANDOFF_PROBE_DIR/release-handoff" ] && return 0
    sleep 0.025
  done
  bail "T211 handoff probe: bounded parent release was not received for $kind"
  return 0
}

persist_pending_launch() {
  local phase="$1"
  [ -n "$LAUNCH_PENDING_CONTROL" ] || return 1
  timeout 1 python3 - "$LAUNCH_PENDING_CONTROL/launch-pending.json" "$phase" \
    "$LAUNCH_PENDING_CASE" "$LAUNCH_PENDING_CONTROL" "$LAUNCH_PENDING_LOG" \
    "$LAUNCH_PENDING_PID" "$LAUNCH_PENDING_START" "$PENDING_EXIT_STATUS" <<'PENDING_LAUNCH'
import json, os, pathlib, sys, time
path, phase, case_dir, control, log, pid, start, pending = sys.argv[1:]
row={"phase":phase,"case_dir":case_dir,"control":control,"log":log,
     "pid":int(pid) if pid else None,"start":int(start) if start else None,
     "pending_exit_status":int(pending),"monotonic":time.monotonic()}
tmp=path+".tmp"
with open(tmp,"w") as stream:
    json.dump(row,stream,sort_keys=True); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
os.replace(tmp,path)
PENDING_LAUNCH
}

ready_supervisor_start() {
  local ready="$1" expected_pid="$2" expected_case="$3" expected_control="$4"
  timeout 0.2 python3 - "$ready" "$expected_pid" "$expected_case" "$expected_control" <<'READY_IDENTITY'
import json, pathlib, sys
path, pid, case_dir, control = sys.argv[1:]
row=json.loads(pathlib.Path(path).read_text())
if int(row.get("supervisor_pid",-1)) != int(pid): raise SystemExit("ready supervisor PID mismatch")
if pathlib.Path(row.get("case_dir","")).resolve() != pathlib.Path(case_dir).resolve(): raise SystemExit("ready case directory mismatch")
if pathlib.Path(row.get("control","")).resolve() != pathlib.Path(control).resolve(): raise SystemExit("ready control directory mismatch")
start=int(row.get("supervisor_start",0))
child=int(row.get("pid",0)); child_start=int(row.get("start",0))
if start <= 0 or child <= 0 or child_start <= 0 or child == int(pid): raise SystemExit("ready identities are incomplete or invalid")
print(start)
READY_IDENTITY
}

ensure_pending_supervisor_row() {
  local pid="$1" case_dir="$2" control="$3" start="" ready_start="" state rc
  if [ -s "$control/ready.json" ]; then
    ready_start="$(ready_supervisor_start "$control/ready.json" "$pid" "$case_dir" "$control" 2>/dev/null)" || ready_start=""
  fi
  start="$(timeout 0.2 python3 "$OWNED_SUPERVISOR" start "$pid" 2>/dev/null)" || start=""
  [[ "$start" =~ ^[0-9]+$ ]] || start=""
  if [ -n "$ready_start" ]; then
    [ -z "$start" ] || [ "$start" = "$ready_start" ] || return 1
    start="$ready_start"
  fi
  [ -n "$start" ] || return 1
  state="$(timeout 0.2 python3 "$OWNED_SUPERVISOR" identity "$pid" "$start" 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] || return 1
  if [ "$state" = gone ] && [ -z "$ready_start" ]; then return 1; fi
  FIXTURE_SUPERVISOR_PID="$pid" FIXTURE_SUPERVISOR_START="$start"
  FIXTURE_CONTROL_DIR="$control"
  local row found=0
  for row in "${OWNED_SUPERVISOR_ROWS[@]}"; do
    if [[ "$row" == *":$control:$pid:$start" ]]; then found=1; break; fi
  done
  [ "$found" -eq 1 ] || OWNED_SUPERVISOR_ROWS+=("$case_dir:$control:$pid:$start")
  LAUNCH_PENDING_START="$start"
  return 0
}

reconcile_pending_launch() {
  local i ready_start="" pid="$LAUNCH_PENDING_PID" case_dir="$LAUNCH_PENDING_CASE" \
    control="$LAUNCH_PENDING_CONTROL" state rc
  [ -n "$pid" ] && [ -n "$control" ] && [ -n "$case_dir" ] || return 1
  for i in $(seq 1 10); do
    if [ -s "$control/ready.json" ]; then
      ready_start="$(ready_supervisor_start "$control/ready.json" "$pid" "$case_dir" "$control" 2>/dev/null)" || ready_start=""
      [ -n "$ready_start" ] && break
    fi
    sleep 0.025
  done
  if ! ensure_pending_supervisor_row "$pid" "$case_dir" "$control"; then
    persist_pending_launch unresolved || :
    return 1
  fi
  if [ -z "$ready_start" ]; then
    persist_pending_launch supervisor-identity-only || :
    return 1
  fi
  # The known supervisor can receive its unique cleanup request, but the
  # uncertainty remains until the existing reap validator proves the subtree.
  persist_pending_launch reconciled-ready || :
  return 0
}

start_owned_supervisor() {
  local case_dir="$1" control="$2" log="$3" role="$4" identity_file start="" ready_start="" i
  shift 4
  if [ "$LAUNCH_UNCERTAIN" -eq 1 ]; then
    bail "refusing a new supervisor launch while prior ownership remains uncertain"
    return 1
  fi
  mkdir -p "$control"
  LAUNCH_PENDING_CASE="$case_dir" LAUNCH_PENDING_CONTROL="$control" LAUNCH_PENDING_LOG="$log"
  LAUNCH_PENDING_PID="" LAUNCH_PENDING_START="" LAUNCH_CAPTURE_ERROR=""
  LAUNCH_UNCERTAIN=1
  persist_pending_launch prepared || {
    bail "could not persist pending supervisor launch before creating process"
    return 1
  }
  HANDOFF_ACTIVE=1
  python3 "$OWNED_SUPERVISOR" run "$case_dir" "$control" "$log" -- "$@" \
    > "$log.supervisor" 2>&1 &
  LAUNCH_PENDING_PID=$!
  FIXTURE_SUPERVISOR_PID="$LAUNCH_PENDING_PID" FIXTURE_CONTROL_DIR="$control"
  persist_pending_launch launched || LAUNCH_CAPTURE_ERROR="pending launch receipt could not be updated after spawn"
  identity_file="$control/ready.json"
  t211_pause_before_registration "$role" "$control" "$identity_file" || :
  for i in $(seq 1 10); do
    start="$(timeout 0.2 python3 "$OWNED_SUPERVISOR" start "$LAUNCH_PENDING_PID" 2>/dev/null)" || start=""
    [[ "$start" =~ ^[0-9]+$ ]] && break
    if [ -s "$identity_file" ]; then
      ready_start="$(ready_supervisor_start "$identity_file" "$LAUNCH_PENDING_PID" "$case_dir" "$control" 2>/dev/null)" || ready_start=""
      if [ -n "$ready_start" ]; then start="$ready_start"; break; fi
    fi
    sleep 0.025
  done
  if [ -z "$start" ]; then
    LAUNCH_CAPTURE_ERROR="supervisor PID/start identity was not recoverable from /proc or its exact ready receipt"
    persist_pending_launch unresolved || :
    HANDOFF_ACTIVE=0
    bail "$LAUNCH_CAPTURE_ERROR; preserving control identity $control"
    [ "$PENDING_EXIT_STATUS" -eq 0 ] || exit "$PENDING_EXIT_STATUS"
    return 1
  fi
  if [ -s "$identity_file" ]; then
    ready_start="$(ready_supervisor_start "$identity_file" "$LAUNCH_PENDING_PID" "$case_dir" "$control" 2>/dev/null)" || ready_start=""
    if [ -n "$ready_start" ] && [ "$ready_start" != "$start" ]; then
      LAUNCH_CAPTURE_ERROR="ready receipt and live supervisor start identities disagree"
      persist_pending_launch unresolved || :
      HANDOFF_ACTIVE=0
      bail "$LAUNCH_CAPTURE_ERROR; preserving control identity $control"
      [ "$PENDING_EXIT_STATUS" -eq 0 ] || exit "$PENDING_EXIT_STATUS"
      return 1
    fi
  fi
  LAUNCH_PENDING_START="$start"
  if ! ensure_pending_supervisor_row "$LAUNCH_PENDING_PID" "$case_dir" "$control"; then
    LAUNCH_CAPTURE_ERROR="supervisor start identity could not be atomically reconciled into the owned registry"
    persist_pending_launch unresolved || :
    HANDOFF_ACTIVE=0
    bail "$LAUNCH_CAPTURE_ERROR; preserving control identity $control"
    [ "$PENDING_EXIT_STATUS" -eq 0 ] || exit "$PENDING_EXIT_STATUS"
    return 1
  fi
  persist_pending_launch supervisor-registered || LAUNCH_CAPTURE_ERROR="registered supervisor receipt could not be persisted"
  HANDOFF_ACTIVE=0
  if [ "$PENDING_EXIT_STATUS" -ne 0 ]; then exit "$PENDING_EXIT_STATUS"; fi
  for i in $(seq 1 10); do
    if [ -s "$identity_file" ]; then
      ready_start="$(ready_supervisor_start "$identity_file" "$LAUNCH_PENDING_PID" "$case_dir" "$control" 2>/dev/null)" || ready_start=""
      if [ -n "$ready_start" ] && [ "$ready_start" = "$start" ]; then break; fi
    fi
    sleep 0.025
  done
  if [ -z "$ready_start" ] || [ "$ready_start" != "$start" ]; then
    LAUNCH_CAPTURE_ERROR="supervisor did not publish a matching child identity receipt"
    persist_pending_launch unresolved || :
    bail "$LAUNCH_CAPTURE_ERROR; cleanup remains uncertain for $control"
    return 1
  fi
  LAUNCH_UNCERTAIN=0
  LAUNCH_CAPTURE_ERROR=""
  persist_pending_launch registered || bail "registered launch receipt could not be persisted for $control"
  return 0
}

wait_bound_nonvacuity_control

write_hold_gitshim() {
  local shim_dir="$1"
  mkdir -p "$shim_dir"
  cat > "$shim_dir/git" <<'SHIM'
#!/usr/bin/env bash
if [ "${1:-}" = commit ]; then
  mkdir -p target
  python3 - target/commit-entered <<'ENTERED'
import os, sys, time
with open(sys.argv[1], "w") as stream:
    stream.write(f"{time.monotonic():.9f}\n")
    stream.flush()
    os.fsync(stream.fileno())
ENTERED
  if [ "${STARGATE_FIXTURE_ESCAPE_CHILD:-0}" = 1 ]; then
    setsid sleep 300 >/dev/null 2>&1 &
    printf '%s\n' "$!" > "$STARGATE_FIXTURE_ESCAPE_PID_FILE"
  fi
  if [ "${STARGATE_FIXTURE_COMMIT_DELAY:-0}" -gt 0 ]; then
    sleep "$STARGATE_FIXTURE_COMMIT_DELAY"
  fi
  : > target/committing
  while [ ! -e target/release-commit ]; do sleep 0.05; done
  if [ -e target/abort-commit ]; then exit 130; fi
fi
exec /usr/bin/git "$@"
SHIM
  chmod +x "$shim_dir/git"
}

# This shared launch path is used by both normal gate-boundary cases and the
# real fixture-owner interruption self-invocation. GNU timeout remains inside
# the session so a timeout signal still reaches the Git shim.
launch_fixture_driver() {
  local case_dir="$1" shim_dir="$2" fake_bin="$3" log="$4" delay="${5:-0}" use_timeout="${6:-yes}"
  local escape_child="${7:-0}" escape_pid_file="${8:-}"
  local identity_file i
  local -a command=(env "PATH=$shim_dir:$fake_bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy
    "STARGATE_FIXTURE_COMMIT_DELAY=$delay" "STARGATE_FIXTURE_ESCAPE_CHILD=$escape_child"
    "STARGATE_FIXTURE_ESCAPE_PID_FILE=$escape_pid_file" bash scripts/run-task.sh T900)
  if [ "$use_timeout" = yes ]; then command=(env "PATH=$shim_dir:$fake_bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy
    "STARGATE_FIXTURE_COMMIT_DELAY=$delay" "STARGATE_FIXTURE_ESCAPE_CHILD=$escape_child"
    "STARGATE_FIXTURE_ESCAPE_PID_FILE=$escape_pid_file" timeout 60 bash scripts/run-task.sh T900); fi
  FIXTURE_CONTROL_DIR="$log.owned"
  mkdir -p "$FIXTURE_CONTROL_DIR"
  identity_file="$FIXTURE_CONTROL_DIR/ready.json"
  start_owned_supervisor "$case_dir" "$FIXTURE_CONTROL_DIR" "$log" driver "${command[@]}" || return 1
  for i in $(seq 1 200); do [ -s "$identity_file" ] && break; sleep 0.025; done
  [ -s "$identity_file" ] || { bail "supervisor failed to publish child identity: $(cat "$log.supervisor" 2>/dev/null)"; return 1; }
  read -r FIXTURE_PID FIXTURE_START FIXTURE_PGID FIXTURE_SID < <(python3 - "$identity_file" <<'IDENTITY'
import json, sys
row=json.load(open(sys.argv[1])); print(row["pid"],row["start"],row["pgid"],row["sid"])
IDENTITY
)
  write_owned_launch_event "$case_dir"
}

write_s14_event() {
  local event="$1" path
  [ -n "${STARGATE_T211_OBSERVER_DIR:-}" ] || return 0
  path="$STARGATE_T211_OBSERVER_DIR/$event.json"
  python3 - "$path" "$S14_CASE_DIR" "$SANDBOX" "$FIXTURE_PID" "$FIXTURE_START" \
    "$FIXTURE_PGID" "$FIXTURE_SID" "$$" "$S14_MODE" "$FIXTURE_SUPERVISOR_PID" \
    "$FIXTURE_SUPERVISOR_START" "$FIXTURE_CONTROL_DIR" <<'EVENT'
import json, os, subprocess, sys, time
path, case_dir, sandbox, pid, start, pgid, sid, owner, mode, supervisor, supervisor_start, control = sys.argv[1:]
case_exists = os.path.isdir(case_dir)
base_dir = os.path.join(sandbox, "gate-approved")
def head(path):
    if not os.path.isdir(path):
        return None
    return subprocess.check_output(["git", "-C", path, "rev-parse", "HEAD"], text=True).strip()
row = {"event": os.path.basename(path).removesuffix(".json"),
       "case_dir": case_dir, "sandbox": sandbox, "pid": int(pid),
       "starttime": int(start), "pgid": int(pgid), "sid": int(sid),
       "owner_pid": int(owner), "mode": mode,
       "supervisor_pid": int(supervisor), "supervisor_starttime": int(supervisor_start),
       "monotonic": time.monotonic(), "case_exists": case_exists,
       "committing": os.path.exists(os.path.join(case_dir, "target/committing")),
       "lock_exists": os.path.isdir(os.path.join(case_dir, "target/runs/T900.review.lock")),
       "head": head(case_dir), "base_head": head(base_dir)}
reap = os.path.join(control, "reap.json")
row["supervisor_reap"] = json.load(open(reap)) if os.path.isfile(reap) else None
tmp = path + ".tmp"
with open(tmp, "w") as stream:
    json.dump(row, stream, sort_keys=True)
    stream.write("\n")
os.replace(tmp, path)
EVENT
}

write_owned_launch_event() {
  [ -n "${STARGATE_T211_OBSERVER_DIR:-}" ] || return 0
  python3 - "$STARGATE_T211_OBSERVER_DIR/launch-$FIXTURE_PID.json" \
    "$1" "$SANDBOX" "$FIXTURE_PID" "$FIXTURE_START" "$FIXTURE_PGID" "$FIXTURE_SID" \
    "$FIXTURE_SUPERVISOR_PID" "$FIXTURE_SUPERVISOR_START" "$FIXTURE_CONTROL_DIR" <<'LAUNCH'
import json, os, sys, time
path, case_dir, sandbox, pid, start, pgid, sid, supervisor, supervisor_start, control = sys.argv[1:]
row = {"case_dir": case_dir, "sandbox": sandbox, "pid": int(pid),
       "starttime": int(start), "pgid": int(pgid), "sid": int(sid),
       "supervisor_pid": int(supervisor), "supervisor_starttime": int(supervisor_start),
       "control_dir": control,
       "monotonic": time.monotonic()}
tmp = path + ".tmp"
with open(tmp, "w") as stream:
    json.dump(row, stream, sort_keys=True)
    stream.write("\n")
os.replace(tmp, path)
LAUNCH
}

# Exercise this script's real EXIT cleanup without recursively running the
# ordinary fixture suite. The parent owns the external observation channel;
# this process owns a real T900 child at s13's commit boundary.
if [ "${1:-}" = "--fixture-owner" ]; then
  source_case="$2" shim_dir="$3" fake_bin="$4" control_dir="$5"
  OWNER_RECEIPT_DIR="$control_dir"
  owner_case="$SANDBOX/owner-case"
  mkdir -p "$control_dir"
  cp -a "$source_case" "$owner_case"
  rm -f "$owner_case/target/committing" "$owner_case/target/release-commit" "$owner_case/target/abort-commit"
  launch_fixture_driver "$owner_case" "$shim_dir" "$fake_bin" "$SANDBOX/owner-driver.log"
  python3 - "$control_dir/owned.json" "$SANDBOX" "$owner_case" "$FIXTURE_PID" "$FIXTURE_START" "$FIXTURE_SID" \
    "$FIXTURE_CONTROL_DIR" "$FIXTURE_SUPERVISOR_PID" "$FIXTURE_SUPERVISOR_START" <<'OWNED'
import json, os, sys
out, sandbox, case_dir, pid, start, sid, control, supervisor, supervisor_start = sys.argv[1:]
row = {"sandbox": sandbox, "case_dir": case_dir, "pid": int(pid),
       "start": int(start), "sid": int(sid),
       "control_dir": control, "supervisor_pid": int(supervisor),
       "supervisor_start": int(supervisor_start)}
tmp = out + ".tmp"
with open(tmp, "w") as stream:
    json.dump(row, stream, sort_keys=True)
    stream.write("\n")
os.replace(tmp, out)
OWNED
  for _ in $(seq 1 300); do [ -f "$owner_case/target/committing" ] && break; sleep 0.05; done
  [ -f "$owner_case/target/committing" ] || exit 71
  if [ "${STARGATE_T211_HOLD_OWNER_READY:-0}" = 1 ]; then
  : > "$control_dir/owner-not-ready"
    while [ ! -e "$control_dir/release-owner" ]; do sleep 0.025; done
  fi
  : > "$control_dir/ready"
  mkfifo "$control_dir/wait.fifo"
  exec 9<>"$control_dir/wait.fifo"
  read -r -t 60 -u 9 _ || :
  exit 0
fi

if [ ! -x "$RUNNER" ]; then
  echo "FAIL: single-gate review launcher missing or not executable: $RUNNER" >&2
  exit 1
fi
if [ ! -f "$MATRIX" ]; then
  echo "FAIL: review matrix missing: $MATRIX" >&2
  exit 1
fi

python3 - "$MATRIX" <<'PY' || exit 1
import json, sys

matrix = json.load(open(sys.argv[1]))
expected = [
    ("glm", "opencode", "stargate-review", "zai-coding-plan/glm-5.3-flash", "xhigh",
     lambda t: f"{t}.review-glm.verdict"),
    ("astra", "codex", "stargate-review", "gpt-6-astra", "high",
     lambda t: f"{t}.review-astra.verdict"),
]
rows = matrix.get("reviewers")
if not isinstance(rows, list) or len(rows) != 2:
    raise SystemExit(f"single gate requires exactly two reviewers: {rows!r}")
for row, (rid, tool, role, model, effort, out) in zip(rows, expected):
    got = (row.get("id"), row.get("tool"), row.get("role"), row.get("model"),
           row.get("effort"), row.get("output", "").replace("{ticket}", "T900"))
    want = (rid, tool, role, model, effort, out("T900"))
    if got != want:
        raise SystemExit(f"matrix mismatch: {got!r} != {want!r}")
if "phases" in matrix:
    raise SystemExit("split-phase matrix survived: 'phases' must be gone")
PY

grep -q 'candidate_seal' "$RUNNER" ||
  bail "launcher does not verify each materialized candidate against the handoff seal"

if grep -Eq '\bdocker\b|\bbwrap\b|\bunshare\b' "$RUNNER"; then
  bail "native review runner must not launch containment infrastructure"
fi

# The retired split-phase CLI surface must be gone, not silently accepted.
"$RUNNER" T900 codereview >/dev/null 2>&1
[ "$?" -eq 2 ] || bail "legacy phase argument must be a hard usage error"

# Exercise the production orchestration path with deterministic local CLI
# stand-ins. Dummy environment values satisfy credential preflight but are
# never sent anywhere; the stand-ins make no network calls.
ACTUAL="$SANDBOX/actual"
mkdir -p "$ACTUAL/scripts" "$ACTUAL/.specify" "$ACTUAL/.claude/agents" \
  "$ACTUAL/specs/001-fixture/tickets" "$ACTUAL/fake-bin"
cp "$RUNNER" "$ACTUAL/scripts/review-task.sh"
cp "$MATRIX" "$ACTUAL/scripts/review-matrix.json"
cp "$REPO_ROOT/scripts/run-task.sh" "$ACTUAL/scripts/run-task.sh"
cp "$REPO_ROOT/scripts/test-first-evidence.py" "$ACTUAL/scripts/test-first-evidence.py"
cp "$REPO_ROOT/.claude/agents/stargate-review.md" "$ACTUAL/.claude/agents/"
printf '#!/usr/bin/env bash\nmkdir -p target\necho "RESULT: GREEN" > target/verify.log\n' > "$ACTUAL/scripts/verify.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$ACTUAL/scripts/regen-status.sh"
chmod +x "$ACTUAL/scripts/"*.sh
printf '{"feature_directory":"specs/001-fixture"}\n' > "$ACTUAL/.specify/feature.json"
printf 'target/\n' > "$ACTUAL/.gitignore"
cat > "$ACTUAL/specs/001-fixture/tickets/T900-fixture.md" <<'EOF'
---
id: T900
title: isolated fixture
status: in-review
privacy_critical: true
test_for: [T901]
files_budget: 8
round_cap: 2
reviews: {}
---
# T900
## Context
Fixture.
## Acceptance
The isolated single-gate review set is required.
## Out-of-scope
None.
EOF

cat > "$ACTUAL/fake-bin/opencode" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = run ] && [ "${2:-}" = 'Perform the attached isolated ticket review directly.' ] || {
  echo 'OpenCode positional message must precede array-valued --file' >&2
  exit 64
}
prompt=""
model=""
role=""
[[ " $* " = *" --variant xhigh "* ]] || exit 64
[[ " $* " != *" --session "* && " $* " != *" --continue "* ]] || exit 64
while [ "$#" -gt 0 ]; do
  case "$1" in
    --file) prompt="$2"; shift 2 ;;
    --dir) cd "$2"; shift 2 ;;
    --model) model="$2"; shift 2 ;;
    --agent) role="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ "$model" = zai-coding-plan/glm-5.3-flash ] || exit 64
[ "$role" = stargate-review ] || exit 64
output="$(sed -n 's/^Your verdict output path is \(.*\) in your private candidate\.$/\1/p' "$prompt" | head -1)"
[ "$output" = target/runs/T900.review-glm.verdict ] || exit 64
[[ "$PWD" = */glm/candidate ]] || exit 64
[ ! -e target/runs/T900.review-astra.verdict ] || exit 64
if [ -n "${STARGATE_FIXTURE_CALL_LOG:-}" ]; then
  printf '%s\n' "$$" >> "$STARGATE_FIXTURE_CALL_LOG"
fi
if [ -n "${STARGATE_FIXTURE_BARRIER:-}" ]; then
  while [ ! -e "$STARGATE_FIXTURE_BARRIER/release" ]; do sleep 0.05; done
fi
[ "${STARGATE_FIXTURE_FAIL:-}" != 1 ] || exit 42
[ ! -f .fixture-fail ] || exit 42
if [ -f .fixture-mutate ]; then
  python3 -c 'open("candidate.txt", "w").write("changed by reviewer")'
fi
[ "${OPENCODE_CONFIG_CONTENT:-}" != "" ] || exit 64
python3 -c 'import json,os; c=json.loads(os.environ["OPENCODE_CONFIG_CONTENT"]); assert c["provider"]["zai-coding-plan"]["models"]["glm-5.3-flash"]["variants"]["xhigh"]["reasoningEffort"] == "max"; assert c["permission"]["task"] == "deny"'
python3 -c 'import json,os; c=json.loads(os.environ["OPENCODE_CONFIG_CONTENT"]); assert c["agent"]["stargate-review"]["mode"] == "all"'
if [ -f .fixture-extra-output ]; then
  mkdir -p target/runs/not-a-verdict
fi
if [ "${STARGATE_FIXTURE_EXPECT_PRIOR:-}" = 1 ]; then
  grep -q 'OWN-GLM-PRIOR' "$prompt"
  grep -q 'OWN-ASTRA-PRIOR' "$prompt" || exit 65
fi
{
  echo "VERDICT: ${STARGATE_FIXTURE_VERDICT:-APPROVE}"
  for field in REVIEWER TOOL MODEL EFFORT SNAPSHOT ROUND; do grep -m1 "^$field:" "$prompt"; done
  echo 'SUMMARY: fixture single-gate approval'
  if [ "${STARGATE_FIXTURE_VERDICT:-APPROVE}" = REWORK ]; then
    echo "FINDINGS: OWN-GLM-PRIOR closure probe"
  else
    echo 'FINDINGS: none'
  fi
} > "$output"
EOF
cat > "$ACTUAL/fake-bin/codex" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
model=""
args="$*"
[[ " $* " = *" -s danger-full-access "* && " $* " = *" --ephemeral "* ]] || exit 64
[[ " $* " = *'model_reasoning_effort="high"'* ]] || exit 64
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output="$2"; shift 2 ;;
    -C) cd "$2"; shift 2 ;;
    -m) model="$2"; shift 2 ;;
    *) shift ;;
  esac
done
[ "$model" = gpt-6-astra ] || exit 64
[[ "$output" = */candidate/target/runs/T900.review-astra.verdict ]] || exit 64
[[ "$PWD" = */astra/candidate ]] || exit 64
[ ! -e target/runs/T900.review-glm.verdict ] || exit 64
if [ -n "${STARGATE_FIXTURE_CALL_LOG:-}" ]; then
  printf '%s\n' "$$" >> "$STARGATE_FIXTURE_CALL_LOG"
fi
if [ -n "${STARGATE_FIXTURE_BARRIER:-}" ]; then
  while [ ! -e "$STARGATE_FIXTURE_BARRIER/release" ]; do sleep 0.05; done
fi
prompt="$(mktemp)"
cat > "$prompt"
effort="$(sed -n 's/^EFFORT: //p' "$prompt" | head -1)"
[[ "$args" = *"model_reasoning_effort=\"$effort\""* ]] || exit 64
if [ "${STARGATE_FIXTURE_EXPECT_PRIOR:-}" = 1 ]; then
  grep -q 'OWN-ASTRA-PRIOR' "$prompt"
  grep -q 'OWN-GLM-PRIOR' "$prompt" || exit 65
fi
{
  echo "VERDICT: ${STARGATE_FIXTURE_VERDICT:-APPROVE}"
  for field in REVIEWER TOOL MODEL EFFORT SNAPSHOT ROUND; do grep -m1 "^$field:" "$prompt"; done
  echo 'SUMMARY: fixture single-gate approval'
  if [ "${STARGATE_FIXTURE_VERDICT:-APPROVE}" = REWORK ]; then
    echo "FINDINGS: OWN-ASTRA-PRIOR closure probe"
  else
    echo 'FINDINGS: none'
  fi
} > "$output"
EOF
chmod +x "$ACTUAL/fake-bin/opencode" "$ACTUAL/fake-bin/codex"
actual_text="$(
(
  cd "$ACTUAL" || exit 1
  git init -q -b main
  git config user.email fixture@example.invalid
  git config user.name 'T142 fixture'
  git config commit.gpgsign false
  printf 'before\n' > candidate.txt
  git add -A
  git commit -qm fixture
  start_sha="$(git rev-parse HEAD)"
  printf 'after\n' > candidate.txt
  git add candidate.txt
  mkdir -p target/runs
  printf '%s\n' "$start_sha" > target/runs/T900.start-sha
  bash scripts/run-task.sh T900 >/dev/null
  PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
    bash scripts/review-task.sh T900
) 2>&1
)"
actual_rc=$?
[ "$actual_rc" -eq 0 ] || bail "production launcher path failed with local CLI stand-ins: $actual_text"
for verdict in T900.review-glm.verdict T900.review-astra.verdict; do
  [ -s "$ACTUAL/target/runs/$verdict" ] || bail "production path did not import $verdict"
done
[ -s "$ACTUAL/target/runs/T900.review-set" ] || bail "production path omitted manifest-last marker"
grep -q '^GATE: review$' "$ACTUAL/target/runs/T900.review-set" || bail "manifest is not the single gate"
[ "$(cat "$ACTUAL/candidate.txt")" = "after" ] || bail "production path modified the live candidate"

[ "$(grep -c '^VERDICT: APPROVE$' "$ACTUAL/target/runs/T900.review-history" 2>/dev/null)" = 2 ] ||
  bail "T194: import did not append both verdicts to the per-ticket review history"

cp -a "$ACTUAL" "$SANDBOX/gate-approved"

if [ "$T211_FAILED_RECEIPT_ONLY" -eq 1 ]; then
  case_dir="$SANDBOX/failed-receipt-case"
  control="$SANDBOX/failed-receipt-supervisor"
  mkdir -p "$case_dir" "$control"
  python3 - "$STARGATE_T211_OBSERVER_DIR/failed-receipt-started.json" "$SANDBOX" <<'FAILED_EVENT'
import json, os, sys, time
path, sandbox = sys.argv[1:]
tmp = path + ".tmp"
with open(tmp, "w") as stream:
    json.dump({"sandbox": sandbox, "monotonic": time.monotonic()}, stream)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(tmp, path)
FAILED_EVENT
  start_owned_supervisor "$case_dir" "$control" "$SANDBOX/failed-receipt.log" none /bin/true || exit 1
  if wait_fixture_supervisor "failed receipt control" "$control" "$FIXTURE_SUPERVISOR_PID" \
      "$FIXTURE_SUPERVISOR_START" yes; then
    bail "failed receipt control: injected invalid cleanup receipt was accepted"
  fi
  exit 1
fi

if [ "$T211_S14_LATE_ONLY" -eq 0 ]; then
# T194: an imported, unconsumed REWORK is never retired by a relaunch; the
# driver must consume it (round advance) first. Approvals still retire.
case_dir="$SANDBOX/sticky-rework"
cp -a "$SANDBOX/gate-approved" "$case_dir"
result="$({
  cd "$case_dir" || exit 1
  PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_VERDICT=REWORK bash scripts/review-task.sh T900
} 2>&1)"
[ "$?" -eq 0 ] || bail "T194: REWORK import over an approval failed: $result"
result="$({
  cd "$case_dir" || exit 1
  PATH="$ACTUAL/fake-bin:$PATH" bash scripts/review-task.sh T900
} 2>&1)"
[ "$?" -ne 0 ] || bail "T194: relaunch retired an unconsumed REWORK"
grep -q '^VERDICT: REWORK$' "$case_dir/target/runs/T900.review-glm.verdict" 2>/dev/null ||
  bail "T194: unconsumed REWORK verdict was removed by a relaunch"
[ -s "$case_dir/target/runs/T900.review-set" ] || bail "T194: unconsumed REWORK manifest was removed by a relaunch"
[ "$(grep -c '^VERDICT: REWORK$' "$case_dir/target/runs/T900.review-history" 2>/dev/null)" = 2 ] ||
  bail "T194: REWORK import missing from history"
(cd "$case_dir" && bash scripts/run-task.sh T900 >/dev/null 2>&1)
grep -q '^status: in-progress' "$case_dir/specs/001-fixture/tickets/T900-fixture.md" ||
  bail "T194: driver did not consume the preserved REWORK"
[ "$(cat "$case_dir/target/runs/T900.round")" = 2 ] || bail "T194: preserved REWORK did not advance the round"

# Each private output directory is a constrained import channel: an unexpected
# directory or symlink must reject the whole set, not be ignored because it is
# not a regular file.
extra_text="$({
  cd "$ACTUAL" || exit 1
  rm -f target/runs/T900.review-glm.verdict target/runs/T900.review-astra.verdict \
    target/runs/T900.review-set
  printf 'trigger\n' > .fixture-extra-output
  git add .fixture-extra-output
  bash scripts/run-task.sh T900 >/dev/null
  PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
    bash scripts/review-task.sh T900
} 2>&1)"
extra_rc=$?
[ "$extra_rc" -ne 0 ] || bail "unexpected reviewer output entry did not fail the set"
[ ! -e "$ACTUAL/target/runs/T900.review-set" ] ||
  bail "rejected output set still received a live manifest: $extra_text"
for verdict in T900.review-glm.verdict T900.review-astra.verdict; do
  [ ! -e "$ACTUAL/target/runs/$verdict" ] || bail "rejected output set imported $verdict"
done

# Failures and source changes invalidate the entire set, even when its peer
# wrote an otherwise valid approval. The live tree must retain its bytes.
for mode in fail mutate; do
  result="$({
    cd "$ACTUAL" || exit 1
    git rm -q -f --ignore-unmatch .fixture-extra-output .fixture-fail .fixture-mutate
    printf 'trigger\n' > ".fixture-$mode"
    git add ".fixture-$mode"
    bash scripts/run-task.sh T900 >/dev/null
    PATH="$ACTUAL/fake-bin:$PATH" bash scripts/review-task.sh T900
  } 2>&1)"
  rc=$?
  [ "$rc" -ne 0 ] || bail "$mode did not reject the review set: $result"
  if [ "$mode" = mutate ]; then
    [[ "$result" = *'reviewer changed its source copy'* ]] || bail "mutation was not the rejection cause: $result"
  fi
  [ ! -e "$ACTUAL/target/runs/T900.review-set" ] || bail "$mode imported a manifest"
  [ "$(cat "$ACTUAL/candidate.txt")" = after ] || bail "$mode changed the live source"
done

# A replacement attempt invalidates prior approvals even if source is unchanged.
case_dir="$SANDBOX/retry"
cp -a "$SANDBOX/gate-approved" "$case_dir"
before="$(git -C "$case_dir" rev-parse HEAD)"
result="$({
  cd "$case_dir" || exit 1
  git rm -q -f --ignore-unmatch .fixture-mutate
  PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_FAIL=1 bash scripts/review-task.sh T900
} 2>&1)"
[ "$?" -ne 0 ] || bail "failed replacement succeeded"
[ ! -e "$case_dir/target/runs/T900.review-set" ] || bail "gate retained old approval manifest"
(cd "$case_dir" && bash scripts/run-task.sh T900 >/dev/null 2>&1)
[ "$(git -C "$case_dir" rev-parse HEAD)" = "$before" ] || bail "gate committed after failed replacement"

# B and C must both refuse while A holds the gate lock.
case_dir="$SANDBOX/concurrent"
cp -a "$SANDBOX/gate-approved" "$case_dir"
mkdir "$SANDBOX/barrier"
call_log="$SANDBOX/barrier/calls"
(
  cd "$case_dir" || exit 1
  PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_BARRIER="$SANDBOX/barrier" \
    STARGATE_FIXTURE_CALL_LOG="$call_log" bash scripts/review-task.sh T900
) > "$SANDBOX/concurrent.log" 2>&1 &
launch_a=$!
for ((attempt=0; attempt<200; attempt++)); do
  [ -f "$call_log" ] && [ "$(wc -l < "$call_log")" -eq 2 ] && break
  sleep 0.05
done
[ -f "$call_log" ] && [ "$(wc -l < "$call_log")" -eq 2 ] || bail "concurrency positive control did not start both reviewers"
for other in B C; do
  result="$({
    cd "$case_dir" || exit 1
    PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_CALL_LOG="$call_log" \
      timeout 10 bash scripts/review-task.sh T900
  } 2>&1)"
  [ "$?" -ne 0 ] || bail "concurrent launch $other was accepted"
  [ -d "$case_dir/target/runs/T900.review.lock" ] || bail "launch $other removed A's lock"
done
touch "$SANDBOX/barrier/release"
wait "$launch_a" || bail "owner launch failed"
[ "$(wc -l < "$call_log")" -eq 2 ] || bail "more than the owner's two reviewers started"

# Prove actual model arguments, not just prompt/model labels, are checked.
for mutation in missing-glm wrong-glm missing-astra wrong-astra missing-role wrong-role; do
  case_dir="$SANDBOX/$mutation"
  cp -a "$SANDBOX/gate-approved" "$case_dir"
  case "$mutation" in
    missing-glm) sed -i 's/--model "$model" //' "$case_dir/scripts/review-task.sh" ;;
    wrong-glm) sed -i 's/--model "$model"/--model wrong-model/' "$case_dir/scripts/review-task.sh" ;;
    missing-astra) sed -i 's/-m "$model" //' "$case_dir/scripts/review-task.sh" ;;
    wrong-astra) sed -i 's/-m "$model"/-m wrong-model/' "$case_dir/scripts/review-task.sh" ;;
    missing-role) sed -i 's/--agent "$role" //' "$case_dir/scripts/review-task.sh" ;;
    wrong-role) sed -i 's/--agent "$role"/--agent build/' "$case_dir/scripts/review-task.sh" ;;
  esac
  result="$({
    cd "$case_dir" || exit 1
    git add scripts/review-task.sh
    bash scripts/run-task.sh T900 >/dev/null 2>&1 || true
    bash scripts/run-task.sh T900 >/dev/null
    PATH="$ACTUAL/fake-bin:$PATH" bash scripts/review-task.sh T900
  } 2>&1)"
  [ "$?" -ne 0 ] && [[ "$result" = *'failed (rc=64)'* ]] || bail "model mutation $mutation escaped argument check: $result"
done

# A REWORK gate must survive the driver round transition as private own-item
# evidence for BOTH reviewers of the next round, and the round after the fix
# commits privacy-critical work on the single gate alone.
case_dir="$SANDBOX/prior"
cp -a "$SANDBOX/gate-approved" "$case_dir"
result="$({
  cd "$case_dir" || exit 1
  PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_VERDICT=REWORK bash scripts/review-task.sh T900
  bash scripts/run-task.sh T900 >/dev/null
  touch target/runs/T900.verified
  bash scripts/run-task.sh T900 >/dev/null
  bash scripts/run-task.sh T900 >/dev/null
  PATH="$ACTUAL/fake-bin:$PATH" STARGATE_FIXTURE_EXPECT_PRIOR=1 bash scripts/review-task.sh T900
  bash scripts/run-task.sh T900 >/dev/null
} 2>&1)"
[ "$?" -eq 0 ] || bail "repeat review lost or leaked prior findings: $result"
grep -q '^status: done' "$case_dir/specs/001-fixture/tickets/T900-fixture.md" ||
  bail "single gate did not carry the privacy-critical ticket to done"
fi

# The driver retains the gate lock through trailer capture and git commit.
# A git shim pauses the driver exactly at `git commit`; while it is held
# there a REAL launcher invocation (fake CLIs) must refuse, and the commit
# that lands afterwards carries exactly the authorizing set's trailers.
commit_boundary_case() {
  local tag="$1" driver="$2" delay="${3:-0}" launcher_rc
  local case_dir="$SANDBOX/$tag"
  local escape_pid_file="$SANDBOX/$tag-escaped.pid" escape_pid="" escape_start="" escape_sid=""
  cp -a "$SANDBOX/gate-approved" "$case_dir"
  # The shim lives OUTSIDE the repo: an in-repo shim would be untracked
  # source the driver's inventory check correctly refuses.
  write_hold_gitshim "$SANDBOX/$tag-gitshim"
  rm -f "$case_dir/target/committing" "$case_dir/target/release-commit" "$case_dir/target/abort-commit"
  if [ "$driver" = mutated ]; then
    python3 - "$case_dir/scripts/run-task.sh" <<'MUT'
import sys
p = sys.argv[1]
t = open(p).read()
anchor = '      REVIEW_LINE="$(review_trailers'
assert anchor in t
# Early-unlock mutation: release right after the in-lock validation, before
# trailer capture — exactly the critical-section-lifetime defect round 3
# flagged S12 for not catching.
open(p, 'w').write(t.replace(
    anchor,
    '      rmdir "$RUN_DIR/$TICKET_ID.review.lock" 2>/dev/null || true\n' + anchor, 1))
MUT
    # The mutation must be part of the reviewed candidate, or the driver's
    # snapshot guard refuses the mutated tree before the boundary.
    (cd "$case_dir" && git add scripts/run-task.sh &&
     bash scripts/run-task.sh T900 >/dev/null 2>&1 || true &&
     bash scripts/run-task.sh T900 >/dev/null 2>&1 &&
     PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
       bash scripts/review-task.sh T900 >/dev/null 2>&1) || bail "$tag: mutant re-approval failed"
  fi
  if [ "$tag" = s13-hold ]; then
    launch_fixture_driver "$case_dir" "$SANDBOX/$tag-gitshim" "$ACTUAL/fake-bin" \
      "$SANDBOX/$tag-driver.log" "$delay" yes 1 "$escape_pid_file"
  else
    launch_fixture_driver "$case_dir" "$SANDBOX/$tag-gitshim" "$ACTUAL/fake-bin" \
      "$SANDBOX/$tag-driver.log" "$delay"
  fi
  local drv="$FIXTURE_PID"
  local i
  if [ "$delay" -gt 15 ]; then
    for i in $(seq 1 100); do [ -s "$case_dir/target/commit-entered" ] && break; sleep 0.05; done
    [ -s "$case_dir/target/commit-entered" ] || {
      bail "$tag: delayed control never entered the real commit command"
      cleanup_owned_session "$case_dir" "$FIXTURE_CONTROL_DIR" \
        "$FIXTURE_SUPERVISOR_PID" "$FIXTURE_SUPERVISOR_START" yes || :
      return
    }
  fi
  for i in $(seq 1 300); do [ -f "$case_dir/target/committing" ] && break; sleep 0.05; done
  if [ "$delay" -gt 15 ] && [ ! -f "$case_dir/target/committing" ]; then
    local before_head rc
    before_head="$(git -C "$case_dir" rev-parse HEAD)"
    cleanup_owned_session "$case_dir" "$FIXTURE_CONTROL_DIR" \
      "$FIXTURE_SUPERVISOR_PID" "$FIXTURE_SUPERVISOR_START" yes ||
      bail "$tag: bounded cleanup failed after the expected 15s readiness miss"
    rc="$FIXTURE_SUPERVISOR_RC"
    [ "$rc" -ne 0 ] || bail "$tag: readiness miss reported success"
    [ ! -d "$case_dir/target/runs/T900.review.lock" ] || bail "$tag: readiness miss stranded review lock"
    [ "$(git -C "$case_dir" rev-parse HEAD)" = "$before_head" ] || bail "$tag: readiness miss committed"
    [ ! -e "$case_dir/target/committing" ] || bail "$tag: delayed readiness marker appeared unexpectedly"
    local residue
    residue="$(python3 "$PROC_CONTROL" snapshot "$drv" "$drv" "$FIXTURE_START" 2>&1)"
    [ "$residue" = "[]" ] || bail "$tag: readiness cleanup left process residue: $residue"
    printf 'T211_CONTROL_PASS %s exceeded the 15s readiness window and left no commit, lock, or process residue\n' "$tag"
    return
  fi
  [ -f "$case_dir/target/committing" ] || {
    bail "$tag: driver never reached the commit boundary: $(tail -3 "$SANDBOX/$tag-driver.log" 2>/dev/null)"
    cleanup_owned_session "$case_dir" "$FIXTURE_CONTROL_DIR" "$FIXTURE_SUPERVISOR_PID" "$FIXTURE_SUPERVISOR_START" yes || :
    return
  }
  local result rc
  result="$(
    cd "$case_dir" || exit 1
    PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
      STARGATE_FIXTURE_VERDICT=REWORK timeout 30 bash scripts/review-task.sh T900 2>&1
  )"
  rc=$?
  if [ "$driver" = mutated ]; then
    # Non-vacuity control: with the early unlock, the boundary launcher is
    # ADMITTED — proving the unmutated assertion below is load-bearing.
    [ "$rc" -eq 0 ] || bail "$tag: mutant unexpectedly refused ($rc): $result"
  else
    [ "$rc" -ne 0 ] || bail "$tag: launcher started while the driver held the gate lock"
    [[ "$result" = *'already running'* ]] || bail "$tag: refusal was not the held lock: $result"
    [ -d "$case_dir/target/runs/T900.review.lock" ] || bail "$tag: driver's lock vanished at the commit boundary"
  fi
  if [ "$tag" = s13-hold ]; then
    [ -s "$escape_pid_file" ] || bail "$tag: escaped-session child did not publish its PID"
    escape_pid="$(cat "$escape_pid_file")"
    read -r escape_start escape_sid < <(python3 - "$escape_pid" <<'ESCAPED'
import sys
raw=open(f"/proc/{sys.argv[1]}/stat").read(); tail=raw[raw.rfind(')')+2:].split()
print(tail[19],tail[3])
ESCAPED
)
    [ "$escape_sid" != "$FIXTURE_SID" ] || bail "$tag: child did not escape the driver's session"
  fi
  : > "$case_dir/target/release-commit"
  wait_fixture_supervisor "$tag: commit boundary" "$FIXTURE_CONTROL_DIR" \
    "$FIXTURE_SUPERVISOR_PID" "$FIXTURE_SUPERVISOR_START" yes ||
    bail "$tag: supervisor cleanup failed after boundary release"
  [ "$FIXTURE_SUPERVISOR_RC" -eq 0 ] || bail "$tag: driver failed after boundary release (rc=$FIXTURE_SUPERVISOR_RC): $(cat "$SANDBOX/$tag-driver.log")"
  if [ "$tag" = s13-hold ]; then
    python3 - "$FIXTURE_CONTROL_DIR/reap.json" "$escape_pid" "$escape_start" "$escape_sid" <<'ESCAPED_REAP'
import json, sys
row=json.load(open(sys.argv[1])); pid,start,sid=map(int,sys.argv[2:])
assert not row["remaining"] and row["direct_wait"]["owner"] == "Popen.wait"
assert any(x["pid"] == pid and x["start"] == start and x["sid"] == sid and x["signal"] == 15 and x["result"] == "sent" for x in row["signals"])
assert any(x.get("pid") == pid and x.get("start") == start and x["result"] == "waitpid" for x in row["waits"])
ESCAPED_REAP
    [ "$?" -eq 0 ] || bail "$tag: subreaper did not PIDFD-signal and waitpid the escaped-session child"
  fi
  if [ "$driver" != mutated ]; then
    grep -q '^status: done' "$case_dir/specs/001-fixture/tickets/T900-fixture.md" ||
      bail "$tag: driver did not complete after release"
    git -C "$case_dir" log -1 --format=%B > "$SANDBOX/$tag-msg"
    grep -q 'Reviewed-by: stargate-review (glm; opencode; model zai-coding-plan/glm-5.3-flash; effort xhigh; VERDICT: APPROVE' "$SANDBOX/$tag-msg" ||
      bail "$tag: commit trailers do not match the authorizing APPROVE set (glm)"
    grep -q 'Reviewed-by: stargate-review (astra; codex; model gpt-6-astra; effort high; VERDICT: APPROVE' "$SANDBOX/$tag-msg" ||
      bail "$tag: commit trailers do not match the authorizing APPROVE set (astra)"
  fi
}
if [ "$T211_S14_LATE_ONLY" -eq 0 ]; then
  commit_boundary_case s13-hold normal
  commit_boundary_case s13-early-unlock-mutant mutated
  commit_boundary_case s13-delayed-normal normal 16
  commit_boundary_case s13-delayed-mutant mutated 16
fi

# Interrupt a self-invocation of this fixture at the actual s13 boundary. It
# uses the same top-level EXIT cleanup and shared launch function as the main
# test. The observer and ownership record live outside the owner's sandbox.
dispose_foreign_sentinel() {
  local pid="$1" start="$2" case_dir="$3" control="$4" supervisor="$5" supervisor_start="$6" state rc
  state="$(python3 "$OWNED_SUPERVISOR" identity "$pid" "$start" 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] || { bail "s13 ownership control: foreign identity changed during disposal: $state"; return 1; }
  cleanup_owned_session "$case_dir" "$control" "$supervisor" "$supervisor_start" yes || {
    bail "s13 ownership control: bounded supervisor cleanup of foreign sentinel failed"; return 1;
  }
  state="$(python3 "$OWNED_SUPERVISOR" identity "$pid" "$start" 2>&1)"; rc=$?
  [ "$rc" -eq 0 ] && [ "$state" = gone ] || {
    bail "s13 ownership control: foreign sentinel was not reaped by its supervisor: $state"; return 1;
  }
}

s13_interrupted_owner_case() {
  local control_dir="$SANDBOX/s13-owner-control" owner owner_start i meta sandbox case_dir pid start sid members result deadline
  local foreign foreign_start foreign_case foreign_control foreign_supervisor foreign_supervisor_start
  local owner_supervisor owner_supervisor_start owner_supervisor_control owner_case_placeholder
  local foreign_state foreign_rc owner_exit signal_result
  mkdir -p "$control_dir"
  foreign_case="$control_dir/foreign-sentinel-case"
  foreign_control="$control_dir/foreign-sentinel-supervisor"
  mkdir -p "$foreign_case" "$foreign_control"
  start_owned_supervisor "$foreign_case" "$foreign_control" \
    "$control_dir/foreign-sentinel.log" foreign /bin/sleep 300 || return
  foreign_supervisor="$FIXTURE_SUPERVISOR_PID"
  foreign_supervisor_start="$FIXTURE_SUPERVISOR_START"
  for i in $(seq 1 200); do [ -s "$foreign_control/ready.json" ] && break; sleep 0.025; done
  if [ ! -s "$foreign_control/ready.json" ]; then
    bail "s13 ownership control: foreign-sentinel supervisor did not publish readiness"
    return
  fi
  mapfile -t meta < <(python3 - "$foreign_control/ready.json" <<'FOREIGN_ID'
import json, sys
row=json.load(open(sys.argv[1])); print(row["pid"]); print(row["start"])
FOREIGN_ID
)
  foreign="${meta[0]}" foreign_start="${meta[1]}"
  if python3 "$OWNED_SUPERVISOR" signal "$foreign" "$((foreign_start + 1))" TERM >/dev/null 2>&1; then
    bail "s13 ownership control: stale start identity was accepted for signaling"
  fi
  foreign_state="$(python3 "$OWNED_SUPERVISOR" identity "$foreign" "$foreign_start" 2>&1)"; foreign_rc=$?
  [ "$foreign_rc" -eq 0 ] && [ "$foreign_state" != gone ] ||
    bail "s13 ownership control: rejected stale signal changed the foreign sleeper"
  owner_supervisor_control="$control_dir/owner-supervisor"
  owner_case_placeholder="$control_dir/unresolved-owner-case"
  mkdir -p "$owner_supervisor_control"
  printf '%s\n' "$control_dir/owned.json" > "$owner_supervisor_control/owner-metadata-path"
  start_owned_supervisor "$SANDBOX/gate-approved" "$owner_supervisor_control" \
    "$control_dir/owner-supervisor.log" owner bash "$REPO_ROOT/tests/contract/workflow/review_task_test.sh" \
    --fixture-owner "$SANDBOX/gate-approved" "$SANDBOX/s13-hold-gitshim" \
    "$ACTUAL/fake-bin" "$control_dir" || return
  owner_supervisor="$FIXTURE_SUPERVISOR_PID"
  owner_supervisor_start="$FIXTURE_SUPERVISOR_START"
  # Keep cleanup's owner metadata lookup tied to the real nested fixture case.
  OWNED_SUPERVISOR_ROWS[${#OWNED_SUPERVISOR_ROWS[@]}-1]="$owner_case_placeholder:$owner_supervisor_control:$owner_supervisor:$owner_supervisor_start"
  for i in $(seq 1 200); do [ -s "$owner_supervisor_control/ready.json" ] && break; sleep 0.025; done
  if [ ! -s "$owner_supervisor_control/ready.json" ]; then
    bail "s13 ownership control: nested-owner supervisor did not publish readiness"
    return
  fi
  mapfile -t meta < <(python3 - "$owner_supervisor_control/ready.json" <<'OWNER_ID'
import json, sys
row=json.load(open(sys.argv[1])); print(row["pid"]); print(row["start"])
OWNER_ID
)
  owner="${meta[0]}" owner_start="${meta[1]}"
  if [ -n "${STARGATE_T211_OUTER_PROBE_DIR:-}" ]; then
    for i in $(seq 1 600); do
      [ -s "$control_dir/owned.json" ] && [ -f "$control_dir/owner-not-ready" ] && break
      sleep 0.025
    done
    if [ -s "$control_dir/owned.json" ] && [ -f "$control_dir/owner-not-ready" ]; then
      outer_start="$(python3 "$OWNED_SUPERVISOR" start "$$")"
      python3 - "$STARGATE_T211_OUTER_PROBE_DIR/s13-owner-ready.json" "$control_dir/owned.json" \
        "$$" "$outer_start" "$owner" "$owner_start" "$foreign" "$foreign_start" "$SANDBOX" "$control_dir" <<'OUTER_EVENT'
import json, os, sys, time
path, owned_path, outer, outer_start, owner, owner_start, foreign, foreign_start, sandbox, control = sys.argv[1:]
owned = json.load(open(owned_path))
row = {"event": "s13-owner-not-ready", "monotonic": time.monotonic(),
       "outer_pid": int(outer), "outer_starttime": int(outer_start),
       "owner_pid": int(owner), "owner_starttime": int(owner_start),
       "foreign_pid": int(foreign), "foreign_starttime": int(foreign_start),
       "sandbox": sandbox, "control_dir": control, "owner": owned}
tmp = path + ".tmp"
with open(tmp, "w") as stream:
    json.dump(row, stream, sort_keys=True)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
os.replace(tmp, path)
OUTER_EVENT
    else
      bail "s13 outer interruption: owner never reached the actual readiness hold"
    fi
  fi
  for i in $(seq 1 400); do [ -f "$control_dir/ready" ] && break; sleep 0.05; done
  if [ ! -s "$control_dir/owned.json" ] || [ ! -f "$control_dir/ready" ]; then
    bail "s13 interruption: real fixture owner did not publish its boundary identity"
    cleanup_owned_session "$owner_case_placeholder" "$owner_supervisor_control" \
      "$owner_supervisor" "$owner_supervisor_start" yes ||
      bail "s13 cleanup: bounded nested-owner rescue failed"
    dispose_foreign_sentinel "$foreign" "$foreign_start" "$foreign_case" "$foreign_control" \
      "$foreign_supervisor" "$foreign_supervisor_start"
    return
  fi
  mapfile -t meta < <(python3 - "$control_dir/owned.json" <<'META'
import json, sys
row = json.load(open(sys.argv[1]))
for key in ("sandbox", "case_dir", "pid", "start", "sid", "control_dir", "supervisor_pid", "supervisor_start"):
    print(row[key])
META
)
  sandbox="${meta[0]}" case_dir="${meta[1]}" pid="${meta[2]}" start="${meta[3]}" sid="${meta[4]}"
  fixture_control="${meta[5]}" supervisor="${meta[6]}" supervisor_start="${meta[7]}"
  signal_result="$(python3 "$OWNED_SUPERVISOR" signal "$owner" "$owner_start" TERM 2>&1)" ||
    bail "s13 fixture owner: PIDFD TERM failed"
  [ "$signal_result" = sent ] || bail "s13 fixture owner: PIDFD TERM was not delivered: $signal_result"
  deadline=$((SECONDS + 10))
  wait_fixture_supervisor "s13 fixture owner" "$owner_supervisor_control" \
    "$owner_supervisor" "$owner_supervisor_start" yes ||
    bail "s13 fixture owner: bounded owner-subtree reap failed"
  owner_exit="$FIXTURE_SUPERVISOR_RC"
  members="$(python3 "$PROC_CONTROL" snapshot "$owner" "$owner" "$owner_start" 2>&1)"; result=$?
  while [ "$result" -eq 0 ] && [ "$members" != "[]" ] && [ "$SECONDS" -lt "$deadline" ]; do
    sleep 0.05
    members="$(python3 "$PROC_CONTROL" snapshot "$owner" "$owner" "$owner_start" 2>&1)"; result=$?
  done
  if [ "$result" -ne 0 ]; then
    bail "s13 fixture owner: owner identity changed during bounded EXIT cleanup: $members"
  elif [ "$members" != "[]" ]; then
    bail "s13 fixture owner: cleanup left processes in the fixture-owner session: $members"
    python3 "$OWNED_SUPERVISOR" signal "$owner" "$owner_start" KILL >/dev/null 2>&1 ||
      bail "s13 fixture owner: bounded KILL failed for the still-running fixture owner"
    deadline=$((SECONDS + 5))
    while [ "$SECONDS" -lt "$deadline" ]; do
      members="$(python3 "$PROC_CONTROL" snapshot "$owner" "$owner" "$owner_start" 2>&1)"; result=$?
      [ "$result" -eq 0 ] && [ "$members" = "[]" ] && break
      sleep 0.05
    done
  fi
  if [ "$result" -eq 0 ] && [ "$members" = "[]" ]; then
    result="$owner_exit"
  else
    bail "s13 fixture owner: refusing unbounded wait while owner identity remains: $members"
    result=1
  fi
  [ "$result" -ne 0 ] || bail "s13 fixture owner: SIGTERM did not terminate the fixture owner"
  python3 - "$control_dir/reap.json" "$pid" "$start" <<'REAP'
import json, sys
row=json.load(open(sys.argv[1]))
assert (row["child_pid"], row["child_start"]) == (int(sys.argv[2]), int(sys.argv[3]))
assert row["direct_wait"]["owner"] == "Popen.wait" and not row["remaining"]
assert any(item["pid"] == int(sys.argv[2]) and item["signal"] == 15 for item in row["signals"])
REAP
  [ "$?" -eq 0 ] || bail "s13 fixture owner: supervisor did not record PIDFD termination and direct-child reaping"
  deadline=$((SECONDS + 10))
  members="$(python3 "$PROC_CONTROL" snapshot "$sid" "$pid" "$start" 2>&1)"; result=$?
  while [ "$result" -eq 0 ] && [ "$members" != "[]" ] && [ "$SECONDS" -lt "$deadline" ]; do
    sleep 0.05
    members="$(python3 "$PROC_CONTROL" snapshot "$sid" "$pid" "$start" 2>&1)"; result=$?
  done
  if [ "$result" -ne 0 ]; then
    bail "s13 fixture owner: owned child identity changed after fixture exit: $members"
  elif [ "$members" != "[]" ]; then
    if [ ! -e "$sandbox" ]; then
      bail "s13 fixture owner: top-level EXIT removed its sandbox before owned children were reaped: $members"
    else
      bail "s13 fixture owner: owned children survived top-level EXIT cleanup: $members"
    fi
    cleanup_owned_session "$case_dir" "$fixture_control" "$supervisor" "$supervisor_start" no ||
      bail "s13 fixture owner: external supervisor cleanup failed"
  fi
  [ ! -e "$sandbox" ] || bail "s13 fixture owner: top-level EXIT retained its sandbox after child cleanup"
  foreign_state="$(python3 "$OWNED_SUPERVISOR" identity "$foreign" "$foreign_start" 2>&1)"; foreign_rc=$?
  if [ "$foreign_rc" -ne 0 ] || [ "$foreign_state" = gone ] || [ "$foreign_state" = Z ]; then
    bail "s13 fixture owner: cleanup signalled or changed the foreign sleeper: $foreign_state"
  fi
  dispose_foreign_sentinel "$foreign" "$foreign_start" "$foreign_case" "$foreign_control" \
    "$foreign_supervisor" "$foreign_supervisor_start"
}
if [ "$T211_S14_LATE_ONLY" -eq 0 ] || [ "$T211_REWORK_PROBE" -eq 1 ] || \
    [ "$T211_HANDOFF_ONLY" = foreign ] || [ "$T211_HANDOFF_ONLY" = owner ]; then
  if [ "$T211_REWORK_PROBE" -eq 1 ] || [ "$T211_HANDOFF_ONLY" = foreign ] || \
      [ "$T211_HANDOFF_ONLY" = owner ]; then
    # The targeted outer-interruption selector skips commit_boundary_case's
    # normal setup, so create the same real commit hold shim it needs here.
    write_hold_gitshim "$SANDBOX/s13-hold-gitshim"
  fi
  s13_interrupted_owner_case
fi
if [ "$T211_HANDOFF_ONLY" = driver ]; then
  commit_boundary_case s13-hold normal
fi

# Catchable termination inside the approval critical section must release the
# gate lock (owner-tracked cleanup) and leave the candidate uncommitted, the
# ticket in review, and the gate immediately usable again.
s14_case() {
  local mode="${1:-normal}" case_dir="$SANDBOX/s14-${1:-normal}" drv i s14_before s14_rc result s14_start members deadline
  cp -a "$SANDBOX/gate-approved" "$case_dir"
  write_hold_gitshim "$SANDBOX/s14-${mode}-gitshim"
  rm -f "$case_dir/target/committing" "$case_dir/target/release-commit" "$case_dir/target/abort-commit"
  local delay=0
  [ "$mode" = late ] && delay=12
  S14_MODE="$mode" S14_CASE_DIR="$case_dir"
  launch_fixture_driver "$case_dir" "$SANDBOX/s14-${mode}-gitshim" "$ACTUAL/fake-bin" \
    "$SANDBOX/s14-${mode}-driver.log" "$delay" no
  drv="$FIXTURE_PID" s14_start="$FIXTURE_START"
  s14_before="$(git -C "$case_dir" rev-parse HEAD)"
  write_s14_event "s14-${mode}-started"
  for i in $(seq 1 200); do [ -f "$case_dir/target/committing" ] && break; sleep 0.05; done
  if [ ! -f "$case_dir/target/committing" ]; then
    [ "$mode" = late ] || bail "s14: driver never reached the commit boundary"
    # The same readiness-miss handler runs in normal and delayed cases. Failure
    # cleanup releases the commit shim before the subreaper signals owned PIDs.
    write_s14_event "s14-readiness-miss"
    cleanup_owned_session "$case_dir" "$FIXTURE_CONTROL_DIR" \
      "$FIXTURE_SUPERVISOR_PID" "$FIXTURE_SUPERVISOR_START" yes ||
      bail "s14: bounded supervisor cleanup failed after readiness miss"
    s14_rc="$FIXTURE_SUPERVISOR_RC"
    python3 - "$FIXTURE_CONTROL_DIR/reap.json" "$drv" "$s14_start" <<'REAP'
import json, sys
row=json.load(open(sys.argv[1]))
assert (row["child_pid"], row["child_start"]) == (int(sys.argv[2]), int(sys.argv[3]))
assert row["direct_wait"]["owner"] == "Popen.wait" and not row["remaining"]
assert any(item["pid"] == int(sys.argv[2]) and item["signal"] == 15 and item["result"] == "sent" for item in row["signals"])
REAP
    [ "$?" -eq 0 ] || bail "s14: supervisor lacked PIDFD/direct-child reap receipt"
    [ "$s14_rc" -ne 0 ] || bail "s14: readiness-miss driver reported success"
    [ ! -d "$case_dir/target/runs/T900.review.lock" ] || bail "s14: readiness miss stranded the review lock"
    [ "$(git -C "$case_dir" rev-parse HEAD)" = "$s14_before" ] || bail "s14: readiness miss committed the candidate"
    members="$(python3 "$PROC_CONTROL" snapshot "$drv" "$drv" "$s14_start" 2>&1)"; result=$?
    [ "$result" -eq 0 ] && [ "$members" = "[]" ] || bail "s14: readiness-miss cleanup left owned session processes: $members"
    return
  fi
  request_fixture_signal "$FIXTURE_CONTROL_DIR" "$drv" "$s14_start"
  : > "$case_dir/target/abort-commit"
  : > "$case_dir/target/release-commit"
  wait_fixture_supervisor "s14 normal" "$FIXTURE_CONTROL_DIR" \
    "$FIXTURE_SUPERVISOR_PID" "$FIXTURE_SUPERVISOR_START" yes ||
    bail "s14: bounded supervisor cleanup failed"
  s14_rc="$FIXTURE_SUPERVISOR_RC"
  deadline=$((SECONDS + 11))
  members="$(python3 "$PROC_CONTROL" snapshot "$drv" "$drv" "$s14_start" 2>&1)"; result=$?
  [ "$result" -eq 0 ] || bail "s14: owned session identity check failed: $members"
  while [ "$result" -eq 0 ] && [ "$members" != "[]" ] && [ "$SECONDS" -lt "$deadline" ]; do
    sleep 0.05
    members="$(python3 "$PROC_CONTROL" snapshot "$drv" "$drv" "$s14_start" 2>&1)"; result=$?
    [ "$result" -eq 0 ] || bail "s14: owned session identity changed during cleanup: $members"
  done
  if [ "$result" -eq 0 ] && [ "$members" != "[]" ]; then
    bail "s14: forced 12s commit delay left owned session processes beyond the 10s cleanup bound: $members"
    cleanup_owned_session "$case_dir" "$FIXTURE_CONTROL_DIR" \
      "$FIXTURE_SUPERVISOR_PID" "$FIXTURE_SUPERVISOR_START" yes || :
  fi
  [ "$s14_rc" -ne 0 ] || bail "s14: terminated driver reported success"
  [ ! -d "$case_dir/target/runs/T900.review.lock" ] || bail "s14: SIGTERM inside the critical section stranded the gate lock"
  [ "$(git -C "$case_dir" rev-parse HEAD)" = "$s14_before" ] || bail "s14: terminated driver still committed"
  grep -q '^status: in-review' "$case_dir/specs/001-fixture/tickets/T900-fixture.md" || bail "s14: ticket left review state on termination"
  # The gate must be immediately usable after the cleanup: a real launcher run
  # acquires the lock and completes.
  result="$(
    cd "$case_dir" || exit 1
    PATH="$ACTUAL/fake-bin:$PATH" ZAI_API_KEY=dummy OPENAI_API_KEY=dummy \
      bash scripts/review-task.sh T900 2>&1
  )"
  [ "$?" -eq 0 ] || bail "s14: gate lock was not reusable after SIGTERM cleanup: $result"
}
if [ -z "$T211_HANDOFF_ONLY" ]; then
  if [ "$T211_S14_LATE_ONLY" -eq 1 ]; then
    s14_case late
  else
    s14_case normal
    s14_case late
  fi
  write_s14_event "s14-handler-returned"
fi

if [ "${#errs[@]}" -gt 0 ]; then
  echo "FAIL: T142 single-gate review boundary (${#errs[@]} finding(s)):" >&2
  printf '  - %s\n' "${errs[@]}" >&2
  exit 1
fi

echo "PASS: T142 single-gate review boundary"
