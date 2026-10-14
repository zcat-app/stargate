#!/usr/bin/python3 -IB
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
"""Strict admission and bounded execution for explicitly guarded workflow commands."""
import fcntl
import hashlib
import json
import math
import os
import signal
import stat
import subprocess
import sys
import time

MAX_INPUT = 1 << 20
MAX_JOURNAL = 1 << 20
MAX_ATTEMPTS = 1000
MAX_DEADLINE_SECONDS = 365 * 24 * 60 * 60
HOOK_VARS = ("STARGATE_GUARD_POLICY", "STARGATE_GUARD_SHA256", "STARGATE_GUARD_ACTION")


class Refuse(Exception):
    pass


def fail(message):
    raise Refuse(message)


def strict_json(data, label):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                fail(f"{label}: duplicate JSON key {key}")
            out[key] = value
        return out
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda value: fail(f"{label}: invalid number {value}"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OverflowError) as exc:
        fail(f"{label}: invalid JSON ({exc})")


def read_regular(path, limit=MAX_INPUT):
    if not isinstance(path, str) or not os.path.isabs(path) or os.path.realpath(path) != path:
        fail("input path must be absolute and contain no symlink components")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        fail(f"cannot open pinned input: {exc}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            fail("pinned input is not a bounded regular file")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > limit:
                fail("pinned input exceeds size limit")
        return b"".join(chunks), st
    finally:
        os.close(fd)


def pin(path, expected_hash, expected_mode):
    if (not isinstance(path, str) or not os.path.isabs(path) or os.path.realpath(path) != path or
            not isinstance(expected_hash, str) or len(expected_hash) != 64 or
            any(ch not in "0123456789abcdef" for ch in expected_hash) or
            type(expected_mode) is not int or not 0 <= expected_mode <= 0o777):
        fail("malformed file pin")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        fail(f"cannot open pinned file {path}: {exc}")
    h = hashlib.sha256()
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != expected_mode:
            fail(f"pinned file type or mode changed: {path}")
        while True:
            block = os.read(fd, 131072)
            if not block:
                break
            h.update(block)
    finally:
        os.close(fd)
    if h.hexdigest() != expected_hash:
        fail(f"pinned file hash changed: {path}")


def exact(obj, keys, label):
    if type(obj) is not dict or set(obj) != set(keys):
        fail(f"{label}: expected exactly fields {', '.join(keys)}")


def valid_pin(obj, label):
    exact(obj, ("path", "sha256", "mode"), label)
    pin(obj["path"], obj["sha256"], obj["mode"])


def validate(policy_path, expected_sha, action_name):
    if not isinstance(expected_sha, str) or len(expected_sha) != 64:
        fail("policy SHA256 is malformed")
    data, _ = read_regular(policy_path)
    if hashlib.sha256(data).hexdigest() != expected_sha:
        fail("policy SHA256 does not match")
    p = strict_json(data, "policy")
    exact(p, ("schema", "run_id", "journal_path", "deadline_epoch", "maximum_attempts",
              "maximum_failed_attempts", "phase", "plan", "reviews", "candidates", "actions"), "policy")
    if p["schema"] != "task-run-guard-policy-v1" or not isinstance(p["run_id"], str) or not p["run_id"]:
        fail("unsupported policy schema or empty run_id")
    if (not isinstance(p["journal_path"], str) or not os.path.isabs(p["journal_path"]) or
            os.path.realpath(p["journal_path"]) != p["journal_path"]):
        fail("journal_path must be absolute and contain no symlink components")
    now_epoch = int(time.time())
    if (type(p["deadline_epoch"]) is not int or p["deadline_epoch"] <= now_epoch or
            p["deadline_epoch"] - now_epoch > MAX_DEADLINE_SECONDS or
            type(p["maximum_attempts"]) is not int or not 1 <= p["maximum_attempts"] <= MAX_ATTEMPTS or
            type(p["maximum_failed_attempts"]) is not int or not 1 <= p["maximum_failed_attempts"] <= 3):
        fail("deadline or attempt budget is invalid or exhausted")
    if not isinstance(p["phase"], str) or not p["phase"]:
        fail("phase must be nonempty")
    valid_pin(p["plan"], "plan")
    if type(p["reviews"]) is not list or len(p["reviews"]) != 2:
        fail("exactly two independent review records are required")
    expected_reviews = {"astra": ("gpt-6-astra", "high"), "luna": ("gpt-6-luna", "high")}
    seen_paths, seen_roles = set(), set()
    for row in p["reviews"]:
        exact(row, ("path", "sha256", "mode", "role", "model", "effort"), "review descriptor")
        valid_pin({k: row[k] for k in ("path", "sha256", "mode")}, "review")
        role = row["role"]
        if (not isinstance(role, str) or role not in expected_reviews or
                not isinstance(row["model"], str) or not isinstance(row["effort"], str) or
                (row["model"], row["effort"]) != expected_reviews[role] or
                role in seen_roles or row["path"] in seen_paths):
            fail("review roles, models, effort or report paths do not match the required pair")
        seen_roles.add(role); seen_paths.add(row["path"])
        report_data, _ = read_regular(row["path"])
        report = strict_json(report_data, "review report")
        if type(report) is not dict or set(report) - {"schema", "role", "model", "effort", "verdict", "plan_sha256", "findings"}:
            fail("review report has unknown fields")
        if any(report.get(k) != v for k, v in {"schema": "task-run-guard-review-v1", "role": role,
                "model": row["model"], "effort": row["effort"], "verdict": "APPROVE",
                "plan_sha256": p["plan"]["sha256"]}.items()):
            fail("review report does not approve this exact plan with required identity")
        if "findings" in report and type(report["findings"]) is not list:
            fail("review findings must be a list")
    if type(p["candidates"]) is not list or not p["candidates"]:
        fail("at least one pinned candidate is required")
    for item in p["candidates"]:
        valid_pin(item, "candidate")
    candidate_paths = {item["path"] for item in p["candidates"]}
    if type(p["actions"]) is not dict or not p["actions"] or action_name not in p["actions"]:
        fail("named action is absent")
    for name, a in p["actions"].items():
        if not isinstance(name, str) or not name:
            fail("action name must be nonempty")
        exact(a, ("phase", "enabled", "blocked_reason", "argv", "cwd", "env", "timeout_seconds"), "action")
        if a["phase"] != p["phase"]:
            fail(f"action {name} phase does not match current policy phase")
        if (type(a["enabled"]) is not bool or not isinstance(a["blocked_reason"], str) or
                (not a["enabled"] and not a["blocked_reason"].strip())):
            fail(f"action {name} is disabled or has no blocking reason")
        if type(a["argv"]) is not list or not a["argv"] or any(not isinstance(v, str) or "\0" in v for v in a["argv"]):
            fail(f"action {name} argv is invalid")
        if not os.path.isabs(a["argv"][0]) or not isinstance(a["cwd"], str) or not os.path.isabs(a["cwd"]):
            fail(f"action {name} executable and cwd must be absolute")
        if a["argv"][0] not in candidate_paths:
            fail(f"action {name} executable is not pinned as a candidate")
        for value in a["argv"][1:]:
            possible = value if os.path.isabs(value) else os.path.join(a["cwd"], value)
            if os.path.isfile(possible):
                resolved_input = os.path.realpath(possible)
                if os.path.islink(possible) or resolved_input not in candidate_paths:
                    fail(f"action {name} file input is not directly pinned as a candidate: {value}")
        if type(a["env"]) is not dict or any(not isinstance(k, str) or not k or "=" in k or "\0" in k or not isinstance(v, str) or "\0" in v for k, v in a["env"].items()):
            fail(f"action {name} environment must contain string pairs")
        timeout = a["timeout_seconds"]
        if (type(timeout) not in (int, float) or
                (type(timeout) is int and timeout > MAX_DEADLINE_SECONDS) or
                (type(timeout) is float and not math.isfinite(timeout)) or timeout <= 0):
            fail(f"action {name} timeout must be positive")
        argv = a["argv"]
        executable = argv[0]
        script_index = None
        if executable == "/usr/bin/python3":
            if any(v in ("-c", "-m", "-") for v in argv[1:]):
                script_index = None
            else:
                script_index = next((i for i in range(1, len(argv)) if not argv[i].startswith("-")), None)
        elif executable == "/usr/bin/bash":
            if "-c" in argv[1:]:
                script_index = None
            else:
                script_index = next((i for i in range(1, len(argv)) if not argv[i].startswith("-")), None)
        if script_index is not None:
            value = argv[script_index]
            candidate_path = value if os.path.isabs(value) else os.path.join(a["cwd"], value)
            if not os.path.isabs(candidate_path) or not os.path.lexists(candidate_path):
                fail(f"action {name} script input must exist as a pinned regular file: {value}")
            st = os.lstat(candidate_path)
            if not stat.S_ISREG(st.st_mode) or os.path.islink(candidate_path) or os.path.realpath(candidate_path) not in candidate_paths:
                fail(f"action {name} script input is not a directly pinned regular file: {value}")
        for value in argv[1:]:
            possible = value if os.path.isabs(value) else os.path.join(a["cwd"], value)
            if not os.path.lexists(possible):
                continue
            st = os.lstat(possible)
            if stat.S_ISDIR(st.st_mode):
                continue
            if not stat.S_ISREG(st.st_mode) or os.path.islink(possible):
                fail(f"action {name} argument is a nonregular input: {value}")
            if os.path.realpath(possible) not in candidate_paths:
                fail(f"action {name} file input is not directly pinned as a candidate: {value}")
    action = p["actions"][action_name]
    if not action["enabled"]:
        fail(action["blocked_reason"])
    return p, action


def journal_open(path):
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        fail("journal path must be absolute and contain no symlink components")
    try:
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_JOURNAL:
            fail("journal must be a bounded regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except OSError as exc:
        fail(f"journal is unavailable or locked: {exc}")


def journal_state(fd, policy, initialize=True):
    os.lseek(fd, 0, os.SEEK_SET)
    raw = os.read(fd, MAX_JOURNAL + 1)
    if len(raw) > MAX_JOURNAL or (raw and not raw.endswith(b"\n")):
        fail("journal is oversized or truncated")
    rows = [strict_json(line, "journal record") for line in raw.splitlines()]
    if len(rows) > MAX_ATTEMPTS * 2:
        fail("journal attempt cap exceeded")
    metadata = {"run_id": policy["run_id"], "deadline_epoch": policy["deadline_epoch"],
                "maximum_attempts": policy["maximum_attempts"],
                "maximum_failed_attempts": policy["maximum_failed_attempts"]}
    attempts, failures, pending = 0, 0, None
    if rows:
        first = rows[0]
        if (type(first) is not dict or first.get("type") != "identity" or
                any(type(first.get(k)) is not type(v) or first.get(k) != v for k, v in metadata.items()) or
                set(first) != {"type", *metadata}):
            fail("journal immutable identity or budget changed")
        rows = rows[1:]
    elif initialize:
        append_record(fd, {"type": "identity", **metadata})
    for row in rows:
        if type(row) is not dict:
            fail("invalid journal record")
        if row.get("type") == "attempt" and pending is None:
            attempts += 1
            if (set(row) != {"type", "number", "action"} or type(row.get("number")) is not int or
                    row.get("number") != attempts or not isinstance(row.get("action"), str) or not row["action"]):
                fail("invalid journal attempt sequence")
            pending = attempts
        elif row.get("type") == "result" and pending is not None:
            result, exit_code = row.get("result"), row.get("exit")
            valid_exit = ((result == "ok" and type(exit_code) is int and exit_code == 0) or
                          (result == "failed" and type(exit_code) is int and exit_code != 0) or
                          (result == "timeout" and (exit_code is None or type(exit_code) is int)) or
                          (result == "uncertain" and exit_code is None))
            if (set(row) != {"type", "attempt", "result", "exit"} or
                    type(row.get("attempt")) is not int or row.get("attempt") != pending or
                    result not in ("ok", "failed", "timeout", "uncertain") or not valid_exit):
                fail("invalid journal result")
            if row["result"] in ("timeout", "uncertain"):
                fail("previous command completion is uncertain; no retries")
            if row["result"] == "failed":
                failures += 1
            pending = None
        else:
            fail("journal has dangling or unknown records")
    if pending is not None:
        fail("journal has an interrupted attempt; no retries")
    if attempts >= policy["maximum_attempts"] or failures >= policy["maximum_failed_attempts"]:
        fail("persistent attempt or failure cap reached")
    return attempts


def check_journal(policy):
    path = policy["journal_path"]
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return
    except OSError as exc:
        fail(f"journal cannot be inspected: {exc}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_JOURNAL:
            fail("journal must be a bounded regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError as exc:
            fail(f"journal is locked: {exc}")
        journal_state(fd, policy, initialize=False)
    finally:
        os.close(fd)


def append_record(fd, row):
    data = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if os.fstat(fd).st_size + len(data) > MAX_JOURNAL:
        fail("journal size cap reached")
    offset = 0
    while offset < len(data):
        try:
            written = os.write(fd, data[offset:])
        except OSError as exc:
            fail(f"journal write failed after {offset} bytes: {exc}")
        if type(written) is not int or written <= 0:
            fail("journal write made no progress")
        offset += written
    try:
        os.fsync(fd)
    except OSError as exc:
        fail(f"journal sync failed: {exc}")


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def stop_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + .25
    while time.monotonic() < deadline and group_exists(proc.pid):
        time.sleep(.01)
    if group_exists(proc.pid):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=1)
        return not group_exists(proc.pid)
    except subprocess.TimeoutExpired:
        return False


def interrupt_guard(_signum, _frame):
    raise KeyboardInterrupt


def run(policy_path, expected_sha, action_name, driver=None, args=()):
    entry_wall = time.time()
    entry_mono = time.monotonic()
    p, action = validate(policy_path, expected_sha, action_name)
    global_deadline = entry_mono + max(0.0, p["deadline_epoch"] - entry_wall)
    if time.monotonic() >= global_deadline:
        fail("admission deadline expired during policy validation")
    if driver is not None:
        actual = ["/usr/bin/bash", "-p", driver, *args]
        if action["argv"] != actual:
            fail("guarded driver arguments do not match the approved action")
        pinned = {item["path"] for item in p["candidates"]}
        bootstrap = {os.path.realpath(__file__), os.path.realpath(sys.executable),
                     os.path.realpath("/usr/bin/readlink")}
        if driver not in pinned or "/usr/bin/bash" not in pinned or not bootstrap.issubset(pinned):
            fail("guarded driver, bash and guard bootstrap inputs must be pinned candidates")
    for name in HOOK_VARS:
        if name in action["env"]:
            fail("guard variables cannot be inherited by the child")
    fd = journal_open(p["journal_path"])
    try:
        attempts = journal_state(fd, p)
        if time.monotonic() >= global_deadline:
            fail("admission deadline expired during journal validation")
        number = attempts + 1
        append_record(fd, {"type": "attempt", "number": number, "action": action_name})
        if time.monotonic() >= global_deadline:
            append_record(fd, {"type": "result", "attempt": number,
                               "result": "timeout", "exit": None})
            print("task-run-guard: admission deadline expired before spawn", file=sys.stderr)
            return 124
        env = dict(action["env"])
        started = time.monotonic()
        proc = None
        action_started = time.monotonic()
        monotonic_deadline = min(global_deadline, action_started + float(action["timeout_seconds"]))
        previous_term = signal.signal(signal.SIGTERM, interrupt_guard)
        try:
            if time.monotonic() >= monotonic_deadline:
                append_record(fd, {"type": "result", "attempt": number,
                                   "result": "timeout", "exit": None})
                print("task-run-guard: admission deadline expired before spawn", file=sys.stderr)
                return 124
            proc = subprocess.Popen(action["argv"], cwd=action["cwd"], env=env,
                                    start_new_session=True)
            remaining = monotonic_deadline - time.monotonic()
            try:
                code = proc.wait(timeout=max(.001, remaining))
            except subprocess.TimeoutExpired:
                clean = stop_group(proc)
                append_record(fd, {"type": "result", "attempt": number,
                    "result": "timeout" if clean else "uncertain", "exit": None})
                print("task-run-guard: command timed out", file=sys.stderr)
                return 124
            if time.monotonic() >= monotonic_deadline:
                clean = stop_group(proc)
                append_record(fd, {"type": "result", "attempt": number,
                    "result": "timeout" if clean else "uncertain", "exit": code})
                print("task-run-guard: command timed out", file=sys.stderr)
                return 124
            if group_exists(proc.pid):
                stop_group(proc)
                append_record(fd, {"type": "result", "attempt": number,
                    "result": "uncertain", "exit": code})
                fail("command left process-group members; stopped group")
            result = "ok" if code == 0 else "failed"
            if code == 0:
                try:
                    validate(policy_path, expected_sha, action_name)
                except Refuse:
                    append_record(fd, {"type": "result", "attempt": number,
                        "result": "uncertain", "exit": code})
                    fail("pinned inputs changed during command")
                if time.monotonic() >= monotonic_deadline:
                    append_record(fd, {"type": "result", "attempt": number,
                        "result": "timeout", "exit": code})
                    print("task-run-guard: command exceeded its time budget", file=sys.stderr)
                    return 124
            append_record(fd, {"type": "result", "attempt": number, "result": result, "exit": code})
            return code
        except KeyboardInterrupt:
            clean = stop_group(proc) if proc is not None else True
            append_record(fd, {"type": "result", "attempt": number,
                "result": "uncertain" if not clean else "timeout", "exit": None})
            return 130
        except OSError as exc:
            append_record(fd, {"type": "result", "attempt": number, "result": "failed", "exit": 127})
            fail(f"cannot start approved command: {exc}")
        finally:
            signal.signal(signal.SIGTERM, previous_term)
    finally:
        os.close(fd)


def main(argv):
    if not argv or argv[0] not in ("check", "run"):
        fail("usage: task-run-guard.py check POLICY SHA256 ACTION | run POLICY SHA256 ACTION [--driver PATH -- ARGS...]")
    mode = argv[0]
    rest = argv[1:]
    if mode == "check" and len(rest) == 3:
        entry_mono = time.monotonic()
        entry_wall = time.time()
        policy, _ = validate(*rest)
        deadline = entry_mono + max(0.0, policy["deadline_epoch"] - entry_wall)
        check_journal(policy)
        if time.monotonic() >= deadline:
            fail("admission deadline expired during check")
        print("task-run-guard: admitted")
        return 0
    if mode == "run" and len(rest) >= 3:
        policy, sha, action = rest[:3]
        driver, args = None, ()
        if len(rest) > 3:
            if len(rest) < 5 or rest[3] != "--driver" or "--" not in rest[4:]:
                fail("malformed guarded driver arguments")
            index = rest.index("--", 4)
            if index != 5:
                fail("malformed guarded driver path")
            driver, args = rest[4], rest[6:]
        return run(policy, sha, action, driver, args)
    fail("invalid command arguments")


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Refuse as exc:
        print(f"task-run-guard: REFUSED: {exc}", file=sys.stderr)
        sys.exit(78)
