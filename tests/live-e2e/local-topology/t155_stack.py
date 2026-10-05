#!/usr/bin/env python3
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T155 — stack phase on the disposable QEMU guest (run as root from the candidate
# tree). Real `scripts/stargate init` on fresh volumes, then the quickstart
# operator surface (tokens.yaml + `restart stargate-control` +
# `scripts/stargate status`) drives Acceptance 2/7 checks against the deployed
# DP on 127.0.0.1:8881. Synthetic tokens only; nothing secret is printed.
# Every check is recorded PASS/FAIL; the script exits non-zero on any FAIL.
#
# `--only resumption` runs init, the first acknowledged reload and the TLS
# resumption phase alone. `--only traffic` runs the real-hour GetStatus probe.
# The default runs all; traffic publication can take a full UTC hour.
import hashlib
import json
import os
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ONLY = sys.argv[2] if sys.argv[1:2] == ["--only"] and len(sys.argv) == 3 else None
if sys.argv[1:] and ONLY not in ("resumption", "traffic"):
    sys.exit("usage: t155_stack.py [--only resumption|traffic]")

ROOT = Path.cwd()
COMPOSE = ROOT / "compose/docker-compose.local.yml"
STAMP = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
P = "t155-stack"
EV = ROOT / "target/live-e2e" / f"T155-stack-{STAMP}"
EV.mkdir(parents=True)
ENV = os.environ.copy()
ENV.update(STARGATE_PROJECT=P, STARGATE_COMPOSE_FILE=str(COMPOSE), STARGATE_ENV_DIR=str(EV),
           STARGATE_ENV_FILE=str(EV / "local.env"), BUILDX_BUILDER=os.environ.get("BUILDX_BUILDER", "t165-native"))
C = ["docker", "compose", "-p", P, "-f", str(COMPOSE), "--env-file", str(EV / "local.env")]
RESULTS = []
TOK = {name: secrets.token_hex(16) for name in ("laptop", "phone", "tablet", "bogus")}
GIMG = "golang:1.26.3-bookworm@sha256:252599aeb51ad60b83e4d8821802068127c528c707cb7dd7afd93be057c6011c"
PROBE = ROOT / "target/stargate-wireprobe"


def log(msg):
    print(msg, flush=True)


def check(name, ok, detail=""):
    RESULTS.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
    log(f"{'PASS' if ok else 'FAIL'}: {name}{' — ' + detail if detail else ''}")
    return ok


def run(argv, timeout=600, env=None, ok=True):
    r = subprocess.run(argv, cwd=ROOT, env=env or ENV, text=True, capture_output=True, timeout=timeout)
    if ok and r.returncode:
        raise RuntimeError(f"{' '.join(map(str, argv[:6]))} exit {r.returncode}: {r.stderr[-800:]}")
    return r


def vol(name):
    return Path(run(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}", f"{P}_{name}"]).stdout.strip())


def write_tokens(*labels):
    # Quickstart step: root writes tokens.yaml into the config volume (sudo tee).
    body = "tokens:\n" + "".join(f"  - label: {l}\n    token: {TOK[l]}\n" for l in labels)
    (vol("stargate-control-config") / "tokens.yaml").write_text(body)


def status():
    r = run(["bash", "scripts/stargate", "status"], timeout=60, ok=False)
    # Whole output, not the last line: STALE_CONFLICT is followed by a pointer line.
    return r.returncode, ["\n".join((r.stdout + r.stderr).strip().splitlines())]


def await_status(rc, needle, timeout):
    deadline = time.monotonic() + timeout
    while True:
        code, out = status()
        if code == rc and needle in out[0]:
            return out[0]
        if time.monotonic() > deadline:
            return f"TIMEOUT last rc={code} out={out[0]}"
        time.sleep(5)


def recv_exact(conn, n):
    data = b""
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part:
            break
        data += part
    return data


def socks_auth(token, site=b"t155-device-profile-normal-example.com"):
    """Return (state, conn): state is 'ok', 'denied' or 'closed'."""
    conn = socket.create_connection(("127.0.0.1", 8881), timeout=10)
    conn.settimeout(30)
    conn.sendall(b"\x05\x01\x02")
    if recv_exact(conn, 2) != b"\x05\x02":
        conn.close()
        return "closed", None
    user = b"sg1:" + hashlib.sha256(site).hexdigest().encode()
    t = token.encode()
    conn.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(t)]) + t)
    reply = recv_exact(conn, 2)
    if reply == b"\x01\x00":
        return "ok", conn
    conn.close()
    return ("denied" if reply == b"\x01\xff" else "closed"), None


def auth_state(label):
    try:
        state, conn = socks_auth(TOK[label])
        if conn:
            conn.close()
        return state
    except OSError as exc:
        return f"error:{type(exc).__name__}"


def tor_bytes(label):
    for attempt in range(3):
        try:
            state, conn = socks_auth(TOK[label])
            if state != "ok":
                return f"auth {state}"
            with conn:
                target = b"example.com"
                conn.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target + b"\x00\x50")
                rep = recv_exact(conn, 10)
                if rep[:2] != b"\x05\x00":
                    last = f"reply {rep[:2].hex()}"
                    continue
                conn.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                head = conn.recv(64)
                if head.startswith(b"HTTP/"):
                    return "ok"
                last = "no HTTP bytes"
        except OSError as exc:
            last = f"{type(exc).__name__}"
        time.sleep(10)
    return last


def wait_listener(timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", 8881), timeout=3) as c:
                c.sendall(b"\x05\x01\x02")
                if recv_exact(c, 2) == b"\x05\x02":
                    return True
        except OSError:
            pass
        time.sleep(2)
    return False


def db_rows():
    tmp = Path(tempfile.mkdtemp(prefix="t155-db-"))
    try:
        state = vol("stargate-control-state")
        for f in state.glob("control.db*"):
            shutil.copy2(f, tmp / f.name)
        con = sqlite3.connect(tmp / "control.db")
        rows = con.execute("SELECT hour_bucket, category, count FROM operational_aggregates ORDER BY 1,2").fetchall()
        con.close()
        return rows
    finally:
        shutil.rmtree(tmp)


def backup(name):
    dst = Path(f"/root/t155-{name}")
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(vol("stargate-control-state"), dst, symlinks=True)
    return dst


def restore(src):
    state = vol("stargate-control-state")
    for child in state.iterdir():
        shutil.rmtree(child) if child.is_dir() and not child.is_symlink() else child.unlink()
    for child in src.iterdir():
        (shutil.copytree if child.is_dir() else shutil.copy2)(child, state / child.name)
    shutil.chown(state, 5101, 5100)
    for child in state.rglob("*"):
        os.chown(child, 5101, 5100, follow_symlinks=False)


def build_probe():
    # Rebuild from this candidate, even when a previous run left a binary.
    run(["docker", "run", "--rm", "-v", f"{ROOT}:/src", "-w", "/src", GIMG, "go", "build", "-buildvcs=false",
         "-o", "/src/target/stargate-wireprobe", "./tests/contract/compose/wireprobe"], timeout=1200)
    PROBE.chmod(0o755)


def traffic_publication_phase():
    """A7 / control-grpc T158: observe the actual DP RPC across real UTC time.
    CP operational_aggregates are a separate writer and cannot prove this.
    No clock injection or DP restart is used. Only synthetic traffic is recorded.
    """
    build_probe()
    samples = []
    published = {}
    dp_id = run(C + ["ps", "-q", "stargate-dp"]).stdout.strip()

    def identity():
        return run(["docker", "inspect", "-f", "{{.Id}} {{.State.StartedAt}} {{.State.Pid}}", dp_id]).stdout.strip()

    started = identity()

    def require(name, ok, detail=""):
        if not check(name, ok, detail):
            raise RuntimeError(name)

    def sample():
        before = int(time.time()) // 3600
        r = run(["docker", "run", "--rm", "--network", "none", "--user", "5101:5100",
                 "-v", f"{P}_stargate-ipc:/run/stargate:ro",
                 "-v", f"{P}_stargate-keys:/etc/stargate/keys:ro",
                 "-v", f"{ROOT}:/src:ro", GIMG, "/src/target/stargate-wireprobe", "counters"], timeout=60)
        after = int(time.time()) // 3600
        response = json.loads(r.stdout)
        rows = response["counters"]
        values = {}
        for row in rows:
            if set(row) != {"route", "hourBucket", "requestCount", "byteCount"} or row["route"] != "TOR":
                raise RuntimeError("GetStatus returned unexpected counter fields or route")
            hour = int(row["hourBucket"])
            if hour in values:
                raise RuntimeError("GetStatus returned a duplicate hour")
            values[hour] = (int(row["requestCount"]), int(row["byteCount"]))
        samples.append({"before_unix_hour": before, "after_unix_hour": after, "counters": rows})
        (EV / "traffic-publication.json").write_text(json.dumps(
            {"dp_identity": started, "samples": samples}, indent=2) + "\n")
        # A sample straddling rollover may contain the newly completed hour.
        # The repeated same-hour samples below are the active-export falsifier.
        require("GetStatus excludes active/future traffic hours", all(h < after for h in values),
                f"sample {len(samples)}; guest UTC hours {before}..{after}; exported {sorted(values)}")
        require("previously published traffic rows remain immutable",
                all(values.get(h) == value for h, value in published.items()))
        published.update(values)
        require("DP process unchanged during traffic publication", identity() == started)
        return before, after, values

    def traffic():
        result = tor_bytes("laptop")
        require("traffic publication positive control: authenticated Tor destination bytes", result == "ok", result)
        # tor_bytes closes its tunnel; allow both forwarding pumps to complete
        # before checking the bucket. The nonzero completed-byte control below
        # fails if no bytes were booked in the measured hour.
        time.sleep(2)

    # If setup crosses the hour, restart the observation window on this same DP.
    deadline = time.monotonic() + 4200
    while True:
        hour = int(time.time()) // 3600
        traffic()
        private_samples = 0
        for _ in range(3):
            before, after, _ = sample()
            if before == after == hour:
                private_samples += 1
            time.sleep(5)
        if private_samples == 3 and int(time.time()) // 3600 == hour:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("no complete pre-boundary observation window")
    require("repeated same-hour GetStatus reads after traffic", private_samples == 3, f"unix hour {hour}")
    traffic()
    sample()
    log(f"traffic publication: waiting for real UTC boundary after unix hour {hour}")
    while int(time.time()) // 3600 == hour:
        if time.monotonic() >= deadline:
            raise RuntimeError("real UTC hour boundary did not arrive within 70 minutes")
        time.sleep(15)
        sample()
    before, after, rows = sample()
    require("real UTC hour boundary crossed on the running DP", before > hour and after > hour)
    completed = rows.get(hour)
    require("nonzero completed TOR traffic row published",
            completed is not None and completed[0] > 0 and completed[1] > 0,
            f"unix hour {hour}; request/byte totals {completed}")
    for _ in range(3):
        traffic()
        _, _, rows = sample()
        require("completed traffic row unchanged after more Tor traffic", rows.get(hour) == completed)
    require("traffic publication DP identity unchanged across real rollover", identity() == started, started)


def resumption_phase():
    """A2 peer-pin rotation/resumption. With the CP stopped (wire-auth.md §6.2
    rotation order), `wireprobe resume`, as the CP identity, takes a session
    ticket from the running DP, resumes it (positive control), rotates
    cp.priv/cp.pub, offers the old ticket, then the old identity in a full
    handshake, then the rotated identity. Its exit code decides; each step is
    also recorded so a failure names its step. Afterwards the observer's
    cp.pub copy is refreshed with init's helper and the CP restarts on the
    rotated key."""
    build_probe()
    dp_id = run(C + ["ps", "-q", "stargate-dp"]).stdout.strip()

    def dp_started():
        return run(["docker", "inspect", "-f", "{{.State.StartedAt}} {{.State.Pid}}", dp_id]).stdout.strip()

    run(C + ["stop", "stargate-control"])
    started = dp_started()
    r = subprocess.run(["docker", "run", "--rm", "--user", "5101:5100", "-v", f"{P}_stargate-ipc:/run/stargate",
                        "-v", f"{P}_stargate-keys:/etc/stargate/keys", "-v", f"{ROOT}:/src", "-w", "/src", GIMG,
                        "/src/target/stargate-wireprobe", "resume", "-socket", "/run/stargate/dp.sock"],
                       capture_output=True, text=True, timeout=600)
    (EV / "resume.log").write_text(r.stdout + r.stderr)
    # The ticket must meet the same DP process that issued it.
    check("DP process unchanged across the resumption probe", dp_started() == started, started)
    steps = {l.split()[2].rstrip(":"): l for l in r.stdout.splitlines() if l.startswith("wireprobe: resume ")}

    def step(name, *needles):
        line = steps.get(name, "")
        return bool(line) and all(n in line for n in needles), line.split(": ", 2)[-1] if line else "step not reached"

    ok, d = step("2-old-resumed-before-rotation", "ticket_offered=true", "resumed=true", "rpc=answered")
    check("resumption positive control: DP resumed the offered ticket before rotation", ok, d)
    ok, d = step("4-old-ticket-after-rotation", "ticket_offered=true", " handshakes=1 ",
                 "first_handshake=[pin_verified=true resumed=true", "rpc=refused")
    check("old CP identity on pin-verified selected PSK path gets no RPC answered", ok, d)
    ok, d = step("5-old-full-after-rotation", "rpc=refused")
    check("old CP identity refused on a full handshake after rotation", ok, d)
    ok, d = step("6-rotated-full", "rpc=answered")
    check("rotated CP identity answered (DP re-read the pin; the refusals are not an outage)", ok, d)
    check("wireprobe resume exit 0", r.returncode == 0, f"exit {r.returncode} {r.stderr.strip()[-300:]}")
    # §6.1 ownership/mode of the rotated files, then the §6.2 observer refresh.
    run(["docker", "run", "--rm", "--user", "0:0", "-v", f"{P}_stargate-keys:/etc/stargate/keys", GIMG, "bash", "-c",
         "chown 5101:5100 /etc/stargate/keys/cp.priv /etc/stargate/keys/cp.pub && "
         "chmod 600 /etc/stargate/keys/cp.priv && chmod 644 /etc/stargate/keys/cp.pub"])
    run(["bash", "-c", '. scripts/lib/compose.sh && refresh_observer_cp_pub "$1" "$2"', "refresh",
         f"{P}_stargate-keys", f"{P}_stargate-observer-keys"])
    run(C + ["start", "stargate-control"])
    s = await_status(0, "ACKNOWLEDGED(", 1200)
    check("CP restarted on the rotated key: token delivery acknowledged", "ACKNOWLEDGED(" in s, s)


def main_focused():
    log(f"evidence: {EV} (--only {ONLY})")
    run(["bash", "scripts/stargate", "init"], timeout=2400)
    check("scripts/stargate init on clean volumes", wait_listener(), "127.0.0.1:8881 SOCKS method reply")
    write_tokens("laptop")
    run(C + ["restart", "stargate-control"])
    s = await_status(0, "ACKNOWLEDGED(", 1200)
    check("authenticated reload acknowledged", "ACKNOWLEDGED(" in s, s)
    if ONLY == "traffic":
        traffic_publication_phase()
    else:
        resumption_phase()
        check("laptop still admitted after the CP rotation", auth_state("laptop") == "ok")


def main():
    log(f"evidence: {EV}")
    # 1. Real operator init on fresh, never-used volumes (Acceptance 2).
    pre = run(["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={P}"]).stdout.strip()
    check("fresh project volumes before init", pre == "", pre)
    run(["bash", "scripts/stargate", "init"], timeout=2400)
    check("scripts/stargate init on clean volumes", wait_listener(), "127.0.0.1:8881 SOCKS method reply")
    code, out = status()
    check("no tokens.yaml: status is not ACKNOWLEDGED", code != 0, f"rc={code} {out[0]}")
    st = auth_state("laptop")
    check("no auth state admits nobody", st == "denied", st)

    # 2. First authenticated reload through the quickstart surface.
    write_tokens("laptop", "phone")
    run(C + ["restart", "stargate-control"])
    s = await_status(0, "ACKNOWLEDGED(", 1200)
    check("authenticated reload acknowledged", "ACKNOWLEDGED(" in s, s)
    gen1 = s
    check("laptop admitted", auth_state("laptop") == "ok")
    check("phone admitted", auth_state("phone") == "ok")
    check("unknown token denied (01 FF)", auth_state("bogus") == "denied")
    tb = tor_bytes("laptop")
    check("Tor-routed destination bytes (CP up)", tb == "ok", tb)

    traffic_publication_phase()

    # 3. Completed-hour-only persistence and retention cleanup (Acceptance 7).
    now_hour = int(time.time()) // 3600 * 3600
    rows = db_rows()
    check("persisted aggregates are completed hours only", all(r[0] < now_hour for r in rows),
          f"{len(rows)} rows, max bucket offset {max((r[0] - now_hour) // 3600 for r in rows) if rows else 'n/a'}h")
    run(C + ["stop", "stargate-control"])
    expired, recent = now_hour - 8 * 86400, now_hour - 2 * 3600
    con = sqlite3.connect(vol("stargate-control-state") / "control.db")
    con.execute("INSERT INTO operational_aggregates VALUES (?, 'config_error', 7)", (expired,))
    con.execute("INSERT INTO operational_aggregates VALUES (?, 'config_error', 7)", (recent,))
    con.commit()
    con.close()
    for f in vol("stargate-control-state").glob("control.db*"):
        os.chown(f, 5101, 5100)
    run(C + ["start", "stargate-control"])
    s = await_status(0, "ACKNOWLEDGED(", 1200)
    time.sleep(10)
    rows = db_rows()
    keys = {(r[0], r[1]) for r in rows}
    check("retention removes an expired (8-day) bucket", (expired, "config_error") not in keys)
    check("retention keeps an in-window bucket (positive control)", (recent, "config_error") in keys)
    # Non-vacuous: the in-window row inserted above must be among them.
    check("still completed hours only after CP restart", bool(rows) and all(r[0] < now_hour for r in rows), f"{len(rows)} rows")

    # 4. HTTP CONNECT refusal and offline restart (T173 probe). Old and new DP
    # images differ only by an added label; both carry the candidate binary.
    dp_image = run(["docker", "inspect", "--format", "{{.Image}}", run(C + ["ps", "-q", "stargate-dp"]).stdout.strip()]).stdout.strip()
    run(["docker", "tag", dp_image, "t155/candidate-dp:built"])
    built = subprocess.run(["docker", "build", "-q", "-t", "t155/old-dp:label", "--label", "t155.migration=label-only", "-"],
                           input="FROM t155/candidate-dp:built\n", text=True, capture_output=True, cwd=ROOT, timeout=300,
                           env={**ENV, "BUILDX_BUILDER": "default"})
    if built.returncode:
        raise RuntimeError(f"label-only image build failed: {built.stderr[-400:]}")
    run(["docker", "tag", "t155/old-dp:label", "stargate/stargate-dp:local"])
    run(C + ["up", "-d", "--no-build", "--no-deps", "--force-recreate", "stargate-dp"])
    check("label-only predecessor DP listening", wait_listener())
    r = run(["python3", "-B", "tests/live-e2e/local-topology/connect_refusal.py"], timeout=3600, ok=False,
            env={**ENV, "STARGATE_LIVE_E2E": "1", "STARGATE_DISPOSABLE_HOST": "1",
                 "STARGATE_EVIDENCE_DIR": str(EV / "connect-refusal"), "STARGATE_CANDIDATE_IMAGE": dp_image})
    (EV / "connect-refusal.log").write_text(r.stdout + r.stderr)
    check("connect_refusal.py (HTTP silent close, traced no Tor connect, SOCKS Tor bytes, snapshot preserved)",
          r.returncode == 0 and "PASS: deployed refusal" in r.stdout, f"exit {r.returncode}")

    # 5. Back to the operator token set; keep a pre-revocation CP state backup.
    write_tokens("laptop", "phone")
    run(C + ["start", "stargate-control"])
    s = await_status(0, "ACKNOWLEDGED(", 1200)
    check("reload after connect_refusal acknowledged", "ACKNOWLEDGED(" in s, s)
    run(C + ["stop", "stargate-control"])
    old_state = backup("state-laptop-phone")
    keys = vol("stargate-keys")
    oldkeys = Path(tempfile.mkdtemp(prefix="t155-oldcp-", dir="/dev/shm"))
    for f in ("cp.priv", "cp.pub"):
        shutil.copy2(keys / f, oldkeys / f)
    run(C + ["start", "stargate-control"])
    s = await_status(0, "ACKNOWLEDGED(", 1200)

    # 6. Wire-auth runtime rows R1-R9 on this deployed stack, mutations enabled
    # (R4 wrong key, R8 CP restart survival, R9 CP key rotation, fresh pin re-read).
    r = run(["bash", "tests/contract/compose/inter_plane_wire_test.sh"], timeout=3600, ok=False,
            env={**ENV, "COMPOSE_PROJECT_NAME": P, "STARGATE_WIRE_RUNTIME_MUTATE": "1"})
    (EV / "inter-plane-wire.log").write_text(r.stdout + r.stderr)
    rows_out = r.stdout + r.stderr
    # T196 repaired R2/R3/R5/R7 and made a row print PASS only without a finding,
    # so the gate's own rows and exit code decide (attempt 3's supplements removed).
    for n in range(1, 10):
        check(f"wire runtime row R{n} PASS (not SKIP)", f"R{n}: PASS" in rows_out and f"R{n}: FAIL" not in rows_out)
    check("inter_plane_wire_test.sh exit 0", r.returncode == 0, f"exit {r.returncode}")

    # 7. After rotation: the OLD CP identity is refused by the running DP; the
    # current identity (positive control) is accepted. Same wireprobe binary.
    probe, gimg = PROBE, GIMG
    shutil.copy2(keys / "dp.pub", oldkeys / "dp.pub")
    for f in oldkeys.iterdir():
        os.chown(f, 5101, 5100)
    os.chmod(oldkeys, 0o755)
    ipc = f"{P}_stargate-ipc"

    def probe_status(keydir_args):
        return subprocess.run(["docker", "run", "--rm", "--user", "5101:5100", "-v", f"{ipc}:/run/stargate", *keydir_args,
                               "-v", f"{ROOT}:/src", "-w", "/src", gimg, "/src/target/stargate-wireprobe", "status",
                               "-socket", "/run/stargate/dp.sock"], capture_output=True, text=True, timeout=120)
    cur = probe_status(["-v", f"{P}_stargate-keys:/etc/stargate/keys:ro"])
    check("rotated (current) CP identity accepted by DP", probe.exists() and cur.returncode == 0, cur.stdout.strip()[-200:])
    # A refusal is a failed RPC after the keys loaded and the dial ran; a
    # setup error (unreadable key, missing binary) is not a refusal.
    old = probe_status(["-v", f"{oldkeys}:/etc/stargate/keys:ro"])
    check("pre-rotation (old) CP identity refused by DP",
          old.returncode != 0 and "GetStatus with correct metadata: code=Unavailable" in old.stderr, old.stderr.strip()[-300:])
    for f in oldkeys.iterdir():
        subprocess.run(["shred", "-u", str(f)])
    oldkeys.rmdir()

    # 7b. TLS session resumption across a second CP rotation (A2 "resumption").
    resumption_phase()

    # 8. Post-rotation reload with a revocation: phone removed.
    write_tokens("laptop")
    run(C + ["restart", "stargate-control"])
    s = await_status(0, "ACKNOWLEDGED(", 1200)
    check("post-rotation reload acknowledged", "ACKNOWLEDGED(" in s and s != gen1, s)
    check("revoked phone denied after acknowledged reload", auth_state("phone") == "denied")
    check("laptop still admitted", auth_state("laptop") == "ok")

    # 9. Idle reload: CP down well past the 60 s IPC channel cap, DP idle, then
    # a new credential set is delivered by the restarted CP.
    run(C + ["stop", "stargate-control"])
    time.sleep(180)
    write_tokens("laptop", "tablet")
    run(C + ["start", "stargate-control"])
    s = await_status(0, "ACKNOWLEDGED(", 1200)
    check("idle reload (180 s CP outage) acknowledged", "ACKNOWLEDGED(" in s, s)
    check("tablet admitted after idle reload", auth_state("tablet") == "ok")
    check("phone still denied", auth_state("phone") == "denied")
    newer_state_gen = s
    run(C + ["stop", "stargate-control"])
    new_state = backup("state-laptop-tablet")

    # 10. DP restart with CP down restores the last acknowledged generation.
    snap = vol("stargate-dp-state") / "dp-snapshot.json"
    snap_hash = hashlib.sha256(snap.read_bytes()).hexdigest()
    run(C + ["restart", "stargate-dp"])
    check("DP listener after restart with CP down", wait_listener())
    check("DP restart: laptop admitted from snapshot", auth_state("laptop") == "ok")
    check("DP restart: tablet admitted from snapshot", auth_state("tablet") == "ok")
    check("DP restart: revoked phone stays denied", auth_state("phone") == "denied")
    tb = tor_bytes("laptop")
    check("CP-down, post-DP-restart Tor-routed destination bytes", tb == "ok", tb)
    check("snapshot unchanged by CP-down DP restart", hashlib.sha256(snap.read_bytes()).hexdigest() == snap_hash)

    # 11. Supported rollback: CP state restored from the older backup (phone
    # still listed) must be refused as stale; the revocation survives.
    restore(old_state)
    write_tokens("laptop", "phone")
    run(C + ["start", "stargate-control"])
    s = await_status(40, "STALE_CONFLICT", 1200)
    check("rollback of CP state reported STALE_CONFLICT", "STALE_CONFLICT" in s, s)
    time.sleep(15)
    check("rollback: revoked phone still denied", auth_state("phone") == "denied")
    check("rollback: tablet still admitted (DP kept newer state)", auth_state("tablet") == "ok")
    # Recovery option 1 (restore the newer CP state).
    run(C + ["stop", "stargate-control"])
    restore(new_state)
    write_tokens("laptop", "tablet")
    run(C + ["start", "stargate-control"])
    s = await_status(0, "ACKNOWLEDGED(", 1200)
    check("recovery option 1 re-acknowledged", "ACKNOWLEDGED(" in s, f"{s} (before: {newer_state_gen})")
    check("phone denied after recovery", auth_state("phone") == "denied")

    # 12. Operational journal policy: no container log driver, no state files
    # beyond the allowlisted stores.
    ids = run(C + ["ps", "-aq"]).stdout.split()
    drivers = {run(["docker", "inspect", "--format", "{{.Name}} {{.HostConfig.LogConfig.Type}}", i]).stdout.strip() for i in ids}
    check("every stack container uses logging driver none", all(d.endswith(" none") for d in drivers), "; ".join(sorted(drivers)))
    cp_files = sorted(str(p.relative_to(vol("stargate-control-state"))) for p in vol("stargate-control-state").rglob("*"))
    dp_files = sorted(str(p.relative_to(vol("stargate-dp-state"))) for p in vol("stargate-dp-state").rglob("*"))
    check("CP state volume holds only the SQLite store", all(f.startswith("control.db") for f in cp_files), ", ".join(cp_files))
    check("DP state volume holds only the auth snapshot", all(f.startswith("dp-snapshot.json") for f in dp_files), ", ".join(dp_files))
    rows = db_rows()
    now_hour = int(time.time()) // 3600 * 3600
    check("final aggregates completed hours only", bool(rows) and all(r[0] < now_hour for r in rows), f"{len(rows)} rows")

    for b in (old_state, new_state):
        shutil.rmtree(b)


# Completion guard (Constitution VII: an unrun check is never PASS). Exit 0
# means every name below was recorded PASS at least the stated number of times
# for the selected mode, and nothing else failed. test_t155_stack.py derives
# the names from the check()/require() calls in this file and fails on any
# difference, so a new or renamed check cannot be left out of the guard.
_COMMON_FOCUSED = ("scripts/stargate init on clean volumes", "authenticated reload acknowledged")
_TRAFFIC = {
    # traffic_publication_phase: at least two rounds before the boundary and
    # three after it; three same-hour samples, one more before the wait, the
    # boundary sample and three after it.
    "traffic publication positive control: authenticated Tor destination bytes": 5,
    "GetStatus excludes active/future traffic hours": 8,
    "previously published traffic rows remain immutable": 8,
    "DP process unchanged during traffic publication": 8,
    "repeated same-hour GetStatus reads after traffic": 1,
    "real UTC hour boundary crossed on the running DP": 1,
    "nonzero completed TOR traffic row published": 1,
    "completed traffic row unchanged after more Tor traffic": 3,
    "traffic publication DP identity unchanged across real rollover": 1,
}
_RESUMPTION = (
    "DP process unchanged across the resumption probe",
    "resumption positive control: DP resumed the offered ticket before rotation",
    "old CP identity on pin-verified selected PSK path gets no RPC answered",
    "old CP identity refused on a full handshake after rotation",
    "rotated CP identity answered (DP re-read the pin; the refusals are not an outage)",
    "wireprobe resume exit 0",
    "CP restarted on the rotated key: token delivery acknowledged",
)
_FULL = (
    "fresh project volumes before init",
    "scripts/stargate init on clean volumes",
    "no tokens.yaml: status is not ACKNOWLEDGED",
    "no auth state admits nobody",
    "authenticated reload acknowledged",
    "laptop admitted",
    "phone admitted",
    "unknown token denied (01 FF)",
    "Tor-routed destination bytes (CP up)",
    "persisted aggregates are completed hours only",
    "retention removes an expired (8-day) bucket",
    "retention keeps an in-window bucket (positive control)",
    "still completed hours only after CP restart",
    "label-only predecessor DP listening",
    "connect_refusal.py (HTTP silent close, traced no Tor connect, SOCKS Tor bytes, snapshot preserved)",
    "reload after connect_refusal acknowledged",
    *(f"wire runtime row R{n} PASS (not SKIP)" for n in range(1, 10)),
    "inter_plane_wire_test.sh exit 0",
    "rotated (current) CP identity accepted by DP",
    "pre-rotation (old) CP identity refused by DP",
    "post-rotation reload acknowledged",
    "revoked phone denied after acknowledged reload",
    "laptop still admitted",
    "idle reload (180 s CP outage) acknowledged",
    "tablet admitted after idle reload",
    "phone still denied",
    "DP listener after restart with CP down",
    "DP restart: laptop admitted from snapshot",
    "DP restart: tablet admitted from snapshot",
    "DP restart: revoked phone stays denied",
    "CP-down, post-DP-restart Tor-routed destination bytes",
    "snapshot unchanged by CP-down DP restart",
    "rollback of CP state reported STALE_CONFLICT",
    "rollback: revoked phone still denied",
    "rollback: tablet still admitted (DP kept newer state)",
    "recovery option 1 re-acknowledged",
    "phone denied after recovery",
    "every stack container uses logging driver none",
    "CP state volume holds only the SQLite store",
    "DP state volume holds only the auth snapshot",
    "final aggregates completed hours only",
)
MANDATORY = {
    None: {**dict.fromkeys(_FULL, 1), **_TRAFFIC, **dict.fromkeys(_RESUMPTION, 1)},
    "resumption": {**dict.fromkeys(_COMMON_FOCUSED, 1), **dict.fromkeys(_RESUMPTION, 1),
                   "laptop still admitted after the CP rotation": 1},
    "traffic": {**dict.fromkeys(_COMMON_FOCUSED, 1), **_TRAFFIC},
}


def missing_mandatory(only, results):
    """Mandatory checks of the mode not recorded PASS often enough."""
    passed = {}
    for r in results:
        if r["result"] == "PASS":
            passed[r["check"]] = passed.get(r["check"], 0) + 1
    return [f"{name} ({passed.get(name, 0)}/{need})" for name, need in MANDATORY[only].items()
            if passed.get(name, 0) < need]


if __name__ == "__main__":
    try:
        main_focused() if ONLY else main()
    except Exception as exc:  # recorded, never converted to PASS
        check("stack phase completed without harness error", False, f"{type(exc).__name__}: {str(exc)[-600:]}")
    except BaseException as exc:  # KeyboardInterrupt, SystemExit: an interrupted run is not a result
        check("stack run incomplete: interrupted before its checks finished", False, type(exc).__name__)
    finally:
        try:
            down = subprocess.run(C + ["down", "-v", "--remove-orphans"], cwd=ROOT, env=ENV, capture_output=True, timeout=300)
            if down.returncode:  # containers or volumes may be left behind: not a clean reset
                check("stack cleanup (compose down) completed", False, f"exit {down.returncode}")
        except BaseException as exc:  # a failed or interrupted cleanup is reported, not swallowed
            check("stack cleanup (compose down) completed", False, type(exc).__name__)
        missing = missing_mandatory(ONLY, RESULTS)
        if missing:
            check("stack run incomplete: mandatory checks not recorded as PASS", False,
                  f"incomplete, {len(missing)} missing: " + "; ".join(missing))
        (EV / "results.json").write_text(json.dumps(RESULTS, indent=2) + "\n")
        fails = [r for r in RESULTS if r["result"] != "PASS"]
        log(f"T155 STACK: {len(RESULTS) - len(fails)} PASS, {len(fails)} FAIL")
        sys.exit(1 if fails else 0)
