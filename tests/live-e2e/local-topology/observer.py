# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""T165 observer checks against the disposable Local deployment.

Called after the real operator init by run.py. The fake Tor control listener
is used only after the disposable Tor container is stopped; it never sends a
control command to an operator stack. CP-down routing uses the real Tor
sidecar. Raw artifacts stay under target/live-e2e/.
"""

import json
import hashlib
import os
import re
import secrets
import shutil
import select
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "tests/live-e2e/local-topology/observer_probe.go"
READY = '250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\r\n250 OK\r\n'
NOT_READY = '250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=42 TAG=loading SUMMARY="Loading"\r\n250 OK\r\n'
RAW_MARKER = "T165_RAW_REPLY_MARKER"


def checked(argv, *, timeout=60):
    result = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} failed with exit {result.returncode}: {result.stderr[-200:]}")
    return result.stdout.strip()


def mounts(inspect):
    return {entry["Destination"]: entry for entry in inspect["Mounts"]}


def assert_boundary(cp, observer, tor):
    """Fail closed on actual container identity, network and mounted authority."""
    if cp["Config"]["User"] != "5101:5100" or observer["Config"]["User"] != "5103:5100":
        raise AssertionError("CP/observer runtime identity drift")
    if cp["HostConfig"]["NetworkMode"] != "none" or observer["HostConfig"]["NetworkMode"] != "none":
        raise AssertionError("CP/observer has a Docker network")
    cm, om, tm = mounts(cp), mounts(observer), mounts(tor)
    for consumer, owned in (("CP", cm), ("observer", om), ("Tor", tm)):
        if "/var/run/docker.sock" in owned:
            raise AssertionError(f"{consumer} has Docker socket")
    if "/var/lib/tor" in cm or "/run/tor-control" in cm or "/run/stargate-tor" in cm:
        raise AssertionError("CP has Tor state, control or SOCKS fabric")
    if "/etc/stargate/observer-keys" in cm or "/etc/stargate/keys" in om:
        raise AssertionError("application/observer key separation failed")
    if "/etc/stargate/observer-keys" not in om or om["/etc/stargate/observer-keys"]["RW"]:
        raise AssertionError("observer key volume is not read-only")
    if "/run/stargate-tor-observer" not in cm or cm["/run/stargate-tor-observer"]["RW"]:
        raise AssertionError("CP lacks read-only health fabric")
    if "/run/stargate-tor-observer" not in om or not om["/run/stargate-tor-observer"]["RW"]:
        raise AssertionError("observer cannot own health fabric")
    if "/run/tor-control" not in om or om["/run/tor-control"]["RW"]:
        raise AssertionError("observer lacks read-only Tor control subpath")
    state_mounts = [entry for entry in observer["HostConfig"]["Mounts"]
                    if entry.get("Target") == "/run/tor-control"]
    if len(state_mounts) != 1 or state_mounts[0].get("VolumeOptions", {}).get("Subpath") != "control":
        raise AssertionError("observer Tor control subpath is not constrained")
    if "/run/stargate-tor" in om or "/run/stargate-tor-observer" in tm:
        raise AssertionError("sidecar fabrics crossed")
    for service in (cp, observer, tor):
        assert_silent_capture(service)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", observer["Config"]["Image"]):
        raise AssertionError("observer image is not immutable")


def assert_silent_capture(service):
    health = service["Config"].get("Healthcheck", {}).get("Test", [])
    if health not in ([], ["NONE"]) or "Health" in service.get("State", {}):
        raise AssertionError("Docker health history is enabled or retained")
    if service["HostConfig"].get("LogConfig", {}).get("Type") != "none" or service.get("LogPath"):
        raise AssertionError("Docker operational logging is enabled")


def assert_empty_archive(result):
    # Engine 29 refuses reads of a disabled driver. Accept only that exact
    # static denial, with no stdout, after inspection proved logging=none.
    denial = "Error response from daemon: configured logging driver does not support reading\n"
    if not result.stdout and ((result.returncode == 0 and not result.stderr) or
                              (result.returncode == 1 and result.stderr == denial)):
        return
    raise AssertionError("operational output capture is not empty or unreadable")


def await_tor_ready(observer_id, timeout=300):
    """Current cookie-authenticated Tor readiness through the existing observer."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(["docker", "exec", observer_id,
                                     "/opt/stargate/tor-observer", "--check-ready"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=6)
            if result.returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise AssertionError("authenticated current Tor readiness unavailable")


def source_hash():
    sources = ("data-plane/go.mod", "data-plane/go.sum", "proto/go.mod", "proto/go.sum",
               "data-plane/cmd/tor-observer/main.go", "sidecars/tor-observer/Dockerfile")
    manifest = "".join(f"{source} {hashlib.sha256((ROOT / source).read_bytes()).hexdigest()}\n"
                       for source in sources)
    return hashlib.sha256(manifest.encode("ascii")).hexdigest()


class FakeTor:
    def __init__(self, path):
        self.path = path
        self.reply = READY
        self.commands = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.listener = None
        self.thread = None

    def __enter__(self):
        self.path.unlink(missing_ok=True)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        os.chown(self.path, 5103, 5103)
        os.chmod(self.path, 0o660)
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("fake Tor listener did not stop")
        self.path.unlink(missing_ok=True)

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.exchange, args=(conn,), daemon=True).start()

    def exchange(self, conn):
        with conn:
            conn.settimeout(6)
            reader = conn.makefile("rb")
            while True:
                try:
                    line = reader.readline(8193)
                except (OSError, TimeoutError):
                    return
                if not line:
                    return
                # Record only the command name; AUTHENTICATE carries cookie bytes.
                name = line.split(b" ", 1)[0].strip().decode("ascii", "replace")
                with self.lock:
                    self.commands.append(name)
                    reply = self.reply
                if name == "AUTHENTICATE":
                    conn.sendall(b"250 OK\r\n")
                elif name == "GETINFO" and line == b"GETINFO status/bootstrap-phase\r\n":
                    if reply is None:
                        time.sleep(5)  # observer's four-second budget must win
                        return
                    conn.sendall(reply.encode("ascii"))
                elif name == "QUIT":
                    try:
                        conn.sendall(b"250 closing connection\r\n")
                    except BrokenPipeError:
                        pass  # the observer writes QUIT while closing its side
                    return
                else:
                    conn.sendall(b"510 rejected\r\n")

    def snapshot(self):
        with self.lock:
            return list(self.commands)

    def set_reply(self, reply):
        with self.lock:
            self.reply = reply


def assert_fixed_queries(commands):
    if commands != ["AUTHENTICATE", "GETINFO", "QUIT"]:
        raise AssertionError(f"observer sent unexpected Tor commands: {commands}")


def assert_no_commands(before, after):
    if after != before:
        raise AssertionError("refused CP input reached a Tor command")


def assert_safe_command_stream(commands):
    state = 0
    for name in commands:
        if state == 0 and name == "AUTHENTICATE":
            state = 1
        elif state == 1 and name == "GETINFO":
            state = 2
        elif state == 2 and name == "QUIT":
            state = 0
        elif state == 2 and name == "AUTHENTICATE":
            state = 1  # a timed-out GETINFO has no QUIT
        else:
            raise AssertionError(f"unexpected Tor command or order: {name}")


class EventObservation:
    """Bounded volatile test-only WatchEvents consumer, never a Docker journal."""

    TOKENS = {"STARTED": ("STARTED", "container_start"),
              "HEALTHY": ("HEALTHY", "healthcheck_pass"),
              "UNHEALTHY": ("UNHEALTHY", "healthcheck_fail")}

    def __init__(self, binary, ipc, keys):
        self.argv = [str(binary), "events", str(ipc), str(keys)]
        self.events = []
        self.lock = threading.Lock()
        self.failed = False
        self.closing = False
        self.process = None
        self.reader = None

    def __enter__(self):
        self.process = subprocess.Popen(self.argv, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True)
        try:
            ready, _, _ = select.select([self.process.stdout], [], [], 10)
            if not ready or self.process.stdout.readline(32) != "SUBSCRIBED\n":
                raise AssertionError("authenticated event subscriber did not connect")
            self.reader = threading.Thread(target=self.read, daemon=True)
            self.reader.start()
            # Subscription send is not server registration; positive events
            # below remain mandatory. Allow the real handler to attach first.
            time.sleep(1)
            self.snapshot()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def read(self):
        while line := self.process.stdout.readline(32):
            with self.lock:
                token = line.removesuffix("\n")
                if line != token + "\n" or token not in self.TOKENS or len(self.events) >= 16:
                    self.failed = True
                    return
                self.events.append(self.TOKENS[token])
        with self.lock:
            if not self.closing:
                self.failed = True

    def snapshot(self):
        with self.lock:
            if self.failed or self.process.poll() is not None:
                raise AssertionError("event subscriber closed or violated the finite boundary")
            return list(self.events)

    def __exit__(self, *_):
        with self.lock:
            self.closing = True
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.reader is not None:
            self.reader.join(timeout=5)
            if self.reader.is_alive():
                raise AssertionError("event subscriber reader did not stop")
        self.process.stdout.close()
        self.events.clear()


def assert_event_sequence(actual, expected):
    if actual != expected:
        raise AssertionError("CP→DP event sequence mismatch (raw events not retained)")


def assert_cp_capture(decoded, tor_address):
    if not re.search(r">\s+127\.0\.0\.1\.39051:", decoded):
        raise AssertionError("CP namespace capture positive control absent")
    if re.search(r">\s+" + re.escape(tor_address) + r"\.9051:", decoded):
        raise AssertionError("CP packet escaped toward Tor control")


def await_commands(fake, count):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        got = fake.snapshot()
        if len(got) >= count:
            return got
        time.sleep(0.01)
    raise AssertionError("fake Tor control did not record the positive command sequence")


def dp_events(observation):
    # Same wire subscription as DP; this measures CP publication, not a DP receipt journal.
    return observation.snapshot()


def await_event_sequence(dp_id, baseline, expected, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = dp_events(dp_id)[baseline:]
        if observed == expected:
            return
        if observed != expected[:len(observed)]:
            assert_event_sequence(observed, expected)
        time.sleep(2)
    assert_event_sequence(dp_events(dp_id)[baseline:], expected)


def sample_cursor(commands, before, expected):
    delta = commands[before:]
    if delta[:len(expected)] == expected:
        return before + len(expected)
    if delta != expected[:len(delta)]:
        raise AssertionError(f"production CP sent unexpected Tor commands: {delta}")
    return None


def await_control_sample(fake, before, expected, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        cursor = sample_cursor(fake.snapshot(), before, expected)
        if cursor is not None:
            return cursor
        time.sleep(0.2)
    raise AssertionError("production CP did not sample fake Tor control")


def receive_exact(conn, count):
    data = bytearray()
    while len(data) < count:
        part = conn.recv(count - len(data))
        if not part:
            raise AssertionError("SOCKS fixture closed before a complete frame")
        data.extend(part)
    return bytes(data)


def socks_auth(conn, token):
    conn.sendall(b"\x05\x01\x02")
    if receive_exact(conn, 2) != b"\x05\x02":
        raise AssertionError("DP refused SOCKS user/password method")
    user = b"t165.invalid"
    conn.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(token)]) + token)
    return receive_exact(conn, 2)


def assert_cp_down_forwarding(evidence, prefix, project, cp_id, observer_id):
    # A disposable test credential is installed after the clean-host operator
    # startup. CP pushes its verifier through the real authenticated reload.
    token = secrets.token_hex(16).encode("ascii")
    config = Path(checked(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}",
                           project + "_stargate-control-config"])) / "tokens.yaml"
    config.write_text("tokens:\n  - label: t165-probe\n    token: " + token.decode("ascii") + "\n")
    os.chown(config, 5101, 5100)
    os.chmod(config, 0o600)
    # Under QEMU TCG a healthy CP can miss the gRPC client's five-second
    # transport deadline while the JVM and DP contend for emulated CPU. The
    # documented next-boot resync retries the same real CP→DP reload. Each
    # attempt waits for the verifier at DP; no harness writes DP state.
    for attempt in range(1, 4):
        checked(prefix + ["restart", "stargate-control"], timeout=90)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", 8881), timeout=2) as conn:
                    conn.settimeout(3)
                    if socks_auth(conn, token) == b"\x01\x00":
                        break
            except (OSError, AssertionError):
                pass
            time.sleep(2)
        else:
            continue
        break
    else:
        raise AssertionError("CP resync did not deliver the disposable token verifier to DP")
    evidence.joinpath("T165-token-reload.txt").write_text(
        f"CP startup delivered the disposable verifier to DP on attempt {attempt}.\n")
    print(f"PASS: CP→DP authenticated token reload (attempt {attempt})", flush=True)

    checked(prefix + ["stop", "stargate-control"], timeout=90)
    if checked(["docker", "inspect", "--format", "{{.State.Running}}", cp_id]) != "false":
        raise AssertionError("CP container remained running")
    await_tor_ready(observer_id)
    with socket.create_connection(("127.0.0.1", 8881), timeout=3) as conn:
        conn.settimeout(40)
        if socks_auth(conn, token) != b"\x01\x00":
            raise AssertionError("CP-down DP authentication failed")
        target = b"example.com"
        conn.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target + (80).to_bytes(2, "big"))
        if receive_exact(conn, 10) != b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00":
            raise AssertionError("CP-down DP did not route through Tor")
        conn.sendall(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        if not conn.recv(128).startswith(b"HTTP/"):
            raise AssertionError("CP-down DP forwarding did not return destination bytes")
    evidence.joinpath("T165-cp-down.txt").write_text(
        "CP stopped and authenticated current Tor readiness READY: disposable credential authenticated "
        "at DP; a SOCKS CONNECT to example.com:80 through Tor returned an HTTP "
        "response. No token or response bytes are retained.\n")


def cp_packet_capture(evidence, cp_pid, tor_address, cp_probe):
    """A live CP-namespace positive socket control makes absence observable."""
    pcap = evidence / "T165-cp-any.pcap"
    fixture_code = ("import socket; s=socket.socket(); s.bind(('127.0.0.1',39051)); "
                    "s.listen(1); print('READY',flush=True); c,_=s.accept(); c.close(); s.close()")
    fixture = subprocess.Popen(["nsenter", "-t", str(cp_pid), "-n", "python3", "-u", "-c", fixture_code],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    recorder = None
    try:
        ready, _, _ = select.select([fixture.stdout], [], [], 8)
        if not ready or fixture.stdout.readline().strip() != "READY":
            raise AssertionError("CP capture fixture did not bind")
        recorder = subprocess.Popen(["nsenter", "-t", str(cp_pid), "-n", "tcpdump", "-i", "any",
                                     "-U", "-w", str(pcap), "tcp port 39051 or tcp port 9051"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        startup = ""
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            ready, _, _ = select.select([recorder.stderr], [], [],
                                        max(0, deadline - time.monotonic()))
            if not ready:
                break
            chunk = os.read(recorder.stderr.fileno(), 4096)
            if not chunk:
                break
            startup += chunk.decode("utf-8", "replace")
            if "listening on" in startup:
                break
        if "listening on" not in startup:
            raise AssertionError(f"CP namespace packet recorder did not become ready: {startup.strip()}")
        positive_code = "import socket; s=socket.create_connection(('127.0.0.1',39051),2); s.close()"
        checked(["nsenter", "-t", str(cp_pid), "-n", "python3", "-c", positive_code])
        for address in ("tor:9051", f"{tor_address}:9051", "127.0.0.1:9051", "[::1]:9051"):
            if cp_probe("tcp", address) != "TCP_REFUSED":
                raise AssertionError("CP raw Tor TCP path reachable")
    finally:
        if recorder is not None:
            recorder.send_signal(signal.SIGINT)
            _, stderr = recorder.communicate(timeout=10)
        else:
            stderr = ""
        if fixture.poll() is None:
            fixture.terminate()
        fixture.wait(timeout=10)
        fixture.stdout.close()
        fixture.stderr.close()
    if recorder.returncode != 0 or not pcap.is_file() or pcap.stat().st_size <= 24 or \
            not re.search(r"(?m)^0 packets? dropped by kernel$", stderr):
        raise AssertionError("CP packet recorder failed or dropped evidence")
    decoded = checked(["tcpdump", "-nn", "-r", str(pcap)], timeout=10)
    assert_cp_capture(decoded, tor_address)
    evidence.joinpath("T165-cp-any.decoded.txt").write_text(decoded + "\n")


def observe_phase(observation, fake, reply, expected, command_names, action=None):
    before = len(fake.snapshot())
    fake.set_reply(reply)
    if action is not None:
        action()
    if command_names is None:
        time.sleep(22)  # two real ten-second monitor polls with observer down
    else:
        for _ in range(2):
            before = await_control_sample(fake, before, command_names, timeout=30)
    # GETINFO is recorded before Tor replies (or times out). Let CP's full
    # six-second call budget expire before asserting that the last sample
    # produced no event; otherwise a false timeout event can escape the window.
    time.sleep(6)
    await_event_sequence(observation, 0, expected, timeout=3)
    time.sleep(1)  # let the last completed sample reach the subscriber
    assert_event_sequence(dp_events(observation), expected)


def exercise_cp_events(evidence, fake, prefix, project, cp_id, observer_id, binary):
    """Observe production CP publication through bounded test-only IPC windows."""
    checked(prefix + ["stop", "tor-observer"], timeout=90)
    fake.set_reply(NOT_READY)
    checked(["docker", "kill", "--signal=CONT", cp_id])
    ipc = Path(checked(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}",
                        project + "_stargate-ipc"])) / "control.sock"
    keys = Path(checked(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}",
                         project + "_stargate-keys"]))
    old_inode = ipc.stat().st_ino if ipc.exists() else None
    checked(prefix + ["restart", "stargate-control"], timeout=90)
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if ipc.is_socket() and ipc.stat().st_ino != old_inode:
            break
        time.sleep(2)
    else:
        raise AssertionError("production CP event server did not recreate its socket")
    results = {}

    def phase(name, reply, expected, command_names, action=None):
        # Each fresh TLS connection gets one <35s window, below T148's
        # channel lifetime. Any early EOF/rotation fails; no replay or gap is hidden.
        with EventObservation(binary, ipc, keys) as observation:
            observe_phase(observation, fake, reply, expected, command_names, action)
            results[name] = {"exact_events": True, "count": len(expected), "reconnects": 0}

    query = ["AUTHENTICATE", "GETINFO", "QUIT"]
    phase("initial-not-ready-and-repeat", NOT_READY, [("STARTED", "container_start")], query,
          lambda: checked(["docker", "start", observer_id], timeout=90))
    phase("ready-and-repeat", READY, [("HEALTHY", "healthcheck_pass")], query)
    phase("not-ready-and-repeat", NOT_READY, [("UNHEALTHY", "healthcheck_fail")], query)
    phase("malformed-and-repeat", "551 " + RAW_MARKER + "\r\n", [], query)
    phase("timeout-and-repeat", None, [], ["AUTHENTICATE", "GETINFO"])
    phase("ready-after-failures", READY, [("HEALTHY", "healthcheck_pass")], query)
    phase("observer-down-and-repeat", READY, [("UNHEALTHY", "healthcheck_fail")], None,
          lambda: checked(prefix + ["stop", "tor-observer"], timeout=90))
    phase("observer-recovery-and-repeat", READY, [("HEALTHY", "healthcheck_pass")], query,
          lambda: checked(["docker", "start", observer_id], timeout=90))
    checked(["docker", "kill", "--signal=STOP", cp_id])
    time.sleep(6)
    assert_safe_command_stream(fake.snapshot())
    evidence.joinpath("T174-cp-events.json").write_text(json.dumps({
        "observation": "ephemeral authenticated test subscriber; production CP publisher",
        "phases": results, "no_duplicate_or_false_lifecycle_events": True,
        "tor_command_allowlist": True,
    }, indent=2) + "\n")
    print("PASS: deployed CP finite event windows and observer-down recovery", flush=True)


def validate(evidence, env):
    project = env["STARGATE_PROJECT"]
    prefix = ["docker", "compose", "-p", project, "-f", str(ROOT / "compose/docker-compose.local.yml"),
              "--env-file", env["STARGATE_ENV_FILE"]]
    ids = {service: checked(prefix + ["ps", "-q", service])
           for service in ("stargate-control", "tor-observer", "tor", "stargate-dp")}
    if any(not value for value in ids.values()):
        raise AssertionError("clean-host init did not start all four services")
    inspected = {service: json.loads(checked(["docker", "inspect", value]))[0]
                 for service, value in ids.items()}
    cp, observer, tor = (inspected[name] for name in ("stargate-control", "tor-observer", "tor"))
    assert_boundary(cp, observer, tor)
    assert_silent_capture(inspected["stargate-dp"])
    image_id = observer["Image"]
    label = checked(["docker", "image", "inspect", "--format",
                     '{{index .Config.Labels "org.opencontainers.image.source-sha256"}}', image_id])
    if label != source_hash():
        raise AssertionError("observer image source hash differs from tested candidate")
    evidence.joinpath("T165-observer-identity.json").write_text(json.dumps({
        "project": project, "cp_id": ids["stargate-control"], "observer_id": ids["tor-observer"],
        "tor_id": ids["tor"], "dp_id": ids["stargate-dp"], "observer_image": image_id,
        "observer_source_sha256": label,
        "images": {name: item["Image"] for name, item in inspected.items()},
        "harness_sha256": {name: hashlib.sha256((SOURCE.parent / name).read_bytes()).hexdigest()
                           for name in ("observer.py", "observer_probe.go", "run.py")},
        "source_head": checked(["git", "rev-parse", "HEAD"]),
        "cp_mounts": sorted(mounts(cp)), "observer_mounts": sorted(mounts(observer)),
    }, indent=2) + "\n")
    binary = evidence / "observer-probe"
    build_env = os.environ.copy()
    build_env.update(GOTOOLCHAIN="go1.26.3", CGO_ENABLED="0")
    subprocess.run(["go", "build", "-o", str(binary), str(SOURCE)], cwd=ROOT, env=build_env,
                   check=True, timeout=120, capture_output=True)
    # Docker rejects `cp` into a read-only rootfs even when /tmp is a writable
    # tmpfs. Place the test executable in CP's disposable config volume, which
    # stays read-only inside CP and is not mounted in Tor, observer or DP.
    config = Path(checked(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}",
                           project + "_stargate-control-config"])) / "t165-observer-probe"
    shutil.copyfile(binary, config)
    os.chown(config, 5101, 5100)
    os.chmod(config, 0o550)

    def cp_probe(*args):
        try:
            return checked(["docker", "exec", "--user", "5101:5100", ids["stargate-control"],
                            "/etc/stargate/t165-observer-probe", *args], timeout=10)
        except RuntimeError as failure:
            raise RuntimeError(f"CP probe mode {args[0]} failed: {failure}") from failure

    if cp_probe("identity") != "IDENTITY_OK":
        raise AssertionError("CP production identity/filesystem probe failed")
    bridge = next(iter(tor["NetworkSettings"]["Networks"].values()))["IPAddress"]
    cp_packet_capture(evidence, cp["State"]["Pid"], bridge, cp_probe)
    initial = cp_probe("health")
    if initial not in ("READY/1", "NOT_READY/1"):
        raise AssertionError("production observer health positive control absent")
    for mode in ("wrong-auth", "absent-auth", "no-eof"):
        if cp_probe(mode) != "REFUSED":
            raise AssertionError("invalid caller/request received a token")

    # Stop only the disposable Tor sidecar. Keep CP's process alive as the
    # production namespace/UID fixture while pausing its periodic sampler.
    checked(prefix + ["stop", "tor"], timeout=90)
    checked(["docker", "kill", "--signal=STOP", ids["stargate-control"]])
    state_name = project + "_stargate-tor-state"
    state = checked(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}", state_name])
    socket_path = Path(state) / "control/tor-control.sock"
    matrix = []
    try:
        with FakeTor(socket_path) as fake:
            # Drain any query started before the CP was stopped. The fake's
            # log starts after the real Tor listener has been removed.
            time.sleep(0.2)
            bad = [b"GETINFO stream-status\n", b"GETINFO circuit-status\n",
                   b"GETCONF SocksPort\n", b"SETCONF SocksPort=9050\n",
                   b"SETEVENTS STREAM\n", b"ATTACHSTREAM 1 1\n",
                   b"ADD_ONION NEW:BEST\n", b"SIGNAL NEWNYM\n",
                   b"COMMAND arbitrary\n", b"HEALTH/2\n", b"HEALTH/1 extra\n",
                   b"HEALTH/1\nX", b"HEALTH/1\r\n"]
            baseline = fake.snapshot()
            for mode in ("wrong-auth", "absent-auth", "no-eof"):
                if cp_probe(mode) != "REFUSED":
                    raise AssertionError("invalid caller/request received a token")
                assert_no_commands(baseline, fake.snapshot())
            for request in bad:
                if cp_probe("request", request.hex()) != "REFUSED":
                    raise AssertionError("forbidden CP input received a token")
                matrix.append(request.split(b" ", 1)[0].decode("ascii", "replace").strip())
                assert_no_commands(baseline, fake.snapshot())
            if cp_probe("health") != "READY/1":
                raise AssertionError("fake positive READY control failed")
            assert_fixed_queries(await_commands(fake, len(baseline) + 3)[len(baseline):])
            baseline = fake.snapshot()
            fake.reply = NOT_READY
            if cp_probe("health") != "NOT_READY/1":
                raise AssertionError("fake NOT_READY control failed")
            assert_fixed_queries(await_commands(fake, len(baseline) + 3)[len(baseline):])
            baseline = fake.snapshot()
            fake.reply = "551 " + RAW_MARKER + "\r\n"
            if cp_probe("health") != "UNAVAILABLE/1":
                raise AssertionError("malformed Tor reply did not become UNAVAILABLE")
            if await_commands(fake, len(baseline) + 3)[len(baseline):] != ["AUTHENTICATE", "GETINFO", "QUIT"]:
                raise AssertionError("malformed reply produced unexpected Tor command")
            baseline = fake.snapshot()
            fake.reply = None
            if cp_probe("health") != "UNAVAILABLE/1":
                raise AssertionError("Tor timeout did not become UNAVAILABLE")
            if await_commands(fake, len(baseline) + 2)[len(baseline):] != ["AUTHENTICATE", "GETINFO"]:
                raise AssertionError("timeout produced unexpected Tor command")
            evidence.joinpath("T165-probe-matrix.json").write_text(json.dumps({
                "forbidden_inputs": matrix, "real_health": initial,
                "invalid_auth_and_eof_non_arrival": True,
                "fake_ready": "READY/1", "fake_not_ready": "NOT_READY/1",
                "fake_malformed": "UNAVAILABLE/1", "fake_timeout": "UNAVAILABLE/1",
                "tor_command_allowlist": True,
            }, indent=2) + "\n")
            exercise_cp_events(evidence, fake, prefix, project, ids["stargate-control"],
                               ids["tor-observer"], binary)
    finally:
        checked(["docker", "kill", "--signal=CONT", ids["stargate-control"]])
        checked(prefix + ["start", "tor"], timeout=90)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if cp_probe("health") in ("READY/1", "NOT_READY/1"):
                break
        except RuntimeError:
            pass
        time.sleep(1)
    else:
        raise AssertionError("observer did not recover after Tor socket recreation")
    checked(prefix + ["restart", "tor-observer"], timeout=90)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if cp_probe("health") in ("READY/1", "NOT_READY/1"):
                break
        except RuntimeError:
            pass
        time.sleep(1)
    else:
        raise AssertionError("observer did not recover after restart")
    checked(prefix + ["stop", "tor-observer"], timeout=90)
    try:
        try:
            cp_probe("health")
        except RuntimeError:
            pass
        else:
            raise AssertionError("observer-down health unexpectedly succeeded")
    finally:
        checked(prefix + ["start", "tor-observer"], timeout=90)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            if cp_probe("health") in ("READY/1", "NOT_READY/1"):
                break
        except RuntimeError:
            pass
        time.sleep(1)
    else:
        raise AssertionError("observer-down recovery failed")
    for service in ("stargate-control", "tor-observer", "stargate-dp", "tor"):
        result = subprocess.run(["docker", "logs", ids[service]], capture_output=True, text=True, timeout=30)
        assert_empty_archive(result)
    state = Path(checked(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}",
                          project + "_stargate-control-state"]))
    for path in state.rglob("*"):
        if path.is_file() and RAW_MARKER.encode("ascii") in path.read_bytes():
            raise AssertionError("raw Tor reply reached CP state or audit rows")
    assert_cp_down_forwarding(evidence, prefix, project, ids["stargate-control"], ids["tor-observer"])
    print("PASS: T165 deployed observer boundary and CP-down authenticated Tor forwarding")
