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
# CP monitor timing (SidecarMonitor): a sample, its transition events, then a
# 10 s sleep; the CP's observer call is capped at 6 s. DELIVERY allows the
# published event to reach the subscriber. The CP event server's 40 s maximum
# connection age (36 s with grpc-java jitter; T148) bounds every window.
POLL_SECONDS = 10
CALL_BUDGET_SECONDS = 6
DELIVERY_SECONDS = 1


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
    if "/run/tor-health" not in om or om["/run/tor-health"]["RW"]:
        raise AssertionError("observer lacks read-only finite health publication")
    if "/run/tor-health" not in tm or not tm["/run/tor-health"]["RW"]:
        raise AssertionError("Tor cannot publish finite health")
    raw = [entry for entry in tor["Mounts"] if entry["Destination"] in ("/var/lib/tor", "/run/tor-fabric")]
    for consumer in (cp, observer):
        for entry in consumer["Mounts"]:
            for private in raw:
                source, forbidden = entry.get("Source", ""), private.get("Source", "")
                if ((private.get("Name") and entry.get("Name") == private["Name"]) or
                        (forbidden and (source == forbidden or source.startswith(forbidden + "/")))):
                    raise AssertionError("consumer has Tor authority through a source mount")
    if om["/run/tor-health"].get("Name") != tm["/run/tor-health"].get("Name"):
        raise AssertionError("publication is not the same output volume")
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
               "data-plane/cmd/tor-observer/main.go", "data-plane/internal/torhealth/health.go",
               "sidecars/tor-observer/Dockerfile")
    manifest = "".join(f"{source} {hashlib.sha256((ROOT / source).read_bytes()).hexdigest()}\n"
                       for source in sources)
    return hashlib.sha256(manifest.encode("ascii")).hexdigest()


class FakeTor:
    def __init__(self, path):
        self.path = path
        self.reply = READY
        self.generation = 0
        self.commands = []
        self.served_log = []
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
                    if name == "GETINFO":
                        # Which reply generation answered this sample (T196):
                        # only samples taken after a phase's trigger count.
                        self.served_log.append((len(self.commands) - 1, self.generation,
                                                time.monotonic()))
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
            self.generation += 1
            return self.generation

    def served(self):
        with self.lock:
            return list(self.served_log)


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
        self.close()

    def close(self):
        # Idempotent: the relay closes a window as soon as its successor has
        # attached, and its context exit then finds nothing left to do.
        with self.lock:
            if self.closing:
                return
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


def await_event_sequence(observation, baseline, expected, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        observed = dp_events(observation)[baseline:]
        if observed == expected:
            return
        if observed != expected[:len(observed)]:
            assert_event_sequence(observed, expected)
        time.sleep(0.2)
    assert_event_sequence(dp_events(observation)[baseline:], expected)


def sample_cursor(commands, before, expected):
    delta = commands[before:]
    if delta[:len(expected)] == expected:
        return before + len(expected)
    if delta != expected[:len(delta)]:
        raise AssertionError(f"production CP sent unexpected Tor commands: {delta}")
    return None


def await_reply_samples(fake, generation, expected, count, timeout=2 * POLL_SECONDS + CALL_BUDGET_SECONDS):
    """Return the GETINFO times of the first `count` complete samples answered
    by reply `generation`. A sample still reading an earlier reply when the
    phase was triggered never counts (T196). Each counted sample must have
    exactly the phase's command shape and follow the previous one directly."""
    deadline = time.monotonic() + timeout
    while True:
        served = fake.served()  # before the command log, which then covers it
        commands = fake.snapshot()
        times, cursor = [], None
        for index, generation_served, at in served:
            if generation_served != generation:
                continue
            start = index - 1
            if start < 0 or (cursor is not None and start != cursor):
                raise AssertionError("production CP sent unexpected Tor commands: "
                                     f"{commands[min(start, cursor or start):index + 1]}")
            cursor = sample_cursor(commands, start, expected)
            if cursor is None:
                break
            times.append(at)
            if len(times) == count:
                return times
        if time.monotonic() >= deadline:
            raise AssertionError("production CP did not sample fake Tor control")
        time.sleep(0.2)


def sleep_until(deadline):
    time.sleep(max(0.0, deadline - time.monotonic()))


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


def assert_cp_down_forwarding(evidence, prefix, project, cp_id, observer_id, quiesce=None):
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
    if quiesce is not None:
        quiesce()
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


# What each phase's asserted silence rests on (T196 round 2; recorded per phase).
ANCHOR_EVENT = "transition event received in this window before its repeat sample"
ANCHOR_ALLOWANCE = "1 s post-SUBSCRIBED allowance only; no event anchors registration"
# The deprecated reply the fake serves while a Docker action runs, so that the
# phase's transition can only happen after the anchored window has attached.
HOLD = "551 " + RAW_MARKER + "\r\n"
# Open an aligned window this long before the next expected monitor sample.
LEAD_SECONDS = 7


def await_fresh_sample(fake, timeout=2 * POLL_SECONDS + CALL_BUDGET_SECONDS):
    """Return the time of the next bootstrap query the fake records."""
    seen = len(fake.served())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        served = fake.served()
        if len(served) > seen:
            return served[-1][2]
        time.sleep(0.2)
    raise AssertionError("production CP did not sample fake Tor control")


def observe_phases(subscribe, fake, phases):
    """Observe CP publication through bounded, anchored test-only windows.

    T196: a subscriber's SUBSCRIBED line proves a sent request, not server
    registration, and the CP replays nothing. So a window may assert silence
    for a repeat sample only after it has itself received the phase's
    transition event (ANCHOR_EVENT). Phases that expect no event (malformed,
    timeout) have nothing to anchor them and keep one window resting on the
    1 s attach allowance, as before T196 (ANCHOR_ALLOWANCE). Windows are
    opened shortly before a monitor sample and waits are deadlines from
    observed samples, so each stays well below the CP's 40 s connection age
    (36 s with jitter; T148). Windows of different phases do not overlap and
    no continuity between them is claimed. No window reconnects, and an early
    closure fails the run.

    Phase kinds: "reply" (the fake's reply is the trigger), "silent" (no event
    expected), "start" (a Docker start; the fake holds HOLD during the action
    and the trigger follows once a second, anchored window has attached) and
    "down" (stopping the observer is the trigger, so its single window opens
    right after a sample and receives the transition itself).
    """
    open_windows, results = {}, {}

    def enter():
        window = subscribe()
        opened = time.monotonic()
        window.__enter__()
        open_windows[id(window)] = (window, opened)
        return window

    def retire(window, expected):
        assert_event_sequence(dp_events(window), expected)
        _, opened = open_windows.pop(id(window))
        window.close()
        return time.monotonic() - opened

    def settle_repeat(window, generation, command_names, expected):
        # T203: Tor samples are autonomous and no longer reveal CP's poll times.
        # Require a post-trigger publisher sample, then observe two entire CP
        # poll intervals and its separate call/delivery budget in this window.
        transition_at, = await_reply_samples(fake, generation, command_names, 1)
        if expected:
            await_event_sequence(window, 0, expected, timeout=max(
                0.0, transition_at + POLL_SECONDS + CALL_BUDGET_SECONDS + DELIVERY_SECONDS - time.monotonic()))
        sleep_until(transition_at + 2 * POLL_SECONDS + CALL_BUDGET_SECONDS + DELIVERY_SECONDS)

    try:
        for name, kind, reply, expected, command_names, action in phases:
            lifetimes = []
            if kind in ("reply", "silent"):
                if reply == READY:
                    # Drain a preceding four-second failed attempt before the
                    # bounded subscription. Previous phases are already non-READY;
                    # HOLD cannot hide their later transition into READY.
                    hold = fake.set_reply(HOLD)
                    await_reply_samples(fake, hold, ["AUTHENTICATE", "GETINFO", "QUIT"], 1)
                window = enter()
                generation = fake.set_reply(reply)
                settle_repeat(window, generation, command_names, expected)
                lifetimes.append(retire(window, expected))
            elif kind == "start":
                fake.set_reply(HOLD)
                # Expire the last cached READY before the slow Docker action.
                time.sleep(4.1)
                action()
                window = enter()
                generation = fake.set_reply(reply)
                settle_repeat(window, generation, command_names, expected)
                lifetimes.append(retire(window, expected))
            elif kind == "down":
                await_fresh_sample(fake)
                window = enter()
                fake.set_reply(reply)
                action()
                await_event_sequence(window, 0, expected,
                                     timeout=2 * POLL_SECONDS + CALL_BUDGET_SECONDS + DELIVERY_SECONDS)
                # No fake-visible sample with the observer down: the repeat sample
                # starts one poll after the emitting one and ends within the budget.
                sleep_until(time.monotonic() + POLL_SECONDS + CALL_BUDGET_SECONDS + DELIVERY_SECONDS)
                lifetimes.append(retire(window, expected))
            else:
                raise ValueError(f"unknown phase kind {kind}")
            results[name] = {"exact_events": True, "count": len(expected), "reconnects": 0,
                             "windows": len(lifetimes), "max_window_seconds": round(max(lifetimes), 1),
                             "silence_anchor": ANCHOR_EVENT if expected else ANCHOR_ALLOWANCE}
            if kind == "start":
                results[name]["hold_reply_during_action"] = True
    finally:
        for window, _ in list(open_windows.values()):
            window.close()
    return results


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
    query = ["AUTHENTICATE", "GETINFO", "QUIT"]

    def start_observer():
        checked(["docker", "start", observer_id], timeout=90)

    # Each window stays well below T148's channel lifetime; an early EOF or
    # rotation fails and nothing is replayed (see observe_phases).
    results = observe_phases(lambda: EventObservation(binary, ipc, keys), fake, [
        ("initial-not-ready-and-repeat", "start", NOT_READY, [("STARTED", "container_start")], query,
         start_observer),
        ("ready-and-repeat", "reply", READY, [("HEALTHY", "healthcheck_pass")], query, None),
        ("not-ready-and-repeat", "reply", NOT_READY, [("UNHEALTHY", "healthcheck_fail")], query, None),
        ("malformed-and-repeat", "silent", HOLD, [], query, None),
        ("timeout-and-repeat", "silent", None, [], ["AUTHENTICATE", "GETINFO"], None),
        ("ready-after-failures", "reply", READY, [("HEALTHY", "healthcheck_pass")], query, None),
        ("observer-down-and-repeat", "down", READY, [("UNHEALTHY", "healthcheck_fail")], None,
         lambda: checked(prefix + ["stop", "tor-observer"], timeout=90)),
        ("observer-recovery-and-repeat", "start", READY, [("HEALTHY", "healthcheck_pass")], query,
         start_observer),
    ])
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
            return checked(["docker", "exec", ids["stargate-control"],
                            "/etc/stargate/t165-observer-probe", *args], timeout=10)
        except RuntimeError as failure:
            raise RuntimeError(f"CP probe mode {args[0]} failed: {failure}") from failure

    observer_keys = Path(checked(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}",
                                  project + "_stargate-observer-keys"])) / "t203-probe"
    shutil.copyfile(binary, observer_keys)
    os.chmod(observer_keys, 0o555)
    tor_state = Path(checked(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}",
                              project + "_stargate-tor-state"])) / "t203-probe"
    shutil.copyfile(binary, tor_state)
    os.chmod(tor_state, 0o555)
    # Default Docker exec identities preserve each production caller's exact
    # uid/groups/caps/namespaces; no privilege-elevated observer surrogate.
    for service, path in (("stargate-control", "/etc/stargate/t165-observer-probe"),
                          ("tor-observer", "/etc/stargate/observer-keys/t203-probe")):
        if checked(["docker", "exec", ids[service], path, "raw-authority"]) != "RAW_AUTHORITY_DENIED":
            raise AssertionError("application raw authority denial failed")
    if checked(["docker", "exec", ids["tor-observer"], "/etc/stargate/observer-keys/t203-probe",
                "publication-boundary"]) != "PUBLICATION_READONLY_TMPFS":
        raise AssertionError("observer output-only backing failed")
    if checked(["docker", "exec", ids["tor"], "/var/lib/tor/t203-probe", "raw-positive"]) != "RAW_AUTHORITY_POSITIVE":
        raise AssertionError("Tor raw authority positive control failed")
    context = {}
    for service, item in inspected.items():
        pid = item["State"]["Pid"]
        status = Path(f"/proc/{pid}/status").read_text().splitlines()
        context[service] = {"image": item["Image"], "user": item["Config"]["User"],
            "status": [line for line in status if line.split(":",1)[0] in ("Uid","Gid","Groups","CapEff","NoNewPrivs")],
            "namespaces": {name: os.readlink(f"/proc/{pid}/ns/{name}") for name in ("mnt","net","pid","time")},
            "mounts": item["Mounts"], "security": item["HostConfig"].get("SecurityOpt"),
            "apparmor": item.get("AppArmorProfile")}
    evidence.joinpath("T203-production-context.json").write_text(json.dumps(context,indent=2)+"\n")

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
    health_name = project + "_stargate-tor-health"
    health_dir = Path(checked(["docker", "volume", "inspect", "--format", "{{.Mountpoint}}", health_name]))
    publisher_id = None
    try:
        with FakeTor(socket_path) as fake:
            # Tor removes its native cookie on clean shutdown. Seed a synthetic
            # fixture cookie for this disposable listener; never copy the real
            # credential into harness output or another authority boundary.
            fixture_cookie = Path(state) / "control_auth_cookie"
            fixture_cookie.write_bytes(bytes([0x51]) * 32)
            os.chown(fixture_cookie, 5103, 5103)
            os.chmod(fixture_cookie, 0o640)
            publisher_id = checked(["docker", "run", "-d", "--name", project + "-publisher-fixture-" + secrets.token_hex(4),
                "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--log-driver", "none",
                "--user", "5103:5103", "--mount", f"type=volume,source={state_name},target=/var/lib/tor",
                "--mount", f"type=volume,source={health_name},target=/run/tor-health",
                "--entrypoint", "/usr/local/bin/tor-health-publisher", tor["Image"]])

            def await_health(reply, expected):
                import struct
                trigger = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                fake.set_reply(reply)
                limit = time.monotonic() + 15
                while time.monotonic() < limit:
                    try:
                        sample = (health_dir / "latest").read_bytes()
                        began = struct.unpack_from("<q", sample, 16)[0] if len(sample) == 24 else -1
                        if began >= trigger and cp_probe("health") == expected:
                            return
                    except (OSError, RuntimeError):
                        pass
                    time.sleep(0.2)
                raise AssertionError("post-trigger finite publisher sample absent")

            await_health(READY, "READY/1")
            bad = [b"GETINFO stream-status\n", b"GETINFO circuit-status\n",
                   b"GETCONF SocksPort\n", b"SETCONF SocksPort=9050\n",
                   b"SETEVENTS STREAM\n", b"ATTACHSTREAM 1 1\n",
                   b"ADD_ONION NEW:BEST\n", b"SIGNAL NEWNYM\n",
                   b"COMMAND arbitrary\n", b"HEALTH/2\n", b"HEALTH/1 extra\n",
                   b"HEALTH/1\nX", b"HEALTH/1\r\n"]
            for mode in ("wrong-auth", "absent-auth", "no-eof"):
                if cp_probe(mode) != "REFUSED":
                    raise AssertionError("invalid caller/request received a token")
            for request in bad:
                if cp_probe("request", request.hex()) != "REFUSED":
                    raise AssertionError("forbidden CP input received a token")
                matrix.append(request.split(b" ", 1)[0].decode("ascii", "replace").strip())
            # Autonomous sampling continues; fixed stream validation and the
            # absence of consumer inputs replace the old global no-query claim.
            assert_safe_command_stream(fake.snapshot())
            await_health(NOT_READY, "NOT_READY/1")
            await_health("551 " + RAW_MARKER + "\r\n", "UNAVAILABLE/1")
            await_health(None, "UNAVAILABLE/1")
            await_health(READY, "READY/1")
            checked(["docker", "kill", "--signal=STOP", publisher_id])
            import struct
            latest = health_dir / "latest"
            saved = latest.read_bytes()
            valid = bytearray(saved)
            struct.pack_into("<q", valid, 16, time.clock_gettime_ns(time.CLOCK_BOOTTIME))

            def record_bytes(data):
                latest.unlink(missing_ok=True)
                latest.write_bytes(data)
                os.chown(latest, 5103, 5103)
                os.chmod(latest, 0o600)

            record_bytes(valid)
            if cp_probe("health") != "READY/1":
                raise AssertionError("finite-file parser positive control failed")
            future = bytearray(valid)
            struct.pack_into("<q", future, 16, time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 3600_000_000_000)
            domain = bytearray(valid)
            domain[8] ^= 1
            for bad_record in (bytes(valid[:5]), bytes(valid) + b"extra", b"X" * 8192,
                               b"BAD1" + bytes(valid[4:]), bytes(future), bytes(domain)):
                record_bytes(bad_record)
                if cp_probe("health") != "UNAVAILABLE/1":
                    raise AssertionError("invalid finite record accepted")
            latest.unlink()
            latest.symlink_to("/dev/zero")
            if cp_probe("health") != "UNAVAILABLE/1":
                raise AssertionError("symlink record accepted")
            latest.unlink()
            os.mkfifo(latest, 0o600)
            os.chown(latest, 5103, 5103)
            if cp_probe("health") != "UNAVAILABLE/1":
                raise AssertionError("FIFO record accepted")
            record_bytes(saved)
            time.sleep(4.1)
            if cp_probe("health") != "UNAVAILABLE/1":
                raise AssertionError("stopped publisher renewed READY")
            os.utime(health_dir / "latest", None)
            checked(prefix + ["restart", "tor-observer"], timeout=90)
            if cp_probe("health") != "UNAVAILABLE/1":
                raise AssertionError("mtime or observer restart renewed READY")
            checked(["docker", "kill", "--signal=CONT", publisher_id])
            await_health(READY, "READY/1")
            checked(["docker", "kill", publisher_id])
            time.sleep(4.1)
            if cp_probe("health") != "UNAVAILABLE/1":
                raise AssertionError("dead publisher retained READY")
            checked(["docker", "start", publisher_id])
            await_health(READY, "READY/1")
            evidence.joinpath("T203-probe-matrix.json").write_text(json.dumps({
                "forbidden_inputs": matrix, "real_health": initial,
                "invalid_auth_and_eof_refused": True, "autonomous_fixed_sampling": True,
                "fresh_ready_not_ready_malformed_timeout": True,
                "publisher_stop_expiry_observer_restart_mtime": True,
                "invalid_file_shape_future_domain_symlink_fifo": True,
                "dead_publisher_expiry_and_recovery": True,
                "controlled_publisher_image": tor["Image"],
            }, indent=2) + "\n")
            exercise_cp_events(evidence, fake, prefix, project, ids["stargate-control"],
                               ids["tor-observer"], binary)
    finally:
        if publisher_id:
            subprocess.run(["docker", "kill", "--signal=CONT", publisher_id],capture_output=True)
            checked(["docker", "stop", "-t", "2", publisher_id], timeout=30)
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
    def signal_publisher(sig):
        script = ('found=0; for proc in /proc/[0-9]*; do '
                  'if [ "$(readlink "$proc/exe")" = /usr/local/bin/tor-health-publisher ]; then '
                  'kill -' + sig + ' "${proc##*/}"; found=$((found+1)); fi; done; '
                  '[ "$found" = 1 ]')
        checked(["docker", "exec", ids["tor"], "sh", "-c", script])

    def quiesce_health():
        checked(prefix + ["stop", "tor-observer"], timeout=90)
        signal_publisher("STOP")
        time.sleep(4.1)

    try:
        assert_cp_down_forwarding(evidence, prefix, project, ids["stargate-control"],
                                  ids["tor-observer"], quiesce_health)
        evidence.joinpath("T203-health-down-forwarding.txt").write_text(
            "CP and observer stopped; Tor-internal publisher SIGSTOPed beyond its original lease. "
            "DP authenticated from retained state and Tor returned destination response bytes.\n")
    finally:
        signal_publisher("CONT")
        checked(prefix + ["start", "tor-observer"], timeout=90)
    print("PASS: deployed observer boundary and CP/observer/publisher-down authenticated forwarding")
