# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""T163 live packet evidence for the checked-in Local deployment.

Run only on a disposable Linux Docker host as root. Captures remain local and
gitignored; they include the host's source address. The helper never contacts
a real destination: its targets are documentation-only addresses.
"""

import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


# Stdin-fed probes have no source path and never use repository resources.
# Keep their setup independent of the caller's working-directory depth.
ROOT = Path.cwd() if __file__ == "<stdin>" else Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "compose/docker-compose.local.yml"
PROFILE = ROOT / "compose/apparmor/stargate-dp"
DP_UID = 5102
DP_GID = 5100
CONTROL_UID = 6000
SOCKS_PORT = 8881
CONFINED_BINARY: Path | None = None
PORTS = {"tcp_positive": 39111, "tcp_negative": 39112,
         "udp_positive": 39113, "udp_negative": 39114}


class CaptureFailure(RuntimeError):
    """A recorder or its positive control cannot support a zero-packet claim."""


def require_capture(path: Path, ready: bool, returncode: int, decoded: str | None) -> str:
    if not ready or returncode != 0 or decoded is None or not path.is_file() or path.stat().st_size == 0:
        raise CaptureFailure(f"invalid capture {path.name}: ready={ready}, exit={returncode}, decoded={decoded is not None}")
    return decoded


def clean_capture_summary(stderr: str) -> bool:
    # A dropped packet could be the forbidden emission being measured.
    return (re.search(r"(?m)^\d+ packets? captured$", stderr) is not None
            and re.search(r"(?m)^0 packets? dropped by kernel$", stderr) is not None)


def classify(decoded: str, destination: str, port: int) -> int:
    """Count packets addressed to one marker endpoint in tcpdump's numeric output."""
    endpoint = re.compile(r">\s+" + re.escape(destination) + r"\." + str(port) + r":")
    return sum(bool(endpoint.search(line)) for line in decoded.splitlines())


def socks_method_reply(reply: bytes) -> bool:
    # This is only a negotiation/admission probe, never a claim of a
    # completed upstream SOCKS CONNECT (Constitution I; T134 A.4f).
    return reply == b"\x05\x02"


def recv_exact(sock: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        if not part:
            break
        result.extend(part)
    return bytes(result)


def command(*argv: str, timeout: int = 120, env: dict | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} failed (exit {result.returncode}): {result.stderr[-500:]}")
    return result


class Recorder:
    def __init__(self, interface: str, expression: str, path: Path):
        self.interface, self.expression, self.path = interface, expression, path
        self.process: subprocess.Popen | None = None
        self.ready = False
        self.startup_stderr = b""

    def start(self) -> None:
        self.process = subprocess.Popen(
            # Kernel denial is fast. Immediate mode drains packets without
            # waiting for libpcap's block timeout before the recorder is stopped.
            ["tcpdump", "--immediate-mode", "-i", self.interface, "-U", "-n", "-w", str(self.path), self.expression],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, bufsize=0,
        )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            readable, _, _ = select.select([self.process.stderr], [], [], 0.2)
            if readable:
                chunk = os.read(self.process.stderr.fileno(), 4096)
                self.startup_stderr += chunk
                if b"listening on " in self.startup_stderr:
                    self.ready = True
                    return
                if not chunk:
                    break
            if self.process.poll() is not None:
                break
        self.stop(allow_invalid=True)
        raise CaptureFailure(f"tcpdump on {self.interface} never became ready")

    def stop(self, allow_invalid: bool = False) -> str:
        if self.process is None:
            raise CaptureFailure("recorder was never started")
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            _, tail = self.process.communicate(timeout=8)
        except subprocess.TimeoutExpired as exc:
            self.process.kill()
            self.process.communicate()
            raise CaptureFailure(f"tcpdump on {self.interface} did not stop") from exc
        stderr = (self.startup_stderr + tail).decode(errors="replace")
        decoded = None
        if self.path.is_file():
            result = subprocess.run(["tcpdump", "-n", "-r", str(self.path)],
                                    text=True, capture_output=True, timeout=15)
            if result.returncode == 0:
                decoded = result.stdout
        self.path.with_suffix(".stderr.txt").write_text(stderr)
        if decoded is not None:
            self.path.with_suffix(".decoded.txt").write_text(decoded)
        if allow_invalid:
            return ""
        if not clean_capture_summary(stderr):
            raise CaptureFailure(f"tcpdump on {self.interface} had no clean exit summary")
        return require_capture(self.path, self.ready, self.process.returncode, decoded)


def stop_recorders(recorders: list[Recorder]) -> list[str]:
    decoded, failures = [], []
    for recorder in recorders:
        if recorder.process is None:
            continue
        try:
            decoded.append(recorder.stop())
        except Exception as exc:
            # A failed capture must invalidate the result, while its peer
            # still gets a chance to exit and close its pcap cleanly.
            failures.append(str(exc))
    if failures:
        raise CaptureFailure("; ".join(failures))
    return decoded


def stop_workers(stopped: threading.Event, workers: list[threading.Thread]) -> None:
    stopped.set()
    for worker in workers:
        worker.join(timeout=3)
    if any(worker.is_alive() for worker in workers):
        raise CaptureFailure("fixture worker did not stop")


def confined_result(returncode: int) -> bool:
    if returncode not in (0, 77):
        raise CaptureFailure(f"confinement probe failed without a denial verdict: exit {returncode}")
    return returncode == 0


def probe(uid: int, kind: str, family: int, address: str, port: int, timeout: float = 30,
          confined: bool = False) -> bool:
    """Bound the helper process separately from its socket-operation deadlines."""
    if confined:
        if uid != DP_UID or CONFINED_BINARY is None:
            raise CaptureFailure("confinement helper not built")
        env = os.environ.copy()
        env.update(STARGATE_PACKET_PROBE=kind, STARGATE_PACKET_FAMILY=str(family),
                   STARGATE_PACKET_ADDRESS=address, STARGATE_PACKET_PORT=str(port))
        result = subprocess.run([str(CONFINED_BINARY), "-test.run=^TestPacketProbe$"],
                                env=env, user=uid, group=DP_GID, extra_groups=[],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return confined_result(result.returncode)
    result = subprocess.run(
        [sys.executable, "-", "--probe", kind, str(family), address, str(port)],
        # The selected UID need not traverse the checkout's private parent.
        # Feed the same source through stdin; a launcher failure is not denial.
        input=Path(__file__).read_bytes(),
        user=uid, group=DP_GID if uid == DP_UID else uid, extra_groups=[],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=timeout,
    )
    if result.returncode not in (0, 1) or result.stderr != b"T163-PROBE-EXECUTED\n":
        raise CaptureFailure(f"socket probe did not complete: exit {result.returncode}")
    return result.returncode == 0


def probe_main(kind: str, family: int, address: str, port: int) -> int:
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    typ = socket.SOCK_DGRAM if kind in ("udp", "dns", "dns-reply") else socket.SOCK_STREAM
    try:
        with socket.socket(af, typ) as sock:
            sock.settimeout(0.8)
            if kind in ("udp", "dns", "dns-reply"):
                data = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" if kind in ("dns", "dns-reply") else b"t163"
                sock.sendto(data, (address, port))
                if kind == "dns-reply":
                    return 0 if sock.recv(5) == b"t163" else 1
                return 0
            sock.connect((address, port))
            if kind == "socks":
                sock.sendall(b"\x05\x01\x02")
                return 0 if socks_method_reply(recv_exact(sock, 2)) else 1
            if kind == "forwarder":
                sock.sendall(b"t163-" if os.geteuid() == DP_UID else b"t163+")
                return 0 if recv_exact(sock, len(b"t163")) == b"t163" else 1
            return 0
    except (OSError, TimeoutError):
        return 1


def route_interface(family: int, address: str) -> str | None:
    result = subprocess.run(["ip", "-j", "-6" if family == 6 else "-4", "route", "get", address],
                            text=True, capture_output=True, timeout=5)
    if result.returncode:
        return None
    routes = json.loads(result.stdout)
    if len(routes) != 1:
        raise RuntimeError(f"ambiguous IPv{family} route to documentation target")
    interface = routes[0].get("dev")
    if not interface or interface == "lo":
        raise RuntimeError(f"IPv{family} target has no non-loopback egress interface")
    return interface


def drop_count(family: int) -> int:
    tool = "ip6tables" if family == 6 else "iptables"
    rules = command(tool, "-w", "-L", "STARGATE_DP_OUT", "-v", "-x", "-n").stdout
    matches = re.findall(r"^\s*(\d+)\s+\d+\s+DROP\b", rules, re.MULTILINE)
    if len(matches) != 1:
        raise RuntimeError(f"IPv{family} owner DROP counter missing or ambiguous")
    return int(matches[0])


def owner_rule_present(family: int) -> bool:
    tool = "ip6tables" if family == 6 else "iptables"
    result = subprocess.run([tool, "-w", "-C", "OUTPUT", "-m", "owner", "--uid-owner", str(DP_UID),
                             "-j", "STARGATE_DP_OUT"], capture_output=True)
    return result.returncode == 0


def record_compose_failure(evidence: Path, env: dict) -> None:
    prefix = ["docker", "compose", "-p", env["STARGATE_PROJECT"], "-f", str(COMPOSE),
              "--env-file", str(evidence / "local.env")]
    result = subprocess.run(prefix + ["ps", "-a", "--format", "json"],
                            text=True, capture_output=True, timeout=15)
    (evidence / "compose-ps.json").write_text(result.stdout if result.returncode == 0 else result.stderr)
    ids = subprocess.run(prefix + ["ps", "-a", "-q"], text=True, capture_output=True, timeout=15)
    if ids.returncode:
        return
    states = []
    for container_id in ids.stdout.split():
        inspected = subprocess.run(["docker", "inspect", "-f",
                                    "{{.Name}} {{.State.Status}} {{.State.Error}}", container_id],
                                   text=True, capture_output=True, timeout=10)
        if inspected.returncode == 0:
            states.append(inspected.stdout.strip())
    (evidence / "compose-states.txt").write_text("\n".join(states) + "\n")
    for state in states:
        if "failed" in state or "error" in state:
            print(f"DEPLOYMENT ERROR: {state}", file=sys.stderr)


def assert_packet_matrix(evidence: Path, family: int, interface: str, confined: bool = False) -> None:
    pos = "2001:db8::77" if family == 6 else "198.51.100.77"
    neg_dns = "2001:db8::78" if family == 6 else "198.51.100.78"
    expression = f"((host {pos} or host {neg_dns}) and (tcp or udp))"
    recorders = [Recorder(name, expression, evidence / f"ipv{family}-{name}.pcap")
                 for name in ("any", interface)]
    try:
        for recorder in recorders:
            recorder.start()
        before = drop_count(family)
        # Ports/destination distinguish unrestricted and DP-identity attempts
        # within the same capture. TCP timeout is intentionally ignored: it is
        # non-discriminating whether the packet was filtered or routed/dropped.
        probe(CONTROL_UID, "tcp", family, pos, PORTS["tcp_positive"])
        probe(CONTROL_UID, "udp", family, pos, PORTS["udp_positive"])
        probe(CONTROL_UID, "dns", family, pos, 53)
        attempts = [("tcp", pos, PORTS["tcp_negative"]),
                    ("udp", pos, PORTS["udp_negative"]), ("dns", neg_dns, 53)]
        if confined:
            attempts += [("reuse", pos, PORTS["tcp_negative"]),
                         ("fastopen", pos, PORTS["tcp_negative"])]
        for kind, target, port in attempts:
            allowed = probe(DP_UID, kind, family, target, port, confined=confined)
            if confined and allowed:
                raise CaptureFailure(f"confinement allowed IPv{family} {kind}")
        time.sleep(0.4)
        after = drop_count(family)
    finally:
        decoded = stop_recorders(recorders)
    if len(decoded) != 2:
        raise CaptureFailure("source or egress recorder missing")
    for name, packets in zip(("source", "egress"), decoded):
        for label, target, port in (("TCP", pos, PORTS["tcp_positive"]),
                                    ("UDP", pos, PORTS["udp_positive"]), ("DNS", pos, 53)):
            if classify(packets, target, port) < 1:
                raise CaptureFailure(f"IPv{family} {name} {label} positive control absent")
        for label, target, port in (("TCP", pos, PORTS["tcp_negative"]),
                                    ("UDP", pos, PORTS["udp_negative"]), ("DNS", neg_dns, 53)):
            if classify(packets, target, port):
                raise CaptureFailure(f"IPv{family} {name} DP {label} packet escaped")
    if not confined and after - before < 3:
        raise CaptureFailure(f"IPv{family} DROP counter did not record all three DP attempts")
    print(f"PASS: IPv{family} source/egress capture controls, zero DP TCP/UDP/DNS packets, DROP delta={after-before}")


def assert_forwarder(evidence: Path, family: int, interface: str, confined: bool = False) -> None:
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    loopback = "::1" if family == 6 else "127.0.0.1"
    target = "2001:db8::77" if family == 6 else "198.51.100.77"
    with socket.socket(af, socket.SOCK_STREAM) as server:
        server.bind((loopback, 0))
        server.listen(2)
        server.settimeout(0.2)
        port = server.getsockname()[1]
        served = []
        failures = []
        stopped = threading.Event()
        workers = []

        def accept_probes():
            while len(served) < 2:
                try:
                    peer, _ = server.accept()
                except socket.timeout:
                    if stopped.is_set():
                        return
                    continue
                except OSError:
                    failures.append("accept")
                    return
                try:
                    with peer:
                        peer.settimeout(0.8)
                        marker = recv_exact(peer, len(b"t163+"))
                        served.append(marker)
                        destination_port = 39116 if marker == b"t163-" else 39115
                        with socket.socket(af, socket.SOCK_DGRAM) as outbound:
                            outbound.sendto(b"t163", (target, destination_port))
                        peer.sendall(b"t163")
                except OSError:
                    failures.append("exchange")
                    return

        recorders = [Recorder("lo", f"tcp port {port}", evidence / f"ipv{family}-forwarder-lo.pcap"),
                     Recorder(interface, f"host {target} and udp and (port 39115 or port 39116)",
                              evidence / f"ipv{family}-forwarder-egress.pcap")]
        try:
            for recorder in recorders:
                recorder.start()
            # Recorder and interpreter startup are not service inactivity.
            # End the fixture explicitly after both bounded probes complete.
            worker = threading.Thread(target=accept_probes, daemon=True)
            worker.start()
            workers.append(worker)
            if not probe(CONTROL_UID, "forwarder", family, loopback, port):
                raise CaptureFailure(f"IPv{family} forwarder positive control failed")
            if probe(DP_UID, "forwarder", family, loopback, port, confined=confined):
                raise CaptureFailure(f"IPv{family} DP reached loopback forwarder")
        finally:
            try:
                stop_workers(stopped, workers)
            finally:
                decoded = stop_recorders(recorders)
        if failures:
            raise CaptureFailure(f"IPv{family} forwarder fixture I/O failed")
        if served != [b"t163+"] or len(decoded) != 2:
            raise CaptureFailure(f"IPv{family} forwarder did not receive exactly the control marker")
        if classify(decoded[0], loopback, port) < 1:
            raise CaptureFailure(f"IPv{family} loopback capture positive control absent")
        if classify(decoded[1], target, 39115) < 1 or classify(decoded[1], target, 39116):
            raise CaptureFailure(f"IPv{family} forwarder capture did not distinguish control from DP mediation")
    print(f"PASS: IPv{family} loopback forwarder positive egress and DP mediation denial")


def assert_resolver(evidence: Path, family: int, confined: bool = False) -> None:
    # A live dummy resolver gives the same UDP/53-shaped exchange to both
    # identities. The unrestricted UID receives a reply; DP cannot initiate
    # even to a host-loopback resolver (Constitution III; T125 channel).
    af = socket.AF_INET6 if family == 6 else socket.AF_INET
    loopback = "::1" if family == 6 else "127.0.0.1"
    with socket.socket(af, socket.SOCK_DGRAM) as server, socket.socket(af, socket.SOCK_DGRAM) as denied_server:
        server.bind((loopback, 0))
        denied_server.bind((loopback, 0))
        server.settimeout(0.2)
        denied_server.settimeout(0.2)
        control_port = server.getsockname()[1]
        denied_port = denied_server.getsockname()[1]
        received, denied_received = [], []
        failures = []
        stopped = threading.Event()
        workers = []

        def answer(endpoint: socket.socket, observations: list):
            while True:
                try:
                    data, sender = endpoint.recvfrom(128)
                except socket.timeout:
                    if stopped.is_set():
                        return
                    continue
                except OSError:
                    failures.append("receive")
                    return
                observations.append(data)
                try:
                    endpoint.sendto(b"t163", sender)
                except OSError:
                    failures.append("reply")
                    return
                return

        recorder = Recorder("lo", f"udp and (port {control_port} or port {denied_port})",
                            evidence / f"ipv{family}-resolver-lo.pcap")
        try:
            recorder.start()
            for endpoint, observations in ((server, received), (denied_server, denied_received)):
                worker = threading.Thread(target=answer, args=(endpoint, observations), daemon=True)
                worker.start()
                workers.append(worker)
            if not probe(CONTROL_UID, "dns-reply", family, loopback, control_port):
                raise CaptureFailure("dummy resolver positive control failed")
            if probe(DP_UID, "dns-reply", family, loopback, denied_port, confined=confined):
                raise CaptureFailure("DP reached a host-loopback resolver")
        finally:
            try:
                stop_workers(stopped, workers)
            finally:
                captures = stop_recorders([recorder])
        if failures:
            raise CaptureFailure(f"IPv{family} resolver fixture I/O failed")
        decoded, = captures
        if len(received) != 1 or classify(decoded, loopback, control_port) < 1:
            raise CaptureFailure("resolver positive control packet absent")
        if denied_received or classify(decoded, loopback, denied_port):
            raise CaptureFailure("DP resolver packet reached the loopback fixture")
    print(f"PASS: IPv{family} dummy loopback resolver reaches control UID, refuses DP UID")


def assert_listener() -> None:
    if not probe(CONTROL_UID, "socks", 4, "127.0.0.1", SOCKS_PORT):
        raise RuntimeError("127.0.0.1:8881 did not admit a SOCKS5 method exchange")
    if probe(CONTROL_UID, "socks", 6, "::1", SOCKS_PORT):
        raise RuntimeError("unsupported IPv6 listener admitted SOCKS5")
    for family, target in ((4, "198.51.100.77"), (6, "2001:db8::77")):
        interface = route_interface(family, target)
        if interface is None:
            continue
        addresses = json.loads(command("ip", "-j", "addr", "show", "dev", interface).stdout)[0]["addr_info"]
        # QEMU's user network advertises only the deprecated site-local fec0::/64
        # prefix (RFC 3879), so a guest's routed IPv6 address has scope "site".
        # It is still a non-loopback address the DP must refuse (T196; D-live-2).
        scopes = ("global", "site") if family == 6 else ("global",)
        scope = [a["local"] for a in addresses if a["family"] == ("inet6" if family == 6 else "inet")
                 and a.get("scope") in scopes]
        if not scope:
            raise RuntimeError(f"IPv{family} egress interface has no bind-probe address")
        if probe(CONTROL_UID, "socks", family, scope[0], SOCKS_PORT):
            raise RuntimeError(f"IPv{family} non-loopback address admitted SOCKS5")
    print("PASS: 127.0.0.1:8881 SOCKS5; non-loopback and ::1 refused")


def compose_args(evidence: Path, env: dict) -> list[str]:
    return ["docker", "compose", "-p", env["STARGATE_PROJECT"], "-f", str(COMPOSE),
            "--env-file", str(evidence / "local.env")]


def wait_listener() -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if probe(CONTROL_UID, "socks", 4, "127.0.0.1", SOCKS_PORT):
            assert_listener()
            return
        time.sleep(0.2)
    raise RuntimeError("DP never resumed SOCKS method admission")


def confined_matrix(evidence: Path) -> None:
    evidence.mkdir()
    for family, target in ((4, "198.51.100.77"), (6, "2001:db8::77")):
        interface = route_interface(family, target)
        if interface is not None:
            assert_packet_matrix(evidence, family, interface, confined=True)
            assert_forwarder(evidence, family, interface, confined=True)
        elif family == 4:
            raise CaptureFailure("missing IPv4 capture route")
        else:
            print("REFUSED: no IPv6 egress route; IPv6 loopback resolver still tested")
        assert_resolver(evidence, family, confined=True)


def assert_rule_absent(evidence: Path, env: dict) -> None:
    # T168's process boundary must preserve safety and valid admission even when
    # either auxiliary jump disappears. A docker exec process would NOT inherit
    # the DP's filters: the attack binary calls the same production Apply itself.
    for family in (4, 6):
        if not owner_rule_present(family):
            raise RuntimeError(f"IPv{family} owner jump missing before owner-loss test")
    for families in ((4,), (6,), (4, 6)):
        label = "owner-loss-" + "-".join(map(str, families))
        try:
            for family in families:
                tool = "ip6tables" if family == 6 else "iptables"
                command(tool, "-w", "-D", "OUTPUT", "-m", "owner", "--uid-owner", str(DP_UID),
                        "-j", "STARGATE_DP_OUT")
                if owner_rule_present(family):
                    raise RuntimeError("owner jump was not removed")
            assert_listener()
            confined_matrix(evidence / label)
            if families == (4, 6):
                command(*compose_args(evidence, env), "restart", "stargate-dp")
                wait_listener()
                confined_matrix(evidence / "owner-loss-restart")
                command("bash", "scripts/stargate", "init", env=env, timeout=900)
                wait_listener()
                if not all(owner_rule_present(f) for f in (4, 6)):
                    raise RuntimeError("re-init did not restore owner rules")
                print("PASS: re-init reinstalls owner rules and resumes service")
        finally:
            for family in families:
                if not owner_rule_present(family):
                    tool = "ip6tables" if family == 6 else "iptables"
                    command(tool, "-w", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", str(DP_UID),
                            "-j", "STARGATE_DP_OUT")
        print(f"PASS: {label} preserves admission and confines origins")


def assert_restriction_unavailable(evidence: Path, env: dict) -> None:
    # Fault injection is test-only Docker policy. Production has no bypass flag.
    # Exercise both unavailable Landlock and failure after partial installation.
    prefix = compose_args(evidence, env)
    for syscall_name in ("landlock_create_ruleset", "landlock_restrict_self", "seccomp"):
        policy = evidence / f"deny-{syscall_name}.json"
        policy.write_text(json.dumps({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": [
            {"names": [syscall_name], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}]}))
        override = evidence / "fault-compose.json"
        # Compose appends these to the base AppArmor/no-new-privileges options.
        override.write_text(json.dumps({"services": {"stargate-dp": {
            "security_opt": [f"seccomp={policy}"]}}}))
        try:
            command(*prefix, "-f", str(override), "up", "-d", "--no-deps", "--force-recreate", "stargate-dp")
            container = command(*prefix, "ps", "-a", "-q", "stargate-dp").stdout.strip()
            code = command("docker", "wait", container, timeout=20).stdout.strip()
            # T152 suppresses startup diagnostics. The injected restriction,
            # nonzero exit, absent admission and restored positive control
            # establish refusal without requiring a forbidden receipt journal.
            if code != "1":
                raise RuntimeError(f"{syscall_name} failure did not refuse at confinement installation")
            if probe(CONTROL_UID, "socks", 4, "127.0.0.1", SOCKS_PORT):
                raise RuntimeError("missing required restriction still admitted SOCKS")
            print(f"PASS: {syscall_name} unavailable refuses startup before serving")
        finally:
            command(*prefix, "up", "-d", "--no-deps", "--force-recreate", "stargate-dp")
            wait_listener()
    print("PASS: supported confinement recovers after each unavailable-feature refusal")


def run_live() -> None:
    if os.environ.get("STARGATE_LIVE_E2E") != "1" or os.environ.get("STARGATE_DISPOSABLE_HOST") != "1":
        raise RuntimeError("set STARGATE_LIVE_E2E=1 and STARGATE_DISPOSABLE_HOST=1 on a dedicated disposable host")
    if os.geteuid() != 0:
        raise RuntimeError("root is required for real host owner rules and packet capture")
    for tool in ("docker", "tcpdump", "ip", "ss", "iptables", "ip6tables", "iptables-save", "ip6tables-save",
                 "iptables-restore", "ip6tables-restore", "apparmor_parser", "go"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"required tool missing: {tool}")
    if "stargate-dp (enforce)" in Path("/sys/kernel/security/apparmor/profiles").read_text():
        raise RuntimeError("stargate-dp AppArmor profile already loaded; use a fresh disposable host")
    for family in (4, 6):
        if owner_rule_present(family):
            raise RuntimeError("owner rule already present; use a fresh disposable host")
    global CONFINED_BINARY
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    evidence = ROOT / "target/live-e2e" / f"T163-{stamp}"
    evidence.mkdir(parents=True)
    env = os.environ.copy()
    env.update(STARGATE_PROJECT=f"t163-{stamp.lower()}", STARGATE_COMPOSE_FILE=str(COMPOSE),
               STARGATE_ENV_DIR=str(evidence), STARGATE_ENV_FILE=str(evidence / "local.env"))
    snapshots = {}
    for tool in ("iptables", "ip6tables"):
        snapshots[tool] = command(tool + "-save").stdout
        (evidence / f"{tool}-before.rules").write_text(snapshots[tool])
    # Dedicated root-owned executable directory, traversable by probe UIDs even
    # when the checkout lives under a private home. Removed with the deployment.
    helper_dir = Path(tempfile.mkdtemp(prefix="stargate-confinement-"))
    helper_dir.chmod(0o755)
    CONFINED_BINARY = helper_dir / "probe"
    try:
        build_env = os.environ.copy()
        build_env["CGO_ENABLED"] = "0"
        command("go", "test", "-c", "-o", str(CONFINED_BINARY), "./data-plane/internal/confinement",
                env=build_env, timeout=120)
        try:
            command("bash", "scripts/stargate", "init", env=env, timeout=900)
        except RuntimeError:
            record_compose_failure(evidence, env)
            raise
        for family in (4, 6):
            if not owner_rule_present(family):
                raise RuntimeError(f"IPv{family} owner rule absent after init")
        wait_listener()
        for family, address in ((4, "198.51.100.77"), (6, "2001:db8::77")):
            interface = route_interface(family, address)
            if interface is None:
                if family == 4:
                    raise RuntimeError("IPv4 egress route missing: no packet proof possible")
                if probe(CONTROL_UID, "socks", 6, "::1", SOCKS_PORT):
                    raise RuntimeError("IPv6 unsupported-family refusal failed")
                print("REFUSED: IPv6 has no egress route and ::1 SOCKS is closed")
                continue
            assert_packet_matrix(evidence, family, interface)
            assert_forwarder(evidence, family, interface)
            assert_resolver(evidence, family)
        # T162's real Tor socket fixture positively checks the available
        # caller matrix before and after Tor recreates its Unix sockets.
        command("go", "test", "-tags=docker", "./tests/contract/tor", "-run", "^TestTorSocketCallerMatrix$",
                "-count=1", timeout=900)
        print("PASS: T162 Tor socket caller matrix before/after Tor restart")
        assert_rule_absent(evidence, env)
        assert_restriction_unavailable(evidence, env)
        # The stdin-fed socket helpers execute this module without its source
        # directory on sys.path. Import only in the live driver, never there.
        import observer
        observer.validate(evidence, env)
    finally:
        shutil.rmtree(helper_dir)
        cleanup_failures = []
        try:
            command("docker", "compose", "-p", env["STARGATE_PROJECT"], "-f", str(COMPOSE),
                    "--env-file", str(evidence / "local.env"), "down", "-v", "--remove-orphans", timeout=180)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            cleanup_failures.append(str(exc))
        for tool in ("iptables", "ip6tables"):
            result = subprocess.run([tool + "-restore"], input=snapshots[tool], text=True, capture_output=True)
            if result.returncode:
                cleanup_failures.append(f"{tool}-restore exit {result.returncode}: {result.stderr[-300:]}")
        if "stargate-dp (enforce)" in Path("/sys/kernel/security/apparmor/profiles").read_text():
            result = subprocess.run(["apparmor_parser", "-T", "-R", str(PROFILE)], capture_output=True, text=True)
            if result.returncode or "stargate-dp (enforce)" in Path("/sys/kernel/security/apparmor/profiles").read_text():
                cleanup_failures.append(f"AppArmor profile removal failed: {result.stderr[-300:]}")
        if cleanup_failures:
            raise RuntimeError("cleanup failure: " + "; ".join(cleanup_failures))
    print(f"PASS: complete live evidence (pcaps kept in {evidence})")


if __name__ == "__main__":
    if len(sys.argv) == 6 and sys.argv[1] == "--probe":
        probe_exit = probe_main(sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]))
        print("T163-PROBE-EXECUTED", file=sys.stderr, flush=True)
        sys.exit(probe_exit)
    if len(sys.argv) != 1:
        sys.exit("usage: python3 tests/live-e2e/local-topology/run.py")
    try:
        run_live()
    except (CaptureFailure, RuntimeError, subprocess.TimeoutExpired, OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
