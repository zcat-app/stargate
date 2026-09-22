# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""Falsifiers for T163's packet recorder and evidence decisions."""

import tempfile
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from run import CaptureFailure, classify, clean_capture_summary, probe_main, require_capture, socks_method_reply, stop_recorders
import run


class CaptureEvidenceTest(unittest.TestCase):
    def test_confinement_refusal_needs_no_operational_journal(self):
        self.confinement_fixture("1", False)

    def test_confinement_refusal_requires_exit_and_no_admission(self):
        for code, admitted in (("0", False), ("2", False), ("1", True)):
            with self.subTest(code=code, admitted=admitted), self.assertRaises(RuntimeError):
                self.confinement_fixture(code, admitted)

    def confinement_fixture(self, code, admitted):
        def command(*args, **kwargs):
            if args[:2] == ("docker", "logs"):
                raise AssertionError("a silent deployment has no readable journal")
            output = code if args[:2] == ("docker", "wait") else "fixture-container"
            return subprocess.CompletedProcess(args, 0, output, "")
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(run, "compose_args", return_value=["docker", "compose"]), \
                patch.object(run, "command", side_effect=command), \
                patch.object(run, "probe", return_value=admitted), \
                patch.object(run, "wait_listener") as recovery:
            run.assert_restriction_unavailable(Path(directory), {})
            self.assertEqual(recovery.call_count, 3)

    def test_delayed_interpreter_still_completes_real_udp_probe(self):
        real_run = subprocess.run

        def delayed(argv, **kwargs):
            # Exercise child startup without needing root in the contract gate.
            for option in ("user", "group", "extra_groups"):
                kwargs.pop(option, None)
            kwargs["input"] = b"import time; time.sleep(3)\n" + kwargs["input"]
            return real_run(argv, **kwargs)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(1)
            with patch.object(run.subprocess, "run", side_effect=delayed):
                self.assertTrue(run.probe(run.CONTROL_UID, "udp", 4, "127.0.0.1",
                                          receiver.getsockname()[1]))
            self.assertEqual(receiver.recvfrom(32)[0], b"t163")

    def test_expired_helpers_never_become_denial(self):
        real_run = subprocess.run

        def stalled(argv, **kwargs):
            for option in ("user", "group", "extra_groups"):
                kwargs.pop(option, None)
            if "input" in kwargs:
                kwargs["input"] = b"import time; time.sleep(30)\n" + kwargs["input"]
            return real_run(argv, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / "stalled-helper"
            helper.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\nraise SystemExit(77)\n")
            helper.chmod(0o700)
            with patch.object(run, "CONFINED_BINARY", helper), \
                 patch.object(run.subprocess, "run", side_effect=stalled):
                for confined in (False, True):
                    with self.subTest(confined=confined), self.assertRaises(subprocess.TimeoutExpired):
                        run.probe(run.DP_UID, "udp", 4, "127.0.0.1", 9,
                                  timeout=0.1, confined=confined)

    def test_fixture_controls_survive_slow_capture_and_probe_startup(self):
        real_socket = socket.socket
        for kind in ("forwarder", "dns-reply"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory, \
                 real_socket(socket.AF_INET, socket.SOCK_DGRAM) as egress_receiver:
                egress_receiver.bind(("127.0.0.1", 0))
                egress_receiver.settimeout(0.1)
                seen = {}
                destinations = []

                class RedirectedDatagram:
                    def __init__(self):
                        self.socket = real_socket(socket.AF_INET, socket.SOCK_DGRAM)

                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        self.socket.close()

                    def sendto(self, data, address):
                        destinations.append(address)
                        return self.socket.sendto(data, egress_receiver.getsockname())

                def fixture_socket(family, typ, *args, **kwargs):
                    if kind == "forwarder" and typ == socket.SOCK_DGRAM:
                        return RedirectedDatagram()
                    return real_socket(family, typ, *args, **kwargs)

                class FixtureRecorder:
                    process = None

                    def __init__(self, interface, expression, path):
                        self.interface = interface

                    def start(self):
                        self.process = object()
                        if not seen.get("capture_started"):
                            time.sleep(2.2)
                            seen["capture_started"] = True

                    def stop(self):
                        # Timing tests use real socket exchanges, while only the
                        # privileged tcpdump boundary is represented by a fixture.
                        if self.interface != "lo":
                            try:
                                data = egress_receiver.recvfrom(32)[0]
                            except socket.timeout:
                                return ""
                            if data == b"t163":
                                return "IP 127.0.0.1.40001 > 198.51.100.77.39115: UDP, length 4"
                            return ""
                        if seen.get("reply"):
                            return f"IP 127.0.0.1.40001 > 127.0.0.1.{seen['port']}: packet"
                        return ""

                def fixture_probe(uid, probe_kind, family, address, port, **kwargs):
                    if uid == run.DP_UID:
                        return False
                    time.sleep(2.2)
                    seen["port"] = port
                    seen["reply"] = run.probe_main(probe_kind, family, address, port) == 0
                    return seen["reply"]

                with patch.object(run, "Recorder", FixtureRecorder), \
                     patch.object(run, "probe", side_effect=fixture_probe), \
                     patch.object(run.socket, "socket", side_effect=fixture_socket):
                    if kind == "forwarder":
                        run.assert_forwarder(Path(directory), 4, "fixture-egress")
                        self.assertEqual(destinations, [("198.51.100.77", 39115)])
                    else:
                        run.assert_resolver(Path(directory), 4)
                self.assertTrue(seen["reply"])

    def test_fixture_teardown_drains_a_queued_negative_datagram(self):
        real_thread = threading.Thread
        real_stop = run.stop_workers
        release = threading.Event()
        created = []
        seen = {}

        def delayed_thread(*args, **kwargs):
            created.append(True)
            if len(created) != 2:
                return real_thread(*args, **kwargs)
            target, arguments = kwargs["target"], kwargs["args"]

            def paused():
                release.wait(timeout=3)
                target(*arguments)

            return real_thread(target=paused, daemon=True)

        def release_after_probes(stopped, workers):
            stopped.set()
            release.set()
            real_stop(stopped, workers)

        class FixtureRecorder:
            process = object()

            def __init__(self, *args):
                pass

            def start(self):
                pass

            def stop(self):
                return f"IP 127.0.0.1.40001 > 127.0.0.1.{seen['port']}: UDP"

        def fixture_probe(uid, kind, family, address, port, **kwargs):
            if uid == run.CONTROL_UID:
                seen["port"] = port
                return run.probe_main(kind, family, address, port) == 0
            # Model an emitted attempt whose client did not obtain a reply.
            # Even a late-scheduled fixture worker must observe this packet.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(b"unexpected", (address, port))
            return False

        with tempfile.TemporaryDirectory() as directory, \
             patch.object(run, "Recorder", FixtureRecorder), \
             patch.object(run, "probe", side_effect=fixture_probe), \
             patch.object(run.threading, "Thread", side_effect=delayed_thread), \
             patch.object(run, "stop_workers", side_effect=release_after_probes):
            with self.assertRaisesRegex(CaptureFailure, "DP resolver packet reached"):
                run.assert_resolver(Path(directory), 4)

    def test_fixture_io_failure_cannot_count_as_denial(self):
        real_socket = socket.socket
        for kind in ("forwarder", "resolver"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                seen = {"created": 0, "accepted": 0}
                stopped = []
                before = set(threading.enumerate())

                class FailedServer:
                    def __init__(self, sock):
                        self.sock = sock

                    def __getattr__(self, name):
                        return getattr(self.sock, name)

                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        self.sock.close()

                    def accept(self):
                        if seen["accepted"]:
                            seen["fault"] = True
                            raise OSError("injected accept failure after positive control")
                        peer = self.sock.accept()
                        seen["accepted"] += 1
                        return peer

                    def recvfrom(self, size):
                        seen["fault"] = True
                        raise OSError("injected resolver receive failure")

                class Datagram:
                    def __enter__(self):
                        return self

                    def __exit__(self, *args):
                        pass

                    def sendto(self, data, address):
                        # Keep this fixture fault regression on loopback only.
                        return len(data)

                def fixture_socket(family, typ, *args, **kwargs):
                    if kind == "forwarder" and typ == socket.SOCK_DGRAM:
                        return Datagram()
                    sock = real_socket(family, typ, *args, **kwargs)
                    if "fileno" not in kwargs:
                        seen["created"] += 1
                        if seen["created"] == (1 if kind == "forwarder" else 2):
                            return FailedServer(sock)
                    return sock

                class FixtureRecorder:
                    process = object()

                    def __init__(self, interface, expression, path):
                        self.interface = interface

                    def start(self):
                        pass

                    def stop(self):
                        stopped.append(self.interface)
                        if self.interface == "lo":
                            return f"IP 127.0.0.1.40001 > 127.0.0.1.{seen['port']}: packet"
                        return "IP 127.0.0.1.40001 > 198.51.100.77.39115: UDP"

                def fixture_probe(uid, probe_kind, family, address, port, **kwargs):
                    result = run.probe_main(probe_kind, family, address, port) == 0
                    if uid == run.CONTROL_UID:
                        seen.update(port=port, positive=result)
                    return result

                with patch.object(run, "Recorder", FixtureRecorder), \
                     patch.object(run, "probe", side_effect=fixture_probe), \
                     patch.object(run.socket, "socket", side_effect=fixture_socket):
                    with self.assertRaisesRegex(CaptureFailure, "fixture.*I/O failed"):
                        if kind == "forwarder":
                            run.assert_forwarder(Path(directory), 4, "fixture-egress")
                        else:
                            run.assert_resolver(Path(directory), 4)
                self.assertTrue(seen["positive"])
                self.assertTrue(seen["fault"])
                self.assertEqual(len(stopped), 2 if kind == "forwarder" else 1)
                self.assertEqual(set(threading.enumerate()) - before, set())

    def test_fixture_failure_joins_workers_and_stops_recorders(self):
        for kind in ("forwarder", "resolver"):
            for failure in ("capture", "probe"):
                with self.subTest(kind=kind, failure=failure), tempfile.TemporaryDirectory() as directory:
                    before = set(threading.enumerate())
                    stopped = []

                    class FixtureRecorder:
                        process = None

                        def __init__(self, *args):
                            pass

                        def start(self):
                            self.process = object()
                            if failure == "capture":
                                raise RuntimeError("fixture startup failed")

                        def stop(self):
                            stopped.append(True)
                            return ""

                    with patch.object(run, "Recorder", FixtureRecorder), \
                         patch.object(run, "probe", side_effect=RuntimeError("fixture probe failed")):
                        with self.assertRaisesRegex(RuntimeError, "fixture (startup|probe) failed"):
                            if kind == "forwarder":
                                run.assert_forwarder(Path(directory), 4, "fixture-egress")
                            else:
                                run.assert_resolver(Path(directory), 4)
                    self.assertTrue(stopped)
                    self.assertEqual(set(threading.enumerate()) - before, set())

    def test_stdin_probe_reaches_udp_fixture_from_shallow_and_normal_cwd(self):
        with tempfile.TemporaryDirectory() as fixture_root, \
             tempfile.TemporaryDirectory(dir="/tmp") as shallow, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            private_parent = Path(fixture_root) / "private"
            private_parent.mkdir(mode=0o700)
            source_path = private_parent / "runner.py"
            source_path.write_bytes(Path(run.__file__).read_bytes())
            source = source_path.read_bytes()
            private_parent.chmod(0)
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(2)
            try:
                for cwd in (shallow, str(run.ROOT)):
                    with self.subTest(cwd=cwd):
                        result = subprocess.run(
                            [sys.executable, "-", "--probe", "udp", "4", "127.0.0.1",
                             str(receiver.getsockname()[1])],
                            input=source, cwd=cwd, capture_output=True, timeout=3,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
                        self.assertEqual(result.stderr, b"T163-PROBE-EXECUTED\n")
                        self.assertEqual(receiver.recvfrom(32)[0], b"t163")
            finally:
                private_parent.chmod(0o700)

    def test_probe_launch_error_cannot_be_classified_as_denial(self):
        failed = subprocess.CompletedProcess([], 1, b"", b"Traceback: launch failed\n")
        with patch.object(run.subprocess, "run", return_value=failed):
            with self.assertRaises(CaptureFailure):
                run.probe(run.CONTROL_UID, "udp", 4, "127.0.0.1", 9)
        denied = subprocess.CompletedProcess([], 1, b"", b"T163-PROBE-EXECUTED\n")
        with patch.object(run.subprocess, "run", return_value=denied):
            self.assertFalse(run.probe(run.CONTROL_UID, "udp", 4, "127.0.0.1", 9))

    def test_recorder_reads_preface_and_ready_from_one_pipe_write(self):
        reader, writer = os.pipe()
        os.write(writer, b"tcpdump: data link type LINUX_SLL2\nlistening on synthetic\n")
        streams = []

        class Process:
            def __init__(self, *args, **kwargs):
                self.stderr = os.fdopen(reader, "r" if kwargs.get("text") else "rb")
                streams.append(self.stderr)

            def poll(self):
                return None

        recorder = run.Recorder("any", "tcp", Path("unused.pcap"))
        try:
            # The old readline consumed both lines into its text buffer but
            # select only saw an empty OS pipe, losing the readiness line.
            with patch.object(run.subprocess, "Popen", Process), \
                 patch.object(run.time, "monotonic", side_effect=[0, 0, 9]), \
                 patch.object(recorder, "stop", return_value=""):
                recorder.start()
            self.assertTrue(recorder.ready)
        finally:
            for stream in streams:
                stream.close()
            os.close(writer)

    def test_confined_probe_requires_proven_kernel_denial(self):
        self.assertFalse(run.confined_result(77))
        self.assertTrue(run.confined_result(0))
        for code in (1, 78, 79, 126, 127, -9, -11):
            with self.subTest(code=code):
                with self.assertRaises(CaptureFailure):
                    run.confined_result(code)

    def test_clean_capture_summary_accepts_singular_and_plural_tcpdump_counts(self):
        self.assertTrue(clean_capture_summary("1 packet captured\n1 packet received by filter\n0 packets dropped by kernel\n"))
        self.assertTrue(clean_capture_summary("10 packets captured\n20 packets received by filter\n0 packets dropped by kernel\n"))
        self.assertFalse(clean_capture_summary("tcpdump failed before its exit summary\n"))
        self.assertFalse(clean_capture_summary("3 packets captured\n4 packets received by filter\n1 packet dropped by kernel\n"))
        self.assertFalse(clean_capture_summary("3 packets captured\n"))

    def test_failed_recorder_still_stops_peer_recorder(self):
        stopped = []

        class FailedRecorder:
            process = object()

            def stop(self):
                stopped.append("failed")
                raise CaptureFailure("invalid pcap")

        class PeerRecorder:
            process = object()

            def stop(self):
                stopped.append("peer")
                return "decoded"

        with self.assertRaisesRegex(CaptureFailure, "invalid pcap"):
            stop_recorders([FailedRecorder(), PeerRecorder()])
        self.assertEqual(stopped, ["failed", "peer"])

    def test_missing_empty_and_failed_recorders_cannot_mean_zero_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            pcap = Path(directory) / "capture.pcap"
            for ready, returncode, decoded in (
                (False, 0, ""),
                (True, 124, ""),
                (True, 0, None),
            ):
                with self.subTest(ready=ready, returncode=returncode, decoded=decoded):
                    with self.assertRaises(CaptureFailure):
                        require_capture(pcap, ready, returncode, decoded)
            pcap.write_bytes(b"pcap")
            self.assertEqual(require_capture(pcap, True, 0, ""), "")

    def test_timeout_cannot_discriminate_filtered_from_routed_drop(self):
        # Both TCP connects can time out. Only the positive packet control
        # and decoded wire bytes distinguish the two possible paths.
        filtered = TimeoutError("connect timed out")
        routed_then_dropped = TimeoutError("connect timed out")
        self.assertEqual(str(filtered), str(routed_then_dropped))
        visible = "IP 198.51.100.1.40001 > 198.51.100.77.39111: Flags [S]"
        self.assertEqual(classify(visible, "198.51.100.77", 39111), 1)
        self.assertEqual(classify("", "198.51.100.77", 39111), 0)
        self.assertEqual(classify("IP6 2001:db8::1.40001 > 2001:db8::77.53: UDP, length 12",
                                  "2001:db8::77", 53), 1)
        with self.assertRaises(CaptureFailure):
            require_capture(Path("missing.pcap"), True, 0, "")

    def test_socks_method_exchange_requires_exact_two_bytes(self):
        self.assertTrue(socks_method_reply(bytes.fromhex("0502")))
        for reply in (b"", bytes.fromhex("05"), bytes.fromhex("0500"), bytes.fromhex("0502ff")):
            with self.subTest(reply=reply):
                self.assertFalse(socks_method_reply(reply))

    def test_dummy_resolver_control_receives_real_udp_reply(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver:
            resolver.bind(("127.0.0.1", 0))
            resolver.settimeout(2)
            seen = []

            def respond():
                data, sender = resolver.recvfrom(64)
                seen.append(data)
                resolver.sendto(b"t163", sender)

            worker = threading.Thread(target=respond, daemon=True)
            worker.start()
            self.assertEqual(probe_main("dns-reply", 4, "127.0.0.1", resolver.getsockname()[1]), 0)
            worker.join(timeout=2)
            self.assertEqual(seen, [b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"])

    def test_forwarder_control_accepts_split_tcp_reply(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as forwarder:
            forwarder.bind(("127.0.0.1", 0))
            forwarder.listen(1)
            forwarder.settimeout(2)
            release = threading.Event()

            def respond():
                with forwarder.accept()[0] as peer:
                    self.assertEqual(peer.recv(6), b"t163+")
                    peer.sendall(b"t1")
                    time.sleep(0.05)
                    peer.sendall(b"63")
                    release.wait(timeout=2)

            worker = threading.Thread(target=respond, daemon=True)
            worker.start()
            try:
                self.assertEqual(probe_main("forwarder", 4, "127.0.0.1", forwarder.getsockname()[1]), 0)
            finally:
                release.set()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
