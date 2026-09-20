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
