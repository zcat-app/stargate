# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""Deterministic rejection tests for the live timeout experiment's decisions."""

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import legacy_timeout_probe as legacy
from run import CaptureFailure


CONTROL = "IP 198.51.100.1.40001 > 198.51.100.2.39111: Flags [S], length 0\n"
ESCAPED = "IP 198.51.100.1.40002 > 198.51.100.2.39112: Flags [S], length 0\n"
COUNTER_HEADER = ("Chain T163_TIMEOUT (1 references)\n"
                  " pkts bytes target prot opt in out source destination\n")
COUNTER = COUNTER_HEADER + " 1 60 DROP all -- * * 0.0.0.0/0 0.0.0.0/0\n"


class LegacyTimeoutEvidenceTest(unittest.TestCase):
    def exercise(self, packets=(CONTROL, CONTROL), counter=COUNTER,
                 outcomes=("TimeoutError", "TimeoutError")):
        # Replace privileged I/O, not the experiment's parsing, classification,
        # verdict or cleanup path. The unchanged instrument also has live proof.
        calls, stopped = [], []

        def command(*args):
            calls.append(args)
            if args[:2] == (sys.executable, "-c"):
                result = outcomes[0 if args[-1] == "39111" else 1]
                if isinstance(result, Exception):
                    raise result
                return result
            if args[:2] == ("iptables", "-L"):
                return counter
            return ""

        class Recorder:
            process = None

            def __init__(self, interface, expression, path):
                self.interface = interface

            def start(self):
                self.process = object()

            def stop(self):
                stopped.append(self.interface)
                result = packets[0 if self.interface == "any" else 1]
                if isinstance(result, Exception):
                    raise result
                return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(legacy, "ROOT", root), \
                 patch.object(legacy.os, "geteuid", return_value=0), \
                 patch.dict(legacy.os.environ, STARGATE_LIVE_E2E="1", STARGATE_DISPOSABLE_HOST="1"), \
                 patch.object(legacy.shutil, "which", return_value="fixture-tool"), \
                 patch.object(legacy.time, "sleep"), \
                 patch.object(legacy, "command", side_effect=command), \
                 patch.object(legacy, "Recorder", Recorder), \
                 contextlib.redirect_stdout(io.StringIO()):
                try:
                    legacy.main()
                except Exception:
                    self.assertEqual(list(root.rglob("result.json")), [])
                    raise
                finally:
                    self.assertEqual(stopped, ["any", "t163-timeout0"])
                    self.assertEqual([args[:2] for args in calls[-5:]],
                                     [("iptables", "-D"), ("iptables", "-F"),
                                      ("iptables", "-X"), ("ip", "link"), ("ip", "netns")])
                    self.assertEqual(calls[-2:], [("ip", "link", "del", "t163-timeout0"),
                                                  ("ip", "netns", "del", "t163-timeout")])
            results = list(root.rglob("result.json"))
            self.assertEqual(len(results), 1)
            return json.loads(results[0].read_text())

    def test_valid_discrimination_publishes_observed_counts(self):
        result = self.exercise()
        self.assertEqual(result["owner_drop_packets"], 1)
        self.assertEqual(result["outcomes"], {"routed_then_dropped": "TimeoutError",
                                              "filtered": "TimeoutError"})
        self.assertEqual(result["captures"], [
            {"interface": "any", "routed_syns": 1, "filtered_syns": 0},
            {"interface": "t163-timeout0", "routed_syns": 1, "filtered_syns": 0},
        ])

    def test_either_capture_rejects_emitted_filtered_syn(self):
        for packets in ((CONTROL + ESCAPED, CONTROL), (CONTROL, CONTROL + ESCAPED)):
            with self.subTest(packets=packets), self.assertRaises(RuntimeError):
                self.exercise(packets=packets)

    def test_either_capture_requires_routed_positive_control(self):
        for packets in (("", CONTROL), (CONTROL, "")):
            with self.subTest(packets=packets), self.assertRaises(RuntimeError):
                self.exercise(packets=packets)

    def test_zero_missing_and_malformed_owner_counters_fail(self):
        for counter in (COUNTER.replace(" 1 60 DROP", " 0 0 DROP"), COUNTER_HEADER,
                        COUNTER.replace(" 1 60 DROP", " unknown 60 DROP")):
            with self.subTest(counter=counter), self.assertRaises((RuntimeError, IndexError, ValueError)):
                self.exercise(counter=counter)

    def test_both_children_must_report_timeout(self):
        for outcomes in (("connected", "TimeoutError"), ("TimeoutError", "ConnectionRefusedError"),
                         ("", "TimeoutError")):
            with self.subTest(outcomes=outcomes), self.assertRaises(RuntimeError):
                self.exercise(outcomes=outcomes)

    def test_child_launch_and_capture_errors_never_publish_success(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.exercise(outcomes=("TimeoutError", subprocess.CalledProcessError(1, ["probe"])))
        with self.assertRaises(CaptureFailure):
            self.exercise(packets=(CaptureFailure("invalid capture"), CONTROL))

    def test_command_propagates_nonzero_child_exit(self):
        with self.assertRaises(subprocess.CalledProcessError):
            legacy.command(sys.executable, "-c", "raise SystemExit(9)")


if __name__ == "__main__":
    unittest.main()
