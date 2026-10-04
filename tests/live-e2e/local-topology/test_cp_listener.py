# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

import unittest
import subprocess
import sys
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import cp_listener


class ListenerProbeTest(unittest.TestCase):
    def test_http_case_rejects_extra_loopback_listener(self):
        view = {"families_inspected": [4, 6], "listeners": [
            {"family": 4, "address": "127.0.0.1", "port": port}
            for port in (8080, 40999, 9000)]}

        def command(argv, **kwargs):
            if argv[:2] == ["docker", "inspect"]:
                return json.dumps({"Running": True, "Pid": 123})
            return "200:0" if argv[0] == "nsenter" else "fixture"

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "config").mkdir()
            (output / "config/key.pem").touch()
            with patch.object(cp_listener, "checked", side_effect=command), \
                    patch.object(cp_listener, "calibrate", return_value={}), \
                    patch.object(cp_listener, "startup_observation", return_value=(view, "/run/stargate/control.sock")), \
                    patch.object(cp_listener.subprocess, "run"), \
                    patch.object(cp_listener.subprocess, "Popen") as process, \
                    patch.object(cp_listener.time, "sleep"), \
                    patch.object(cp_listener.time, "monotonic", side_effect=range(100)):
                process.return_value.poll.return_value = 0
                with self.assertRaisesRegex(AssertionError, "HTTP listener inventory differs"):
                    cp_listener.package_matrix("image", "keys", "config", output,
                                               only_case="management-runtime")

    def test_stalled_command_fails_instead_of_outliving_poll_deadline(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            cp_listener.checked([sys.executable, "-c", "import time; time.sleep(6)"])

    def test_docker_terminal_state_can_lag_process_exit(self):
        running = '{"Status":"running","Running":true,"ExitCode":0}'
        exited = '{"Status":"exited","Running":false,"ExitCode":1}'
        with patch.object(cp_listener, "snapshot", side_effect=FileNotFoundError), \
                patch.object(cp_listener, "checked", side_effect=[running, exited]), \
                patch.object(cp_listener.time, "sleep"):
            self.assertIsNone(cp_listener.startup_observation("fixture", 123, 1, True))

    def test_terminal_exit_is_not_a_clean_observation(self):
        for allowed, samples, state, accepted in (
                (True, 1, '{"Status":"exited","Running":false,"ExitCode":1}', True),
                (False, 1, '{"Status":"exited","Running":false,"ExitCode":1}', False),
                (True, 0, '{"Status":"exited","Running":false,"ExitCode":1}', False),
                (True, 1, '{"Status":"running","Running":true,"ExitCode":0}', False),
                (True, 1, '{"Status":"exited","Running":false,"ExitCode":0}', False)):
            with patch.object(cp_listener, "snapshot", side_effect=FileNotFoundError), \
                    patch.object(cp_listener, "checked", return_value=state), \
                    patch.object(cp_listener.time, "monotonic", side_effect=[0, 0, 10]):
                if accepted:
                    self.assertIsNone(cp_listener.startup_observation("fixture", 123, samples, allowed))
                else:
                    with self.assertRaises(FileNotFoundError):
                        cp_listener.startup_observation("fixture", 123, samples, allowed)
        with patch.object(cp_listener, "snapshot", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                cp_listener.startup_observation("fixture", 123, 1, True)

    def test_distinct_family_address_predicates(self):
        for family, address, allowed in ((4, "127.0.0.1", True), (4, "0.0.0.0", False),
                                         (6, "::1", False), (6, "::", False),
                                         (6, "::ffff:7f00:1", True),
                                         (6, "::ffff:c000:201", False)):
            row = {"families_inspected": [4, 6], "listeners": [
                {"family": family, "address": address, "port": 8080}]}
            if allowed:
                cp_listener.assert_boundary(row)
            else:
                with self.assertRaises(AssertionError):
                    cp_listener.assert_boundary(row)

    def test_empty_or_truncated_inspection_is_not_absence(self):
        for text in ("", "error", "local_address\ntruncated"):
            with self.assertRaises(ValueError):
                cp_listener.parse_table(text, 4)
        with self.assertRaises(FileNotFoundError):
            cp_listener.snapshot(2147483647)

    def test_little_endian_proc_addresses(self):
        with patch.object(cp_listener.sys, "byteorder", "little"):
            for family, encoded, expected in ((4, "0100007F", "127.0.0.1"),
                    (4, "00000000", "0.0.0.0"),
                    (6, "00000000000000000000000001000000", "::1"),
                    (6, "00000000000000000000000000000000", "::")):
                text = f"local_address\n0: {encoded}:1F90 0 0A 0 0 0 0 0 123"
                self.assertEqual(expected, cp_listener.parse_table(text, family)[0]["address"])

    def test_real_family_and_transient_controls(self):
        self.assertTrue(cp_listener.calibrate()["transient_forbidden_detected"])


if __name__ == "__main__":
    unittest.main()
