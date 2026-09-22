# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""T165 falsifiers for deployed observer-boundary verdicts."""

import copy
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import observer as subject

from observer import (assert_boundary, assert_fixed_queries, assert_cp_capture,
                      assert_no_commands, assert_event_sequence,
                      sample_cursor, assert_safe_command_stream)


def fixture():
    cp = {
        "Config": {"User": "5101:5100", "Image": "stargate/control:local"},
        "HostConfig": {"NetworkMode": "none", "Mounts": []},
        "Mounts": [{"Destination": "/run/stargate-tor-observer", "RW": False}],
    }
    observer = {
        "Config": {"User": "5103:5100", "Image": "sha256:" + "a" * 64},
        "HostConfig": {"NetworkMode": "none", "Mounts": [
            {"Target": "/run/tor-control", "VolumeOptions": {"Subpath": "control"}},
        ]},
        "Mounts": [
            {"Destination": "/etc/stargate/observer-keys", "RW": False},
            {"Destination": "/run/stargate-tor-observer", "RW": True},
            {"Destination": "/run/tor-control", "RW": False},
        ],
    }
    tor = {
        "Config": {"Healthcheck": {"Test": ["NONE"]}},
        "HostConfig": {},
        "Mounts": [{"Destination": "/var/lib/tor", "RW": True}],
    }
    for service in (cp, observer, tor):
        service["Config"]["Healthcheck"] = {"Test": ["NONE"]}
        service["HostConfig"]["LogConfig"] = {"Type": "none"}
        service["State"] = {"Running": True}
    return cp, observer, tor


class ObserverBoundaryVerdictTest(unittest.TestCase):
    def test_authenticated_event_probe_socket_contract(self):
        root = Path(__file__).resolve().parents[3]
        result = subprocess.run(["go", "test", str(root / "tests/live-e2e/local-topology/observer_probe.go"),
                                 str(root / "tests/live-e2e/local-topology/observer_probe_test.go")],
                                cwd=root, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_positive_control(self):
        assert_boundary(*fixture())

    def test_full_tor_state_mount_is_rejected(self):
        cp, observer, tor = copy.deepcopy(fixture())
        observer["HostConfig"]["Mounts"][0]["VolumeOptions"]["Subpath"] = ""
        with self.assertRaisesRegex(AssertionError, "subpath"):
            assert_boundary(cp, observer, tor)

    def test_docker_socket_mount_is_rejected(self):
        cp, observer, tor = copy.deepcopy(fixture())
        cp["Mounts"].append({"Destination": "/var/run/docker.sock", "RW": False})
        with self.assertRaisesRegex(AssertionError, "Docker socket"):
            assert_boundary(cp, observer, tor)

    def test_post_t152_absent_health_metadata_accepts_current_boundary(self):
        cp, observer, tor = fixture()
        del tor["Config"]["Healthcheck"]
        assert_boundary(cp, observer, tor)

    def test_docker_health_history_cannot_be_restored(self):
        cp, observer, tor = copy.deepcopy(fixture())
        tor["Config"]["Healthcheck"]["Test"] = ["CMD", "true"]
        with self.assertRaisesRegex(AssertionError, "health history"):
            assert_boundary(cp, observer, tor)

    def test_operational_capture_cannot_be_restored(self):
        for index in range(3):
            services = fixture()
            services[index]["HostConfig"]["LogConfig"]["Type"] = "json-file"
            with self.assertRaisesRegex(AssertionError, "logging"):
                assert_boundary(*services)

    def test_disabled_docker_reader_is_not_a_retained_operational_archive(self):
        denial = "Error response from daemon: configured logging driver does not support reading\n"
        for code, stdout, stderr in ((0, "", ""), (1, "", denial)):
            subject.assert_empty_archive(subprocess.CompletedProcess([], code, stdout, stderr))
        for code, stdout, stderr in ((0, "raw marker", ""), (1, "raw marker", denial),
                                     (2, "", denial), (1, "", "unrelated Docker failure")):
            with self.subTest(code=code, stdout=stdout), self.assertRaises(AssertionError):
                subject.assert_empty_archive(subprocess.CompletedProcess([], code, stdout, stderr))

    def test_empty_dp_journal_uses_authenticated_ephemeral_observation(self):
        expected = [("STARTED", "container_start")]
        source = Mock()
        source.snapshot.return_value = expected
        with patch.object(subject.subprocess, "run",
                          return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            assert_event_sequence(subject.dp_events(source), expected)
            run.assert_not_called()

    def test_current_readiness_requires_authenticated_ready_not_running(self):
        for code in (1, 2, 125):
            with self.subTest(code=code), patch.object(subject.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], code, "", "")):
                with self.assertRaisesRegex(AssertionError, "readiness"):
                    subject.await_tor_ready("observer-fixture", timeout=0.01)
        with patch.object(subject.subprocess, "run",
                return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            subject.await_tor_ready("observer-fixture", timeout=0.01)
            self.assertEqual(run.call_args.args[0][-2:],
                             ["/opt/stargate/tor-observer", "--check-ready"])
            self.assertLessEqual(run.call_args.kwargs["timeout"], 6)

    def test_observer_key_volume_must_be_read_only(self):
        cp, observer, tor = copy.deepcopy(fixture())
        observer["Mounts"].append({"Destination": "/etc/stargate/observer-keys", "RW": True})
        with self.assertRaisesRegex(AssertionError, "observer key"):
            assert_boundary(cp, observer, tor)

    def test_forbidden_tor_command_is_rejected_even_after_positive_control(self):
        assert_fixed_queries(["AUTHENTICATE", "GETINFO", "QUIT"])
        with self.assertRaises(AssertionError):
            assert_fixed_queries(["AUTHENTICATE", "GETINFO", "SETCONF", "QUIT"])

    def test_cp_packet_verdict_requires_visible_control_and_no_tor_packet(self):
        positive = "IP 127.0.0.1.40000 > 127.0.0.1.39051: Flags [S]"
        escaped = "IP 10.0.0.2.40000 > 172.18.0.2.9051: Flags [S]"
        assert_cp_capture(positive, "172.18.0.2")
        with self.assertRaisesRegex(AssertionError, "positive"):
            assert_cp_capture("", "172.18.0.2")
        with self.assertRaisesRegex(AssertionError, "escaped"):
            assert_cp_capture(positive + "\n" + escaped, "172.18.0.2")

    def test_auth_refusal_verdict_rejects_hidden_tor_query(self):
        assert_no_commands(["AUTHENTICATE"], ["AUTHENTICATE"])
        with self.assertRaisesRegex(AssertionError, "Tor command"):
            assert_no_commands(["AUTHENTICATE"], ["AUTHENTICATE", "GETINFO"])

    def test_deployed_event_verdict_requires_positive_control_and_exact_transitions(self):
        expected = [("STARTED", "container_start"), ("HEALTHY", "healthcheck_pass"),
                    ("UNHEALTHY", "healthcheck_fail"), ("HEALTHY", "healthcheck_pass")]
        assert_event_sequence(expected, expected)
        with self.assertRaisesRegex(AssertionError, "event sequence"):
            assert_event_sequence([], expected)  # CP sampling disabled
        with self.assertRaisesRegex(AssertionError, "event sequence"):
            assert_event_sequence(expected + [expected[-1]], expected)
        with self.assertRaisesRegex(AssertionError, "event sequence"):
            assert_event_sequence([("RESTARTED", "container_start")] + expected[1:], expected)

    def test_ephemeral_subscriber_rejects_eof_unknown_and_overflow(self):
        for lines in ([], ["RAW_DETAIL"], ["HEALTHY"] * 17):
            with self.subTest(lines=len(lines)):
                observation = subject.EventObservation("unused", "/unused", "/unused")
                code = "import time; print('SUBSCRIBED',flush=True); "
                if lines:
                    code += "print(" + repr("\n".join(lines)) + ",flush=True); time.sleep(60)"
                observation.argv = [sys.executable, "-u", "-c", code]
                with self.assertRaisesRegex(AssertionError, "subscriber"):
                    with observation:
                        observation.snapshot()

    def test_ephemeral_subscriber_preserves_duplicates_and_clears_memory(self):
        observation = subject.EventObservation("unused", "/unused", "/unused")
        observation.argv = [sys.executable, "-u", "-c",
                            "import time; print('SUBSCRIBED\\nSTARTED\\nSTARTED',flush=True); time.sleep(60)"]
        with observation:
            actual = observation.snapshot()
            self.assertEqual(len(actual), 2)
            with self.assertRaisesRegex(AssertionError, "event sequence"):
                assert_event_sequence(actual, [("STARTED", "container_start")])
        self.assertEqual(observation.events, [])

    def test_timeout_matrix_waits_for_cp_classification_before_asserting_silence(self):
        clock = [0]
        fake = Mock()
        fake.snapshot.return_value = []
        observation = Mock()
        # The fake sees GETINFO immediately; CP can only classify its timeout
        # four seconds later. A false lifecycle event at that point must fail.
        observation.snapshot.side_effect = lambda: ([('CRASHED', 'container_exit')]
                                                    if clock[0] >= 4 else [])
        with patch.object(subject, 'await_control_sample', return_value=2), \
                patch.object(subject.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0]+seconds)):
            with self.assertRaisesRegex(AssertionError, 'event sequence'):
                subject.observe_phase(observation, fake, None, [], ['AUTHENTICATE', 'GETINFO'])

    def test_sample_cursor_does_not_skip_an_unexpected_following_command(self):
        commands = ["AUTHENTICATE", "GETINFO", "QUIT", "SETCONF"]
        self.assertEqual(sample_cursor(commands, 0,
                                       ["AUTHENTICATE", "GETINFO", "QUIT"]), 3)
        with self.assertRaisesRegex(AssertionError, "unexpected Tor commands"):
            sample_cursor(commands, 3, ["AUTHENTICATE", "GETINFO", "QUIT"])

    def test_complete_command_stream_rejects_forbidden_or_out_of_order_names(self):
        assert_safe_command_stream(["AUTHENTICATE", "GETINFO", "QUIT",
                                    "AUTHENTICATE", "GETINFO"])
        with self.assertRaisesRegex(AssertionError, "unexpected Tor command"):
            assert_safe_command_stream(["AUTHENTICATE", "GETINFO", "QUIT", "SETCONF"])
        with self.assertRaisesRegex(AssertionError, "unexpected Tor command"):
            assert_safe_command_stream(["GETINFO", "AUTHENTICATE"])


if __name__ == "__main__":
    unittest.main()
