# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""T165 falsifiers for deployed observer-boundary verdicts."""

import copy
import unittest

from observer import (assert_boundary, assert_fixed_queries, assert_cp_capture,
                      assert_no_commands, assert_event_sequence, parse_dp_events,
                      has_dp_event_stream, sample_cursor, assert_safe_command_stream)


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
        "Config": {"Healthcheck": {"Test": ["CMD-SHELL",
            "od /var/lib/tor/control_auth_cookie; AUTHENTICATE; GETINFO status/bootstrap-phase; "
            "nc -U /var/lib/tor/control/tor-control.sock"]}},
        "Mounts": [{"Destination": "/var/lib/tor", "RW": True}],
    }
    return cp, observer, tor


class ObserverBoundaryVerdictTest(unittest.TestCase):
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

    def test_native_tor_healthcheck_cannot_use_cp_fabric(self):
        cp, observer, tor = copy.deepcopy(fixture())
        tor["Config"]["Healthcheck"]["Test"][1] = "nc -U /run/stargate-tor-observer/health.sock"
        with self.assertRaisesRegex(AssertionError, "Tor-native healthcheck"):
            assert_boundary(cp, observer, tor)

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
        lines = "\n".join(
            f'time=2026-09-21T16:00:00Z level=INFO msg="sidecar event" '
            f'sidecar=tor kind=EVENT_KIND_{kind} detail={detail}'
            for kind, detail in expected)
        assert_event_sequence(parse_dp_events(lines), expected)
        with self.assertRaisesRegex(AssertionError, "event sequence"):
            assert_event_sequence(parse_dp_events(""), expected)  # CP sampling disabled
        with self.assertRaisesRegex(AssertionError, "event sequence"):
            assert_event_sequence(parse_dp_events(lines + "\n" + lines.splitlines()[-1]), expected)
        with self.assertRaisesRegex(AssertionError, "event sequence"):
            assert_event_sequence(parse_dp_events(lines.replace("EVENT_KIND_HEALTHY",
                                                        "EVENT_KIND_RESTARTED", 1)), expected)

    def test_event_stream_readiness_requires_connected_control_socket(self):
        listening = 'u_str LISTEN 0 4096 /run/stargate/control.sock 42 * 0'
        wrong = 'u_str ESTAB 0 0 /run/stargate/dp.sock 43 * 44'
        connected = 'u_str ESTAB 0 0 /run/stargate/control.sock 45 * 46'
        self.assertFalse(has_dp_event_stream(listening))
        self.assertFalse(has_dp_event_stream(wrong))
        self.assertTrue(has_dp_event_stream(listening + '\n' + connected))

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
