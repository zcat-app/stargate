# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""T165 falsifiers for deployed observer-boundary verdicts."""

import copy
import heapq
import json
import socket
import subprocess
import sys
import tempfile
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
        "HostConfig": {"NetworkMode": "none", "Mounts": []},
        "Mounts": [
            {"Destination": "/etc/stargate/observer-keys", "RW": False},
            {"Destination": "/run/stargate-tor-observer", "RW": True},
            {"Destination": "/run/tor-health", "RW": False,"Name":"health","Source":"/vol/health"},
        ],
    }
    tor = {
        "Config": {"Healthcheck": {"Test": ["NONE"]}},
        "HostConfig": {},
        "Mounts": [{"Destination": "/var/lib/tor", "RW": True,"Name":"state","Source":"/vol/state"},{"Destination":"/run/tor-health","RW":True,"Name":"health","Source":"/vol/health"}],
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
        observer["Mounts"].append({"Destination":"/alternate","RW":False,"Name":"state","Source":"/vol/state/control"})
        with self.assertRaisesRegex(AssertionError, "Tor authority"):
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
        # The fake sees GETINFO immediately; CP can only classify its timeout
        # four seconds later. A false lifecycle event at that point must fail.
        with self.assertRaisesRegex(AssertionError, 'event sequence'):
            run_cp_events(bug=SimBug("CRASHED", lambda world, health: world.fake.reply is None))

    def test_cp_event_windows_survive_emulated_slow_actions(self):
        # T196: under QEMU TCG a Docker start/stop takes seconds and the old fixed
        # 35 s windows overran the CP's 40 s max connection age (36 s with jitter).
        world, report = run_cp_events(start=10.0, stop=10.0, connect=2.0)
        self.assertEqual(len(report["phases"]), 8)
        self.assertTrue(all(phase["exact_events"] for phase in report["phases"].values()))
        self.assertFalse([w for w in world.windows if w.cut], "a window outlived the CP lifetime")
        lifetimes = [w.closed - w.opened for w in world.windows]
        self.assertLess(max(lifetimes), SimWorld.LIFETIME - 1, lifetimes)
        self.assertLessEqual(max(phase["max_window_seconds"] for phase in report["phases"].values()),
                             max(lifetimes) + 0.1)
        # No continuity is claimed; each phase states what its silence rests on.
        self.assertNotIn("continuous_overlapping_windows", report)
        for name, phase in report["phases"].items():
            want = ANCHOR_ALLOWANCE if name in ("malformed-and-repeat", "timeout-and-repeat") else ANCHOR_EVENT
            self.assertEqual(phase["silence_anchor"], want, name)

    def test_window_registered_after_the_transition_rejects_the_run(self):
        # Astra round 1: a successor window whose server registration is delayed
        # past the transition (and so past a duplicate published at the repeat
        # sample) must not vouch for silence. Every silent window must first
        # have received its phase's transition event.
        with self.assertRaisesRegex(AssertionError, "event sequence"):
            run_cp_events(start=10.0, stop=10.0, register_delays={2: 15.0},
                          bug=SimBug("STARTED", lambda world, health: world.fake.reply == subject.NOT_READY,
                                     repeat=True))

    def test_cp_event_relay_observes_the_repeat_sample_and_its_call_budget(self):
        # A duplicate published by the repeat sample, as late as the CP's
        # six-second call cap allows, must still land in an open window.
        for kind, when in (("STARTED", lambda world, health: world.fake.reply == subject.NOT_READY),
                           ("UNHEALTHY", lambda world, health: not world.observer_up)):
            with self.subTest(kind=kind), self.assertRaisesRegex(AssertionError, "event sequence"):
                run_cp_events(start=10.0, stop=10.0, bug=SimBug(kind, when, repeat=True, late=5.5))

    def test_cp_event_relay_requires_the_positive_transitions(self):
        with self.assertRaisesRegex(AssertionError, "event sequence"):
            run_cp_events(bug=SimBug(None, lambda world, health: True))

    def test_reply_samples_count_only_samples_served_after_the_trigger(self):
        query = ["AUTHENTICATE", "GETINFO", "QUIT"]
        fake = Mock()
        fake.snapshot.return_value = query * 3
        # The first sample read the previous reply generation: it is not a
        # sample of this phase even though it follows the phase's mark.
        fake.served.return_value = [(1, 1, 10.0), (4, 2, 20.0), (7, 2, 30.0)]
        self.assertEqual(subject.await_reply_samples(fake, 2, query, 2), [20.0, 30.0])
        clock = SimClock()
        fake.snapshot.return_value = query * 2 + ["AUTHENTICATE", "GETINFO"]
        with patch.object(subject, "time", clock), \
                self.assertRaisesRegex(AssertionError, "did not sample"):
            subject.await_reply_samples(fake, 2, query, 2, timeout=5)
        fake.snapshot.return_value = query + ["AUTHENTICATE", "GETINFO", "SETCONF"] + query
        with patch.object(subject, "time", clock), \
                self.assertRaisesRegex(AssertionError, "unexpected Tor commands"):
            subject.await_reply_samples(fake, 2, query, 2, timeout=5)
        # Nothing may come between the counted samples either.
        fake.snapshot.return_value = query + ["SETCONF"] + query
        fake.served.return_value = [(1, 2, 10.0), (5, 2, 20.0)]
        with patch.object(subject, "time", clock), \
                self.assertRaisesRegex(AssertionError, "unexpected Tor commands"):
            subject.await_reply_samples(fake, 2, query, 2, timeout=5)

    def test_fake_tor_records_the_reply_generation_of_each_bootstrap_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = subject.FakeTor(Path(tmp) / "control.sock")
            first = fake.set_reply(subject.NOT_READY)
            second = fake.set_reply(subject.READY)
            self.assertEqual(second, first + 1)
            client, server = socket.socketpair()
            with client:
                client.sendall(b"AUTHENTICATE 00\r\nGETINFO status/bootstrap-phase\r\nQUIT\r\n")
                fake.exchange(server)
                received = b""
                while chunk := client.recv(4096):
                    received += chunk
                self.assertIn(b"PROGRESS=100", received)
            self.assertEqual(fake.snapshot(), ["AUTHENTICATE", "GETINFO", "QUIT"])
            ((index, generation, _),) = fake.served()
            self.assertEqual((index, generation), (1, second))

    def test_ephemeral_subscriber_close_is_idempotent(self):
        observation = subject.EventObservation("unused", "/unused", "/unused")
        observation.argv = [sys.executable, "-u", "-c",
                            "import time; print('SUBSCRIBED',flush=True); time.sleep(60)"]
        with observation:
            observation.close()
            observation.close()

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


class SimClock:
    """Stand-in for observer.time: sleeping advances virtual time."""

    def __init__(self, world=None):
        self.world = world
        self.now = 0.0

    def monotonic(self):
        return self.world.now if self.world else self.now

    def sleep(self, seconds):
        if self.world:
            self.world.advance(seconds)
        else:
            self.now += max(0.0, seconds)


class SimBug:
    """A faulty CP publication: drop the transitions or add an event."""

    def __init__(self, kind, when, repeat=False, late=0.0):
        self.kind, self.when, self.repeat, self.late = kind, when, repeat, late
        self.armed = not repeat


class SimFake:
    def __init__(self, world):
        self.world = world
        self.commands = []
        self.log = []
        self.reply = subject.NOT_READY
        self.generation = 0

    def record(self, name, served=False):
        self.commands.append(name)
        if served:
            self.log.append((len(self.commands) - 1, self.generation, self.world.now))

    def snapshot(self):
        return list(self.commands)

    def set_reply(self, reply):
        self.reply = reply
        self.generation += 1
        return self.generation

    def served(self):
        return list(self.log)


class SimWindow:
    """Stand-in for EventObservation against the simulated CP event server."""

    def __init__(self, world):
        self.world = world
        self.events = []
        self.opened = self.attached = self.closed = None
        self.cut = False

    def __enter__(self):
        world = self.world
        self.opened = world.now
        world.windows.append(self)
        world.schedule(self.opened + world.LIFETIME, self.goaway)
        world.advance(world.connect)              # TLS handshake until SUBSCRIBED
        # Server registration lags the client; a test may delay a given window.
        world.schedule(world.now + 0.5 + world.register_delays.get(len(world.windows), 0.0), self.attach)
        world.advance(1.0)                        # EventObservation's attach allowance
        return self

    def attach(self):
        if self.closed is None:
            self.attached = self.world.now

    def goaway(self):
        if self.closed is None:
            self.cut = True

    def snapshot(self):
        if self.cut:
            raise AssertionError("event subscriber closed or violated the finite boundary")
        return list(self.events)

    def close(self):
        if self.closed is None:
            self.closed = self.world.now

    def __exit__(self, *_):
        self.close()


class SimWorld:
    """Discrete-time model of the deployed CP monitor, observer and fake Tor.

    Mirrors SidecarMonitor: one sample, its transition events, then a ten-second
    sleep; the CP's observer call is capped at six seconds and a timed-out Tor
    query is classified after the observer's four-second budget. The CP's event
    server closes a subscriber LIFETIME seconds after it connects: 40 s maximum
    connection age less grpc-java's 10 % jitter (ControlGrpcService, T148).
    """

    POLL = 10.0
    LIFETIME = 36.0

    def __init__(self, tmp, *, start=1.0, stop=1.0, restart=20.0, connect=1.5,
                 sample=0.6, delivery=0.2, bug=None, register_delays=None):
        self.now = 0.0
        self.queue = []
        self.seq = 0
        self.tmp = tmp
        self.durations = {"start": start, "stop": stop, "restart": restart}
        self.connect, self.sample, self.delivery = connect, sample, delivery
        self.bug = bug
        self.register_delays = register_delays or {}
        self.observer_up = True
        self.frozen = True      # validate() pauses the CP before the event phases
        self.overdue = False
        self.epoch = 0          # CP incarnation; a restart retires the old sampler
        self.ever_valid, self.previous = True, "READY"
        self.windows = []
        self.fake = SimFake(self)
        self.ipc = tmp / "ipc"
        self.ipc.mkdir()
        (tmp / "keys").mkdir()
        self.recreate_socket()
        self.cached_health, self.sample_start = "UNAVAILABLE", -10.0
        self.schedule(0.0, self.publisher_tick)
        self.schedule(0.0, self.tick, self.epoch)

    def schedule(self, when, function, *args):
        self.seq += 1
        heapq.heappush(self.queue, (when, self.seq, function, args))

    def advance(self, seconds):
        target = self.now + max(0.0, seconds)
        while self.queue and self.queue[0][0] <= target:
            when, _, function, args = heapq.heappop(self.queue)
            self.now = max(self.now, when)
            function(*args)
        self.now = target

    def recreate_socket(self):
        # Bind the replacement before retiring the old file: a distinct inode.
        staged = self.ipc / "control.new"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(staged))
        listener.close()
        staged.replace(self.ipc / "control.sock")

    def set_observer(self, up):
        self.observer_up = up

    def publisher_tick(self):
        reply, start = self.fake.reply, self.now
        self.fake.record("AUTHENTICATE")
        self.fake.record("GETINFO", served=True)
        delay = 4.0 if reply is None else 0.05
        health = {subject.READY: "READY", subject.NOT_READY: "NOT_READY"}.get(reply, "UNAVAILABLE")
        def complete():
            self.cached_health, self.sample_start = health, start
            self.fake.record("QUIT")
            self.schedule(self.now + 1.0, self.publisher_tick)
        self.schedule(self.now + delay, complete)

    def tick(self, epoch):
        if epoch != self.epoch:
            return
        if self.frozen:
            self.overdue = True
            return
        health = self.cached_health if self.observer_up and self.now - self.sample_start < 4 else "UNAVAILABLE"
        self.schedule(self.now + self.sample, self.finish, epoch, health)

    def finish(self, epoch, health):
        if epoch != self.epoch:
            return
        events = []
        if not self.ever_valid and health != "UNAVAILABLE":
            self.ever_valid = True
            events.append(("STARTED", "container_start"))
        if health == "READY" and self.previous != "READY":
            events.append(("HEALTHY", "healthcheck_pass"))
        elif self.previous == "READY" and health != "READY":
            events.append(("UNHEALTHY", "healthcheck_fail"))
        late = 0.0
        bug = self.bug
        if bug is not None and bug.when(self, health):
            if bug.kind is None:
                events = []
            elif bug.repeat and not bug.armed:
                bug.armed = any(kind == bug.kind for kind, _ in events)
            elif bug.armed:
                events.append((bug.kind, "duplicate" if bug.repeat else "false"))
                late, bug.armed = bug.late, False
        self.previous = health
        for event in events:
            self.schedule(self.now + self.delivery + late, self.deliver, event)
        self.schedule(self.now + self.POLL, self.tick, epoch)

    def deliver(self, event):
        for window in self.windows:
            if window.attached is not None and window.closed is None and not window.cut:
                window.events.append(event)

    def checked(self, argv, timeout=60):
        if argv[:3] == ["docker", "volume", "inspect"]:
            return str(self.ipc if argv[-1].endswith("_stargate-ipc") else self.tmp / "keys")
        if argv[:2] == ["docker", "kill"]:
            if argv[2] == "--signal=STOP":
                self.frozen = True
            else:
                self.frozen = False
                if self.overdue:
                    self.overdue = False
                    self.schedule(self.now, self.tick, self.epoch)
            self.advance(0.3)
            return ""
        if argv[-2:] == ["restart", "stargate-control"]:
            self.epoch += 1
            self.frozen = self.overdue = False
            for window in self.windows:
                window.cut = window.cut or window.closed is None
            self.advance(self.durations["restart"])
            self.recreate_socket()
            self.ever_valid, self.previous = False, "UNAVAILABLE"
            self.schedule(self.now + 5.0, self.tick, self.epoch)
            return ""
        if "stop" in argv and ("tor-observer" in argv or "observer-sim" in argv):
            self.schedule(self.now + 1.0, self.set_observer, False)
            self.advance(self.durations["stop"])
            return ""
        if argv[:2] == ["docker", "start"]:
            self.schedule(self.now + self.durations["start"] / 2, self.set_observer, True)
            self.advance(self.durations["start"])
            return ""
        raise AssertionError(f"unexpected harness command {argv}")


ANCHOR_EVENT = "transition event received in this window before its repeat sample"
ANCHOR_ALLOWANCE = "1 s post-SUBSCRIBED allowance only; no event anchors registration"


def run_cp_events(**kwargs):
    with tempfile.TemporaryDirectory() as tmp:
        world = SimWorld(Path(tmp), **kwargs)
        world.fake.set_reply(subject.READY)
        with patch.object(subject, "time", SimClock(world)), \
                patch.object(subject, "checked", world.checked), \
                patch.object(subject, "EventObservation", lambda *_: SimWindow(world)):
            subject.exercise_cp_events(Path(tmp), world.fake, ["docker", "compose", "-p", "sim"],
                                       "sim", "cp-sim", "observer-sim", "probe")
        report = json.loads((Path(tmp) / "T174-cp-events.json").read_text())
    return world, report


if __name__ == "__main__":
    unittest.main()
