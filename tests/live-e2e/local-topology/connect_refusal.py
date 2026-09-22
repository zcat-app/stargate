# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""T173: deployed Local stop/restart, HTTP refusal and real Tor positive control.

Run as root on an already initialized disposable Local stack. The caller owns
installation/cleanup. Only synthetic credentials are provisioned; socket traces
contain Unix endpoint paths, never auth or application buffers.
"""
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TOR_PATH = '/run/stargate-tor/tor-socks.sock'


def validate_trace(refused, control, overruns, missed):
    assert overruns and not any(overruns) and missed == 0, 'missing or lost trace evidence'
    assert '(fault)' not in refused + control and 'path=(null)' not in refused + control, 'invalid endpoint fetch'
    marker = f'path="{TOR_PATH}"'
    assert marker not in refused, 'HTTP caused a DP-to-Tor connect'
    assert marker in control, 'no observed Tor connect positive control'


def checked(argv, timeout=120):
    result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'{argv[0]} failed: exit {result.returncode}')
    return result.stdout.strip()


def receive(conn, n):
    data = b''
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part:
            raise AssertionError('incomplete SOCKS response')
        data += part
    return data


def connect(token):
    conn = socket.create_connection(('127.0.0.1', 8881), timeout=10)
    conn.settimeout(45)
    try:
        conn.sendall(b'\x05\x01\x02')
        assert receive(conn, 2) == b'\x05\x02', 'method refusal'
        user = b'sg1:' + hashlib.sha256(b't173-device-profile-normal-example.com').hexdigest().encode()
        conn.sendall(b'\x01' + bytes([len(user)]) + user + bytes([len(token)]) + token)
        assert receive(conn, 2) == b'\x01\x00', 'auth refusal'
        target = b'example.com'
        conn.sendall(b'\x05\x01\x00\x03' + bytes([len(target)]) + target + b'\x00\x50')
        assert receive(conn, 10) == b'\x05\x00\x00\x01' + bytes(6), 'Tor route not established'
        return conn
    except BaseException:
        conn.close()
        raise


class Trace:
    def __init__(self):
        self.root = Path('/sys/kernel/tracing')
        self.instance = self.root / 'instances/t173'

    def __enter__(self):
        self.instance.mkdir()
        self.probe_created = False
        try:
            self.instance.joinpath('buffer_size_kb').write_text('4096')
            # unix_stream_connect receives a kernel sockaddr_un; sun_path starts
            # after sa_family_t. Linux documents argument/string fetches.
            self.update_probe('p:t173_connect unix_stream_connect path=+2($arg2):string task=$comm\n')
            self.probe_created = True
            self.instance.joinpath('events/kprobes/t173_connect/filter').write_text('task == "stargate-proxy"')
            self.instance.joinpath('events/kprobes/t173_connect/enable').write_text('1')
            self.instance.joinpath('tracing_on').write_text('1')
        except BaseException:
            self.__exit__()
            raise
        return self

    def take(self):
        self.instance.joinpath('tracing_on').write_text('0')
        data = self.instance.joinpath('trace').read_text()
        overruns = []
        for path in self.instance.glob('per_cpu/cpu*/stats'):
            fields = dict(line.split(':', 1) for line in path.read_text().splitlines() if ':' in line)
            overruns.extend(int(fields[k].strip()) for k in ('overrun', 'commit overrun', 'dropped events'))
        assert overruns, 'missing per-CPU trace accounting'
        profile = [line.split() for line in self.root.joinpath('kprobe_profile').read_text().splitlines() if line.split()[0] == 't173_connect']
        assert len(profile) == 1, 'missing kprobe accounting'
        self.instance.joinpath('trace').write_text('')
        self.instance.joinpath('tracing_on').write_text('1')
        return data, overruns, int(profile[0][2])

    def __exit__(self, *_):
        self.instance.joinpath('tracing_on').write_text('0')
        if self.probe_created:
            self.instance.joinpath('events/kprobes/t173_connect/enable').write_text('0')
        self.instance.rmdir()
        if self.probe_created:
            self.update_probe('-:t173_connect\n')

    def update_probe(self, command):
        # tracefs rejects seek-to-end; O_TRUNC would remove other probes.
        fd = os.open(self.root / 'kprobe_events', os.O_WRONLY)
        try:
            os.write(fd, command.encode())
        finally:
            os.close(fd)


def run():
    assert os.geteuid() == 0 and os.environ.get('STARGATE_DISPOSABLE_HOST') == '1'
    assert os.environ.get('STARGATE_LIVE_E2E') == '1'
    project = os.environ['STARGATE_PROJECT']
    evidence = Path(os.environ['STARGATE_EVIDENCE_DIR'])
    evidence.mkdir(parents=True, exist_ok=True)
    candidate = os.environ['STARGATE_CANDIDATE_IMAGE']
    assert re.fullmatch(r'sha256:[0-9a-f]{64}', candidate), 'candidate must be immutable image ID'
    prefix = ['docker', 'compose', '-p', project, '-f', str(ROOT / 'compose/docker-compose.local.yml'), '--env-file', os.environ['STARGATE_ENV_FILE']]
    dp = checked(prefix + ['ps', '-q', 'stargate-dp'])
    old = json.loads(checked(['docker', 'inspect', dp]))[0]
    old_binary_hash = hashlib.sha256(Path(f"/proc/{old['State']['Pid']}/exe").read_bytes()).hexdigest()
    token = secrets.token_hex(16).encode()
    config = Path(checked(['docker', 'volume', 'inspect', '--format', '{{.Mountpoint}}', project + '_stargate-control-config'])) / 'tokens.yaml'
    config.write_text('tokens:\n  - label: t173-disposable\n    token: ' + token.decode() + '\n')
    os.chown(config, 5101, 5100)
    config.chmod(0o600)
    held = None
    for attempt in range(3):
        print(f'CP startup attempt {attempt + 1}', flush=True)
        checked(prefix + ['restart', 'stargate-control'])
        # TCG JVM startup can itself take 160s; setup has its own bounded
        # budget. Protocol/refusal deadlines and production settings stay fixed.
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                held = connect(token)
                break
            except (OSError, AssertionError) as exc:
                last_failure = f'{type(exc).__name__}: {exc}'
                time.sleep(3)
        if held:
            break
        print(f'CP attempt {attempt + 1} did not establish control: {last_failure}', flush=True)
    assert held is not None, 'old candidate did not establish authenticated Tor tunnel'
    print('PASS: old candidate authenticated Tor tunnel', flush=True)
    checked(prefix + ['stop', 'stargate-control'])
    checked(prefix + ['stop', 'stargate-dp'])
    with held:
        held.settimeout(10)
        assert held.recv(1) == b'', 'old pipe not closed on stop'
    try:
        with socket.create_connection(('127.0.0.1', 8881), timeout=3):
            raise AssertionError('admission remained open after stop')
    except ConnectionRefusedError:
        pass
    state = Path(checked(['docker', 'volume', 'inspect', '--format', '{{.Mountpoint}}', project + '_stargate-dp-state'])) / 'dp-snapshot.json'
    snapshot_hash = hashlib.sha256(state.read_bytes()).hexdigest()
    checked(['docker', 'tag', candidate, 'stargate/stargate-dp:local'])
    checked(prefix + ['up', '-d', '--no-build', '--no-deps', '--force-recreate', 'stargate-dp'])
    dp = checked(prefix + ['ps', '-q', 'stargate-dp'])
    new = json.loads(checked(['docker', 'inspect', dp]))[0]
    assert new['Image'] == candidate and new['HostConfig']['NetworkMode'] == 'host'
    assert new['AppArmorProfile'] == 'stargate-dp'
    assert old['Image'] != new['Image'], 'migration requires different old/new images'
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', 8881), timeout=3) as conn:
                conn.sendall(b'\x05\x01\x02')
                assert receive(conn, 2) == b'\x05\x02'
            break
        except OSError:
            time.sleep(1)
    else:
        raise AssertionError('candidate listener unavailable')
    pid = new['State']['Pid']
    assert Path(f'/proc/{pid}/comm').read_text().strip() == 'stargate-proxy'
    dp_pids = [p.parent.name for p in Path('/proc').glob('[0-9]*/comm') if p.read_text().strip() == 'stargate-proxy']
    assert dp_pids == [str(pid)], 'trace command filter is ambiguous'
    with Trace() as trace:
        for label, credential in [('valid', token), ('missing', None), ('malformed', b'malformed')]:
            request = b'CONNECT example.com:80 HTTP/1.1\r\n'
            if credential is not None:
                request += b'Proxy-Authorization: Bearer ' + credential + b'\r\n'
            request += b'Proxy-Stargate-Isolation: sg1:' + b'a' * 64 + b'\r\nOrigin: https://a.example\r\n\r\n'
            with socket.create_connection(('127.0.0.1', 8881), timeout=5) as conn:
                conn.settimeout(5)
                conn.sendall(request)
                try:
                    assert conn.recv(1) == b'', 'HTTP response bytes returned'
                except ConnectionResetError:
                    pass
            print(f'PASS: HTTP {label} silent close', flush=True)
        time.sleep(1)
        refused, negatives, missed_negative = trace.take()
        with connect(token) as conn:
            conn.sendall(b'HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
            assert conn.recv(128).startswith(b'HTTP/'), 'no destination bytes through real Tor'
        control, positives, missed_positive = trace.take()
        validate_trace(refused, control, negatives + positives, missed_negative + missed_positive)
        evidence.joinpath('refusal.trace').write_text(refused)
        evidence.joinpath('positive.trace').write_text(control)
    assert hashlib.sha256(state.read_bytes()).hexdigest() == snapshot_hash, 'snapshot changed during offline restart'
    evidence.joinpath('result.json').write_text(json.dumps({
        'result': 'PASS', 'cp_startup_attempt': attempt + 1, 'old_image': old['Image'], 'candidate_image': candidate,
        'old_container': old['Id'], 'candidate_container': dp, 'dp_pid': pid,
        'old_binary_sha256': old_binary_hash,
        'candidate_binary_sha256': hashlib.sha256(Path(f'/proc/{pid}/exe').read_bytes()).hexdigest(),
        'probe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'compose_sha256': hashlib.sha256((ROOT / 'compose/docker-compose.local.yml').read_bytes()).hexdigest(),
        'kernel': os.uname().release, 'dp_netns': os.readlink(f'/proc/{pid}/ns/net'),
        'host_netns': os.readlink('/proc/self/ns/net'), 'apparmor': new['AppArmorProfile'],
        'http_cases': 3, 'http_tor_connects': 0, 'socks_destination_bytes': True,
        'old_pipe_closed': True, 'stopped_listener_refused': True, 'snapshot_preserved': True,
        'cp_stopped': True, 'trace_overruns': negatives + positives, 'trace_missed': missed_negative + missed_positive,
    }, indent=2) + '\n')
    print('PASS: deployed refusal, traced Tor control, stop/restart and retained offline auth', flush=True)


if __name__ == '__main__':
    run()
