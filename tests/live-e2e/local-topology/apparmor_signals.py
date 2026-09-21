# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

"""T170: production AppArmor startup, lifecycle and signal-peer regression."""

import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
PROFILE = ROOT / 'compose/apparmor/stargate-dp'
IMAGE = 'stargate/stargate-dp:local'
NAME = 't170-signal-lifecycle'
PORT = 18881


def command(*args, check=True, timeout=60, env=None):
    return subprocess.run(args, cwd=ROOT, env=env, check=check, text=True,
                          capture_output=True, timeout=timeout)


def profile_loaded():
    return any(line.startswith('stargate-dp (') for line in
               Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines())


def ready():
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', PORT), timeout=0.5) as connection:
                connection.sendall(bytes.fromhex('050102'))
                reply = b''
                while len(reply) < 2:
                    chunk = connection.recv(2 - len(reply))
                    if not chunk:
                        break
                    reply += chunk
                if reply == bytes.fromhex('0502'):
                    return True
        except OSError:
            pass
        time.sleep(0.2)
    return False


def container_pid():
    pid = int(command('docker', 'inspect', '-f', '{{.State.Pid}}', NAME).stdout)
    if pid <= 0:
        raise RuntimeError('no running DP PID for host signal control')
    return pid


def main():
    if (os.geteuid() != 0 or os.environ.get('STARGATE_LIVE_E2E') != '1'
            or os.environ.get('STARGATE_DISPOSABLE_HOST') != '1'):
        raise RuntimeError('requires root and explicit disposable live-host opt-in')
    command('docker', 'info')
    if profile_loaded():
        raise RuntimeError('production profile already loaded; use a fresh disposable host')
    if command('docker', 'inspect', NAME, check=False).returncode == 0:
        raise RuntimeError('lifecycle fixture container already exists')
    with socket.socket() as check_port:
        check_port.bind(('127.0.0.1', PORT))

    with tempfile.TemporaryDirectory(prefix='t170-signals-') as temporary:
        fixture = Path(temporary)
        keys = fixture / 'keys'
        keys.mkdir(mode=0o750)
        os.chown(keys, 5101, 5100)
        # Public fixture only: no enrolled tokens or real device credentials.
        pepper = keys / 'pepper.key'
        pepper.write_bytes(bytes(range(32)))
        pepper.chmod(0o640)
        os.chown(pepper, 5101, 5100)
        probe = fixture / 'profileprobe'
        build_env = os.environ.copy()
        build_env['CGO_ENABLED'] = '0'
        command('go', 'build', '-o', str(probe), './tests/contract/compose/profileprobe',
                env=build_env, timeout=180)

        created = False
        loaded = False
        target = None
        try:
            command('apparmor_parser', '-T', '-r', str(PROFILE))
            loaded = True
            if 'stargate-dp (enforce)' not in Path('/sys/kernel/security/apparmor/profiles').read_text():
                raise RuntimeError('production profile is not enforcing')
            command('docker', 'run', '-d', '--name', NAME, '--network', 'host',
                    '--read-only', '--user', '5102:5100', '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges:true', '--security-opt', 'apparmor=stargate-dp',
                    '--tmpfs', '/tmp', '--tmpfs', '/run', '--memory', '512m', '--pids-limit', '256',
                    '-v', f'{keys}:/etc/stargate/keys:ro',
                    '-e', f'STARGATE_LISTEN_ADDR=127.0.0.1:{PORT}',
                    '-e', 'STARGATE_TOR_SOCKS_ADDR=unix:///run/stargate-tor/tor-socks.sock', IMAGE)
            created = True
            for index, (kind, expected) in enumerate((('TERM', '0'), ('INT', '0'), ('KILL', '137'))):
                if index:
                    command('docker', 'start', NAME)
                admitted = ready()
                if admitted and index == 0:
                    try:
                        os.kill(container_pid(), signal.SIGUSR1)
                    except PermissionError:
                        print('PASS: unapproved host USR1 signal denied', flush=True)
                    else:
                        raise RuntimeError('profile admitted an unapproved host signal')
                if kind == 'INT':
                    os.kill(container_pid(), signal.SIGINT)
                    stopped = True
                elif kind == 'TERM':
                    stopped = command('docker', 'stop', '--time', '10', NAME, check=False).returncode == 0
                else:
                    stopped = command('docker', 'kill', '--signal', 'KILL', NAME, check=False).returncode == 0
                print(f'OBSERVED: {kind} startup_method_reply={admitted} signal_succeeded={stopped}', flush=True)
                if not admitted or not stopped:
                    raise RuntimeError(f'{kind}: production startup/lifecycle requirement failed')
                code = command('docker', 'wait', NAME, timeout=30).stdout.strip()
                if code != expected:
                    raise RuntimeError(f'{kind}: exit {code}, expected {expected}')
                print(f'PASS: production profile startup and {kind} exit {code}', flush=True)

            target = subprocess.Popen(['sleep', '300'], user=5102, group=5100, extra_groups=[])
            # Host PID visibility is a test-only falsifier: DAC permits this UID
            # to signal the target. AppArmor must independently deny other peers.
            for policy, expected, marker in (('unconfined', 0, 'OK'), ('stargate-dp', 77, 'DENIED')):
                result = command('docker', 'run', '--rm', '--network', 'none', '--pid', 'host',
                                 '--read-only', '--user', '5102:5100', '--cap-drop', 'ALL',
                                 '--security-opt', 'no-new-privileges:true',
                                 '--security-opt', f'apparmor={policy}',
                                 '-v', f'{probe}:/opt/stargate/stargate-proxy:ro',
                                 IMAGE, 'signal-exists', str(target.pid), check=False)
                if result.returncode != expected or result.stdout.strip() != marker or target.poll() is not None:
                    raise RuntimeError(f'signal peer control {policy} failed: exit {result.returncode}')
                print(f'PASS: signal-zero peer control {policy}: {marker}', flush=True)
        finally:
            if target is not None:
                target.terminate()
                target.wait(timeout=10)
            removal = command('docker', 'rm', '-f', NAME, check=False) if created else None
            if loaded:
                command('apparmor_parser', '-T', '-R', str(PROFILE))
            if removal is not None and removal.returncode:
                # Recover disposable state after the OLD profile's denial, but
                # never turn that recovery into a passing lifecycle assertion.
                command('docker', 'rm', '-f', NAME)
                raise RuntimeError('Docker cleanup was denied under the enforcing profile')
    print('PASS: T170 AppArmor signal lifecycle and peer boundary')


if __name__ == '__main__':
    main()
