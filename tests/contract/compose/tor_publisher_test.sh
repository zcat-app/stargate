#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T203: real launcher control flow with private fixture paths and executables.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
python3 - <<'PY'
import os, pathlib, signal, subprocess, tempfile, time
with tempfile.TemporaryDirectory() as raw:
 d=pathlib.Path(raw)
 for path in ('run/tor-fabric/private','run/tor-health','var/lib/tor/control','usr/local/bin'):
  (d/path).mkdir(parents=True)
 (d/'var/lib/tor/control/control_auth_cookie').write_text('legacy')
 (d/'run/tor-health/latest').write_text('old READY')
 tor=d/'tor';tor.write_text('#!/bin/sh\necho $$ > "'+str(d/'tor.pid')+'"\ntrap "exit 0" TERM INT\nwhile :; do sleep 0.1; done\n');tor.chmod(0o755)
 pub=d/'usr/local/bin/tor-health-publisher';pub.write_text('#!/bin/sh\necho $$ > "'+str(d/'publisher.pid')+'"\ntrap "" TERM INT\nwhile :; do sleep 0.1; done\n');pub.chmod(0o755)
 script=pathlib.Path('sidecars/tor/entrypoint.sh').read_text()
 for prefix in ('/run/tor-', '/var/lib/tor', '/usr/local/bin/tor-health-publisher'):
  script=script.replace(prefix,str(d)+prefix)
 launcher=d/'entrypoint';launcher.write_text(script)
 p=subprocess.Popen(['sh',str(launcher)],env={**os.environ,'PATH':str(d)+':'+os.environ['PATH']})
 try:
  deadline=time.monotonic()+3
  while time.monotonic()<deadline and not (d/'publisher.pid').exists():time.sleep(.05)
  assert (d/'publisher.pid').exists(),'publisher never supervised'
  assert not (d/'var/lib/tor/control/control_auth_cookie').exists(),'legacy cookie remains'
  assert not (d/'run/tor-health/latest').exists(),'old READY survives startup'
  pubpid=int((d/'publisher.pid').read_text());os.kill(pubpid,signal.SIGSTOP)
  start=time.monotonic();p.terminate();p.wait(timeout=3)
  assert time.monotonic()-start<3,'stopped publisher blocked shutdown'
  for name in ('tor.pid','publisher.pid'):
   pid=int((d/name).read_text())
   try:os.kill(pid,0)
   except ProcessLookupError:continue
   raise AssertionError(name+' orphaned')
  assert not (d/'run/tor-health/latest').exists(),'shutdown retained READY'
 finally:
  for name in ('tor.pid','publisher.pid'):
   if (d/name).exists():
    try:os.kill(int((d/name).read_text()),signal.SIGKILL)
    except ProcessLookupError:pass
  if p.poll() is None:p.kill()
  p.wait()
print('PASS: launcher invalidation, upgrade and bounded stop/reap with stopped publisher')
PY
