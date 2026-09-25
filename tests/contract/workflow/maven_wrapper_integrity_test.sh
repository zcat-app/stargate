#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T145: exercise the checked-in only-script wrapper against local archive bytes.
set -euo pipefail

python3 - "$(git rev-parse --show-toplevel)" <<'PY'
from pathlib import Path
import hashlib
import http.server
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import zipfile

root = Path(sys.argv[1])
wrapper = root / 'control-plane/mvnw'
properties = root / 'control-plane/.mvn/wrapper/maven-wrapper.properties'
assert 'distributionSha256Sum=' in properties.read_text()
assert 'wrapperSha256Sum=' not in properties.read_text(), 'only-script has no wrapper JAR to hash'
windows_wrapper = (root / 'control-plane/mvnw.cmd').read_text()
assert windows_wrapper.index('if (!$distributionSha256Sum)') < windows_wrapper.index('if (Test-Path -Path "$MAVEN_HOME"'), 'Windows presence gate must precede cached Maven'

with tempfile.TemporaryDirectory(prefix='stargate-t145-') as tmp:
    work = Path(tmp)
    class RequestRecorder(http.server.BaseHTTPRequestHandler):
        requests = 0

        def do_GET(self):
            type(self).requests += 1
            self.send_error(404)

        def log_message(self, *args):
            pass

    recorder = http.server.ThreadingHTTPServer(('127.0.0.1', 0), RequestRecorder)
    thread = threading.Thread(target=recorder.serve_forever, daemon=True)
    thread.start()
    bindir = work / 'bin'
    bindir.mkdir()
    fake_wget = bindir / 'wget'
    fake_wget.write_text('#!/bin/sh\nset -eu\nwhile [ "$#" -gt 0 ]; do\n'
                         '  if [ "$1" = -O ]; then shift; dest=$1; fi\n'
                         '  shift\ndone\ncp "$FIXTURE_ARCHIVE" "$dest"\n'
                         'printf downloaded >> "$DOWNLOAD_MARKER"\n')
    fake_wget.chmod(0o755)

    use_zip = shutil.which('unzip') is not None
    archive = work / ('apache-maven-fixture-bin.zip' if use_zip else 'apache-maven-fixture-bin.tar.gz')
    content = b'#!/bin/sh\nprintf executed >> "$EXEC_MARKER"\n'
    buf = io.BytesIO()
    if use_zip:
        with zipfile.ZipFile(buf, 'w') as zf:
            item = zipfile.ZipInfo('apache-maven-fixture/bin/mvn')
            item.external_attr = 0o100755 << 16
            zf.writestr(item, content)
    else:
        with tarfile.open(fileobj=buf, mode='w:gz') as tf:
            item = tarfile.TarInfo('apache-maven-fixture/bin/mvn')
            item.mode = 0o755
            item.size = len(content)
            tf.addfile(item, io.BytesIO(content))
    good = buf.getvalue()
    digest = hashlib.sha256(good).hexdigest()
    wrapper_dir = work / 'control-plane'
    (wrapper_dir / '.mvn/wrapper').mkdir(parents=True)
    (wrapper_dir / 'mvnw').write_bytes(wrapper.read_bytes())
    prop = wrapper_dir / '.mvn/wrapper/maven-wrapper.properties'
    url = 'https://example.invalid/org/apache/maven/apache-maven/fixture/apache-maven-fixture-bin.zip'
    base = f'distributionUrl={url}\n'
    parent_env = dict(os.environ, MVNW_USERNAME='fixture-user',
                      MVNW_PASSWORD='fixture-password',
                      MVNW_REPOURL=f'http://127.0.0.1:{recorder.server_port}')
    env = dict(parent_env, PATH=f'{bindir}{os.pathsep}{parent_env["PATH"]}',
               MAVEN_USER_HOME=str(work / 'm2'), FIXTURE_ARCHIVE=str(archive),
               DOWNLOAD_MARKER=str(work / 'downloaded'), EXEC_MARKER=str(work / 'executed'))
    # Paired credentials select the wrapper's Java downloader; an inherited
    # repository override can then send this fixture's request to a real host.
    for name in ('MVNW_USERNAME', 'MVNW_PASSWORD', 'MVNW_REPOURL'):
        env.pop(name, None)

    def run(checksum, payload=good, cached=False):
        prop.write_text(base + (f'distributionSha256Sum={checksum}\n' if checksum is not None else ''))
        archive.write_bytes(payload)
        for marker in ('downloaded', 'executed'):
            (work / marker).unlink(missing_ok=True)
        if not cached:
            subprocess.run(['rm', '-rf', str(work / 'm2')], check=True)
        result = subprocess.run(['sh', str(wrapper_dir / 'mvnw')], env=env,
                                cwd=wrapper_dir, capture_output=True, text=True)
        return result, (work / 'downloaded').exists(), (work / 'executed').exists()

    result, downloaded, executed = run(digest)
    assert (result.returncode, downloaded, executed) == (0, True, True), (result.stdout, result.stderr)
    result, downloaded, executed = run(digest, cached=True)
    assert (result.returncode, downloaded, executed) == (0, False, True), result.stderr
    for checksum in (None, ''):
        result, downloaded, executed = run(digest)
        assert (result.returncode, downloaded, executed) == (0, True, True), result.stderr
        result, downloaded, executed = run(checksum, cached=True)
        assert result.returncode != 0 and not downloaded and not executed, result.stderr
        result, downloaded, executed = run(checksum)
        assert result.returncode != 0 and not downloaded and not executed, result.stderr
    result, downloaded, executed = run(digest, good + b'changed')
    assert result.returncode != 0 and downloaded and not executed, result.stderr
    recorder.shutdown()
    recorder.server_close()
    thread.join()
    assert RequestRecorder.requests == 0, 'fixture contacted the inherited repository'

print('PASS: Maven wrapper checks local archive bytes and refuses absent checksum')
PY
