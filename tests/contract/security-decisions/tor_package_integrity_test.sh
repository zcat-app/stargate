#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# T160 / Constitution IV: a signed mutable index must not replace the reviewed
# Tor package with different bytes under the same package name and version.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

python3 - <<'PY'
import hashlib
import os
from pathlib import Path
import re
import subprocess
import shutil
import tempfile
import sys

version = "0.4.9.12-1~d12.bookworm+1"
root = Path.cwd()
dockerfile = (root / "sidecars/tor/Dockerfile").read_text()
commands = re.sub(r"\\\n\s*", " ", dockerfile)
installer = root / "sidecars/tor/install-tor.sh"
pins = root / "sidecars/tor/tor-packages.sha256"
errors = []
if version not in commands:
    errors.append("Tor security release 0.4.9.12 is not selected")
if re.search(r"apt-get install [^&\n]*\btor=", commands):
    errors.append("Tor is installed directly from mutable metadata without a checked local artifact")
if f"/tmp/install-tor.sh {version} /tmp/tor-packages.sha256" not in commands:
    errors.append("Dockerfile does not invoke the content-checked Tor installer")
if not installer.is_file() or not pins.is_file():
    errors.append("build installer and architecture content pins must be delivered together")
if errors:
    raise SystemExit("FAIL: " + "\nFAIL: ".join(errors))

# Both supported architectures must have exactly one reviewed artifact identity.
rows = [line.split() for line in pins.read_text().splitlines() if line.strip()]
assert len(rows) == 2, "expected precisely amd64 and arm64 package pins"
assert {row[1] for row in rows} == {
    f"tor_{version}_amd64.deb", f"tor_{version}_arm64.deb"
}, "package filenames do not match the promoted version/architectures"
assert all(re.fullmatch(r"[0-9a-f]{64}", row[0]) for row in rows)
assert "COPY install-tor.sh tor-packages.sha256 /tmp/" in dockerfile
assert "rm -f /tmp/install-tor.sh /tmp/tor-packages.sha256" in commands
assert "--no-download" in installer.read_text(), "install phase can fetch a replacement after the hash check"

payload = b"deterministic fixture package bytes, version unchanged\n"
digest = hashlib.sha256(payload).hexdigest()

with tempfile.TemporaryDirectory(prefix="stargate-t160-") as tmp:
    work = Path(tmp)
    bindir = work / "bin"
    bindir.mkdir()
    (bindir / "dpkg").write_text('''#!/bin/sh
test "$1" = --print-architecture || exit 64
printf '%s\\n' "$FIXTURE_ARCH"
''')
    (bindir / "apt-get").write_text("#!" + sys.executable + "\n" + r'''import os
from pathlib import Path
import shutil
import subprocess
import sys
args = sys.argv[1:]
version = os.environ["FIXTURE_VERSION"]
arch = os.environ["FIXTURE_ARCH"]
package = f"tor_{version}_{arch}.deb"
options = dict(arg.split("=", 1) for arg in args if arg.startswith("Dir::"))
cache = Path(options.get("Dir::Cache::archives", "."))
if "download" in args:
    assert args[-1] == "tor=" + version
    if os.environ["FAIL_DOWNLOAD"] == "1":
        sys.exit(66)
    shutil.copyfile(os.environ["FIXTURE_PAYLOAD"], cache / package)
elif "--download-only" in args:
    assert cache.is_dir()
    assert args[-1] in ("tor=" + version, "./" + package)
    if os.environ["FAIL_DOWNLOAD"] == "1":
        sys.exit(66)
    fixture = os.environ.get("DEPENDENCY_FIXTURE")
    if fixture:
        # Exercise real APT's source selection under the installer's actual options.
        # The fixture is inert metadata: --print-uris never retrieves or executes it.
        snapshot_only = (options.get("Dir::Etc::sourcelist") ==
                         "/etc/apt/sources.list.d/snapshot.list" and
                         options.get("Dir::Etc::sourceparts") == "-")
        source = "snapshot.list" if snapshot_only else "sources.list"
        query = [os.environ["REAL_APT_GET"], "-o", "APT::Architecture=amd64",
                 "-o", "Dir::Etc::sourcelist=" + fixture + "/" + source,
                 "-o", "Dir::Etc::sourceparts=-",
                 "-o", "Dir::Etc::preferences=/dev/null",
                 "-o", "Dir::Etc::preferencesparts=-",
                 "-o", "Dir::State::lists=" + fixture + "/lists",
                 "-o", "Dir::State::status=/dev/null",
                 "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=",
                 "--print-uris", "download", "libevent-2.1-7"]
        result = subprocess.run(query, capture_output=True, text=True)
        print(result.stdout + result.stderr)
        assert result.returncode == 0, "APT fixture failed"
        assert result.stdout.startswith("'http://snapshot.debian.org/"), (
            "mutable Tor repository selected for a dependency")
    if args[-1] == "tor=" + version:
        shutil.copyfile(os.environ["FIXTURE_PAYLOAD"], cache / package)
else:
    assert "--no-download" in args
    if os.environ.get("DEPENDENCY_FIXTURE"):
        assert options.get("Dir::Etc::sourcelist") == "/etc/apt/sources.list.d/snapshot.list"
        assert options.get("Dir::Etc::sourceparts") == "-"
    Path(os.environ["INSTALL_RECORD"]).write_text("\n".join(args) + "\n")
''')
    for executable in bindir.iterdir():
        executable.chmod(0o755)

    def exercise(name, arch="amd64", contents=payload, missing_pin=False, download_fail=False, dependency_version=None):
        case = work / name
        case.mkdir()
        source = case / "payload"
        source.write_bytes(contents)
        checksum = case / "pins.sha256"
        checksum.write_text("" if missing_pin else f"{digest}  tor_{version}_{arch}.deb\n")
        record = case / "installed"
        env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                   FIXTURE_ARCH=arch, FIXTURE_VERSION=version,
                   FIXTURE_PAYLOAD=str(source), INSTALL_RECORD=str(record),
                   FAIL_DOWNLOAD="1" if download_fail else "0", TMPDIR=str(case))
        if dependency_version:
            real_apt = shutil.which("apt-get")
            assert real_apt, "real APT is required for the offline repository-selection regression"
            indexes = case / "indexes"
            (indexes / "lists").mkdir(parents=True)
            snapshot = "http://snapshot.debian.org/archive/debian/20260714T082229Z/"
            tor_repo = "https://deb.torproject.org/torproject.org"
            (indexes / "snapshot.list").write_text(f"deb {snapshot} bookworm main\n")
            # Put the adversarial repository first to challenge same-version source selection.
            (indexes / "sources.list").write_text(
                f"deb {tor_repo} bookworm main\ndeb {snapshot} bookworm main\n")
            for filename, selected_version, index_digest in (
                ("deb.torproject.org_torproject.org_dists_bookworm_main_binary-amd64_Packages",
                 dependency_version, "1" * 64),
                ("snapshot.debian.org_archive_debian_20260714T082229Z_dists_bookworm_main_binary-amd64_Packages",
                 "2.1.12-stable-8", "0" * 64),
            ):
                (indexes / "lists" / filename).write_text(
                    f"Package: libevent-2.1-7\nVersion: {selected_version}\nArchitecture: amd64\n"
                    f"Filename: pool/fixture/libevent.deb\nSize: 1\nSHA256: {index_digest}\n"
                    "Description: inert metadata, never retrieved or executed\n\n")
            env.update(DEPENDENCY_FIXTURE=str(indexes), REAL_APT_GET=real_apt)
        result = subprocess.run(["sh", str(installer), version, str(checksum)],
                                cwd=case, env=env, capture_output=True, text=True)
        return result, record

    for arch in ("amd64", "arm64"):
        result, record = exercise("valid-" + arch, arch=arch)
        assert result.returncode == 0, result.stdout + result.stderr
        arguments = record.read_text().splitlines()
        assert "--no-download" in arguments, arguments
        assert "--no-install-recommends" in arguments, arguments
        assert arguments[-1] == f"./tor_{version}_{arch}.deb", arguments

    for name, options in (
        ("substituted-same-version", {"contents": payload + b"changed"}),
        ("missing-pin", {"missing_pin": True}),
        ("failed-download", {"download_fail": True}),
        ("unsupported-architecture", {"arch": "ppc64el"}),
    ):
        result, record = exercise(name, **options)
        assert result.returncode != 0, name + " unexpectedly succeeded"
        assert not record.exists(), name + " reached installation before verification"

    for name, dependency_version in (("higher-version", "999.0"),
                                     ("same-version", "2.1.12-stable-8")):
        result, record = exercise("repository-" + name, dependency_version=dependency_version)
        assert result.returncode == 0, result.stdout + result.stderr
        assert record.exists(), "snapshot dependency selection did not reach checked installation"
        print(f"OK: {name} dependency control selected the Debian snapshot")

print("OK: T160 repository isolation, security version, checked local installation, amd64/arm64 and four rejection controls")
PY
