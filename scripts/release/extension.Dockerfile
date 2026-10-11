# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# Keep outside extension/: package.sh intentionally archives its source tree.
FROM debian:12-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

# HTTP transports signed metadata, not authority. The base's pinned Debian
# keyring must authenticate this exact InRelease; no unsigned/expiry bypass.
# dpkg installs only the checked local debs; audit refuses incomplete dependency
# configuration without asking the apt resolver to fetch another archive.
RUN test "$(dpkg --print-architecture)" = amd64 \
 && rm -f /etc/apt/sources.list \
 && rm -rf /etc/apt/sources.list.d \
 && mkdir /etc/apt/sources.list.d \
 && printf '%s\n' 'deb http://snapshot.debian.org/archive/debian/20260714T082229Z/ bookworm main' > /etc/apt/sources.list.d/snapshot.list \
 && apt-get update \
 && printf '%s\n' '77737fa4b34f2693e982cc9ee35736816c35a7778fc2d326cc1bbf5b301fe1aa  /var/lib/apt/lists/snapshot.debian.org_archive_debian_20260714T082229Z_dists_bookworm_InRelease' | sha256sum -c - \
 && mkdir /tmp/packages \
 && cd /tmp/packages \
 && apt-get download zip=3.0-13 libbz2-1.0=1.0.8-5+b1 \
 && printf '%s\n' \
      '8877a360e455c7b9b6d448503eeaacc6b9a1325b548f3fb7eef69a87ab558b96  zip_3.0-13_amd64.deb' \
      '54149da3f44b22d523b26b692033b84503d822cc5122fed606ea69cc83ca5aeb  libbz2-1.0_1.0.8-5+b1_amd64.deb' | sha256sum -c - \
 && dpkg -i ./libbz2-1.0_1.0.8-5+b1_amd64.deb ./zip_3.0-13_amd64.deb \
 && dpkg --audit \
 && printf '%s\n' \
      'f718b59a4b1a647d2a9ce52fdec4011b626f581d5fd34ba598aae333611600ce  /usr/bin/zip' \
      'e4f501c8bd22390e42422691093d8af4e744a3e854809b809948055e8b08bda5  /lib/x86_64-linux-gnu/libbz2.so.1.0.4' | sha256sum -c - \
 && rm -rf /var/lib/apt/lists/* /tmp/packages

WORKDIR /source
