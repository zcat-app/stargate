#!/bin/sh
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# Constitution IV / T160: apt authenticates the current repository, then the
# reviewed content pin prevents same-version replacement by that repository.
set -eu

version=$1
pins=$2
arch=$(dpkg --print-architecture)
case "$arch" in
    amd64|arm64) ;;
    *) echo "Unsupported Tor package architecture: $arch" >&2; exit 1 ;;
esac

package="tor_${version}_${arch}.deb"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
cd "$work"

# Fetch only Tor while its authenticated repository is available. Dependencies
# must not inherit that mutable source's authority (Constitution IV / T160).
apt-get download "tor=$version"
awk -v package="$package" '$2 == package' "$pins" > expected.sha256
sha256sum --check expected.sha256

# APT priorities select versions, not necessarily the source of identical
# versions. Exclude the Tor repository entirely while resolving dependencies.
set -- -o "Dir::Cache::archives=$work" \
    -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/snapshot.list \
    -o Dir::Etc::sourceparts=-
apt-get "$@" --download-only install -y --no-install-recommends "./$package"
# APT can refetch even a local package; prohibit downloads after verification.
apt-get "$@" --no-download install -y --no-install-recommends "./$package"
