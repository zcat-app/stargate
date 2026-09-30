#!/bin/sh
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
#
# T184 / Constitution IV: refuse rolled-back Debian metadata and any drift in
# the Tor image's installed package closure.
#
# Why: snapshot.debian.org InRelease files carry no Valid-Until and apt's
# Max-ValidTime defaults to 0, so over plain HTTP an on-path attacker can serve
# an OLDER, genuinely signed bookworm index at the pinned snapshot URL; apt
# accepts it and resolves older libraries (libssl3 3.0.17 instead of 3.0.20).
# A signature authenticates origin, not freshness. Two committed pins in
# package-closure.lock close that:
#
#   inrelease  Run after EVERY `apt-get update`, before anything is installed
#              from its result. The stored snapshot InRelease must match the
#              reviewed SHA-256. apt has already verified its signature and
#              binds every Packages index (and so every .deb sha256) to it.
#   closure    Run after the last installation. Every installed package's
#              name, version, architecture and authenticated archive SHA-256
#              must equal this architecture's rows in the lock, exactly.
#   print      Emit this architecture's actual closure rows (manual promotion
#              aid, Principle IV; never used to accept a change automatically).
#
# A row's SHA-256 is the .deb hash that the enabled, signature-verified indexes
# record for that exact identity; `base` means no enabled index carries it, so
# it can only have come from the digest-pinned base image. An identity that two
# indexes record with different hashes prints AMBIGUOUS and never matches.
set -eu

mode=$1
lock=$2
lists=/var/lib/apt/lists

closure() {
    arch=$(dpkg --print-architecture)
    {
        for index in $(apt-get indextargets --format '$(FILENAME)' 'Created-By: Packages'); do
            /usr/lib/apt/apt-helper cat-file "$index"
            echo
        done | awk '
            /^Package: /      { p = $2 }
            /^Version: /      { v = $2 }
            /^Architecture: / { a = $2 }
            /^SHA256: /       { h = $2 }
            /^$/ { if (p != "") print "I", p, v, a, h; p = v = a = h = "" }
            END  { if (p != "") print "I", p, v, a, h }'
        dpkg-query -W -f='D ${Package} ${Version} ${Architecture}\n'
    } | awk -v arch="$arch" '
        $1 == "I" { k = $2 " " $3 " " $4
                    if ((k in hash) && hash[k] != $5) hash[k] = "AMBIGUOUS"; else hash[k] = $5
                    next }
        $1 == "D" { k = $2 " " $3 " " $4; print arch, k, ((k in hash) ? hash[k] : "base") }' \
      | LC_ALL=C sort
}

case "$mode" in
    inrelease)
        # A missing InRelease (e.g. a forced Release/Release.gpg fallback)
        # yields no match and fails closed, as does a missing lock row.
        awk -v lists="$lists" '$1 == "inrelease" { print $2 "  " lists "/" $3 }' "$lock" \
          | sha256sum --check --strict --quiet - \
          || { echo "T184: snapshot InRelease does not match the pinned hash in package-closure.lock (rolled-back or substituted index)" >&2; exit 1; }
        ;;
    closure)
        arch=$(dpkg --print-architecture)
        expected=$(awk -v arch="$arch" '$1 == arch' "$lock" | LC_ALL=C sort)
        actual=$(closure)
        if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
            echo "T184: installed package closure differs from package-closure.lock for $arch" >&2
            printf '%s\n' "$expected" > /tmp/closure.expected
            printf '%s\n' "$actual" > /tmp/closure.actual
            diff -u /tmp/closure.expected /tmp/closure.actual >&2 || true
            exit 1
        fi
        ;;
    print)
        closure
        ;;
    *)
        echo "usage: verify-closure.sh inrelease|closure|print <lock>" >&2
        exit 64
        ;;
esac
