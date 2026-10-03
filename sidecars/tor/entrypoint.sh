#!/bin/sh
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

# Suppress shell startup errors and Tor diagnostics before any private state is read (III).
exec >/dev/null 2>&1
set -eu

# T162 / Constitution III: Tor requires its native socket directory to be
# private. Re-expose only the SOCKS inode at the DP fabric root. The control
# socket and cookie stay inside Tor's separate private DataDirectory.
native=/run/tor-fabric/private/tor-socks.sock
exposed=/run/tor-fabric/tor-socks.sock
# T203: remove the obsolete observer hardlink on upgrade and invalidate before
# Tor starts. The volatile sample is never an input into this trusted launcher.
rm -f /var/lib/tor/control/control_auth_cookie /run/tor-health/latest /run/tor-health/pending
rm -f "$native" "$exposed" /var/lib/tor/control/tor-control.sock
tor -f /etc/tor/torrc &
tor_pid=$!
/usr/local/bin/tor-health-publisher &
publisher_pid=$!

stop_publisher() {
    kill "$publisher_pid" 2>/dev/null || true
    # A SIGSTOPed helper cannot process TERM. Bound this independently of its
    # four-second control query so it cannot hold Tor shutdown or republish.
    sleep 0.2
    kill -KILL "$publisher_pid" 2>/dev/null || true
    wait "$publisher_pid" 2>/dev/null || true
    rm -f /run/tor-health/latest /run/tor-health/pending
}
shutdown() {
    trap '' INT TERM
    kill "$tor_pid" 2>/dev/null || true
    stop_publisher
    wait "$tor_pid" 2>/dev/null || true
    exit 143
}
trap shutdown INT TERM

same_inode() {
    [ "$(stat -Lc '%d:%i' "$1" 2>/dev/null)" = "$(stat -Lc '%d:%i' "$2" 2>/dev/null)" ]
}

while kill -0 "$tor_pid" 2>/dev/null; do
    if [ -S "$native" ]; then
        if [ ! -S "$exposed" ] || ! same_inode "$native" "$exposed"; then
            ln -f "$native" "$exposed"
        fi
        chgrp 5200 "$native"
        chmod 0660 "$native"
    fi
    sleep 0.2
done

stop_publisher
# Preserve Tor's exit status; helper failure never terminates Tor forwarding.
wait "$tor_pid"
