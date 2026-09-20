#!/bin/sh
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0

set -eu

# T162 / Constitution III: Tor requires its native socket directory to be
# private. Re-expose only the SOCKS inode at the DP fabric root. The control
# socket and cookie stay inside Tor's separate private DataDirectory.
native=/run/tor-fabric/private/tor-socks.sock
exposed=/run/tor-fabric/tor-socks.sock
rm -f "$native" "$exposed" /var/lib/tor/control/tor-control.sock
tor -f /etc/tor/torrc &
tor_pid=$!
trap 'kill "$tor_pid" 2>/dev/null || true; wait "$tor_pid" 2>/dev/null || true; exit 143' INT TERM

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

wait "$tor_pid"
