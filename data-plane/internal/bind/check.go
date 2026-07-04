// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package bind implements the FR-010 bind-safety check: the data plane
// refuses to start if its bind address would publish on a non-loopback
// interface in the local profile. The single function Check is pure —
// no sockets, no listener side effects, no DNS resolution — and is
// called by the startup sequence (T050) BEFORE any listener opens.
package bind

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrBindRefused is the sentinel returned by Check when addr is not a
// loopback IP literal. The startup sequence classifies the failure mode
// via errors.Is(err, ErrBindRefused) and exits non-zero on a match
// (FR-010 / arch §10.1 BIND_REFUSED row). Wrapped errors carry context
// for debuggability; callers MUST match with errors.Is, not equality or
// string comparison.
var ErrBindRefused = errors.New("BIND_REFUSED")

// Check verifies that addr is a loopback IP literal (FR-010).
//
// Returns nil if addr parses as a loopback IP (IPv4 127.0.0.0/8 or IPv6
// ::1). Returns an error wrapping ErrBindRefused for any non-loopback
// IP, hostname, malformed input, or empty string.
//
// The function is pure: it performs no I/O of any kind. netip.ParseAddr
// rejects hostnames outright — it is a string parser, not a resolver —
// so name resolution cannot smuggle a non-loopback bind past this gate.
// This is the load-bearing property the `localhost` row of check_test.go
// exists to pin: a future "helpful" refactor that resolves hostnames
// upstream before calling Check would silently break the local-profile
// invariant.
func Check(addr string) error {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return fmt.Errorf("bind refused %q: not an IP literal: %w", addr, ErrBindRefused)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("bind refused %q: not loopback: %w", addr, ErrBindRefused)
	}
	return nil
}
