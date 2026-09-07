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

// CheckListener verifies a listen address against the T125-amended FR-010
// bind policy for the given deployment mode.
//
// The user-approved amend-spec (2026-09-07, SECURITY-DECISIONS.md) moved
// the loopback-only HOST guarantee out of the in-container bind address:
// Docker's port publishing can only reach the container's eth0, so a
// container-loopback listener (the literal FR-010 reading) is unreachable
// from the host and contradicts FR-005. In a compose deployment the
// guarantee is carried by the host-published `127.0.0.1:8881:8881`
// binding plus the container network namespace (THREAT-MODEL §3.1), and
// the listener binds the container-wide address instead.
//
// Policy:
//   - loopback: accepted in both modes (Check's contract, preserved).
//   - unspecified address (0.0.0.0/::): accepted ONLY behind
//     containerBoundary — i.e. when the caller attests the process runs
//     inside the compose network namespace (main.go wires
//     STARGATE_IN_CONTAINER=1 from the compose file). Bare metal keeps
//     the original loopback-only contract.
//   - a SPECIFIC non-loopback interface literal: refused in both modes —
//     the listener may be container-wide, never pointed at a shared
//     interface (a LAN/public address must never be bindable, whoever
//     sets the env).
//   - malformed input / hostnames: refused (same as Check — ParseAddr
//     rejects names, so resolution cannot smuggle a bind past this gate).
//
// The function stays pure: parsed IP literals only, no I/O, no
// resolution; the deployment mode arrives as a parameter, not from the
// environment — env wiring is the caller's decision (and is what the
// compose structural contract pins).
func CheckListener(addr string, containerBoundary bool) error {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return fmt.Errorf("bind refused %q: not an IP literal: %w", addr, ErrBindRefused)
	}
	if ip.IsLoopback() {
		return nil
	}
	if containerBoundary && ip.IsUnspecified() {
		return nil
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("bind refused %q: wildcard bind requires the container boundary (STARGATE_IN_CONTAINER=1): %w", addr, ErrBindRefused)
	}
	return fmt.Errorf("bind refused %q: not loopback: %w", addr, ErrBindRefused)
}
