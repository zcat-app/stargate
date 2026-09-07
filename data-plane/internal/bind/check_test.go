// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package bind

import (
	"errors"
	"testing"
)

// TestCheck pins the FR-010 bind-safety contract: bind.Check must accept
// exactly the loopback IP literals (IPv4 127.0.0.0/8 and IPv6 ::1) and
// reject everything else — non-loopback IPs, DNS names, malformed input,
// empty strings — with errors.Is(err, ErrBindRefused) == true.
//
// Constitution Principle VII: bind/routing decisions are privacy-critical,
// so this test lands BEFORE the implementation (T013). Until check.go
// exists, this file does not compile (undefined: Check, ErrBindRefused) —
// that is the intended test-first red state. T013's green criterion is
// `go test ./internal/bind/...` returning 0 with every row passing.
//
// The function under test MUST be pure: no goroutines, no sockets, no
// listener side effects, no DNS resolution. The check operates on parsed
// IP literals only, so name resolution cannot smuggle a non-loopback bind
// past it (load-bearing: a "helpful" future refactor that resolves
// hostnames upstream would silently break the local-profile invariant).
func TestCheck(t *testing.T) {
	tests := []struct {
		name   string
		addr   string
		accept bool // true → expect nil error; false → expect ErrBindRefused
	}{
		// (a) IPv4 loopback — the whole 127.0.0.0/8 is loopback, not just 127.0.0.1.
		{"ipv4 loopback canonical", "127.0.0.1", true},
		{"ipv4 loopback network addr", "127.0.0.0", true},
		{"ipv4 loopback .2", "127.0.0.2", true},
		{"ipv4 loopback top of /8", "127.255.255.255", true},

		// (b) IPv6 loopback.
		{"ipv6 loopback ::1", "::1", true},

		// (c) Non-loopback IPs — must be rejected with ErrBindRefused.
		{"ipv4 wildcard", "0.0.0.0", false},
		{"ipv6 wildcard", "::", false},
		{"rfc1918 192.168/16", "192.168.1.1", false},
		{"rfc1918 10/8", "10.0.0.1", false},
		{"rfc1918 172.16/12 start", "172.16.0.1", false},
		{"rfc1918 172.16/12 end", "172.31.255.255", false},
		{"ipv4 link-local 169.254/16", "169.254.1.1", false},
		{"ipv6 link-local fe80::/10", "fe80::1", false},
		{"public-routable ipv4", "8.8.8.8", false},

		// (d) DNS names / arbitrary strings — rejected because the check
		// operates on parsed IP literals only.
		{"dns localhost", "localhost", false},
		{"dns hostname", "example.com", false},
		{"arbitrary non-ip string", "not-an-ip", false},

		// (e) Malformed / empty.
		{"empty string", "", false},
		{"whitespace only", "   ", false},
		{"bracketed ipv6 (URI form, not bare literal)", "[::1]", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Check(tt.addr)
			if tt.accept {
				if err != nil {
					t.Fatalf("Check(%q): expected nil error (loopback accepted), got %v", tt.addr, err)
				}
				return
			}
			// Reject cases: must return the BIND_REFUSED sentinel
			// specifically — a bare non-sentinel error would let the
			// startup sequence mis-classify the failure mode.
			if err == nil {
				t.Fatalf("Check(%q): expected ErrBindRefused, got nil", tt.addr)
			}
			if !errors.Is(err, ErrBindRefused) {
				t.Fatalf("Check(%q): expected errors.Is(err, ErrBindRefused), got %T %v", tt.addr, err, err)
			}
		})
	}
}

// TestCheckListener pins the T125-amended FR-010 contract for the
// compose deployment mode. The user-approved amend-spec (2026-09-07;
// SECURITY-DECISIONS.md) moved the loopback-only HOST guarantee from the
// in-container bind address to the host-side publish
// (`127.0.0.1:8881:8881`) plus the container network namespace: a
// listener bound to the container's loopback is unreachable through
// Docker's port publishing (probed live — host CONNECT refused while the
// in-container listener was up), so inside compose the data plane binds
// the container-wide address instead.
//
// The policy stays tight in both modes:
//   - bare metal (containerBoundary=false): loopback ONLY — the original
//     Check contract, byte-for-byte (TestCheck continues to pin it).
//   - compose (containerBoundary=true): loopback OR the unspecified
//     address (0.0.0.0/::) — a SPECIFIC non-loopback interface literal
//     (the container's eth0, a LAN address) is still refused in both
//     modes: the listener may be container-wide, never pointed at a
//     shared interface.
//
// Same purity requirement as Check: parsed IP literals only, no I/O, no
// resolution — env wiring happens in the caller (main.go), not here.
func TestCheckListener(t *testing.T) {
	tests := []struct {
		name              string
		addr              string
		containerBoundary bool
		accept            bool
	}{
		// (a) Compose boundary: the wildcard the compose env now sends.
		{"container: unspecified ipv4", "0.0.0.0", true, true},
		{"container: unspecified ipv6", "::", true, true},
		// Loopback stays legal in both modes (a bare-metal default inside
		// a container is merely unreachable, not exposed).
		{"container: loopback", "127.0.0.1", true, true},
		{"container: ipv6 loopback", "::1", true, true},

		// (b) Compose boundary: specific non-loopback interfaces stay
		// refused — the listener is never pointed at a shared interface.
		{"container: specific private ipv4", "192.168.1.5", true, false},
		{"container: specific carrier ipv4", "10.0.0.7", true, false},
		{"container: specific public ipv4", "203.0.113.9", true, false},

		// (c) Bare metal: identical to Check — wildcard refused (this is
		// the row that keeps a compose-only relaxation from leaking into
		// a bare-metal local run).
		{"bare metal: unspecified ipv4 refused", "0.0.0.0", false, false},
		{"bare metal: loopback accepted", "127.0.0.1", false, true},

		// (d) Both modes: garbage stays refused.
		{"container: hostname", "stargate-dp", true, false},
		{"bare metal: hostname", "localhost", false, false},
		{"container: empty", "", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckListener(tt.addr, tt.containerBoundary)
			if tt.accept {
				if err != nil {
					t.Fatalf("CheckListener(%q, %v): expected nil error, got %v", tt.addr, tt.containerBoundary, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckListener(%q, %v): expected ErrBindRefused, got nil", tt.addr, tt.containerBoundary)
			}
			if !errors.Is(err, ErrBindRefused) {
				t.Fatalf("CheckListener(%q, %v): expected errors.Is(err, ErrBindRefused), got %T %v", tt.addr, tt.containerBoundary, err, err)
			}
		})
	}
}
