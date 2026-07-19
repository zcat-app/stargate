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
