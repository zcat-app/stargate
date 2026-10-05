// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"errors"
	"strings"
	"testing"
)

// Honest diagnostics (Constitution V; SOCKS request-phase failure contract):
// DP unavailable/deadline replies do not identify a native Tor refusal.
func TestT059RouteDiagnosticDoesNotInventTorRefusal(t *testing.T) {
	t.Run("nil remains ok", func(t *testing.T) {
		if got := t059ClassifyDialErr(nil); got != "ok" {
			t.Fatalf("nil: %q, want ok", got)
		}
	})
	t.Run("auth remains AUTH", func(t *testing.T) {
		got := t059ClassifyDialErr(errors.New("username/password authentication failed"))
		if !strings.HasPrefix(got, "AUTH:") {
			t.Fatalf("auth: %q, want AUTH classification", got)
		}
	})
	for _, c := range []struct{ name, message, want string }{
		{"listener remains ROUTE", "dial tcp 127.0.0.1:8881: connect: connection refused", "ROUTE: DP listener unreachable"},
		{"05 preserves earlier listener branch", "unknown error connection refused", "ROUTE: DP listener unreachable"},
		{"deadline branch unchanged", "context deadline exceeded", "ROUTE: tor rendezvous/descriptor latency exceeded the window"},
		{"HTTP timeout branch unchanged", "Client.Timeout exceeded while awaiting headers", "ROUTE: tor rendezvous/descriptor latency exceeded the window"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := t059ClassifyDialErr(errors.New(c.message)); !strings.HasPrefix(got, c.want) {
				t.Fatalf("unchanged branch: %q, want prefix %q", got, c.want)
			}
		})
	}
	for _, c := range []struct{ name, reply string }{
		{"03 unavailable", "network unreachable"},
		{"04 refusal class", "host unreachable"},
		{"06 DP deadline", "TTL expired"},
	} {
		t.Run(c.name, func(t *testing.T) {
			const detail = "arbitrary-test-detail-that-must-not-be-copied"
			got := t059ClassifyDialErr(errors.New("unknown error " + c.reply + " " + detail))
			if !strings.HasPrefix(got, "ROUTE:") || len(strings.TrimSpace(strings.TrimPrefix(got, "ROUTE:"))) == 0 {
				t.Errorf("reply class %s: %q, want nonempty ROUTE classification", c.name, got)
			}
			if strings.Contains(got, detail) {
				t.Errorf("reply class %s copied arbitrary input details", c.name)
			}
			low := strings.ToLower(got)
			if strings.Contains(low, "tor sidecar) refused") || strings.Contains(low, "tor refused") {
				t.Errorf("reply class %s invents native Tor refusal: %q", c.name, got)
			}
			if !strings.Contains(low, "unknown") {
				t.Errorf("reply class %s: %q, want explicit unknown cause", c.name, got)
			}
		})
	}
}
