// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package listener

import "testing"

// T173 replaces the HTTP parser's case/framing/auth variants with unconditional
// refusal. Real socket, payload and upstream observations live in the named
// contract regression; this seam check detects even unsuccessful auth calls.
func TestHTTPRefusalDoesNotConsultVerifier(t *testing.T) {
	for _, accept := range []bool{false, true} {
		f := startFixture(t, nil, accept)
		write(t, f.client, 'C')
		expectEOFWithNoData(t, f.client, "HTTP refusal")
		awaitDone(t, f, "HTTP refusal")
		if f.auth.count() != 0 || f.audit.count() != 0 {
			t.Fatal("HTTP reached auth or audit")
		}
		if n, _, _ := f.forward.state(); n != 0 {
			t.Fatal("HTTP reached forwarding")
		}
	}
}
