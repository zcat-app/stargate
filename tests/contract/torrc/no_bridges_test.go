// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// no_bridges_test.go is the focused bridge / pluggable-transport sweep named
// by contracts/torrc.md §"no_bridges_test.go" and FR-011 (spec.md §"Sidecar
// configuration"). It complements T029's whole-file byte-match (which catches
// any drift as an opaque byte offset) and T030's `UseBridges_0_no_Bridge_lines`
// directive-map subtest (which checks the parsed directive keys but skips
// comments and directive-argument positions) with a named, message-clear scan
// over the entire rendered output — comments included — so a bridge reference
// smuggled into a comment or a transport name placed in an argument fails this
// test by name rather than as a byte-offset diff.
//
// Constitution Principle I (dumb router): a stray Bridge line routes traffic
// outside the v1 threat model — bridges are a separate feature spec. Principle
// VII (tests-first for privacy-critical paths): the sidecar torrc contract is
// privacy-critical, so this gate lands before the renderer (T037).
//
// The test consumes the package-level wantTorrc golden pinned by T029 rather
// than re-transcribing or re-extracting from the contract document; T029
// already gates doc ↔ golden byte-equality, and a second transcription would
// be a third copy that could drift.
package torrc

import (
	"strings"
	"testing"
)

// TestNoBridgesOrPluggableTransports asserts the rendered v1 torrc contains
// no bridge or pluggable-transport configuration, anywhere in the file. Per
// contracts/torrc.md §"no_bridges_test.go" the enumerated surface is the four
// strings `Bridge`, `obfs4`, `snowflake`, `webtunnel`; this test fails if any
// appears in the rendered output.
//
// Two matching strategies, and why they differ:
//
//  1. The pluggable-transport names (`obfs4`, `snowflake`, `webtunnel`) have
//     no legitimate appearance anywhere in the v1 golden, so they are matched
//     as case-insensitive substrings of the whole rendered torrc. Case is
//     folded because Tor directive arguments are case-insensitive and a
//     transport name could appear in any casing.
//  2. "Bridge" is matched as a whitespace-delimited TOKEN, not a raw
//     substring, because invariant #7 REQUIRES the directive `UseBridges 0`,
//     whose name legitimately contains the substring "Bridge". A naive
//     `strings.Contains(wantTorrc, "Bridge")` would always false-positive on
//     the very directive the contract mandates. Token matching catches a
//     `Bridge obfs4 ...` directive line (whose first token is exactly "Bridge")
//     while leaving "UseBridges" untouched.
//
// The live-sidecar GETCONF assertion that the loaded config carries no
// bridges is T032; this test gates only the rendered golden. The Java
// renderer == golden link is T037's scope.
func TestNoBridgesOrPluggableTransports(t *testing.T) {
	// Lowercase the whole rendered output once for case-insensitive scanning.
	// Tor directives and their arguments are case-insensitive, so a transport
	// name or bridge directive could appear in any casing.
	lowered := strings.ToLower(wantTorrc)

	// (a) Pluggable-transport names: no legitimate appearance anywhere.
	t.Run("no_pluggable_transport_names", func(t *testing.T) {
		for _, pt := range []string{"obfs4", "snowflake", "webtunnel"} {
			if strings.Contains(lowered, pt) {
				t.Errorf("rendered torrc contains the pluggable-transport "+
					"string %q — contracts/torrc.md §\"no_bridges_test.go\" / "+
					"invariant #7 forbid pluggable transports in v1 (a stray "+
					"transport reference routes traffic outside the v1 threat "+
					"model — Principle I)", pt)
			}
		}
	})

	// (b) "Bridge" as a standalone token: catches a `Bridge ...` directive
	// line (or any standalone "Bridge" reference) without false-positive-ing
	// on the mandated `UseBridges 0` directive, whose token is "usebridges".
	t.Run("no_Bridge_directive_or_token", func(t *testing.T) {
		for _, tok := range strings.Fields(lowered) {
			if tok == "bridge" {
				t.Errorf("rendered torrc contains a standalone \"Bridge\" "+
					"token — contracts/torrc.md invariant #7 forbids any "+
					"Bridge directive line (privacy-load-bearing: a Bridge "+
					"line routes traffic outside the v1 threat model — "+
					"Principle I). Note: the substring \"Bridge\" inside the "+
					"mandated `UseBridges 0` directive is NOT a match because "+
					"this check is token-level, not substring-level")
			}
		}
	})
}
