// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// invariants_test.go is the per-row companion to T029's whole-file byte-match
// gate (render_byte_match_test.go). FR-011 (spec.md §"Sidecar configuration")
// pins the Tor sidecar's rendered torrc byte-for-byte against contracts/torrc.md
// §"Rendered file"; that contract lists 13 invariants in its Invariants table.
// T029 catches any drift as an opaque "first diverging byte at offset N"; this
// test breaks the 13 rows out as named subtests so a missing or mutated
// directive reports by row. Per contracts/torrc.md §"invariants_test.go":
// "This test gives a clearer diff message than the byte-match test when a
// directive is missing or changed."
//
// Constitution Principle VII (tests-first for privacy-critical paths) lands
// here as: every privacy-load-bearing directive flagged in contracts/torrc.md
// §"When this contract changes" (rows 1, 5, 6, 7, 8, 12) has an explicit,
// falsifiable assertion — not only the transitive byte-match.
//
// The test consumes the package-level wantTorrc golden pinned by T029 rather
// than re-transcribing or re-extracting from the contract document. T029
// already gates doc ↔ golden byte-equality; a second transcription would be a
// third copy that could drift.
package torrc

import (
	"regexp"
	"strings"
	"testing"
)

// TestTorrcInvariants asserts each row of contracts/torrc.md §"Invariants"
// (rows 1–13) individually against the wantTorrc golden pinned by T029. Each
// subtest names its row so a failure reports the specific invariant violated,
// not an opaque byte offset. Subtests are independent: directive parsing happens
// once at the top, each subtest reads the parsed maps without mutating them.
//
// The directive model: a torrc directive line is `Name args...` where Name is
// the first whitespace-delimited token. Comment lines (`#`) and blank lines
// are not directives. Only the first token is the directive name; subsequent
// tokens are arguments whose meaning is directive-specific. `directiveArgs`
// returns the arguments following the first occurrence of a given directive
// name (torrc does not repeat directives in v1; if it ever does, the first
// occurrence is the load-bearing one for these invariants).
func TestTorrcInvariants(t *testing.T) {
	directives := parseDirectives(wantTorrc)
	commentLines := parseCommentLines(wantTorrc)

	// Row 1 — SocksPort line contains both IsolateClientAddr and IsolateSOCKSAuth.
	// Why: FR-011, Principle III — stream isolation by first-party domain
	// depends on IsolateSOCKSAuth.
	t.Run("SocksPort_isolation_flags", func(t *testing.T) {
		args, ok := directives["SocksPort"]
		if !ok {
			t.Fatalf("no SocksPort directive line in wantTorrc — FR-011 " +
				"requires SocksPort with IsolateClientAddr IsolateSOCKSAuth")
		}
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "IsolateClientAddr") {
			t.Errorf("SocksPort line %q is missing IsolateClientAddr — "+
				"contracts/torrc.md invariant #1", "SocksPort "+joined)
		}
		if !strings.Contains(joined, "IsolateSOCKSAuth") {
			t.Errorf("SocksPort line %q is missing IsolateSOCKSAuth — "+
				"contracts/torrc.md invariant #1 (privacy-load-bearing: "+
				"per-first-party stream isolation depends on it)",
				"SocksPort "+joined)
		}
	})

	// Row 2 — SocksPort binds 0.0.0.0:9050 (container-internal; compose does
	// not map the port to the host).
	t.Run("SocksPort_bind_address", func(t *testing.T) {
		args, ok := directives["SocksPort"]
		if !ok {
			t.Fatal("no SocksPort directive line in wantTorrc")
		}
		joined := strings.Join(args, " ")
		// Match the literal host:port token rather than a substring so a
		// future `9050` argument elsewhere cannot satisfy the check.
		if !containsToken(joined, "0.0.0.0:9050") {
			t.Errorf("SocksPort line %q does not bind 0.0.0.0:9050 — "+
				"contracts/torrc.md invariant #2 (the bind address is "+
				"part of the byte-match contract; bare `9050` would not)",
				"SocksPort "+joined)
		}
	})

	// Row 3 — ControlPort on 0.0.0.0:9051 with CookieAuthentication 1.
	t.Run("ControlPort_and_CookieAuthentication", func(t *testing.T) {
		cpArgs, ok := directives["ControlPort"]
		if !ok {
			t.Fatal("no ControlPort directive line in wantTorrc")
		}
		if !containsToken(strings.Join(cpArgs, " "), "0.0.0.0:9051") {
			t.Errorf("ControlPort line %q does not bind 0.0.0.0:9051 — "+
				"contracts/torrc.md invariant #3",
				"ControlPort "+strings.Join(cpArgs, " "))
		}
		caArgs, ok := directives["CookieAuthentication"]
		if !ok {
			t.Fatalf("no CookieAuthentication directive line in wantTorrc " +
				"— contracts/torrc.md invariant #3 requires CookieAuthentication 1")
		}
		if !containsToken(strings.Join(caArgs, " "), "1") {
			t.Errorf("CookieAuthentication line %q is not 1 — "+
				"contracts/torrc.md invariant #3 (cookie auth keeps the "+
				"control-port channel privileged)",
				"CookieAuthentication "+strings.Join(caArgs, " "))
		}
	})

	// Row 4 — CookieAuthFileGroupReadable 1 present alongside CookieAuthentication 1.
	t.Run("CookieAuthFileGroupReadable", func(t *testing.T) {
		args, ok := directives["CookieAuthFileGroupReadable"]
		if !ok {
			t.Fatal("no CookieAuthFileGroupReadable directive line in " +
				"wantTorrc — contracts/torrc.md invariant #4 requires " +
				"CookieAuthFileGroupReadable 1 alongside CookieAuthentication 1")
		}
		if !containsToken(strings.Join(args, " "), "1") {
			t.Errorf("CookieAuthFileGroupReadable line %q is not 1 — "+
				"contracts/torrc.md invariant #4 (the contract-test harness "+
				"at T062 cannot read the cookie without it)",
				"CookieAuthFileGroupReadable "+strings.Join(args, " "))
		}
		if _, ok := directives["CookieAuthentication"]; !ok {
			t.Errorf("CookieAuthFileGroupReadable present but "+
				"CookieAuthentication absent — contracts/torrc.md invariant "+
				"#4 requires them together")
		}
	})

	// Row 5 — ClientUseIPv6 0 (v1 is IPv4-only).
	t.Run("ClientUseIPv6_0", func(t *testing.T) {
		args, ok := directives["ClientUseIPv6"]
		if !ok {
			t.Fatal("no ClientUseIPv6 directive line in wantTorrc — " +
				"contracts/torrc.md invariant #5 requires ClientUseIPv6 0")
		}
		if !containsToken(strings.Join(args, " "), "0") {
			t.Errorf("ClientUseIPv6 line %q is not 0 — "+
				"contracts/torrc.md invariant #5 (FR-011, IPv4-only in v1)",
				"ClientUseIPv6 "+strings.Join(args, " "))
		}
	})

	// Row 6 — AvoidDiskWrites 1 (THREAT-MODEL §3.1 — minimise incidental writes).
	t.Run("AvoidDiskWrites_1", func(t *testing.T) {
		args, ok := directives["AvoidDiskWrites"]
		if !ok {
			t.Fatal("no AvoidDiskWrites directive line in wantTorrc — " +
				"contracts/torrc.md invariant #6 requires AvoidDiskWrites 1")
		}
		if !containsToken(strings.Join(args, " "), "1") {
			t.Errorf("AvoidDiskWrites line %q is not 1 — "+
				"contracts/torrc.md invariant #6 (THREAT-MODEL §3.1: "+
				"minimise incidental writes)",
				"AvoidDiskWrites "+strings.Join(args, " "))
		}
	})

	// Row 7 — UseBridges 0 AND no Bridge directive anywhere (no bridges in v1).
	// Privacy-load-bearing: a stray Bridge line would route traffic outside
	// the threat model. The dedicated no_bridges_test.go substring sweep
	// (Bridge / obfs4 / snowflake / webtunnel) is T031; this subtest asserts
	// the contract row 7 wording (UseBridges 0 + no Bridge directive line).
	t.Run("UseBridges_0_no_Bridge_lines", func(t *testing.T) {
		args, ok := directives["UseBridges"]
		if !ok {
			t.Fatal("no UseBridges directive line in wantTorrc — " +
				"contracts/torrc.md invariant #7 requires UseBridges 0")
		}
		if !containsToken(strings.Join(args, " "), "0") {
			t.Errorf("UseBridges line %q is not 0 — "+
				"contracts/torrc.md invariant #7 (Bridge support is a "+
				"separate feature spec)",
				"UseBridges "+strings.Join(args, " "))
		}
		if _, present := directives["Bridge"]; present {
			t.Errorf("a Bridge directive line is present in wantTorrc — "+
				"contracts/torrc.md invariant #7 forbids any Bridge line "+
				"(privacy-load-bearing: a stray Bridge line routes traffic "+
				"outside the v1 threat model)")
		}
	})

	// Row 8 — Log notice stdout AND SafeLogging 1.
	t.Run("Log_notice_stdout_and_SafeLogging_1", func(t *testing.T) {
		logArgs, ok := directives["Log"]
		if !ok {
			t.Fatal("no Log directive line in wantTorrc — " +
				"contracts/torrc.md invariant #8 requires Log notice stdout")
		}
		joined := strings.Join(logArgs, " ")
		if !containsToken(joined, "notice") || !containsToken(joined, "stdout") {
			t.Errorf("Log line %q is not `notice stdout` — "+
				"contracts/torrc.md invariant #8 (Notice level is "+
				"sufficient for the healthcheck's Bootstrapped 100%% probe)",
				"Log "+joined)
		}
		slArgs, ok := directives["SafeLogging"]
		if !ok {
			t.Fatalf("no SafeLogging directive line in wantTorrc — " +
				"contracts/torrc.md invariant #8 requires SafeLogging 1")
		}
		if !containsToken(strings.Join(slArgs, " "), "1") {
			t.Errorf("SafeLogging line %q is not 1 — "+
				"contracts/torrc.md invariant #8 (privacy-load-bearing: "+
				"SafeLogging 1 scrubs sensitive fields from Tor logs)",
				"SafeLogging "+strings.Join(slArgs, " "))
		}
	})

	// Row 9 — NO HiddenServiceDir / HiddenServicePort directives
	// (this feature is a *client* of onion services, not a service).
	t.Run("no_hidden_service_directives", func(t *testing.T) {
		for _, name := range []string{"HiddenServiceDir", "HiddenServicePort"} {
			if _, present := directives[name]; present {
				t.Errorf("%s directive line is present in wantTorrc — "+
					"contracts/torrc.md invariant #9 forbids it (v1 is a "+
					"client of onion services, not a service)", name)
			}
		}
	})

	// Row 10 — NO ExitPolicy overrides (this feature does not run an exit node).
	t.Run("no_ExitPolicy", func(t *testing.T) {
		if _, present := directives["ExitPolicy"]; present {
			t.Errorf("ExitPolicy directive line is present in wantTorrc — " +
				"contracts/torrc.md invariant #10 forbids it (v1 does not " +
				"run an exit node)")
		}
	})

	// Row 11 — NO DataDirectory override (default /var/lib/tor from the
	// Debian package, mounted from stargate-tor-state for guard persistence).
	t.Run("no_DataDirectory", func(t *testing.T) {
		if _, present := directives["DataDirectory"]; present {
			t.Errorf("DataDirectory directive line is present in wantTorrc — " +
				"contracts/torrc.md invariant #11 forbids it (an override " +
				"would risk pointing guard state somewhere ephemeral)")
		}
	})

	// Row 12 — NO comments containing per-user data (no labels, no token
	// references, no domains). Privacy-load-bearing: the rendered file is a
	// Principle III boundary; it must contain no per-user content. The
	// byte-match (T029) pins the exact comment set; this subtest is the
	// semantic defence-in-depth — it fails loudly with the offending line if
	// a future comment edit introduces an email, bare IP literal, domain TLD,
	// or token/label/user= key.
	t.Run("no_per_user_data_in_comments", func(t *testing.T) {
		for _, line := range commentLines {
			if loc := perUserDataPattern.FindStringIndex(line); loc != nil {
				t.Errorf("comment line %q contains per-user-data-looking "+
					"content at offset %d (%q) — contracts/torrc.md "+
					"invariant #12 forbids per-user data in any comment "+
					"(privacy-load-bearing: the rendered file is a "+
					"Principle III boundary)",
					line, loc[0], line[loc[0]:loc[1]])
			}
		}
	})

	// Row 13 — file ends with a single trailing \n (no CRLF, no missing
	// newline at EOF). Determinism / byte-for-byte test reproducibility. T029
	// asserts the same on wantTorrc as part of the byte-match; this subtest
	// breaks the row out individually so an EOF-newline defect reports by
	// invariant rather than as a byte-offset diff.
	t.Run("single_trailing_LF_no_CR", func(t *testing.T) {
		if !strings.HasSuffix(wantTorrc, "\n") {
			t.Errorf("wantTorrc does not end with a trailing \\n — "+
				"contracts/torrc.md invariant #13 (no missing newline at EOF)")
		}
		if strings.HasSuffix(wantTorrc, "\n\n") {
			t.Errorf("wantTorrc ends with two+ newlines — "+
				"contracts/torrc.md invariant #13 requires exactly ONE " +
				"trailing newline")
		}
		if strings.ContainsRune(wantTorrc, '\r') {
			t.Errorf("wantTorrc contains a CR (\\r) — " +
				"contracts/torrc.md invariant #13 forbids CRLF; line " +
				"endings must be LF only")
		}
	})
}

// parseDirectives parses torrc content into a map of directive name → argument
// list (first occurrence wins). Comment lines (`#`) and blank lines are
// skipped. Argument splitting is on any whitespace runs; Tor's torrc parser is
// itself whitespace-tolerant, so this mirrors its tokenisation closely enough
// for the invariants under test (none of which depend on intra-arg whitespace).
func parseDirectives(torrc string) map[string][]string {
	out := make(map[string][]string)
	for _, raw := range strings.Split(torrc, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if _, exists := out[name]; !exists {
			out[name] = fields[1:]
		}
	}
	return out
}

// parseCommentLines returns the comment lines (with the leading `#` and any
// single leading space stripped) for invariant #12's per-user-data scan.
// Returns the text content so the regex can flag user data that may appear
// after the `#`.
func parseCommentLines(torrc string) []string {
	var out []string
	for _, raw := range strings.Split(torrc, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.TrimSpace(strings.TrimPrefix(line, "#")))
	}
	return out
}

// containsToken reports whether s contains the given token as a
// whitespace-delimited field. Used instead of strings.Contains so that, for
// example, checking for argument `0` does not match a `0` substring inside
// `0.0.0.0:9050`.
func containsToken(s, token string) bool {
	for _, f := range strings.Fields(s) {
		if f == token {
			return true
		}
	}
	return false
}

// perUserDataPattern matches substrings that look like per-user data and have
// no business in a rendered torrc comment: email addresses, bare IPv4/IPv6
// literals, domain-like strings with a known TLD, and token/label/user/key
// assignments. It is intentionally a union of anchored alternations rather
// than a single fuzzy pattern so each branch is auditable. False positives
// (e.g. a future comment that legitimately mentions `user` in prose) are the
// point — they force a human reviewer to allowlist the new comment, which is
// exactly the vigilance invariant #12 demands.
//
// Branches:
//   - email:        `local@host` with a dotted host tail
//   - ipv4:         four dot-separated 0–255 octets, not bounded by other dots/digits
//   - ipv6:         3–8 colon-separated hex groups; does NOT match `::`-compressed
//                   forms (`::1`, `fe80::1`) — the current v1 golden has no IPv6
//                   in comments, and matching compressed forms reliably requires
//                   a much fuzzier pattern with higher false-positive risk. If a
//                   future contract edit introduces IPv6 literals in comments,
//                   widen this branch (and add a golden fixture) at that time.
//   - domain TLD:   a hostname followed by a common TLD from a small allowlist
//   - secret key:   `token=`, `label=`, `user=`, `key=`, `secret=` (case-insensitive)
//
// Coverage note (deferred to stargate-redteam): a bare username with no `=`
// (e.g. `# configured by bob`) slips through every branch. The enumerated
// patterns are the deterministic scope; whether bare-username-in-comment is a
// realistic Principle-III leak vector worth a fuzzier heuristic is redteam's
// call, not this test's.
var perUserDataPattern = regexp.MustCompile(
	`(?i)(` +
		`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}` + // email
		`|` +
		`\b(?:\d{1,3}\.){3}\d{1,3}\b` + // ipv4 literal
		`|` +
		`\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){2,7}\b` + // ipv6 literal (non-compressed)
		`|` +
		`\b[A-Za-z0-9.-]+\.(?:com|org|net|io|onion|co|info|biz|me|app|dev|xyz)\b` + // domain TLD
		`|` +
		`\b(?:token|label|user|key|secret)\s*=` + // secret key assignment
		`)`,
)
