// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// invariants_test.go is the per-row companion to T029's whole-file byte-match
// gate (render_byte_match_test.go). FR-011 (spec.md §"Sidecar configuration",
// amended by T089) pins the Tor sidecar's image-baked torrc byte-for-byte
// against contracts/torrc.md §"Rendered file"; that contract lists 14
// invariants in its Invariants table. T029 catches any drift as an opaque
// "first diverging byte at offset N"; this test breaks the 14 rows out as
// named subtests so a missing or mutated directive reports by row. Per
// contracts/torrc.md §"invariants_test.go": "This test gives a clearer diff
// message than the byte-match test when a directive is missing or changed."
//
// Constitution Principle VII (tests-first for privacy-critical paths) lands
// here as: every privacy-load-bearing directive flagged in contracts/torrc.md
// §"When this contract changes" (rows 1, 5, 6, 7, 8, 12) has an explicit,
// falsifiable assertion — not only the transitive byte-match.
//
// The test consumes the package-level wantTorrc golden pinned by T029 rather
// than re-transcribing or re-extracting from the contract document. T029
// already gates doc ↔ golden byte-equality; a second transcription would be a
// third copy that could drift. Row 14 (T208) additionally reads the shipped
// sidecars/tor/torrc and requires it to equal the golden byte for byte.
package torrc

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTorrcInvariants asserts each row of contracts/torrc.md §"Invariants"
// (rows 1–14) individually against the wantTorrc golden pinned by T029; row 14
// also reads the shipped sidecars/tor/torrc file. Each
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

	// Row 2 — native SOCKS socket stays in Tor's private fabric directory.
	t.Run("SocksPort_bind_address", func(t *testing.T) {
		args, ok := directives["SocksPort"]
		if !ok {
			t.Fatal("no SocksPort directive line in wantTorrc")
		}
		joined := strings.Join(args, " ")
		if !containsToken(joined, "unix:/run/tor-fabric/private/tor-socks.sock") {
			t.Errorf("SocksPort line %q does not bind the private Unix socket — "+
				"contracts/torrc.md invariant #2",
				"SocksPort "+joined)
		}
	})

	// Row 3 — raw control remains a private Tor-only Unix socket.
	t.Run("ControlSocket_and_CookieAuthentication", func(t *testing.T) {
		cpArgs, ok := directives["ControlSocket"]
		if !ok {
			t.Fatal("no ControlSocket directive line in wantTorrc")
		}
		if !containsToken(strings.Join(cpArgs, " "), "/var/lib/tor/control/tor-control.sock") {
			t.Errorf("ControlSocket line %q does not bind the private Unix socket — "+
				"contracts/torrc.md invariant #3",
				"ControlSocket "+strings.Join(cpArgs, " "))
		}
		if _, ok := directives["ControlPort"]; ok {
			t.Error("ControlPort TCP directive must be absent")
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
			t.Errorf("CookieAuthFileGroupReadable present but " +
				"CookieAuthentication absent — contracts/torrc.md invariant " +
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
			t.Errorf("a Bridge directive line is present in wantTorrc — " +
				"contracts/torrc.md invariant #7 forbids any Bridge line " +
				"(privacy-load-bearing: a stray Bridge line routes traffic " +
				"outside the v1 threat model)")
		}
	})

	// Row 8 — Log notice file /dev/null AND SafeLogging 1.
	t.Run("Log_discard_and_SafeLogging_1", func(t *testing.T) {
		logArgs, ok := directives["Log"]
		if !ok {
			t.Fatal("no Log directive line in wantTorrc — " +
				"contracts/torrc.md invariant #8 requires Log notice file /dev/null")
		}
		joined := strings.Join(logArgs, " ")
		if joined != "notice file /dev/null" {
			t.Error("Tor diagnostic output must be discarded before retention (Constitution III)")
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

	// Row 11 — DataDirectory /var/lib/tor is explicit. The image entrypoint
	// runs `tor -f /etc/tor/torrc` WITHOUT --defaults-torrc, so Debian's
	// torrc-defaults (which would set DataDirectory /var/lib/tor) is never
	// loaded (T087 / T089 / sol-review B2+M3). Without an explicit directive
	// Tor falls back to $HOME/.tor, landing the control cookie at the wrong
	// path and breaking the healthcheck + T062's control-port helper.
	t.Run("DataDirectory_var_lib_tor", func(t *testing.T) {
		args, ok := directives["DataDirectory"]
		if !ok {
			t.Fatal("no DataDirectory directive line in wantTorrc — " +
				"contracts/torrc.md invariant #11 (amended by T089) " +
				"requires DataDirectory /var/lib/tor because the image " +
				"entrypoint does not load Debian's torrc-defaults")
		}
		if !containsToken(strings.Join(args, " "), "/var/lib/tor") {
			t.Errorf("DataDirectory line %q is not /var/lib/tor — "+
				"contracts/torrc.md invariant #11 (the cookie file must "+
				"land at /var/lib/tor/control_auth_cookie for the "+
				"healthcheck and T062)",
				"DataDirectory "+strings.Join(args, " "))
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
			t.Errorf("wantTorrc does not end with a trailing \\n — " +
				"contracts/torrc.md invariant #13 (no missing newline at EOF)")
		}
		if strings.HasSuffix(wantTorrc, "\n\n") {
			t.Errorf("wantTorrc ends with two+ newlines — " +
				"contracts/torrc.md invariant #13 requires exactly ONE " +
				"trailing newline")
		}
		if strings.ContainsRune(wantTorrc, '\r') {
			t.Errorf("wantTorrc contains a CR (\\r) — " +
				"contracts/torrc.md invariant #13 forbids CRLF; line " +
				"endings must be LF only")
		}
	})

	// Row 14 — NO SocksTimeout directive (T208). The data plane's upstream
	// deadline (contracts/socks5-auth.md §"Deadlines") is sized against Tor's
	// default SocksTimeout of 120 s; setting the option requires re-deriving
	// that deadline in the same change. The golden is scanned with Tor's own
	// name matching, and the shipped file must equal the golden byte for
	// byte, so a prefixed form or a `%include` in the shipped file cannot
	// carry the option past this hermetic guard.
	t.Run("no_SocksTimeout", func(t *testing.T) {
		if hits := socksTimeoutDirectives(wantTorrc); len(hits) != 0 {
			t.Errorf("wantTorrc sets SocksTimeout (%q) — contracts/torrc.md "+
				"invariant #14 forbids it: the data plane's upstream deadline "+
				"is sized against Tor's default", hits)
		}
		// The matcher must see the spellings Tor resolves to SocksTimeout,
		// and must not fire on the SocksPort line the golden carries.
		for _, line := range []string{"SocksTimeout 300", "sockstimeout 300", "SocksTime 300", "\tSOCKST 300", "+SocksTimeout 300"} {
			if hits := socksTimeoutDirectives(wantTorrc + line + "\n"); len(hits) != 1 {
				t.Errorf("matcher found %d SocksTimeout directives in golden + %q, want 1 — "+
					"Tor resolves this name to SocksTimeout", len(hits), line)
			}
		}
		for _, line := range []string{"SocksPort 9050", "SocksPolicy accept *", "Socks 300", "# SocksTimeout 300"} {
			if hits := socksTimeoutDirectives(line + "\n"); len(hits) != 0 {
				t.Errorf("matcher treats %q as SocksTimeout (%q); it is not", line, hits)
			}
		}
		shippedPath := filepath.Join(findRepoRoot(t), "sidecars", "tor", "torrc")
		shipped, err := os.ReadFile(shippedPath)
		if err != nil {
			t.Fatalf("reading the shipped torrc %s: %v", shippedPath, err)
		}
		if string(shipped) != wantTorrc {
			t.Errorf("shipped %s does NOT equal the wantTorrc golden byte for byte "+
				"(first diverging byte at offset %d; golden %d bytes, shipped %d bytes) — "+
				"contracts/torrc.md invariant #14 is checked on the golden, so the "+
				"shipped file must be the golden", shippedPath,
				firstDifferingOffset(shipped, []byte(wantTorrc)), len(wantTorrc), len(shipped))
		}
	})
}

// socksTimeoutDirectives returns the directive names in torrc that Tor
// resolves to its SocksTimeout option. Tor matches option names
// case-insensitively and accepts an abbreviation, resolving a truncated name
// to the first option it is a prefix of; `SocksT…` can only be SocksTimeout
// (a shorter prefix resolves to an earlier option: the shipped Tor 0.4.9.13
// reads `Socks` as Socks4Proxy and `SocksT`, `SocksTime` as SocksTimeout,
// checked with `tor --verify-config` on 2026-10-05). A leading `+` or `/`
// (Tor's append/clear forms) is not part of the name.
func socksTimeoutDirectives(torrc string) []string {
	const option, minimum = "sockstimeout", len("sockst")
	var out []string
	for _, raw := range strings.Split(torrc, "\n") {
		fields := strings.Fields(raw)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		name := strings.ToLower(strings.TrimLeft(fields[0], "+/"))
		if len(name) >= minimum && strings.HasPrefix(option, name) {
			out = append(out, fields[0])
		}
	}
	return out
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
// example, checking for argument `0` does not match a `0` embedded in a
// socket pathname.
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
//     forms (`::1`, `fe80::1`) — the current v1 golden has no IPv6
//     in comments, and matching compressed forms reliably requires
//     a much fuzzier pattern with higher false-positive risk. If a
//     future contract edit introduces IPv6 literals in comments,
//     widen this branch (and add a golden fixture) at that time.
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
