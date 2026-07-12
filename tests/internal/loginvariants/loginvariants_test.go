// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Self-test for the loginvariants allowlist + scan core. Pure-
// function tests, no DP process — runs even while the contract test
// (no_per_request_logs_test.go) self-skips on the T042/T044/T045/
// T046/T047/T050 content gates, mirroring the T020 leakscan_test.go
// precedent: the scan core is itself a Constitution-level gate, so
// it cannot share the contract test's skip-on-impl-absent behavior.
//
// The negative-control cases (TestAssertNoSecrets_*) MUST catch each
// of the eight encodings individually — a future regression that
// narrows the encoding set (e.g. drops base64url-raw) surfaces here
// before it lets a real hash leak through the SOCKS5 success-path
// contract test.
//
// The wrapper-parity cases use a local fake LogReporter rather than
// *testing.T so a correctly-flagged call does not abort the table
// loop (Go's *testing.T marks the sub-test failed on the wrapper's
// own Errorf, which would prevent iterating "this SHOULD be flagged"
// across many shapes in one test). The fake implements the same
// LogReporter interface the production wrappers consume.
package loginvariants

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// leakScanSecret is a fixed 32-byte stand-in for an argon2id hash
// or a destination body payload. Fixed, not random: the clean-journal
// cases below MUST be deterministic across runs.
var leakScanSecret = []byte{
	0xa3, 0x1f, 0x8c, 0x57, 0xe2, 0x09, 0xb4, 0x6d,
	0x71, 0xc8, 0x3e, 0x95, 0x0a, 0xf6, 0x42, 0xd9,
	0x88, 0x2b, 0x64, 0xcf, 0x13, 0x7a, 0xe5, 0x50,
	0x9e, 0x06, 0xbb, 0x41, 0xdc, 0x78, 0x2f, 0x93,
}

// cleanJournalFixture is the realistic secret-free journal from T020's
// leakscan_test.go:60 extended with the two remaining classes the
// allowlist reserves (SidecarEvent consumption, shutdown). Every line
// matches exactly one AllowedLineClass; a regression that flags any
// line here is an allowlist false-positive.
const cleanJournalFixture = `level=info msg=startup listener=127.0.0.1:8881
level=info msg="tokens applied" generation=2 count=1
level=info msg="sidecar event" sidecar=tor kind=EVENT_KIND_HEALTHY detail=healthcheck_pass
level=warn msg="snapshot write failed" err="open /var/lib/stargate/.tmp: read-only file system"
level=info msg=shutdown reason="received SIGINT"`

// fakeReporter is the self-test's LogReporter double. It records
// Errorf calls without aborting the surrounding *testing.T, so a
// table loop can iterate "this input SHOULD be flagged" across many
// shapes and assert each one was caught.
type fakeReporter struct {
	failed bool
	errors strings.Builder
}

func (f *fakeReporter) Helper() {}
func (f *fakeReporter) Errorf(format string, args ...any) {
	f.failed = true
	fmt.Fprintf(&f.errors, format+"\n", args...)
}

// TestAllowedLineClasses_AcceptsEachClass asserts each line of the
// clean-journal fixture matches exactly one allowlist class. A line
// matching zero classes is a false-negative (allowlist too tight); a
// line matching two-or-more is a false-positive overlap (allowlist
// patterns too broad). Either is a regression.
func TestAllowedLineClasses_AcceptsEachClass(t *testing.T) {
	for i, line := range strings.Split(cleanJournalFixture, "\n") {
		matches := 0
		firstMatch := ""
		for _, c := range AllowedLineClasses {
			if c.Pattern.MatchString(line) {
				matches++
				if firstMatch == "" {
					firstMatch = c.Name
				}
			}
		}
		switch matches {
		case 0:
			t.Errorf("line %d %q matched zero allowlist classes — "+
				"either the DP-emitted line shape drifted or the "+
				"allowlist is too tight", i, line)
		case 1:
			// expected
		default:
			t.Errorf("line %d %q matched %d allowlist classes "+
				"(%s first) — patterns overlap; tighten the looser "+
				"one so each line class has exactly one home",
				i, line, matches, firstMatch)
		}
	}
}

// TestAllowedLineClasses_AcceptsBareAndQuotedShapes pins the slog
// TextHandler shape tolerance: every msg= value MUST match whether
// the logger emits it bare (msg=startup) or quoted
// (msg="startup"). This is what makes the allowlist robust to a
// logger-config change without requiring an edit.
// The trailing field is the class's own permitted field (T101 acceptance
// #2 rejects extra fields), keeping this a positive control.
func TestAllowedLineClasses_AcceptsBareAndQuotedShapes(t *testing.T) {
	pairs := []struct {
		bare      string
		quoted    string
		class     string
		allowedKV string
	}{
		{`msg=startup`, `msg="startup"`, "startup", "listener=127.0.0.1:8881"},
		{`msg=shutdown`, `msg="shutdown"`, "shutdown", "reason=signal"},
	}
	for _, p := range pairs {
		for _, shape := range []string{p.bare, p.quoted} {
			line := "level=info " + shape + " " + p.allowedKV
			matched := false
			for _, c := range AllowedLineClasses {
				if c.Name == p.class && c.Pattern.MatchString(line) {
					matched = true
				}
			}
			if !matched {
				t.Errorf("%s class did not match %q — every msg= value "+
					"must accept both bare and quoted slog TextHandler "+
					"shapes (a logger-config change must not require an "+
					"allowlist edit)", p.class, line)
			}
		}
	}
}

// TestAllowedLineClasses_RejectsPerRequestNoise asserts the
// allowlist flags each of the per-request shapes it exists to forbid.
// These are NOT in any allowed class — they are the breach surface
// FR-008 exists to prevent. A regression that lets any of these
// through is the very leak the allowlist was extracted to gate.
func TestAllowedLineClasses_RejectsPerRequestNoise(t *testing.T) {
	noise := []string{
		// Per-request log shapes a naive DP might emit:
		`level=info msg=CONNECT dst=example.onion port=443`,
		`level=info msg=forwarded dst=example.onion bytes=1234`,
		`level=info msg="request received" host=example.onion`,
		`level=info routed host=example.onion bytes=1234`,
		// Bare secret / destination bytes (no msg= field):
		`forwarded 1234 bytes to example.onion`,
		`a31f8c57e209b46d71c83e950af642d9882b64cf137ae5509e06bb41dc782f93`,
		`connected to t025a-dest-042-example.onion`,
		// A per-request-shaped line that happens to contain an
		// allowlisted word as a substring — the anchored msg= field
		// prevents this from matching:
		`level=info msg=routed startup_ms=42 dst=example.onion`,
		// Codereview round-1 finding: a per-request log line that
		// contains a violation marker as a free-text field value
		// (not inside msg="…") MUST NOT pass the allowlist.
		`level=info msg=forwarded status=rejected dst=example.onion`,
		`level=warn msg="route error" reason=violation bytes=1234`,
		// stargate-redteam round-1 finding: a per-request log line
		// with a violation marker INSIDE the msg="…" value MUST NOT
		// pass either. The sidecar_event violation-marker
		// alternation was removed entirely (rather than tightened
		// to markers-inside-msg=) because T021's substring
		// tolerance made any marker-in-msg= alternation
		// exploitable. T070a will extend the allowlist with the
		// exact violation-msg= phrasing T045 emits when it lands.
		`level=info msg="request rejected" dst=example.onion`,
		`level=warn msg="sidecar violation" detail=unknown dst=example.onion`,
	}
	for _, line := range noise {
		var fr fakeReporter
		AssertOnlyAllowedLines(&fr, line)
		if !fr.failed {
			t.Errorf("allowlist did not flag per-request noise %q — "+
				"the patterns must require an anchored msg= field "+
				"matching one of the five reserved classes; a "+
				"substring coincidence (including a violation "+
				"marker anywhere on the line) MUST NOT false-pass",
				line)
		}
	}
}

// TestAllowedLineClasses_CleanJournalNoFindings asserts the layered
// end-to-end check: a realistic secret-free journal composed of
// every allowed class produces zero AssertOnlyAllowedLines findings.
// This is the negative-control mirror of the contract test's
// success-path assertion.
func TestAllowedLineClasses_CleanJournalNoFindings(t *testing.T) {
	var fr fakeReporter
	AssertOnlyAllowedLines(&fr, cleanJournalFixture)
	if fr.failed {
		t.Errorf("AssertOnlyAllowedLines flagged the clean-journal "+
			"fixture — every line in the fixture MUST match exactly "+
			"one allowlist class; findings:\n%s", fr.errors.String())
	}
}

// TestAllowedLineClasses_RejectsForbiddenExtraFields is the T101
// regression for review A2's second false-assurance path: the allowlist
// pattern matched any line carrying an allowed msg= value, so a
// per-request field smuggled onto an allowed line —
// `msg=startup dst=evil.onion` — passed undetected. Acceptance #2
// requires field allowlisting: an allowed msg= with a forbidden field
// MUST be flagged. Each case pairs an allowed msg= with a per-request
// field the class's AllowedFields set does not name.
//
// Each diagnostic MUST NOT echo the field's value (the destination /
// hash a future DP might log there) — that is the A2 third path,
// gated separately by TestAssertOnlyAllowedLines_DiagnosticsIndexOnly.
func TestAllowedLineClasses_RejectsForbiddenExtraFields(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"startup with destination", "level=info msg=startup dst=t025a-dest-042-example.onion"},
		{"startup with bytes", "level=info msg=startup bytes=1234"},
		{"shutdown with destination", "level=info msg=shutdown dst=t025a-dest-042-example.onion"},
		{"tokens applied with destination", `level=info msg="tokens applied" generation=2 count=1 dst=t025a-dest-042-example.onion`},
		{"sidecar event with bytes", `level=info msg="sidecar event" sidecar=tor kind=EVENT_KIND_HEALTHY bytes=1234`},
		{"snapshot with destination", `level=warn msg="snapshot write failed" err="read-only" dst=t025a-dest-042-example.onion`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var fr fakeReporter
			AssertOnlyAllowedLines(&fr, c.line)
			if !fr.failed {
				t.Errorf("allowlist did not flag an allowed msg= carrying a "+
					"forbidden per-request field — A2 false-assurance path #2; "+
					"line (len=%d) class-allowed but field-unconstrained",
					len(c.line))
			}
			// The field's VALUE is exactly the per-request surface FR-008
			// exists to keep out of journals; echoing it in the failure
			// re-leaks it into CI logs (A2 false-assurance path #3).
			if msg := fr.errors.String(); strings.Contains(msg, "t025a-dest-042-example.onion") {
				t.Errorf("failure diagnostic echoed the forbidden field's value "+
					"— A2 path #3; the destination MUST NOT appear in CI output: %s",
					msg)
			}
		})
	}
}

// TestAssertOnlyAllowedLines_DiagnosticsIndexOnly is the T101 regression
// for review A2's third false-assurance path: the prior diagnostic
// printed the full rejected line via %q, which can echo a leaked
// destination / token / UNAME straight into CI output. Acceptance #3:
// diagnostics carry only source index, byte length, and rule ID — never
// the rejected line or matched secret. A no-class line carrying a
// secret-shaped marker exercises the diagnostic path directly (the line
// is rejected regardless of the field-allowlisting landing).
func TestAssertOnlyAllowedLines_DiagnosticsIndexOnly(t *testing.T) {
	const secretValue = "a31f8c57e209b46d71c83e950af642d9882b64cf137ae5509e06bb41dc782f93"
	line := "level=info msg=CONNECT dst=" + secretValue + " bytes=1234"
	var fr fakeReporter
	AssertOnlyAllowedLines(&fr, line)
	if !fr.failed {
		t.Fatalf("AssertOnlyAllowedLines did not flag a no-class line — " +
			"prerequisite for the diagnostic check below failed")
	}
	msg := fr.errors.String()
	if strings.Contains(msg, secretValue) {
		t.Errorf("diagnostic echoed the rejected line's secret hash — A2 path #3; " +
			"FR-008-named surface MUST NOT reach CI output")
	}
	if strings.Contains(msg, line) {
		t.Errorf("diagnostic echoed the rejected line verbatim — A2 path #3; " +
			"failure output MUST be index/length/rule-only")
	}
	// Positive contract: the diagnostic MUST carry the source index and
	// byte length, so a maintainer reading CI output can locate the breach
	// without seeing its content.
	if !strings.Contains(msg, "line 0") {
		t.Errorf("diagnostic lacks the source line index — acceptance #3 "+
			"requires index/length/rule, got: %s", msg)
	}
	if !strings.Contains(msg, "len=") && !strings.Contains(msg, "length=") {
		t.Errorf("diagnostic lacks the byte length — acceptance #3 requires "+
			"index/length/rule, got: %s", msg)
	}
}

// TestAssertNoSubHourTimestamp_DetectsAndMisses pins the regex's
// matched and deliberately-unmatched shapes. The Unix-epoch
// non-match documents the residue (§Analysis); a future regex
// tightening that promotes it to matched MUST update this case in
// the same change so the residue list stays accurate.
func TestAssertNoSubHourTimestamp_DetectsAndMisses(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		matched bool
	}{
		// Matched shapes:
		{"HH:MM:SS", "started at 12:34:56", true},
		{"HH:MM:SS fractional", "ts=12:34:56.789", true},
		{"THH:MM:SS (ISO 8601 prefix)", "ts=T12:34:56", true},
		{"RFC3339 prefix", "ts=2026-07-07T12:34:56Z", true},
		{"RFC3339 with offset", "ts=2026-07-07T12:34:56+02:00", true},
		{"RFC3339 with fractional", `ts="2026-07-07T12:34:56.123Z"`, true},

		// Deliberately NOT matched:
		{"date only", "ts=2026-07-07", false},
		{"single hour", "hour=12", false},
		{"port number", "listen=127.0.0.1:8881", false},
		{"aggregate counter name", "table=aggregate_counters", false},
		{"Unix epoch seconds", "ts=1735000000", false},
		{"Unix epoch millis", "ts=1735000000123", false},
		{"Unix epoch fractional", "ts=1735000000.123", false},
	}
	for _, c := range cases {
		got := SubHourTimestamp.MatchString(c.input)
		if got != c.matched {
			t.Errorf("%s: SubHourTimestamp.MatchString(%q) = %v, want %v "+
				"— matched-shape cases must catch every sub-hour form a "+
				"realistic logger emits; unmatched cases must not "+
				"false-positive on the byte counts, port numbers, or "+
				"Unix-epoch residue shapes documented in §Analysis",
				c.name, c.input, got, c.matched)
		}

		// Wrapper parity: AssertNoSubHourTimestamp surfaces the same
		// detection (or non-detection) end-to-end. The fake reporter
		// isolates the flag call from the surrounding *testing.T so
		// the wrapper's Errorf does not abort the table loop.
		var fr fakeReporter
		AssertNoSubHourTimestamp(&fr, c.input)
		if fr.failed != c.matched {
			t.Errorf("%s: AssertNoSubHourTimestamp flagged=%v, want %v "+
				"— wrapper must agree with SubHourTimestamp.MatchString",
				c.name, fr.failed, c.matched)
		}
	}
}

// TestAssertNoSubHourTimestamp_DiagnosticsIndexOnly is the T101
// regression for review A2's third false-assurance path applied to the
// timestamp scanner: the prior diagnostic echoed the matched timestamp
// and a ±80-byte context window, which can echo a concurrent
// destination / UNAME leak into CI output. Acceptance #3 requires
// index/length/rule-only diagnostics — no captured content. The marker
// below sits inside the old ±80-byte window, so the old diagnostic
// re-leaked it.
func TestAssertNoSubHourTimestamp_DiagnosticsIndexOnly(t *testing.T) {
	const secretMarker = "t025a-dest-042-example.onion"
	// Place the marker within 80 bytes of the timestamp so the old
	// ±80-byte context window would have captured it.
	delta := "ts=12:34:56 dst=" + secretMarker
	var fr fakeReporter
	AssertNoSubHourTimestamp(&fr, delta)
	if !fr.failed {
		t.Fatalf("AssertNoSubHourTimestamp did not flag a sub-hour timestamp — " +
			"prerequisite for the diagnostic check below failed")
	}
	msg := fr.errors.String()
	if strings.Contains(msg, secretMarker) {
		t.Errorf("diagnostic echoed content adjacent to the matched " +
			"timestamp — A2 path #3; a concurrent leak within the old " +
			"±80-byte window re-reaches CI output")
	}
	if strings.Contains(msg, "12:34:56") {
		t.Errorf("diagnostic echoed the matched timestamp substring — " +
			"acceptance #3 requires index/length/rule only, no captured content")
	}
}

// TestAssertNoSecrets_NineEncodingsEachCaught asserts each of the
// nine textual renderings an accidental slog / fmt logger would
// produce for a []byte OR string field is caught. The raw entry
// (stargate-redteam round-1 finding) is the most basic leak form —
// the cleartext string a DP would emit if it logged an ASCII corpus
// item (destination hostname, body payload, UNAME) verbatim. The
// eight derived forms cover hex/base64/decimal encodings a hash or
// non-ASCII secret would take.
//
// A regression that narrows the encoding set (e.g. drops raw or
// base64url-raw) is the leak path T020's redteam finding
// 20260706-001 + T025a's round-1 redteam finding were filed to gate.
func TestAssertNoSecrets_NineEncodingsEachCaught(t *testing.T) {
	cases := []struct {
		name    string
		journal string
	}{
		// Raw — the cleartext form. leakScanSecret is binary
		// (non-ASCII bytes), so the rendering appears as a byte
		// run in the journal; the scan catches it.
		{"raw_cleartext", "dst=" + string(leakScanSecret)},
		// For the destination-hostname leak shape specifically
		// (an ASCII string, where []byte(s) IS the cleartext),
		// confirm the raw entry catches `dst=<string>`:
		{"raw_ascii_destination", "dst=t025a-dest-042-example.onion"},
		{"hex_lower", "level=info msg=reload hash=" + hex.EncodeToString(leakScanSecret)},
		{"hex_upper", "APPLIED HASH " + strings.ToUpper(hex.EncodeToString(leakScanSecret))},
		{"base64_std", "reload applied hash=" + base64.StdEncoding.EncodeToString(leakScanSecret)},
		{"base64_raw_std", "reload applied hash=" + base64.RawStdEncoding.EncodeToString(leakScanSecret)},
		{"base64_url", "reload applied hash=" + base64.URLEncoding.EncodeToString(leakScanSecret)},
		{"base64_raw_url", "reload applied hash=" + base64.RawURLEncoding.EncodeToString(leakScanSecret)},
		// fmt %v and slog TextHandler both render []byte as "[163 31 …]"
		// — the most likely accidental logging path in a Go DP.
		{"decimal_slice", fmt.Sprintf("time=x level=INFO msg=reload hash=%v", leakScanSecret)},
		{"decimal_run_brackets_stripped", "hash bytes: " + strings.Trim(fmt.Sprint(leakScanSecret), "[]")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var secrets [][]byte
			switch c.name {
			case "raw_ascii_destination":
				// ASCII destination case: scan for the string
				// directly. This is the redteam-flagged shape —
				// raw must catch it.
				secrets = [][]byte{[]byte("t025a-dest-042-example.onion")}
			default:
				// Binary leakScanSecret case: scan for the
				// 32-byte hash across all nine renderings.
				secrets = [][]byte{leakScanSecret}
			}
			leaks := FindSecretLeaks(c.journal, secrets...)
			if len(leaks) == 0 {
				t.Errorf("FindSecretLeaks missed the %s rendering — "+
					"a DP logging the secret this way would pass the "+
					"success-path contract test's no-logging clause "+
					"undetected", c.name)
			}
			var fr fakeReporter
			AssertNoSecrets(&fr, c.journal, secrets...)
			if !fr.failed {
				t.Errorf("AssertNoSecrets did not flag the %s rendering "+
					"— the wrapper must surface the same leak the "+
					"pure-function FindSecretLeaks does", c.name)
			}
		})
	}
}

// TestAssertNoSecrets_CleanJournalNoFindings asserts the layered
// scan core gates on content, not chatter: a realistic secret-free
// journal composed of allowed-class lines produces zero findings.
// This is the negative-control that catches a future regex
// over-broadening (e.g. a sub-`\w+` pattern that matches the
// fixture's `level=info` substring).
func TestAssertNoSecrets_CleanJournalNoFindings(t *testing.T) {
	leaks := FindSecretLeaks(cleanJournalFixture, leakScanSecret)
	if len(leaks) != 0 {
		t.Errorf("FindSecretLeaks flagged a secret-free journal: %v "+
			"— the scan gates on content, not chatter", leaks)
	}
	var fr fakeReporter
	AssertNoSecrets(&fr, cleanJournalFixture, leakScanSecret)
	if fr.failed {
		t.Errorf("AssertNoSecrets flagged a secret-free journal: %s "+
			"— same regression surface as above", fr.errors.String())
	}
}

// TestAssertNoSecrets_NilAndEmptyIgnored asserts nil and empty
// secrets are ignored, never treated as matches-everything. A
// future change that special-cases empty input MUST preserve this
// invariant (T020 leakscan_test.go:70 precedent).
func TestAssertNoSecrets_NilAndEmptyIgnored(t *testing.T) {
	var fr fakeReporter
	AssertNoSecrets(&fr, cleanJournalFixture, nil, []byte{})
	if fr.failed {
		t.Errorf("nil/empty secrets produced findings: %s — the scan "+
			"must never treat an empty secret as "+
			"matches-everything", fr.errors.String())
	}
}
