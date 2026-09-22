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
// leakscan_test.go:60 extended with the remaining classes the
// allowlist reserves (SidecarEvent consumption + its T045
// closed-vocabulary violation line, control-channel lifecycle,
// snapshot persist + T046 cold-start restore outcomes, shutdown).
// Every line matches exactly one AllowedLineClass; a regression that
// flags any line here is an allowlist false-positive.
const cleanJournalFixture = `level=info msg=startup listener=127.0.0.1:8881
level=info msg="tokens applied" generation=2 count=1
level=info msg="snapshot written"
level=info msg="snapshot restored" generation=7
level=warn msg="snapshot restore ignored" reason="schemaVersion 1"
level=info msg="sidecar event" sidecar=tor kind=EVENT_KIND_HEALTHY detail=healthcheck_pass
level=error msg="sidecar event rejected" kind=EVENT_KIND_STARTED err="detail outside closed vocabulary"
level=warn msg="control channel degraded" err="connection refused"
level=info msg="control channel recovered"
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

func TestOnlyEmptyOperationalJournalIsAccepted(t *testing.T) {
	var reporter fakeReporter
	AssertOnlyAllowedLines(&reporter, "\n\r\n")
	if reporter.failed {
		t.Fatal("empty output rejected")
	}
}

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

func TestOperationalJournalIsForbidden(t *testing.T) {
	for _, line := range strings.Split(cleanJournalFixture, "\n") {
		var reporter fakeReporter
		AssertOnlyAllowedLines(&reporter, line)
		if !reporter.failed {
			t.Fatal("legacy operational journal was accepted")
		}
	}
}
