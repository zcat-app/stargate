// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package loginvariants rejects deployed diagnostic journals and checks known
// secret encodings and sub-hour timestamps. It is shared by contract and
// integration modules so the Constitution III boundary has one oracle.
package loginvariants

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// LogReporter is the minimal *testing.T surface the Assert* wrappers
// in this package require. Defined as an interface (rather than
// taking *testing.T directly) so the self-test under
// loginvariants_test.go can record failures without aborting the
// table loops the wrapper-parity assertions need — Go's testing.TB
// carries a private() method that blocks external fakes, so a
// project-local interface is the standard escape hatch.
//
// *testing.T and *testing.B satisfy LogReporter; production callers
// pass their real *testing.T unchanged.
type LogReporter interface {
	Helper()
	Errorf(format string, args ...any)
}

// SubHourTimestamp matches any timestamp shape at finer than ≥1-hour
// resolution. FR-008 / arch §6.4 prohibit per-request timestamps
// finer than the aggregate_counter hour bucket; the allowlist's
// positive form (allowed line classes) is the primary gate, this is
// the belt-and-braces negative form.
//
// Covered shapes:
//
//   - HH:MM:SS                (12:34:56)
//   - THH:MM:SS               (T12:34:56 — ISO 8601 prefix)
//   - YYYY-MM-DDTHH:MM:SS     (RFC3339 prefix)
//   - HH:MM:SS.nnn+           (fractional seconds — same prefix)
//
// Deliberately NOT matched:
//
//   - Bare Unix epoch (e.g. 1735000000, 1735000000.123). Too broad a
//     pattern false-positives on byte counts and port numbers. The
//     allowlist is the primary gate; this regex is the obvious-form
//     backstop (same scope as T025 leak_test.go's subHourTimestamp).
//   - Date-only (YYYY-MM-DD). Day granularity is coarser than hour —
//     permitted.
var SubHourTimestamp = regexp.MustCompile(
	`(?:\d{4}-\d{2}-\d{2})?T?\d{2}:\d{2}:\d{2}(?:\.\d+)?`)

// AssertOnlyAllowedLines rejects every deployed DP journal record. The CP's
// completed-hour SQLite counters are the only operational retention surface (III).
// Diagnostics identify an offset/length, never echo rejected bytes or keys.
func AssertOnlyAllowedLines(t LogReporter, journal string) {
	t.Helper()
	for i, line := range strings.Split(journal, "\n") {
		if strings.TrimSpace(line) != "" {
			t.Errorf("journal line %d (len=%d, rule=operational_record_forbidden)", i, len(line))
		}
	}
}

// AssertNoSubHourTimestamp asserts delta contains no sub-hour-
// resolution timestamp shape. FR-008 prohibits per-request
// timestamps finer than the ≥1-hour aggregate bucket; any
// HH:MM:SS-shaped substring in delta is a violation. Delta-scoping
// (not the whole journal) is the caller's responsibility — boot-log
// timestamps written before the event under test would otherwise
// false-positive.
//
// Failure diagnostics are offset/length/rule-only (T101 acceptance #3,
// review A2 path #3): the matched timestamp substring and any
// surrounding delta bytes are NEVER echoed. The prior ±80-byte context
// window could capture a concurrent destination / UNAME leak and
// re-leak it into CI output; the timestamp substring itself is captured
// content the scanner has no reason to republish. A maintainer locates
// the breach via the byte offset + matched length.
func AssertNoSubHourTimestamp(t LogReporter, delta string) {
	t.Helper()
	loc := SubHourTimestamp.FindStringIndex(delta)
	if loc == nil {
		return
	}
	t.Errorf("delta contains a sub-hour timestamp at offset %d "+
		"(len=%d, rule=sub_hour_timestamp) — FR-008 / arch §6.4 "+
		"prohibit per-request timestamps finer than the ≥1-hour "+
		"aggregate bucket; matched content elided",
		loc[0], loc[1]-loc[0])
}

// AssertNoSecrets asserts none of secrets (raw byte slices) appear
// in journal in any of the nine textual renderings an accidental
// slog / fmt logger would produce for a []byte or string field:
// the raw cleartext (the form ASCII corpus items like destination
// hostnames and UNAMEs take when []byte(s) IS the string), hex
// (both cases), all four base64 variants, and the decimal byte-
// slice forms. Failure messages name only the secret's index and
// encoding, never the bytes — a failing run cannot itself leak
// into CI logs.
//
// The encoding set extends T020's redteam finding 20260706-001
// (the former local copy in tests/contract/control-grpc) with the raw
// entry T025 leak_test.go:523 already carried — T025a
// stargate-redteam round-1 flagged that without raw, ASCII corpus
// items would slip past all eight derived forms. T101 consolidated
// the legacy control-gRPC call sites onto this scanner, closing the
// raw-encoding gap that the local copy carried (review A2 path #1).
func AssertNoSecrets(t LogReporter, journal string, secrets ...[]byte) {
	t.Helper()
	for _, leak := range FindSecretLeaks(journal, secrets...) {
		t.Errorf("journal contains a corpus secret rendering (%s) — "+
			"FR-006 / FR-008 / contracts/socks5-auth.md §\"Forbidden "+
			"behaviours\": server-side data MUST NOT appear in any "+
			"response, log, or counter increment", leak)
	}
}

// FindSecretLeaks reports every (secret index, encoding) pair present
// in journal, sorted for determinism. Kept a pure function (no
// *testing.T) so the self-test under loginvariants_test.go can
// negative-control each encoding — proving the scan actually catches
// it — without booting a DP process. Mirrors the T020 helper's
// shape so a future refactor of T020/T021 to consume this package
// is a one-line import swap.
func FindSecretLeaks(journal string, secrets ...[]byte) []string {
	var leaks []string
	for i, secret := range secrets {
		if len(secret) == 0 {
			continue
		}
		for name, enc := range secretEncodings(secret) {
			if strings.Contains(journal, enc) {
				leaks = append(leaks, fmt.Sprintf("secret %d as %s", i, name))
			}
		}
	}
	sort.Strings(leaks)
	return leaks
}

// secretEncodings returns every textual rendering of secret the leak
// scan hunts for. The set covers the realistic accidental-logging
// paths, not just canonical dumps: the cleartext string (raw —
// critical for ASCII corpus items like destination hostnames and
// UNAMEs, where []byte(s) IS the string the DP would log if it
// leaked the value verbatim), hex (both cases), all four base64
// variants, and the decimal byte-slice forms — `[12 34 56]` is what
// fmt's %v/%+v verbs AND slog's TextHandler emit for a []byte, i.e.
// the single most likely way a future DP change leaks a hash or
// destination byte without anyone writing an encoder.
//
// Mirrors the former tests/contract/control-grpc local copy (T020)
// plus the raw-bytes entry T025 leak_test.go:523 carries — by design,
// so the scan surfaces cannot drift. T020 redteam finding
// 20260706-001 originally established the eight derived encodings;
// the raw entry was re-added in T025a after stargate-redteam round-1
// flagged that ASCII corpus items would otherwise slip past all
// eight derived forms. T101 removed the local copy and made this the
// sole scanner; this is now the single encoding-set source of truth.
func secretEncodings(secret []byte) map[string]string {
	return map[string]string{
		// Raw first: the cleartext string the DP would emit if it
		// logged an ASCII corpus item verbatim (destination
		// hostname, body payload, UNAME). For non-ASCII []byte
		// secrets (argon2id hashes, salts), this entry still
		// matches the raw byte sequence and is harmless.
		"raw":           string(secret),
		"hex":           hex.EncodeToString(secret),
		"HEX":           strings.ToUpper(hex.EncodeToString(secret)),
		"base64":        base64.StdEncoding.EncodeToString(secret),
		"base64-raw":    base64.RawStdEncoding.EncodeToString(secret),
		"base64url":     base64.URLEncoding.EncodeToString(secret),
		"base64url-raw": base64.RawURLEncoding.EncodeToString(secret),
		"decimal-slice": fmt.Sprint(secret),
		// The same digit run without brackets catches a reformatted
		// or field-joined rendering of the slice.
		"decimal-run": strings.Trim(fmt.Sprint(secret), "[]"),
	}
}
