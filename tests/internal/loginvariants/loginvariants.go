// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package loginvariants is the canonical allowlist + leak-scan
// surface for data-plane journal output. It is consumed by every
// contract / integration test that captures the DP's stderr journal
// (T025a success-path log invariants, T025b long-lived CONNECT,
// T070a mid-request circuit drop) so the line-class contract and
// the encoding-aware secret scan live in one place rather than
// restated — partially — in each consumer.
//
// The package's home is tests/internal/loginvariants/ (not
// tests/contract/internal/) because T025a (under tests/contract/)
// and T070a (under tests/integration/) live in DIFFERENT workspace
// modules and Go's internal-package rule forbids tests/contract
// from importing tests/integration's internals (and vice versa).
// Import path github.com/zcat-app/stargate/tests/internal/loginvariants
// satisfies the rule for both: the rule's parent-of-internal root
// is github.com/zcat-app/stargate/tests, and both consumers are
// rooted below that prefix.
//
// FR-008 / arch §6.4 prohibit the data plane from emitting any
// per-request metadata (destination hostname, URL, header, body
// byte, sub-hour timestamp). The allowlist is the positive form of
// that invariant — every journal line MUST match one of the five
// reserved line classes (startup, shutdown, SidecarEvent
// consumption, ReloadTokens apply, snapshot-write events).
// AssertNoSecrets and AssertNoSubHourTimestamp are the targeted
// negative forms; together they form the layered defense a single
// gate alone could not cover (corpus scan catches specific leaks
// the allowlist might let through; allowlist catches unanticipated
// per-request log lines no corpus item names).
//
// The line-class shape was pinned by T020's redteam finding
// 20260706-001 (tests/contract/control-grpc/leakscan_test.go's
// clean-journal case renders three of the five classes); the
// remaining two (SidecarEvent consumption, shutdown) are implicit
// in T021's contract and T050's lifecycle. T025a makes the
// allowlist explicit and reusable.
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

// AllowedLineClass names one permitted data-plane journal line
// class. The Pattern matches a single journal line (not a multi-line
// span) of that class; Patterns are case-insensitive and
// multiline-anchored so they apply line-by-line to a captured
// journal regardless of the line terminator the DP's logger emits.
//
// AllowedFields is the per-class field contract (T101 acceptance #2,
// review A2 path #2): the set of slog key= names a line of this class
// MAY carry beyond the universal slog fields (level, msg). A line whose
// msg= matches the class but which carries a key not in AllowedFields
// AND not in universalFields is rejected — `msg=startup dst=...` is a
// per-request leak that the bare pattern (pre-T101) let through. Field
// KEYS are programmer vocabulary (not captured content), so a rejected
// field's KEY may appear in the failure diagnostic; its VALUE never does.
type AllowedLineClass struct {
	Name          string
	Pattern       *regexp.Regexp
	AllowedFields []string
}

// universalFields are the slog TextHandler fields every journal line
// carries regardless of class. slog always emits level= and msg=; the
// DP's logger is configured WITHOUT time= (AssertNoSubHourTimestamp
// would flag every line otherwise), so time is deliberately NOT
// universal — a `time=`-bearing line is a per-request timestamp the
// scanner surfaces rather than normalises.
var universalFields = map[string]bool{
	"level": true,
	"msg":   true,
}

// msgFieldAlts returns the regex alternation contents (without the
// enclosing (?:…)) matching a slog TextHandler msg= field for any
// of the given values. slog's TextHandler emits msg=startup for
// single words and msg="tokens applied" for phrases (quoting only
// when whitespace is present). Both shapes are accepted for single-
// word values so a future DP that changes a name shape does not
// require an allowlist edit; phrases accept only the quoted form
// (slog never emits bare phrases — a future logger that does is
// non-conformant and would surface as an allowlist failure that
// forces a deliberate edit).
//
// RE2 (Go's regexp engine) does not support lookahead, so the bare
// form's terminator is consumed via (?:\s|$) rather than asserted
// via (?=…). The enclosing pattern's trailing .*$ still matches
// because (.*) accepts zero characters.
func msgFieldAlts(values ...string) string {
	parts := make([]string, 0, len(values)*2)
	for _, v := range values {
		quoted := `msg="` + regexp.QuoteMeta(v) + `"`
		if strings.ContainsAny(v, " \t") {
			// Phrase: only the quoted shape is emitted by slog
			// TextHandler; accepting a bare phrase would
			// over-permit (a bare `msg=tokens applied` parses
			// as msg=tokens followed by free-text `applied`,
			// which is not slog output).
			parts = append(parts, quoted)
		} else {
			// Single word: bare (msg=startup, terminated by
			// whitespace or end-of-line so `msg=startupxyz`
			// does not match) OR quoted (msg="startup").
			bare := `msg=` + regexp.QuoteMeta(v) + `(?:[\s]|$)`
			parts = append(parts, quoted, bare)
		}
	}
	return strings.Join(parts, `|`)
}

// AllowedLineClasses is the canonical allowlist every DP journal
// line must match exactly one of. Tests that capture the DP journal
// (T025a/b, T070a) assert every line matches a class in this slice
// rather than restating the patterns. The set is reserved by the
// existing contract tests (T020 ReloadTokens, T021 WatchEvents,
// T025 leak); a new line class is a Constitution-level change that
// amends this list AND every contract that references it.
//
// Five classes per FR-008 / arch §6.4 + the T025a task body:
//
//  1. startup             — boot lines before the listener accepts
//  2. shutdown            — graceful-teardown lines on SIGINT
//  3. reload_tokens_apply — ReloadTokens generation swap (T020)
//  4. snapshot_write      — dp-snapshot.json persist (T020/T046)
//  5. sidecar_event       — WatchEvents push consumption (T021);
//     includes the closed-vocabulary violation marker (T021's
//     journalHasDetailViolation in
//     tests/contract/control-grpc/watch_events_test.go:310) because
//     the violation is emitted from the same WatchEvents consumer
//     and is not a separate line class from the contract's
//     standpoint.
//
// Patterns are constructed eagerly at init (MustCompile panics on a
// bad pattern — a regression caught at first test run, not deferred
// to the field).
var AllowedLineClasses = []AllowedLineClass{
	{
		Name: "startup",
		Pattern: regexp.MustCompile(
			`(?im)^.*\b(?:` + msgFieldAlts("startup") + `).*$`),
		AllowedFields: []string{"listener"},
	},
	{
		Name: "shutdown",
		Pattern: regexp.MustCompile(
			`(?im)^.*\b(?:` + msgFieldAlts("shutdown") + `).*$`),
		AllowedFields: []string{"reason"},
	},
	{
		Name: "reload_tokens_apply",
		Pattern: regexp.MustCompile(
			`(?im)^.*\b(?:` + msgFieldAlts(
				"tokens applied", "reload applied",
				"reload_applied", "reload_tokens_apply",
			) + `).*$`),
		AllowedFields: []string{"generation", "count"},
	},
	{
		Name: "snapshot_write",
		Pattern: regexp.MustCompile(
			// Both success (msg="snapshot written") and failure
			// (msg="snapshot write failed") variants per T020's
			// reload_tokens_test.go:206 and leakscan_test.go:63.
			`(?im)^.*\b(?:` + msgFieldAlts(
				"snapshot written", "snapshot write failed",
				"snapshot_persisted", "snapshot_persist_failed",
			) + `).*$`),
		AllowedFields: []string{"err"},
	},
	{
		Name: "sidecar_event",
		Pattern: regexp.MustCompile(
			// The event-received log line (slog msg= field) the
			// WatchEvents consumer emits when it processes a
			// pushed SidecarEvent (T021's contract). Matches the
			// happy-path event-receipt shape only — the closed-
			// vocabulary detail-violation journal line T021's
			// journalHasDetailViolation greps for is NOT matched
			// here; that line's msg= phrasing is unspecified
			// (T021 uses substring tolerance) and including any
			// marker-based alternation created a per-request
			// false-pass vector (stargate-redteam round-1 finding:
			// `msg="request rejected" dst=…` would match a
			// bare-word marker alternation; tightening to
			// markers-inside-msg= still let
			// `msg="request rejected"` through). When T070a
			// lands and pins the actual violation-msg= phrasing
			// the DP emits, this class extends with that exact
			// value; until then T070a's future delta-scoped
			// journal check (snapshot around the violation push)
			// plus the corpus scan is the established pattern
			// for handling violation journal output without
			// broadening the allowlist.
			`(?im)^.*\b(?:` +
				msgFieldAlts(
					"sidecar event", "sidecar_event",
					"event received", "event_received",
					"watchevents event", "watchevents_event",
				) +
				`).*$`),
		AllowedFields: []string{"sidecar", "kind", "detail"},
	},
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

// AssertOnlyAllowedLines splits journal into lines and asserts each
// non-empty line matches exactly one AllowedLineClasses pattern AND
// carries no field key outside that class's AllowedFields ∪ the
// universal slog fields (level, msg). t.Errorf per violator (no fatal)
// so a multi-line breach surfaces all offenders in one run rather than
// just the first. Trailing "\r" is trimmed per line so a CRLF-formatted
// journal (Windows-side container output edge case) does not
// false-negative on the allowlist while still failing the corpus scan
// that operates on the raw delta.
//
// Failure diagnostics are index/length/rule-only (T101 acceptance #3,
// review A2 path #3): the rejected line is NEVER echoed, because a
// per-request field smuggled onto an allowlisted msg= often carries the
// very destination / token / UNAME bytes FR-008 exists to keep out of
// journals — echoing the line re-leaks it into CI output. The matched
// class name and the offending field's KEY are vocabulary, not captured
// content, and appear in the diagnostic so a maintainer can locate the
// breach without seeing its value.
func AssertOnlyAllowedLines(t LogReporter, journal string) {
	t.Helper()
	for i, line := range strings.Split(journal, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if strings.TrimSpace(trimmed) == "" {
			continue
		}
		var matched *AllowedLineClass
		matches := 0
		for idx := range AllowedLineClasses {
			if AllowedLineClasses[idx].Pattern.MatchString(trimmed) {
				matches++
				matched = &AllowedLineClasses[idx]
			}
		}
		switch matches {
		case 0:
			t.Errorf("journal line %d (len=%d, rule=no_class_matched) "+
				"not in any allowlist class — per-request or "+
				"otherwise-unclassified journal output is a "+
				"Constitution Principle I / III breach; content elided "+
				"(FR-008 / arch §6.4; T025a §Analysis)",
				i, len(trimmed))
		case 1:
			// Field allowlist (T101 acceptance #2). A field key not in
			// the class's AllowedFields ∪ universalFields is a per-
			// request surface smuggled past the msg= gate.
			for _, key := range fieldKeys(trimmed) {
				if universalFields[key] {
					continue
				}
				if isAllowedField(matched.AllowedFields, key) {
					continue
				}
				t.Errorf("journal line %d (len=%d, class=%s) has "+
					"field %q not in the class allowlist "+
					"(rule=unexpected_field) — an allowed msg= may not "+
					"carry a per-request field; field VALUE elided "+
					"(FR-008 / arch §6.4; Constitution Principle I / III)",
					i, len(trimmed), matched.Name, key)
			}
		default:
			t.Errorf("journal line %d (len=%d, rule=ambiguous_class) "+
				"matched %d allowlist classes — patterns overlap; "+
				"tighten the looser one so each line class has exactly "+
				"one home; content elided",
				i, len(trimmed), matches)
		}
	}
}

// isAllowedFields reports whether key is in fields. A small linear
// scan over a short slice (the largest class allowlist has three
// entries) outperforms a map allocation per line and keeps the class
// definitions literal []strings rather than maps.
func isAllowedField(fields []string, key string) bool {
	for _, f := range fields {
		if f == key {
			return true
		}
	}
	return false
}

// quotedValue matches a double-quoted slog value (with \" escapes) so
// fieldKeys can mask quoted values before scanning for key= tokens — a
// `key=` substring inside a quoted value (e.g. an err= string reading
// `unknown field=xyz`) would otherwise masquerade as a field key.
var quotedValue = regexp.MustCompile(`"[^"\\]*(?:\\.[^"\\]*)*"`)

// fieldKey matches a slog TextHandler field key: an identifier at a
// token boundary (line start or whitespace) followed immediately by =.
// Values are separated from keys by the same boundary, so the key
// capture is unambiguous once quoted values are masked.
var fieldKey = regexp.MustCompile(`(?:^|[\s])([A-Za-z_][A-Za-z0-9_]*)=`)

// fieldKeys extracts the slog field keys present in line, respecting
// quoted values. Used by AssertOnlyAllowedLines's per-class field
// allowlist (T101 acceptance #2).
func fieldKeys(line string) []string {
	masked := quotedValue.ReplaceAllString(line, `""`)
	out := fieldKey.FindAllStringSubmatch(masked, -1)
	if len(out) == 0 {
		return nil
	}
	keys := make([]string, 0, len(out))
	for _, m := range out {
		keys = append(keys, m[1])
	}
	return keys
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
