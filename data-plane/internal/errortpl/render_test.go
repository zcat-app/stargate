// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// render_test.go — direct unit gate for the future HTTP renderer
// (contracts/error-template.md §"Wire format"). The byte-level contract
// tests are T027 (tests/contract/error-template/auth_required_test.go)
// and T068a (header_set_test.go), which drive the whole DP process; this
// suite pins the same properties at the unit layer so a drift fails in
// milliseconds instead of a harness boot:
//
//   - the exact status line + four headers in declared order +
//     Content-Length matching the body actually emitted;
//   - the body equal to the Template literal with ONLY the three
//     permitted substitutions ({ROUTE_LABEL}=Tor, {CODE}=AUTH_REQUIRED,
//     {LOCAL_REFERENCE_ID}=16 lowercase hex);
//   - the ref-ID slot the ONLY render-to-render variable bytes
//     (T027's structural-equality property at unit altitude);
//   - the route-code formats and unknown-code fail-closed behavior.
package errortpl

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// refIDPattern is the §"Response body" LOCAL_REFERENCE_ID shape:
// exactly 16 lowercase hex chars, derived from crypto/rand.Read(8).
var refIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// renderAuthRequired renders one AUTH_REQUIRED response and returns it.
func renderAuthRequired(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	r := &Renderer{}
	if err := r.WriteFailure(&buf, CodeAuthRequired); err != nil {
		t.Fatalf("WriteFailure(AUTH_REQUIRED): %v", err)
	}
	return buf.Bytes()
}

func renderFailure(t *testing.T, code ErrorCode) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := (&Renderer{}).WriteFailure(&buf, code); err != nil {
		t.Fatalf("WriteFailure(%s): %v", code, err)
	}
	return buf.Bytes()
}

// extractRefID locates the 16-char ref-ID slot behind the literal
// body prefix the template fixes ("Code: {CODE} · Reference: " with
// CODE=AUTH_REQUIRED) — the same locator T027's mask uses.
func extractRefID(t *testing.T, resp []byte) string {
	t.Helper()
	const marker = "Code: AUTH_REQUIRED · Reference: "
	i := bytes.Index(resp, []byte(marker))
	if i < 0 {
		t.Fatalf("ref-ID marker %q not found in response", marker)
	}
	start := i + len(marker)
	if start+16 > len(resp) {
		t.Fatalf("ref-ID slot truncated: %d bytes after marker", len(resp)-start)
	}
	return string(resp[start : start+16])
}

// maskRefIDSlot zeroes exactly the 16 ref-ID bytes so the remaining
// bytes of two renders compare byte-for-byte (T027's mask width).
func maskRefIDSlot(t *testing.T, resp []byte) []byte {
	t.Helper()
	const marker = "Code: AUTH_REQUIRED · Reference: "
	i := bytes.Index(resp, []byte(marker))
	if i < 0 {
		t.Fatalf("ref-ID marker %q not found in response", marker)
	}
	out := append([]byte(nil), resp...)
	for j := 0; j < 16; j++ {
		out[i+len(marker)+j] = 0
	}
	return out
}

// TestWriteFailureAuthRequiredShape pins the byte-exact response
// assembly: status line, exactly four headers in declared order,
// Content-Length equal to the body length emitted in the same
// response, blank-line terminator, and a body equal to the Template
// literal with only the three permitted substitutions.
func TestWriteFailureAuthRequiredShape(t *testing.T) {
	resp := renderAuthRequired(t)

	refID := extractRefID(t, resp)
	if !refIDPattern.MatchString(refID) {
		t.Errorf("LOCAL_REFERENCE_ID %q is not 16 lowercase hex chars "+
			"(contracts/error-template.md §\"Response body\")", refID)
	}

	wantBody := strings.NewReplacer(
		"{ROUTE_LABEL}", "Tor",
		"{CODE}", "AUTH_REQUIRED",
		"{LOCAL_REFERENCE_ID}", refID,
	).Replace(Template)

	want := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: " + itoa(len(wantBody)) + "\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Stargate-Error: AUTH_REQUIRED\r\n" +
		"\r\n" +
		wantBody
	if !bytes.Equal(resp, []byte(want)) {
		t.Errorf("AUTH_REQUIRED response drift from the contract assembly "+
			"(got %d bytes, want %d) — status line, header set/order, "+
			"Content-Length, or body substitution deviates "+
			"(contracts/error-template.md §\"Wire format\")", len(resp), len(want))
	}
}

// TestWriteFailureRefIDIsFreshLowercaseHex pins AUTH_REQUIRED call freshness;
// the all-code sample test below checks repeated-call uniqueness at volume.
func TestWriteFailureRefIDIsFreshLowercaseHex(t *testing.T) {
	id1 := extractRefID(t, renderAuthRequired(t))
	id2 := extractRefID(t, renderAuthRequired(t))
	if id1 == id2 {
		t.Error("two renders produced the same LOCAL_REFERENCE_ID — " +
			"the value must be fresh per response " +
			"(contracts/error-template.md §\"Response body\")")
	}
}

// TestWriteFailureRefIDIsOnlyVariableBytes pins the
// no-distinguishing-substring property at unit altitude: masking the
// 16-byte ref-ID slot makes any two renders byte-identical, so no
// request data, timing value, or counter can vary the rest of the
// response (T027 (c)'s invariant; FR-006).
func TestWriteFailureRefIDIsOnlyVariableBytes(t *testing.T) {
	m1 := maskRefIDSlot(t, renderAuthRequired(t))
	m2 := maskRefIDSlot(t, renderAuthRequired(t))
	if !bytes.Equal(m1, m2) {
		t.Error("renders differ outside the 16-byte LOCAL_REFERENCE_ID " +
			"slot — no byte outside the permitted substitution slot may " +
			"vary (contracts/error-template.md §\"Contract tests\" row 1)")
	}
}

func TestWriteFailureRouteCodes(t *testing.T) {
	cases := []struct {
		code   ErrorCode
		status string
	}{
		{CodeRouteDown, "502 Bad Gateway"},
		{CodeRouteRefused, "502 Bad Gateway"},
		{CodeRouteTimeout, "504 Gateway Timeout"},
	}
	for _, tc := range cases {
		t.Run(string(tc.code), func(t *testing.T) {
			resp := renderFailure(t, tc.code)
			refID := extractRefIDForCode(t, resp, tc.code)
			if !refIDPattern.MatchString(refID) {
				t.Fatalf("LOCAL_REFERENCE_ID is not 16 lowercase hex chars")
			}
			body := strings.NewReplacer(
				"{ROUTE_LABEL}", "Tor",
				"{CODE}", string(tc.code),
				"{LOCAL_REFERENCE_ID}", refID,
			).Replace(Template)
			want := "HTTP/1.1 " + tc.status + "\r\n" +
				"Content-Type: text/html; charset=utf-8\r\n" +
				"Content-Length: " + itoa(len(body)) + "\r\n" +
				"Cache-Control: no-store\r\n" +
				"X-Stargate-Error: " + string(tc.code) + "\r\n\r\n" + body
			if !bytes.Equal(resp, []byte(want)) {
				t.Errorf("%s response differs from the byte-exact contract format (got %d bytes, want %d)", tc.code, len(resp), len(want))
			}
		})
	}
}

func TestWriteFailureReferenceIDsDistributed(t *testing.T) {
	// This 1,000-sample bound is a coarse detector for gross per-position
	// bias: every digit must occur 10–150 times at each of 16 positions.
	// It does not prove independence or unlinkability; crypto/rand remains the
	// implementation guarantee under test/review.
	codes := []ErrorCode{CodeAuthRequired, CodeRouteDown, CodeRouteRefused, CodeRouteTimeout}
	for _, code := range codes {
		t.Run(string(code), func(t *testing.T) {
			const samples = 1000
			seen := make(map[string]struct{}, samples)
			var counts [16][16]int
			for i := 0; i < samples; i++ {
				id := extractRefIDForCode(t, renderFailure(t, code), code)
				if !refIDPattern.MatchString(id) {
					t.Fatalf("sample %d: LOCAL_REFERENCE_ID is not 16 lowercase hex chars", i)
				}
				if _, exists := seen[id]; exists {
					t.Fatalf("sample %d: duplicate LOCAL_REFERENCE_ID", i)
				}
				seen[id] = struct{}{}
				for pos, digit := range id {
					counts[pos][hexDigitIndex(digit)]++
				}
			}
			for pos, digitCounts := range counts {
				for digit, count := range digitCounts {
					if count < 10 || count > 150 {
						t.Errorf("position %d digit %x appeared %d times; want 10–150 in %d samples", pos, digit, count, samples)
					}
				}
			}
		})
	}
}

func TestWriteFailureUnknownCode(t *testing.T) {
	var buf bytes.Buffer
	err := (&Renderer{}).WriteFailure(&buf, ErrorCode("UNKNOWN"))
	if err == nil {
		t.Fatal("unknown code returned nil error")
	}
	if buf.Len() != 0 {
		t.Fatalf("unknown code wrote %d bytes", buf.Len())
	}
}

func extractRefIDForCode(t *testing.T, resp []byte, code ErrorCode) string {
	t.Helper()
	marker := "Code: " + string(code) + " · Reference: "
	i := bytes.Index(resp, []byte(marker))
	if i < 0 {
		t.Fatalf("ref-ID marker for %s not found", code)
	}
	start := i + len(marker)
	if start+16 > len(resp) {
		t.Fatalf("%s ref-ID slot truncated", code)
	}
	return string(resp[start : start+16])
}

func hexDigitIndex(digit rune) int {
	if digit >= '0' && digit <= '9' {
		return int(digit - '0')
	}
	return int(digit-'a') + 10
}

// itoa is a tiny ASCII decimal formatter keeping this test free of
// strconv-import variance with the rendered header (the number itself
// is asserted via the byte comparison, not re-parsed).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
