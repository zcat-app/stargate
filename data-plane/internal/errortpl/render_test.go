// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// render_test.go — unit gate for the T048 AUTH_REQUIRED renderer
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
//   - route codes write nothing (T071's lift point — deliberate).
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

// TestWriteFailureRefIDIsFreshLowercaseHex pins freshness: two renders
// of the same request shape carry DIFFERENT ref-IDs (the property
// T027's structural-equality check leans on — the slot is the only
// allowed variance). Distribution/uniqueness at volume is T069's scope.
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

// TestWriteFailureRouteCodesWriteNothing pins the T048/T071 scope
// boundary: route codes are T071's wire shape; until that lands the
// renderer writes ZERO bytes rather than
// inventing a response outside the contract-review loop.
func TestWriteFailureRouteCodesWriteNothing(t *testing.T) {
	for _, code := range []ErrorCode{
		CodeRouteDown,
		CodeRouteRefused,
		CodeRouteTimeout,
	} {
		var buf bytes.Buffer
		r := &Renderer{}
		err := r.WriteFailure(&buf, code)
		if buf.Len() != 0 {
			t.Errorf("%s: renderer wrote %d bytes — route codes must "+
				"write nothing until T071 lands (scope boundary)",
				code, buf.Len())
		}
		if err == nil {
			t.Errorf("%s: renderer returned nil error — must report the "+
				"unrendered code instead of a silent partial response", code)
		}
	}
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
