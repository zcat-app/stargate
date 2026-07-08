// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the HTTP CONNECT AUTH_REQUIRED response shape and
// its no-distinguishing-substring property — specs/001-tor-route/spec.md
// FR-006 (HTTP CONNECT path on token absence/mismatch → 407 +
// AUTH_REQUIRED template; offered token and rejected destination MUST
// NOT appear in any response) + FR-009 (privacy-safe failure response
// shape) and contracts/error-template.md §"Contract tests" row 1
// (missing vs malformed → 407 + AUTH_REQUIRED, byte-for-byte identical
// except the LOCAL_REFERENCE_ID substitution slot) +
// contracts/socks5-auth.md §"HTTP CONNECT path" (the auth-failure
// flow) + §"HTTP CONNECT path · Invariants enforced by the contract
// test" (Missing → 407; Malformed → 407 no distinction from missing;
// Response NEVER includes destination or offered token). Task body:
// specs/001-tor-route/tasks.md T027.
//
// This is the failure-path half of the two-framing split (research.md
// §9); T026 owns the success-path half. T025's
// AuthFailure_NoTokenBytesInCapture is the SOCKS5 analogue and the
// route-independent auth-failure setup precedent (bare dpharness.Start,
// one token push, NO upstream, NO HEALTHY) T027 mirrors for the
// CONNECT path. The no-distinguishing-substring property is unique to
// the CONNECT template path: the SOCKS5 failure is a fixed 2-byte
// `01 FF` with no renderable body, so "identical modulo the random
// ref-ID slot" is a non-trivial property the SOCKS5 path does not
// need.
//
// The structural-equality check masks EXACTLY the 16-char
// LOCAL_REFERENCE_ID hex slot (located via the body literal prefix
// `Code: AUTH_REQUIRED · Reference: `) and asserts the two responses
// are byte-for-byte equal on the remainder — proving no
// distinguishing substring outside the ref-ID slot. The
// distinct-ref-ID property (ref-IDs vary across responses) is T069's
// orthogonal scope; T027 does NOT assert the two captured ref-IDs
// differ, only that no distinguishing substring exists outside the
// slot.
//
// Tests-first (Constitution Principle VII): content-gates on T043
// (listener/connect.go — the inbound CONNECT surface under test),
// T044 (auth/token.go — the bearer-verify failure path that produces
// AUTH_REQUIRED), and T048 (errortpl/render.go — the renderer that
// substitutes {ROUTE_LABEL}/{CODE}/{LOCAL_REFERENCE_ID} into the
// Template and emits the four headers), plus the boot minimum inside
// dpharness.Start (T042/T045/T050); the test SKIPs until all land,
// then a response-shape, structural-equality, or leak regression is
// FAIL, not SKIP.
package errortemplate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

// authRequiredPlaintext is the bearer-token plaintext the test mints
// into an argon2id hash via dpharness.MintToken and pushes to the DP
// via ReloadTokens. The generation is NON-EMPTY — the realistic case
// where a missing/malformed offer is rejected against a populated
// generation, not the degenerate empty-generation case. 32 hex chars
// — the CONNECT path's syntactic gate (contracts/socks5-auth.md
// §"HTTP CONNECT path" step 2: ^[0-9a-f]{32}$) passes for THIS token
// (the valid one); the malformed offer `notatoken` fails the gate and
// never reaches hashing. Distinct from T025a/T025b/T026's token
// plaintexts so a corpus-scan hit is attributable to this test.
const authRequiredPlaintext = "a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c"

// malformedToken is the canonical malformed bearer-token value sent
// in case (b). Per contracts/socks5-auth.md §"HTTP CONNECT path"
// step 2 the syntactic gate ^[0-9a-f]{32}$ fires BEFORE hashing;
// `notatoken` fails BOTH the length gate (9 chars ≠ 32) AND the
// charset gate (contains non-hex 'n'/'o'/'t'/'k'). One value covers
// both failure modes, matching the cited test method verbatim.
const malformedToken = "notatoken"

// wantStatusLine is the byte-exact status line the DP MUST emit on
// the CONNECT AUTH_REQUIRED path (contracts/error-template.md
// §"Wire format · Status line", AUTH_REQUIRED row).
const wantStatusLine = "HTTP/1.1 407 Proxy Authentication Required\r\n"

// wantXStargateError is the byte-exact header that marks the
// response as AUTH_REQUIRED (contracts/error-template.md
// §"Wire format · Response headers"). Asserted via Contains so a
// future header-order regression does not false-fail this shape
// check before the structural-equality check gives a more precise
// byte-comparison failure; the exhaustive header-order gate is
// T068a's scope.
const wantXStargateError = "X-Stargate-Error: AUTH_REQUIRED\r\n"

// refIDSlotPrefix is the body literal immediately preceding the
// 16-char LOCAL_REFERENCE_ID hex run. Used to locate the ref-ID slot
// for the structural-equality masking. The literal is body-specific
// (no header carries "Code:"), so a single byte.Index locates the
// slot unambiguously.
const refIDSlotPrefix = "Code: AUTH_REQUIRED · Reference: "

// refIDHexLen is the exact width of the LOCAL_REFERENCE_ID
// substitution slot per contracts/error-template.md §"Response body"
// (16-char lowercase-hex of crypto/rand.Read(8)). The masking check
// zeroes EXACTLY this many bytes — a wider or narrower mask would
// hide real distinguishing bytes (§Analysis redteam scope (b)).
const refIDHexLen = 16

// authRequiredBodyRe matches the AUTH_REQUIRED response body
// byte-for-byte, with {ROUTE_LABEL}="Tor", {CODE}="AUTH_REQUIRED",
// and {LOCAL_REFERENCE_ID}=[0-9a-f]{16}. Synced from
// contracts/error-template.md §"Response body" at /start 2026-07-07
// (which matches data-plane/internal/errortpl/template.go's Template
// literal byte-for-byte per T019's gate). The contract file is the
// durable source of truth; this inline copy is the gate that catches
// drift between the contract and the DP's rendered body.
//
// LF line endings (single \n), NOT CRLF — per §"Response body":
// "Line endings are \n (single LF), not CRLF". Anchored with ^...$
// so an extra body element before or after the Template fails the
// match (§Analysis redteam scope (e)). The · is the UTF-8 middle dot
// (U+00B7, bytes 0xC2 0xB7) — Go regexp handles UTF-8 natively.
var authRequiredBodyRe = regexp.MustCompile(
	`^<!doctype html><meta charset=utf-8>\n` +
		`<title>Stargate: route unavailable</title>\n` +
		`<h1>Route unavailable</h1>\n` +
		`<p>The Tor route is currently not serving requests\.</p>\n` +
		`<p>Code: AUTH_REQUIRED · Reference: [0-9a-f]{16}</p>\n` +
		`<p>See the admin dashboard for details\.</p>$`)

// TestAUTHRequired pins the CONNECT AUTH_REQUIRED contract: exact
// response shape, no distinguishing substring between missing and
// malformed offers, and response leak-scan. Single consolidated body
// for act+shape+structural (the assertions layer on one fixture —
// one DP boot, one token push, two sequential CONNECT auth-fail
// requests on independent connections); only the two response-bytes
// leak scans split into sub-tests so a corpus hit in either case is
// independently attributable (the T025 leak-test precedent).
func TestAUTHRequired(t *testing.T) {
	repoRoot := dpharness.FindRepoRoot(t)
	// Per-test content gates beyond the boot minimum inside
	// dpharness.Start (T042/T045/T050): the CONNECT listener under
	// test, the auth-failure surface, and the renderer that produces
	// the AUTH_REQUIRED response bytes.
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "listener", "connect.go"),
		"listener/connect.go not implemented yet (T043); this skip self-lifts when T043 lands")
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "auth", "token.go"),
		"auth/token.go not implemented yet (T044); this skip self-lifts when T044 lands")
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "errortpl", "render.go"),
		"errortpl/render.go not implemented yet (T048 — the AUTH_REQUIRED renderer); "+
			"this skip self-lifts when T048 lands")

	// Route-independent auth-failure setup (mirrors T025's
	// AuthFailure_NoTokenBytesInCapture, NOT T026's success-path
	// setup): bare dpharness.Start — NO WithUpstream (auth-fail
	// happens before the forward path is consulted; the upstream is
	// never dialed), NO WithBeforeBoot(fakecp.Start) (no HEALTHY to
	// push — AUTH_REQUIRED is route-independent; the DP's background
	// WatchEvents dial fails harmlessly). The valid token below
	// establishes a non-empty generation — the realistic case where
	// a missing/malformed offer is rejected against a populated
	// generation.
	h := dpharness.Start(t)

	reloadResp := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenHash{dpharness.MintToken(t, authRequiredPlaintext)})
	if reloadResp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want "+
			"APPLY_STATUS_OK — precondition for the AUTH_REQUIRED "+
			"test failed; the DP did not accept the test's token "+
			"generation (without a populated generation the test "+
			"cannot assert the missing-vs-malformed distinction "+
			"against a realistic state)", reloadResp.GetStatus())
	}

	// Distinctive corpus items scanned across response bytes. The
	// destination is the FR-006/FR-009-named surface; the malformed
	// token is the offered-but-rejected secret. Each is scanned in
	// nine renderings (raw + eight derived) per loginvariants.
	const dest = "t027-dest.example.onion"

	// (a) Missing Proxy-Authorization → 407 + AUTH_REQUIRED template.
	// Request-line only, no Proxy-Authorization header — the cited
	// test method's missing-header shape.
	respMissing := sendCONNECT(t, h,
		fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\n\r\n", dest))

	// (b) Malformed token → 407 + AUTH_REQUIRED template. The DP
	// closes after AUTH_REQUIRED, so this is a NEW connection (not a
	// pipelined follow-up on the first).
	respMalformed := sendCONNECT(t, h,
		fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nProxy-Authorization: Bearer %s\r\n\r\n",
			dest, malformedToken))

	// (a) StatusShape: both responses ARE the AUTH_REQUIRED template,
	// not (e.g.) a 200, a 502, or a different code. Gates the
	// response identity before the structural-equality check gives a
	// misleading byte-comparison failure. Response bytes are WITHHELD
	// from failure messages (a buggy DP may echo the destination or
	// malformed token into the response, and those are scanned
	// separately under Response_NoCorpusItem).
	assertStatusShape(t, "missing", respMissing)
	assertStatusShape(t, "malformed", respMalformed)

	// (b) BodyTemplate: both response bodies match the Template
	// literal byte-for-byte with the permitted substitutions.
	assertBodyTemplate(t, "missing", respMissing)
	assertBodyTemplate(t, "malformed", respMalformed)

	// (c) NoDistinguishingSubstring: the two responses are
	// byte-for-byte identical EXCEPT for the 16-char ref-ID slot.
	// Mask those 16 bytes in both and assert equality on the
	// remainder — a DP that emits ANY distinguishing byte outside
	// the ref-ID slot (a header value, a body field, an extra CRLF,
	// a different Content-Length) fails here. The masking is exactly
	// 16 bytes wide so a wider-or-narrower mask cannot hide real
	// distinguishing bytes (§Analysis redteam scope (b)). This is
	// the property the task body names.
	maskedMissing := maskRefIDSlot(t, respMissing)
	maskedMalformed := maskRefIDSlot(t, respMalformed)
	if !bytes.Equal(maskedMissing, maskedMalformed) {
		t.Errorf("AUTH_REQUIRED responses for missing vs malformed "+
			"Proxy-Authorization differ outside the 16-char "+
			"LOCAL_REFERENCE_ID slot — contracts/socks5-auth.md "+
			"§\"HTTP CONNECT path · Invariants\" row 2 and "+
			"contracts/error-template.md §\"Contract tests\" row 1 "+
			"require byte-for-byte identity outside the ref-ID "+
			"slot (a third-party observer must not learn from the "+
			"response bytes whether the client sent a missing "+
			"header or a malformed token; Principle III). "+
			"Response bytes withheld (leak-safe; see "+
			"Response_NoCorpusItem for the dest/token scan). "+
			"masked responses: missing=%d bytes, malformed=%d bytes.",
			len(maskedMissing), len(maskedMalformed))
	}

	// (d) ResponseLeaksNothing — two sub-tests, one per case so a
	// corpus hit is independently attributable. The 407 response
	// carries no destination and no malformed-token byte in any of
	// the nine textual renderings an accidental logger would
	// produce (contracts/socks5-auth.md §"Invariants" rows 4–5;
	// contracts/error-template.md §"Leak-corpus invariant";
	// Principle III / FR-006 / FR-009).
	t.Run("Response_NoCorpusItem_Missing", func(t *testing.T) {
		loginvariants.AssertNoSecrets(t, string(respMissing),
			[]byte(dest), []byte(malformedToken))
	})
	t.Run("Response_NoCorpusItem_Malformed", func(t *testing.T) {
		loginvariants.AssertNoSecrets(t, string(respMalformed),
			[]byte(dest), []byte(malformedToken))
	})
}

// sendCONNECT dials the DP, writes req, and reads the full response
// until EOF. The DP closes after AUTH_REQUIRED per
// contracts/error-template.md §"HTTP CONNECT path"; io.ReadAll
// returns the complete response on clean EOF. A wedged DP that
// writes the response but never closes fails at the connection
// deadline rather than hanging the test (§Analysis redteam scope
// (f)).
func sendCONNECT(t *testing.T, h *dpharness.Harness, req string) []byte {
	t.Helper()
	conn := dialProxy(t, h)
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT request: %v — the DP closed or "+
			"errored before reading the request (assertion setup "+
			"failed; the AUTH_REQUIRED response was never produced)",
			err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatalf("DP did not close within the connection "+
				"deadline after the CONNECT request — "+
				"contracts/error-template.md §\"HTTP CONNECT "+
				"path\" requires close after AUTH_REQUIRED; "+
				"possible wedged DP (read returned partial "+
				"response of %d bytes, withheld)", len(resp))
		}
		t.Fatalf("reading AUTH_REQUIRED response (got %d bytes "+
			"before error, withheld): %v", len(resp), err)
	}
	return resp
}

// dialProxy connects to the DP's proxy listener with a deadline that
// covers the argon2id auth-fail path (~50 ms nominal, more on loaded
// CI) plus the render + close. Mirrors the package-local dialProxy
// in tests/contract/socks5/demux_test.go (T023); not importable
// across packages, so re-implemented here. 30 s mirrors T025/T026's
// deadline — generous for argon2id under CI load.
func dialProxy(t *testing.T, h *dpharness.Harness) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", h.ProxyAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	return conn
}

// assertStatusShape asserts resp begins with the AUTH_REQUIRED
// status line and carries the X-Stargate-Error: AUTH_REQUIRED
// header. Gates the response IS the AUTH_REQUIRED template before
// the structural-equality check gives a misleading byte-comparison
// failure. Response bytes are WITHHELD from the failure message (a
// buggy DP may echo the destination or malformed token into the
// response; those are scanned separately under
// Response_NoCorpusItem).
func assertStatusShape(t *testing.T, label string, resp []byte) {
	t.Helper()
	if !bytes.HasPrefix(resp, []byte(wantStatusLine)) {
		t.Errorf("%s: AUTH_REQUIRED response does not start "+
			"with the contract status line (contracts/error-"+
			"template.md §\"Wire format · Status line\", "+
			"AUTH_REQUIRED row); got %d bytes (withheld; see "+
			"Response_NoCorpusItem_%s for the dest/token scan)",
			label, len(resp), label)
		return
	}
	if !bytes.Contains(resp, []byte(wantXStargateError)) {
		t.Errorf("%s: AUTH_REQUIRED response missing the "+
			"X-Stargate-Error: AUTH_REQUIRED header "+
			"(contracts/error-template.md §\"Wire format · "+
			"Response headers\"); got %d bytes (withheld)",
			label, len(resp))
	}
}

// assertBodyTemplate asserts the response body matches the errortpl
// Template literal byte-for-byte after substituting
// {ROUTE_LABEL}="Tor", {CODE}="AUTH_REQUIRED", and
// {LOCAL_REFERENCE_ID}=a 16-char lowercase-hex run. Locates the body
// via the header-terminating blank line (\r\n\r\n); LF line endings
// in the body per §"Response body". A DP that emits a different body
// (extra whitespace, missing element, wrong ROUTE_LABEL, trailing
// newline, CRLF contamination) fails here. The match is
// full-Template-literal (anchored ^...$), not prefix/suffix
// (§Analysis redteam scope (e)).
func assertBodyTemplate(t *testing.T, label string, resp []byte) {
	t.Helper()
	body := bodyAfterHeaders(resp)
	if body == nil {
		t.Errorf("%s: AUTH_REQUIRED response has no header-"+
			"terminating blank line (\\r\\n\\r\\n) — the header "+
			"block is malformed or never terminated "+
			"(contracts/error-template.md §\"Wire format\"); "+
			"got %d bytes (withheld)", label, len(resp))
		return
	}
	if !authRequiredBodyRe.Match(body) {
		t.Errorf("%s: AUTH_REQUIRED body does not match the "+
			"Template literal with {ROUTE_LABEL}=\"Tor\", "+
			"{CODE}=\"AUTH_REQUIRED\", {LOCAL_REFERENCE_ID}="+
			"[0-9a-f]{16} (contracts/error-template.md "+
			"§\"Response body\"); body was %d bytes (withheld; "+
			"see Response_NoCorpusItem_%s for the dest/token "+
			"scan)", label, len(body), label)
	}
}

// bodyAfterHeaders returns the bytes after the header-terminating
// blank line (\r\n\r\n), or nil if the blank line is absent. The
// body starts immediately after the 4-byte terminator.
func bodyAfterHeaders(resp []byte) []byte {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil
	}
	return resp[idx+4:]
}

// maskRefIDSlot returns a copy of resp with the 16-byte
// LOCAL_REFERENCE_ID slot (the bytes immediately following
// refIDSlotPrefix) zeroed out. Fails the test if the prefix is
// absent or the response ends before 16 bytes follow it — the
// slot's location is load-bearing for the structural-equality check,
// and a DP that moves or removes it breaches the body-template
// contract (BodyTemplate would have flagged the shape failure first;
// reaching this point with a missing slot is a divergent bug worth
// surfacing explicitly).
func maskRefIDSlot(t *testing.T, resp []byte) []byte {
	t.Helper()
	prefix := []byte(refIDSlotPrefix)
	idx := bytes.Index(resp, prefix)
	if idx < 0 {
		t.Fatalf("AUTH_REQUIRED response missing the ref-ID slot "+
			"prefix %q — the body does not match contracts/error-"+
			"template.md §\"Response body\" (BodyTemplate would "+
			"have flagged this first; response bytes withheld)",
			refIDSlotPrefix)
	}
	slotStart := idx + len(prefix)
	slotEnd := slotStart + refIDHexLen
	if slotEnd > len(resp) {
		t.Fatalf("AUTH_REQUIRED response ends %d bytes after the "+
			"ref-ID slot prefix, want at least %d (a 16-hex "+
			"ref-ID) — truncated response (bytes withheld)",
			len(resp)-slotStart, refIDHexLen)
	}
	out := make([]byte, len(resp))
	copy(out, resp)
	for i := slotStart; i < slotEnd; i++ {
		out[i] = 0
	}
	return out
}
