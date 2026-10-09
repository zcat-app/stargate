// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Direct production-renderer contract assertions for all four formats.
package errortemplate

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

const headerSetPlaintext = "9c8b7a6d5e4f3021b2a3c4d5e6f70819"

// wantContentTypeLine and wantCacheControlLine are the byte-exact
// header lines the contract mandates (contracts/error-template.md
// §"Wire format · Response headers").
const (
	wantContentTypeLine  = "Content-Type: text/html; charset=utf-8"
	wantCacheControlLine = "Cache-Control: no-store"
)

// wantHeaderOrder is the exact wire order of the four permitted header
// names (case-sensitive, as serialised).
var wantHeaderOrder = [...]string{"Content-Type", "Content-Length", "Cache-Control", "X-Stargate-Error"}

// forbiddenHeaderNames is the closed set asserted absent from the
// captured block (task body (g)): the spec's enumerated forbidden list
// plus the headers Go's net/http server adds by default if not
// suppressed — a regression to http.Server defaults trips here.
var forbiddenHeaderNames = [...]string{
	"Server", "Via",
	"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port",
	"Proxy-Agent",
	"Date", "Connection", "Keep-Alive", "Transfer-Encoding",
}

// headerSetFixedCorpus is the fragment set of contracts/error-template.md
// §"Leak-corpus invariant" applicable to a harness-isolated run: the
// would-be version strings and backtrace fragments. (The
// .onion-corpus / egress-IP / exit-IP entries require the live stack;
// this run's dynamic items are the per-test destination and token,
// added at the scan site.)
var headerSetFixedCorpus = [...]string{
	"Server: tor/", "Tor", "Tor Browser", "Mandrel", "Quarkus", "Hibernate", "SQLite",
	"panic:", "goroutine", "stack trace", "at line",
}

func TestHeaderSet(t *testing.T) {
	response, err := renderCode(t, "AUTH_REQUIRED")
	if err != nil {
		t.Fatal(err)
	}
	assertHeaderBlock(t, "AUTH_REQUIRED", "t068a-auth.example.onion", response)
}

func TestRouteRenderers(t *testing.T) {
	cases := []struct {
		code   string
		status string
	}{
		{"ROUTE_DOWN", "502 Bad Gateway"},
		{"ROUTE_REFUSED", "502 Bad Gateway"},
		{"ROUTE_TIMEOUT", "504 Gateway Timeout"},
	}
	for _, tc := range cases {
		code := tc.code
		t.Run(code, func(t *testing.T) {
			response, err := renderCode(t, code)
			if err != nil {
				t.Fatalf("direct renderer rejected supported route code: %v", err)
			}
			assertRouteResponse(t, code, tc.status, "t071-dest.example.onion", response)
		})
	}
}

func assertRouteResponse(t *testing.T, code, status, dest string, resp []byte) {
	t.Helper()
	refIDPrefix := []byte("Code: " + code + " · Reference: ")
	body := bodyAfterHeaderBlock(t, code, resp)
	i := bytes.Index(body, refIDPrefix)
	if i < 0 || i+len(refIDPrefix)+16 > len(body) {
		t.Fatalf("%s response has no complete reference-ID slot; body withheld", code)
	}
	refID := body[i+len(refIDPrefix) : i+len(refIDPrefix)+16]
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).Match(refID) {
		t.Errorf("%s LOCAL_REFERENCE_ID is not 16 lowercase hex chars", code)
	}
	wantBody := "<!doctype html><meta charset=utf-8>\n" +
		"<title>Stargate: route unavailable</title>\n" +
		"<h1>Route unavailable</h1>\n" +
		"<p>The Tor route is currently not serving requests.</p>\n" +
		"<p>Code: " + code + " · Reference: " + string(refID) + "</p>\n" +
		"<p>See the admin dashboard for details.</p>"
	want := "HTTP/1.1 " + status + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(wantBody)) + "\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Stargate-Error: " + code + "\r\n\r\n" + wantBody
	if !bytes.Equal(resp, []byte(want)) {
		t.Errorf("%s response differs from byte-exact status, header, or template format (got %d bytes, want %d); response withheld", code, len(resp), len(want))
	}

	loginvariants.AssertNoSecrets(t, string(resp), []byte(dest), []byte(headerSetPlaintext))
	assertResponseCorpus(t, code, resp, dest, headerSetPlaintext)
}

func assertResponseCorpus(t *testing.T, code string, resp []byte, extra ...string) {
	t.Helper()
	body := bodyAfterHeaderBlock(t, "response", resp)
	// The checked-in corpus deliberately retains "Tor": its one permitted
	// hit is the contract's fixed route label at this independently checked
	// template position. Every other corpus value is forbidden everywhere.
	label := []byte("The Tor route")
	wantAt := bytes.Index(body, label) + len("The ")
	if wantAt < len("The ") || bytes.Count(resp, []byte("Tor")) != 1 || bytes.Index(resp, []byte("Tor")) != bytes.Index(resp, []byte("\r\n\r\n"))+4+wantAt {
		t.Errorf("response has a Tor occurrence outside the single fixed route-label position")
	}
	corpusBytes, err := os.ReadFile("leak-corpus.txt")
	if err != nil {
		t.Fatalf("read checked-in leak corpus: %v", err)
	}
	corpus := strings.Split(strings.TrimSpace(string(corpusBytes)), "\n")
	for _, item := range extra {
		corpus = append(corpus, item)
	}
	for _, fragment := range corpus {
		if fragment == "" {
			continue
		}
		if fragment == "Tor" {
			continue
		}
		if bytes.Contains(resp, []byte(fragment)) {
			t.Errorf("%s response contains a checked-in leak-corpus item (length %d); response withheld", code, len(fragment))
		}
	}
}

func bodyAfterHeaderBlock(t *testing.T, code string, resp []byte) []byte {
	t.Helper()
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatalf("%s response has no header terminator; response withheld", code)
	}
	return resp[idx+4:]
}

func splitHeaderBlock(t *testing.T, code string, resp []byte) (block, body []byte) {
	t.Helper()
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatalf("%s: response has no header-terminating blank line "+
			"(\\r\\n\\r\\n) — cannot capture the header block "+
			"(contracts/error-template.md §\"Wire format\"); got %d bytes "+
			"(withheld)", code, len(resp))
	}
	return resp[:idx+4], resp[idx+4:]
}

// assertHeaderBlock asserts the eight task-body invariants over one
// captured error response. Diagnostics carry index/length/rule only:
// header VALUES, the body, the destination, and the token are never
// echoed into CI output (a buggy DP may have smuggled them into the
// block; echoing re-leaks — the loginvariants discipline).
func assertHeaderBlock(t *testing.T, code, dest string, resp []byte) {
	t.Helper()
	block, body := splitHeaderBlock(t, code, resp)
	headerBytes := block[:len(block)-4] // strip the \r\n\r\n terminator
	lines := bytes.Split(headerBytes, []byte("\r\n"))
	// lines[0] is the status line — capture metadata; its per-code byte
	// shape is T065–T067's assertion (§Analysis residue).
	headers := lines[1:]

	// (a) Header count is exactly four.
	if len(headers) != len(wantHeaderOrder) {
		t.Errorf("(a) %s: header block carries %d header lines, want "+
			"exactly %d (contracts/error-template.md §\"Response "+
			"headers\": exactly these four headers, no others); block "+
			"bytes withheld", code, len(headers), len(wantHeaderOrder))
		return
	}

	// (b) Order matches the contract, case-sensitive as serialised.
	for i, want := range wantHeaderOrder {
		name, _, ok := bytes.Cut(headers[i], []byte(":"))
		if !ok || string(name) != want {
			t.Errorf("(b) %s: header %d (len=%d) is not %q — the four "+
				"headers must appear in contract order, case-sensitive "+
				"as serialised on the wire (contracts/error-template.md "+
				"§\"Response headers\"); name bytes withheld",
				code, i, len(headers[i]), want)
		}
	}

	// (c) Content-Type byte-for-byte.
	if !bytes.Equal(headers[0], []byte(wantContentTypeLine)) {
		t.Errorf("(c) %s: Content-Type line (len=%d) is not the byte-exact "+
			"contract line (contracts/error-template.md §\"Response "+
			"headers\"); line bytes withheld", code, len(headers[0]))
	}

	// (d) Content-Length parses (ASCII digits only) to the body length
	// actually emitted in this same response.
	if clValue, ok := bytes.CutPrefix(headers[1], []byte("Content-Length: ")); !ok {
		// (b) already flagged the name/order drift; nothing more to
		// compare without a parseable value.
	} else if n, err := parseContentLength(clValue); err != nil {
		t.Errorf("(d) %s: Content-Length value (len=%d) does not parse to a "+
			"non-negative integer: %v — task body (d); value bytes withheld",
			code, len(clValue), err)
	} else if n != len(body) {
		t.Errorf("(d) %s: Content-Length %d != %d body bytes actually "+
			"emitted in the same response — task body (d), framing "+
			"integrity (contracts/error-template.md §\"Response headers\")",
			code, n, len(body))
	}

	// (e) Cache-Control byte-for-byte.
	if !bytes.Equal(headers[2], []byte(wantCacheControlLine)) {
		t.Errorf("(e) %s: Cache-Control line (len=%d) is not the byte-exact "+
			"contract line — the response MUST be no-store so no "+
			"intermediary or client cache retains the failure "+
			"(contracts/error-template.md §\"Response headers\"); line "+
			"bytes withheld", code, len(headers[2]))
	}

	// (f) X-Stargate-Error matches the failure code under test.
	wantXSE := "X-Stargate-Error: " + code
	if !bytes.Equal(headers[3], []byte(wantXSE)) {
		t.Errorf("(f) %s: X-Stargate-Error line (len=%d) does not match the "+
			"failure code under test (want the byte-exact contract line) — "+
			"a DP that misroutes one failure kind to another code's "+
			"response fails here (contracts/error-template.md §\"Response "+
			"headers\"); line bytes withheld", code, len(headers[3]))
	}

	// (g) No forbidden header name anywhere in the captured block.
	// Case-insensitive so a folded-case regression cannot slip the
	// literal scan; the four required headers and the per-code status
	// lines contain none of these substrings, so there is no
	// false-positive surface. Redundant with (a)+(b) by construction —
	// a byte-exact four-line block excludes extras — but gives the
	// precise diagnostic when the drift IS the extra header, and is
	// the tripwire for http.Server-default regressions.
	lowerBlock := strings.ToLower(string(block))
	for _, name := range forbiddenHeaderNames {
		if strings.Contains(lowerBlock, strings.ToLower(name)) {
			t.Errorf("(g) %s: forbidden header name %q appears in the "+
				"captured block — the closed set spans the spec's "+
				"enumerated list plus net/http's default Server/Date/"+
				"Connection/Keep-Alive/Transfer-Encoding, so a regression "+
				"to http.Server defaults trips (contracts/error-template.md "+
				"§\"Response headers\"); block bytes withheld", code, name)
		}
	}

	// (h) Leak-corpus scan over every captured header byte: this run's
	// destination and token plus the fixed §"Leak-corpus invariant"
	// fragments, in all nine textual renderings (loginvariants).
	corpus := make([][]byte, 0, len(headerSetFixedCorpus)+2)
	corpus = append(corpus, []byte(dest), []byte(headerSetPlaintext))
	for _, frag := range headerSetFixedCorpus {
		corpus = append(corpus, []byte(frag))
	}
	loginvariants.AssertNoSecrets(t, string(block), corpus...)
}

// parseContentLength parses a Content-Length value that must be ASCII
// digits only — no sign, no whitespace, no 0x prefix (§Analysis
// redteam scope (d): lenient parsers accept "+5" or " 5"; the wire
// contract permits only the canonical decimal form, and digits-only
// implies the required non-negative integer).
func parseContentLength(v []byte) (int, error) {
	if len(v) == 0 {
		return 0, errors.New("empty value")
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, errors.New("non-digit byte in value (lenient-form rejection)")
		}
	}
	return strconv.Atoi(string(v))
}
