// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the response-header invariants of the privacy-safe
// error template — specs/001-tor-route/spec.md FR-009 + US3
// acceptance-scenario 2 ("they contain exactly Content-Type,
// Content-Length, Cache-Control: no-store, and X-Stargate-Error: <CODE>
// — and no other headers") + contracts/error-template.md §"Response
// headers" ("Exactly these four headers, in this order, no others") +
// §"Contract tests" row header_set_test.go. Task body:
// specs/001-tor-route/tasks.md T068a; the per-code setups mirror
// T065–T067 + T027 per the task body.
//
// For one CONNECT-path failure of EACH of the four codes
// (AUTH_REQUIRED, ROUTE_DOWN, ROUTE_REFUSED, ROUTE_TIMEOUT) the test
// captures the response header block (every byte from the status line
// through the blank line that terminates headers) and asserts: exactly
// four headers; contract order, case-sensitive on the wire; byte-exact
// Content-Type and Cache-Control; Content-Length parsing to the body
// length actually emitted; X-Stargate-Error equal to the code under
// test; no forbidden header name (the spec's enumerated list plus the
// headers Go's net/http server adds by default, so a regression to
// http.Server defaults trips); and a zero-hit leak-corpus scan over
// every captured header byte.
//
// Tests-first (Constitution Principle VII — header handling is a
// privacy-critical category per the constitution discipline table):
// authored BEFORE T048 lands. Content-gates: the dpharness boot
// minimum (T042/T045/T050), listener/connect.go (T043), auth/token.go
// (T044), errortpl/render.go (T048), forward/tor.go (T047). T071
// (route-code rendering) and T072 (failure mapping + the 30 s
// deadline) EXTEND render.go and tor.go — files that already exist
// once T048/T047 land — so the route sub-tests additionally gate on
// content markers (the route-code identifiers those tickets must
// introduce); a plain file-existence gate would lift the skip while
// the route-code surface is still absent and turn the route sub-tests
// red mid-sequence instead of SKIP. All skips self-lift as the
// surfaces land.
package errortemplate

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	integration "github.com/zcat-app/stargate/tests/integration"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

// headerSetPlaintext is the bearer-token plaintext minted into an HMAC
// verifier (dpharness.MintToken) and pushed to the DP via ReloadTokens
// for every sub-test's fixture — the valid credential the three
// route-failure setups authenticate with. 32 hex chars, passing the
// CONNECT path's syntactic gate (contracts/socks5-auth.md §"HTTP
// CONNECT path" step 2). Distinct from T025a/T025b/T026/T027's token
// plaintexts so a corpus-scan hit is attributable to THIS test (the
// T027 precedent).
const headerSetPlaintext = "9c8b7a6d5e4f3021b2a3c4d5e6f70819"

// headerSetReadDeadline bounds one error-response capture on the fast
// sub-tests (auth-fail, dial-refused, REP-0x04 are sub-ms nominal; 30 s
// mirrors T025/T026/T027's generous CI-load deadline).
const headerSetReadDeadline = 30 * time.Second

// headerSetTimeoutReadDeadline bounds the ROUTE_TIMEOUT capture: the DP
// holds the CONNECT for its full 30 s dial-and-handshake deadline
// (contracts/socks5-auth.md §"Deadlines") before answering 504, so the
// capture deadline exceeds that with CI slack while still bounding a DP
// that NEVER times out — it fails at the deadline rather than hanging
// the run (§Analysis redteam scope (e)).
const headerSetTimeoutReadDeadline = 90 * time.Second

// headerSetSlowLatency is the shared fake's first-upstream-write delay
// for the ROUTE_TIMEOUT sub-test. Strictly greater than the DP's 30 s
// dial-and-handshake deadline so the DP deterministically fires
// ROUTE_TIMEOUT first — the delay discipline contracts/socks5-auth.md
// §"Deadlines" pins for slow-mode test setups.
const headerSetSlowLatency = 45 * time.Second

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

// refusingConnDeadline bounds one refused-connection lifetime so a DP
// that connects and then stalls cannot leak handler goroutines past
// the test.
const refusingConnDeadline = 60 * time.Second

// TestHeaderSet pins the response-header invariants of the privacy-safe
// template across one CONNECT-path failure of EACH of the four codes.
// Four sub-tests, one per code, each on its OWN harness — the setups
// need different upstream wiring (none / dead port / REP-0x04 backend /
// slow fake); within a sub-test the eight invariants layer on one
// captured response, mirroring T027's consolidated-body precedent.
func TestHeaderSet(t *testing.T) {
	t.Run("AUTH_REQUIRED", func(t *testing.T) {
		requireAuthPathGates(t)

		// T027's route-independent auth-failure setup: bare Start —
		// no upstream (auth fails before the forward path is
		// consulted; the upstream is never dialed), no HEALTHY
		// (AUTH_REQUIRED is route-independent; the DP's background
		// WatchEvents dial fails harmlessly).
		h := startHeaderSetDP(t)

		const dest = "t068a-auth.example.onion"
		resp := captureResponse(t, h,
			"CONNECT "+dest+":443 HTTP/1.1\r\n\r\n",
			headerSetReadDeadline)
		assertHeaderBlock(t, "AUTH_REQUIRED", dest, resp)
	})

	t.Run("ROUTE_DOWN", func(t *testing.T) {
		requireRoutePathGates(t)

		// Bind-then-release a loopback port: nothing listens, the
		// DP's upstream dial gets TCP RST → ROUTE_DOWN. FR-009: the
		// dial result alone decides; no HEALTHY is pushed (T090 /
		// sol-review B3 precedent — admission and dialing are not
		// CP-gated; T026's WithUpstream wiring).
		dead := dpharness.FreeLoopbackAddr(t)
		h := startHeaderSetDP(t, dpharness.WithUpstream(dead))

		const dest = "t068a-down.example.onion"
		resp := captureResponse(t, h,
			"CONNECT "+dest+":443 HTTP/1.1\r\n"+
				"Proxy-Authorization: Bearer "+headerSetPlaintext+"\r\n\r\n",
			headerSetReadDeadline)
		assertHeaderBlock(t, "ROUTE_DOWN", dest, resp)
	})

	t.Run("ROUTE_REFUSED", func(t *testing.T) {
		requireRoutePathGates(t)

		// Tor-sidecar-up-but-refusing: the package-local backend
		// completes the SOCKS5 handshake then replies REP=0x04 — the
		// wire shape the real sidecar produces for a non-resolvable
		// .onion (T066's setup).
		upstream := startRefusingBackend(t)
		h := startHeaderSetDP(t, dpharness.WithUpstream(upstream))

		const dest = "t068a-refused.example.onion"
		resp := captureResponse(t, h,
			"CONNECT "+dest+":443 HTTP/1.1\r\n"+
				"Proxy-Authorization: Bearer "+headerSetPlaintext+"\r\n\r\n",
			headerSetReadDeadline)
		assertHeaderBlock(t, "ROUTE_REFUSED", dest, resp)
	})

	t.Run("ROUTE_TIMEOUT", func(t *testing.T) {
		requireRoutePathGates(t)

		// The shared fake in Slow mode: the handshake completes, then
		// the first upstream write is delayed past the DP's 30 s
		// dial-and-handshake deadline, so the DP deterministically
		// fires ROUTE_TIMEOUT first (contracts/socks5-auth.md
		// §"Deadlines"; T067's setup).
		upstream := integration.NewServer(integration.Slow,
			integration.WithLatency(headerSetSlowLatency))
		upstreamAddr, err := upstream.Start()
		if err != nil {
			t.Fatalf("starting slow fake upstream: %v", err)
		}
		t.Cleanup(func() { _ = upstream.Close() })
		h := startHeaderSetDP(t, dpharness.WithUpstream(upstreamAddr))

		const dest = "t068a-timeout.example.onion"
		resp := captureResponse(t, h,
			"CONNECT "+dest+":443 HTTP/1.1\r\n"+
				"Proxy-Authorization: Bearer "+headerSetPlaintext+"\r\n\r\n",
			headerSetTimeoutReadDeadline)
		assertHeaderBlock(t, "ROUTE_TIMEOUT", dest, resp)
	})
}

// requireAuthPathGates content-gates a sub-test on the CONNECT + auth +
// renderer surfaces (the boot minimum is inside dpharness.Start).
func requireAuthPathGates(t *testing.T) {
	t.Helper()
	repoRoot := dpharness.FindRepoRoot(t)
	for _, gate := range [...]struct{ rel, ticket string }{
		{"data-plane/internal/listener/connect.go", "T043"},
		{"data-plane/internal/auth/token.go", "T044"},
		{"data-plane/internal/errortpl/render.go", "T048"},
	} {
		dpharness.RequireFile(t, filepath.Join(repoRoot, gate.rel),
			gate.rel+" not implemented yet ("+gate.ticket+"); this skip "+
				"self-lifts when "+gate.ticket+" lands")
	}
}

// requireRoutePathGates additionally gates the route sub-tests on the
// forward surface and on the T071/T072 extensions of files that already
// exist once T048/T047 land.
func requireRoutePathGates(t *testing.T) {
	t.Helper()
	requireAuthPathGates(t)
	repoRoot := dpharness.FindRepoRoot(t)
	dpharness.RequireFile(t, filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go"),
		"forward/tor.go not implemented yet (T047); this skip self-lifts when T047 lands")
	requireImplMarker(t, filepath.Join(repoRoot, "data-plane", "internal", "errortpl", "render.go"),
		"ROUTE_DOWN", "T071", "errortpl/render.go does not render the route codes yet")
	requireImplMarker(t, filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go"),
		"ROUTE_REFUSED", "T072", "forward/tor.go does not map upstream failures to the route codes yet")
}

// requireImplMarker content-gates a sub-test on an implementation file
// not merely existing but containing a marker string. T071 (route-code
// rendering) and T072 (upstream-failure mapping + the 30 s constant)
// EXTEND render.go and forward/tor.go — files that already exist once
// T048/T047 land — so plain RequireFile would lift the skip while the
// route-code surface is still absent, turning the route sub-tests red
// in the window between T048 and T071/T072 instead of SKIP. The
// markers are the route-code identifiers those tickets must introduce;
// the skip self-lifts when they land.
func requireImplMarker(t *testing.T, path, marker, ticket, why string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("blocked: %s absent — %s; this skip self-lifts when the file lands", path, why)
	}
	if !bytes.Contains(b, []byte(marker)) {
		t.Skipf("blocked: %s does not reference %q yet — %s (%s); this skip "+
			"self-lifts when %s lands", filepath.Base(path), marker, why, ticket, ticket)
	}
}

// startHeaderSetDP boots one harness and pushes token generation 1 —
// the shared fixture step. The route sub-tests authenticate with the
// valid token; the AUTH_REQUIRED sub-test rejects a MISSING offer
// against the populated generation (the realistic case, T027's
// rationale).
func startHeaderSetDP(t *testing.T, opts ...dpharness.Option) *dpharness.Harness {
	t.Helper()
	h := dpharness.Start(t, opts...)
	reloadResp := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenVerifier{dpharness.MintToken(t, headerSetPlaintext)})
	if reloadResp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want "+
			"APPLY_STATUS_OK — fixture precondition failed (without a "+
			"populated generation the route sub-tests cannot authenticate "+
			"and the AUTH_REQUIRED sub-test cannot reject against a "+
			"realistic state)", reloadResp.GetStatus())
	}
	return h
}

// captureResponse dials the DP, sends one CONNECT request, and reads
// the full response until EOF (the DP closes after the error response
// per contracts/error-template.md; a wedged DP that writes the
// response but never closes fails at the deadline rather than hanging
// the run — T027's wedged-DP handling). Response bytes are WITHHELD
// from failure messages: a buggy DP may have echoed the destination or
// the token into the response, and those bytes are scanned separately
// by the corpus check.
func captureResponse(t *testing.T, h *dpharness.Harness, req string, readDeadline time.Duration) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", h.ProxyAddr, err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(readDeadline)); err != nil {
		t.Fatalf("setting capture deadline: %v", err)
	}
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT request: %v — the DP closed or errored "+
			"before reading the request (assertion setup failed; the error "+
			"response was never produced)", err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatalf("DP did not close within %s of the CONNECT request — "+
				"contracts/error-template.md requires close after the error "+
				"response; possible wedged DP (read returned partial "+
				"response of %d bytes, withheld)", readDeadline, len(resp))
		}
		t.Fatalf("reading error response (got %d bytes before error, "+
			"withheld): %v", len(resp), err)
	}
	return resp
}

// splitHeaderBlock splits resp at the FIRST \r\n\r\n: the header block
// (status line through the terminating blank line — the bytes the
// task-body invariants govern) and the body. The first terminator is
// the header/body boundary by construction; the body itself is
// LF-ended (contracts/error-template.md §"Response body"), so a later
// \r\n\r\n could only exist in a non-conforming body — splitting on
// the first keeps the capture honest either way.
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

// startRefusingBackend starts a package-local synthetic SOCKS5 upstream
// that completes the SOCKS5 handshake (mirroring the shared fake's
// method-selection + RFC 1929 sub-negotiation surface, so the DP's
// UNAME pass-through meets the real sidecar's accept shape) and then
// replies REP=0x04 (host unreachable) to the CONNECT request — the wire
// shape the real Tor sidecar produces for a non-resolvable .onion
// (T066's setup; contracts/socks5-auth.md §"SOCKS5 request-phase
// failures (post-auth)": ROUTE_REFUSED ↔ 0x04). T019a's shared fake has
// no refusing mode, and a file-local backend keeps this ticket to its
// single named artifact; if the socks5-package tests (T067a/T067b) need
// the same surface, promoting a Refuse mode into the shared fake is the
// follow-up (§Out-of-scope). Returns the dialable address.
func startRefusingBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("refusing backend listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed via Cleanup
			}
			go serveRefused(conn)
		}
	}()
	return ln.Addr().String()
}

// serveRefused walks one connection through method selection, the
// RFC 1929 sub-negotiation (when the DP offers method 0x02 — it passes
// the bearer token through as UNAME per T047), and the CONNECT request,
// then answers REP=0x04 with BND.ADDR/BND.PORT zeroed.
func serveRefused(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(refusingConnDeadline))
	br := bufio.NewReader(conn)

	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil || header[0] != 0x05 || header[1] == 0 {
		return // client misbehaved; close
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	selected := byte(0x00)
	for _, m := range methods {
		if m == 0x02 {
			selected = 0x02
			break
		}
	}
	if _, err := conn.Write([]byte{0x05, selected}); err != nil {
		return
	}
	if selected == 0x02 {
		// RFC 1929 sub-negotiation: peek 0x01 then read VER ULEN UNAME
		// PLEN PASSWD; reply success without validating (the shared
		// fake's surface — bearer auth is the DP's inbound job, not the
		// upstream's).
		if _, err := br.Peek(1); err != nil {
			return
		}
		sub := make([]byte, 2) // VER ULEN
		if _, err := io.ReadFull(br, sub); err != nil {
			return
		}
		if _, err := io.ReadFull(br, make([]byte, int(sub[1]))); err != nil { // UNAME
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(br, plen); err != nil {
			return
		}
		if _, err := io.ReadFull(br, make([]byte, int(plen[0]))); err != nil { // PASSWD
			return
		}
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}

	// CONNECT request: VER CMD RSV ATYP + address payload; consume it so
	// the 0x04 reply follows the full request (the real sidecar's order).
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[0] != 0x05 || req[1] != 0x01 {
		return
	}
	switch req[3] {
	case 0x01: // IPv4 + port
		if _, err := io.ReadFull(br, make([]byte, 6)); err != nil {
			return
		}
	case 0x03: // DOMAIN + port
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		if _, err := io.ReadFull(br, make([]byte, int(l[0])+2)); err != nil {
			return
		}
	case 0x04: // IPv6 + port
		if _, err := io.ReadFull(br, make([]byte, 18)); err != nil {
			return
		}
	default:
		return
	}

	// REP=0x04 (host unreachable) — ROUTE_REFUSED's upstream trigger.
	_, _ = conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}
