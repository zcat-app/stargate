// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the port-8881 inbound HTTP CONNECT framing (T043),
// driven through the exported HandleConn surface over net.Pipe with
// stub seams (Verifier / Tunneler / Audit / ErrorRenderer).
//
// Why this exists alongside the contract suites (T026 success, T027
// 407, T065 502): those suites boot the whole data-plane process and
// content-gate on T043+T044+T045+T047+T048+T050 landing together, so
// they stay SKIP — and gate nothing — until the set is complete. These
// in-package tests pin the byte contract NOW, at T043's own review
// (residue promotion per the ticket §Analysis). The contract suites
// remain the end-to-end gates and self-lift when the set lands.
//
// Byte-level contract: specs/001-tor-route/contracts/socks5-auth.md
// §"HTTP CONNECT path" and specs/001-tor-route/contracts/error-template.md
// §"Wire format".
package listener

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- CONNECT stub seams -----------------------------------------------

// stubTunnel is the Tunneler stub: Dial records its target, Pipe reads
// at most one client byte (bounded — a client that withholds it must
// not wedge the stub), echoes it back (the round-trip vehicle for the
// anti-over-read assertion), and closes the upstream per the seam's
// ownership contract.
type stubTunnel struct {
	dialErr error
	pipeErr error

	mu       sync.Mutex
	n        int
	target   string
	called   chan struct{}
	upstream net.Conn // server end of the Dial pipe
	piped    bool
	closed   bool          // upstream was closed by Pipe (ownership contract)
	pipedCh  chan struct{} // closed when Pipe is entered
}

func (s *stubTunnel) Dial(target string) (net.Conn, error) {
	s.mu.Lock()
	s.n++
	s.target = target
	s.mu.Unlock()
	select {
	case <-s.called:
	default:
		close(s.called)
	}
	if s.dialErr != nil {
		return nil, s.dialErr
	}
	c1, c2 := net.Pipe()
	s.mu.Lock()
	s.upstream = c2
	s.mu.Unlock()
	return c1, nil
}

func (s *stubTunnel) Pipe(client, upstream net.Conn) error {
	s.mu.Lock()
	s.piped = true
	s.mu.Unlock()
	select {
	case <-s.pipedCh:
	default:
		close(s.pipedCh)
	}
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	n, err := client.Read(buf)
	if err == nil && n == 1 {
		_, _ = client.Write(buf) // echo: proves the byte reached the pipe
	}
	_ = upstream.Close()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return s.pipeErr
}

func (s *stubTunnel) state() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n, s.target
}

func (s *stubTunnel) upstreamClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *stubTunnel) pipeEntered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.piped
}

// stubRenderer is the ErrorRenderer stub: it records every code it is
// asked to render and writes a fixed marker payload, so tests can pin
// both WHICH code was rendered and the exact bytes that reached the wire.
type stubRenderer struct {
	mu    sync.Mutex
	codes []ErrorCode
}

func (r *stubRenderer) WriteFailure(w io.Writer, code ErrorCode) error {
	r.mu.Lock()
	r.codes = append(r.codes, code)
	r.mu.Unlock()
	_, err := w.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
	return err
}

func (r *stubRenderer) rendered() []ErrorCode {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ErrorCode(nil), r.codes...)
}

// --- CONNECT harness ---------------------------------------------------

// cfixture bundles one net.Pipe pair with HandleConn serving the server
// end, Deps.Connect wired to HandleConnect over the stubs, and every
// seam handle the tests assert on.
type cfixture struct {
	client   net.Conn
	server   *deadlineRecorder
	auth     *stubAuth
	audit    *stubAudit
	tunnel   *stubTunnel
	renderer *stubRenderer
	done     chan struct{}
}

// startConnectFixture serves one connection whose first byte is NOT
// consumed — tests write the leading 'C' like any real client would.
func startConnectFixture(t *testing.T, authAccept bool, tunnel *stubTunnel, renderer *stubRenderer) *cfixture {
	t.Helper()
	c, s := net.Pipe()
	// Bounded client writes: net.Pipe writes block until consumed, so a
	// test whose server stops reading (oversized headers) fails fast
	// here instead of hanging on the write.
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	f := &cfixture{
		client:   c,
		server:   &deadlineRecorder{Conn: s},
		auth:     &stubAuth{accept: authAccept},
		audit:    &stubAudit{},
		tunnel:   tunnel,
		renderer: renderer,
		done:     make(chan struct{}),
	}
	if f.tunnel.called == nil {
		f.tunnel.called = make(chan struct{})
	}
	if f.tunnel.pipedCh == nil {
		f.tunnel.pipedCh = make(chan struct{})
	}
	d := &Deps{
		Auth:  f.auth,
		Audit: f.audit,
		Connect: func(conn net.Conn) {
			HandleConnect(conn, &ConnectDeps{
				Auth:     f.auth,
				Tunnel:   f.tunnel,
				Audit:    f.audit,
				Renderer: f.renderer,
			})
		},
	}
	go func() {
		HandleConn(f.server, d)
		close(f.done)
	}()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return f
}

// awaitTunnel blocks until the Dial seam has been invoked at least once.
func awaitTunnel(t *testing.T, f *cfixture) {
	t.Helper()
	select {
	case <-f.tunnel.called:
	case <-time.After(2 * time.Second):
		t.Fatalf("tunnel Dial seam never invoked")
	}
}

// awaitPipe blocks until the Pipe seam has been ENTERED — the
// happens-before anchor for asserting the deadline was already cleared
// (the handler must zero it before handing off to the byte pipe).
func awaitPipe(t *testing.T, f *cfixture) {
	t.Helper()
	select {
	case <-f.tunnel.pipedCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("tunnel Pipe seam never invoked")
	}
}

// connectReq builds a CONNECT request: target, the Proxy-Authorization
// header ("" to omit), then any extra raw header lines. The request line
// starts at "ONNECT" — sendConnect writes the demux 'C' separately, so
// the leading 'C' must NOT appear here (mirroring what the handler sees
// after demux).
func connectReq(target, authHeader string, extra ...string) []byte {
	lines := []string{"ONNECT " + target + " HTTP/1.1"}
	if authHeader != "" {
		lines = append(lines, authHeader)
	}
	lines = append(lines, extra...)
	lines = append(lines, "", "")
	return []byte(strings.Join(lines, "\r\n"))
}

// sendConnect writes the demux 'C' plus the request body.
func sendConnect(t *testing.T, conn net.Conn, req []byte) {
	t.Helper()
	write(t, conn, 'C')
	write(t, conn, req...)
}

// readUntilEOF reads everything the server sends with a bounded
// deadline — the assertion vehicle for renderer-output-only responses.
func readUntilEOF(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var got []byte
	buf := make([]byte, 128)
	for {
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return got
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatalf("peer did not close: got %d byte(s) then timeout", len(got))
			}
			t.Fatalf("read: %v", err)
		}
	}
}

// awaitConnectDone asserts HandleConn returned within 2s of the test's
// final action — every close path must terminate the handler (the
// socks5_test.go awaitDone twin, typed to this file's fixture).
func awaitConnectDone(t *testing.T, f *cfixture, what string) {
	t.Helper()
	select {
	case <-f.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("HandleConn did not return after %s (goroutine stuck)", what)
	}
}

// expectRendered asserts the only bytes on the wire are the stub
// renderer's marker for exactly one render of want, then close.
func expectRendered(t *testing.T, f *cfixture, what string, want ErrorCode) {
	t.Helper()
	got := readUntilEOF(t, f.client)
	if string(got) != "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n" {
		t.Fatalf("%s: unexpected response bytes (%q)", what, got)
	}
	if codes := f.renderer.rendered(); len(codes) != 1 || codes[0] != want {
		t.Fatalf("%s: renderer codes = %v, want [%s]", what, codes, want)
	}
	awaitConnectDone(t, f, what)
}

// expectRenderer407 is the AUTH_REQUIRED-shaped specialisation.
func expectRenderer407(t *testing.T, f *cfixture, what string) {
	t.Helper()
	expectRendered(t, f, what, CodeAuthRequired)
}

// t043Token is this test file's canonical valid bearer token
// (32 lowercase hex per ^[0-9a-f]{32}$).
const t043Token = "0123456789abcdef0123456789abcdef"

// --- success path -------------------------------------------------------

func TestConnect_Success_Exact200_VerbatimTarget(t *testing.T) {
	f := startConnectFixture(t, true, &stubTunnel{called: make(chan struct{})}, &stubRenderer{})
	sendConnect(t, f.client, connectReq("t043.example.onion:443",
		"Proxy-Authorization: Bearer "+t043Token,
		"User-Agent: probe", "X-Stargate-Probe: ignored"))
	readExact(t, f.client, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")...)
	awaitTunnel(t, f)
	awaitPipe(t, f)
	n, target := f.tunnel.state()
	if n != 1 || target != "t043.example.onion:443" {
		t.Fatalf("Dial invoked %d time(s) with target %q, want 1× verbatim target", n, target)
	}
	// Byte-pipe phase must be deadline-free: the zero SetDeadline is
	// recorded before the handoff (contracts/socks5-auth.md §"Deadlines").
	// awaitPipe gives the happens-before edge: the handler zeroes the
	// deadline BEFORE entering Pipe.
	if f.server.zeroed() == 0 {
		t.Fatalf("no zero-deadline call before the pipe handoff — "+
			"post-handshake idle deadline forbidden; deadline calls: %d", f.server.total())
	}
	// FR-008: the count fires once per auth-passed request, before the
	// status line; route outcome irrelevant.
	if n := f.audit.count(); n != 1 {
		t.Fatalf("audit fired %d time(s) after auth pass, want 1", n)
	}
	// The auth seam saw the raw token bytes (post format gate).
	if got := f.auth.candidate(0); string(got) != t043Token {
		t.Fatalf("auth seam received %q, want the raw token", got)
	}
	// Renderer must never fire on the success path.
	if codes := f.renderer.rendered(); len(codes) != 0 {
		t.Fatalf("renderer fired on success path: %v", codes)
	}
	_ = f.client.Close()
	awaitConnectDone(t, f, "success")
}

// TestConnect_EarlyTunnelBytesNotSwallowed pins the anti-over-read
// property: the parser stops reading at the header-terminating blank
// line, so bytes the client sent in the same write belong to the
// tunnel (a buffered reader would swallow them — T026 redteam (a)'s
// DP-side twin).
func TestConnect_EarlyTunnelBytesNotSwallowed(t *testing.T) {
	f := startConnectFixture(t, true, &stubTunnel{called: make(chan struct{})}, &stubRenderer{})
	// ONE write: full request + the first tunnel byte. The write runs
	// in a background goroutine because net.Pipe is unbuffered: the
	// server answers the 200 after consuming the header block but
	// before reading the sentinel, so the test goroutine must be free
	// to read (the fixture's write deadline bounds the goroutine).
	blob := append(connectReq("t043.example.onion:443",
		"Proxy-Authorization: Bearer "+t043Token), 'Z')
	write(t, f.client, 'C')
	go func() { _, _ = f.client.Write(blob) }()
	readExact(t, f.client, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")...)
	// The stub Pipe echoes exactly one client byte: it must be the
	// sentinel, not a leftover header byte.
	_ = f.client.SetReadDeadline(time.Now().Add(2 * time.Second))
	var got [1]byte
	if _, err := io.ReadFull(f.client, got[:]); err != nil {
		t.Fatalf("read sentinel: %v", err)
	}
	if got[0] != 'Z' {
		t.Fatalf("pipe received %q, want the sentinel 'Z' — the parser over-read", got)
	}
	awaitConnectDone(t, f, "early tunnel bytes")
}

func TestConnect_HeaderNameCaseInsensitive(t *testing.T) {
	f := startConnectFixture(t, true, &stubTunnel{called: make(chan struct{})}, &stubRenderer{})
	// HTTP header names are case-insensitive; the value is untouched.
	sendConnect(t, f.client, connectReq("t043.example.onion:443",
		"proxy-AUTHORIZATION: Bearer "+t043Token))
	readExact(t, f.client, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")...)
	awaitTunnel(t, f)
	_ = f.client.Close()
	awaitConnectDone(t, f, "case-insensitive header name")
}

// --- auth failures -------------------------------------------------------

func TestConnect_AuthMissing_407_NoAuthNoCounter(t *testing.T) {
	f := startConnectFixture(t, true, &stubTunnel{called: make(chan struct{})}, &stubRenderer{})
	sendConnect(t, f.client, connectReq("t043.example.onion:443", ""))
	expectRenderer407(t, f, "missing Proxy-Authorization")
	if n := f.auth.count(); n != 0 {
		t.Fatalf("auth seam consulted %d time(s) with no header, want 0", n)
	}
	if n := f.audit.count(); n != 0 {
		t.Fatalf("audit fired %d time(s) on auth failure, want 0 (FR-008)", n)
	}
	if n, _ := f.tunnel.state(); n != 0 {
		t.Fatalf("Dial invoked on auth failure, want 0 invocations")
	}
}

// TestConnect_AuthMalformed_407_Indistinguishable pins the format gate:
// every malformed candidate — wrong length, non-hex, uppercase hex, a
// non-Bearer or wrong-cased scheme — gets the IDENTICAL response with
// the auth seam never consulted (the gate precedes hashing; no
// distinguishing substring, contracts/socks5-auth.md §"HTTP CONNECT
// path" invariant row 2).
func TestConnect_AuthMalformed_407_Indistinguishable(t *testing.T) {
	cases := []struct{ name, header string }{
		{"NotAToken", "Proxy-Authorization: Bearer notatoken"},
		{"Short31", "Proxy-Authorization: Bearer 0123456789abcdef0123456789abcde"},
		{"Long33", "Proxy-Authorization: Bearer 0123456789abcdef0123456789abcdef0"},
		{"UppercaseHex", "Proxy-Authorization: Bearer 0123456789ABCDEF0123456789ABCDEF"},
		{"LowercaseScheme", "Proxy-Authorization: bearer " + t043Token},
		{"BasicScheme", "Proxy-Authorization: Basic " + t043Token},
		{"NoScheme", "Proxy-Authorization: " + t043Token},
		{"EmptyValue", "Proxy-Authorization:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startConnectFixture(t, true, &stubTunnel{called: make(chan struct{})}, &stubRenderer{})
			sendConnect(t, f.client, connectReq("t043.example.onion:443", tc.header))
			expectRenderer407(t, f, tc.name)
			if n := f.auth.count(); n != 0 {
				t.Fatalf("auth seam consulted %d time(s) on a format-gate failure, want 0", n)
			}
			if n := f.audit.count(); n != 0 {
				t.Fatalf("audit fired %d time(s), want 0", n)
			}
		})
	}
}

func TestConnect_AuthVerifyFail_407_NoCounter(t *testing.T) {
	// Format-valid token, but the verifier rejects it.
	f := startConnectFixture(t, false, &stubTunnel{called: make(chan struct{})}, &stubRenderer{})
	sendConnect(t, f.client, connectReq("t043.example.onion:443",
		"Proxy-Authorization: Bearer "+t043Token))
	expectRenderer407(t, f, "verifier rejection")
	if n := f.auth.count(); n != 1 {
		t.Fatalf("auth seam consulted %d time(s), want 1", n)
	}
	if n := f.audit.count(); n != 0 {
		t.Fatalf("audit fired %d time(s) on auth FAILURE, want 0 — "+
			"counting auth failures side-channels token guessing (FR-008)", n)
	}
	if n, _ := f.tunnel.state(); n != 0 {
		t.Fatalf("Dial invoked on auth failure, want 0 invocations")
	}
}

func TestConnect_LookalikeHeader_407(t *testing.T) {
	// Only the exact header name authenticates; prefix/suffix lookalikes
	// must be skipped like any other header.
	f := startConnectFixture(t, true, &stubTunnel{called: make(chan struct{})}, &stubRenderer{})
	sendConnect(t, f.client, connectReq("t043.example.onion:443", "",
		"X-Proxy-Authorization: Bearer "+t043Token,
		"Proxy-Authorization-X: Bearer "+t043Token))
	expectRenderer407(t, f, "lookalike headers")
	if n := f.auth.count(); n != 0 {
		t.Fatalf("auth seam consulted %d time(s) on lookalike headers, want 0", n)
	}
}

// --- framing garbage ------------------------------------------------------

// TestConnect_FramingGarbage_SilentClose pins the zero-byte silent
// close for every request-line framing violation: the contract defines
// no 400-class response, and auth must never be consulted on a framing
// close (mirrors the SOCKS5 path's post-auth framing row).
func TestConnect_FramingGarbage_SilentClose(t *testing.T) {
	cases := []struct{ name, line string }{
		{"WrongVersion", "ONNECT t043.example.onion:443 HTTP/1.0"},
		{"MissingAuthority", "ONNECT  HTTP/1.1"},
		{"NonDigitPort", "ONNECT t043.example.onion:none HTTP/1.1"},
		{"EmptyPort", "ONNECT t043.example.onion: HTTP/1.1"},
		{"SixDigitPort", "ONNECT t043.example.onion:443443 HTTP/1.1"},
		{"LowercaseMethod", "onnect t043.example.onion:443 HTTP/1.1"},
		{"WrongMethod", "JUNK t043.example.onion:443 HTTP/1.1"},
		{"BareLF", "ONNECT t043.example.onion:443 HTTP/1.1\n"},
		{"ImmediateBlank", ""},
		{"ExtraToken", "ONNECT t043.example.onion:443 extra HTTP/1.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startConnectFixture(t, true, &stubTunnel{called: make(chan struct{})}, &stubRenderer{})
			write(t, f.client, 'C')
			write(t, f.client, []byte(tc.line)...)
			// The server legitimately stops reading the moment the
			// malformed line ends (silent close), so these trailing
			// terminator bytes may fail to write — ignored on purpose.
			_, _ = f.client.Write([]byte{'\r', '\n', '\r', '\n'})
			expectEOFWithNoData(t, f.client, tc.name)
			awaitConnectDone(t, f, tc.name)
			if n := f.auth.count(); n != 0 {
				t.Fatalf("auth seam consulted %d time(s) on framing garbage, want 0", n)
			}
			if n := f.audit.count(); n != 0 {
				t.Fatalf("audit fired %d time(s) on framing garbage, want 0", n)
			}
			if codes := f.renderer.rendered(); len(codes) != 0 {
				t.Fatalf("renderer fired on framing garbage: %v", codes)
			}
		})
	}
}

// TestConnect_OversizedHeaders_SilentClose pins the header-block budget:
// a client streaming past the named bound gets a silent close, never an
// unbounded buffer (edge-input validation; the oversized line sits
// INSIDE the header block — before the blank line — or it would be
// tunnel bytes, not headers). The write helper is not used because the
// server stops reading mid-line and the pending pipe write errors.
func TestConnect_OversizedHeaders_SilentClose(t *testing.T) {
	f := startConnectFixture(t, true, &stubTunnel{called: make(chan struct{})}, &stubRenderer{})
	write(t, f.client, 'C')
	req := connectReq("t043.example.onion:443",
		"Proxy-Authorization: Bearer "+t043Token,
		"X-Pad: "+strings.Repeat("A", 2*8192))
	_, _ = f.client.Write(req) // fixture write deadline bounds this; close unblocks
	expectEOFWithNoData(t, f.client, "oversized headers")
	awaitConnectDone(t, f, "oversized headers")
	if codes := f.renderer.rendered(); len(codes) != 0 {
		t.Fatalf("renderer fired on oversized headers: %v", codes)
	}
	if n := f.auth.count(); n != 0 {
		t.Fatalf("auth seam consulted %d time(s) on oversized headers, want 0", n)
	}
}

// --- route failures -------------------------------------------------------

func TestConnect_RouteError_Template(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want ErrorCode
	}{
		{"RouteDown", &routeErr{rep: 0x03}, CodeRouteDown},
		{"RouteRefused", &routeErr{rep: 0x04}, CodeRouteRefused},
		{"RouteTimeout", &routeErr{rep: 0x06}, CodeRouteTimeout},
		{"UnclassifiedFallsBackToDown", errors.New("boom"), CodeRouteDown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startConnectFixture(t, true, &stubTunnel{dialErr: tc.err, called: make(chan struct{})}, &stubRenderer{})
			sendConnect(t, f.client, connectReq("t043.example.onion:443",
				"Proxy-Authorization: Bearer "+t043Token))
			awaitTunnel(t, f)
			// The template is the FIRST and ONLY thing on the wire — no
			// 200 bytes precede it (the status line is written only after
			// the upstream handshake result is known).
			expectRendered(t, f, tc.name, tc.want)
			if n := f.audit.count(); n != 1 {
				t.Fatalf("audit fired %d time(s) on auth-passed route failure, want 1 (FR-008)", n)
			}
		})
	}
}

// TestConnect_PipeError_NoInjectedBytes pins the established-tunnel
// rule: a Pipe failure closes the connection without injecting any
// byte into it.
func TestConnect_PipeError_NoInjectedBytes(t *testing.T) {
	f := startConnectFixture(t, true, &stubTunnel{pipeErr: errors.New("upstream dropped"), called: make(chan struct{})}, &stubRenderer{})
	sendConnect(t, f.client, connectReq("t043.example.onion:443",
		"Proxy-Authorization: Bearer "+t043Token))
	readExact(t, f.client, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")...)
	awaitTunnel(t, f)
	// The stub Pipe's bounded read finds no client byte (the test
	// withholds one), closes the upstream, and returns its error — the
	// client must see EOF with zero additional bytes.
	expectEOFWithNoData(t, f.client, "pipe error")
	awaitConnectDone(t, f, "pipe error")
	if !f.tunnel.pipeEntered() || !f.tunnel.upstreamClosed() {
		t.Fatalf("Pipe not entered (%v) or upstream not closed (%v) — seam contract breach",
			f.tunnel.pipeEntered(), f.tunnel.upstreamClosed())
	}
}
