// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the port-8881 inbound SOCKS5 framing (T042), driven
// through the exported HandleConn surface over net.Pipe with stub
// seams (Auth / Forward / Audit / Connect).
//
// Why this exists alongside the contract suites (T023/T024/T025/T028):
// those suites boot the whole data-plane process and content-gate on
// T042+T045+T050 landing together, so they stay SKIP — and gate
// nothing — until the trio is complete. These in-package tests pin the
// byte contract NOW, at T042's own review, without any of the
// downstream tickets (residue promotion per the ticket §Analysis). The
// contract suites remain the end-to-end gates and self-lift when
// T044/T045/T050 land.
//
// Byte-level contract: specs/001-tor-route/contracts/socks5-auth.md
// §"Two inbound protocols, one port", §"Auth method negotiation",
// §"Username/password sub-negotiation", §"SOCKS5 request-phase
// failures (post-auth)".
package listener

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// --- stub seams -------------------------------------------------------

// stubAuth records every candidate it is offered (so tests can assert
// the raw PASSWD reached the seam unmodified) and returns its fixed
// verdict.
type stubAuth struct {
	accept   bool
	mu       sync.Mutex
	cands    [][]byte
	verifies int
}

func (s *stubAuth) VerifyPassword(candidate []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifies++
	s.cands = append(s.cands, append([]byte(nil), candidate...))
	return s.accept
}

func (s *stubAuth) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.verifies }

func (s *stubAuth) candidate(i int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cands[i]
}

// stubForward records the UNAME/target it is handed. err is what the
// call returns. It never touches the client conn — the ownership
// contract on Forwarder reserves closing for the listener.
type stubForward struct {
	err    error
	called chan struct{} // closed on the first invocation
	mu     sync.Mutex
	n      int
	uname  []byte
	target string
}

func (s *stubForward) Forward(_ net.Conn, uname []byte, target string) error {
	s.mu.Lock()
	s.n++
	s.uname = append([]byte(nil), uname...)
	s.target = target
	s.mu.Unlock()
	select {
	case <-s.called:
	default:
		close(s.called)
	}
	return s.err
}

// awaitForward blocks until the seam has been invoked at least once —
// net.Pipe consumption can complete slightly before the server's
// post-read bookkeeping runs, so callers must synchronize on the event,
// not on their own write returning.
func awaitForward(t *testing.T, f *fixture) {
	t.Helper()
	select {
	case <-f.forward.called:
	case <-time.After(2 * time.Second):
		t.Fatalf("forward seam never invoked")
	}
}

func (s *stubForward) state() (int, []byte, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n, s.uname, s.target
}

// stubAudit counts AuthPassedRequest calls.
type stubAudit struct {
	mu sync.Mutex
	n  int
}

func (a *stubAudit) AuthPassedRequest() { a.mu.Lock(); a.n++; a.mu.Unlock() }

func (a *stubAudit) count() int { a.mu.Lock(); defer a.mu.Unlock(); return a.n }

// deadlineRecorder wraps the server-side conn and records every
// SetDeadline argument, so tests can assert the handshake deadline is
// armed at entry and cleared (zero) before the byte-pipe handoff
// (contracts/socks5-auth.md §"Deadlines" — no idle deadline after the
// handshake; T025b).
type deadlineRecorder struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (r *deadlineRecorder) SetDeadline(t time.Time) error {
	r.mu.Lock()
	r.deadlines = append(r.deadlines, t)
	r.mu.Unlock()
	return r.Conn.SetDeadline(t)
}

// zeroedBefore reports how many zero-deadline calls were recorded at
// the moment of the call — the Forward stub uses it to prove the
// deadline was already cleared when the handoff happened.
func (r *deadlineRecorder) zeroed() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, t := range r.deadlines {
		if t.IsZero() {
			n++
		}
	}
	return n
}

func (r *deadlineRecorder) total() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.deadlines) }

// --- harness ----------------------------------------------------------

// fixture bundles one net.Pipe pair with HandleConn already serving the
// server end (in a goroutine) and every stub seam.
type fixture struct {
	client    net.Conn
	server    *deadlineRecorder
	auth      *stubAuth
	forward   *stubForward
	audit     *stubAudit
	connects  []net.Conn    // conns the Connect seam received
	connected chan struct{} // closed when the Connect seam first fires
	done      chan struct{}
}

// startFixture serves one connection. The first byte is NOT consumed —
// tests write it like any real client would.
func startFixture(t *testing.T, fwdErr error, authAccept bool) *fixture {
	t.Helper()
	c, s := net.Pipe()
	// Bounded client writes: net.Pipe writes block until the server
	// consumes them, so a test whose server legitimately replies before
	// consuming a full client message (unknown-ATYP) would otherwise
	// hang on the write instead of failing fast here.
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	f := &fixture{
		client:    c,
		server:    &deadlineRecorder{Conn: s},
		auth:      &stubAuth{accept: authAccept},
		forward:   &stubForward{err: fwdErr, called: make(chan struct{})},
		audit:     &stubAudit{},
		connected: make(chan struct{}),
		done:      make(chan struct{}),
	}
	d := &Deps{
		Auth:    f.auth,
		Forward: f.forward,
		Audit:   f.audit,
		Connect: func(conn net.Conn) {
			f.connects = append(f.connects, conn)
			select {
			case <-f.connected:
			default:
				close(f.connected)
			}
			// Hold the conn like the real CONNECT handler (T043) does —
			// the handler owns the connection from the seam onward, so a
			// no-op stub would close it and false-positive the held-open
			// assertion. Blocked read releases at test cleanup's Close.
			buf := make([]byte, 16)
			for {
				if _, err := conn.Read(buf); err != nil {
					return
				}
			}
		},
	}
	go func() {
		HandleConn(f.server, d)
		close(f.done)
	}()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return f
}

// awaitDone asserts HandleConn returned within 2s of the test's final
// action — every close path must terminate the handler (no stuck
// goroutine per abandoned connection).
func awaitDone(t *testing.T, f *fixture, what string) {
	t.Helper()
	select {
	case <-f.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("HandleConn did not return after %s (goroutine stuck)", what)
	}
}

// write sends bytes or fails the test.
func write(t *testing.T, conn net.Conn, b ...byte) {
	t.Helper()
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write %x: %v", b, err)
	}
}

// readExact reads exactly len(want) bytes and compares.
func readExact(t *testing.T, conn net.Conn, want ...byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read %d bytes: %v (want %x)", len(want), err, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reply = %x, want %x", got, want)
		}
	}
}

// expectEOFWithNoData asserts the peer closed: EOF with zero preceding
// bytes — the silent-close and every reply-then-close path's tail.
func expectEOFWithNoData(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if n != 0 {
		t.Fatalf("%s: got %d trailing byte(s) (% x) before close", what, n, buf[:n])
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("%s: read err = %v, want EOF (peer did not close)", what, err)
	}
}

// expectHeldOpen asserts the server is silent and connected — the
// contracted state after `05 02` and `01 00` (waiting for more client
// input, no trailing bytes, no close).
func expectHeldOpen(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if n > 0 {
		t.Fatalf("%s: server wrote %d trailing byte(s) (% x)", what, n, buf[:n])
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("%s: server closed the connection (err=%v) — contract requires held-open", what, err)
	}
}

// greet performs the client half of method negotiation (single method:
// USERNAME/PASSWORD) and asserts the `05 02` reply.
func greet(t *testing.T, conn net.Conn) {
	t.Helper()
	write(t, conn, 0x05, 0x01, 0x02)
	readExact(t, conn, 0x05, 0x02)
}

// subneg performs the RFC 1929 sub-negotiation with raw byte fields and
// asserts the wanted 2-byte reply.
func subneg(t *testing.T, conn net.Conn, uname, passwd []byte, want ...byte) {
	t.Helper()
	write(t, conn, 0x01, byte(len(uname)))
	write(t, conn, uname...)
	write(t, conn, byte(len(passwd)))
	write(t, conn, passwd...)
	readExact(t, conn, want...)
}

// requestConnect sends a SOCKS5 CONNECT for an ATYP=0x03 domain target.
func requestConnect(t *testing.T, conn net.Conn, domain string, port []byte) {
	t.Helper()
	write(t, conn, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	write(t, conn, []byte(domain)...)
	write(t, conn, port[0], port[1])
}

// --- demux ------------------------------------------------------------

func TestDemux_SilentClose_UnknownFirstByte(t *testing.T) {
	f := startFixture(t, nil, false)
	write(t, f.client, 0x47) // 'G' — neither 0x05 nor 'C'
	expectEOFWithNoData(t, f.client, "unknown first byte")
	awaitDone(t, f, "unknown first byte")
}

func TestDemux_ConnectRouted(t *testing.T) {
	f := startFixture(t, nil, false)
	write(t, f.client, 0x43) // 'C'
	// The 'C' byte is consumed by the demux; the seam receives the conn
	// positioned after it and the server must NOT have replied anything
	// (no SOCKS5-shaped bytes, no close — T023(d)).
	expectHeldOpen(t, f.client, "'C' first byte")
	select {
	case <-f.connected:
	case <-time.After(2 * time.Second):
		t.Fatalf("Connect seam never invoked")
	}
	if len(f.connects) != 1 {
		t.Fatalf("Connect seam invoked %d time(s), want 1", len(f.connects))
	}
	_ = f.client.Close()
	awaitDone(t, f, "'C' first byte")
}

// --- method negotiation ------------------------------------------------

func TestMethod_UserPassOnly_0502(t *testing.T) {
	f := startFixture(t, nil, false)
	// Segmented greeting: byte-at-a-time writes pin the framing reads
	// (VER NMETHODS METHODS) against fixed-size assumptions.
	write(t, f.client, 0x05)
	write(t, f.client, 0x01)
	write(t, f.client, 0x02)
	readExact(t, f.client, 0x05, 0x02)
	expectHeldOpen(t, f.client, "method-selection reply")
	_ = f.client.Close()
	awaitDone(t, f, "method negotiation")
}

func TestMethod_Mixed_0502(t *testing.T) {
	f := startFixture(t, nil, false)
	write(t, f.client, 0x05, 0x02, 0x00, 0x02) // NO_AUTH offered too — USER/PASS wins
	readExact(t, f.client, 0x05, 0x02)
	expectHeldOpen(t, f.client, "mixed-methods reply")
	_ = f.client.Close()
	awaitDone(t, f, "mixed methods")
}

func TestMethod_NoAuthOnly_05FF_Close(t *testing.T) {
	f := startFixture(t, nil, false)
	write(t, f.client, 0x05, 0x01, 0x00)
	readExact(t, f.client, 0x05, 0xFF)
	expectEOFWithNoData(t, f.client, "NO_AUTH-only rejection")
	awaitDone(t, f, "NO_AUTH-only rejection")
}

func TestMethod_EmptyMethods_05FF_Close(t *testing.T) {
	f := startFixture(t, nil, false)
	write(t, f.client, 0x05, 0x00) // NMETHODS=0: no method can be selected
	readExact(t, f.client, 0x05, 0xFF)
	expectEOFWithNoData(t, f.client, "empty methods rejection")
	awaitDone(t, f, "empty methods rejection")
}

// --- RFC 1929 sub-negotiation ------------------------------------------

func TestSubneg_Success_0100_ThenRequestPhase(t *testing.T) {
	f := startFixture(t, nil, true)
	greet(t, f.client)

	// UNAME with control bytes proves byte-verbatim pass-through (a
	// string-normalising implementation would mangle 0x00/0xFF).
	uname := []byte{0x61, 0x00, 0xFF, 0x7F, 0x62}
	subneg(t, f.client, uname, []byte("0123456789abcdef0123456789abcdef"), 0x01, 0x00)

	// Audit fired exactly once, BEFORE the request phase; auth-passed
	// requests count regardless of the route outcome (FR-008).
	if n := f.audit.count(); n != 1 {
		t.Fatalf("audit fired %d time(s) after auth pass, want 1", n)
	}

	requestConnect(t, f.client, "example.onion", []byte{0x01, 0xBB}) // :443

	awaitForward(t, f)
	called, gotUname, gotTarget := f.forward.state()
	if called != 1 {
		t.Fatalf("forward seam invoked %d time(s), want 1", called)
	}
	if string(gotUname) != string(uname) {
		t.Fatalf("UNAME forwarded = %x, want verbatim %x (FR-007)", gotUname, uname)
	}
	if gotTarget != "example.onion:443" {
		t.Fatalf("target = %q, want %q", gotTarget, "example.onion:443")
	}
	// Byte-pipe phase must be deadline-free: the zero SetDeadline is
	// recorded before the handoff (§"Deadlines").
	if n := f.server.zeroed(); n == 0 {
		t.Fatalf("no zero-deadline call recorded before the forward handoff — "+
			"post-handshake idle deadline forbidden (T025b); deadline calls: %d", f.server.total())
	}
	// Auth seam saw the raw PASSWD bytes.
	if got := f.auth.candidate(0); string(got) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("auth seam received %q, want the raw PASSWD", got)
	}
	awaitDone(t, f, "forward success")
}

// TestSubneg_Success_IPv4_IPv6_Targets pins the IP-literal target
// rendering: formatted, never resolved (FR-007 — no local DNS; Principle
// III). IPv6 renders bracketed per RFC 3986 host syntax so the upstream
// dial address is unambiguous.
func TestSubneg_Success_IPv4_IPv6_Targets(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		f := startFixture(t, nil, true)
		greet(t, f.client)
		subneg(t, f.client, []byte("u"), []byte("0123456789abcdef0123456789abcdef"), 0x01, 0x00)
		write(t, f.client, 0x05, 0x01, 0x00, 0x01, 10, 0, 0, 1, 0x01, 0xBB)
		awaitForward(t, f)
		if _, _, got := f.forward.state(); got != "10.0.0.1:443" {
			t.Fatalf("target = %q, want %q", got, "10.0.0.1:443")
		}
		awaitDone(t, f, "IPv4 target")
	})
	t.Run("IPv6", func(t *testing.T) {
		f := startFixture(t, nil, true)
		greet(t, f.client)
		subneg(t, f.client, []byte("u"), []byte("0123456789abcdef0123456789abcdef"), 0x01, 0x00)
		write(t, f.client, 0x05, 0x01, 0x00, 0x04,
			0x26, 0x00, 0x10, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x35)
		awaitForward(t, f)
		if _, _, got := f.forward.state(); got != "[2600:1001::1]:53" {
			t.Fatalf("target = %q, want %q", got, "[2600:1001::1]:53")
		}
		awaitDone(t, f, "IPv6 target")
	})
}

func TestSubneg_Failure_01FF_Close_NoCounter(t *testing.T) {
	f := startFixture(t, nil, false) // auth rejects everything
	greet(t, f.client)
	subneg(t, f.client, []byte("anyuser"), []byte("0123456789abcdef0123456789abcdef"), 0x01, 0xFF)
	expectEOFWithNoData(t, f.client, "auth failure")
	awaitDone(t, f, "auth failure")
	if n := f.audit.count(); n != 0 {
		t.Fatalf("audit fired %d time(s) on auth FAILURE, want 0 — "+
			"counting auth failures side-channels token guessing (FR-008)", n)
	}
	if called, _, _ := f.forward.state(); called != 0 {
		t.Fatalf("forward seam invoked %d time(s) after auth failure, want 0", called)
	}
}

// TestSubneg_NoFormatGate pins research.md §9: the SOCKS5 path applies
// NO syntactic token gate — an arbitrary 8-byte PASSWD reaches the auth
// seam raw and the reply depends only on its verdict (the 32-hex gate
// is CONNECT-path-only, T043).
func TestSubneg_NoFormatGate(t *testing.T) {
	f := startFixture(t, nil, true)
	greet(t, f.client)
	subneg(t, f.client, []byte("u"), []byte("tooshort"), 0x01, 0x00)
	if got := f.auth.candidate(0); string(got) != "tooshort" {
		t.Fatalf("auth seam received %q, want the unfiltered raw PASSWD", got)
	}
	_ = f.client.Close()
	awaitDone(t, f, "no-format-gate")
}

func TestSubneg_MalformedFraming_01FF(t *testing.T) {
	t.Run("VerNot01", func(t *testing.T) {
		f := startFixture(t, nil, true)
		greet(t, f.client)
		write(t, f.client, 0x02, 0x01, 'u', 0x01, 'p') // VER=0x02
		readExact(t, f.client, 0x01, 0xFF)
		expectEOFWithNoData(t, f.client, "VER!=01 sub-negotiation")
		awaitDone(t, f, "VER!=01")
	})
	t.Run("EmptyUNAME", func(t *testing.T) {
		f := startFixture(t, nil, true)
		greet(t, f.client)
		write(t, f.client, 0x01, 0x00, 0x01, 'p') // ULEN=0
		readExact(t, f.client, 0x01, 0xFF)
		expectEOFWithNoData(t, f.client, "ULEN=0")
		awaitDone(t, f, "ULEN=0")
	})
	t.Run("EmptyPASSWD", func(t *testing.T) {
		f := startFixture(t, nil, true)
		greet(t, f.client)
		write(t, f.client, 0x01, 0x01, 'u', 0x00) // PLEN=0
		readExact(t, f.client, 0x01, 0xFF)
		expectEOFWithNoData(t, f.client, "PLEN=0")
		awaitDone(t, f, "PLEN=0")
	})
}

// --- request phase -----------------------------------------------------

// routeErr is a test RouteError carrying a fixed REP code.
type routeErr struct{ rep byte }

func (e *routeErr) Error() string     { return "route error" }
func (e *routeErr) SOCKS5Reply() byte { return e.rep }

func TestRequestPhase_RouteError_ZeroedBND(t *testing.T) {
	// ROUTE_DOWN classification (0x03): the reply is byte-exact
	// 05 03 00 01 00 00 00 00 00 00 and the auth-pass counter stands
	// (FR-008 asymmetry: route failures count, auth failures don't).
	f := startFixture(t, &routeErr{rep: 0x03}, true)
	greet(t, f.client)
	subneg(t, f.client, []byte("u"), []byte("0123456789abcdef0123456789abcdef"), 0x01, 0x00)
	requestConnect(t, f.client, "dead.onion", []byte{0x00, 0x50})
	readExact(t, f.client,
		0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	expectEOFWithNoData(t, f.client, "route-failure reply tail")
	awaitDone(t, f, "route failure")
	if n := f.audit.count(); n != 1 {
		t.Fatalf("audit fired %d time(s) on auth-passed route failure, want 1 (FR-008)", n)
	}

	// A plain error (no RouteError) falls back to REP=0x01 (RFC general
	// failure) — never a leaky or zero REP.
	t.Run("GenericErrorFallsBackTo0x01", func(t *testing.T) {
		g := startFixture(t, errors.New("boom"), true)
		greet(t, g.client)
		subneg(t, g.client, []byte("u"), []byte("0123456789abcdef0123456789abcdef"), 0x01, 0x00)
		requestConnect(t, g.client, "dead.onion", []byte{0x00, 0x50})
		readExact(t, g.client,
			0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
		expectEOFWithNoData(t, g.client, "generic-failure reply tail")
		awaitDone(t, g, "generic failure")
	})
}

func TestRequestPhase_UnsupportedCmd_0507(t *testing.T) {
	f := startFixture(t, nil, true)
	greet(t, f.client)
	subneg(t, f.client, []byte("u"), []byte("0123456789abcdef0123456789abcdef"), 0x01, 0x00)
	write(t, f.client, 0x05, 0x02, 0x00, 0x03, 0x03, 'a', 'b', 'c', 0x00, 0x50) // CMD=0x02 BIND
	readExact(t, f.client, 0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	expectEOFWithNoData(t, f.client, "unsupported-CMD reply tail")
	awaitDone(t, f, "unsupported CMD")
	if called, _, _ := f.forward.state(); called != 0 {
		t.Fatalf("forward seam invoked on a non-CONNECT command, want 0")
	}
}

func TestRequestPhase_UnknownATYP_0508(t *testing.T) {
	f := startFixture(t, nil, true)
	greet(t, f.client)
	subneg(t, f.client, []byte("u"), []byte("0123456789abcdef0123456789abcdef"), 0x01, 0x00)
	write(t, f.client, 0x05, 0x01, 0x00, 0x09) // ATYP=0x09: no such address type
	readExact(t, f.client, 0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	expectEOFWithNoData(t, f.client, "unknown-ATYP reply tail")
	awaitDone(t, f, "unknown ATYP")
}

// TestClientVanishMidFraming pins the quiet path: a client that goes
// away mid-handshake terminates the handler without any reply attempt
// surfacing as an error.
func TestClientVanishMidFraming(t *testing.T) {
	f := startFixture(t, nil, true)
	write(t, f.client, 0x05, 0x01) // greeting only — no methods byte
	_ = f.client.Close()
	awaitDone(t, f, "client vanish mid-framing")
}
