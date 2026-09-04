// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package forward

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/listener"
)

// The suite drives the real golang.org/x/net client (pinned by go.mod)
// against a minimal recording SOCKS5 upstream stub — the property under
// test is THIS package's behavior (passthrough, classification, reply
// bytes, pipe semantics), not the upstream's. The heavier synthetic
// backend used by the contract/integration layers is
// tests/integration/fake_socks5_tor.go (T019a); duplicating it here
// would drag its Docker-era API into a unit suite.

// stub is a scripted SOCKS5 upstream. It records the greeting methods,
// the selected method, the RFC 1929 username/password bytes, and the
// request-phase target, then answers the BND reply with rep (0x00 →
// echo relay, any other value → close without relaying). silent accepts
// the TCP connection and never speaks — the surface the dial deadline
// times out against.
type stub struct {
	ln     net.Listener
	rep    byte
	silent bool

	mu       sync.Mutex
	offered  []byte
	selected byte
	hasSub   bool
	uname    []byte
	plen     int
	atyp     byte
	host     string
	port     int
}

func newStub(t *testing.T, rep byte, silent bool) *stub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}
	s := &stub{ln: ln, rep: rep, silent: silent}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *stub) addr() string { return s.ln.Addr().String() }

func (s *stub) serve(conn net.Conn) {
	defer conn.Close()
	if s.silent {
		time.Sleep(2 * time.Second) // outlives every injected test deadline
		return
	}
	br := bufio.NewReader(conn)

	// Greeting (RFC 1928 §3): record the offered methods, prefer
	// USERNAME/PASSWORD when offered (mirrors the fake Tor and lets the
	// passthrough asserts fire), reply with the selection.
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
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
	s.mu.Lock()
	s.offered = append([]byte(nil), methods...)
	s.selected = selected
	s.mu.Unlock()
	if _, err := conn.Write([]byte{0x05, selected}); err != nil {
		return
	}

	// Sub-negotiation (RFC 1929), when selected: record UNAME/PLEN
	// verbatim, always reply success.
	if selected == 0x02 {
		var v [2]byte
		if _, err := io.ReadFull(br, v[:]); err != nil {
			return
		}
		uname := make([]byte, v[1])
		if _, err := io.ReadFull(br, uname); err != nil {
			return
		}
		var plen [1]byte
		if _, err := io.ReadFull(br, plen[:]); err != nil {
			return
		}
		passwd := make([]byte, plen[0])
		if _, err := io.ReadFull(br, passwd); err != nil {
			return
		}
		s.mu.Lock()
		s.hasSub = true
		s.uname = uname
		s.plen = int(plen[0])
		s.mu.Unlock()
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}

	// Request phase (RFC 1928 §4): record ATYP + target, reply BND with
	// the scripted REP, then echo-relay only on success.
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	var host string
	var port int
	switch req[3] {
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(br, l[:]); err != nil {
			return
		}
		rest := make([]byte, int(l[0])+2)
		if _, err := io.ReadFull(br, rest); err != nil {
			return
		}
		host = string(rest[:len(rest)-2])
		port = int(rest[len(rest)-2])<<8 | int(rest[len(rest)-1])
	case 0x01:
		rest := make([]byte, 6)
		if _, err := io.ReadFull(br, rest); err != nil {
			return
		}
		host = net.IP(rest[:4]).String()
		port = int(rest[4])<<8 | int(rest[5])
	default:
		return
	}
	s.mu.Lock()
	s.atyp = req[3]
	s.host = host
	s.port = port
	s.mu.Unlock()
	if _, err := conn.Write([]byte{0x05, s.rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	if s.rep == 0x00 {
		_, _ = io.Copy(conn, conn)
	}
}

func (s *stub) greeting() (offered []byte, selected byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.offered, s.selected
}

func (s *stub) subNegotiation() (hasSub bool, uname []byte, plen int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasSub, s.uname, s.plen
}

func (s *stub) target() (atyp byte, host string, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.atyp, s.host, s.port
}

// forwardOn accepts exactly one inbound connection on a fresh loopback
// listener and serves it with f.Forward, returning the dialable client
// address and a channel carrying Forward's return value.
func forwardOn(t *testing.T, f *Tor, uname []byte, target string) (string, <-chan error) {
	t.Helper()
	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("inbound listen: %v", err)
	}
	t.Cleanup(func() { inLn.Close() })
	errc := make(chan error, 1)
	go func() {
		c, err := inLn.Accept()
		if err != nil {
			errc <- err
			return
		}
		errc <- f.Forward(c, uname, target)
	}()
	return inLn.Addr().String(), errc
}

// roundTrip exchanges two frames in both directions over the established
// tunnel and asserts the inbound success reply was the exact zeroed
// 10-byte form, preceding any tunnel byte.
func roundTrip(t *testing.T, cli net.Conn) {
	t.Helper()
	rep := make([]byte, 10)
	if _, err := io.ReadFull(cli, rep); err != nil {
		t.Fatalf("read BND reply: %v", err)
	}
	want := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(rep, want) {
		t.Fatalf("BND reply = %x, want %x (zeroed, byte-exact)", rep, want)
	}
	for _, frame := range []string{"first-frame", "second-frame"} {
		if _, err := cli.Write([]byte(frame)); err != nil {
			t.Fatalf("client write: %v", err)
		}
		got := make([]byte, len(frame))
		if _, err := io.ReadFull(cli, got); err != nil {
			t.Fatalf("client read (echo): %v", err)
		}
		if string(got) != frame {
			t.Fatalf("echo = %q, want %q", got, frame)
		}
	}
}

func TestForwardWritesZeroedSuccessReplyAndBridges(t *testing.T) {
	s := newStub(t, 0x00, false)
	f := New(s.addr(), &stubCounter{})
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), "unresolvable.invalid:443")

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	roundTrip(t, cli)

	// Either end closing ends the tunnel; Forward's return is nil —
	// never failure bytes injected into an established tunnel.
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Forward after established tunnel = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return after client close")
	}
}

func TestForwardPassesUNAMEVerbatimAsUpstreamUsername(t *testing.T) {
	s := newStub(t, 0x00, false)
	f := New(s.addr(), &stubCounter{})
	const uname = "firstparty.example"
	addr, errc := forwardOn(t, f, []byte(uname), "unresolvable.invalid:443")

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	roundTrip(t, cli)
	// Forward returns only when the tunnel ends — close the client first.
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Forward: %v", err)
	}

	offered, selected := s.greeting()
	if !bytes.Contains(offered, []byte{0x02}) {
		t.Fatalf("greeting methods = %x, want 0x02 (USERNAME/PASSWORD) offered", offered)
	}
	if selected != 0x02 {
		t.Fatalf("selected method = 0x%02x, want 0x02", selected)
	}
	hasSub, gotUname, plen := s.subNegotiation()
	if !hasSub {
		t.Fatal("no RFC 1929 sub-negotiation reached the upstream")
	}
	if string(gotUname) != uname {
		t.Fatalf("upstream UNAME = %q, want verbatim %q", gotUname, uname)
	}
	if plen != 0 {
		t.Fatalf("upstream PLEN = %d, want 0 (password is never re-sent upstream)", plen)
	}
}

func TestForwardSendsDomainTargetUnresolved(t *testing.T) {
	s := newStub(t, 0x00, false)
	f := New(s.addr(), &stubCounter{})
	const target = "unresolvable.invalid:443" // RFC 6761: cannot resolve
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), target)

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	roundTrip(t, cli) // completes ⇒ nothing tried to resolve the target
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Forward: %v", err)
	}

	atyp, host, port := s.target()
	if atyp != 0x03 {
		t.Fatalf("request ATYP = 0x%02x, want 0x03 (FQDN — SOCKS5h, FR-007)", atyp)
	}
	if host != "unresolvable.invalid" || port != 443 {
		t.Fatalf("upstream target = %q:%d, want verbatim host from %q", host, port, target)
	}
}

func TestForwardUnreachableUpstreamIsRouteDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	closedAddr := ln.Addr().String()
	ln.Close() // a port that deterministically refuses

	f := New(closedAddr, &stubCounter{})
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })

	err = f.Forward(c1, []byte("firstparty.example"), "example.com:443")
	if err == nil {
		t.Fatal("Forward to a closed upstream port = nil, want ROUTE_DOWN error")
	}
	var re listener.RouteError
	if !errors.As(err, &re) {
		t.Fatalf("err = %v, want a listener.RouteError classification", err)
	}
	if re.SOCKS5Reply() != 0x03 {
		t.Fatalf("SOCKS5Reply = 0x%02x, want 0x03 (ROUTE_DOWN)", re.SOCKS5Reply())
	}
}

func TestForwardUpstreamRefusalIsRouteRefused(t *testing.T) {
	s := newStub(t, 0x05, false) // alive sidecar, BND REP=5 host-unreachable
	f := New(s.addr(), &stubCounter{})
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), "deadmeta.onion:443")

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Forward with BND REP=5 = nil, want ROUTE_REFUSED error")
		}
		var re listener.RouteError
		if !errors.As(err, &re) {
			t.Fatalf("err = %v, want a listener.RouteError classification", err)
		}
		if re.SOCKS5Reply() != 0x04 {
			t.Fatalf("SOCKS5Reply = 0x%02x, want 0x04 (ROUTE_REFUSED)", re.SOCKS5Reply())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return after upstream refusal")
	}
}

func TestForwardDialDeadlineIsRouteTimeout(t *testing.T) {
	s := newStub(t, 0x00, true) // accepts TCP, never speaks
	f := New(s.addr(), &stubCounter{})
	f.dialTimeout = 250 * time.Millisecond // injected short deadline
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), "slow.onion:443")

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Forward past the dial deadline = nil, want ROUTE_TIMEOUT error")
		}
		var re listener.RouteError
		if !errors.As(err, &re) {
			t.Fatalf("err = %v, want a listener.RouteError classification", err)
		}
		if re.SOCKS5Reply() != 0x06 {
			t.Fatalf("SOCKS5Reply = 0x%02x, want 0x06 (ROUTE_TIMEOUT)", re.SOCKS5Reply())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return after the dial deadline")
	}
}

func TestDialNoUsernameOffersNoAuthAndBridges(t *testing.T) {
	s := newStub(t, 0x00, false)
	f := New(s.addr(), &stubCounter{})

	up, err := f.Dial("example.org:80")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer up.Close()

	offered, selected := s.greeting()
	if bytes.Contains(offered, []byte{0x02}) {
		t.Fatalf("greeting methods = %x, want NO_AUTH only (CONNECT carries no username)", offered)
	}
	if selected != 0x00 {
		t.Fatalf("selected method = 0x%02x, want 0x00", selected)
	}
	if hasSub, uname, _ := s.subNegotiation(); hasSub {
		t.Fatalf("sub-negotiation reached the upstream with UNAME %q; CONNECT path must not send one", uname)
	}
	if _, host, port := s.target(); host != "example.org" || port != 80 {
		t.Fatalf("upstream target = %q:%d, want example.org:80", host, port)
	}

	// Pipe bridges after the handshake; teardown returns nil and the
	// client conn stays the listener's.
	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("inbound listen: %v", err)
	}
	t.Cleanup(func() { inLn.Close() })
	errc := make(chan error, 1)
	go func() {
		c, err := inLn.Accept()
		if err != nil {
			errc <- err
			return
		}
		errc <- f.Pipe(c, up)
	}()
	cli, err := net.Dial("tcp", inLn.Addr().String())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })

	if _, err := cli.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatalf("client read (echo): %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("echo = %q, want %q", got, "hello")
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Pipe after teardown = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return after client close")
	}
}

func TestProductionDialDeadlineIsThirtySeconds(t *testing.T) {
	// contracts/socks5-auth.md §"Deadlines" row 1: the dial-and-handshake
	// ceiling is 30 s, wired as the single named constant; row 2: no
	// post-handshake deadline exists (asserted structurally — no code
	// path sets one after dialUpstream returns).
	if upstreamDialTimeout != 30*time.Second {
		t.Fatalf("upstreamDialTimeout = %v, want 30s", upstreamDialTimeout)
	}
	if f := New("tor:9050", &stubCounter{}); f.dialTimeout != upstreamDialTimeout {
		t.Fatalf("New().dialTimeout = %v, want the production constant", f.dialTimeout)
	}
}

// stubCounter records what the byte-count seam flushed. The production
// implementer is T049's audit.Counters; this suite stays audit-agnostic
// (the seam consumer is defined in THIS package), so a local stand-in
// pins the contract from the forward side.
type stubCounter struct {
	mu sync.Mutex
	n  uint64
}

func (s *stubCounter) AddForwardedBytes(n uint64) {
	s.mu.Lock()
	s.n += n
	s.mu.Unlock()
}

func (s *stubCounter) total() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

func TestByteFlushAtCloseBothDirections(t *testing.T) {
	s := newStub(t, 0x00, false)
	counts := &stubCounter{}
	f := New(s.addr(), counts)
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), "unresolvable.invalid:443")

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	roundTrip(t, cli) // 11+12 bytes each way = 46 tunnel bytes

	// data-model.md §3: byte_count increments AT REQUEST CLOSE, not per
	// operation. The tunnel is open and quiescent, so nothing has landed
	// yet — even though all 46 bytes have crossed it in both directions.
	if got := counts.total(); got != 0 {
		t.Fatalf("counter = %d while tunnel open, want 0 (flush is at close)", got)
	}

	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Forward: %v", err)
	}
	// bridge closes the upstream from BOTH pump goroutines; a flush per
	// close would double the count to 92. Exactly 46 pins flush-once.
	if got := counts.total(); got != 46 {
		t.Fatalf("counter = %d after close, want exactly 46 (2×23 forwarded bytes, flushed once)", got)
	}
}

func TestUpstreamRelayCountsTunnelBytesExactly(t *testing.T) {
	s := newStub(t, 0x00, false)
	counts := &stubCounter{}
	f := New(s.addr(), counts)
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), "unresolvable.invalid:443")

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })

	// Success reply first, byte-exact — and NOT counted (the listener's
	// synthesised bytes never cross the upstream conn).
	rep := make([]byte, 10)
	if _, err := io.ReadFull(cli, rep); err != nil {
		t.Fatalf("read BND reply: %v", err)
	}

	const B = 1000
	payload := bytes.Repeat([]byte{0xA5}, B)
	if _, err := cli.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := make([]byte, B)
	if _, err := io.ReadFull(cli, got); err != nil {
		t.Fatalf("client read (echo): %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("echo payload mismatch")
	}

	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Forward: %v", err)
	}

	// Exactly 2B: the SOCKS5 handshake bytes on either side (greeting,
	// method choice, sub-negotiation, request, BND) are upstream protocol
	// and excluded by the post-handshake wrap point (data-model.md §3 —
	// only client↔upstream forwarded bytes contribute).
	if total := counts.total(); total != 2*B {
		t.Fatalf("counter = %d, want exactly %d (B each direction, handshake bytes excluded)", total, 2*B)
	}
}
