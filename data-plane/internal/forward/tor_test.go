// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package forward

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"path/filepath"
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

	// hold, when non-nil, withholds the BND reply until it is closed: the
	// request stays pending at the upstream the way it does at Tor while
	// a connect is unresolved (T208). got, when non-nil, replaces the
	// echo relay: it receives every byte that reached the upstream after
	// the reply, delivered once the data plane closed the connection.
	hold chan struct{}
	got  chan []byte

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
	return newStubOnListener(t, ln, rep, silent)
}

func newStubUnix(t *testing.T, rep byte) *stub {
	t.Helper()
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "tor.sock"))
	if err != nil {
		t.Fatalf("unix stub listen: %v", err)
	}
	return newStubOnListener(t, ln, rep, false)
}

func newStubOnListener(t *testing.T, ln net.Listener, rep byte, silent bool) *stub {
	t.Helper()
	return startStub(t, &stub{ln: ln, rep: rep, silent: silent})
}

// newHoldingStub is a success-replying upstream that withholds its BND
// reply until the test closes hold, then reports what it received.
func newHoldingStub(t *testing.T) *stub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}
	return startStub(t, &stub{ln: ln, hold: make(chan struct{}), got: make(chan []byte, 1)})
}

func startStub(t *testing.T, s *stub) *stub {
	t.Helper()
	go func() {
		for {
			conn, err := s.ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	t.Cleanup(func() { s.ln.Close() })
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
	if s.hold != nil {
		<-s.hold
	}
	if _, err := conn.Write([]byte{0x05, s.rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	if s.got != nil {
		b, _ := io.ReadAll(br) // returns when the data plane closes the upstream
		s.got <- b
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

// T162 / Constitution I and III: changing the transport to AF_UNIX must not
// change the SOCKS5h target or send the inbound bearer to Tor.
func TestForwardUnixSocketPreservesSOCKS5hAuth(t *testing.T) {
	s := newStubUnix(t, 0x00)
	f := New("unix://"+s.addr(), &stubCounter{})
	addr, errc := forwardOn(t, f, []byte("sg1:opaque-partition"), "unresolvable.invalid:443")
	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })
	if err := cli.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("client deadline: %v", err)
	}
	roundTrip(t, cli)
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("Forward: %v", err)
	}
	_, username, plen := s.subNegotiation()
	if string(username) != "sg1:opaque-partition" || plen != 0 {
		t.Fatalf("upstream auth = %q, password length %d", username, plen)
	}
	atyp, host, port := s.target()
	if atyp != 0x03 || host != "unresolvable.invalid" || port != 443 {
		t.Fatalf("upstream target = ATYP %x %q:%d, want hostname-form", atyp, host, port)
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

// T173 removes the NO_AUTH Dial/Pipe seam. The same-target refusal regression
// and its real SOCKS partition/empty-password controls replace that old assertion.
func TestProductionDialDeadlineIsContractValue(t *testing.T) {
	// contracts/socks5-auth.md §"Deadlines" row 1 (value set by T208): the
	// dial-and-handshake ceiling is 250 s, wired as the single named
	// constant; row 2: no live-tunnel idle deadline exists. bridge's
	// terminal deadline only cancels pending I/O after a pump has finished.
	if upstreamDialTimeout != 250*time.Second {
		t.Fatalf("upstreamDialTimeout = %v, want 250s (contracts/socks5-auth.md §Deadlines row 1)", upstreamDialTimeout)
	}
	if f := New("tor:9050", &stubCounter{}); f.dialTimeout != upstreamDialTimeout {
		t.Fatalf("New().dialTimeout = %v, want the production constant", f.dialTimeout)
	}
}

// Characterization (T208; passes before and after the deadline change): a
// sidecar that ANSWERS with REP=0x06 (Tor's own "TTL expired", sent when it
// gives up on a stream) is the sidecar's failure reply, so the class is
// ROUTE_REFUSED (0x04). ROUTE_TIMEOUT (0x06) is reserved for the data
// plane's own deadline — the sidecar gave no reply
// (contracts/socks5-auth.md §"Deadlines"; pinned by
// TestForwardDialDeadlineIsRouteTimeout).
func TestForwardUpstreamTTLExpiredReplyIsRouteRefused(t *testing.T) {
	s := newStub(t, 0x06, false)
	f := New(s.addr(), &stubCounter{})
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), "deadmeta.onion:443")

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	t.Cleanup(func() { cli.Close() })

	select {
	case err := <-errc:
		var re listener.RouteError
		if !errors.As(err, &re) {
			t.Fatalf("err = %v, want a listener.RouteError classification", err)
		}
		if re.SOCKS5Reply() != 0x04 {
			t.Fatalf("SOCKS5Reply = 0x%02x, want 0x04 (ROUTE_REFUSED) for an upstream REP=0x06", re.SOCKS5Reply())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return after the upstream's REP=0x06")
	}
}

// awaitPendingAtUpstream blocks until the stub has read the request, i.e.
// the data plane's connect is pending upstream with the reply withheld.
func awaitPendingAtUpstream(t *testing.T, s *stub) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if atyp, _, _ := s.target(); atyp != 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("request never became pending at the upstream stub")
}

// Characterization (T208; passes before and after the deadline change;
// THREAT-MODEL §5.10 "Upstream deadline"): the data plane does not watch
// the client while the upstream connect is pending. When the client sent
// bytes after its request and then closed, and the upstream answers
// afterwards, those bytes are forwarded and the upstream connection is then
// closed promptly — nothing else is sent on it.
func TestForwardAbandonedClientPendingBytesForwardedThenUpstreamClosed(t *testing.T) {
	s := newHoldingStub(t)
	f := New(s.addr(), &stubCounter{})
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), "unresolvable.invalid:443")

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	const early = "bytes-sent-before-the-reply"
	if _, err := cli.Write([]byte(early)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	awaitPendingAtUpstream(t, s)

	// The request stays pending although the client is still there...
	select {
	case err := <-errc:
		t.Fatalf("Forward returned (%v) while the upstream reply was withheld", err)
	case <-time.After(100 * time.Millisecond):
	}
	// ...and after it has gone: no client-liveness coupling in this phase.
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	select {
	case err := <-errc:
		t.Fatalf("Forward returned (%v) on client close while the upstream reply was withheld", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(s.hold) // the upstream answers after the client has gone
	select {
	case got := <-s.got:
		if string(got) != early {
			t.Fatalf("upstream received %q after its reply, want exactly the client's pending bytes %q", got, early)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection was not closed promptly after the reply to an abandoned request")
	}
	select {
	case <-errc: // nil or a client-reply write error; both end the request
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return after the upstream closed")
	}
}

// Characterization (T208; passes before and after the deadline change): a
// client that RESET its connection while the upstream connect was pending
// makes Forward return the client-reply write error once the upstream
// answers, and the upstream connection is closed promptly with nothing
// forwarded on it.
func TestForwardResetClientReturnsWriteErrorAndClosesUpstream(t *testing.T) {
	s := newHoldingStub(t)
	f := New(s.addr(), &stubCounter{})
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), "unresolvable.invalid:443")

	cli, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	awaitPendingAtUpstream(t, s)
	if err := cli.(*net.TCPConn).SetLinger(0); err != nil { // close sends RST
		t.Fatalf("SetLinger: %v", err)
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // let the RST land on the data-plane side

	close(s.hold)
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Forward = nil after the client reset, want the client-reply write error")
		}
		var re listener.RouteError
		if errors.As(err, &re) {
			t.Fatalf("err = %v is a route classification; want the plain client write error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Forward did not return after the upstream answered a reset client")
	}
	select {
	case got := <-s.got:
		if len(got) != 0 {
			t.Fatalf("upstream received %d bytes for a reset client, want none", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream connection was not closed promptly for a reset client")
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
	// Both pumps can request shutdown; a flush per pump would double the
	// count to 92. Exactly 46 pins flush-once.
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
