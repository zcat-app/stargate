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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/listener"
)

// The suite exercises this package's SOCKS5 upstream behavior against a
// minimal recording stub. Most cases drive Forward; the RFC 1929 length
// guard calls socks5Connect directly. Assertions cover method selection,
// request framing, reply classification and byte relay, not upstream
// implementation. The heavier contract/integration backend is
// tests/integration/fake_socks5_tor.go (T019a); duplicating its Docker-era
// API here would drag integration concerns into this unit suite.

// stub is a bounded scripted SOCKS5 upstream. It records method selection,
// RFC 1929 bytes, target framing and any payload received.
type stub struct {
	ln              net.Listener
	rep             byte
	silent          bool
	preferNoAuth    bool
	forcedMethod    *byte
	greetingVersion byte
	authReply       []byte
	bndReply        []byte
	closeAfterBND   bool
	hold            chan struct{}
	got             chan []byte
	holdOnce        sync.Once
	done            chan struct{}

	mu          sync.Mutex
	active      net.Conn
	offered     []byte
	selected    byte
	hasSub      bool
	uname       []byte
	plen        int
	atyp        byte
	host        string
	port        int
	requestSeen bool
	received    []byte
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
	return startStub(t, &stub{ln: ln, rep: rep, silent: silent, greetingVersion: 0x05,
		authReply: []byte{0x01, 0x00}, done: make(chan struct{})})
}

func TestSOCKS5ConnectRequestBoundsAndEncodesPort(t *testing.T) {
	for _, tc := range []struct {
		target string
		want   []byte
	}{
		{target: "example.test:1", want: []byte{0, 1}},
		{target: "example.test:65535", want: []byte{0xff, 0xff}},
	} {
		request, err := socks5ConnectRequest(tc.target)
		if err != nil {
			t.Fatalf("socks5ConnectRequest(%q): %v", tc.target, err)
		}
		if got := request[len(request)-2:]; !bytes.Equal(got, tc.want) {
			t.Errorf("socks5ConnectRequest(%q) port bytes = %x, want %x", tc.target, got, tc.want)
		}
	}
	for _, target := range []string{"example.test:0", "example.test:65536", "example.test:999999999999999999999999"} {
		if _, err := socks5ConnectRequest(target); err == nil {
			t.Errorf("socks5ConnectRequest(%q) succeeded, want out-of-range error", target)
		}
	}
}

func TestSOCKS5ConnectRejectsUsernameOutsideRFC1929Length(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	err := socks5Connect(client, bytes.Repeat([]byte{'x'}, 256), "example.test:443")
	if err == nil {
		t.Fatal("socks5Connect accepted a username longer than RFC 1929's one-byte length")
	}
	if err := server.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, readErr := server.Read(b[:]); readErr == nil {
		t.Fatal("socks5Connect wrote a greeting before rejecting the oversized username")
	}
}

func newHoldingStub(t *testing.T) *stub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("stub listen: %v", err)
	}
	return startStub(t, &stub{ln: ln, hold: make(chan struct{}), got: make(chan []byte, 1),
		greetingVersion: 0x05, authReply: []byte{0x01, 0x00}, done: make(chan struct{})})
}

func startStub(t *testing.T, s *stub) *stub {
	t.Helper()
	go func() {
		defer close(s.done)
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.active = conn
		s.mu.Unlock()
		s.serve(conn)
	}()
	t.Cleanup(func() {
		s.releaseHold()
		s.mu.Lock()
		conn := s.active
		s.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		_ = s.ln.Close()
		select {
		case <-s.done:
		case <-time.After(time.Second):
			t.Errorf("upstream stub did not stop within its cleanup bound")
		}
	})
	return s
}

func (s *stub) addr() string { return s.ln.Addr().String() }

func (s *stub) serve(conn net.Conn) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		return
	}
	if s.silent {
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	br := bufio.NewReader(conn)
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	selected := byte(0xff)
	for _, method := range methods {
		if s.preferNoAuth && method == 0x00 {
			selected = 0x00
			break
		}
		if method == 0x02 {
			selected = 0x02
			if !s.preferNoAuth {
				break
			}
		}
	}
	if s.forcedMethod != nil {
		selected = *s.forcedMethod
	}
	s.mu.Lock()
	s.offered = append([]byte(nil), methods...)
	s.selected = selected
	s.mu.Unlock()
	if _, err := conn.Write([]byte{s.greetingVersion, selected}); err != nil {
		return
	}
	if selected == 0x02 {
		var authHeader [2]byte
		if _, err := io.ReadFull(br, authHeader[:]); err != nil {
			return
		}
		uname := make([]byte, int(authHeader[1]))
		if _, err := io.ReadFull(br, uname); err != nil {
			return
		}
		var plen [1]byte
		if _, err := io.ReadFull(br, plen[:]); err != nil {
			return
		}
		passwd := make([]byte, int(plen[0]))
		if _, err := io.ReadFull(br, passwd); err != nil {
			return
		}
		s.mu.Lock()
		s.hasSub = true
		s.uname = uname
		s.plen = int(plen[0])
		s.mu.Unlock()
		if _, err := conn.Write(s.authReply); err != nil || len(s.authReply) != 2 || s.authReply[0] != 0x01 || s.authReply[1] != 0x00 {
			return
		}
	} else if selected != 0x00 {
		return
	}

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
		var length [1]byte
		if _, err := io.ReadFull(br, length[:]); err != nil {
			return
		}
		rest := make([]byte, int(length[0])+2)
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
	case 0x04:
		rest := make([]byte, 18)
		if _, err := io.ReadFull(br, rest); err != nil {
			return
		}
		host = net.IP(rest[:16]).String()
		port = int(rest[16])<<8 | int(rest[17])
	default:
		return
	}
	s.mu.Lock()
	s.atyp, s.host, s.port, s.requestSeen = req[3], host, port, true
	s.mu.Unlock()
	if s.hold != nil {
		select {
		case <-s.hold:
		case <-time.After(10 * time.Second):
			return
		}
	}
	bnd := s.bndReply
	if bnd == nil {
		bnd = []byte{0x05, s.rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	}
	if _, err := conn.Write(bnd); err != nil {
		return
	}
	if s.closeAfterBND {
		return
	}
	if s.got != nil {
		b, _ := io.ReadAll(br)
		s.mu.Lock()
		s.received = append([]byte(nil), b...)
		s.mu.Unlock()
		s.got <- b
		return
	}
	if s.rep == 0x00 {
		_, _ = io.Copy(conn, conn)
	}
}

func (s *stub) releaseHold() {
	if s.hold != nil {
		s.holdOnce.Do(func() { close(s.hold) })
	}
}

func (s *stub) greeting() (offered []byte, selected byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.offered...), s.selected
}

func (s *stub) subNegotiation() (hasSub bool, uname []byte, plen int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hasSub, append([]byte(nil), s.uname...), s.plen
}

func (s *stub) target() (atyp byte, host string, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.atyp, s.host, s.port
}

func (s *stub) observations() (requestSeen bool, received []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requestSeen, append([]byte(nil), s.received...)
}

func awaitStub(t *testing.T, s *stub) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream stub did not finish within its deadline")
	}
}

func forwardOn(t *testing.T, f *Tor, uname []byte, target string) (string, <-chan error) {
	t.Helper()
	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("inbound listen: %v", err)
	}
	if err := inLn.(*net.TCPListener).SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		_ = inLn.Close()
		t.Fatalf("inbound accept deadline: %v", err)
	}
	errC := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := inLn.Accept()
		if err != nil {
			errC <- err
			return
		}
		_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
		defer conn.Close()
		errC <- f.Forward(conn, uname, target)
	}()
	t.Cleanup(func() {
		_ = inLn.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Errorf("Forward fixture did not stop within its cleanup bound")
		}
	})
	return inLn.Addr().String(), errC
}

func dialForwardClient(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = conn.Close()
		t.Fatalf("client deadline: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func awaitForward(t *testing.T, errC <-chan error) error {
	t.Helper()
	select {
	case err := <-errC:
		return err
	case <-time.After(6 * time.Second):
		t.Fatal("Forward result exceeded its fixture deadline")
		return nil
	}
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

func TestForwardOffersOnlyRFC1929ToNoAuthPreferringUpstream(t *testing.T) {
	s := newStub(t, 0x00, false)
	s.preferNoAuth = true
	counts := &stubCounter{}
	f := New(s.addr(), counts)
	const uname = "sg1:opaque-partition"
	addr, errC := forwardOn(t, f, []byte(uname), "unresolvable.invalid:443")
	client := dialForwardClient(t, addr)
	roundTrip(t, client)
	if err := client.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := awaitForward(t, errC); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	awaitStub(t, s)

	offered, selected := s.greeting()
	if !bytes.Equal(offered, []byte{0x02}) || selected != 0x02 {
		t.Fatalf("upstream greeting methods=%x selected=0x%02x; want only 0x02 and selection 0x02", offered, selected)
	}
	hasSub, gotUname, plen := s.subNegotiation()
	if !hasSub || !bytes.Equal(gotUname, []byte(uname)) || plen != 0 {
		t.Fatalf("RFC 1929 upstream auth hasSub=%t username=%q passwordLength=%d", hasSub, gotUname, plen)
	}
	if counts.total() != 46 {
		t.Fatalf("forwarded byte count=%d, want 46 healthy payload bytes", counts.total())
	}
}

func TestForwardRejectsForcedNoAuthBeforeSuccessConnectOrPayload(t *testing.T) {
	noAuth := byte(0x00)
	s := newStub(t, 0x00, false)
	s.forcedMethod = &noAuth
	s.got = make(chan []byte, 1)
	counts := &stubCounter{}
	f := New(s.addr(), counts)
	addr, errC := forwardOn(t, f, []byte("sg1:opaque-partition"), "unresolvable.invalid:443")
	client := dialForwardClient(t, addr)
	const payload = "opaque-payload-marker"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("queue client payload: %v", err)
	}
	var reply [10]byte
	n, replyErr := io.ReadFull(client, reply[:])
	_ = client.Close()
	err := awaitForward(t, errC)
	awaitStub(t, s)

	requestSeen, got := s.observations()
	if err == nil {
		t.Fatalf("forced NO_AUTH selection established a tunnel; reply=%x requestSeen=%t payload=%q forwardedBytes=%d; want ROUTE_REFUSED before CONNECT/payload",
			reply[:n], requestSeen, got, counts.total())
	}
	var routeErr listener.RouteError
	if !errors.As(err, &routeErr) || routeErr.SOCKS5Reply() != 0x04 {
		t.Fatalf("Forward error=%v; want ROUTE_REFUSED (0x04)", err)
	}
	noSuccessReply := n == 0 && (errors.Is(replyErr, io.EOF) || errors.Is(replyErr, syscall.ECONNRESET))
	if !noSuccessReply {
		t.Fatalf("client received %d bytes before refusal (reply=%x, err=%v); want no success reply", n, reply[:n], replyErr)
	}
	if hasSub, _, _ := s.subNegotiation(); hasSub {
		t.Fatal("RFC 1929 sub-negotiation followed a forbidden NO_AUTH selection")
	}
	if requestSeen || len(got) != 0 {
		t.Fatalf("upstream observed CONNECT=%t payload=%q after forbidden NO_AUTH selection", requestSeen, got)
	}
	if counts.total() != 0 {
		t.Fatalf("forwarded byte count=%d, want zero before authentication", counts.total())
	}
}

func TestForwardRefusesInvalidUpstreamProtocolReplies(t *testing.T) {
	versionOne, versionThree, noMethods := byte(0x01), byte(0x03), byte(0xff)
	cases := []struct {
		name      string
		configure func(*stub)
		want      byte
	}{
		{name: "forced-method-01", configure: func(s *stub) { s.forcedMethod = &versionOne }, want: 0x04},
		{name: "forced-method-03", configure: func(s *stub) { s.forcedMethod = &versionThree }, want: 0x04},
		{name: "forced-method-ff", configure: func(s *stub) { s.forcedMethod = &noMethods }, want: 0x04},
		{name: "wrong-greeting-version", configure: func(s *stub) { s.greetingVersion = 0x04 }, want: 0x04},
		{name: "wrong-auth-version", configure: func(s *stub) { s.authReply = []byte{0x02, 0x00} }, want: 0x04},
		{name: "auth-rejected", configure: func(s *stub) { s.authReply = []byte{0x01, 0x01} }, want: 0x04},
		{name: "wrong-bnd-version", configure: func(s *stub) { s.bndReply = []byte{0x04, 0, 0, 1, 0, 0, 0, 0, 0, 0} }, want: 0x04},
		{name: "nonzero-bnd-reserved", configure: func(s *stub) { s.bndReply = []byte{0x05, 0, 1, 1, 0, 0, 0, 0, 0, 0} }, want: 0x04},
		{name: "unknown-bnd-address-type", configure: func(s *stub) { s.bndReply = []byte{0x05, 0, 0, 0x7f} }, want: 0x04},
		{name: "truncated-bnd-io", configure: func(s *stub) {
			s.bndReply = []byte{0x05, 0}
			s.closeAfterBND = true
		}, want: 0x03},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStub(t, 0x00, false)
			tc.configure(s)
			counts := &stubCounter{}
			addr, errC := forwardOn(t, New(s.addr(), counts), []byte("sg1:opaque-partition"), "unresolvable.invalid:443")
			client := dialForwardClient(t, addr)
			var reply [10]byte
			n, readErr := io.ReadFull(client, reply[:])
			_ = client.Close()
			err := awaitForward(t, errC)
			awaitStub(t, s)
			var routeErr listener.RouteError
			if !errors.As(err, &routeErr) || routeErr.SOCKS5Reply() != tc.want {
				t.Fatalf("Forward error=%v; want route class 0x%02x", err, tc.want)
			}
			if n != 0 || !errors.Is(readErr, io.EOF) {
				t.Fatalf("client received %d bytes before upstream refusal (reply=%x, err=%v)", n, reply[:n], readErr)
			}
			if requestSeen, received := s.observations(); received != nil {
				t.Fatalf("upstream payload=%q, requestSeen=%t; want no forwarded bytes", received, requestSeen)
			}
			if counts.total() != 0 {
				t.Fatalf("forwarded byte count=%d, want zero before a successful handshake", counts.total())
			}
		})
	}
}

func TestForwardPreservesIPTargetsAndConsumesAllBNDAddressForms(t *testing.T) {
	ipv6BND := []byte{0x05, 0, 0, 0x04}
	ipv6BND = append(ipv6BND, net.ParseIP("2001:db8::9").To16()...)
	ipv6BND = append(ipv6BND, 0, 1)
	cases := []struct {
		name     string
		target   string
		bnd      []byte
		wantATYP byte
		wantHost string
	}{
		{name: "ipv4-target-bnd-ipv4", target: "192.0.2.7:443", bnd: []byte{0x05, 0, 0, 1, 192, 0, 2, 9, 0, 1}, wantATYP: 1, wantHost: "192.0.2.7"},
		{name: "ipv6-target-bnd-ipv6", target: "[2001:db8::7]:443", bnd: ipv6BND, wantATYP: 4, wantHost: "2001:db8::7"},
		{name: "domain-target-bnd-domain", target: "unresolvable.invalid:443", bnd: []byte{0x05, 0, 0, 3, 3, 'b', 'n', 'd', 0, 1}, wantATYP: 3, wantHost: "unresolvable.invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStub(t, 0x00, false)
			s.bndReply = tc.bnd
			addr, errC := forwardOn(t, New(s.addr(), &stubCounter{}), []byte("sg1:opaque-partition"), tc.target)
			client := dialForwardClient(t, addr)
			roundTrip(t, client)
			_ = client.Close()
			if err := awaitForward(t, errC); err != nil {
				t.Fatalf("Forward: %v", err)
			}
			awaitStub(t, s)
			atyp, host, port := s.target()
			if atyp != tc.wantATYP || host != tc.wantHost || port != 443 {
				t.Fatalf("upstream target = ATYP %d %q:%d; want %d %q:443", atyp, host, port, tc.wantATYP, tc.wantHost)
			}
		})
	}
}

func TestForwardWritesZeroedSuccessReplyAndBridges(t *testing.T) {
	s := newStub(t, 0x00, false)
	f := New(s.addr(), &stubCounter{})
	addr, errc := forwardOn(t, f, []byte("firstparty.example"), "unresolvable.invalid:443")

	cli := dialForwardClient(t, addr)
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

	cli := dialForwardClient(t, addr)
	roundTrip(t, cli)
	// Forward returns only when the tunnel ends — close the client first.
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := awaitForward(t, errc); err != nil {
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

	cli := dialForwardClient(t, addr)
	roundTrip(t, cli) // completes ⇒ nothing tried to resolve the target
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := awaitForward(t, errc); err != nil {
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

// T070a / Constitution I: once the production inbound listener has emitted
// SOCKS5 success, an upstream EOF ends the byte pipe. It must not be
// reclassified into a second SOCKS reply or any replacement bytes.
func TestCircuitDropMidstreamClosesWithoutSynthesizedBytes(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upstream.Close()

	const payload = "opaque-upstream-frame\x00\xff"
	var accepted atomic.Int32
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		accepted.Add(1)
		defer conn.Close()
		br := bufio.NewReader(conn)
		var greeting [2]byte
		if _, err := io.ReadFull(br, greeting[:]); err != nil {
			return
		}
		methods := make([]byte, greeting[1])
		if _, err := io.ReadFull(br, methods); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		var authHeader [2]byte
		if _, err := io.ReadFull(br, authHeader[:]); err != nil {
			return
		}
		uname := make([]byte, authHeader[1])
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
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
		var request [5]byte
		if _, err := io.ReadFull(br, request[:]); err != nil || request[0] != 0x05 || request[3] != 0x03 {
			return
		}
		domain := make([]byte, int(request[4])+2)
		if _, err := io.ReadFull(br, domain); err != nil {
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			return
		}
		_, _ = io.WriteString(conn, payload)
		_ = conn.Close()
		for {
			conn, err = upstream.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()

	f := New(upstream.Addr().String(), &stubCounter{})
	deps := &listener.Deps{
		Auth:    acceptEveryPassword{},
		Forward: f,
		Audit:   testAudit{},
	}
	inbound, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("inbound listen: %v", err)
	}
	defer inbound.Close()
	go func() {
		conn, err := inbound.Accept()
		if err == nil {
			listener.HandleConn(conn, deps)
		}
	}()

	client, err := net.DialTimeout("tcp", inbound.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("client deadline: %v", err)
	}
	if _, err := client.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write SOCKS greeting: %v", err)
	}
	var methodReply [2]byte
	if _, err := io.ReadFull(client, methodReply[:]); err != nil || methodReply != [2]byte{0x05, 0x02} {
		t.Fatalf("SOCKS method reply = %x, err=%v", methodReply, err)
	}
	uname, password, host := []byte("sg1:test-partition"), []byte("test-bearer"), []byte("example.invalid")
	auth := []byte{0x01, byte(len(uname))}
	auth = append(auth, uname...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := client.Write(auth); err != nil {
		t.Fatalf("write SOCKS auth: %v", err)
	}
	var authReply [2]byte
	if _, err := io.ReadFull(client, authReply[:]); err != nil || authReply != [2]byte{0x01, 0x00} {
		t.Fatalf("SOCKS auth reply = %x, err=%v", authReply, err)
	}
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, host...)
	request = append(request, 0x01, 0xbb)
	if _, err := client.Write(request); err != nil {
		t.Fatalf("write SOCKS CONNECT: %v", err)
	}
	var gotSuccessReply [10]byte
	if _, err := io.ReadFull(client, gotSuccessReply[:]); err != nil || gotSuccessReply != successReply {
		t.Fatalf("SOCKS success reply = %x, err=%v", gotSuccessReply, err)
	}
	got, readErr := io.ReadAll(client)
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, syscall.ECONNRESET) {
		t.Fatalf("client tunnel did not end with EOF/RST: %v", readErr)
	}
	if !bytes.Equal(got, []byte(payload)) {
		t.Fatalf("post-success client bytes length=%d, want exactly the %d upstream payload bytes", len(got), len(payload))
	}
	if err := upstream.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("bound the upstream retry observation: %v", err)
	}
	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("upstream response server did not finish after closing its stream")
	}
	time.Sleep(100 * time.Millisecond)
	if got := accepted.Load(); got != 1 {
		t.Fatalf("upstream TCP accepts = %d, want exactly one", got)
	}
}

type acceptEveryPassword struct{}

func (acceptEveryPassword) VerifyPassword([]byte) bool { return true }

type testAudit struct{}

func (testAudit) AuthPassedRequest() {}

// T162 / Constitution I and III: changing the transport to AF_UNIX must not
// change the SOCKS5h target or send the inbound bearer to Tor.
func TestForwardUnixSocketPreservesSOCKS5hAuth(t *testing.T) {
	s := newStubUnix(t, 0x00)
	f := New("unix://"+s.addr(), &stubCounter{})
	addr, errc := forwardOn(t, f, []byte("sg1:opaque-partition"), "unresolvable.invalid:443")
	cli := dialForwardClient(t, addr)
	if err := cli.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("client deadline: %v", err)
	}
	roundTrip(t, cli)
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	if err := awaitForward(t, errc); err != nil {
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

	_ = dialForwardClient(t, addr)

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

	_ = dialForwardClient(t, addr)

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

	_ = dialForwardClient(t, addr)

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

	cli := dialForwardClient(t, addr)
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

	s.releaseHold() // the upstream answers after the client has gone
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

	cli := dialForwardClient(t, addr)
	awaitPendingAtUpstream(t, s)
	if err := cli.(*net.TCPConn).SetLinger(0); err != nil { // close sends RST
		t.Fatalf("SetLinger: %v", err)
	}
	if err := cli.Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}
	time.Sleep(100 * time.Millisecond) // let the RST land on the data-plane side

	s.releaseHold()
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

	cli := dialForwardClient(t, addr)
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
	if err := awaitForward(t, errc); err != nil {
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

	cli := dialForwardClient(t, addr)

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
	if err := awaitForward(t, errc); err != nil {
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
