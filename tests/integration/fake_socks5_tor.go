// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package integration hosts Stargate's integration-test helpers and
// shared synthetic backends. The data plane's privacy-critical
// integration tests (T020a cold-start, T025a/b/d success-path counters,
// T067 ROUTE_TIMEOUT, T079a concurrent-CONNECTS) drive the data plane
// against the synthetic SOCKS5 backend declared in this file rather
// than the live Tor network — see specs/001-tor-route/research.md §7
// for the rationale (the property under test is the data plane's
// forwarding hot path, which does not depend on the upstream being the
// real Tor network).
//
// The fake mimics Tor's SocksPort accept-and-relay SURFACE; it does
// not reproduce Tor's circuit-building, cell-level encryption, or
// consensus-tracking (specs/001-tor-route/tickets/T019a-*.md R1).
package integration

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Mode controls the synthetic SOCKS5 backend's behavior. See the
// Mode constants below for the semantics consumers depend on.
type Mode int

const (
	// AcceptAndRelay is the default mode: the fake completes the SOCKS5
	// handshake, returns REP=0x00 success, then bidirectionally pipes
	// bytes between the client and an in-memory echo peer. Used by
	// SC-005 load runs (T079/T079a), cold-start survival tests (T020a),
	// and success-path log invariants (T025a/b/d).
	AcceptAndRelay Mode = iota

	// Slow completes the SOCKS5 handshake normally, then delays the
	// first upstream-to-client write by the configured latency
	// (WithLatency, default 250 ms). Consumers whose read deadline is
	// shorter than the delay observe i/o timeout — this is the surface
	// T067/T067a/T067b use to trigger the data plane's ROUTE_TIMEOUT.
	Slow

	// Hung accepts the TCP connection and reads the client's SOCKS5
	// greeting but never writes the method-selection reply. Reserved
	// for negative leak-corpus tests; consumers terminate via their
	// own context deadline (R3 documents the accepted-socket lifetime).
	Hung
)

// Server is a synthetic SOCKS5 backend mimicking the Tor sidecar's
// accept-and-relay surface (research.md §7 / T019a). The zero value is
// NOT usable; construct via NewServer.
type Server struct {
	mode Mode
	cfg  config

	mu       sync.Mutex
	listen   net.Listener
	circuits map[string]struct{} // observed SOCKS5 USERNAMEs (M3 stream-isolation mimicry)
	connects int                 // fully parsed SOCKS5 CONNECT requests; request data is discarded
	wg       sync.WaitGroup      // in-flight handler goroutines

	closeMu sync.Mutex
	closed  bool
}

// Option configures a Server at construction time.
type Option func(*config)

type config struct {
	listenAddr string
	latency    time.Duration
}

// WithListenAddr overrides the default loopback listen address
// ("127.0.0.1:0" — kernel-assigned port). Tests that need a fixed
// port (rare; the data plane reads the dial target from compose DNS
// in production) may set this.
func WithListenAddr(addr string) Option {
	return func(c *config) { c.listenAddr = addr }
}

// WithUnixSocket uses the same pathname transport as the deployed Tor sidecar.
// Closing and recreating Server at this path models Tor's socket recreation.
func WithUnixSocket(path string) Option {
	return WithListenAddr("unix://" + path)
}

// WithLatency sets the first-upstream-write delay for Slow mode
// (default 250 ms). The value MUST exceed the consumer's read deadline
// for the slow path to be observable. Ignored in other modes.
func WithLatency(d time.Duration) Option {
	return func(c *config) { c.latency = d }
}

// NewServer constructs a synthetic SOCKS5 backend configured by opts.
// The returned Server is not running until Start is called.
func NewServer(m Mode, opts ...Option) *Server {
	cfg := config{
		listenAddr: "127.0.0.1:0",
		latency:    250 * time.Millisecond,
	}
	for _, o := range opts {
		o(&cfg)
	}
	return &Server{
		mode:     Mode(m),
		cfg:      cfg,
		circuits: make(map[string]struct{}),
	}
}

// Start brings up the listener and begins accepting SOCKS5 connections.
// Returns the dialable address ("host:port") the data plane (or a test
// SOCKS5 client) should target.
func (s *Server) Start() (string, error) {
	network, address := "tcp", s.cfg.listenAddr
	if strings.HasPrefix(address, "unix://") {
		network, address = "unix", strings.TrimPrefix(address, "unix://")
	}
	ln, err := net.Listen(network, address)
	if err != nil {
		return "", fmt.Errorf("fake_socks5_tor: listen %s: %w", s.cfg.listenAddr, err)
	}
	s.mu.Lock()
	s.listen = ln
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed via Close
			}
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				s.serve(c)
			}(conn)
		}
	}()
	if network == "unix" {
		return "unix://" + address, nil
	}
	return ln.Addr().String(), nil
}

// Close stops the listener and waits for all in-flight handler
// goroutines to exit. Safe to call multiple times; subsequent calls
// are no-ops.
func (s *Server) Close() error {
	s.closeMu.Lock()
	if s.closed {
		s.closeMu.Unlock()
		return nil
	}
	s.closed = true
	s.closeMu.Unlock()

	s.mu.Lock()
	ln := s.listen
	s.mu.Unlock()
	if ln != nil {
		// Closing the listener unblocks Accept, which signals the
		// accept loop goroutine to return. In-flight handler goroutines
		// exit when their conn.Read returns EOF/error from the peer
		// close below OR when the consumer's context deadline fires.
		_ = ln.Close()
	}
	// Wait for the accept loop and any accepted-but-still-running
	// handlers (Hung mode accepted sockets included). Bounded by the
	// consumer's deadline in practice; if a test forgets a deadline
	// this WaitGroup could block — acceptable for a test helper.
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Last-resort: don't let a misbehaving test hang the suite.
	}
	return nil
}

// CircuitIDs returns a snapshot of the distinct SOCKS5 USERNAMEs the
// fake has observed at sub-negotiation time. Mirrors Tor's
// IsolateSOCKSAuth stream-isolation key (contracts/torrc.md). The
// returned slice is independently usable; the underlying set may
// continue to mutate after the call returns.
func (s *Server) CircuitIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.circuits))
	for k := range s.circuits {
		out = append(out, k)
	}
	return out
}

// ConnectCount reports the number of complete SOCKS5 CONNECT requests the
// fake has parsed. The counter stores no target or other request data.
func (s *Server) ConnectCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connects
}

// serve handles one inbound SOCKS5 connection end-to-end. The exact
// behavior depends on the configured Mode.
func (s *Server) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)

	// Hung mode: read the client's greeting but NEVER write back. The
	// consumer's context deadline will fire. Per T019a §Analysis M2,
	// Hung stops the handshake itself — checking the mode AFTER calling
	// negotiateMethod would incorrectly write the method-selection reply
	// (caught by TestHungBlocksHandshake at round-1 container validation).
	if s.mode == Hung {
		io.Copy(io.Discard, br)
		return
	}

	// --- Method selection (RFC 1928 §3) -----------------------------------
	// The fake is the UPSTREAM (Tor stand-in). Tor's SocksPort accepts
	// both NO_AUTH (0x00) and USERNAME/PASSWORD (0x02) at method
	// negotiation; the bearer-token auth gate is the DATA PLANE's job,
	// not the upstream's (R4). The fake mirrors Tor's surface.
	if err := negotiateMethod(br, c); err != nil {
		return // client misbehaved; close
	}

	// --- Username/password sub-negotiation (RFC 1929), if requested -----
	// The fake does not validate credentials. Tor's SocksPort uses the
	// USERNAME/PASSWORD purely as a stream-isolation key; the fake
	// records the observed USERNAME for CircuitIDs() and replies success.
	username, err := authSubNegotiation(br, c)
	if err != nil {
		return
	}
	if username != "" {
		s.mu.Lock()
		s.circuits[username] = struct{}{}
		s.mu.Unlock()
	}

	// --- SOCKS5 request phase (RFC 1928 §4) ------------------------------
	// Read CONNECT to a target. ATYP=0x01 (IPv4) and ATYP=0x03 (DOMAIN)
	// are both accepted; the fake does not dial a real target — it
	// short-circuits to an in-memory byte pipe.
	if err := readConnectRequest(br); err != nil {
		writeReply(c, 0x07) // Command not supported / general failure
		return
	}
	s.mu.Lock()
	s.connects++
	s.mu.Unlock()

	// Slow mode: delay the BND reply (the success reply below) past
	// the data plane's dial-and-handshake deadline. contracts/socks5-
	// auth.md §"Deadlines" row 1 bounds the phase "Open TCP to
	// tor:9050 + complete SOCKS5 method + auth + write request + read
	// BND reply" to 250 s (T208) → ROUTE_TIMEOUT; row 2 marks post-handshake
	// as deadline-free / long-lived. The Slow delay MUST land BEFORE
	// writeReply so the data plane's ROUTE_TIMEOUT fires — placing it
	// after writeReply would only delay the post-handshake byte pipe,
	// which has no deadline and would never trigger 0x06 (codereview F1).
	if s.mode == Slow {
		time.Sleep(s.cfg.latency)
	}

	// Success reply: VER=05 REP=00 RSV=00 ATYP=01 BND.ADDR=0.0.0.0 BND.PORT=0
	if err := writeReply(c, 0x00); err != nil {
		return
	}

	// --- Relay phase -----------------------------------------------------
	switch s.mode {
	case AcceptAndRelay:
		relayEcho(c)
	case Slow:
		// The Slow delay already fired before writeReply above. Once
		// the BND reply is sent (late), relay normally — consumers
		// whose deadline already fired will have closed; others see
		// the relay surface.
		relayEcho(c)
	}
}

// negotiateMethod reads the client's SOCKS5 greeting (VER NMETHODS
// METHODS…) and writes the method-selection reply. Per R4 the fake
// accepts both NO_AUTH (0x00) and USERNAME/PASSWORD (0x02); if the
// client offers 0x02 it is selected (so the fake can record the
// username for CircuitIDs()), otherwise NO_AUTH is selected.
func negotiateMethod(br *bufio.Reader, w io.Writer) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return fmt.Errorf("fake_socks5_tor: not SOCKS5 (VER=0x%02x)", header[0])
	}
	nmethods := int(header[1])
	if nmethods == 0 {
		return errors.New("fake_socks5_tor: NMETHODS=0")
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	selected := byte(0x00) // NO_AUTH default
	for _, m := range methods {
		if m == 0x02 { // USERNAME/PASSWORD wins for stream-isolation visibility
			selected = 0x02
			break
		}
	}
	_, err := w.Write([]byte{0x05, selected})
	return err
}

// authSubNegotiation handles RFC 1929 username/password sub-negotiation
// when the client offered method 0x02. The fake always replies success
// (0x01 0x00) and records the USERNAME for CircuitIDs(). Returns the
// observed username (empty string if no sub-negotiation was requested).
func authSubNegotiation(br *bufio.Reader, w io.Writer) (string, error) {
	// We need to detect whether the client is about to send a sub-
	// negotiation message. The negotiated method was selected by
	// negotiateMethod above; if it was 0x00, no sub-negotiation
	// follows. If 0x02, the RFC 1929 message comes next.
	// To keep this simple and robust, we PEEK at the first byte: a
	// 0x01 indicates the start of RFC 1929 sub-negotiation.
	peek, err := br.Peek(1)
	if err != nil {
		return "", nil // client may have closed; treat as no auth
	}
	if peek[0] != 0x01 {
		return "", nil // not RFC 1929; no sub-negotiation
	}
	// Read the full sub-negotiation header: VER ULEN UNAME PLEN PASSWD.
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return "", err
	}
	ulen := int(header[1])
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(br, uname); err != nil {
		return "", err
	}
	plenByte := make([]byte, 1)
	if _, err := io.ReadFull(br, plenByte); err != nil {
		return "", err
	}
	plen := int(plenByte[0])
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(br, passwd); err != nil {
		return "", err
	}
	// Always reply success — the fake is the upstream Tor stand-in;
	// bearer-token auth is the data plane's job (R4 / §Out-of-scope).
	if _, err := w.Write([]byte{0x01, 0x00}); err != nil {
		return "", err
	}
	return string(uname), nil
}

// readConnectRequest reads a SOCKS5 CONNECT request (RFC 1928 §4) and
// discards the target — the fake does not dial a real upstream. VER
// must be 0x05; CMD must be 0x01 (CONNECT); the request's address
// payload is parsed only enough to consume it from the wire so the
// subsequent relay phase reads application bytes, not request residue.
func readConnectRequest(br *bufio.Reader) error {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("fake_socks5_tor: request VER=0x%02x (want 0x05)", hdr[0])
	}
	if hdr[1] != 0x01 { // only CONNECT is supported
		return fmt.Errorf("fake_socks5_tor: CMD=0x%02x (want 0x01 CONNECT)", hdr[1])
	}
	// hdr[2] is RSV (must be 0x00); hdr[3] is ATYP.
	switch hdr[3] {
	case 0x01: // IPv4: 4 address bytes + 2 port bytes
		if _, err := io.ReadFull(br, make([]byte, 6)); err != nil {
			return err
		}
	case 0x03: // DOMAIN: 1 length byte + N address bytes + 2 port bytes
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(br, lenByte); err != nil {
			return err
		}
		if _, err := io.ReadFull(br, make([]byte, int(lenByte[0])+2)); err != nil {
			return err
		}
	case 0x04: // IPv6: 16 address bytes + 2 port bytes
		if _, err := io.ReadFull(br, make([]byte, 18)); err != nil {
			return err
		}
	default:
		return fmt.Errorf("fake_socks5_tor: ATYP=0x%02x (unsupported)", hdr[3])
	}
	return nil
}

// writeReply sends a SOCKS5 reply with the given REP code. BND.ADDR/
// BND.PORT are 0.0.0.0:0 — the data plane does not inspect them per
// contracts/socks5-auth.md §"SOCKS5 request-phase failures (post-auth)".
func writeReply(w io.Writer, rep byte) error {
	// VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
	_, err := w.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// relayEcho pipes bytes from the client back to the client until the
// client closes or errors. This is the simplest byte-transparent
// upstream: every byte the client writes is read and written back,
// satisfying T025b's round-trip-invariant test surface when the data
// plane sits between two fakes or between a fake and a real client.
//
// The relay does NOT frame or buffer beyond what io.Copy provides; it
// is the minimal byte-pipe.
func relayEcho(c net.Conn) {
	_, _ = io.Copy(c, c)
}
