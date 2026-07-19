// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// dialSOCKS5 returns a SOCKS5 client backed by a raw TCP connection to
// addr. The client uses USERNAME/PASSWORD sub-negotiation (method 0x02)
// so the fake records the username for CircuitIDs(). Returns the
// error rather than calling t.Fatalf so callers in non-test goroutines
// (TestConcurrentDistinctUsernames) can route the error through the
// main test goroutine via the channel — per the testing package docs,
// FailNow / Fatalf is safe ONLY from the test goroutine (codereview F2).
func dialSOCKS5(addr, username, password string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", addr, &proxy.Auth{
		User:     username,
		Password: password,
	}, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dialer: %w", err)
	}
	conn, err := dialer.Dial("tcp", "example.onion:443")
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dial: %w", err)
	}
	return conn, nil
}

// dialSOCKS5T is the single-goroutine variant that may call t.Fatalf
// directly (used by tests that do NOT spawn helper goroutines).
func dialSOCKS5T(t *testing.T, addr, username, password string) net.Conn {
	t.Helper()
	conn, err := dialSOCKS5(addr, username, password)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return conn
}

// TestAcceptAndRelayRoundTrip verifies the default mode round-trips
// bytes bidirectionally and records the SOCKS5 username for CircuitIDs()
// (T019a §Acceptance case (a)).
func TestAcceptAndRelayRoundTrip(t *testing.T) {
	srv := NewServer(AcceptAndRelay)
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	conn := dialSOCKS5T(t, addr, "alice-device", "bearer-token-xyz")
	defer conn.Close()

	// Write a known pattern; expect to read it back unmodified.
	pattern := []byte("stargate-round-trip-probe\n")
	if _, err := conn.Write(pattern); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(pattern))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != string(pattern) {
		t.Fatalf("round-trip mismatch: wrote %q read %q", pattern, buf)
	}

	// CircuitIDs() must report exactly one entry — the username we sent.
	ids := srv.CircuitIDs()
	if len(ids) != 1 || ids[0] != "alice-device" {
		t.Fatalf("CircuitIDs = %v, want [alice-device]", ids)
	}
}

// TestSlowTriggersDeadline verifies Slow mode's pre-BND-reply latency is
// observable to a consumer's handshake-phase deadline (T019a §Acceptance
// case (b)). contracts/socks5-auth.md §"Deadlines" row 193 bounds the
// "Open TCP + complete SOCKS5 method + auth + write request + read BND
// reply" phase to 30 s → ROUTE_TIMEOUT; row 194 marks post-handshake as
// deadline-free. Slow mode's delay MUST land BEFORE writeReply so the
// data plane's ROUTE_TIMEOUT fires (codereview F1). T067/T067a/T067b
// depend on this surface.
func TestSlowTriggersDeadline(t *testing.T) {
	srv := NewServer(Slow, WithLatency(500*time.Millisecond))
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	// Raw TCP dial + manual SOCKS5 client so we can apply a handshake-
	// phase deadline BEFORE the BND reply arrives. proxy.SOCKS5 does
	// not expose per-phase deadlines, so we drive the bytes by hand.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Method negotiation: greeting 0x05 0x01 0x02 (offer USERNAME/PWD).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	// RFC 1929 sub-negotiation: VER=0x01 ULEN=0x0d UNAME="slow-device"
	// PLEN=0x03 PASSWD="tok".
	if _, err := conn.Write([]byte{0x01, 0x0d,
		's', 'l', 'o', 'w', '-', 'd', 'e', 'v', 'i', 'c', 'e', '-', 'x',
		0x03, 't', 'o', 'k'}); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	// CONNECT request to example.onion:443 — ATYP=0x03 DOMAIN.
	// VER CMD RSV ATYP LEN DOMAIN... PORT
	// "example.onion" is 13 chars → LEN=0x0d (RFC 1928 §5 domain-length
	// byte). Codereview r2 F6 caught a prior 0x0b typo (the fake does
	// not validate LEN, so the test passed regardless, but the bytes
	// are now RFC-1928-valid on their face).
	req := []byte{0x05, 0x01, 0x00, 0x03, 0x0d,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'n', 'i', 'o', 'n',
		0x01, 0xbb}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	// Handshake-phase deadline: 50 ms < 500 ms Slow latency. The BND
	// reply will NOT arrive in time → i/o timeout. This is what the
	// data plane observes and translates to ROUTE_TIMEOUT (REP 0x06).
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err = io.ReadFull(conn, make([]byte, 10)) // BND reply is 10 bytes
	if err == nil {
		t.Fatalf("Read BND: expected i/o timeout, got nil")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read BND: expected i/o timeout, got %v", err)
	}
}

// TestHungBlocksHandshake verifies Hung mode never completes the SOCKS5
// handshake before the client's deadline fires (T019a §Acceptance case
// (c)).
func TestHungBlocksHandshake(t *testing.T) {
	srv := NewServer(Hung)
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	// Raw TCP dial — proxy.SOCKS5 would block forever waiting for the
	// method-selection reply that Hung never writes.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Send the SOCKS5 greeting (VER NMETHODS METHODS = 0x05 0x01 0x02).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	// Read deadline; Hung must not reply within it.
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 2)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatalf("Read: expected i/o timeout, got nil")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read: expected i/o timeout, got %v", err)
	}
}

// TestConcurrentDistinctUsernames verifies 50 parallel CONNECTs with
// distinct SOCKS5 usernames are all served concurrently and that
// CircuitIDs() reports 50 distinct entries (T019a §Acceptance case (d)).
// This is the load-shape T079a will eventually scale to 200.
func TestConcurrentDistinctUsernames(t *testing.T) {
	srv := NewServer(AcceptAndRelay)
	addr, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	const N = 50
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			// dialSOCKS5 returns the error rather than calling
			// t.Fatalf — FailNow is unsafe from non-test goroutines
			// (codereview F2). Route every error through errs into
			// the main test goroutine, which uses t.Errorf.
			conn, err := dialSOCKS5(addr, "device-"+itoa(i), "tok")
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			pattern := []byte{byte(i), 0xAA, 0x55}
			if _, err := conn.Write(pattern); err != nil {
				errs <- fmt.Errorf("conn %d write: %w", i, err)
				return
			}
			got := make([]byte, len(pattern))
			if _, err := io.ReadFull(conn, got); err != nil {
				errs <- fmt.Errorf("conn %d read: %w", i, err)
				return
			}
			if string(got) != string(pattern) {
				// codereview F3: explicit return after send — the
				// prior version fell through to a second send.
				errs <- fmt.Errorf("conn %d mismatch: wrote %q read %q", i, pattern, got)
				return
			}
			errs <- nil
		}()
	}
	for i := 0; i < N; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
	}
	ids := srv.CircuitIDs()
	if len(ids) != N {
		t.Fatalf("CircuitIDs len = %d, want %d (got %v)", len(ids), N, ids)
	}
	seen := make(map[string]bool, N)
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("CircuitIDs duplicate: %s", id)
		}
		seen[id] = true
	}
}

// itoa is a tiny zero-alloc int-to-string to keep the concurrency test
// allocation-free. Avoids pulling fmt into the per-goroutine hot path
// (the per-connection error formatters above are cold paths — they only
// allocate on failure).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
