// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package socks5 hosts the contract tests for the data plane's
// port-8881 inbound surface that is NOT the privacy-safe error-template
// (that surface has its own package at tests/contract/error-template/).
// The split mirrors the contract document: tests/contract/socks5/ holds
// the SOCKS5 demux + auth + sub-negotiation byte-shape tests plus the
// CONNECT-framed auth-success and byte-pipe transparency tests, plus
// the multi-protocol invariants (counter side-channel under mixed
// SOCKS5 + CONNECT load). See specs/001-tor-route/contracts/socks5-
// auth.md §"Scope" for the directory's enumeration.
package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
)

// TestSOCKS5DemuxAndMethodNegotiation pins the byte-exact contract from
// specs/001-tor-route/contracts/socks5-auth.md §"Two inbound protocols,
// one port" and §"Auth method negotiation".
//
// Tests-first (Constitution Principle VII) for T042
// (data-plane/internal/listener/socks5.go): this test exists RED-but-
// SKIP until T042/T045/T050 land; once they do, it drives the
// implementation to satisfy the byte contract. The DP-process boot
// harness self-skips (never fails) while the implementation files are
// absent (see dpharness.Start content gate).
func TestSOCKS5DemuxAndMethodNegotiation(t *testing.T) {
	h := dpharness.Start(t)

	// (a) Method negotiation: client offers ONLY USERNAME/PASSWORD.
	// Input  05 01 02       (VER NMETHODS METHODS=[0x02])
	// Reply  05 02          (USERNAME/PASSWORD selected)
	t.Run("MethodNegotiation_UserPassOnly", func(t *testing.T) {
		conn := dialProxy(t, h)
		defer conn.Close()
		if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			t.Fatalf("write greeting [0x02]-only: %v", err)
		}
		got := readN(t, conn, 2)
		want := []byte{0x05, 0x02}
		if !bytes.Equal(got, want) {
			t.Errorf("method-selection reply for input 05 01 02 = %x, want %x — "+
				"contracts/socks5-auth.md §\"Auth method negotiation\": single "+
				"method USERNAME/PASSWORD offered MUST select 0x02",
				got, want)
		}
		// Contract: the reply is EXACTLY 2 bytes, then the DP MUST wait
		// for the client's RFC 1929 sub-negotiation. A 3rd byte or an
		// immediate close is a contract breach — symmetric with sub-
		// test (c)'s expectEOF check, but here the expected state is
		// "held open and silent" rather than "closed".
		expectHeldOpen(t, conn, "after 2-byte method-selection reply")
	})

	// (b) Method negotiation: mixed methods [0x00, 0x02].
	// Input  05 02 00 02    (VER NMETHODS=2 METHODS=[NO_AUTH, USER/PASS])
	// Reply  05 02          (USERNAME/PASSWORD wins even with NO_AUTH also offered)
	//
	// This case guards the realistic stock-client shape (most SOCKS5
	// clients offer both methods) against an accidental NO_AUTH-accept
	// regression that would let same-host unprivileged processes proxy
	// without the bearer token (THREAT-MODEL §3.1).
	t.Run("MethodNegotiation_MixedMethods", func(t *testing.T) {
		conn := dialProxy(t, h)
		defer conn.Close()
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			t.Fatalf("write greeting [0x00,0x02] mixed: %v", err)
		}
		got := readN(t, conn, 2)
		want := []byte{0x05, 0x02}
		if !bytes.Equal(got, want) {
			t.Errorf("method-selection reply for input 05 02 00 02 = %x, want %x — "+
				"contracts/socks5-auth.md §\"Auth method negotiation\": "+
				"USERNAME/PASSWORD (0x02) MUST be selected even when NO_AUTH "+
				"(0x00) is also offered (the realistic-client shape)",
				got, want)
		}
		expectHeldOpen(t, conn, "after 2-byte method-selection reply")
	})

	// (c) Method negotiation: client offers ONLY NO_AUTH.
	// Input  05 01 00       (VER NMETHODS METHODS=[0x00])
	// Reply  05 FF          (no acceptable methods)
	// Then the DP MUST close — no further bytes. The data plane never
	// accepts unauthenticated SOCKS5 (contracts/socks5-auth.md §"Auth
	// method negotiation" — even loopback-bound, the local-process
	// threat model assumes other unprivileged processes on the same
	// host should not get free proxy access).
	t.Run("MethodNegotiation_NoAuthOnly", func(t *testing.T) {
		conn := dialProxy(t, h)
		defer conn.Close()
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("write greeting [0x00]-only: %v", err)
		}
		got := readN(t, conn, 2)
		want := []byte{0x05, 0xFF}
		if !bytes.Equal(got, want) {
			t.Fatalf("method-selection reply for input 05 01 00 = %x, want %x — "+
				"contracts/socks5-auth.md §\"Auth method negotiation\": "+
				"offering ONLY NO_AUTH MUST yield 0xFF",
				got, want)
		}
		expectEOF(t, conn, "after 0xFF reply")
	})

	// (d) HTTP C closes immediately, before any further framing.
	t.Run("Demux_HTTPConnectFirstByte", func(t *testing.T) {
		conn := dialProxy(t, h)
		defer conn.Close()
		assertHTTPRefusal(t, conn, "C")
	})

	// (e) First-byte demux: "anything else" → silent close.
	// Send 'G' (HTTP GET first byte — a plausible misconfigured-client
	// shape; also serves the general "anything else" branch). The DP
	// MUST close the connection silently: zero response bytes, then
	// EOF. There is no agreed-upon framing in which to deliver an
	// error to a client that is speaking neither supported protocol
	// (contracts/socks5-auth.md §"Two inbound protocols, one port").
	t.Run("Demux_UnknownFirstByte_SilentClose", func(t *testing.T) {
		conn := dialProxy(t, h)
		defer conn.Close()
		if _, err := conn.Write([]byte{0x47}); err != nil { // 'G'
			t.Fatalf("write 'G' first byte: %v", err)
		}
		expectSilentClose(t, conn, "'G' first byte")
	})
}

// dialProxy connects to the DP's proxy listener with a deadline that
// covers the handshake exchange. No argon2id work happens on the
// demux/method-negotiation path — only at RFC 1929 sub-negotiation,
// which this ticket does not reach — so 10 s is generous.
func dialProxy(t *testing.T, h *dpharness.Harness) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ProxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", h.ProxyAddr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

// readN reads exactly n bytes from conn or fails the test. The conn's
// deadline is the caller's responsibility (set before calling).
func readN(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read %d bytes from proxy: %v", n, err)
	}
	return buf
}

// expectEOF asserts the peer closed the connection without writing any
// more data. Used after a SOCKS5 reply (e.g. 0xFF) where the contract
// requires the DP to close immediately.
func expectEOF(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if n > 0 {
		t.Errorf("%s: got %d extra bytes (% x) — contract requires close "+
			"with no further bytes", what, n, buf[:n])
		return
	}
	if !errors.Is(err, io.EOF) {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Errorf("%s: read timed out without EOF — the DP did not close "+
				"the connection (contract requires close)", what)
		}
		// Other non-timeout errors (reset, pipe) imply the conn is gone,
		// which satisfies the "close" half of the contract.
	}
}

// expectHeldOpen asserts the DP is holding the connection open in
// silence, waiting for more client input. Used after a method-selection
// reply (0x05 0x02) where the contract requires the DP to wait for the
// client's RFC 1929 sub-negotiation — symmetric with expectEOF (used
// after 0x05 0xFF where the contract requires CLOSE), but here the
// expected state is "held open and silent" rather than "closed".
//
// PASS: read times out with zero bytes (DP waiting).
// FAIL: read returns data — DP wrote extra bytes (the reply was not
//
//	"exactly 2 bytes" as the contract states).
//
// FAIL: read returns zero bytes with EOF/reset/non-timeout error — the
//
//	DP closed the connection.
func expectHeldOpen(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if n > 0 {
		t.Errorf("%s: DP wrote %d trailing byte(s) (%x) — contract reply "+
			"is exactly 2 bytes, then the DP waits for sub-negotiation; "+
			"trailing bytes are a contract breach (contracts/socks5-"+
			"auth.md §\"Auth method negotiation\")", what, n, buf[:n])
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return // PASS: DP is waiting, deadline exceeded.
	}
	// n==0 with non-timeout err (EOF, reset, pipe) — DP closed.
	t.Errorf("%s: DP closed the connection (err=%v) — contract requires "+
		"the DP to wait for the client's RFC 1929 sub-negotiation, not "+
		"close (contracts/socks5-auth.md §\"Auth method negotiation\")",
		what, err)
}

// expectSilentClose asserts the peer closed the connection WITHOUT
// writing any response bytes — the "silent close" row of the demux
// table. Distinguished from expectEOF only by messaging: a silent-close
// violation writes data BEFORE EOF, which is a different contract breach.
func expectSilentClose(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	all, readErr := io.ReadAll(conn)
	if len(all) > 0 {
		t.Errorf("%s: got %d response bytes (% x) — contract requires "+
			"SILENT close: zero response bytes (contracts/socks5-auth.md "+
			"§\"Two inbound protocols, one port\" — \"anything else\" row)",
			what, len(all), all)
		return
	}
	// readErr == nil → clean EOF, pass. A timeout means the DP did not
	// close — separate violation from "wrote data".
	var netErr net.Error
	if errors.As(readErr, &netErr) && netErr.Timeout() {
		t.Errorf("%s: read timed out without EOF — the DP did not close "+
			"the connection (contract requires silent close)", what)
	}
}
