// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package listener implements the data plane's port-8881 inbound proxy
// surface (FR-005): bounded protocol refusal and the SOCKS5 (RFC 1928 + RFC 1929) auth framing, and the
// RFC 1928 §4 request-phase read. The byte-level contract is
// specs/001-tor-route/contracts/socks5-auth.md.
//
// Framing only (Constitution Principle I — dumb router): this package
// parses exactly the fields the protocols require, performs no name
// resolution (FR-007), inspects no payload, and emits no per-request
// log line (FR-008). Auth is delegated to Verifier (T044 auth/token.go),
// forwarding to Forwarder (T047 forward/tor.go), aggregates to Audit
// (T049 audit/counters.go); Deps is the single wiring point, filled once
// by the startup sequence (T050 cmd/stargate-proxy/main.go).
package listener

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// inboundHandshakeTimeout bounds the client-facing framing phase (demux
// through the RFC 1928 §4 request read). Generous by design — a healthy
// loopback client never sees it; its purpose is stopping a stalled or
// malicious local client from pinning a goroutine forever. It is
// cleared before the byte-pipe handoff: the contract forbids any
// post-handshake idle deadline (contracts/socks5-auth.md §"Deadlines";
// T025b). The separate 30 s UPSTREAM dial deadline lives in
// forward/tor.go (T047) per the contract's implementation note.
const inboundHandshakeTimeout = 30 * time.Second

// SOCKS5 wire constants (RFC 1928 §2–§4, RFC 1929 §2).
const (
	socks5Version  = 0x05
	userPassVer    = 0x01 // RFC 1929 sub-negotiation version
	methodUserPass = 0x02 // USERNAME/PASSWORD (RFC 1929 §3)
	methodNoAccept = 0xFF // no acceptable methods
	authSuccess    = 0x00 // RFC 1929 status: success
	authFailure    = 0xFF // RFC 1929 status: failure

	cmdConnect = 0x01 // RFC 1928 §4 CMD — the only command v1 forwards

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// REP codes for the framing-failure replies the route layer does not
	// classify. ROUTE_DOWN/REFUSED/TIMEOUT (0x03/0x04/0x06) come from
	// the route error itself (RouteError, T047's classification);
	// contracts/socks5-auth.md §"SOCKS5 request-phase failures".
	repGeneralFailure = 0x01
	repCommandNotSupp = 0x07
	repAddressNotSupp = 0x08
)

// Verifier is the auth seam (implemented by data-plane/internal/auth,
// T044). The candidate arrives as the raw RFC 1929 PASSWD bytes — this
// package applies NO format gate and does no hashing (Principle I:
// framing only); the auth seam rejects malformed candidates before any
// hash work and verifies constant-time across the whole verifier list
// (data-model.md §1.5; the T093 contract in hmac_verifier_test.go).
// Every auth failure — missing, malformed, or mismatched — yields the
// byte-identical `01 FF` reply (research.md §9), so the response cannot
// distinguish them, and nothing about the candidate is logged (FR-008).
type Verifier interface {
	VerifyPassword(candidate []byte) bool
}

// RouteError classifies a forwarding failure into the RFC 1928 §6 REP
// code the SOCKS5 failure reply carries (FR-009): ROUTE_DOWN→0x03,
// ROUTE_REFUSED→0x04, ROUTE_TIMEOUT→0x06.
type RouteError interface {
	error
	SOCKS5Reply() byte
}

// Forwarder is the forwarding seam (implemented by
// data-plane/internal/forward, T047). Ownership contract at the seam:
// Forward dials the fixed upstream for target and bridges
// client↔upstream as a transparent byte pipe until either end closes
// (Principle I). It owns and closes the upstream connection but NEVER
// closes the client conn — the listener owns the client conn for the
// connection's whole life and writes the failure reply itself when
// Forward returns an error.
type Forwarder interface {
	Forward(client net.Conn, uname []byte, target string) error
}

// Audit is the aggregate-counter seam (implemented by
// data-plane/internal/audit, T049). AuthPassedRequest fires exactly
// once per auth-passed request — never on auth failures (FR-008:
// counting them would side-channel token guessing). Route failures
// after auth pass still count, so the seam fires BEFORE the request
// phase and the route outcome is irrelevant to it.
type Audit interface {
	AuthPassedRequest()
}

// Deps is the wiring point for the port-8881 inbound surface. The
// startup sequence (T050) fills every field before the first connection
// is accepted; all fields must be non-nil whenever HandleConn runs (no
// defensive nil checks inside the trust boundary — CONTRIBUTING.md).
type Deps struct {
	Auth    Verifier
	Forward Forwarder
	Audit   Audit
}

// HandleConn serves one accepted port-8881 connection: it sniffs the
// first byte and dispatches per the contract's demux table
// (contracts/socks5-auth.md §"HTTP CONNECT refusal").
// It owns conn for the connection's whole life and closes it on every
// path.
func HandleConn(conn net.Conn, d *Deps) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(inboundHandshakeTimeout))

	var first [1]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return // client vanished before speaking — nothing to reply to
	}
	switch first[0] {
	case socks5Version:
		handleSOCKS5(conn, d)
	default:
		// Unsupported ingress, including HTTP C, closes before auth,
		// counters or upstream dial (T173; Constitution III). Silent close
		// with zero response bytes — there is no agreed framing in
		// which an error could be delivered (contract demux table,
		// "anything else" row).
	}
}

// handleSOCKS5 runs the SOCKS5 path: method negotiation (RFC 1928 §3),
// username/password sub-negotiation (RFC 1929), then the request-phase
// read (RFC 1928 §4) and the forward handoff.
func handleSOCKS5(conn net.Conn, d *Deps) {
	// -- Method negotiation: USERNAME/PASSWORD is the only method v1
	// selects; a client not offering it (NO_AUTH-only, empty list) gets
	// the exact 2-byte `05 FF` and a close — the data plane never
	// accepts unauthenticated SOCKS5 (THREAT-MODEL §3.1).
	var nmethods [1]byte
	if _, err := io.ReadFull(conn, nmethods[:]); err != nil {
		return
	}
	methods := make([]byte, nmethods[0])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if !bytes.Contains(methods, []byte{methodUserPass}) {
		_, _ = conn.Write([]byte{socks5Version, methodNoAccept})
		return
	}
	if _, err := conn.Write([]byte{socks5Version, methodUserPass}); err != nil {
		return
	}

	// -- Sub-negotiation framing (RFC 1929). Every framing deviation and
	// every auth rejection produce the byte-identical `01 FF` + close —
	// the 2-byte reply plus close is the ENTIRE failure surface, with
	// no distinguishing substring across missing/malformed/empty
	// cases (FR-006; research.md §9). Nothing is logged.
	uname, passwd, ok := readUserPass(conn)
	if !ok || !d.Auth.VerifyPassword(passwd) {
		_, _ = conn.Write([]byte{userPassVer, authFailure})
		return
	}
	// FR-008: the count fires here — auth passed, route outcome
	// irrelevant. It precedes the success reply byte so the counter is
	// already consistent when the client can observe success; never
	// earlier (auth failures must not count).
	d.Audit.AuthPassedRequest()
	if _, err := conn.Write([]byte{userPassVer, authSuccess}); err != nil {
		return
	}

	// -- Request phase (RFC 1928 §4): read the target, never resolve it.
	target, rep, ok := readRequestTarget(conn)
	if !ok {
		if rep != 0 {
			writeFailureReply(conn, rep)
		}
		// rep == 0: the client broke its own protocol after auth —
		// silent close; the auth-pass count stands (FR-008).
		return
	}

	// Byte-pipe phase from here: no idle deadline (contracts/
	// socks5-auth.md §"Deadlines" — the connection lives until either
	// end closes; T025b).
	_ = conn.SetDeadline(time.Time{})
	if err := d.Forward.Forward(conn, uname, target); err != nil {
		writeFailureReply(conn, routeRep(err))
	}
	// Success: Forward pumped both directions to completion; the client
	// conn is closed by HandleConn's defer.
}

// readUserPass reads the full RFC 1929 username/password message and
// only then classifies it. The drain-before-reply ordering is
// deliberate: replying while client bytes of the same message remain
// unread would make the subsequent close send RST (close with unread
// receive-buffer data), which on some stacks discards the queued reply
// before the client reads it. ok=false on any framing deviation (wrong
// version, zero-length field, early EOF) — the caller folds all of
// them into the same `01 FF`.
func readUserPass(conn net.Conn) (uname, passwd []byte, ok bool) {
	var ver [1]byte
	if _, err := io.ReadFull(conn, ver[:]); err != nil {
		return nil, nil, false
	}
	var ulen [1]byte
	if _, err := io.ReadFull(conn, ulen[:]); err != nil {
		return nil, nil, false
	}
	uname = make([]byte, ulen[0])
	if _, err := io.ReadFull(conn, uname); err != nil {
		return nil, nil, false
	}
	var plen [1]byte
	if _, err := io.ReadFull(conn, plen[:]); err != nil {
		return nil, nil, false
	}
	passwd = make([]byte, plen[0])
	if _, err := io.ReadFull(conn, passwd); err != nil {
		return nil, nil, false
	}
	if ver[0] != userPassVer || ulen[0] == 0 || plen[0] == 0 {
		return nil, nil, false
	}
	return uname, passwd, true
}

// readRequestTarget reads the full RFC 1928 §4 request and only then
// classifies it (same drain-before-reply rationale as readUserPass).
// Returns (target, 0, true) on success; ("", rep, false) when a failure
// reply is owed (CMD/ATYP problems); ("", 0, false) when the client is
// gone or violated the framing after auth (silent close).
//
// The one undrainable case is an unknown ATYP: its address length is
// unknowable, so the `0x08` reply goes out with any trailing client
// bytes still unread. Only a client that is already speaking garbage
// reaches that row; no contract surface depends on its delivery.
//
// Target rendering never resolves anything (FR-007 / Principle III): a
// DOMAIN target is forwarded verbatim (SOCKS5h), IP-literal targets are
// re-rendered as literals (IPv6 bracketed per RFC 3986 so the dial
// address is unambiguous).
func readRequestTarget(conn net.Conn) (target string, rep byte, ok bool) {
	var hdr [4]byte // VER CMD RSV ATYP
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", 0, false
	}
	if hdr[0] != socks5Version {
		return "", 0, false
	}
	var addrLen int
	switch hdr[3] {
	case atypIPv4:
		addrLen = net.IPv4len
	case atypIPv6:
		addrLen = net.IPv6len
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return "", 0, false
		}
		addrLen = int(l[0]) // 0 stays drainable: only the port follows
	default:
		return "", repAddressNotSupp, false
	}
	addr := make([]byte, addrLen)
	if _, err := io.ReadFull(conn, addr); err != nil {
		return "", 0, false
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", 0, false
	}
	if hdr[1] != cmdConnect {
		return "", repCommandNotSupp, false
	}
	if hdr[3] == atypDomain && addrLen == 0 {
		return "", repAddressNotSupp, false
	}
	portNum := strconv.Itoa(int(port[0])<<8 | int(port[1]))
	if hdr[3] == atypDomain {
		return string(addr) + ":" + portNum, 0, true
	}
	host := net.IP(addr).String()
	if hdr[3] == atypIPv6 {
		host = "[" + host + "]"
	}
	return host + ":" + portNum, 0, true
}

// routeRep maps a forward error to its REP code; an error that carries
// no classification gets the RFC's general-failure code.
func routeRep(err error) byte {
	var re RouteError
	if errors.As(err, &re) {
		return re.SOCKS5Reply()
	}
	return repGeneralFailure
}

// writeFailureReply emits the 10-byte RFC 1928 §6 failure reply. BND.ADDR
// and BND.PORT are always zeroed — they must never echo the request's
// target, the upstream's address, or any port-derived value, because
// those fields would be a destination-metadata leak on the failure path
// (FR-009; contracts/socks5-auth.md §"SOCKS5 request-phase failures").
// Best-effort write: a client that already vanished cannot be replied
// to, and nothing about the attempt is logged (FR-008).
func writeFailureReply(conn net.Conn, rep byte) {
	_, _ = conn.Write([]byte{socks5Version, rep, 0x00, atypIPv4,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
