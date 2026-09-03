// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// HTTP CONNECT inbound framing for the port-8881 proxy surface (T043),
// dispatched here by the first-byte demux in socks5.go with the leading
// 'C' already consumed. Byte-level contract:
// specs/001-tor-route/contracts/socks5-auth.md §"HTTP CONNECT path" and
// specs/001-tor-route/contracts/error-template.md §"Wire format".
//
// Framing only (Constitution Principle I): the request line and the
// Proxy-Authorization header are the ONLY input this file interprets —
// every other header line is consumed byte-wise to find the blank line
// and never branched on (FR-007). No name resolution, no payload
// inspection, no per-request log (FR-008).
package listener

import (
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// connectHeaderBudget bounds the whole header block (request line +
// headers + terminator). Edge-input validation: without it a local
// client could pin unbounded memory per connection by streaming
// headers; the value is an nginx-class default, generous for the
// canonical request (~100 bytes). Overflow is a framing violation —
// silent close.
const connectHeaderBudget = 8 * 1024

// httpConnectOK is the byte-exact auth-success response: status line +
// header-terminating blank line, nothing else — no Date, no
// Proxy-Agent, no body (T026's exact-bytes gate).
const httpConnectOK = "HTTP/1.1 200 Connection Established\r\n\r\n"

// ErrorCode is the fixed response-code vocabulary the error-template
// contract defines for the HTTP CONNECT path
// (contracts/error-template.md §"Wire format").
type ErrorCode string

const (
	CodeAuthRequired ErrorCode = "AUTH_REQUIRED"
	CodeRouteDown    ErrorCode = "ROUTE_DOWN"
	CodeRouteRefused ErrorCode = "ROUTE_REFUSED"
	CodeRouteTimeout ErrorCode = "ROUTE_TIMEOUT"
)

// REP codes this file maps to template codes; these three are produced
// by the route layer (T047's RouteError classification), unlike the
// framing REPs named in socks5.go.
const (
	repRouteDown    = 0x03
	repRouteRefused = 0x04
	repRouteTimeout = 0x06
)

// Tunneler is the CONNECT-path forwarding seam (implemented by
// data-plane/internal/forward, T047). It is split where Forwarder is
// fused because the CONNECT contract orders the status line AFTER the
// upstream result: `200` only once the upstream SOCKS5 handshake has
// succeeded, the route-error template when it has not (FR-009;
// error-template contract row 3; T065). The SOCKS5 path's fused seam
// cannot express that — its failure reply travels inside the RFC 1928
// request reply, a framing this path does not have.
type Tunneler interface {
	// Dial opens the fixed upstream SOCKS5 connection and completes the
	// SOCKS5 handshake for target (SOCKS5h — no local resolution,
	// FR-007). Errors classify via RouteError for the template-code
	// mapping. The CONNECT framing carries no username, so Dial takes
	// none; US2's per-first-party stream isolation is SOCKS5-framed.
	Dial(target string) (net.Conn, error)

	// Pipe bridges client↔upstream as a transparent byte pipe until
	// either end closes (Principle I). Ownership contract at the seam:
	// Pipe owns and closes upstream but NEVER touches client — the
	// listener owns the client conn for the connection's whole life.
	Pipe(client, upstream net.Conn) error
}

// ErrorRenderer is the failure-response seam (implemented by
// data-plane/internal/errortpl/render.go, T048 v1 / T071 route codes).
// WriteFailure emits the complete response for code — status line,
// exactly the four contract headers in declared order, and the
// rendered template body — whose bytes MUST NOT vary with WHY the
// failure happened and MUST NOT carry the destination, the offered
// token, or any request-derived value (error-template §"Forbidden";
// FR-006/FR-009). The caller closes the connection afterwards; a write
// error is best-effort (a vanished client cannot be replied to) and is
// never logged.
type ErrorRenderer interface {
	WriteFailure(w io.Writer, code ErrorCode) error
}

// ConnectDeps is the wiring point for the HTTP CONNECT inbound surface.
// T050 closure-wires HandleConnect into Deps.Connect; all fields must
// be non-nil whenever HandleConnect runs (no defensive nil checks
// inside the trust boundary — CONTRIBUTING.md).
type ConnectDeps struct {
	Auth     Verifier
	Tunnel   Tunneler
	Audit    Audit
	Renderer ErrorRenderer
}

// HandleConnect serves one HTTP CONNECT connection; conn arrives
// positioned after the demux consumed the leading 'C'. It owns the
// connection from that point (closing stays with HandleConn's defer)
// and returns on every path.
//
// Response ordering (contract §"HTTP CONNECT path"): the auth verdict
// precedes everything — a failure gets the AUTH_REQUIRED template and a
// close; a pass dials the upstream and only then answers `200` (or the
// route-error template), so the status line always reflects the true
// tunnel outcome.
func HandleConnect(conn net.Conn, d *ConnectDeps) {
	authority, token, ok := readConnectRequest(conn)
	if !ok {
		// The client never produced a parseable CONNECT request line:
		// framing garbage. The contract defines no 400-class response —
		// silent close with zero bytes (the SOCKS5 path's post-auth
		// framing precedent), auth never consulted.
		return
	}
	if !validBearerToken(token) || !d.Auth.VerifyPassword(token) {
		// Every auth failure — header absent, scheme not `Bearer `,
		// format-gate fail, verifier mismatch — renders the same
		// AUTH_REQUIRED response; the short-circuit keeps a
		// format-invalid candidate from ever reaching the hash.
		d.Renderer.WriteFailure(conn, CodeAuthRequired)
		return
	}
	// FR-008 asymmetry: the count fires here — auth passed, route
	// outcome irrelevant — and never on the failure paths above.
	d.Audit.AuthPassedRequest()

	upstream, err := d.Tunnel.Dial(authority)
	if err != nil {
		d.Renderer.WriteFailure(conn, routeCode(err))
		return
	}
	if _, err := io.WriteString(conn, httpConnectOK); err != nil {
		_ = upstream.Close()
		return
	}
	// Byte-pipe phase from here: no idle deadline (contracts/
	// socks5-auth.md §"Deadlines"; T025b).
	_ = conn.SetDeadline(time.Time{})
	// Pipe's outcome only decides when the connection ends — a failure
	// mid-tunnel closes it; injecting bytes into an established tunnel
	// is forbidden.
	_ = d.Tunnel.Pipe(conn, upstream)
}

// readConnectRequest reads the CONNECT request byte-at-a-time up to and
// including the header-terminating blank line. The byte-at-a-time read
// is load-bearing, not style: a buffered reader would over-read past
// the blank line and swallow the client's first tunnel bytes (T026
// redteam scope (a), DP side). Returns (authority, token, true) on a
// parseable request — token nil when no Proxy-Authorization header was
// present, first header winning — or ("", nil, false) on any framing
// violation (silent-close row in the ticket §Analysis).
//
// Only the request line and Proxy-Authorization values are interpreted;
// every other line is skipped after a name check and never stored
// (FR-007 — no header inspection beyond what auth requires).
func readConnectRequest(conn net.Conn) (authority string, token []byte, ok bool) {
	var consumed int
	line, n, ok := readCRLFLine(conn, connectHeaderBudget-consumed)
	if !ok {
		return "", nil, false
	}
	consumed += n
	authority, ok = parseRequestLine(line)
	if !ok {
		return "", nil, false
	}
	for {
		line, n, ok = readCRLFLine(conn, connectHeaderBudget-consumed)
		if !ok {
			return "", nil, false
		}
		consumed += n
		if line == "" {
			return authority, token, true // blank line: end of headers
		}
		if token == nil {
			token = parseProxyAuthorization(line)
		}
	}
}

// readCRLFLine reads one CR LF-terminated line byte-at-a-time, capped at
// budget bytes, returning the line without the CRLF and its consumed
// byte count (CRLF included). A bare LF, an EOF, or an over-budget line
// is a framing failure (ok=false).
func readCRLFLine(conn net.Conn, budget int) (line string, consumed int, ok bool) {
	if budget <= 0 {
		return "", 0, false
	}
	var b [1]byte
	var sb strings.Builder
	for {
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", 0, false // client vanished mid-request
		}
		consumed++
		if b[0] == '\n' {
			l := sb.String()
			if !strings.HasSuffix(l, "\r") {
				return "", 0, false // bare LF: not our client's protocol
			}
			return l[:len(l)-1], consumed, true
		}
		if consumed > budget {
			return "", 0, false
		}
		sb.WriteByte(b[0])
	}
}

// parseRequestLine validates `ONNECT <authority> HTTP/1.1` (the leading
// 'C' was consumed by the demux). Method and version are case-sensitive
// literals per the contract's canonical request; the authority must be
// host:port-shaped (authority-form) but is never canonicalised or
// resolved — it is forwarded verbatim (FR-007, SOCKS5h).
func parseRequestLine(line string) (string, bool) {
	const prefix = "ONNECT "
	const suffix = " HTTP/1.1"
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, suffix) {
		return "", false
	}
	authority := line[len(prefix) : len(line)-len(suffix)]
	if !authorityForm(authority) {
		return "", false
	}
	return authority, true
}

// authorityForm accepts `host:port` structurally: non-empty host, a
// 1–5-digit port after the LAST colon (which keeps bracketed IPv6
// literals like `[::1]:443` intact without interpreting the host).
// Anything DNS-worthy about the host is the upstream's problem — this
// side resolves nothing.
func authorityForm(authority string) bool {
	i := strings.LastIndexByte(authority, ':')
	if i <= 0 || i == len(authority)-1 {
		return false
	}
	port := authority[i+1:]
	if len(port) > 5 {
		return false
	}
	for j := 0; j < len(port); j++ {
		if port[j] < '0' || port[j] > '9' {
			return false
		}
	}
	return true
}

// parseProxyAuthorization interprets ONLY a Proxy-Authorization header
// line and returns its bearer token, or nil. The name match is
// ASCII-case-insensitive (HTTP header names are case-insensitive) and
// EXACT — prefix/suffix lookalikes are other headers and must never
// authenticate. The scheme is the contract's case-sensitive literal
// `Bearer `; the token must be exactly 32 lowercase hex per the
// contract's `^[0-9a-f]{32}$` pre-hash gate (validated by
// validBearerToken, after this returns).
func parseProxyAuthorization(line string) []byte {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return nil // header-less line: skip, not our header
	}
	if !strings.EqualFold(line[:colon], "Proxy-Authorization") {
		return nil
	}
	value := strings.Trim(line[colon+1:], " \t") // OWS
	const scheme = "Bearer "
	if !strings.HasPrefix(value, scheme) {
		return nil
	}
	return []byte(value[len(scheme):])
}

// validBearerToken enforces the contract's syntactic gate
// `^[0-9a-f]{32}$` before hashing; a nil token (header absent) fails.
func validBearerToken(token []byte) bool {
	if len(token) != 32 {
		return false
	}
	for _, c := range token {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// routeCode maps a Dial failure to its template code via the route
// layer's REP classification (0x03/0x04/0x06, T047). An unclassified
// error means the sidecar path is broken — ROUTE_DOWN is the honest
// template, never a request-derived or empty value.
func routeCode(err error) ErrorCode {
	var re RouteError
	if errors.As(err, &re) {
		switch re.SOCKS5Reply() {
		case repRouteRefused:
			return CodeRouteRefused
		case repRouteTimeout:
			return CodeRouteTimeout
		}
	}
	return CodeRouteDown
}
