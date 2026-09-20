// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package forward implements the data plane's outbound hop (T047): the
// fixed-at-startup SOCKS5 client that dials the Tor sidecar over its
// unix-socket fabric and bridges it to the port-8881 inbound surfaces.
// Byte-level contract: specs/001-tor-route/contracts/socks5-auth.md
// §"Deadlines" and §"SOCKS5 request-phase failures (post-auth)".
//
// Privacy posture (Constitution Principle I / III): the SOCKS5 handshake
// is delegated to golang.org/x/net/proxy, whose client forwards non-IP
// targets as RFC 1928 ATYP=0x03 FQDN — this package never resolves a
// target hostname locally (FR-007). Nothing here logs, and no target,
// username, or token material reaches a client-facing reply: the
// listeners answer failures from the route classification alone (FR-008).
package forward

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/zcat-app/stargate/data-plane/internal/listener"
)

// upstreamDialTimeout bounds the dial-and-handshake phase — open the socket to
// the sidecar + SOCKS5 method + auth + request write + BND reply — and
// is the single named constant the contract requires
// (contracts/socks5-auth.md §"Deadlines" row 1), so re-tuning is one
// edit. Row 2: no idle deadline exists after the handshake — the tunnel
// is a deliberately long-lived byte pipe (Principle I, T025b).
const upstreamDialTimeout = 30 * time.Second

// Route classification REP codes (contracts/socks5-auth.md §"SOCKS5
// request-phase failures (post-auth)").
const (
	repRouteDown    = 0x03 // upstream sidecar unreachable — no TCP connection
	repRouteRefused = 0x04 // sidecar accepted SOCKS5 but refused the target
	repRouteTimeout = 0x06 // upstream dial+I/O deadline exceeded
)

// successReply is the RFC 1928 §6 BND reply the inbound SOCKS5 client
// receives once the upstream handshake succeeds: VER=05 REP=00 RSV=00
// ATYP=01, BND.ADDR=0.0.0.0 BND.PORT=0. BND is always zeroed — never an
// echo of the upstream's BND (destination-metadata hygiene, Principle
// III; the failure replies in listener keep the same rule).
var successReply = [...]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

// ByteCounter is the aggregate-counter seam (implemented by
// data-plane/internal/audit, T049): one AddForwardedBytes call per request
// at close, carrying the total bytes the tunnel moved in both directions —
// the byte_count increment of data-model.md §3. The constructor requires
// it (T050 wires the boot's Counters); there is no nil path inside the
// trust boundary (CONTRIBUTING doctrine).
type ByteCounter interface {
	AddForwardedBytes(n uint64)
}

// Tor is the outbound hop: one sidecar address, pinned at construction
// (startup wiring, T050) — there is no per-request route or upstream
// selection (Principle I; FR-005's port-8881→Tor binding).
type Tor struct {
	upstream string
	counts   ByteCounter

	// dialTimeout is upstreamDialTimeout except in tests, which shorten
	// it to keep the ROUTE_TIMEOUT classification observable.
	dialTimeout time.Duration
}

// New pins the upstream sidecar address and the counter for the process
// lifetime.
func New(upstream string, counts ByteCounter) *Tor {
	return &Tor{upstream: upstream, counts: counts, dialTimeout: upstreamDialTimeout}
}

// Compile-time seam conformance with the landed inbound surfaces
// (T042/T043): the SOCKS5 path fuses dial+bridge in Forwarder; the HTTP
// CONNECT path needs the split Tunneler because its `200` status line
// may only follow a successful upstream handshake; errors classify
// through listener.RouteError via errors.As.
var (
	_ listener.Forwarder  = (*Tor)(nil)
	_ listener.Tunneler   = (*Tor)(nil)
	_ listener.RouteError = routeError{}
)

// routeError carries the route classification for the listeners'
// failure replies. The wrapped text is never client-visible and never
// logged — the listeners reply by class alone.
type routeError struct {
	reply byte
	err   error
}

func (e routeError) Error() string     { return e.err.Error() }
func (e routeError) SOCKS5Reply() byte { return e.reply }
func (e routeError) Unwrap() error     { return e.err }

// classify maps a dial-and-handshake failure onto the contract's
// three-way route vocabulary.
//
// The REFUSED row leans on x/net v0.54.0's only upstream-refusal
// surface: a completed handshake whose BND reply carried a non-zero REP
// comes back as a *net.OpError wrapping plain
// errors.New("unknown error <reply>"), and an RFC 1929 rejection as
// errors.New("username/password authentication failed"). Neither is
// typed, so classification keys on that wrapper text — pinned by
// go.mod and by TestForwardUpstreamRefusalIsRouteRefused, which drives
// the real client bytes; a dependency upgrade that changes the surface
// fails there, not in production.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if isTimeout(err) {
		return routeError{reply: repRouteTimeout, err: err}
	}
	if refusedByUpstream(err) {
		return routeError{reply: repRouteRefused, err: err}
	}
	return routeError{reply: repRouteDown, err: err}
}

// isTimeout reports whether err is a deadline expiry anywhere in the
// dial-and-handshake phase — the ctx deadline (context) or the conn
// deadline x/net derives from it (os/net).
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// refusedByUpstream reports whether the sidecar itself answered and
// refused (see classify for the wrapper-string coupling).
func refusedByUpstream(err error) bool {
	var oe *net.OpError
	if !errors.As(err, &oe) {
		return false
	}
	msg := oe.Err.Error()
	return strings.HasPrefix(msg, "unknown error ") ||
		msg == "username/password authentication failed"
}

// dialUpstream opens the fixed upstream and completes the SOCKS5
// handshake for target. uname non-empty sends it verbatim as the
// upstream SOCKS5 username (FR-007 — the US2 IsolateSOCKSAuth key) with
// an empty password (PLEN=0): the inbound PASSWD is the bearer token,
// auth-layer material that is never re-sent upstream. uname empty (the
// HTTP CONNECT path carries no username) offers NO_AUTH only — x/net
// rejects an empty user/pass pair outright, and US2's per-first-party
// isolation is SOCKS5-framed. The client is rebuilt per call because
// x/net bakes the credentials into the dialer.
func (t *Tor) dialUpstream(uname []byte, target string) (net.Conn, error) {
	var auth *proxy.Auth
	if len(uname) > 0 {
		auth = &proxy.Auth{User: string(uname)}
	}
	network, address := "tcp", t.upstream
	if strings.HasPrefix(address, "unix://") {
		network = "unix"
		address = strings.TrimPrefix(address, "unix://")
	}
	d, err := proxy.SOCKS5(network, address, auth, nil)
	if err != nil {
		return nil, classify(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.dialTimeout)
	defer cancel()
	// Hard assertion, not a checked fallback: x/net's SOCKS5 dialer has
	// implemented ContextDialer since context support landed; a build
	// that loses it must fail loudly, not silently drop the deadline.
	up, err := d.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, classify(err)
	}
	// DialContext cleared the conn deadline on return (x/net defers
	// SetDeadline(zero) after the handshake) — post-handshake the tunnel
	// is deadline-free per contract row 2.
	// Counting wraps HERE, post-handshake: everything before this point is
	// upstream SOCKS5 protocol, not forwarded payload, so byte_count sees
	// only client↔upstream tunnel bytes (data-model.md §3). The synthesised
	// reply bytes the listeners emit live on the client conn and never
	// cross this one.
	return &countingConn{Conn: up, counts: t.counts}, nil
}

// countingConn tallies the bytes the tunnel moves and hands the total to
// the counter exactly once, at close — the "at request close" increment of
// data-model.md §3. Reads are upstream→client, Writes client→upstream;
// their sum is the request's byte_count delta. The tallies are atomic
// because bridge pumps the two directions from different goroutines.
type countingConn struct {
	net.Conn
	counts        ByteCounter
	read, written atomic.Uint64
	flush         sync.Once
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(uint64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(uint64(n))
	return n, err
}

// Close flushes before the underlying close. bridge closes the upstream
// from both pump goroutines, so the once-guard is what keeps the count
// from doubling; every Forward/Pipe path closes this conn (the ownership
// contract this package's seams state), so the flush cannot be skipped.
func (c *countingConn) Close() error {
	c.flush.Do(func() {
		c.counts.AddForwardedBytes(c.read.Load() + c.written.Load())
	})
	return c.Conn.Close()
}

// Forward implements listener.Forwarder (SOCKS5 inbound path): dial the
// fixed upstream for target, emit the zeroed success reply, then bridge
// client↔upstream until either end closes (Principle I). Errors are
// classified for the listener's RFC 1928 failure reply; once the tunnel
// is established the return is always nil — injecting failure bytes into
// a live tunnel is forbidden (T070a). Never touches client's close: the
// listener owns that conn for its whole life (T042 seam contract).
func (t *Tor) Forward(client net.Conn, uname []byte, target string) error {
	up, err := t.dialUpstream(uname, target)
	if err != nil {
		return err
	}
	if _, err := client.Write(successReply[:]); err != nil {
		up.Close()
		return err
	}
	bridge(client, up)
	return nil
}

// Dial implements listener.Tunneler (HTTP CONNECT inbound path): open
// the fixed upstream and complete the SOCKS5 handshake; the caller
// writes `200` only after this succeeds (T043 response ordering).
func (t *Tor) Dial(target string) (net.Conn, error) {
	return t.dialUpstream(nil, target)
}

// Pipe implements listener.Tunneler's bridge phase with the same
// semantics as bridge; the return is always nil because connect.go
// must not inject bytes into an established tunnel (its own contract
// note at the call site).
func (t *Tor) Pipe(client, upstream net.Conn) error {
	bridge(client, upstream)
	return nil
}

// bridge pumps client↔upstream until either direction finishes, then
// closes the upstream — the only conn this package owns; the client's
// close stays with the listener. Pipe errors are deliberately swallowed:
// a mid-tunnel break ends the connection, it does not become a reply.
// The client→upstream goroutine may outlive the return by one pending
// client Read — HandleConn's deferred client Close unblocks it, so
// nothing outlives the connection.
func bridge(client, upstream net.Conn) {
	go func() {
		_, _ = io.Copy(upstream, client)
		upstream.Close()
	}()
	_, _ = io.Copy(client, upstream)
	upstream.Close()
}
