// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package forward implements the data plane's outbound hop (T047): the
// fixed-at-startup SOCKS5 client that dials the Tor sidecar over its
// unix-socket fabric and bridges it to the port-8881 inbound surfaces.
// Byte-level contract: specs/001-tor-route/contracts/socks5-auth.md
// §"Deadlines" and §"SOCKS5 request-phase failures (post-auth)".
//
// Privacy posture (Constitution Principle I / III): the bounded SOCKS5
// handshake forwards non-IP targets as RFC 1928 ATYP=0x03 FQDN — this
// package never resolves a target hostname locally (FR-007). Nothing here
// logs, and no target, username, or token material reaches a client-facing
// reply: the listeners answer failures from the route classification alone
// (FR-008).
package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/listener"
)

// upstreamDialTimeout bounds the dial-and-handshake phase — open the socket to
// the sidecar + SOCKS5 method + auth + request write + BND reply — and
// is the single named constant the contract requires
// (contracts/socks5-auth.md §"Deadlines" row 1), so re-tuning is one
// edit. Row 2: no idle deadline exists after the handshake — the tunnel
// is a deliberately long-lived byte pipe (Principle I, T025b).
//
// 250 s (T208) is a finite backstop against a sidecar that never answers,
// not a judgment about how long a destination may take: it exceeds two of
// Tor's SocksTimeout periods (120 s by default; contracts/torrc.md
// invariant 14 keeps the option unset), so that outside the cases the
// contract lists Tor's own answer — mapped to ROUTE_REFUSED — ends the
// attempt first. The client is not watched during this phase: an abandoned
// request stays pending upstream until Tor answers or this deadline
// expires (THREAT-MODEL §5.10).
const upstreamDialTimeout = 250 * time.Second

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

// Compile-time conformance for the authenticated SOCKS path.
var (
	_ listener.Forwarder  = (*Tor)(nil)
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

var errUpstreamRefused = errors.New("upstream SOCKS5 refused")

// classify maps a dial-and-handshake failure onto the contract's
// three-way route vocabulary.
func classify(err error) error {
	if err == nil {
		return nil
	}
	if isTimeout(err) {
		return routeError{reply: repRouteTimeout, err: err}
	}
	if errors.Is(err, errUpstreamRefused) {
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

// dialUpstream forwards the authenticated SOCKS partition intact with an empty
// upstream password: the bearer never crosses the Tor boundary (Principle III).
// The listener guarantees a nonempty username before this internal call.
func (t *Tor) dialUpstream(uname []byte, target string) (*countingConn, error) {
	network, address := "tcp", t.upstream
	if strings.HasPrefix(address, "unix://") {
		network = "unix"
		address = strings.TrimPrefix(address, "unix://")
	}
	ctx, cancel := context.WithTimeout(context.Background(), t.dialTimeout)
	defer cancel()
	up, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, classify(err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		_ = up.Close()
		return nil, classify(errors.New("upstream dial context has no deadline"))
	}
	if err := up.SetDeadline(deadline); err != nil {
		_ = up.Close()
		return nil, classify(err)
	}
	if err := socks5Connect(up, uname, target); err != nil {
		_ = up.Close()
		return nil, classify(err)
	}
	// The bounded negotiation deadline ends with the SOCKS handshake; the
	// established tunnel has no idle deadline (contract Deadlines row 2).
	if err := up.SetDeadline(time.Time{}); err != nil {
		_ = up.Close()
		return nil, classify(err)
	}
	// Counting wraps HERE, post-handshake: everything before this point is
	// upstream SOCKS5 protocol, not forwarded payload, so byte_count sees
	// only client↔upstream tunnel bytes (data-model.md §3). The synthesised
	// reply bytes the listeners emit live on the client conn and never
	// cross this one.
	return &countingConn{Conn: up, counts: t.counts}, nil
}

// socks5Connect performs the fixed Tor-side RFC 1928/1929 exchange. Only
// USERNAME/PASSWORD is offered; no upstream refusal can establish a tunnel.
func socks5Connect(conn net.Conn, uname []byte, target string) error {
	if len(uname) > 255 {
		return errors.New("SOCKS5 username too long")
	}
	if err := writeSOCKSFrame(conn, []byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	var selection [2]byte
	if _, err := io.ReadFull(conn, selection[:]); err != nil {
		return err
	}
	if selection != [2]byte{0x05, 0x02} {
		return errUpstreamRefused
	}

	auth := make([]byte, 0, 3+len(uname))
	auth = append(auth, 0x01, byte(len(uname))) // #nosec G115 -- RFC 1929 length is bounded above.
	auth = append(auth, uname...)
	auth = append(auth, 0x00) // empty password: PLEN=0
	if err := writeSOCKSFrame(conn, auth); err != nil {
		return err
	}
	var authReply [2]byte
	if _, err := io.ReadFull(conn, authReply[:]); err != nil {
		return err
	}
	if authReply != [2]byte{0x01, 0x00} {
		return errUpstreamRefused
	}

	request, err := socks5ConnectRequest(target)
	if err != nil {
		return err
	}
	if err := writeSOCKSFrame(conn, request); err != nil {
		return err
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[2] != 0x00 || reply[1] != 0x00 {
		return errUpstreamRefused
	}
	var tailLen int
	switch reply[3] {
	case 0x01:
		tailLen = net.IPv4len + 2
	case 0x04:
		tailLen = net.IPv6len + 2
	case 0x03:
		var nameLen [1]byte
		if _, err := io.ReadFull(conn, nameLen[:]); err != nil {
			return err
		}
		tailLen = int(nameLen[0]) + 2
	default:
		return errUpstreamRefused
	}
	var tail [255 + 2]byte
	if tailLen > len(tail) {
		return errUpstreamRefused
	}
	if _, err := io.ReadFull(conn, tail[:tailLen]); err != nil {
		return err
	}
	return nil
}

func writeSOCKSFrame(w io.Writer, frame []byte) error {
	for len(frame) > 0 {
		n, err := w.Write(frame)
		frame = frame[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func socks5ConnectRequest(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}
	if port == 0 {
		return nil, errors.New("SOCKS5 target port out of range")
	}
	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, 0x01)
			request = append(request, ip4...)
		} else if ip16 := ip.To16(); ip16 != nil {
			request = append(request, 0x04)
			request = append(request, ip16...)
		} else {
			return nil, errors.New("unknown SOCKS5 address type")
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("SOCKS5 domain name too long")
		}
		request = append(request, 0x03, byte(len(host))) // #nosec G115 -- RFC 1928 length is bounded above.
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	return request, nil
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
	c.read.Add(uint64(n)) // #nosec G115 -- net.Conn.Read returns a nonnegative byte count
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(uint64(n)) // #nosec G115 -- net.Conn.Write returns a nonnegative byte count
	return n, err
}

// finalize runs only after both pumps have stopped (or before either starts).
// Closing the socket alone does not join Read/Write's accounting increments:
// T149 / data-model.md §3 requires their complete total at request close.
func (c *countingConn) finalize() {
	c.flush.Do(func() {
		c.counts.AddForwardedBytes(c.read.Load() + c.written.Load())
	})
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
		_ = up.Close() // client reply failed; close is best effort and original error is returned
		up.finalize()
		return err
	}
	bridge(client, up)
	return nil
}

// bridge pumps client↔upstream until either direction finishes, then
// closes the upstream — the only conn this package owns; the client's
// close stays with the listener. Pipe errors are deliberately swallowed:
// a mid-tunnel break ends the connection, it does not become a reply.
// Cancel pending client I/O before joining: the listener cannot close its
// connection until Forward returns. The deadline is shutdown-only, never an
// idle timeout on a live tunnel (socks5-auth.md §Deadlines).
func bridge(client net.Conn, upstream *countingConn) {
	defer upstream.finalize()
	var stop sync.Once
	shutdown := func() {
		stop.Do(func() {
			_ = upstream.Close() // shutdown is best effort; the connection cannot be reused
			_ = client.SetDeadline(time.Now())
		})
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(upstream, client)
		shutdown()
	}()
	_, _ = io.Copy(client, upstream)
	shutdown()
	<-done
}
