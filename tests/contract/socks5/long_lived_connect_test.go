// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the long-lived bidirectional CONNECT byte-pipe
// invariant — Constitution Principle I (dumb router), specs/001-tor-
// route/spec.md FR-005/FR-006/FR-007/FR-008 and §"Edge Cases" rows
// "WebSocket upgrade through CONNECT" + "HTTP/2 connections (forced
// fallback from QUIC)" (both mechanically subsumed: after the SOCKS5/
// CONNECT handshake completes, any TLS-over-CONNECT payload is opaque
// bytes to the data plane, so the byte-transparency assertion covers
// every protocol shape without protocol-specific tests), and
// contracts/socks5-auth.md §"Deadlines" (post-handshake deadline is
// "none — long-lived") + §"HTTP CONNECT path". Task body:
// specs/001-tor-route/tasks.md T025b.
//
// Two tunnels are opened through the DP's port-8881 listener to the
// accept-and-relay fake upstream (T019a) — one via authenticated
// SOCKS5, one via HTTP CONNECT + Proxy-Authorization: Bearer — and
// each exchanges a deterministic, seeded byte stream for ≥30 s (mixed
// frame sizes, bursty vs. trickle phases, idle gaps up to 5 s).
// Because the upstream is an echo, every byte traverses the DP once
// in each direction; the reader regenerates the expected stream from
// the same seed and compares chunk-by-chunk, so insertion, deletion,
// reordering, or rewriting in EITHER direction surfaces as a
// divergence (offset reported, bytes withheld — leak-safe failures).
// The journal delta around the exchange is held to the T025a shared
// allowlist (tests/internal/loginvariants) — the DP must not narrate
// frame traffic.
//
// Anti echo-false-pass (redteam finding 20260706-002 class): a DP
// that short-circuited to a local echo without forwarding would pass
// the transparency assertion, so the SOCKS5 leg's distinctive UNAME
// is asserted present in upstream.CircuitIDs() — proof the traffic
// transited the fake, doubling as FR-007 username-passed-through-
// unchanged evidence. See the ticket §Analysis residue for the
// CONNECT leg's indirect equivalent.
//
// Tests-first (Constitution Principle VII): content-gates on T042/
// T045/T050 (dpharness boot minimum) plus T044 auth/token.go, T047
// forward/tor.go, T045 controlclient/client.go, and T043
// listener/connect.go; the test SKIPs until all land, then a byte-pipe
// or log regression is FAIL, not SKIP.
package socks5

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/contract/internal/fakecp"
	integration "github.com/zcat-app/stargate/tests/integration"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

// longLivedPlaintext is the bearer-token plaintext for both legs. 32
// hex chars — the CONNECT path's syntactic gate (contracts/socks5-
// auth.md §"HTTP CONNECT path" step 2: ^[0-9a-f]{32}$) must pass so
// the tunnel opens. Distinct from T025a's token so a corpus hit is
// attributable to this test.
const longLivedPlaintext = "f0e1d2c3b4a5968778695a4b3c2d1e0f"

// minExchange is the ≥30 s the task body mandates, measured per leg
// from first payload write to writer completion (probe included). The
// writer's schedule is time-based, so slow CI stretches the run rather
// than shrinking coverage.
const minExchange = 30 * time.Second

// mainPhaseDuration + longIdleGap + probe round-trip is the writer's
// wall-clock floor (≈26 s + 4.7 s + ε > 30 s). longIdleGap is the
// "idle gaps up to 5 s" ceiling row of the task body: long enough to
// catch a short idle-timeout regression, under the 5 s ceiling so the
// schedule stays within the mandate (a >5 s finite timeout escapes —
// ticket §Analysis residue).
const (
	mainPhaseDuration = 26 * time.Second
	longIdleGap       = 4700 * time.Millisecond
)

// readStallDeadline bounds a single reader Read. It must exceed
// longIdleGap (the longest legitimate quiet period, echo latency
// included) so an idle gap is never misread as a stall; a timeout
// with echoed bytes outstanding IS a stall (deletion or a wedged
// pipe) and fails assertion (a)/(c).
const readStallDeadline = 15 * time.Second

// legDeadline bounds one whole leg (writer + reader drain). Generous
// vs. the ~31 s nominal run so -race CI never trips it; a hang past
// this is a wedged DP, reported with counts, not payload bytes.
const legDeadline = 180 * time.Second

// TestLongLivedBidirectionalCONNECT drives the two framing legs
// concurrently (bounding wall-clock at ~one exchange window, not two
// — concurrency is NOT the property under test; that is T079a), then
// asserts the upstream-transit gate and the journal invariants over
// one delta window covering both legs.
func TestLongLivedBidirectionalCONNECT(t *testing.T) {
	repoRoot := dpharness.FindRepoRoot(t)
	// Per-test content gates beyond the boot minimum inside
	// dpharness.Start (T042/T045/T050): the auth surface, the forward
	// path, the WatchEvents client (advisory; admission is not CP-gated
	// per T090), and — new vs. T025a — the HTTP CONNECT listener path
	// for leg 2.
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "auth", "token.go"),
		"auth/token.go not implemented yet (T044); this skip self-lifts when T044 lands")
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go"),
		"forward/tor.go not implemented yet (T047); this skip self-lifts when T047 lands")
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "controlclient", "client.go"),
		"controlclient/client.go not implemented yet (T045 client side); "+
			"needed to consume the WatchEvents stream (advisory; admission is not CP-gated per T090)")
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "listener", "connect.go"),
		"listener/connect.go not implemented yet (T043); needed for the HTTP CONNECT leg")

	// Fake upstream in AcceptAndRelay mode: completes the upstream
	// SOCKS5 handshake, REP=0x00, then echoes. Every byte the test
	// writes traverses the DP client→upstream, is echoed, and
	// traverses the DP upstream→client — both directions covered by
	// one stream-equality check.
	upstream := integration.NewServer(integration.AcceptAndRelay)
	upstreamAddr, err := upstream.Start()
	if err != nil {
		t.Fatalf("starting fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = upstream.Close() })

	// TLS fake CP hosted on control.sock BEFORE the DP boots (the
	// wire-auth §4 fixture lift, T050) so the first WatchEvents dial
	// lands against the programmable stream.
	h := dpharness.Start(t,
		dpharness.WithUpstream(upstreamAddr),
		dpharness.WithControlPlane(),
	)
	cp := h.CP

	reloadResp := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenVerifier{dpharness.MintToken(t, longLivedPlaintext)})
	if reloadResp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want APPLY_STATUS_OK "+
			"— precondition failed; the DP did not accept the test's token "+
			"generation", reloadResp.GetStatus())
	}

	// A HEALTHY event is pushed for advisory status visibility, but
	// admission is NOT gated on it (data-model.md §2; Principle II;
	// sol-review B3; remediated by T090) — the tunnel opens regardless.
	waitForWatchEventsDial(t, cp)
	if err := cp.Send(fakecp.Healthy("tor")); err != nil {
		t.Fatalf("pushing HEALTHY event: %v", err)
	}

	// Quiesce before the journal snapshot — same rationale and value
	// as T025a: boot/reload/HEALTHY lines must flush so the delta
	// carries only exchange-window output.
	time.Sleep(250 * time.Millisecond)
	before := h.Journal.String()

	// Per-leg distinctive corpus items. The payload sentinel is the
	// deterministic stream's literal prefix, so "payload bytes in the
	// journal" is scannable without hashing MBs of PRNG output (the
	// allowlist gate below is the primary catch for unnamed lines —
	// ticket §Analysis residue).
	const (
		destSOCKS5      = "t025b-dest-socks5.example.onion"
		destConnect     = "t025b-dest-connect.example.onion"
		unameSOCKS5     = "t025b-uname-socks5"
		sentinelSOCKS5  = "t025b-payload-sentinel-socks5-XXXXXXXXXX"
		sentinelConnect = "t025b-payload-sentinel-connect-XXXXXXXXX"
	)

	// Distinct seeds → distinct streams, so a cross-leg wiring bug in
	// the DP (leg A's bytes surfacing on leg B) is a divergence, not a
	// coincidental pass.
	t.Run("Exchange", func(t *testing.T) {
		t.Run("SOCKS5", func(t *testing.T) {
			t.Parallel()
			conn := dialProxy(t, h)
			t.Cleanup(func() { _ = conn.Close() })
			doMethodNegotiation(t, conn)
			subReply := doSubnegotiation(t, conn, unameSOCKS5, longLivedPlaintext)
			if want := []byte{0x01, 0x00}; !bytes.Equal(subReply, want) {
				t.Fatalf("sub-negotiation reply = %x, want %x — the DP rejected "+
					"a valid token; tunnel precondition failed (T024's contract)",
					subReply, want)
			}
			writeConnectRequest(t, conn, destSOCKS5, 443)
			rep := readN(t, conn, 10)
			if rep[0] != 0x05 || rep[1] != 0x00 {
				t.Fatalf("SOCKS5 CONNECT reply = %x, want 05 00... — the forward "+
					"path did not reach the upstream (contracts/socks5-auth.md "+
					"§\"SOCKS5 request-phase failures\")", rep)
			}
			driveBytePipe(t, conn, 0x5b_0001, sentinelSOCKS5)
		})
		t.Run("HTTPConnect", func(t *testing.T) {
			t.Parallel()
			conn := openHTTPConnectTunnel(t, h, destConnect, longLivedPlaintext)
			t.Cleanup(func() { _ = conn.Close() })
			driveBytePipe(t, conn, 0x5b_0002, sentinelConnect)
		})
	})

	// Upstream-transit gate (echo-false-pass class, finding
	// 20260706-002): the fake records SOCKS5 sub-negotiation UNAMEs;
	// FR-007 requires the DP to pass the username through unchanged,
	// so the leg's distinctive UNAME observed AT THE UPSTREAM proves
	// the tunnel's bytes transited the fake rather than a DP-local
	// echo. (CONNECT-leg equivalent is indirect — ticket §Analysis.)
	seen := false
	for _, id := range upstream.CircuitIDs() {
		if id == unameSOCKS5 {
			seen = true
			break
		}
	}
	if !seen {
		t.Errorf("upstream never observed the SOCKS5 leg's distinctive " +
			"UNAME at sub-negotiation — traffic did not transit the fake " +
			"upstream (echo-false-pass guard, redteam 20260706-002 class; " +
			"FR-007 username pass-through)")
	}

	// Post-exchange quiesce, then the delta over BOTH legs. The
	// LockedBuffer is append-only (strings.Builder), so slicing at
	// len(before) is safe — same grounding note as T025a.
	time.Sleep(250 * time.Millisecond)
	after := h.Journal.String()
	var delta string
	if len(after) >= len(before) {
		delta = after[len(before):]
	} else {
		delta = after
		t.Logf("journal shrank between snapshots (before=%d, after=%d) — "+
			"harness bug; scanning the whole post-exchange journal",
			len(before), len(after))
	}

	// (b) The DP emits no log line for the frame traffic: allowlist
	// first (catches unnamed per-request lines), then the corpus scan
	// (nine renderings per item), then the timestamp gate.
	t.Run("Journal_AllowlistOnly", func(t *testing.T) {
		loginvariants.AssertOnlyAllowedLines(t, delta)
	})
	t.Run("Journal_NoCorpusItem", func(t *testing.T) {
		loginvariants.AssertNoSecrets(t, delta,
			[]byte(destSOCKS5),
			[]byte(destConnect),
			[]byte(unameSOCKS5),
			[]byte(sentinelSOCKS5),
			[]byte(sentinelConnect),
			[]byte(longLivedPlaintext))
	})
	t.Run("Journal_NoSubHourTimestamp", func(t *testing.T) {
		loginvariants.AssertNoSubHourTimestamp(t, delta)
	})
}

// openHTTPConnectTunnel opens the HTTP CONNECT framing leg: request
// line + Proxy-Authorization only (the DP parses nothing else per
// contracts/socks5-auth.md §"HTTP CONNECT path" step 1), then reads
// the response strictly up to and including the header-terminating
// blank line — byte-at-a-time, so not one tunnel byte is swallowed
// into a discarded buffer (over-reading here would corrupt the
// transparency evidence; ticket §Analysis redteam scope (b)).
func openHTTPConnectTunnel(t *testing.T, h *dpharness.Harness, dest, token string) net.Conn {
	t.Helper()
	conn := dialProxy(t, h)
	req := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nProxy-Authorization: Bearer %s\r\n\r\n",
		dest, token)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	var hdr []byte
	one := make([]byte, 1)
	for !bytes.HasSuffix(hdr, []byte("\r\n\r\n")) {
		if len(hdr) > 8192 {
			t.Fatalf("CONNECT response header block exceeded 8 KiB without a "+
				"terminating blank line (got %d bytes so far)", len(hdr))
		}
		if _, err := io.ReadFull(conn, one); err != nil {
			t.Fatalf("read CONNECT response (after %d bytes): %v", len(hdr), err)
		}
		hdr = append(hdr, one[0])
	}
	statusLine, _, _ := bytes.Cut(hdr, []byte("\r\n"))
	if want := "HTTP/1.1 200 Connection Established"; string(statusLine) != want {
		t.Fatalf("CONNECT status line = %q, want %q (contracts/socks5-auth.md "+
			"§\"HTTP CONNECT path\" auth-success shape)", statusLine, want)
	}
	return conn
}

// driveBytePipe runs one leg's post-handshake exchange: a writer
// goroutine emits the seeded schedule, a reader goroutine verifies
// the echo against an independently regenerated expected stream.
// Asserts (a) zero divergence and written==read, and (c) the tunnel
// survives the whole run — the ONLY close is the client's, after the
// post-gap probe round-trips.
func driveBytePipe(t *testing.T, conn net.Conn, seed int64, sentinel string) {
	t.Helper()
	// dialProxy armed a 10 s whole-conn deadline for the handshake;
	// the exchange manages its own per-operation deadlines.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing handshake deadline: %v", err)
	}

	var writtenTotal atomic.Int64
	writerDone := make(chan struct{})
	writerErr := make(chan error, 1)
	readerRes := make(chan readResult, 1)
	start := time.Now()

	go func() {
		writerErr <- runWriter(conn, seed, sentinel, &writtenTotal, writerDone)
	}()
	go func() {
		n, err := runReader(conn, seed, sentinel, &writtenTotal, writerDone)
		readerRes <- readResult{n: n, err: err}
	}()

	// t.Fatalf must run on the subtest goroutine, so the workers
	// report over channels. The leg deadline is a hang backstop.
	legTimeout := time.After(legDeadline)
	select {
	case err := <-writerErr:
		if err != nil {
			t.Fatalf("writer: %v", err)
		}
	case <-legTimeout:
		t.Fatalf("leg wedged: writer did not finish within %v (written=%d)",
			legDeadline, writtenTotal.Load())
	}
	var res readResult
	select {
	case res = <-readerRes:
	case <-legTimeout:
		t.Fatalf("leg wedged: reader did not drain within %v (written=%d)",
			legDeadline, writtenTotal.Load())
	}
	if res.err != nil {
		t.Fatalf("reader: %v", res.err)
	}

	if written := writtenTotal.Load(); res.n != written {
		t.Errorf("bytes read back = %d, want %d written — the byte pipe "+
			"dropped or duplicated data (Principle I)", res.n, written)
	}
	if elapsed := time.Since(start); elapsed < minExchange {
		t.Errorf("exchange lasted %v, want ≥%v — schedule regression; the "+
			"long-lived property was not exercised", elapsed, minExchange)
	}
	// Client-initiated close: the one and only close of the leg
	// (assertion (c) — any earlier EOF/reset already failed above).
	_ = conn.Close()
}

type readResult struct {
	n   int64
	err error
}

// expectedStream produces the leg's deterministic byte stream: the
// ASCII sentinel literal, then math/rand output (whose Read is
// documented to produce a chunk-boundary-independent byte sequence
// for a given seed — writer and reader regenerate identical streams
// from independent instances, so nothing is buffered).
type expectedStream struct {
	pending []byte
	rng     *rand.Rand
}

func newExpectedStream(seed int64, sentinel string) *expectedStream {
	return &expectedStream{
		pending: []byte(sentinel),
		rng:     rand.New(rand.NewSource(seed)),
	}
}

func (e *expectedStream) next(n int) []byte {
	out := make([]byte, n)
	m := copy(out, e.pending)
	e.pending = e.pending[m:]
	if m < n {
		_, _ = e.rng.Read(out[m:]) // math/rand Read never errors
	}
	return out
}

// runWriter emits the schedule: sentinel first, then a time-based
// mixed phase (small/medium frames, large-frame bursts, trickle
// gaps — the burst-vs-trickle shape is how "asymmetric bandwidth" is
// realized against an echo upstream; ticket §Analysis residue), then
// the long idle gap, then a probe frame proving the tunnel outlived
// the gap. Closes writerDone after its final counted write so the
// reader's drain target is stable.
func runWriter(conn net.Conn, seed int64, sentinel string, writtenTotal *atomic.Int64, writerDone chan<- struct{}) error {
	defer close(writerDone)
	content := newExpectedStream(seed, sentinel)
	// Schedule PRNG is separate from content so frame sizing never
	// perturbs the byte sequence the reader regenerates.
	sched := rand.New(rand.NewSource(seed + 1))

	write := func(n int) error {
		chunk := content.next(n)
		if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return fmt.Errorf("arming write deadline: %w", err)
		}
		wn, err := conn.Write(chunk)
		writtenTotal.Add(int64(wn))
		if err != nil {
			return fmt.Errorf("write failed after %d bytes of a %d-byte frame "+
				"(total written %d) — the DP closed or wedged a live tunnel "+
				"(assertion (c)): %w", wn, n, writtenTotal.Load(), err)
		}
		return nil
	}

	if err := write(len(sentinel)); err != nil {
		return err
	}
	phaseEnd := time.Now().Add(mainPhaseDuration)
	for time.Now().Before(phaseEnd) {
		switch sched.Intn(10) {
		case 0, 1, 2, 3, 4, 5: // small frame, short pause
			if err := write(1 + sched.Intn(64)); err != nil {
				return err
			}
			time.Sleep(time.Duration(sched.Intn(50)) * time.Millisecond)
		case 6, 7: // medium frame
			if err := write(1<<10 + sched.Intn(7<<10)); err != nil {
				return err
			}
			time.Sleep(time.Duration(sched.Intn(20)) * time.Millisecond)
		case 8: // burst: large frames back-to-back (high in-flight window)
			for i := 0; i < 6; i++ {
				if err := write(64<<10 + sched.Intn(192<<10)); err != nil {
					return err
				}
			}
		case 9: // trickle: sub-second idle gap
			time.Sleep(time.Duration(300+sched.Intn(700)) * time.Millisecond)
		}
	}
	// The long idle gap (≤5 s per the task body), then the probe: a
	// DP idle-timeout regression closes the tunnel during this sleep
	// and surfaces as a probe write error here or a reader error.
	time.Sleep(longIdleGap)
	if err := write(1 << 10); err != nil {
		return fmt.Errorf("post-idle-gap probe: %w", err)
	}
	return nil
}

// runReader verifies the echo against the regenerated expected
// stream, chunk-by-chunk. Divergence reports offset and lengths only
// — never payload bytes — so a failing run cannot itself leak into CI
// logs (loginvariants precedent). Returns the total bytes read back.
func runReader(conn net.Conn, seed int64, sentinel string, writtenTotal *atomic.Int64, writerDone <-chan struct{}) (int64, error) {
	expected := newExpectedStream(seed, sentinel)
	var readTotal int64
	buf := make([]byte, 128<<10)
	for {
		select {
		case <-writerDone:
			if readTotal == writtenTotal.Load() {
				return readTotal, nil // fully drained
			}
		default:
		}
		if err := conn.SetReadDeadline(time.Now().Add(readStallDeadline)); err != nil {
			return readTotal, fmt.Errorf("arming read deadline: %w", err)
		}
		n, err := conn.Read(buf)
		if n > 0 {
			want := expected.next(n)
			for i := 0; i < n; i++ {
				if buf[i] != want[i] {
					return readTotal, fmt.Errorf("stream divergence at offset %d "+
						"(within a %d-byte chunk) — the byte pipe inserted, "+
						"reordered, or rewrote data (Principle I; payload bytes "+
						"withheld from this message)", readTotal+int64(i), n)
				}
			}
			readTotal += int64(n)
		}
		if err != nil {
			outstanding := writtenTotal.Load() - readTotal
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				// readStallDeadline exceeds every legitimate quiet
				// period (longest scheduled gap + echo latency), so a
				// timeout with bytes outstanding is a stall: dropped
				// bytes (assertion (a)) or a wedged pipe (c).
				if outstanding > 0 {
					return readTotal, fmt.Errorf("echo stalled: %d bytes "+
						"outstanding after %v with no progress (read %d of %d)",
						outstanding, readStallDeadline, readTotal, writtenTotal.Load())
				}
				continue // idle drain-complete window; loop re-checks writerDone
			}
			return readTotal, fmt.Errorf("read failed before client-initiated "+
				"close (read %d, outstanding %d) — the DP MUST NOT close a "+
				"live tunnel for inactivity, content, or size (assertion (c); "+
				"contracts/socks5-auth.md §\"Deadlines\"): %w",
				readTotal, outstanding, err)
		}
	}
}
