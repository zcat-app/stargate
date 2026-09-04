// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the POSITIVE counter increments on the auth-passed
// forwarding path — specs/001-tor-route/spec.md FR-008 (first half:
// only auth-passing requests count), data-model.md §3 (the canonical
// per-column rules: request_count +1 per authenticated SOCKS5/HTTP
// CONNECT; byte_count += forwarded client↔upstream bytes in both
// directions at request close; hour_bucket = unix-hour at increment
// time; the synthesised error-template body is excluded from
// byte_count), and contracts/control-grpc.md §"GetStatus (minimum
// subset)" Tests row 2 (this file: 100 auth-passing CONNECTs, each
// transferring exactly 2B; request_count delta exactly 100,
// byte_count delta exactly 100 × 2B).
//
// Method: baseline GetStatus snapshot for (route='TOR', hour_bucket)
// via the shared dpharness.Status probe (T025c's seam), then 50
// authenticated SOCKS5 CONNECTs + 50 authenticated HTTP CONNECTs
// against the AcceptAndRelay fake upstream (T019a), each writing a
// known payload of exactly B=4096 bytes and reading exactly B back
// (the echo books 2B through the DP's counting conn: B each way),
// then a second snapshot. The error-template exclusion is degenerate
// here (no error is ever triggered) and is asserted for completeness
// via a side-channel: every byte the test reads off the tunnel
// surface is captured and scanned for the errortpl.Template markers —
// the captured template-byte count must be zero (Principle I: a
// happy-path tunnel carries no DP-synthesised bytes). The journal
// delta across the burst is held to the T025a shared allowlist:
// counter writes emit no per-request log line (FR-008).
//
// Three-angle mapping of the FR-008 counter contract: T025c gates
// must-NOT-increment on auth failure, this file gates must-increment
// on auth pass + happy relay, T067b gates must-increment with
// byte_count 0 on auth pass + route failure. Tasks.md T025d.
//
// Tests-first (Constitution Principle VII): content-gates on T042/
// T045/T050 (dpharness boot minimum) plus T044 auth/token.go, T047
// forward/tor.go, T045 controlclient/client.go, and T043
// listener/connect.go; the test SKIPs until all land, then a counter
// or log regression is FAIL, not SKIP.
package socks5

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"path/filepath"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/contract/internal/fakecp"
	integration "github.com/zcat-app/stargate/tests/integration"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

// t025dLoadedToken is the 32-hex plaintext minted into the generation's
// single verifier (FR-017's `^[0-9a-f]{32}$` format gate — the CONNECT
// path's syntactic gate must pass so the HTTP leg's tunnels open).
// Low-entropy alternating nibbles on purpose: test-only placeholder
// (never deployed), and a high-entropy constant trips the pre-commit
// gitleaks generic-api-key rule the same way T025c's fixture did.
// Distinct from every sibling test's token constant so a corpus hit is
// attributable to this file.
const t025dLoadedToken = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f"

// t025dConnsPerFraming is the per-framing connection count the task
// body fixes (N=50 SOCKS5 CONNECTs + N=50 HTTP CONNECTs = the 100
// auth-passing CONNECTs of contracts/control-grpc.md §"GetStatus
// (minimum subset)" Tests row 2). Sequential per the sibling-burst
// shape (T025a/T025c); the concurrent variant is T079a's scope.
const t025dConnsPerFraming = 50

// t025dPayloadBytes is B — the exact per-direction payload size the
// task body leaves free and this test pins. Each connection writes B
// and reads B back, booking 2B through the DP's counting conn; the
// whole burst books 100 × 2 × 4096 = 819,200 bytes, far above any
// off-by-a-few accounting slip and far below CI cost.
const t025dPayloadBytes = 4096

// t025dTemplateMarkers are distinctive substrings of the rendered
// error template (data-plane/internal/errortpl.Template — the tests
// module cannot import the data plane's internal package, so the
// markers mirror the literal; drift there is gated byte-for-byte by
// its own unit test and the T029 contract test). All are ≥ 13 bytes,
// so a coincidental match against 4096-byte seeded-PRNG payloads is
// effectively impossible. The rendered substitutions ({ROUTE_LABEL},
// {CODE}, {LOCAL_REFERENCE_ID}) never appear verbatim, so the markers
// match the RENDERED body shape, not just the raw literal.
var t025dTemplateMarkers = [][]byte{
	[]byte("<!doctype html><meta charset=utf-8>"),
	[]byte("Route unavailable"),
	[]byte("Stargate: route unavailable"),
	[]byte("route is currently not serving requests"),
	[]byte(" \u00b7 Reference: "),
	[]byte("See the admin dashboard for details"),
}

// TestAuthPassedCounterIncrements pins the FR-008 / data-model.md §3
// positive counter contract on the auth-passed forwarding path.
// Single consolidated body (the T025a/T025c precedent): the assertion
// layers ride one DP boot + one token generation + one 100-connection
// burst; splitting would force extra boots for the same fixture
// without adding assertion coverage.
func TestAuthPassedCounterIncrements(t *testing.T) {
	// Per-test content gates beyond the boot minimum inside
	// dpharness.Start (T042/T045/T050): the auth surface, the forward
	// path, the WatchEvents client (advisory; admission is not
	// CP-gated per T090), and the HTTP CONNECT listener path for the
	// second framing.
	repoRoot := dpharness.FindRepoRoot(t)
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
		"listener/connect.go not implemented yet (T043); needed for the HTTP CONNECT framing")

	// Fake upstream in AcceptAndRelay mode: completes the upstream
	// SOCKS5 handshake, REP=0x00, then echoes. Every payload byte the
	// test writes traverses the DP client→upstream, is echoed, and
	// traverses the DP upstream→client — the 2B-per-connection premise
	// of the byte_count delta.
	upstream := integration.NewServer(integration.AcceptAndRelay)
	upstreamAddr, err := upstream.Start()
	if err != nil {
		t.Fatalf("starting fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = upstream.Close() })

	// Fake CP hosted on control.sock BEFORE the DP boots, then a
	// single HEALTHY push (advisory; admission is not CP-gated per
	// T090) — the T025a fixture shape, keeping control-channel retry
	// noise out of the journal delta assertion (d) scans.
	var cp *fakecp.Server
	h := dpharness.Start(t,
		dpharness.WithUpstream(upstreamAddr),
		dpharness.WithBeforeBoot(func(ipcDir string) {
			cp = fakecp.Start(t, ipcDir)
		}),
	)

	reloadResp := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenVerifier{dpharness.MintToken(t, t025dLoadedToken)})
	if reloadResp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want APPLY_STATUS_OK "+
			"— precondition for the positive counter test failed; the DP did "+
			"not accept the test's token generation (every connection would "+
			"fail auth and increment nothing)",
			reloadResp.GetStatus())
	}

	waitForWatchEventsDial(t, cp)
	if err := cp.Send(fakecp.Healthy("tor")); err != nil {
		t.Fatalf("pushing HEALTHY event: %v", err)
	}

	// Quiesce: boot/reload/HEALTHY journal lines flush before the
	// journal snapshot (T025a rationale), so the delta carries only
	// burst-window output. The counter baseline needs no settling —
	// Snapshot() reads the in-process map under its mutex — but taking
	// both here keeps one consistent pre-burst reference point.
	time.Sleep(250 * time.Millisecond)
	journalBefore := h.Journal.String()
	before := dpharness.Status(t, h)
	// h0 is the wall-clock hour at baseline (data-model.md §3 computes
	// hour_bucket at increment time; rows may land in h0 or, if the
	// run crosses an hour boundary, the adjacent h0+1).
	h0 := uint64(time.Now().Unix() / 3600)

	// The burst: 50 SOCKS5 + 50 HTTP CONNECT, alternating framings so
	// both protocol surfaces interleave (i%2 covers each framing
	// exactly 50 times). Every connection carries its own distinctive
	// destination / UNAME / payload so a journal-corpus hit pins the
	// leak to the specific iteration (T025a precedent).
	capture := &bytes.Buffer{} // every byte read off the tunnel surface
	for i := 0; i < 2*t025dConnsPerFraming; i++ {
		dest := fmt.Sprintf("t025d-dest-%03d.example.onion", i)
		uname := fmt.Sprintf("t025d-uname-%03d", i)
		payload := t025dPayload(i)
		if i%2 == 0 {
			t025dDriveSocks5Success(t, h, i, dest, uname, t025dLoadedToken, payload, capture)
		} else {
			t025dDriveHTTPConnectSuccess(t, h, i, dest, t025dLoadedToken, payload, capture)
		}
	}

	// Post-burst quiesce (the T025c precedent): byte_count is handed
	// over once at request close, so let the last tunnel teardown and
	// its close-flush settle before the probe, and let journal writes
	// flush before the second journal snapshot.
	time.Sleep(250 * time.Millisecond)
	after := dpharness.Status(t, h)
	journalAfter := h.Journal.String()

	beforeReq, beforeBytes := t025dCounterTotals(before)
	afterReq, afterBytes := t025dCounterTotals(after)

	// (a) request_count delta exactly 100 — one increment per
	// authenticated connection, framing-independent (FR-008 first
	// half; data-model.md §3).
	t.Run("RequestCount_Delta100", func(t *testing.T) {
		want := uint64(2 * t025dConnsPerFraming)
		if afterReq != beforeReq+want {
			t.Fatalf("auth-passed burst moved request_count by %d (baseline "+
				"%d → %d, want exactly +%d) — FR-008 / data-model.md §3: "+
				"every SOCKS5 or HTTP CONNECT that passes authentication "+
				"MUST increment request_count exactly once",
				afterReq-beforeReq, beforeReq, afterReq, want)
		}
	})

	// (b) byte_count delta exactly 100 × 2B — B forwarded client→
	// upstream plus the B-byte echo upstream→client, per connection,
	// booked once at request close (data-model.md §3 byte_count rule).
	t.Run("ByteCount_Delta100x2B", func(t *testing.T) {
		want := uint64(2*t025dConnsPerFraming) * 2 * t025dPayloadBytes
		if afterBytes != beforeBytes+want {
			t.Fatalf("auth-passed burst moved byte_count by %d (baseline "+
				"%d → %d, want exactly +%d) — data-model.md §3: byte_count "+
				"MUST accumulate the bytes forwarded between client and "+
				"upstream in both directions at request close (each of the "+
				"%d connections forwarded exactly %d bytes each way)",
				afterBytes-beforeBytes, beforeBytes, afterBytes, want,
				2*t025dConnsPerFraming, t025dPayloadBytes)
		}
	})

	// (b, completeness) No DP-emitted error-template bytes anywhere on
	// the tunnel surface. The data-model §3 template exclusion is
	// degenerate on a run that never triggers an error — so the guard
	// is a capture-and-scan side-channel: had the DP synthesised or
	// injected template bytes, the byte_count delta above alone could
	// not see them (they are not forwarded bytes), but they would show
	// up here as nonzero captured template bytes.
	t.Run("NoTemplateBytesEmitted", func(t *testing.T) {
		captured := 0
		stream := capture.Bytes()
		for _, marker := range t025dTemplateMarkers {
			captured += bytes.Count(stream, marker) * len(marker)
		}
		if captured != 0 {
			t.Fatalf("captured %d error-template byte(s) on the tunnel "+
				"surface of a burst that never triggers an error — the DP "+
				"synthesised bytes into a happy-path relay (Principle I; "+
				"data-model.md §3 excludes the template body from "+
				"byte_count, so the counter deltas alone cannot see this)", captured)
		}
	})

	// (c) hour_bucket wall-clock truth: every row the snapshot carries
	// is route 'TOR' (the only label the v1 DP produces) in the
	// baseline hour or the adjacent one — the two-row allowance for a
	// mid-run hour rollover, where a connection's request_count
	// increment and its close-time byte flush may land in adjacent
	// buckets while both deltas stay exact (data-model.md §3).
	t.Run("HourBucket_WallClock", func(t *testing.T) {
		for _, c := range after.GetCounters() {
			if c.GetRoute() != "TOR" {
				t.Errorf("counter row route=%q, want \"TOR\" — the only "+
					"route label the v1 DP produces (data-model.md §3)", c.GetRoute())
			}
			if hour := c.GetHourBucket(); hour != h0 && hour != h0+1 {
				t.Errorf("counter row hour_bucket=%d, want %d (baseline "+
					"wall-clock hour) or %d (the one adjacent-bucket "+
					"allowance for a mid-run rollover) — data-model.md §3: "+
					"hour_bucket is the unix-hour at increment time",
					hour, h0, h0+1)
			}
		}
	})

	// (d) Journal delta across the burst holds the T025a shared
	// allowlist: counter writes emit no per-request log line. The
	// append-only LockedBuffer makes after[len(before):] a safe slice
	// of the burst-window lines only (T025a grounding note).
	var delta string
	if len(journalAfter) >= len(journalBefore) {
		delta = journalAfter[len(journalBefore):]
	} else {
		delta = journalAfter
		t.Logf("journal shrank between snapshots (before=%d, after=%d) — "+
			"harness bug; scanning the whole post-burst journal",
			len(journalBefore), len(journalAfter))
	}
	t.Run("Journal_AllowlistOnly", func(t *testing.T) {
		loginvariants.AssertOnlyAllowedLines(t, delta)
	})
	t.Run("Journal_NoSubHourTimestamp", func(t *testing.T) {
		loginvariants.AssertNoSubHourTimestamp(t, delta)
	})
	t.Run("Journal_NoCorpusItem", func(t *testing.T) {
		for i := 0; i < 2*t025dConnsPerFraming; i++ {
			loginvariants.AssertNoSecrets(t, delta,
				[]byte(fmt.Sprintf("t025d-dest-%03d.example.onion", i)),
				[]byte(fmt.Sprintf("t025d-uname-%03d", i)),
				[]byte(fmt.Sprintf("t025d-body-%03d-", i)))
		}
		loginvariants.AssertNoSecrets(t, delta, []byte(t025dLoadedToken))
	})
}

// t025dDriveSocks5Success opens one authenticated SOCKS5 CONNECT
// tunnel and runs the payload exchange. The handshake asserts are the
// attempt's success precondition (T024's contract shapes): method
// selection 05 02, sub-negotiation reply exactly `01 00`, CONNECT
// reply 05 00 — an unexpected auth failure would increment nothing
// and mask the counter deltas, so it fails fast with the iteration
// named. The CONNECT reply's 10 bytes are captured for the
// template-byte scan.
func t025dDriveSocks5Success(t *testing.T, h *dpharness.Harness, i int,
	dest, uname, plaintext string, payload []byte, capture *bytes.Buffer) {
	t.Helper()
	conn := dialProxy(t, h)
	defer func() { _ = conn.Close() }()
	// 30 s per attempt covers HMAC auth (sub-ms nominal), the forward
	// path's upstream dial, and the B-byte echo round trip plus
	// scheduler slack on a loaded CI runner — the sibling-burst
	// deadline shape.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	doMethodNegotiation(t, conn)
	subReply := doSubnegotiation(t, conn, uname, plaintext)
	capture.Write(subReply)
	if want := []byte{0x01, 0x00}; !bytes.Equal(subReply, want) {
		t.Fatalf("connection %d: sub-negotiation reply = %x, want %x — "+
			"the DP rejected a valid token; the success precondition failed "+
			"and a failed attempt increments nothing (T024's contract)",
			i, subReply, want)
	}
	writeConnectRequest(t, conn, dest, 443)
	rep := readN(t, conn, 10)
	capture.Write(rep)
	if rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("connection %d: SOCKS5 CONNECT reply = %x, want 05 00... "+
			"— the forward path did not reach the upstream successfully; "+
			"a failed attempt increments nothing (contracts/socks5-auth.md "+
			"§\"SOCKS5 request-phase failures (post-auth)\")", i, rep)
	}
	t025dExchangePayload(t, conn, i, payload, capture)
}

// t025dDriveHTTPConnectSuccess opens one authenticated HTTP CONNECT
// tunnel (openHTTPConnectTunnel asserts the HTTP/1.1 200 Connection
// Established success shape — the framing's success precondition) and
// runs the payload exchange.
func t025dDriveHTTPConnectSuccess(t *testing.T, h *dpharness.Harness, i int,
	dest, plaintext string, payload []byte, capture *bytes.Buffer) {
	t.Helper()
	conn := openHTTPConnectTunnel(t, h, dest, plaintext)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	t025dExchangePayload(t, conn, i, payload, capture)
}

// t025dExchangePayload runs one connection's payload leg: writes
// exactly B payload bytes, reads exactly B back, and byte-compares
// the echo — the per-connection premise of the 2B byte_count
// accounting (a dropped, duplicated, or rewritten byte invalidates
// it, so it fails fast with the iteration named; the transparency
// property itself is T025b's scope). Every byte read is appended to
// capture for the template-byte scan, and a bounded silence probe
// then asserts the DP appended nothing beyond the echo — a DP that
// injected synthesised bytes after the relayed stream is caught here
// (content withheld from the failure message, loginvariants
// precedent).
func t025dExchangePayload(t *testing.T, conn net.Conn, i int,
	payload []byte, capture *bytes.Buffer) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("connection %d: write %d-byte payload: %v", i, len(payload), err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("connection %d: read %d-byte echo: %v — the byte pipe did "+
			"not return the payload exactly once; the 2B-per-connection "+
			"byte_count premise is broken (Principle I)", i, len(payload), err)
	}
	capture.Write(echo)
	if !bytes.Equal(echo, payload) {
		t.Fatalf("connection %d: echo mismatch — the DP or the fake "+
			"upstream mutated the payload; a mutated relay invalidates the "+
			"exact 2B byte_count premise (payload bytes withheld from this "+
			"message)", i)
	}

	// Silence probe: after the full echo, a correct DP has nothing
	// more to send and holds the tunnel open (the close is the
	// client's — T025b assertion (c)). 100 ms is generous for loopback
	// ordering: injected bytes would already be in flight behind the
	// echo. Timeout = pass; EOF = the DP closed after a complete echo
	// (a lifetime-contract concern owned by T025b, not extra bytes).
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	trailing := make([]byte, 512)
	n, _ := conn.Read(trailing)
	if n > 0 {
		capture.Write(trailing[:n])
		t.Fatalf("connection %d: DP emitted %d trailing byte(s) beyond the "+
			"echoed payload on a happy-path tunnel — DP-synthesised bytes "+
			"must never enter the relay (Principle I); content withheld", i, n)
	}
}

// t025dPayload builds connection i's known payload: exactly
// t025dPayloadBytes bytes, a distinctive ASCII prefix (the journal
// corpus item — long enough that a coincidental match in noise text
// is statistically impossible) followed by a seeded-PRNG fill so the
// byte stream is deterministic yet payload-like (the T025b stream
// shape). math/rand.Read never errors.
func t025dPayload(i int) []byte {
	p := make([]byte, t025dPayloadBytes)
	prefix := fmt.Sprintf("t025d-body-%03d-", i)
	copy(p, prefix)
	_, _ = rand.New(rand.NewSource(int64(i) + 1)).Read(p[len(prefix):])
	return p
}

// t025dCounterTotals sums request_count and byte_count across every
// row of a snapshot. Summed over the whole snapshot the deltas are
// stricter than filtering route='TOR': an increment leaking in under
// any unexpected route label cannot hide (the route labels themselves
// are pinned per-row by HourBucket_WallClock). uint64 magnitudes here
// are far below overflow range.
func t025dCounterTotals(resp *grpcpb.StatusResponse) (requests, bytes uint64) {
	for _, c := range resp.GetCounters() {
		requests += c.GetRequestCount()
		bytes += c.GetByteCount()
	}
	return requests, bytes
}
