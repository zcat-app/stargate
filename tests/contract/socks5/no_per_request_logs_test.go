// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the SOCKS5 success-path log invariants —
// specs/001-tor-route/spec.md FR-008, arch §6.4 (hour-bucket
// resolution), contracts/socks5-auth.md §"Invariants enforced by
// the contract test" row "No per-request log on auth failure"
// (rule applies symmetrically to the success path), and the
// specs/001-tor-route/tasks.md T025a task body.
//
// Drives 100 sequential authenticated CONNECTs through port 8881 to
// an in-process accept-and-relay upstream (T019a's
// fake_socks5_tor.go); captures the data plane's journal delta for
// the duration of the run; asserts:
//
//	(a) no destination hostname, body byte, or UNAME appears anywhere
//	    in the delta (FR-008 verbatim — corpus scan in raw, hex, all
//	    four base64 variants, and decimal-slice renderings);
//	(b) no per-request timestamp at finer than the ≥1-hour aggregate-
//	    counter bucket (FR-008, arch §6.4);
//	(c) every delta line belongs to the fixed allowlist (startup,
//	    shutdown, SidecarEvent consumption, ReloadTokens apply,
//	    snapshot-write events) — the inverse form of FR-008, catching
//	    per-request log lines that do not happen to contain a corpus
//	    item.
//
// The allowlist + scan core live in the shared
// github.com/zcat-app/stargate/tests/internal/loginvariants package
// so T025b (long-lived CONNECT byte-pipe) and T070a (mid-request
// circuit drop) reference the same canonical set rather than
// duplicate it. T025 leak_test.go's local helpers stay put (filed
// as a follow-up to refactor once the success-path contract lands).
//
// Tests-first (Constitution Principle VII) for the data plane's
// success-path journal surface: T042 (listener), T044 (auth/token.go),
// T045 (gRPC server + control client), T046 (snapshot write), T047
// (forward/tor.go), T050 (main wiring). The test self-skips until
// all six land; once present, a leak regression is FAIL, not SKIP.
package socks5

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/contract/internal/fakecp"
	integration "github.com/zcat-app/stargate/tests/integration"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

// successPathPlaintext is the bearer-token plaintext the test mints
// into an argon2id hash via dpharness.MintToken and pushes to the DP
// via ReloadTokens. Fixed across the 100-CONNECT burst so the auth
// surface is identical on every iteration; the corpus scan's job is
// catching a leak of the per-iteration destination/body/UNAME, not
// the shared token (whose plaintext is hashed before the DP sees it
// and whose hash is gated by T020's no-logging clause separately).
const successPathPlaintext = "0123456789abcdef0123456789abcdef"

// successPathConnectCount is the per-burst CONNECT count the T025a
// task body fixes. 100 is large enough that a per-request log line
// is statistically impossible to miss (a 1%-of-the-time leak would
// surface ~1 hit per run) but small enough that the sequential test
// finishes well under the per-test deadline on a CI runner even with
// argon2id auth at ~50 ms/op (100 × ~50 ms = ~5 s of auth work plus
// forward-path overhead).
const successPathConnectCount = 100

// TestSOCKS5SuccessPathLogInvariants pins the success-path journal
// invariants FR-008 / arch §6.4 enumerate. Single consolidated body
// (not sub-tests) because the §Analysis must-holds are layered on
// the same 100-CONNECT burst — splitting would force 4× DP boots for
// the same setup, multiplying the argon2id + container-build cost
// without adding assertion coverage.
func TestSOCKS5SuccessPathLogInvariants(t *testing.T) {
	// Boot-minimum gate (T042 listener + T045 gRPC server + T050
	// main wiring) is inside dpharness.Start. Additional per-test
	// gates: T044 auth/token.go, T047 forward/tor.go, T045 client
	// (needed to receive the HEALTHY event that engages the forward
	// path — without HEALTHY the route stays DISABLED, the request-
	// phase forward returns ROUTE_DOWN byte-exact, and the success-
	// path surface under test is never reached).
	repoRoot := dpharness.FindRepoRoot(t)
	authGate := filepath.Join(repoRoot, "data-plane", "internal", "auth", "token.go")
	dpharness.RequireFile(t, authGate,
		"auth/token.go not implemented yet (T044); this skip self-lifts when T044 lands")
	forwardGate := filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go")
	dpharness.RequireFile(t, forwardGate,
		"forward/tor.go not implemented yet (T047); this skip self-lifts when T047 lands")
	clientGate := filepath.Join(repoRoot, "data-plane", "internal", "controlclient", "client.go")
	dpharness.RequireFile(t, clientGate,
		"controlclient/client.go not implemented yet (T045 client side); "+
			"needed to receive the HEALTHY event that engages the forward path")

	// Fake upstream: fake_socks5_tor in AcceptAndRelay mode. The
	// data plane forwards each CONNECT to this loopback address
	// (STARGATE_TOR_SOCKS_ADDR override); the fake short-circuits
	// to an in-memory echo, so every byte the test writes is read
	// back unmodified. The forward-path byte-pipe transparency
	// invariant itself is T025b's scope; this test only needs the
	// forward path to engage so the journal surface under test is
	// exercised.
	upstream := integration.NewServer(integration.AcceptAndRelay)
	upstreamAddr, err := upstream.Start()
	if err != nil {
		t.Fatalf("starting fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = upstream.Close() })

	// Boot DP with the upstream override + fake CP hosted on
	// control.sock BEFORE the DP boots (so the first WatchEvents
	// dial lands against our programmable stream). fakecp pushes
	// a single HEALTHY event for "tor" once the DP's dial lands.
	var cp *fakecp.Server
	h := dpharness.Start(t,
		dpharness.WithUpstream(upstreamAddr),
		dpharness.WithBeforeBoot(func(ipcDir string) {
			cp = fakecp.Start(t, ipcDir)
		}),
	)

	// Push token generation 1 with one valid hash. APPLY_STATUS_OK
	// is the only acceptable response — a stale-generation or
	// invalid-hash response would mean T044 / T046 (snapshot) is
	// broken in a way T020's contract test gates more precisely.
	reloadResp := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenHash{dpharness.MintToken(t, successPathPlaintext)})
	if reloadResp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want "+
			"APPLY_STATUS_OK — precondition for the success-path "+
			"test failed; the DP did not accept the test's token "+
			"generation", reloadResp.GetStatus())
	}

	// Wait for the DP's WatchEvents dial to land on the fake CP,
	// then push HEALTHY so routeEnableMask[TOR] transitions to
	// ENABLED (data-model.md §2). Without HEALTHY the forward path
	// short-circuits to ROUTE_DOWN and the journal surface under
	// test is never exercised.
	waitForWatchEventsDial(t, cp)
	if err := cp.Send(fakecp.Healthy("tor")); err != nil {
		t.Fatalf("pushing HEALTHY event: %v", err)
	}

	// Quiesce: let boot/setup/ReloadTokens/HEALTHY-receipt journal
	// lines flush before the snapshot. 250 ms is generous against
	// the DP's buffered-stderr write latency; the snapshot delta
	// is what carries the load-bearing assertions, so a too-short
	// quiesce would false-POSITIVE (boot lines leaking into the
	// delta) rather than false-negative — caught by the allowlist
	// gate, but at the cost of a misleading failure message.
	time.Sleep(250 * time.Millisecond)

	before := h.Journal.String()

	// Per-iteration distinctive strings. Each destination, body,
	// and UNAME carries the iteration index so a corpus-scan hit
	// pins the leak to the specific iteration that produced it
	// (useful for diagnosing a flaky or state-dependent leak).
	dests := make([]string, successPathConnectCount)
	bodies := make([][]byte, successPathConnectCount)
	unames := make([]string, successPathConnectCount)
	for i := 0; i < successPathConnectCount; i++ {
		dests[i] = fmt.Sprintf("t025a-dest-%03d-example.onion", i)
		// Body: 32 distinctive ASCII bytes (the corpus scan's hex
		// encoding is 64 chars; long enough that a coincidental
		// match in noise text is statistically impossible).
		bodies[i] = []byte(fmt.Sprintf("t025a-body-%03d-XXXXXXXXXXXXXXXXX", i))
		unames[i] = fmt.Sprintf("t025a-uname-%03d", i)
	}

	// Drive the burst. Sequential per the T025a task body — the
	// concurrent variant is T079a's scope (PR-cadence regression
	// gate for SC-005 pool-fill). Each iteration opens a fresh
	// connection (no multiplexing) so a per-request log line is
	// attributable to a specific CONNECT, not pooled.
	for i := 0; i < successPathConnectCount; i++ {
		conn := dialProxy(t, h)
		// 30 s per iteration covers argon2id auth (~50 ms nominal,
		// more on loaded CI) + the forward-path dial + the body
		// echo round-trip.
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

		doMethodNegotiation(t, conn)
		subReply := doSubnegotiation(t, conn, unames[i], successPathPlaintext)
		if want := []byte{0x01, 0x00}; !bytes.Equal(subReply, want) {
			_ = conn.Close()
			t.Fatalf("iteration %d: sub-negotiation reply = %x, want %x "+
				"— success-path precondition failed; the DP rejected a "+
				"valid token (a leak regression here would mask the "+
				"journal scan's load-bearing assertions)",
				i, subReply, want)
		}

		// SOCKS5 CONNECT to the iteration's distinctive .onion.
		writeConnectRequest(t, conn, dests[i], 443)
		// The fake's success reply is 10 bytes (05 00 00 01 00*6)
		// per writeReply in fake_socks5_tor.go. A stuck forward
		// path would hang here; the bounded read surfaces that as
		// a test failure rather than a timeout pile-up.
		rep := readN(t, conn, 10)
		if rep[0] != 0x05 || rep[1] != 0x00 {
			_ = conn.Close()
			t.Fatalf("iteration %d: SOCKS5 CONNECT reply = %x, want "+
				"05 00... (success) — the forward path did not reach "+
				"the upstream successfully (contracts/socks5-auth.md "+
				"§\"SOCKS5 request-phase failures\"; rep[1] mapping "+
				"per data-model.md §2)", i, rep)
		}

		// Write the distinctive body and read the echo back. The
		// fake's relayEcho pipes client→client, so the bytes the
		// test writes are the bytes it reads. The LimitReader
		// bounds the read so a buggy fake that over-echoes cannot
		// wedge the test.
		if _, err := conn.Write(bodies[i]); err != nil {
			_ = conn.Close()
			t.Fatalf("iteration %d: write body: %v", i, err)
		}
		echo := make([]byte, len(bodies[i]))
		if _, err := io.ReadFull(conn, echo); err != nil {
			_ = conn.Close()
			t.Fatalf("iteration %d: read echo: %v", i, err)
		}
		if !bytes.Equal(echo, bodies[i]) {
			_ = conn.Close()
			t.Fatalf("iteration %d: echo mismatch — the fake upstream "+
				"or the forward path mutated the body; this is T025b's "+
				"invariant, but a failure here would mask the journal "+
				"scan's load-bearing assertions", i)
		}
		_ = conn.Close()
	}

	// Post-burst quiesce: let any in-flight journal write flush
	// before the snapshot. Same 250 ms rationale as above.
	time.Sleep(250 * time.Millisecond)

	after := h.Journal.String()

	// Delta computation: the LockedBuffer in dpharness is append-
	// only (strings.Builder only grows), so after[len(before):] is
	// a safe slice of the post-burst lines only. A future binary
	// journal sink or reset-on-rotate harness would break this
	// assumption — re-grounding would surface as an index-out-of-
	// bounds panic, not a silent false-pass (§Analysis residue).
	var delta string
	if len(after) >= len(before) {
		delta = after[len(before):]
	} else {
		// Journal shrank — unexpected; would indicate a harness
		// bug. Scan the whole thing rather than skip the
		// assertions (which would silently false-pass).
		delta = after
		t.Logf("journal shrank between snapshots (before=%d, "+
			"after=%d) — harness bug; scanning the whole "+
			"post-burst journal", len(before), len(after))
	}

	// (a) Corpus scan: no destination / body / UNAME in delta, in
	// any of the eight textual renderings an accidental slog / fmt
	// logger would produce. The destination is the FR-008-named
	// surface ("destination hostname"); the body is the FR-008-
	// named surface ("body byte"); the UNAME is included belt-and-
	// braces (FR-007 opaque-to-auth-layer rule applies to logging
	// too — the UNAME is forwarded verbatim to the upstream, never
	// logged locally). Asserting per-iteration rather than batched
	// keeps a leak diagnostic pinpointed to the iteration.
	t.Run("Corpus_NoDestinationBodyOrUname", func(t *testing.T) {
		for i := 0; i < successPathConnectCount; i++ {
			loginvariants.AssertNoSecrets(t, delta,
				[]byte(dests[i]),
				bodies[i],
				[]byte(unames[i]))
		}
	})

	// (b) Timestamp scan: no sub-hour timestamp in delta. FR-008 /
	// arch §6.4 prohibit per-request timestamps finer than the ≥1-
	// hour aggregate bucket. Bare Unix-epoch seconds are a
	// documented residue (loginvariants.SubHourTimestamp comment)
	// — the allowlist below is the primary gate for that shape.
	t.Run("Timestamp_NoSubHourResolution", func(t *testing.T) {
		loginvariants.AssertNoSubHourTimestamp(t, delta)
	})

	// (c) Allowlist: every delta line matches one of the five
	// reserved classes. On a correct DP implementation the delta
	// is empty (no lifecycle events fire during a request burst
	// with no reload / no sidecar-event push / no shutdown); this
	// gate catches the unanticipated per-request log line that
	// (a) misses because no corpus item names it (e.g.
	// `msg=forwarded bytes=42`). Constitution Principle I / III
	// breach — fail, not skip, once T042/T044/T045/T046/T047/T050
	// have landed and the content gates above self-lift.
	t.Run("Allowlist_OnlyReservedClasses", func(t *testing.T) {
		loginvariants.AssertOnlyAllowedLines(t, delta)
	})
}
