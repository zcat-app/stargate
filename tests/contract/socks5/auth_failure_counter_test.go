// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the auth-failure counter side channel — specs/
// 001-tor-route/spec.md FR-008 ("auth failures leave the counter
// unchanged"), FR-006 (the failure framings the burst drives),
// data-model.md §3 (the rule's canonical statement: counting failures
// would side-channel token guessing, since an attacker can submit
// tokens at will; the synthesised AUTH_REQUIRED template body is
// excluded from byte_count), and contracts/control-grpc.md §"GetStatus
// (minimum subset)" Tests rows 1 and 4 (this file; the no-traffic
// sandwich).
//
// The test lives next to the SOCKS5 leak tests, not under
// tests/contract/control-grpc/: the property under test sits at the
// port-8881 auth boundary, and GetStatus is used here as the test-only
// probe data-model.md §3 documents — the read surface whose side-effect
// freedom is itself one of the gated properties.
//
// Method: probe GetStatus for a baseline counter snapshot, verify the
// probe itself is side-effect-free (snapshot → ≥1 s idle → snapshot →
// identical), drive 200 auth-failure attempts at port 8881 — 100 SOCKS5
// CONNECTs and 100 HTTP CONNECTs cycling four malformation modes each
// (missing password/header, all-zero token, wrong-length token,
// correct-length token absent from the loaded generation) — then probe
// again and assert the request_count and byte_count deltas are both
// EXACTLY zero and the full snapshot is unchanged.
//
// This is the counter channel of the auth-failure leak family: T025
// gates the log/journal channel, T025d/T067b the positive (increment)
// angles. All must hold or the failure path leaks. The failure
// responses' own byte contracts are siblings' scope (T028 the 01 FF
// shape, T027 the 407 template) — asserted here only as each attempt's
// failure precondition, because an attempt that unexpectedly succeeds
// increments and masks the delta assertions.
//
// Tests-first (Constitution Principle VII): dpharness.Start self-skips
// until T050 (cmd/stargate-proxy/main.go) lands the boot wiring; the
// gate then fails closed. The precondition ReloadTokens rides the
// shared harness helper whose §5.3 metadata gap is recorded residue
// owned by T022/T050 (T020a Notes) — loud precondition failure, never a
// silent pass, if it is unfixed at first real run.
package socks5

import (
	"bytes"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
)

// t025cLoadedToken is the 32-hex plaintext minted into the generation's
// single verifier (FR-017's `^[0-9a-f]{32}$` format gate — non-hex
// fixtures fail the DP's gate on first real run, per T020a's follow-up
// note). Low-entropy alternating nibbles on purpose: it is a test-only
// placeholder (never deployed), and a high-entropy constant trips the
// pre-commit gitleaks generic-api-key rule the same way T034's fixture
// did. Distinct from every sibling test's token constant and from every
// candidate below (so a leak or count attributable to a specific
// plaintext names this file). Never offered by the burst: the
// candidates are all wrong.
const t025cLoadedToken = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"

// t025cAttemptsPerFraming is the per-framing attempt count the task body
// fixes (N=100 SOCKS5 CONNECTs and N=100 HTTP CONNECTs; 200 total, per
// contracts/control-grpc.md §"GetStatus (minimum subset)" Tests row 1).
// Same statistical shape as T025a's 100-burst: large enough that any
// per-failure accounting slip cannot average out, small enough for CI.
const t025cAttemptsPerFraming = 100

// t025cCandidates enumerates the four malformation modes the task body
// fixes, rendered for both framings. Each mode is a distinct attacker
// strategy against the auth surface; a DP that special-cased any of
// them into an increment (or into anything other than its framing's
// auth failure) breaks either the per-attempt shape assert or the
// counter deltas.
var t025cCandidates = []struct {
	label string
	// socks5Passwd is the RFC 1929 PASSWD offer. Empty string is the
	// missing-password shape (PLEN=0): doSubnegotiation's guard rejects
	// empty PASSWD because its callers assert well-formed offers, so
	// that mode goes through writeRawSubnegotiation below.
	socks5Passwd string
	// httpAuthHeader is the full Proxy-Authorization header line, or
	// empty to omit the header entirely (the missing-password analog on
	// the CONNECT framing). AllZero passes validBearerToken's 32-hex
	// gate and reaches the compare loop; WrongLength short-circuits at
	// the gate; CorrectLength is a near-miss against the loaded
	// generation — the three attacker depths the compare path must
	// treat identically.
	httpAuthHeader string
}{
	{
		label:          "MissingPassword",
		socks5Passwd:   "",
		httpAuthHeader: "",
	},
	{
		label:          "AllZeroToken",
		socks5Passwd:   "00000000000000000000000000000000",
		httpAuthHeader: "Proxy-Authorization: Bearer 00000000000000000000000000000000",
	},
	{
		label:          "WrongLengthToken",
		socks5Passwd:   "tooshort",
		httpAuthHeader: "Proxy-Authorization: Bearer tooshort",
	},
	{
		label:          "CorrectLength_AbsentFromGeneration",
		socks5Passwd:   "ffffffffffffffffffffffffffffffff",
		httpAuthHeader: "Proxy-Authorization: Bearer ffffffffffffffffffffffffffffffff",
	},
}

// TestAuthFailureCounterSideChannelResistance pins the FR-008 /
// data-model.md §3 counter side-channel contract at the port-8881 auth
// boundary. Single consolidated body (the T025a precedent): the
// assertions layer on one DP boot + one token generation + one
// 200-attempt burst; splitting would force extra boots for the same
// fixture without adding assertion coverage.
func TestAuthFailureCounterSideChannelResistance(t *testing.T) {
	// Boot-minimum gate (T042 listener + T045 gRPC server + T050 main
	// wiring) is inside dpharness.Start. Additional gate: the auth
	// failure path itself (T044) — the burst's premise.
	authGate := filepath.Join(dpharness.FindRepoRoot(t), "data-plane", "internal", "auth", "token.go")
	dpharness.RequireFile(t, authGate,
		"auth/token.go not implemented yet (T044); this skip self-lifts when T044 lands")

	// No upstream, no fake CP (the T028 fixture shape): an auth failure
	// short-circuits before the upstream dial on both framings
	// (listener socks5.go / connect.go), so nothing downstream of auth
	// is ever reached. WatchEvents retry noise is irrelevant — this
	// test asserts counters, not the journal.
	h := dpharness.Start(t)

	// Populate the generation with one valid verifier so the
	// CorrectLength_AbsentFromGeneration mode is a near-miss against
	// realistic state — the right shape, the wrong secret. A fresh DP's
	// empty generation would make that mode indistinguishable from
	// MissingPassword at the compare layer.
	reloadResp := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenVerifier{dpharness.MintToken(t, t025cLoadedToken)})
	if reloadResp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want APPLY_STATUS_OK — "+
			"precondition for the counter test failed; the DP did not accept "+
			"the test's token generation (without a populated generation the "+
			"near-miss mode does not exercise the comparison loop)",
			reloadResp.GetStatus())
	}

	// Baseline snapshot for route='TOR' (the only label the v1 DP
	// produces, data-model.md §3). On a fresh boot with zero
	// auth-passed traffic the snapshot carries no rows yet — rows are
	// born only on post-auth increments — so the deltas below are
	// asserted against whatever the baseline holds and stay correct
	// even if boot ever gains a startup row.
	before := dpharness.Status(t, h)

	// (c) No-traffic sandwich: snapshot → ≥1 s idle (no port-8881
	// traffic) → snapshot → identical. A side-effecting read surface
	// would make every delta assertion in this file meaningless
	// (contracts/control-grpc.md §"GetStatus (minimum subset)": "The
	// data plane MUST NOT increment any counter as a side-effect of
	// serving GetStatus"). 1.1 s covers the contract's "separated by
	// ≥1 s" with scheduler slack.
	time.Sleep(1100 * time.Millisecond)
	sandwich := dpharness.Status(t, h)

	t.Run("Probe_IsSideEffectFree", func(t *testing.T) {
		if !proto.Equal(before, sandwich) {
			t.Fatalf("GetStatus changed the counters with no port-8881 traffic "+
				"(before=%v after=%v) — contracts/control-grpc.md §\"GetStatus "+
				"(minimum subset)\" no-side-effect row: a side-effecting probe "+
				"defeats the sandwich and every delta assertion in this test",
				before, sandwich)
		}
	})

	// The burst: 100 SOCKS5 + 100 HTTP CONNECT auth failures — exactly
	// the contract's N per framing (contracts/control-grpc.md §"GetStatus
	// (minimum subset)" Tests row 1) — cycling the four malformation
	// modes (25 each per framing; i % 4 covers each mode 25 times).
	// Sequential per the sibling-burst shape (T025a/T028); the
	// concurrent variant is not this contract's concern. Each attempt
	// asserts its framing's failure shape — the precondition that keeps
	// the delta assertions honest (a success would increment and could
	// cancel to zero only by luck; failing fast names the mode instead).
	for i := 0; i < t025cAttemptsPerFraming; i++ {
		mode := i % len(t025cCandidates)
		t025cDriveSocks5AuthFailure(t, h, mode)
		t025cDriveHTTPConnectAuthFailure(t, h, mode)
	}

	// Post-burst quiesce (the T025a precedent): let the last teardown
	// and any in-flight write settle before the probe. 250 ms is
	// generous against the DP's buffered-stderr latency and the
	// in-process counter mutex, so a regression whose increment lands
	// slightly after close is not missed by a too-early snapshot.
	time.Sleep(250 * time.Millisecond)
	after := dpharness.Status(t, h)

	// (a) request_count delta exactly zero — the FR-008 side-channel
	// rule itself (data-model.md §3: counting failures would let an
	// attacker brute-forcing tokens read their progress from the
	// counter; Principle III).
	t.Run("RequestCount_DeltaZero", func(t *testing.T) {
		beforeReq, _ := t025cCounterTotals(before)
		afterReq, _ := t025cCounterTotals(after)
		if afterReq != beforeReq {
			t.Fatalf("auth-failure burst moved request_count: baseline %d → "+
				"%d (want exactly 0 delta) — FR-008 / data-model.md §3: "+
				"auth failures MUST NOT count (Principle III: a counting "+
				"failure path is a token-guessing side channel, since an "+
				"attacker can submit tokens at will and read their progress)",
				beforeReq, afterReq)
		}
	})

	// (b) byte_count delta exactly zero — the synthesised AUTH_REQUIRED
	// template body (HTTP framing) and the 01 FF reply (SOCKS5 framing)
	// are DP-generated, never forwarded client↔upstream bytes
	// (data-model.md §3 byte_count rule). A failure path that wrapped
	// the client conn with the counting seam would book the template
	// body here; a failure path that dialed the upstream anyway would
	// book relay bytes. Zero is the only consistent value.
	t.Run("ByteCount_DeltaZero", func(t *testing.T) {
		_, beforeBytes := t025cCounterTotals(before)
		_, afterBytes := t025cCounterTotals(after)
		if afterBytes != beforeBytes {
			t.Fatalf("auth-failure burst moved byte_count: baseline %d → "+
				"%d (want exactly 0 delta) — data-model.md §3: byte_count "+
				"reflects only bytes forwarded between client and upstream; "+
				"the synthesised AUTH_REQUIRED template body is excluded, and "+
				"a failure path reaches no upstream at all",
				beforeBytes, afterBytes)
		}
	})

	// Whole-snapshot identity — stricter than the two per-column sums:
	// no row may appear, disappear, or change under any (route, hour)
	// key. Robust to an hour-boundary rollover mid-test (nothing
	// increments, so no adjacent row can be born; a rollover with a
	// regression present still shows up as an inequality here).
	t.Run("Snapshot_UnchangedByBurst", func(t *testing.T) {
		if !proto.Equal(before, after) {
			t.Fatalf("counter snapshot changed across the 200-attempt "+
				"auth-failure burst (before=%v after=%v) — some row under "+
				"some (route, hour) key changed even though the per-column "+
				"deltas above passed; data-model.md §3 leaves nothing else "+
				"the failure path may touch", before, after)
		}
	})
}

// t025cDriveSocks5AuthFailure performs one SOCKS5 CONNECT auth-failure
// attempt in the given mode and asserts the framing's failure shape:
// method selection 05 02, sub-negotiation reply exactly `01 FF`, then
// close with no further bytes (contracts/socks5-auth.md §"Auth failure
// response"). The reply's cross-case byte identity is T028's scope; the
// assert here is the attempt's failure precondition.
func t025cDriveSocks5AuthFailure(t *testing.T, h *dpharness.Harness, mode int) {
	t.Helper()
	c := t025cCandidates[mode]
	conn := dialProxy(t, h)
	defer func() { _ = conn.Close() }()
	// 30 s per attempt covers HMAC auth (sub-ms nominal) plus scheduler
	// slack on a loaded CI runner — the sibling tests' deadline shape.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	doMethodNegotiation(t, conn)
	reply := writeRawSubnegotiation(t, conn, "t025c", c.socks5Passwd)
	if want := []byte{0x01, 0xFF}; !bytes.Equal(reply, want) {
		_ = conn.Close()
		t.Fatalf("iteration burst mode %s: sub-negotiation reply = %x, "+
			"want %x — the attempt did not fail auth (FR-006); a success "+
			"increments request_count and masks the counter delta assertions",
			c.label, reply, want)
	}
	expectEOF(t, conn, "after 01 FF (mode "+c.label+")")
}

// t025cDriveHTTPConnectAuthFailure performs one HTTP CONNECT
// auth-failure attempt in the given mode and asserts the failure
// precondition: the response status line carries 407, the AUTH_REQUIRED
// signal on the CONNECT framing (FR-006 HTTP path). The template body's
// byte shape is T027's scope; the body is drained through EOF (bounded
// close window) so the DP's close is observed — the point where a
// close-flush regression would book failure bytes, if one ever existed.
func t025cDriveHTTPConnectAuthFailure(t *testing.T, h *dpharness.Harness, mode int) {
	t.Helper()
	c := t025cCandidates[mode]
	conn := dialProxy(t, h)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	dest := "t025c-connect.example.onion"
	req := "CONNECT " + dest + ":443 HTTP/1.1\r\n"
	if c.httpAuthHeader != "" {
		req += c.httpAuthHeader + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT request (mode %s): %v", c.label, err)
	}

	// Byte-at-a-time header read (the package helper) cannot over-read
	// past the header block — irrelevant for a failure response (no
	// tunnel follows), but it keeps the drain below well-defined.
	hdr := readConnectResponseHeader(t, conn)
	statusLine := hdr
	if i := bytes.Index(hdr, []byte("\r\n")); i >= 0 {
		statusLine = hdr[:i]
	}
	if !bytes.HasPrefix(statusLine, []byte("HTTP/1.1 407")) {
		_ = conn.Close()
		t.Fatalf("mode %s: CONNECT response status line = %q, want 407 — "+
			"the attempt did not fail auth (FR-006); a success increments "+
			"request_count and masks the counter delta assertions",
			c.label, statusLine)
	}

	// Drain the template body through EOF. The 2 s deadline is the
	// close-check window (the contract requires close after the failure
	// response); a timeout means the DP held the connection — surfaced,
	// not swallowed, so the attempt cannot silently stay in flight
	// across the post-burst snapshot. ReadAll returns nil (not io.EOF)
	// on a clean close, so the guard below is exactly the error path.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Errorf("mode %s: DP did not close within 2 s of the 407 "+
				"response (contract requires close) — the attempt's "+
				"connection was still open at the drain deadline", c.label)
		}
		// Other non-timeout errors (reset, pipe) imply the conn is gone,
		// which satisfies the close half of the contract.
	}
}

// writeRawSubnegotiation writes the RFC 1929 username/password message
// (VER ULEN UNAME PLEN PASSWD) verbatim, allowing PLEN=0 — the
// missing-password attacker shape. doSubnegotiation rejects empty
// PASSWD because its callers assert well-formed offers; this raw form
// exists for the one mode that is deliberately not one. The DP's
// readUserPass treats PLEN=0 as a failed read (`!ok`) and replies the
// same `01 FF` + close as any other failure (listener socks5.go).
func writeRawSubnegotiation(t *testing.T, conn net.Conn, uname, passwd string) []byte {
	t.Helper()
	user := []byte(uname)
	pass := []byte(passwd)
	req := append([]byte{0x01, byte(len(user))}, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write RFC 1929 sub-negotiation: %v", err)
	}
	return readN(t, conn, 2)
}

// t025cCounterTotals sums request_count and byte_count across every row
// of a snapshot. The FR-008 property is "auth failures do not increment"
// — summed over the whole snapshot it is stricter than filtering
// route='TOR': a failure-mode increment leaking in under any route label
// cannot hide. uint64 magnitudes here are far below overflow range.
func t025cCounterTotals(resp *grpcpb.StatusResponse) (requests, bytes uint64) {
	for _, c := range resp.GetCounters() {
		requests += c.GetRequestCount()
		bytes += c.GetByteCount()
	}
	return requests, bytes
}
