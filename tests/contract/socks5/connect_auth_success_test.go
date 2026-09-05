// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the HTTP CONNECT auth-success response shape and
// bridge engagement — specs/001-tor-route/spec.md FR-005/FR-006/
// FR-007/FR-008 and contracts/socks5-auth.md §"HTTP CONNECT path"
// (the auth-success response is byte-exactly
// `HTTP/1.1 200 Connection Established\r\n\r\n`, then the data plane
// bridges to the upstream SOCKS5 connection using the host from the
// request line as the target) + §"Two inbound protocols, one port"
// (directory convention: CONNECT-framed auth-success lives under
// socks5/, not error-template/). Task body:
// specs/001-tor-route/tasks.md T026.
//
// This is the positive-path half of the two-framing split (research.md
// §9); T027 owns the AUTH_REQUIRED 407 failure half. T025b consumes
// CONNECT framing as a vehicle for the long-lived byte-pipe test and
// checks only the status-line prefix; T026 pins the EXACT response
// bytes (status line + blank line, no header, no body) and that the
// bridge engages the upstream — the contract detail T025b's
// §Out-of-scope defers here.
//
// The success response is scanned for the destination host and the
// offered token (the leak-scan rows apply symmetrically to success;
// Principle III / FR-008), and the journal delta around the CONNECT
// success is held to the T025a shared allowlist
// (tests/internal/loginvariants) — the CONNECT path is a distinct
// inbound surface (T043 listener/connect.go) from the SOCKS5 path
// T025a gated.
//
// Tests-first (Constitution Principle VII): content-gates on T043
// (listener/connect.go — the surface under test), T044 (auth/token.go),
// T047 (forward/tor.go — the bridge), and T045
// (controlclient/client.go — consumes the WatchEvents stream), plus
// the boot minimum inside dpharness.Start (T042/T045/T050); the test
// SKIPs until all land, then a response-shape or leak regression is
// FAIL, not SKIP. Admission is NOT gated on a SidecarEvent (data-model.md
// §2; Principle II; sol-review B3; remediated by T090): this test
// forwards through the fake upstream WITHOUT pushing HEALTHY — the
// primary no-gating regression for the CONNECT path.
package socks5

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	integration "github.com/zcat-app/stargate/tests/integration"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

// connectSuccessPlaintext is the bearer-token plaintext the test mints
// into an HMAC verifier via dpharness.MintToken and pushes to the DP
// via ReloadTokens. 32 hex chars — the CONNECT path's syntactic gate
// (contracts/socks5-auth.md §"HTTP CONNECT path" step 2:
// ^[0-9a-f]{32}$) must pass so the 200 + bridge engages. Distinct from
// T025a's and T025b's token plaintexts so a corpus-scan hit is
// attributable to this test.
const connectSuccessPlaintext = "f1e2d3c4b5a69788796a5b4c3d2e1f0a"

// wantConnectSuccessResponse is the byte-exact auth-success response
// the data plane MUST emit on the CONNECT path: the status line and
// the header-terminating blank line, nothing else — no Date, no
// Proxy-Agent, no Content-Length, no body before the bridge
// (contracts/socks5-auth.md §"HTTP CONNECT path" success prose).
const wantConnectSuccessResponse = "HTTP/1.1 200 Connection Established\r\n\r\n"

// connectResponseHeaderCeil bounds the captured response header block.
// The success response is 39 bytes; a DP that never emits the
// terminating blank line (or streams an unbounded response) would
// otherwise hang the reader. 8 KiB is far above the success response
// and tight against any plausible malformed response.
const connectResponseHeaderCeil = 8 << 10

// TestHTTPConnectAuthSuccess pins the CONNECT auth-success contract
// (exact 200 response bytes + bridge engagement + response/journal
// leak invariants). Single consolidated body — the four must-holds
// layer on one fixture (one DP boot, one token push, no HEALTHY, one
// CONNECT success); splitting would multiply HMAC-mint + boot cost
// without adding assertion coverage (the T025a precedent). No HEALTHY
// is pushed: admission is not CP-gated (T090; data-model.md §2).
func TestHTTPConnectAuthSuccess(t *testing.T) {
	repoRoot := dpharness.FindRepoRoot(t)
	// Per-test content gates beyond the boot minimum inside
	// dpharness.Start (T042/T045/T050): the CONNECT listener under
	// test, the auth surface, the forward path (the bridge), and the
	// WatchEvents client (consumes the advisory event stream).
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "listener", "connect.go"),
		"listener/connect.go not implemented yet (T043); this skip self-lifts when T043 lands")
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

	// Fake upstream in AcceptAndRelay mode: completes the upstream
	// SOCKS5 handshake, REP=0x00, then echoes. A sentinel written by
	// the client round-trips client→DP→upstream→DP→client, proving the
	// bridge engaged a real upstream connection (anti echo-false-pass).
	upstream := integration.NewServer(integration.AcceptAndRelay)
	upstreamAddr, err := upstream.Start()
	if err != nil {
		t.Fatalf("starting fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = upstream.Close() })

	// TLS fake CP hosted on control.sock BEFORE the DP boots (the
	// wire-auth §4 fixture lift, T050) so the WatchEvents consumer
	// actually connects (waitForWatchEventsDial below asserts the dial).
	h := dpharness.Start(t,
		dpharness.WithUpstream(upstreamAddr),
		dpharness.WithControlPlane(),
	)
	cp := h.CP

	reloadResp := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenVerifier{dpharness.MintToken(t, connectSuccessPlaintext)})
	if reloadResp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want "+
			"APPLY_STATUS_OK — precondition for the CONNECT success "+
			"test failed; the DP did not accept the test's token "+
			"generation", reloadResp.GetStatus())
	}

	// No HEALTHY push: admission is not CP-gated (data-model.md §2;
	// Principle II; sol-review B3; remediated by T090). The forward path
	// reaches the upstream and the bridge engages without any SidecarEvent.
	// The fake CP is hosted only so the DP's WatchEvents dial lands (no
	// retry-log noise); no event is sent.
	waitForWatchEventsDial(t, cp)

	// Quiesce before the journal snapshot — boot/reload lines must
	// flush so the delta carries only the CONNECT-success window.
	time.Sleep(250 * time.Millisecond)
	before := h.Journal.String()

	// Distinctive corpus items. The destination is the FR-008-named
	// surface; the token is the offered secret; the sentinel is the
	// bridge probe. Each is scanned in nine renderings where it could
	// appear (response bytes for dest+token; journal delta for all
	// three).
	const (
		dest     = "t026-dest.example.onion"
		sentinel = "t026-bridge-sentinel-payload-XXXXXXXXXXXX"
	)

	conn := dialProxy(t, h)
	t.Cleanup(func() { _ = conn.Close() })
	// 30 s covers HMAC auth (sub-ms) + the upstream dial + the echo round-trip.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Minimal valid request shape (contracts/socks5-auth.md §"HTTP
	// CONNECT path" step 1: the DP parses ONLY the request line and
	// Proxy-Authorization). Request line + Proxy-Authorization, then
	// the header-terminating blank line.
	req := fmt.Sprintf("CONNECT %s:443 HTTP/1.1\r\nProxy-Authorization: Bearer %s\r\n\r\n",
		dest, connectSuccessPlaintext)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	// (a) Exact auth-success response. Read the response byte-at-a-time,
	// capturing the full header block strictly up to and including the
	// header-terminating blank line. Byte-at-a-time (not bufio) so not
	// one tunnel byte is swallowed into a discarded buffer — the
	// discipline keeps the exact-response evidence self-contained and
	// over-read-free (§Analysis redteam scope (a); T025b's
	// openHTTPConnectTunnel uses the same technique).
	resp := readConnectResponseHeader(t, conn)
	if string(resp) != wantConnectSuccessResponse {
		// Response bytes are WITHHELD from this message: a buggy DP may
		// echo the destination or token into the response, and those
		// are scanned separately under Response_NoCorpusItem. Length-
		// only mirrors the loginvariants index-only discipline.
		t.Errorf("CONNECT auth-success response was %d bytes, want "+
			"byte-exactly %d (the status line + the header-terminating "+
			"blank line — contracts/socks5-auth.md §\"HTTP CONNECT "+
			"path\" success shape; Principle I); the DP added a header, "+
			"a body, or a non-canonical status line. Response bytes "+
			"withheld (leak-safe; see Response_NoCorpusItem for the "+
			"dest/token scan).",
			len(resp), len(wantConnectSuccessResponse))
	}

	// (c) Response leaks nothing: the 200 must carry no destination
	// host and no offered-token byte, in any of the nine textual
	// renderings an accidental logger would produce (the contract's
	// leak-scan rows apply symmetrically to success; Principle III /
	// FR-008). Run before the bridge so a response-shape bug is
	// attributable independent of the bridge outcome.
	t.Run("Response_NoCorpusItem", func(t *testing.T) {
		loginvariants.AssertNoSecrets(t, string(resp),
			[]byte(dest), []byte(connectSuccessPlaintext))
	})

	// (b) Bridge engages the upstream. After the 200 the data plane
	// MUST be a live byte pipe to the upstream SOCKS5 connection; a
	// sentinel written by the client round-trips through the
	// accept-and-relay echo. A DP that 200'd then dropped the socket
	// (or short-circuited to a local sink) cannot echo — the anti
	// echo-false-pass class. Single round-trip: the sustained
	// bidirectional pipe is T025b's scope.
	if _, err := conn.Write([]byte(sentinel)); err != nil {
		t.Fatalf("write bridge sentinel: %v — the DP closed or wedged "+
			"the tunnel immediately after the 200 (assertion (b): the "+
			"bridge MUST engage)", err)
	}
	echo := make([]byte, len(sentinel))
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("read bridge echo (len %d): %v — the tunnel did not "+
			"round-trip the sentinel through the upstream (assertion "+
			"(b); the bridge engaged neither the upstream nor a local "+
			"echo)", len(sentinel), err)
	}
	if !bytes.Equal(echo, []byte(sentinel)) {
		t.Errorf("bridge echo mismatch (len %d) — the byte pipe "+
			"mutated data on the first round-trip (Principle I; "+
			"payload bytes withheld from this message)", len(sentinel))
	}

	// Post-exchange quiesce, then the delta. The LockedBuffer is
	// append-only (strings.Builder), so slicing at len(before) is
	// safe — same grounding note as T025a/T025b.
	time.Sleep(250 * time.Millisecond)
	after := h.Journal.String()
	var delta string
	if len(after) >= len(before) {
		delta = after[len(before):]
	} else {
		delta = after
		t.Logf("journal shrank between snapshots (before=%d, after=%d) "+
			"— harness bug; scanning the whole post-exchange journal",
			len(before), len(after))
	}

	// (d) The CONNECT success path emits no per-request journal line:
	// allowlist first (catches unnamed per-request lines), then the
	// corpus scan (nine renderings per item), then the timestamp gate.
	// Symmetric to T025a's SOCKS5 success-path gate, for the distinct
	// CONNECT inbound surface (T043).
	t.Run("Journal_AllowlistOnly", func(t *testing.T) {
		loginvariants.AssertOnlyAllowedLines(t, delta)
	})
	t.Run("Journal_NoCorpusItem", func(t *testing.T) {
		loginvariants.AssertNoSecrets(t, delta,
			[]byte(dest), []byte(connectSuccessPlaintext), []byte(sentinel))
	})
	t.Run("Journal_NoSubHourTimestamp", func(t *testing.T) {
		loginvariants.AssertNoSubHourTimestamp(t, delta)
	})
}

// readConnectResponseHeader reads the HTTP CONNECT auth-success
// response strictly up to and including the header-terminating blank
// line (`\r\n\r\n`), byte-at-a-time, and returns the full captured
// header block. One-byte reads mean the reader cannot over-read past
// the blank line into tunnel bytes — the same discipline T025b's
// openHTTPConnectTunnel uses; this local helper additionally RETURNS
// the captured block so the caller can assert the response is byte-
// exactly the status line + blank line (T025b checks only the status-
// line prefix).
//
// Bounded by connectResponseHeaderCeil: a response that never emits
// the terminating blank line fails the test rather than hanging.
func readConnectResponseHeader(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var hdr []byte
	one := make([]byte, 1)
	for !bytes.HasSuffix(hdr, []byte("\r\n\r\n")) {
		if len(hdr) > connectResponseHeaderCeil {
			t.Fatalf("CONNECT response header block exceeded %d bytes "+
				"without a terminating blank line (got %d) — the DP "+
				"is streaming an unbounded response or never "+
				"terminating the header (contracts/socks5-auth.md "+
				"§\"HTTP CONNECT path\")", connectResponseHeaderCeil, len(hdr))
		}
		if _, err := io.ReadFull(conn, one); err != nil {
			t.Fatalf("read CONNECT response (after %d bytes): %v — the "+
				"DP closed or errored before terminating the header "+
				"block (contracts/socks5-auth.md §\"HTTP CONNECT "+
				"path\")", len(hdr), err)
		}
		hdr = append(hdr, one[0])
	}
	return hdr
}
