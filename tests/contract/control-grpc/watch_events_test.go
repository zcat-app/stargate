// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the WatchEvents RPC — specs/001-tor-route/contracts/
// control-grpc.md §"WatchEvents · Tests" rows 1–3, one sub-test per row.
//
// WatchEvents is server-streamed by the control plane; the data plane is
// the gRPC CLIENT that dials /run/stargate/control.sock. This test hosts
// a FAKE control plane on control.sock before the DP boots (the inverse
// of T020's no-CP harness, which exercises the DP-hosted ReloadTokens
// surface), drives the event stream from the server side, and observes
// the DP externally only: the SOCKS5 request-phase reply on port 8881
// (route transition), the stream lifecycle (dial count, server-side
// close), and the captured stderr journal (contract violations).
//
// Scope (per T021 task body): happy-path pairings only — STARTED pairs
// with container_start, HEALTHY pairs with healthcheck_pass. The failure-
// transition pairings (UNHEALTHY/STOPPED/CRASHED/RESTARTED) are T070b's
// scope (Phase 5, paired with T074 implementation). The
// assertDetailRejected helper below is the shared seam T070b sub-test (e)
// reuses for its fixed-vocabulary invariant.
package controlgrpc

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// --- fake control plane ---------------------------------------------------

// fakeEventsServer is a programmable Events server hosted on control.sock.
// Each WatchEvents call creates a controlledStream that test code drives
// via send / closeFromServer and observes via dialCount / latestStream.
type fakeEventsServer struct {
	grpcpb.UnimplementedEventsServer

	mu      sync.Mutex
	dials   int
	streams []*controlledStream
}

// controlledStream is one WatchEvents RPC invocation. push feeds events
// to the DP; done is closed when the handler returns (DP disconnect,
// test-initiated close, or stream-context cancel); closeSig lets the test
// end the stream from the server side (row 3's disconnect scenario).
type controlledStream struct {
	push     chan *grpcpb.SidecarEvent
	done     chan struct{}
	closeSig chan struct{}
}

func (f *fakeEventsServer) WatchEvents(_ *grpcpb.WatchEventsRequest, stream grpcpb.Events_WatchEventsServer) error {
	f.mu.Lock()
	f.dials++
	cs := &controlledStream{
		push:     make(chan *grpcpb.SidecarEvent, 16),
		done:     make(chan struct{}),
		closeSig: make(chan struct{}),
	}
	f.streams = append(f.streams, cs)
	f.mu.Unlock()

	defer close(cs.done)
	for {
		select {
		case ev := <-cs.push:
			if err := stream.Send(ev); err != nil {
				return err
			}
		case <-cs.closeSig:
			return nil
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (f *fakeEventsServer) dialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dials
}

func (f *fakeEventsServer) latestStream() *controlledStream {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.streams) == 0 {
		return nil
	}
	return f.streams[len(f.streams)-1]
}

// send pushes an event to the most-recent stream's handler, which then
// forwards it to the DP via stream.Send. Returns an error if no stream
// exists or it has already ended.
func (f *fakeEventsServer) send(ev *grpcpb.SidecarEvent) error {
	cs := f.latestStream()
	if cs == nil {
		return errors.New("no active WatchEvents stream")
	}
	select {
	case cs.push <- ev:
		return nil
	case <-cs.done:
		return errors.New("stream already ended")
	}
}

// closeFromServer ends the latest stream from the server side (row 3's
// disconnect scenario). Safe to call multiple times; a no-op on streams
// already closed.
func (f *fakeEventsServer) closeFromServer() {
	cs := f.latestStream()
	if cs == nil {
		return
	}
	select {
	case <-cs.closeSig:
	default:
		close(cs.closeSig)
	}
}

// startFakeCP hosts a fake control plane on ${ipcDir}/control.sock BEFORE
// the DP boots, so the DP's first WatchEvents dial succeeds immediately.
// Cleanup (GracefulStop) is registered with t.
func startFakeCP(t *testing.T, ipcDir string) *fakeEventsServer {
	t.Helper()
	sockPath := filepath.Join(ipcDir, "control.sock")
	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen on %s: %v", sockPath, err)
	}
	srv := grpc.NewServer()
	f := &fakeEventsServer{}
	grpcpb.RegisterEventsServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)
	return f
}

// --- content gates --------------------------------------------------------

// requireWatchEventsConsumer gates on the DP's WatchEvents consumer
// existing. Every T021 sub-test needs client.go (T045 client side);
// without it the DP never dials control.sock and no event stream exists.
func requireWatchEventsConsumer(t *testing.T) {
	t.Helper()
	repoRoot := findRepoRoot(t)
	gate := filepath.Join(repoRoot, "data-plane", "internal", "controlclient", "client.go")
	if _, err := os.Stat(gate); err != nil {
		t.Skipf("blocked: %s absent — DP WatchEvents consumer not implemented (T045 client.go); this skip self-lifts when it lands", gate)
	}
}

// requireForwardPath gates on the SOCKS5 listener + forward path existing.
// Route-transition observations (rows 1 and 3) need both: the listener to
// reach the request phase, the forward path to produce a post-HEALTHY
// reply that is NOT the DISABLED-mask ROUTE_DOWN shape.
func requireForwardPath(t *testing.T) {
	t.Helper()
	repoRoot := findRepoRoot(t)
	for _, gate := range []string{
		filepath.Join(repoRoot, "data-plane", "internal", "listener", "socks5.go"),
		filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go"),
	} {
		if _, err := os.Stat(gate); err != nil {
			t.Skipf("blocked: %s absent — forward path not implemented (T042/T047); route-observation sub-test self-lifts when both land", gate)
		}
	}
}

// --- SOCKS5 request-phase probe -------------------------------------------

// socks5ConnectReply drives a full SOCKS5 handshake (method negotiation +
// RFC 1929 auth with the given plaintext + RFC 1928 §4 CONNECT request)
// and returns the 10-byte request-phase reply. On the DISABLED-mask path
// the reply is byte-exact 05 03 00 01 00 00 00 00 00 00 per
// contracts/socks5-auth.md §"SOCKS5 request-phase failures"; on the
// ENABLED path the REP is ≠ 0x03 (exact value forward-path/T072-
// dependent, not T021's claim). Fatal on any transport or auth-phase
// contract breach — those failures are not what the sub-tests assert.
func (h *dpHarness) socks5ConnectReply(t *testing.T, plaintext string) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", h.proxyAddr, err)
	}
	defer conn.Close()
	// 30 s covers argon2id auth (~50 ms) + worst-case forward dial.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Method negotiation: offer USERNAME/PASSWORD only.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	methods := make([]byte, 2)
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if methods[0] != 0x05 || methods[1] != 0x02 {
		t.Fatalf("method selection = %#02x %#02x, want 0x05 0x02 (socks5-auth.md §\"Auth method negotiation\")", methods[0], methods[1])
	}

	// RFC 1929 auth with the plaintext as password.
	user := []byte("t021")
	pass := []byte(plaintext)
	req := append([]byte{0x01, byte(len(user))}, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write userpass sub-negotiation: %v", err)
	}
	authRep := make([]byte, 2)
	if _, err := io.ReadFull(conn, authRep); err != nil {
		t.Fatalf("read userpass reply: %v", err)
	}
	if authRep[0] != 0x01 {
		t.Fatalf("userpass reply version = %#02x, want 0x01 (RFC 1929 §2)", authRep[0])
	}
	if authRep[1] != 0x00 {
		// Don't interpolate the plaintext — it's the one secret in scope,
		// and failure output lands in CI logs (index-only hygiene, same
		// discipline as assertNoSecretLeak).
		t.Fatalf("auth failed: userpass status = %#02x — plaintext not in current generation", authRep[1])
	}

	// RFC 1928 §4 CONNECT to 198.51.100.1:443 (TEST-NET-2, unroutable).
	// The destination is irrelevant to the reply-byte assertion — it just
	// needs to be a valid IPv4 ATYP request shape.
	connectReq := []byte{
		0x05,                   // VER
		0x01,                   // CMD = CONNECT
		0x00,                   // RSV
		0x01,                   // ATYP = IPv4
		0xc6, 0x33, 0x64, 0x01, // 198.51.100.1
		0x01, 0xbb, // port 443
	}
	if _, err := conn.Write(connectReq); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	// Read the 10-byte reply (socks5-auth.md's failure-path shape; the
	// success path is also a 10-byte reply with a different REP).
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatalf("read CONNECT reply (expected 10 bytes per socks5-auth.md §\"SOCKS5 request-phase failures\"): %v", err)
	}
	return rep
}

// assertRouteStaysDisabled polls the SOCKS5 reply for ~2 s, asserting the
// mask STAYS DISABLED throughout. Used after STARTED to prove STARTED
// alone does not transition the mask (data-model.md §2: only HEALTHY
// transitions to ENABLED). Polling — not a single-shot probe — catches a
// spurious transition any time in the window, which a single shot could
// miss if the DP's event goroutine runs after the probe returns.
func assertRouteStaysDisabled(t *testing.T, h *dpHarness, plaintext, why string) {
	t.Helper()
	want := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	deadline := time.Now().Add(2 * time.Second)
	for probes := 1; time.Now().Before(deadline); probes++ {
		rep := h.socks5ConnectReply(t, plaintext)
		if !bytes.Equal(rep, want) {
			t.Errorf("route transitioned away from DISABLED during the STARTED-only window (%s, probe %d) — reply = % x, want byte-exact ROUTE_DOWN shape; STARTED alone MUST NOT flip the mask (data-model.md §2)", why, probes, rep)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// waitForRouteEnabled polls the SOCKS5 reply until the mask flips to
// ENABLED (REP ≠ 0x03) or the timeout expires. The post-HEALTHY reply's
// exact REP is forward-path/T072-dependent; this helper asserts only that
// the DISABLED-mask ROUTE_DOWN reply (05 03 ...) is gone — the only
// contract claim row 1 makes at the route layer.
func waitForRouteEnabled(t *testing.T, h *dpHarness, plaintext, why string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		rep := h.socks5ConnectReply(t, plaintext)
		if len(rep) >= 2 && rep[1] != 0x03 {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("route did not transition to ENABLED within 15s (%s) — still DISABLED\ndata-plane journal:\n%s", why, h.journal.String())
}

// journalHasDetailViolation reports whether the captured journal contains
// a marker that only a contract-violation line for an out-of-vocabulary
// detail value would contain. The contract does not pin the exact line
// shape; this checks a set of plausible violation phrasings rather than
// the bare substring "detail", which an event-receipt log line could also
// match (and which would therefore never catch a DP that logs the receipt
// but not the violation).
func (h *dpHarness) journalHasDetailViolation() bool {
	for _, marker := range []string{"violation", "unknown detail", "invalid detail", "forbidden detail", "rejected"} {
		if h.journalContains(marker) {
			return true
		}
	}
	return false
}

// --- shared helper (reused by T070b sub-test (e)) -------------------------

// assertDetailRejected sends a SidecarEvent with the given detail value
// and asserts the DP's WatchEvents consumer treats it as a contract
// violation: the stream ends (DP-side close observed server-side via the
// handler returning) and the journal records the violation. Shared with
// T070b sub-test (e) per the T021 task body's "shared helper" commitment.
func assertDetailRejected(t *testing.T, h *dpHarness, fakeCP *fakeEventsServer, detail string) {
	t.Helper()
	cs := fakeCP.latestStream()
	if cs == nil {
		t.Fatalf("no active WatchEvents stream to send forbidden detail to")
	}
	ev := &grpcpb.SidecarEvent{
		Ts:      timestamppb.Now(),
		Sidecar: "tor",
		Kind:    grpcpb.EventKind_EVENT_KIND_STARTED,
		Detail:  detail,
	}
	// Send directly to the CAPTURED stream's push channel, not via
	// fakeCP.send (which re-resolves latestStream internally and could
	// race with a reconnect between the capture above and the send —
	// relevant for T070b's failure-transition reuse where reconnects are
	// part of the scenario under test).
	select {
	case cs.push <- ev:
	case <-cs.done:
		t.Fatalf("stream ended before forbidden-detail event could be sent")
	}
	// The DP MUST close the stream on the violation (contracts/control-
	// grpc.md §"WatchEvents · Contract" closed-vocabulary clause).
	select {
	case <-cs.done:
		// good — handler returned (DP closed the stream)
	case <-time.After(10 * time.Second):
		t.Errorf("DP did not close the stream after forbidden detail %q within 10s — contract requires unknown detail to be treated as a violation", detail)
	}
	// The DP MUST journal the violation (a line class T025a's allowlist
	// reserves). The marker set matches plausible violation-line phrasings
	// without matching event-receipt lines.
	if !h.journalHasDetailViolation() {
		t.Errorf("journal has no contract-violation marker for forbidden detail %q — contract requires the violation to be journaled", detail)
	}
	// The closed-vocabulary gate exists so sidecar free text never reaches
	// the DP journal. The violation must be journaled WITHOUT the offending
	// value — a DP that logs "rejected: detail=\"could not bind...\"" would
	// pass the marker check above while leaking the exact text the
	// vocabulary exists to keep out (constitution Principle III). Reuses
	// findSecretLeaks so a DP that logs the value in hex/base64/decimal is
	// caught too. Failure messages are encoding-name-only (no byte values)
	// per the established index-only hygiene.
	if leaks := findSecretLeaks(h.journal.String(), []byte(detail)); len(leaks) != 0 {
		t.Errorf("journal echoes forbidden detail verbatim (%s) — closed-vocabulary violation must be journaled without the offending sidecar free-text (constitution Principle III)", strings.Join(leaks, ", "))
	}
}

// --- the test -------------------------------------------------------------

func TestWatchEvents(t *testing.T) {
	// Every sub-test needs the WatchEvents consumer (T045 client.go) plus
	// the DP gRPC server + main that startDP gates on. Run the consumer
	// gate here so one precise skip message covers the whole test when
	// T045's client side hasn't landed yet.
	requireWatchEventsConsumer(t)

	// eventStarted / eventHealthy are the v1 happy-path (kind, detail)
	// pairings per contracts/control-grpc.md §"WatchEvents · Contract".
	eventStarted := &grpcpb.SidecarEvent{
		Ts:      timestamppb.Now(),
		Sidecar: "tor",
		Kind:    grpcpb.EventKind_EVENT_KIND_STARTED,
		Detail:  "container_start",
	}
	eventHealthy := &grpcpb.SidecarEvent{
		Ts:      timestamppb.Now(),
		Sidecar: "tor",
		Kind:    grpcpb.EventKind_EVENT_KIND_HEALTHY,
		Detail:  "healthcheck_pass",
	}

	// Contract row 1: STARTED then HEALTHY transitions routeEnableMask
	// from cold-start DISABLED to ENABLED. STARTED alone MUST NOT flip
	// the mask — probed between the two events.
	t.Run("HappyPathTransitionsRouteToEnabled", func(t *testing.T) {
		requireForwardPath(t) // route observation needs T042 + T047

		var fakeCP *fakeEventsServer
		h := startDPWith(t, func(ipcDir string) {
			fakeCP = startFakeCP(t, ipcDir)
		})

		// Load a known-plaintext token so SOCKS5 auth reaches the
		// request phase, where the route mask is observed.
		const plaintext = "t021-plain-alpha"
		tok := mintToken(t, plaintext)
		h.reload(t, 1, []*grpcpb.TokenHash{tok})

		// Wait for the DP to dial control.sock (WatchEvents consumer up).
		waitFor(t, "DP to dial control.sock", 20*time.Second, h.journal, func() bool {
			return fakeCP.dialCount() >= 1
		})

		// Send STARTED. The mask MUST stay DISABLED (data-model.md §2:
		// only HEALTHY transitions to ENABLED). Poll for ~2 s so a
		// spurious transition any time in the window is caught, not just
		// at one point — the STARTED consumer runs async to this probe.
		if err := fakeCP.send(eventStarted); err != nil {
			t.Fatalf("send STARTED: %v", err)
		}
		assertRouteStaysDisabled(t, h, plaintext, "after STARTED alone (HEALTHY not yet sent)")

		// Send HEALTHY. The mask MUST flip to ENABLED.
		if err := fakeCP.send(eventHealthy); err != nil {
			t.Fatalf("send HEALTHY: %v", err)
		}
		waitForRouteEnabled(t, h, plaintext, "after HEALTHY/healthcheck_pass")

		assertNoSecretLeak(t, h, tok.GetHash(), tok.GetSalt(), []byte(plaintext))
	})

	// Contract row 2: an out-of-vocabulary detail is a contract violation.
	// Regression gate against a maintainer piping log lines into detail.
	t.Run("ForbiddenDetailRejected", func(t *testing.T) {
		var fakeCP *fakeEventsServer
		h := startDPWith(t, func(ipcDir string) {
			fakeCP = startFakeCP(t, ipcDir)
		})

		waitFor(t, "DP to dial control.sock", 20*time.Second, h.journal, func() bool {
			return fakeCP.dialCount() >= 1
		})

		assertDetailRejected(t, h, fakeCP, "could not bind 0.0.0.0:9050")
	})

	// Contract row 3: the DP reconnects with bounded backoff after a
	// server-side stream close; events on the second stream are applied.
	t.Run("DisconnectReconnectAppliesEvents", func(t *testing.T) {
		// The reconnect-timing assertion (below) needs ONLY client.go
		// (T045 reconnect logic) — per §Acceptance it runs even when the
		// forward path is absent. requireForwardPath is therefore called
		// AFTER the timing assertion, gating only the route-observation
		// tail (which needs T042 + T047). This matches row 2's pattern.
		var fakeCP *fakeEventsServer
		h := startDPWith(t, func(ipcDir string) {
			fakeCP = startFakeCP(t, ipcDir)
		})

		const plaintext = "t021-plain-alpha"
		tok := mintToken(t, plaintext)
		h.reload(t, 1, []*grpcpb.TokenHash{tok})

		waitFor(t, "DP to dial control.sock", 20*time.Second, h.journal, func() bool {
			return fakeCP.dialCount() >= 1
		})

		// Send STARTED on the first stream, then close from the server
		// side (simulates CP crash / restart / network blip).
		if err := fakeCP.send(eventStarted); err != nil {
			t.Fatalf("send STARTED on first stream: %v", err)
		}
		fakeCP.closeFromServer()
		// Wait for the handler to actually return so the timing
		// measurement starts from a confirmed stream termination.
		firstStream := fakeCP.latestStream()
		if firstStream != nil {
			select {
			case <-firstStream.done:
			case <-time.After(5 * time.Second):
				t.Fatalf("first stream did not end within 5s of server-side close")
			}
		}
		streamEndTime := time.Now()

		// The DP reconnects with bounded backoff (initial 1s, ±20% jitter,
		// cap 30s per contracts/control-grpc.md §"WatchEvents"). The
		// waitFor timeout is 35s — strictly above the 30s cap — so the
		// upper-bound assertion below is reachable rather than dead code
		// (waitFor.Fatalf would fire first at a 30s timeout).
		waitFor(t, "DP to reconnect after server-side stream close", 35*time.Second, h.journal, func() bool {
			return fakeCP.dialCount() >= 2
		})
		elapsed := time.Since(streamEndTime)

		// Lower bound (0.8s): proves backoff, not immediate retry. The
		// contract's initial backoff is 1s ± 20% → [0.8s, 1.2s].
		if elapsed < 800*time.Millisecond {
			t.Errorf("reconnect after %v — want ≥ 0.8s (backoff initial 1s ±20%%); immediate retry violates contracts/control-grpc.md §WatchEvents", elapsed)
		}
		// Upper bound (30s): the contract's cap. The first reconnect after
		// one close is structurally near ~1s (initial backoff step), so
		// this is a sanity bound rather than a precision test — the
		// contract cap itself is T045's unit-test territory.
		if elapsed > 30*time.Second {
			t.Errorf("reconnect after %v — want ≤ 30s (backoff cap per contracts/control-grpc.md §WatchEvents)", elapsed)
		}

		// Route observation on the second stream — needs the forward path.
		requireForwardPath(t)

		if err := fakeCP.send(eventHealthy); err != nil {
			t.Fatalf("send HEALTHY on reconnected stream: %v", err)
		}
		waitForRouteEnabled(t, h, plaintext, "after HEALTHY on the reconnected stream")

		assertNoSecretLeak(t, h, tok.GetHash(), tok.GetSalt(), []byte(plaintext))
	})
}
