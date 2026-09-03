// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the DP's WatchEvents consumer (T045 client.go):
// contracts/control-grpc.md §"WatchEvents" — the bounded backoff (initial
// 1s, cap 30s, jitter ±20%), the advisory-only event application
// (data-model.md §2; Principle II), and the closed-vocabulary detail gate
// (violation closes the stream and is journaled WITHOUT the offending
// value). The fake control plane here serves mTLS with the package's own
// configs, so the full gRPC-over-TLS dial path is exercised in-process;
// the process-level tier is T021 (tests/contract/control-grpc), which pins
// the reconnect band end-to-end once T050 lands.
package controlclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// --- key fixtures ------------------------------------------------------------

// keyFixture is one plane's key material: the Ed25519 key plus the PEM
// files the on-disk contract uses (dp.priv/dp.pub/cp.priv/cp.pub shapes).
type keyFixture struct {
	priv    ed25519.PrivateKey
	privPem []byte
}

func newKeyFixture(t *testing.T) keyFixture {
	t.Helper()
	priv, pemBytes := newEd25519Key(t)
	return keyFixture{priv: priv, privPem: pemBytes}
}

// writeKeysDir materialises a stargate-keys dir: dp.priv/dp.pub/cp.priv/
// cp.pub (wire-auth.md §6.1). pepper.key is auth-package territory and not
// written here.
func writeKeysDir(t *testing.T, dp, cp keyFixture) string {
	t.Helper()
	dir := t.TempDir()
	writePrivFile(t, filepath.Join(dir, "dp.priv"), dp.privPem)
	writePrivFile(t, filepath.Join(dir, "cp.priv"), cp.privPem)
	writePubFile(t, filepath.Join(dir, "dp.pub"), dp.priv)
	writePubFile(t, filepath.Join(dir, "cp.pub"), cp.priv)
	return dir
}

// --- backoff (§"WatchEvents": initial 1s, cap 30s, jitter ±20%) --------------

func TestBackoffSequenceBounds(t *testing.T) {
	// Deterministic jitter: rng is the uniform sample in [0,1]; factor =
	// 1 + (2*rng − 1)·0.2 → rng 0.5 → 1.0×. Growth: 1s, 2s, 4s … capped.
	b := newBackoff(backoffConfig{initial: time.Second, max: 30 * time.Second, jitterPct: 0.2}, func() float64 { return 0.5 })
	wantBase := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	for i, base := range wantBase {
		if got := b.next(); got != base {
			t.Errorf("attempt %d wait = %v, want %v (exponential growth from 1s, capped at 30s)", i, got, base)
		}
	}
	for i := 0; i < 5; i++ {
		if got := b.next(); got != 30*time.Second {
			t.Fatalf("post-cap wait = %v, want the 30s cap", got)
		}
	}
}

func TestBackoffJitterStaysInContractBand(t *testing.T) {
	// ±20% jitter around the base; the 30s cap is respected AFTER jitter
	// (a capped base may never wait longer than 30s).
	hi := newBackoff(backoffConfig{initial: time.Second, max: 30 * time.Second, jitterPct: 0.2}, func() float64 { return 1 })
	if got := hi.next(); got != 1200*time.Millisecond {
		t.Errorf("upper-jitter first wait = %v, want 1.2s (1s +20%%)", got)
	}
	lo := newBackoff(backoffConfig{initial: time.Second, max: 30 * time.Second, jitterPct: 0.2}, func() float64 { return 0 })
	if got := lo.next(); got != 800*time.Millisecond {
		t.Errorf("lower-jitter first wait = %v, want 0.8s (1s −20%%; T021's reconnect lower bound)", got)
	}
	capped := newBackoff(backoffConfig{initial: time.Second, max: 30 * time.Second, jitterPct: 0.2}, func() float64 { return 1 })
	for i := 0; i < 20; i++ {
		capped.next()
	}
	if got := capped.next(); got > 30*time.Second {
		t.Errorf("capped wait = %v exceeds the 30s contract cap", got)
	}
}

func TestBackoffResetOnHealthyStream(t *testing.T) {
	// A stream that proved alive (delivered an event) resets the chain, so
	// a drop after a long-lived stream waits the initial ~1s band, not the
	// 30s cap (control-grpc.md §"WatchEvents" reconnect semantics).
	b := newBackoff(backoffConfig{initial: time.Second, max: 30 * time.Second, jitterPct: 0.2}, func() float64 { return 0.5 })
	for i := 0; i < 6; i++ {
		b.next()
	}
	b.reset()
	if got := b.next(); got != time.Second {
		t.Errorf("post-reset wait = %v, want the 1s initial (reconnect-after-drop contract)", got)
	}
}

// --- in-process fake control plane over mTLS ---------------------------------

// recordingSink is the EventSink seam (T073's advisory-application point):
// it records applied events. Application is structurally admission-free —
// the listener never consults the sink; the client only feeds it.
type recordingSink struct {
	mu     sync.Mutex
	events []*grpcpb.SidecarEvent
}

func (r *recordingSink) HandleSidecarEvent(ev *grpcpb.SidecarEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingSink) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// fakeStream is one observed WatchEvents invocation.
type fakeStream struct {
	push     chan *grpcpb.SidecarEvent
	closeSig chan struct{}
	done     chan struct{}
	mu       sync.Mutex
	closed   bool
}

// send queues an event to the DP; closeFromServer ends the stream from the
// server side (the row-3 disconnect scenario).
func (s *fakeStream) send(ev *grpcpb.SidecarEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.push <- ev
}

func (s *fakeStream) closeFromServer() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.closeSig)
	}
}

// fakeCP is a programmable mTLS Events server — the in-process stand-in for
// the control plane's WatchEvents half (T038).
type fakeCP struct {
	grpcpb.UnimplementedEventsServer

	mu      sync.Mutex
	streams []*fakeStream
}

func (f *fakeCP) WatchEvents(_ *grpcpb.WatchEventsRequest, stream grpcpb.Events_WatchEventsServer) error {
	fs := &fakeStream{
		push:     make(chan *grpcpb.SidecarEvent, 8),
		closeSig: make(chan struct{}),
		done:     make(chan struct{}),
	}
	f.mu.Lock()
	f.streams = append(f.streams, fs)
	f.mu.Unlock()
	defer close(fs.done)
	for {
		select {
		case ev := <-fs.push:
			if err := stream.Send(ev); err != nil {
				return err
			}
		case <-fs.closeSig:
			return nil
		case <-stream.Context().Done():
			return nil
		}
	}
}

func (f *fakeCP) latest() *fakeStream {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.streams) == 0 {
		return nil
	}
	return f.streams[len(f.streams)-1]
}

func (f *fakeCP) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.streams)
}

// startFakeCPOnUDS hosts the fake CP over the package's own server TLS
// (cert = cp identity, pinning dp.pub — the mirror image of the DP's
// control.sock dial) on a short unix socket, returning the path.
func startFakeCPOnUDS(t *testing.T, f *fakeCP, keysDir string, cp keyFixture) string {
	t.Helper()
	cert, err := DeriveCert(cp.priv, CPIdentity)
	if err != nil {
		t.Fatalf("DeriveCert(cp): %v", err)
	}
	sockDir, err := os.MkdirTemp("", "t045cp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "control.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen %s: %v", sock, err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(ServerTLSConfig(cert, filepath.Join(keysDir, "dp.pub")))))
	grpcpb.RegisterEventsServer(gs, f)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return sock
}

// newTestClient builds a Client against sock with fast deterministic
// backoff and a captured journal. TLS comes from DeriveDPTLS(keysDir) —
// the production path.
func newTestClient(t *testing.T, sock, keysDir string, sink EventSink, logBuf *bytes.Buffer) *Client {
	t.Helper()
	tlsClient, _, err := DeriveDPTLS(keysDir)
	if err != nil {
		t.Fatalf("DeriveDPTLS: %v", err)
	}
	client, err := NewClient(ClientConfig{
		ControlSocket: sock,
		TLS:           tlsClient,
		Sink:          sink,
		Log:           slog.New(slog.NewTextHandler(logBuf, nil)),
	}, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func waitDial(t *testing.T, f *fakeCP, n int) *fakeStream {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f.count() >= n {
			return f.latest()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("client never reached %d dials (at %d)", n, f.count())
	return nil
}

// --- the consumer loop -------------------------------------------------------

func TestClientConsumesEventsAdvisory(t *testing.T) {
	// Contract: events reach the sink (advisory status/audit hints) and are
	// journaled as receipts; nothing in the path gates anything else — the
	// consumer only ever calls the sink (T073 wires the audit application).
	dp, cp := newKeyFixture(t), newKeyFixture(t)
	keysDir := writeKeysDir(t, dp, cp)
	fake := &fakeCP{}
	sock := startFakeCPOnUDS(t, fake, keysDir, cp)
	sink := &recordingSink{}
	var logBuf bytes.Buffer
	client := newTestClient(t, sock, keysDir, sink, &logBuf)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		client.Run(ctx)
		close(done)
	}()

	sc := waitDial(t, fake, 1)
	sc.send(&grpcpb.SidecarEvent{Sidecar: "tor", Kind: 1 /* STARTED */, Detail: "container_start"})
	waitFor(t, 2*time.Second, func() bool { return sink.len() == 1 })
	if got := sink.events[0].GetDetail(); got != "container_start" {
		t.Errorf("sink saw detail %q, want container_start (advisory pass-through)", got)
	}
	if !bytes.Contains(logBuf.Bytes(), []byte(`msg="sidecar event"`)) {
		t.Errorf("no sidecar_event receipt journal line; journal:\n%s", logBuf.String())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestClientIgnoresForeignSidecars(t *testing.T) {
	// §"WatchEvents": other sidecar values appear in later features; this
	// feature IGNORES them — no sink call, no violation.
	dp, cp := newKeyFixture(t), newKeyFixture(t)
	keysDir := writeKeysDir(t, dp, cp)
	fake := &fakeCP{}
	sock := startFakeCPOnUDS(t, fake, keysDir, cp)
	sink := &recordingSink{}
	var logBuf bytes.Buffer
	client := newTestClient(t, sock, keysDir, sink, &logBuf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	sc := waitDial(t, fake, 1)
	sc.send(&grpcpb.SidecarEvent{Sidecar: "nym", Kind: 3, Detail: "healthcheck_pass"})
	time.Sleep(200 * time.Millisecond)
	if sink.len() != 0 {
		t.Error("foreign-sidecar event reached the sink — contract says ignore")
	}
	if bytes.Contains(logBuf.Bytes(), []byte("rejected")) {
		t.Errorf("foreign sidecar journaled as a violation — it must be ignored; journal:\n%s", logBuf.String())
	}
}

func TestClientRejectsOutOfVocabularyDetail(t *testing.T) {
	// Contract row 2 / closed-vocabulary clause: an out-of-vocabulary detail
	// is a violation — the DP closes the stream and journals the violation
	// WITHOUT echoing the offending value (Principle III; T021's
	// assertDetailRejected asserts the process-level shape of this).
	dp, cp := newKeyFixture(t), newKeyFixture(t)
	keysDir := writeKeysDir(t, dp, cp)
	fake := &fakeCP{}
	sock := startFakeCPOnUDS(t, fake, keysDir, cp)
	var logBuf bytes.Buffer
	client := newTestClient(t, sock, keysDir, &recordingSink{}, &logBuf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	sc := waitDial(t, fake, 1)
	const freeText = "could not bind 0.0.0.0:9050"
	sc.send(&grpcpb.SidecarEvent{Sidecar: "tor", Kind: 1, Detail: freeText})

	// The DP must tear the stream down — observable as the fake handler
	// returning (sc.done closed) within a bounded window.
	select {
	case <-sc.done:
	case <-time.After(5 * time.Second):
		t.Error("DP did not close the stream after an out-of-vocabulary detail")
	}
	logged := logBuf.String()
	if !bytes.Contains(logBuf.Bytes(), []byte("rejected")) {
		t.Errorf("journal has no violation marker for the forbidden detail; journal:\n%s", logged)
	}
	// The violation must be journaled without the offending free text —
	// the vocabulary exists to keep sidecar log lines out of the DP journal.
	if bytes.Contains(logBuf.Bytes(), []byte(freeText)) {
		t.Errorf("journal echoes the forbidden detail verbatim (Principle III); journal:\n%s", logged)
	}
}

func TestClientReconnectsAfterServerClose(t *testing.T) {
	// Contract row 3: after a server-side close the client reconnects and
	// events delivered on the new stream are applied normally. The real
	// [0.8s, 1.2s] reconnect band is pinned arithmetically (TestBackoff*)
	// and end-to-end by T021; the fast-backoff unit fixture pins the LOOP
	// behavior (reconnect happens, events flow again).
	dp, cp := newKeyFixture(t), newKeyFixture(t)
	keysDir := writeKeysDir(t, dp, cp)
	fake := &fakeCP{}
	sock := startFakeCPOnUDS(t, fake, keysDir, cp)
	sink := &recordingSink{}
	var logBuf bytes.Buffer
	client := newTestClient(t, sock, keysDir, sink, &logBuf)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.Run(ctx)

	first := waitDial(t, fake, 1)
	first.send(&grpcpb.SidecarEvent{Sidecar: "tor", Kind: 3, Detail: "healthcheck_pass"})
	waitFor(t, 2*time.Second, func() bool { return sink.len() == 1 })

	// Server-side close (CP crash / restart simulation).
	first.closeFromServer()
	second := waitDial(t, fake, 2)
	second.send(&grpcpb.SidecarEvent{Sidecar: "tor", Kind: 3, Detail: "healthcheck_pass"})
	waitFor(t, 2*time.Second, func() bool { return sink.len() == 2 })
}

func TestClientDegradedModeWarning(t *testing.T) {
	// Acceptance #6 / wire-auth §4 / arch §5.4: the CP being unreachable is
	// a degraded-mode WARNING and the loop keeps retrying — never fatal
	// (Principle II; the Run loop outlives the dead CP until ctx expires).
	// The warning fires on the degraded TRANSITION, not per retry.
	dir, err := os.MkdirTemp("", "t045nocp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	var logBuf bytes.Buffer
	tlsClient, _, errTLS := DeriveDPTLS(writeKeysDir(t, newKeyFixture(t), newKeyFixture(t)))
	if errTLS != nil {
		t.Fatal(errTLS)
	}
	client, err := NewClient(ClientConfig{
		ControlSocket: filepath.Join(dir, "absent.sock"),
		TLS:           tlsClient,
		Sink:          &recordingSink{},
		Log:           slog.New(slog.NewTextHandler(&logBuf, nil)),
	}, func() float64 { return 0.5 })
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	client.Run(ctx) // returns when ctx expires — the loop survived a dead CP

	logged := logBuf.String()
	if !bytes.Contains(logBuf.Bytes(), []byte("control channel degraded")) {
		t.Errorf("no degraded-mode warning journaled (acceptance #6); journal:\n%s", logged)
	}
	if n := bytes.Count(logBuf.Bytes(), []byte("control channel degraded")); n != 1 {
		t.Errorf("degraded warning fired %d times — the transition is journaled once, not per retry; journal:\n%s", n, logged)
	}
}

func TestClientNewClientRequiresConfig(t *testing.T) {
	// Edge validation at the boundary: a production Client without a socket
	// path, TLS config, or sink cannot be constructed (no insecure dials,
	// no nil-deref paths inside the trust boundary — CONTRIBUTING doctrine).
	if _, err := NewClient(ClientConfig{}, nil); err == nil {
		t.Error("NewClient accepted an empty config")
	}
	dp, cp := newKeyFixture(t), newKeyFixture(t)
	keysDir := writeKeysDir(t, dp, cp)
	tlsClient, _, err := DeriveDPTLS(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(ClientConfig{TLS: tlsClient, Sink: &recordingSink{}}, nil); err == nil {
		t.Error("NewClient accepted a config without a control socket path")
	}
	if _, err := NewClient(ClientConfig{ControlSocket: "/run/stargate/control.sock", Sink: &recordingSink{}}, nil); err == nil {
		t.Error("NewClient accepted a config without TLS — no insecure inter-plane dials (wire-auth §4)")
	}
	if _, err := NewClient(ClientConfig{ControlSocket: "/run/stargate/control.sock", TLS: tlsClient}, nil); err == nil {
		t.Error("NewClient accepted a config without an event sink")
	}
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met within deadline")
}
