// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package fakecp hosts a programmable control-plane Events server on
// a Unix domain socket. It is the contract-test surrogate for the
// production control plane that hosts WatchEvents on
// /run/stargate/control.sock (T038). Tests host the fake BEFORE the
// data-plane process boots (via dpharness.WithBeforeBoot) so the DP's
// first WatchEvents dial (T045 client.go) succeeds immediately and
// the test can drive the event stream from the server side.
//
// The pattern is extracted from
// tests/contract/control-grpc/watch_events_test.go's fakeEventsServer.
// That file is deliberately NOT refactored to import from here — out
// of scope per ticket §Out-of-scope; the duplication is the
// established repo pattern (mirrors tests/contract/tor/findRepoRoot).
//
// Scope: T024 (this package's author) needs only the programmable-
// stream + Send capability (to push advisory HEALTHY/STARTED events;
// admission is not CP-gated per T090/data-model.md §2). The full
// surface (closeFromServer, dialCount, latestStream) is included
// because the package is designed for reuse by T025a–d, T026, T028,
// T070b — all of which need some subset.
package fakecp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// Server is a programmable Events server hosted on a Unix domain
// socket. Each WatchEvents call creates a controlledStream that test
// code drives via Send / CloseFromServer and observes via DialCount /
// LatestStream. The zero value is NOT usable; construct via Start.
type Server struct {
	grpcpb.UnimplementedEventsServer

	mu      sync.Mutex
	dials   int
	streams []*ControlledStream
}

// ControlledStream is one WatchEvents RPC invocation. Push feeds
// events to the DP; Done is closed when the handler returns (DP
// disconnect, test-initiated close, or stream-context cancel);
// closeSig lets the test end the stream from the server side.
type ControlledStream struct {
	push     chan *grpcpb.SidecarEvent
	done     chan struct{}
	closeSig chan struct{}
}

// WatchEvents is the gRPC server handler. It creates a fresh
// ControlledStream, registers it, and blocks feeding events to the
// DP until either the test pushes them, the test closes the stream,
// or the DP disconnects (stream context cancelled).
func (s *Server) WatchEvents(_ *grpcpb.WatchEventsRequest, stream grpcpb.Events_WatchEventsServer) error {
	s.mu.Lock()
	s.dials++
	cs := &ControlledStream{
		push:     make(chan *grpcpb.SidecarEvent, 16),
		done:     make(chan struct{}),
		closeSig: make(chan struct{}),
	}
	s.streams = append(s.streams, cs)
	s.mu.Unlock()

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

// DialCount returns the number of WatchEvents calls the DP has made
// to this Server. Used to assert reconnect behaviour (T021 row 3).
func (s *Server) DialCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dials
}

// LatestStream returns the most recently created ControlledStream, or
// nil if none exists. Used by tests that push events to the active
// stream without tracking the stream pointer themselves.
func (s *Server) LatestStream() *ControlledStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.streams) == 0 {
		return nil
	}
	return s.streams[len(s.streams)-1]
}

// Send pushes an event to the most-recent stream's handler, which
// forwards it to the DP via stream.Send. Returns an error if no
// stream exists or it has already ended. The common path is
// Healthy("tor"), an advisory status event (data-model.md §2;
// admission is not CP-gated per T090/Principle II — events do NOT
// gate admission, they update advisory status only).
func (s *Server) Send(ev *grpcpb.SidecarEvent) error {
	cs := s.LatestStream()
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

// CloseFromServer ends the latest stream from the server side (the
// disconnect scenario in T021 row 3). Safe to call multiple times; a
// no-op on streams already closed.
func (s *Server) CloseFromServer() {
	cs := s.LatestStream()
	if cs == nil {
		return
	}
	select {
	case <-cs.closeSig:
	default:
		close(cs.closeSig)
	}
}

// Start hosts a fake control plane on ${ipcDir}/control.sock BEFORE
// the DP boots, so the DP's first WatchEvents dial succeeds
// immediately. Cleanup (GracefulStop + listener close + socket file
// removal) is registered with t.
//
// ipcDir is the same dir the data plane reads via STARGATE_IPC_DIR
// (typically the harness's IPCDir field). The socket file name
// "control.sock" matches the production contract
// (contracts/control-grpc.md §"Socket topology").
//
// The transport is PLAINTEXT — the pre-wire-auth fixture shape kept for
// callers that never assert a DP dial (the keyless boot degrades before
// the WatchEvents client starts, so nothing ever connects). Tests that
// assert event delivery MUST use StartTLS: the landed DP client refuses
// unauthenticated inter-plane dials (data-plane controlclient NewClient,
// wire-auth.md §4), so a plaintext control.sock can never serve it.
func Start(t *testing.T, ipcDir string) *Server {
	return start(t, ipcDir, nil)
}

// StartTLS is Start with the wire-auth.md §4 server half: the fake CP
// presents the self-signed Ed25519 cert derived from keysDir/cp.priv and
// requires a DP client cert byte-pinned against keysDir/dp.pub (fresh
// read per handshake, §3.1 step 3) — the mirror of the DP's control.sock
// dial, exactly what the production CP (T038) will serve. keysDir is the
// SAME dir seeded for the DP process (dpharness.SeedInterPlaneKeys), so
// the pinned keys cross-match by construction.
func StartTLS(t *testing.T, ipcDir, keysDir string) *Server {
	cpPriv, err := LoadSigner(filepath.Join(keysDir, "cp.priv"))
	if err != nil {
		t.Fatalf("fakecp: loading seeded cp.priv: %v", err)
	}
	cert, err := SelfSigned(cpPriv, "stargate-cp")
	if err != nil {
		t.Fatalf("fakecp: deriving CP identity cert: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		// wire-auth.md §4 (mirrored from the DP side; see that §4 comment
		// for why InsecureSkipVerify=true is the load-bearing coupling):
		// client auth REQUIRED, the pin hook is the sole trust decision.
		InsecureSkipVerify:    true, //nolint:gosec // pinned peer public key IS the verifier (wire-auth.md §4)
		VerifyPeerCertificate: PinVerifier(filepath.Join(keysDir, "dp.pub")),
		ClientAuth:            tls.RequireAnyClientCert,
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{"h2"}, // wire-auth.md §4: pin explicitly; Go peers can mask omission
	}
	return start(t, ipcDir, cfg)
}

// start is the shared listen/serve core; a nil TLS config yields the
// legacy plaintext fixture, a non-nil one the §4 mTLS surface.
func start(t *testing.T, ipcDir string, tlsCfg *tls.Config) *Server {
	t.Helper()
	sockPath := filepath.Join(ipcDir, "control.sock")
	// Remove any stale socket file from a prior run. MkdirTemp gives
	// a fresh dir, but belt-and-braces: a stale file at this exact
	// path would make Listen(unix) fail with EADDRINUSE.
	_ = os.Remove(sockPath)
	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("fakecp: listen on %s: %v", sockPath, err)
	}
	var srv *grpc.Server
	if tlsCfg != nil {
		srv = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	} else {
		srv = grpc.NewServer()
	}
	s := &Server{}
	grpcpb.RegisterEventsServer(srv, s)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.GracefulStop()
		_ = os.Remove(sockPath)
	})
	return s
}

// --- wire-mirror helpers (independent outside view; the Go internal-
// package rule forbids importing data-plane/internal, the same reason
// wireprobe carries its own copies of this shape) -----------------------------

// LoadSigner reads a PKCS#8 PEM ed25519 private key (stargate-keys format).
func LoadSigner(path string) (ed25519.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: %T, want ed25519", path, key)
	}
	return priv, nil
}

// SelfSigned derives the minimal self-signed Ed25519 identity cert with
// the wire-auth.md §2.2 field values.
func SelfSigned(key ed25519.PrivateKey, cn string) (tls.Certificate, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return tls.Certificate{}, errors.New("fakecp: not an ed25519 key")
	}
	tmpl := &x509.Certificate{
		Version:               3,
		SerialNumber:          big.NewInt(0),
		SignatureAlgorithm:    x509.PureEd25519,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// PinVerifier is the §3.1 peer-pin hook: raw 32-byte Ed25519 key from the
// peer (DP) cert, byte-equal against the pinned dp.pub re-read fresh from
// disk on every handshake.
func PinVerifier(peerPubPath string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) != 1 {
			return fmt.Errorf("peer sent %d certs, want 1", len(rawCerts))
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		peerKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("peer key %T, want ed25519", cert.PublicKey)
		}
		pemBytes, err := os.ReadFile(peerPubPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return fmt.Errorf("%s: no PEM block", peerPubPath)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		pinned, ok := parsed.(ed25519.PublicKey)
		if !ok || !peerKey.Equal(pinned) {
			return errors.New("peer public key does not match the pinned key")
		}
		return nil
	}
}

// Healthy is a convenience constructor for the canonical HEALTHY
// SidecarEvent for the named sidecar. This is an advisory status
// event (data-model.md §2; admission is not CP-gated per
// T090/Principle II — events do NOT gate admission). Some tests push
// exactly one Healthy("tor") event after the DP's WatchEvents dial
// lands for advisory status visibility; the forward path is reached
// with or without it.
func Healthy(sidecar string) *grpcpb.SidecarEvent {
	return &grpcpb.SidecarEvent{
		Ts:      timestamppb.Now(),
		Sidecar: sidecar,
		Kind:    grpcpb.EventKind_EVENT_KIND_HEALTHY,
		Detail:  "healthcheck_pass",
	}
}

// Started is a convenience constructor for the STARTED SidecarEvent
// (paired with detail "container_start"). Tests that need to walk a
// sidecar through the full STARTED → HEALTHY advisory sequence use
// this before Healthy; tests that only need advisory status skip
// straight to Healthy.
func Started(sidecar string) *grpcpb.SidecarEvent {
	return &grpcpb.SidecarEvent{
		Ts:      timestamppb.Now(),
		Sidecar: sidecar,
		Kind:    grpcpb.EventKind_EVENT_KIND_STARTED,
		Detail:  "container_start",
	}
}
