// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Hermetic discrimination test for the `resume` mode (T155 A-1). The live
// probe runs against the deployed DP; this test shows, without Docker, that
// its verdict depends on the property it names. A dp.sock stand-in that
// re-checks the current cp.pub on resumed handshakes (VerifyConnection, as
// wire-auth.md §3.1/§4 require) must pass; one that pins only on full
// handshakes (VerifyPeerCertificate, the T135 defect) must fail at step 4;
// one that never issues tickets must fail the step-2 positive control; one
// that declines the old ticket after the rotation (as a restarted DP would)
// must fail step 4 as vacuous, because its refusal is a full handshake.
// The stand-in's pin check is written here, independently of the probe's.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

type statusServer struct {
	grpcpb.UnimplementedControlServer
}

func (statusServer) GetStatus(context.Context, *grpcpb.StatusRequest) (*grpcpb.StatusResponse, error) {
	return &grpcpb.StatusResponse{}, nil
}

func writePEM(t *testing.T, path, kind string, der []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), mode); err != nil {
		t.Fatal(err)
	}
}

// standInKeys writes cp.priv, cp.pub and dp.pub in the stargate-keys layout
// and returns the DP's private key.
func standInKeys(t *testing.T, dir string) ed25519.PrivateKey {
	t.Helper()
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dpPub, dpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(cpPriv)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "cp.priv"), "PRIVATE KEY", privDER, 0o600)
	for name, pub := range map[string]ed25519.PublicKey{"cp.pub": cpPub, "dp.pub": dpPub} {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		writePEM(t, filepath.Join(dir, name), "PUBLIC KEY", der, 0o644)
	}
	return dpPriv
}

// currentCPPin compares the peer key with cp.pub read now, per handshake.
func currentCPPin(keysDir string, certs []*x509.Certificate) error {
	if len(certs) != 1 {
		return errors.New("want exactly one peer certificate")
	}
	raw, err := os.ReadFile(filepath.Join(keysDir, "cp.pub"))
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("cp.pub: no PEM block")
	}
	pinned, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := certs[0].PublicKey.(ed25519.PublicKey)
	if !ok || !key.Equal(pinned) {
		return errors.New("peer key is not the current cp.pub")
	}
	return nil
}

// serveStandIn starts a dp.sock stand-in. mode is "connection" (pin on full
// and resumed handshakes), "peercert" (pin on full handshakes only),
// "noticket" (correct pin, session tickets disabled) or "declined" (correct
// pin; tickets are refused once cp.pub has changed, like a restarted DP).
func serveStandIn(t *testing.T, socket, keysDir, mode string, dpPriv ed25519.PrivateKey) {
	t.Helper()
	cert, err := selfSigned(dpPriv, "stargate-dp")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	var partial func(net.Conn) net.Conn
	switch mode {
	case "connection", "noticket", "declined", "partialflight":
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			return currentCPPin(keysDir, state.PeerCertificates)
		}
		cfg.SessionTicketsDisabled = mode == "noticket"
		if mode == "declined" || mode == "partialflight" {
			// Fixed keys survive the credentials' Clone, so cfg can decrypt
			// the tickets the cloned server config issued.
			var key [32]byte
			if _, err := rand.Read(key[:]); err != nil {
				t.Fatal(err)
			}
			cfg.SetSessionTicketKeys([][32]byte{key})
			initial, err := os.ReadFile(filepath.Join(keysDir, "cp.pub"))
			if err != nil {
				t.Fatal(err)
			}
			changed := func() bool {
				now, err := os.ReadFile(filepath.Join(keysDir, "cp.pub"))
				return err != nil || string(now) != string(initial)
			}
			var restored, truncated atomic.Int32
			var selected atomic.Bool
			cfg.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
				if changed() && mode == "declined" {
					return nil, nil // decline: full handshake
				}
				state, err := cfg.DecryptTicket(identity, cs)
				if state != nil && changed() {
					restored.Add(1)
					selected.Store(true)
				}
				return state, err
			}
			if mode == "partialflight" {
				partial = func(c net.Conn) net.Conn {
					return &partialFlightConn{Conn: c, changed: changed, selected: &selected, truncated: &truncated}
				}
				t.Cleanup(func() {
					if restored.Load() == 0 || truncated.Load() == 0 {
						t.Errorf("incomplete-flight controls invalid: restored=%d truncated=%d", restored.Load(), truncated.Load())
					}
				})
			}
		}
	case "peercert":
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				c, err := x509.ParseCertificate(raw)
				if err != nil {
					return err
				}
				certs = append(certs, c)
			}
			return currentCPPin(keysDir, certs)
		}
	default:
		t.Fatalf("unknown stand-in mode %q", mode)
	}
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if partial != nil {
		lis = wrappingListener{Listener: lis, wrap: partial}
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	grpcpb.RegisterControlServer(srv, statusServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
}

func TestProbeResumeDiscriminates(t *testing.T) {
	cases := []struct {
		mode    string
		wantErr string // empty: the probe must pass
	}{
		{"connection", ""},
		{"peercert", "step 4"},
		{"noticket", "step 2 (positive control)"},
		{"declined", "did not take the resumed path"},
		{"partialflight", "did not take the resumed path"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			dir := t.TempDir()
			keys := filepath.Join(dir, "k")
			if err := os.Mkdir(keys, 0o700); err != nil {
				t.Fatal(err)
			}
			dpPriv := standInKeys(t, keys)
			socket := filepath.Join(dir, "dp.sock")
			serveStandIn(t, socket, keys, tc.mode, dpPriv)
			err := probeResume(socket, keys, 5*time.Second)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("probe failed against a resumption-safe DP stand-in: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("probe passed against the %q stand-in; want a failure naming %q", tc.mode, tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("probe failed for the wrong reason against %q: %v (want %q)", tc.mode, err, tc.wantErr)
			}
		})
	}
	t.Run("HandshakeWitnessAttribution", testHandshakeWitnessAttribution)
}

// Constitution VII and wire-auth §2.4: refusal without selected PSK is inconclusive.
func TestFalsifyEarlyAbortBeforePSKAcceptance(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "k")
	if err := os.Mkdir(keys, 0700); err != nil {
		t.Fatal(err)
	}
	dpPriv := standInKeys(t, keys)
	cert, err := selfSigned(dpPriv, "stargate-dp")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := os.ReadFile(filepath.Join(keys, "cp.pub"))
	if err != nil {
		t.Fatal(err)
	}
	changed := func() bool {
		now, err := os.ReadFile(filepath.Join(keys, "cp.pub"))
		if err != nil {
			return true
		}
		return string(now) != string(initial)
	}
	var earlyAborts, preRestored, postRestored, postResumedVerify atomic.Int32
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if changed() && cs.DidResume {
			postResumedVerify.Add(1)
		}
		return currentCPPin(keys, cs.PeerCertificates)
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	cfg.SetSessionTicketKeys([][32]byte{key})
	cfg.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		post := changed()
		if post {
			earlyAborts.Add(1)
			return nil, errors.New("test abort before PSK acceptance")
		}
		state, err := cfg.DecryptTicket(identity, cs)
		if state != nil {
			if post {
				postRestored.Add(1)
			} else {
				preRestored.Add(1)
			}
		}
		return state, err
	}
	socket := filepath.Join(dir, "dp.sock")
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	grpcpb.RegisterControlServer(srv, statusServer{})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	err = probeResume(socket, keys, 5*time.Second)
	t.Logf("probe err=%v; pre-restored=%d early-aborts=%d post-restored=%d post-resumed-verifier=%d", err, preRestored.Load(), earlyAborts.Load(), postRestored.Load(), postResumedVerify.Load())
	if preRestored.Load() == 0 || earlyAborts.Load() == 0 || postRestored.Load() != 0 || postResumedVerify.Load() != 0 {
		t.Fatal("experiment controls invalid")
	}
	if err == nil {
		t.Fatal("FALSE PASS: probe accepted post-rotation refusal without any PSK restoration or resumed verifier")
	}
}

// A resumed ServerHello followed by an incomplete encrypted flight must not
// borrow an earlier handshake's witness (Constitution VII, wire-auth §2.4).
type wrappingListener struct {
	net.Listener
	wrap func(net.Conn) net.Conn
}

func (l wrappingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.wrap(c), nil
}

type partialFlightConn struct {
	net.Conn
	changed   func() bool
	selected  *atomic.Bool
	truncated *atomic.Int32
}

func (c *partialFlightConn) Write(b []byte) (int, error) {
	if !c.changed() || !c.selected.Load() {
		return c.Conn.Write(b)
	}
	// Go's TLS server flushes the ServerHello record before its pin callback.
	// Pass that record, then cut the encrypted flight before client verification.
	if len(b) >= 6 && b[0] == 22 && b[5] == 2 {
		n := 5 + (int(b[3]) << 8) + int(b[4])
		if n <= len(b) {
			written, err := c.Conn.Write(b[:n])
			c.selected.Store(false)
			c.truncated.Add(1)
			_ = c.Conn.Close()
			if err != nil {
				return written, err
			}
			return written, io.ErrUnexpectedEOF
		}
	}
	return c.Conn.Write(b)
}

// Reusing one credentials/log object must not carry a previous raw
// handshake's resumed witness into a later error (Constitution VII).
func testHandshakeWitnessAttribution(t *testing.T) {
	dir := t.TempDir()
	dpPriv := standInKeys(t, dir)
	cpPriv, err := loadSigner(filepath.Join(dir, "cp.priv"))
	if err != nil {
		t.Fatal(err)
	}
	cpCert, err := selfSigned(cpPriv, "stargate-cp")
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "dp.sock")
	serveStandIn(t, socket, dir, "connection", dpPriv)
	cache := &countingCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	full := attemptStatus(socket, dir, cpCert, cache, 5*time.Second)
	if full.rpcErr != nil {
		t.Fatal(full.rpcErr)
	}
	cfg := clientConfig(cpCert, filepath.Join(dir, "dp.pub"))
	cfg.ClientSessionCache = cache
	cfg.ServerName = "stargate-dp"
	cfg.VerifyPeerCertificate = nil
	pin := pinVerifier(filepath.Join(dir, "dp.pub"))
	var verified atomic.Bool
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		var raw [][]byte
		for _, cert := range cs.PeerCertificates {
			raw = append(raw, cert.Raw)
		}
		if err := pin(raw, nil); err != nil {
			return err
		}
		verified.Store(true)
		return nil
	}
	var mu sync.Mutex
	var log []handshakeRecord
	creds := recordingCreds{TransportCredentials: credentials.NewTLS(cfg), config: cfg, mu: &mu, log: &log}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := creds.ClientHandshake(ctx, "stargate-dp", raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	verified.Store(false)
	raw, err = net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	_, info, err := creds.Clone().ClientHandshake(ctx, "stargate-dp", afterWitnessWriteError{Conn: raw, verified: &verified})
	t.Logf("forced post-witness write: err=%v TLSInfo=%v verified=%v", err, info, verified.Load())
	if err == nil || !strings.Contains(err.Error(), "test write error after selected-PSK witness") || info != nil || !verified.Load() {
		t.Fatalf("post-witness error control invalid: err=%v info=%v verified=%v", err, info, verified.Load())
	}
	local, peer := net.Pipe()
	_ = peer.Close()
	_, _, err = creds.Clone().ClientHandshake(ctx, "stargate-dp", local)
	if err == nil {
		t.Fatal("early-close control unexpectedly completed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(log) != 3 || !log[0].peerVerified || !log[0].resumed || log[0].err != nil || !log[1].peerVerified || !log[1].resumed || log[1].err == nil || log[2].peerVerified || log[2].resumed || log[2].err == nil {
		t.Fatalf("each raw handshake needs its own witness: %+v", log)
	}
}

// The selected-PSK witness survives an error after verification even though
// gRPC supplies no TLSInfo. No previous connection supplies that witness.
type afterWitnessWriteError struct {
	net.Conn
	verified *atomic.Bool
}

func (c afterWitnessWriteError) Write(b []byte) (int, error) {
	if c.verified.Load() {
		return 0, errors.New("test write error after selected-PSK witness")
	}
	return c.Conn.Write(b)
}
