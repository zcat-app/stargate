// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/zcat-app/stargate/data-plane/internal/torhealth"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	config      config
	cpPriv      ed25519.PrivateKey
	observerPub ed25519.PublicKey
}

func writeKeyPair(t *testing.T, dir, name string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".priv"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0644); err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newFixture(t *testing.T, reply string) fixture {
	t.Helper()
	dir := t.TempDir()
	cpPub, cpPriv := writeKeyPair(t, dir, "cp")
	_ = cpPub
	observerPub, _ := writeKeyPair(t, dir, "observer")
	sampleDir := newSampleDir(t)
	publishFixture(t, sampleDir, torhealth.Ready)
	c := config{
		healthSocket: filepath.Join(dir, "health.sock"),
		sampleDir:    sampleDir,
		privateKey:   filepath.Join(dir, "observer.priv"),
		peerKey:      filepath.Join(dir, "cp.pub"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	go func() { _ = serve(ctx, c, ready) }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("observer did not bind")
	}
	t.Cleanup(cancel)
	return fixture{config: c, cpPriv: cpPriv, observerPub: observerPub}
}

func clientCall(t *testing.T, f fixture, req []byte, closeWrite bool, clientKey ed25519.PrivateKey) ([]byte, error) {
	t.Helper()
	c, err := net.DialTimeout("unix", f.config.healthSocket, time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(7 * time.Second))
	prelude := make([]byte, 6+32)
	if _, err := io.ReadFull(c, prelude); err != nil {
		return nil, err
	}
	if string(prelude[:6]) != "OBS/1\n" {
		return nil, errors.New("bad observer prelude")
	}
	var clientNonce [32]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return nil, err
	}
	transcript := append(append([]byte{}, prelude[6:]...), clientNonce[:]...)
	clientSig := ed25519.Sign(clientKey, append([]byte("stargate-observer/1 client\n"), transcript...))
	packet := append(append([]byte("CP/1\n"), clientNonce[:]...), clientSig...)
	if _, err := c.Write(packet); err != nil {
		return nil, err
	}
	serverProof := make([]byte, 5+64)
	if _, err := io.ReadFull(c, serverProof); err != nil {
		return nil, err
	}
	if string(serverProof[:5]) != "OK/1\n" || !ed25519.Verify(f.observerPub,
		append([]byte("stargate-observer/1 server\n"), transcript...), serverProof[5:]) {
		return nil, errors.New("observer authentication failed")
	}
	if _, err := c.Write(req); err != nil {
		return nil, err
	}
	if closeWrite {
		if err := c.(*net.UnixConn).CloseWrite(); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(c)
}

const readyTor = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n"

func newSampleDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/dev/shm", "stargate-observer-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}
func publishFixture(t *testing.T, dir string, state torhealth.State) {
	t.Helper()
	stamp, err := torhealth.Now()
	if err != nil {
		t.Fatal(err)
	}
	if err := torhealth.Write(dir, state, stamp); err != nil {
		t.Fatal(err)
	}
}
func TestSanitizedHealthAndRecovery(t *testing.T) {
	f := newFixture(t, readyTor)
	for _, tc := range []struct {
		state torhealth.State
		reply string
	}{{torhealth.Ready, readyReply}, {torhealth.NotReady, notReadyReply}, {torhealth.Unavailable, unavailable}, {torhealth.Ready, readyReply}} {
		publishFixture(t, f.config.sampleDir, tc.state)
		got, err := clientCall(t, f, []byte(healthRequest), true, f.cpPriv)
		if err != nil || string(got) != tc.reply {
			t.Fatalf("got %q %v", got, err)
		}
	}
}

func TestCommandAndAuthenticationInputsNeverReachTor(t *testing.T) {
	f := newFixture(t, readyTor)
	bad := [][]byte{
		[]byte("GETINFO stream-status\n"), []byte("GETINFO circuit-status\n"),
		[]byte("GETCONF SocksPort\n"), []byte("SETCONF SocksPort=9050\n"),
		[]byte("SETEVENTS STREAM\n"), []byte("ATTACHSTREAM 1 1\n"),
		[]byte("ADD_ONION NEW:BEST\n"), []byte("SIGNAL NEWNYM\n"),
		[]byte("COMMAND arbitrary\n"), []byte("HEALTH/2\n"),
		[]byte("HEALTH/1\r\n"), []byte("HEALTH/1\x00\n"),
		[]byte("HEALTH/1 extra\n"), []byte("HEALTH/1\nX"),
		[]byte(strings.Repeat("X", 1024)),
	}
	for _, req := range bad {
		got, _ := clientCall(t, f, req, true, f.cpPriv)
		if len(got) != 0 {
			t.Errorf("input %q received health token %q", req, got)
		}
	}
	_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
	_, err := clientCall(t, f, []byte("HEALTH/1\n"), true, wrongKey)
	if err == nil {
		t.Error("wrong caller was authenticated")
	}
}

func TestAbsentAuthenticationAndMissingEOFReceiveNoToken(t *testing.T) {
	f := newFixture(t, readyTor)
	raw, err := net.Dial("unix", f.config.healthSocket)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.Write([]byte("HEALTH/1\n")) // no client signature
	_ = raw.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	got, _ := io.ReadAll(raw)
	_ = raw.Close()
	if bytes.Contains(got, []byte("READY/1\n")) || bytes.Contains(got, []byte("UNAVAILABLE/1\n")) {
		t.Fatalf("unauthenticated caller got token: %q", got)
	}
	got, _ = clientCall(t, f, []byte("HEALTH/1\n"), false, f.cpPriv)
	if len(got) != 0 {
		t.Fatalf("missing request EOF got token: %q", got)
	}
}

// The Java core suite launches this fixture to exercise the actual Java
// client against this Go server, fake Tor socket and real Ed25519 keys.
// Ordinary Go runs skip it; Maven owns the cross-language assertion.
func TestJavaClientInteropFixture(t *testing.T) {
	dir := os.Getenv("T164_INTEROP_DIR")
	if dir == "" {
		t.Skip("launched by the Java observer client contract test")
	}
	sampleDir := newSampleDir(t)
	publishFixture(t, sampleDir, torhealth.Ready)
	c := config{
		healthSocket: filepath.Join(dir, "health.sock"),
		sampleDir:    sampleDir,
		privateKey:   filepath.Join(dir, "observer.priv"),
		peerKey:      filepath.Join(dir, "cp.pub"),
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- serve(ctx, c, ready) }()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("observer fixture did not bind")
	}
	if err := os.WriteFile(filepath.Join(dir, "ready"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "stop")); err == nil {
			break
		}
		publishFixture(t, sampleDir, torhealth.Ready)
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestInstallerReadinessExitCodesAndExpiry(t *testing.T) {
	f := newFixture(t, readyTor)
	for _, tc := range []struct {
		state torhealth.State
		exit  int
	}{{torhealth.Ready, 0}, {torhealth.NotReady, 1}, {torhealth.Unavailable, 2}} {
		publishFixture(t, f.config.sampleDir, tc.state)
		if got := run(f.config, []string{"--check-ready"}); got != tc.exit {
			t.Fatalf("exit=%d want=%d", got, tc.exit)
		}
	}
	if run(f.config, []string{"--arbitrary-command"}) != 2 {
		t.Fatal("unknown mode accepted")
	}
	publishFixture(t, f.config.sampleDir, torhealth.Ready)
	stamp, err := torhealth.Now()
	if err != nil {
		t.Fatal(err)
	}
	stamp.Boot -= int64(5 * time.Second)
	if err := torhealth.Write(f.config.sampleDir, torhealth.Ready, stamp); err != nil {
		t.Fatal(err)
	}
	// Both a newly launched check and an existing authenticated server reject it.
	if run(f.config, []string{"--check-ready"}) != 2 {
		t.Fatal("consumer restart renewed lease")
	}
	got, err := clientCall(t, f, []byte(healthRequest), true, f.cpPriv)
	if err != nil || string(got) != unavailable {
		t.Fatal("server retained stale READY")
	}
}
