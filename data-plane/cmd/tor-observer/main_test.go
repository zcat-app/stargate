// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeTor struct {
	listener net.Listener
	mu       sync.Mutex
	commands []string
	reply    string
	stalled  bool
}

func startFakeTor(t *testing.T, path, reply string) *fakeTor {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTor{listener: l, reply: reply}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.handle(c)
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return f
}

func (f *fakeTor) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		f.mu.Lock()
		f.commands = append(f.commands, line)
		reply, stalled := f.reply, f.stalled
		f.mu.Unlock()
		switch {
		case strings.HasPrefix(line, "AUTHENTICATE "):
			_, _ = io.WriteString(c, "250 OK\r\n")
		case line == "GETINFO status/bootstrap-phase":
			if stalled {
				_, _ = io.Copy(io.Discard, c)
				return
			}
			_, _ = io.WriteString(c, reply)
		case line == "QUIT":
			_, _ = io.WriteString(c, "250 closing connection\r\n")
			return
		default:
			_, _ = io.WriteString(c, "510 rejected\r\n")
		}
	}
}

func (f *fakeTor) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

type fixture struct {
	config      config
	cpPriv      ed25519.PrivateKey
	observerPub ed25519.PublicKey
	fake        *fakeTor
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
	cookie := filepath.Join(dir, "control_auth_cookie")
	if err := os.WriteFile(cookie, []byte("0123456789abcdefghijklmnopqrstuv"), 0600); err != nil {
		t.Fatal(err)
	}
	torPath := filepath.Join(dir, "tor.sock")
	f := startFakeTor(t, torPath, reply)
	c := config{
		healthSocket: filepath.Join(dir, "health.sock"),
		torSocket:    torPath,
		cookiePath:   cookie,
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
	return fixture{config: c, cpPriv: cpPriv, observerPub: observerPub, fake: f}
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

func TestSanitizedHealthAndRecovery(t *testing.T) {
	f := newFixture(t, readyTor)
	call := func(want string) {
		t.Helper()
		got, err := clientCall(t, f, []byte("HEALTH/1\n"), true, f.cpPriv)
		if err != nil || string(got) != want {
			t.Fatalf("health: got %q, %v; want %q", got, err, want)
		}
	}
	call("READY/1\n")
	var got []string
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		got = f.fake.snapshot()
		if len(got) == 3 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(got) != 3 || !strings.HasPrefix(got[0], "AUTHENTICATE ") || got[1] != "GETINFO status/bootstrap-phase" || got[2] != "QUIT" {
		t.Fatalf("Tor command sequence: %q", got)
	}
	f.fake.mu.Lock()
	f.fake.reply = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=42 TAG=loading SUMMARY=\"Loading networkstatus consensus\"\r\n250 OK\r\n"
	f.fake.mu.Unlock()
	call("NOT_READY/1\n")
	f.fake.mu.Lock()
	f.fake.reply = "250-status/bootstrap-phase=WARN BOOTSTRAP SUMMARY=\"Retrying directory mirror\" TAG=loading PROGRESS=42 WARNING=\"timeout\"\r\n250 OK\r\n"
	f.fake.mu.Unlock()
	call("NOT_READY/1\n")
	_ = f.fake.listener.Close()
	call("UNAVAILABLE/1\n")
	f.fake = startFakeTor(t, f.config.torSocket, readyTor)
	call("READY/1\n")
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
	if got := f.fake.snapshot(); len(got) != 0 {
		t.Fatalf("invalid inputs reached Tor: %q", got)
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
	if commands := f.fake.snapshot(); len(commands) != 0 {
		t.Fatalf("invalid callers caused Tor query: %q", commands)
	}
}

func TestTorTimeoutAndConcurrentQueryLimit(t *testing.T) {
	f := newFixture(t, readyTor)
	f.fake.mu.Lock()
	f.fake.stalled = true
	f.fake.mu.Unlock()
	first := make(chan []byte, 1)
	go func() {
		got, _ := clientCall(t, f, []byte("HEALTH/1\n"), true, f.cpPriv)
		first <- got
	}()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		if len(f.fake.snapshot()) >= 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	got, err := clientCall(t, f, []byte("HEALTH/1\n"), true, f.cpPriv)
	if err != nil || string(got) != "UNAVAILABLE/1\n" {
		t.Fatalf("excess query got %q, %v", got, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("excess query waited behind active Tor query")
	}
	select {
	case got = <-first:
		if string(got) != "UNAVAILABLE/1\n" {
			t.Fatalf("Tor timeout leaked non-finite reply %q", got)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("Tor query exceeded four-second budget")
	}
}

func TestTorReplyBoundsAndMalformedResult(t *testing.T) {
	for name, reply := range map[string]string{
		"malformed":       "250-status/bootstrap-phase=garbage\r\n250 OK\r\n",
		"garbage ready":   "250-status/bootstrap-phase=garbage PROGRESS=100\r\n250 OK\r\n",
		"missing tag":     "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 SUMMARY=\"Done\"\r\n250 OK\r\n",
		"missing summary": "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n250 OK\r\n",
		"quoted progress": "250-status/bootstrap-phase=NOTICE BOOTSTRAP TAG=done SUMMARY=\"PROGRESS=100\"\r\n250 OK\r\n",
		"progress type":   "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=\"100\" TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n",
		"bad tag":         "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=bad! SUMMARY=\"Done\"\r\n250 OK\r\n",
		"oversized line":  "250-" + strings.Repeat("X", 8192) + "\r\n250 OK\r\n",
		"too many lines":  strings.Repeat("250-irrelevant\r\n", 65) + "250 OK\r\n",
		"raw error":       "551 sensitive destination\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, reply)
			got, err := clientCall(t, f, []byte("HEALTH/1\n"), true, f.cpPriv)
			if err != nil || string(got) != "UNAVAILABLE/1\n" {
				t.Fatalf("got %q, %v", got, err)
			}
		})
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
	cookie := filepath.Join(dir, "control_auth_cookie")
	if err := os.WriteFile(cookie, []byte("0123456789abcdefghijklmnopqrstuv"), 0600); err != nil {
		t.Fatal(err)
	}
	torPath := filepath.Join(dir, "tor.sock")
	startFakeTor(t, torPath, readyTor)
	c := config{
		healthSocket: filepath.Join(dir, "health.sock"),
		torSocket:    torPath,
		cookiePath:   cookie,
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
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The operator's one-shot mode reuses the authenticated, bounded native query.
func TestInstallerReadinessExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		want        int
	}{
		{"ready", "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n", 0},
		{"not-ready", "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=25 TAG=loading SUMMARY=\"Loading\"\r\n250 OK\r\n", 1},
		{"unavailable", "551 unavailable\r\n", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.reply)
			if got := run(f.config, []string{"--check-ready"}); got != tc.want {
				t.Fatalf("current readiness exit = %d, want %d", got, tc.want)
			}
			commands := f.fake.snapshot()
			if len(commands) < 2 || !strings.HasPrefix(commands[0], "AUTHENTICATE ") || commands[1] != "GETINFO status/bootstrap-phase" {
				t.Fatal("readiness bypassed authenticated fixed bootstrap query")
			}
		})
	}
	f := newFixture(t, "551 unavailable\r\n")
	if got := run(f.config, []string{"--arbitrary-command"}); got != 2 {
		t.Fatal("unknown mode was accepted")
	}
	if len(f.fake.snapshot()) != 0 {
		t.Fatal("unknown mode touched Tor")
	}
}

func TestInstallerReadinessDeadlineIncludesCookieIO(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "cookie")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	// Release a blocked reader after the assertion, including on the pre-fix path.
	defer func() {
		f, err := os.OpenFile(fifo, os.O_RDWR, 0600)
		if err == nil {
			f.Close()
		}
	}()
	done := make(chan int, 1)
	go func() { done <- run(config{cookiePath: fifo}, []string{"--check-ready"}) }()
	select {
	case got := <-done:
		if got != 2 {
			t.Fatalf("blocked cookie exit = %d, want unavailable", got)
		}
	case <-time.After(torWindow + time.Second):
		t.Fatal("installer readiness deadline did not bound cookie I/O")
	}
}
