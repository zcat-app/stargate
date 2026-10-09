// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package socks5

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

const (
	t066Token                 = "a066a066a066a066a066a066a066a066"
	t066Destination           = "t066-route-refused-fixture.onion"
	t066Sentinel              = "T066-UPSTREAM-PRIVATE-REASON-7f39c2"
	t066DialObservationWindow = 500 * time.Millisecond
)

type t066Connect struct {
	host string
	port uint16
}

// t066ScriptedSOCKS5Upstream records every accepted connection. After the
// first complete refusal exchange it keeps accepting through a bounded
// observation window, so retries cannot hide in the listener backlog.
func t066ScriptedSOCKS5Upstream(t *testing.T) (string, *atomic.Int64, <-chan t066Connect, <-chan error, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpListener := listener.(*net.TCPListener)
	t.Cleanup(func() { _ = listener.Close() })

	var dials atomic.Int64
	connects := make(chan t066Connect, 1)
	fixtureResult := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		conn, err := listener.Accept()
		if err != nil {
			fixtureResult <- fmt.Errorf("accept initial upstream connection: %w", err)
			return
		}
		dials.Add(1)
		firstErr := t066ServeRefusal(conn, connects)
		if deadlineErr := tcpListener.SetDeadline(time.Now().Add(t066DialObservationWindow)); deadlineErr != nil && firstErr == nil {
			firstErr = fmt.Errorf("set bounded upstream observation window: %w", deadlineErr)
		}
		for {
			extra, acceptErr := listener.Accept()
			if acceptErr != nil {
				var netErr net.Error
				if !errors.As(acceptErr, &netErr) || !netErr.Timeout() {
					if firstErr == nil {
						firstErr = fmt.Errorf("accept during upstream observation window: %w", acceptErr)
					}
				}
				break
			}
			dials.Add(1)
			_ = extra.Close()
		}
		fixtureResult <- firstErr
	}()
	return listener.Addr().String(), &dials, connects, fixtureResult, finished
}

func t066ServeRefusal(conn net.Conn, connects chan<- t066Connect) error {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set initial upstream deadline: %w", err)
	}
	reader := bufio.NewReader(conn)
	read := func(n int) ([]byte, error) {
		buf := make([]byte, n)
		_, err := io.ReadFull(reader, buf)
		return buf, err
	}
	header, err := read(2)
	if err != nil {
		return fmt.Errorf("read upstream method greeting: %w", err)
	}
	if header[0] != 5 {
		return fmt.Errorf("upstream SOCKS version = %d, want 5", header[0])
	}
	methods, err := read(int(header[1]))
	if err != nil {
		return fmt.Errorf("read upstream methods: %w", err)
	}
	if !bytes.Contains(methods, []byte{2}) {
		return fmt.Errorf("upstream did not offer USERPASS method")
	}
	if _, err = conn.Write([]byte{5, 2}); err != nil {
		return fmt.Errorf("write upstream method selection: %w", err)
	}
	authHeader, err := read(2)
	if err != nil {
		return fmt.Errorf("read upstream RFC 1929 header: %w", err)
	}
	if authHeader[0] != 1 {
		return fmt.Errorf("upstream RFC 1929 version = %d, want 1", authHeader[0])
	}
	if _, err = read(int(authHeader[1])); err != nil {
		return fmt.Errorf("read upstream username: %w", err)
	}
	passwordLength, err := read(1)
	if err != nil {
		return fmt.Errorf("read upstream password length: %w", err)
	}
	if _, err = read(int(passwordLength[0])); err != nil {
		return fmt.Errorf("read upstream password: %w", err)
	}
	if _, err = conn.Write([]byte{1, 0}); err != nil {
		return fmt.Errorf("write upstream auth success: %w", err)
	}
	requestHeader, err := read(5)
	if err != nil {
		return fmt.Errorf("read upstream CONNECT header: %w", err)
	}
	if !bytes.Equal(requestHeader[:4], []byte{5, 1, 0, 3}) {
		return fmt.Errorf("upstream CONNECT header = %x, want 05 01 00 03", requestHeader[:4])
	}
	addressAndPort, err := read(int(requestHeader[4]) + 2)
	if err != nil {
		return fmt.Errorf("read upstream CONNECT destination: %w", err)
	}
	connects <- t066Connect{
		host: string(addressAndPort[:len(addressAndPort)-2]),
		port: uint16(addressAndPort[len(addressAndPort)-2])<<8 | uint16(addressAndPort[len(addressAndPort)-1]),
	}
	payload := append([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}, []byte(t066Sentinel)...)
	if err := t066WriteAll(conn, payload); err != nil {
		return fmt.Errorf("write combined upstream refusal and sentinel: %w", err)
	}
	return nil
}

func t066WriteAll(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func TestRouteRefusedSOCKS5Reply(t *testing.T) {
	upstreamAddr, dials, connects, fixtureResult, upstreamFinished := t066ScriptedSOCKS5Upstream(t)
	h := dpharness.Start(t, dpharness.WithUpstream(upstreamAddr), dpharness.WithControlPlane())
	if got := dpharness.Reload(t, h, 1, []*grpcpb.TokenVerifier{dpharness.MintToken(t, t066Token)}); got.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens status = %v, want APPLY_STATUS_OK", got.GetStatus())
	}
	waitForWatchEventsDial(t, h.CP)
	time.Sleep(100 * time.Millisecond)
	journalBefore := h.Journal.String()

	conn := dialProxy(t, h)
	defer conn.Close()
	doMethodNegotiation(t, conn)
	user := refusalIdentity(t066Token, "t066-profile", t066Destination)
	if got := doSubnegotiation(t, conn, user, t066Token); !bytes.Equal(got, []byte{1, 0}) {
		t.Fatalf("SOCKS5 auth reply = %x, want 0100", got)
	}
	writeConnectRequest(t, conn, t066Destination, 443)

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reply := readN(t, conn, 10)
	trailing, readErr := io.ReadAll(conn)
	fullReply := append(append([]byte(nil), reply...), trailing...)
	want := []byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(reply, want) {
		t.Errorf("SOCKS5 refusal reply = %x, want exactly %x", reply, want)
	}
	if len(trailing) != 0 {
		t.Errorf("SOCKS5 refusal sent %d trailing bytes after fixed reply: %q", len(trailing), trailing)
	}
	if readErr != nil {
		t.Errorf("SOCKS5 refusal connection did not end cleanly at EOF: %v", readErr)
	}

	select {
	case observed := <-connects:
		if observed.host != t066Destination || observed.port != 443 {
			t.Errorf("upstream CONNECT = %q:%d, want %q:443", observed.host, observed.port, t066Destination)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scripted upstream did not observe the requested CONNECT")
	}
	select {
	case <-upstreamFinished:
	case <-time.After(3 * time.Second):
		t.Fatal("scripted upstream did not finish refusal and bounded dial observation")
	}
	select {
	case err := <-fixtureResult:
		if err != nil {
			t.Fatalf("scripted upstream fixture failed; reply/leak assertions are not valid: %v", err)
		}
	default:
		t.Fatal("scripted upstream finished without reporting its handshake/write result")
	}
	if got := dials.Load(); got != 1 {
		t.Errorf("upstream dial count = %d, want exactly 1", got)
	}

	time.Sleep(100 * time.Millisecond)
	journalAfter := h.Journal.String()
	journalDelta := journalAfter
	if len(journalAfter) >= len(journalBefore) {
		journalDelta = journalAfter[len(journalBefore):]
	} else {
		t.Errorf("journal shrank during refusal: before=%d after=%d", len(journalBefore), len(journalAfter))
	}

	repoRoot := dpharness.FindRepoRoot(t)
	corpusPath := filepath.Join(repoRoot, "tests", "contract", "error-template", "leak-corpus.txt")
	corpusBytes, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatalf("read T064 leak corpus: %v", err)
	}
	secrets := [][]byte{[]byte(t066Token), []byte(t066Destination), []byte(t066Sentinel)}
	for _, entry := range strings.Fields(string(corpusBytes)) {
		secrets = append(secrets, []byte(entry))
	}
	loginvariants.AssertNoSecrets(t, string(fullReply), secrets...)
	loginvariants.AssertNoSecrets(t, journalDelta, secrets...)
	loginvariants.AssertOnlyAllowedLines(t, journalDelta)
	for label, capture := range map[string]string{"reply": string(fullReply), "journal delta": journalDelta} {
		lower := strings.ToLower(capture)
		if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype html") || strings.Contains(lower, "content-type: text/html") {
			t.Errorf("%s contains an HTML marker", label)
		}
	}
}
