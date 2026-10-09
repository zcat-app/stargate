// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package socks5

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

const (
	t065RouteDownToken       = "a0650a0650a0650a0650a0650a0650a0"
	t065RouteDownUsername    = "t065-route-down-user"
	t065RouteDownDestination = "t065-route-down-target.example.onion"
)

// TestRouteDownSOCKS5Reply pins the authenticated request-phase failure
// contract from socks5-auth.md: an unreachable fixed upstream returns the
// zeroed 10-byte REP=0x03 response and closes without trailing data. The
// known-absent Unix socket makes reachability, rather than advisory sidecar
// state, the cause of ROUTE_DOWN (Constitution Principles I, II, and III).
func TestRouteDownSOCKS5Reply(t *testing.T) {
	repoRoot := dpharness.FindRepoRoot(t)
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "auth", "token.go"),
		"auth/token.go not implemented yet (T044); this skip self-lifts when T044 lands")
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go"),
		"forward/tor.go not implemented yet (T047); this skip self-lifts when T047 lands")

	upstreamDir := t.TempDir()
	missingSocket := filepath.Join(upstreamDir, "known-absent.sock")
	if _, err := os.Lstat(missingSocket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("upstream socket precondition failed: Lstat(%q) error = %v, want not-exist",
			missingSocket, err)
	}

	h := dpharness.Start(t, dpharness.WithUpstream("unix://"+missingSocket))
	reload := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenVerifier{dpharness.MintToken(t, t065RouteDownToken)})
	if reload.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want APPLY_STATUS_OK; valid-token setup failed",
			reload.GetStatus())
	}
	time.Sleep(250 * time.Millisecond)
	journalBefore := h.Journal.String()

	conn := dialProxy(t, h)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	doMethodNegotiation(t, conn)
	if got, want := doSubnegotiation(t, conn, t065RouteDownUsername, t065RouteDownToken), []byte{0x01, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("RFC 1929 auth reply = %x, want %x; request-phase failure requires successful authentication first", got, want)
	}
	writeConnectRequest(t, conn, t065RouteDownDestination, 443)

	got := readN(t, conn, 10)
	want := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("SOCKS5 ROUTE_DOWN reply = % x, want exactly % x", got, want)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline for ROUTE_DOWN close assertion: %v", err)
	}
	trailing, closeErr := io.ReadAll(conn)
	if len(trailing) != 0 {
		t.Errorf("SOCKS5 ROUTE_DOWN sent %d trailing bytes after fixed reply", len(trailing))
	}
	if closeErr != nil {
		t.Errorf("SOCKS5 ROUTE_DOWN close read returned %v, want clean EOF", closeErr)
	}

	time.Sleep(250 * time.Millisecond)
	journalAfter := h.Journal.String()
	journalDelta := t065JournalDelta(journalBefore, journalAfter)
	corpus := t065LoadLeakCorpus(t, filepath.Join(repoRoot, "tests", "contract", "error-template", "leak-corpus.txt"))
	secrets := append(corpus, []byte(t065RouteDownToken), []byte(t065RouteDownDestination))
	loginvariants.AssertNoSecrets(t, string(got), secrets...)
	loginvariants.AssertNoSecrets(t, journalDelta, secrets...)
}

func t065LoadLeakCorpus(t *testing.T, path string) [][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open T064 leak corpus: %v", err)
	}
	defer file.Close()

	var corpus [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}
		corpus = append(corpus, []byte(entry))
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read T064 leak corpus: %v", err)
	}
	if len(corpus) == 0 {
		t.Fatal("T064 leak corpus is empty")
	}
	return corpus
}

func t065JournalDelta(before, after string) string {
	if strings.HasPrefix(after, before) {
		return after[len(before):]
	}
	// A shortened journal indicates harness rotation; scanning the full
	// post-request capture preserves the no-leak assertion in that case.
	return after
}
