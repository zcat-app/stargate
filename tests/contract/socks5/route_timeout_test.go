// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package socks5

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	integration "github.com/zcat-app/stargate/tests/integration"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

const (
	t067RouteTimeoutToken       = "a067a067a067a067a067a067a067a067"
	t067RouteTimeoutUsername    = "t067-route-timeout-user"
	t067RouteTimeoutDestination = "t067-route-timeout-target.example.onion"
	t067SlowLatency             = 251 * time.Second
	t067ClientDeadline          = 4*time.Minute + 30*time.Second
)

// TestRouteTimeoutSOCKS5Reply pins the authenticated SOCKS5 handshake
// deadline contract. T019a's Slow backend accepts the SOCKS5 request, then
// withholds its BND reply beyond the production 250-second deadline; the
// data plane returns fixed REP=0x06 and closes (Principles I and III).
func TestRouteTimeoutSOCKS5Reply(t *testing.T) {
	repoRoot := dpharness.FindRepoRoot(t)
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "auth", "token.go"),
		"auth/token.go not implemented yet (T044); this skip self-lifts when T044 lands")
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go"),
		"forward/tor.go not implemented yet (T047); this skip self-lifts when T047 lands")

	slow := integration.NewServer(integration.Slow, integration.WithLatency(t067SlowLatency))
	upstreamAddr, err := slow.Start()
	if err != nil {
		t.Fatalf("starting T019a Slow upstream: %v", err)
	}
	t.Cleanup(func() { _ = slow.Close() })

	h := dpharness.Start(t, dpharness.WithUpstream(upstreamAddr))
	reload := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenVerifier{dpharness.MintToken(t, t067RouteTimeoutToken)})
	if reload.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want APPLY_STATUS_OK; valid-token setup failed",
			reload.GetStatus())
	}
	time.Sleep(250 * time.Millisecond)
	journalBefore := h.Journal.String()

	conn := dialProxy(t, h)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(t067ClientDeadline)); err != nil {
		t.Fatalf("set client deadline beyond the 250-second contract deadline: %v", err)
	}
	doMethodNegotiation(t, conn)
	if got, want := doSubnegotiation(t, conn, t067RouteTimeoutUsername, t067RouteTimeoutToken), []byte{0x01, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("RFC 1929 auth reply = %x, want %x; request-phase timeout requires successful authentication first", got, want)
	}
	requestStarted := time.Now()
	writeConnectRequest(t, conn, t067RouteTimeoutDestination, 443)

	reply := readN(t, conn, 10)
	requestElapsed := time.Since(requestStarted)
	trailing, readErr := io.ReadAll(conn)
	fullReply := append(append([]byte(nil), reply...), trailing...)
	want := []byte{0x05, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(reply, want) {
		t.Errorf("SOCKS5 ROUTE_TIMEOUT reply = % x, want exactly % x", reply, want)
	}
	if len(trailing) != 0 {
		t.Errorf("SOCKS5 ROUTE_TIMEOUT sent %d trailing bytes after fixed reply", len(trailing))
	}
	if readErr != nil {
		t.Errorf("reading trailing SOCKS5 ROUTE_TIMEOUT bytes returned %v, want nil at EOF", readErr)
	}
	if requestElapsed < 240*time.Second {
		t.Errorf("ROUTE_TIMEOUT arrived after %s, too early to show the full 250-second deadline and T019a Slow request path", requestElapsed)
	}
	if got := slow.CircuitIDs(); len(got) != 1 || got[0] != t067RouteTimeoutUsername {
		t.Errorf("T019a Slow observed upstream auth identities = %v, want [%s]; upstream authentication evidence is missing", got, t067RouteTimeoutUsername)
	}
	if got := slow.ConnectCount(); got != 1 {
		t.Errorf("T019a Slow fully parsed CONNECT count = %d, want exactly 1", got)
	}

	time.Sleep(250 * time.Millisecond)
	journalAfter := h.Journal.String()
	journalDelta := t067JournalDelta(journalBefore, journalAfter)
	corpus := t067LoadLeakCorpus(t, filepath.Join(repoRoot, "tests", "contract", "error-template", "leak-corpus.txt"))
	secrets := append(corpus, []byte(t067RouteTimeoutToken), []byte(t067RouteTimeoutDestination))
	loginvariants.AssertNoSecrets(t, string(fullReply), secrets...)
	loginvariants.AssertNoSecrets(t, journalDelta, secrets...)
	loginvariants.AssertOnlyAllowedLines(t, journalDelta)
}

func t067LoadLeakCorpus(t *testing.T, path string) [][]byte {
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

func t067JournalDelta(before, after string) string {
	if strings.HasPrefix(after, before) {
		return after[len(before):]
	}
	// A shortened journal indicates harness rotation; scanning the full
	// post-request capture preserves the no-leak assertion in that case.
	return after
}
