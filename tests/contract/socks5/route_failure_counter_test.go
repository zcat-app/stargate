// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package socks5

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	integration "github.com/zcat-app/stargate/tests/integration"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

const (
	t067bRequestCount        = 20
	t067bToken               = "a067b067b067b067b067b067b067b067"
	t067bCounterClock        = "2026-09-04T10:30:00Z"
	t067bRefusalSentinel     = "T067B-UPSTREAM-REASON-8d4c21"
	t067bSlowLatency         = 251 * time.Second
	t067bClientDeadline      = 4*time.Minute + 30*time.Second
	t067bQuickClientDeadline = 20 * time.Second
)

type t067bAttempt struct {
	index   int
	dest    string
	reply   []byte
	full    []byte
	elapsed time.Duration
	err     error
}

type t067bConnect struct {
	host string
	port uint16
}

type t067bCaseResult struct {
	requests uint64
	bytes    uint64
}

// TestRouteFailureCounterAsymmetry pins the FR-008/data-model.md §3 rule:
// authentication-passed route failures count once, while failure replies are
// not forwarded bytes. The three fresh DP processes keep each cause isolated.
func TestRouteFailureCounterAsymmetry(t *testing.T) {
	repoRoot := dpharness.FindRepoRoot(t)
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "auth", "token.go"),
		"auth/token.go not implemented yet (T044); this skip self-lifts when T044 lands")
	dpharness.RequireFile(t,
		filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go"),
		"forward/tor.go not implemented yet (T047); this skip self-lifts when T047 lands")

	clock, err := time.Parse(time.RFC3339, t067bCounterClock)
	if err != nil {
		t.Fatalf("parse frozen counter clock: %v", err)
	}
	corpus := t067bLoadLeakCorpus(t, filepath.Join(repoRoot, "tests", "contract", "error-template", "leak-corpus.txt"))
	var totals t067bCaseResult

	t.Run("ROUTE_DOWN", func(t *testing.T) {
		upstreamDir := t.TempDir()
		missingSocket := filepath.Join(upstreamDir, "known-absent.sock")
		if _, err := os.Lstat(missingSocket); !os.IsNotExist(err) {
			t.Fatalf("upstream socket precondition: Lstat(%q) error=%v, want absent", missingSocket, err)
		}
		got := t067bRunRouteFailureCase(t, "down", "unix://"+missingSocket, 0x03, clock, corpus, nil)
		totals.requests += got.requests
		totals.bytes += got.bytes
	})

	t.Run("ROUTE_REFUSED", func(t *testing.T) {
		upstream, dials, connects, finished := t067bRefusingUpstream(t)
		got := t067bRunRouteFailureCase(t, "refused", upstream, 0x04, clock, corpus, [][]byte{[]byte(t067bRefusalSentinel)})
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Fatal("scripted refusal upstream did not finish all CONNECTs")
		}
		if n := dials.Load(); n != t067bRequestCount {
			t.Errorf("refusal upstream dials=%d, want exactly %d", n, t067bRequestCount)
		}
		seen := make(map[string]int, t067bRequestCount)
		for i := 0; i < t067bRequestCount; i++ {
			select {
			case observed := <-connects:
				if observed.port != 443 {
					t.Errorf("refusal upstream port=%d for %q, want 443", observed.port, observed.host)
				}
				seen[observed.host]++
			case <-time.After(3 * time.Second):
				t.Fatalf("refusal upstream recorded %d of %d CONNECTs", i, t067bRequestCount)
			}
		}
		for i := 0; i < t067bRequestCount; i++ {
			dest := t067bDestination("refused", i)
			if seen[dest] != 1 {
				t.Errorf("refusal upstream observed destination %q %d times, want once", dest, seen[dest])
			}
		}
		totals.requests += got.requests
		totals.bytes += got.bytes
	})

	t.Run("ROUTE_TIMEOUT", func(t *testing.T) {
		slow := integration.NewServer(integration.Slow, integration.WithLatency(t067bSlowLatency))
		upstream, err := slow.Start()
		if err != nil {
			t.Fatalf("start T019a Slow upstream: %v", err)
		}
		t.Cleanup(func() { _ = slow.Close() })
		got := t067bRunRouteFailureCase(t, "timeout", upstream, 0x06, clock, corpus, nil)
		seen := make(map[string]bool, t067bRequestCount)
		for _, username := range slow.CircuitIDs() {
			seen[username] = true
		}
		if len(seen) != t067bRequestCount {
			t.Errorf("T019a Slow observed %d distinct authenticated SOCKS identities, want %d", len(seen), t067bRequestCount)
		}
		if got := slow.ConnectCount(); got != t067bRequestCount {
			t.Errorf("T019a Slow fully parsed CONNECT count = %d, want exactly %d", got, t067bRequestCount)
		}
		totals.requests += got.requests
		totals.bytes += got.bytes
	})

	if totals.requests != 3*t067bRequestCount || totals.bytes != 0 {
		t.Errorf("combined route-failure counter deltas = requests %d, bytes %d; want exactly +%d requests and +0 bytes",
			totals.requests, totals.bytes, 3*t067bRequestCount)
	}
}

func t067bRunRouteFailureCase(
	t *testing.T,
	label string,
	upstream string,
	rep byte,
	clock time.Time,
	corpus [][]byte,
	additionalSecrets [][]byte,
) t067bCaseResult {
	t.Helper()
	h := dpharness.Start(t,
		dpharness.WithUpstream(upstream),
		dpharness.WithCounterClock(clock))
	reload := dpharness.Reload(t, h, 1,
		[]*grpcpb.TokenVerifier{dpharness.MintToken(t, t067bToken)})
	if reload.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("ReloadTokens(generation=1) status=%v, want APPLY_STATUS_OK", reload.GetStatus())
	}
	time.Sleep(250 * time.Millisecond)
	journalBefore := h.Journal.String()
	before := dpharness.Status(t, h)
	beforeRequests, beforeBytes := t067bCounterTotals(before)
	expectedHour := uint64(h.CounterTime.Unix() / 3600)

	attempts := t067bRunAttempts(h, label, rep)
	secrets := append(append([][]byte{}, corpus...), []byte(t067bToken))
	secrets = append(secrets, additionalSecrets...)
	for i := 0; i < t067bRequestCount; i++ {
		dest := t067bDestination(label, i)
		secrets = append(secrets, []byte(dest), []byte(refusalIdentity(t067bToken, "t067b-"+label, dest)))
	}
	for _, attempt := range attempts {
		if attempt.err != nil {
			t.Errorf("%s attempt %02d (%s): %v", label, attempt.index, attempt.dest, attempt.err)
			continue
		}
		want := []byte{0x05, rep, 0, 1, 0, 0, 0, 0, 0, 0}
		if !bytes.Equal(attempt.reply, want) {
			t.Errorf("%s reply %02d = % x, want exactly % x", label, attempt.index, attempt.reply, want)
		}
		if len(attempt.full) != 10 {
			t.Errorf("%s full reply %02d has %d bytes, want exactly 10", label, attempt.index, len(attempt.full))
		}
		if rep == 0x06 && attempt.elapsed < 240*time.Second {
			t.Errorf("ROUTE_TIMEOUT attempt %02d completed in %s, too early for the production 250-second deadline", attempt.index, attempt.elapsed)
		}
		loginvariants.AssertNoSecrets(t, string(attempt.full), secrets...)
		if bytes.Contains(bytes.ToLower(attempt.full), []byte("<!doctype html>")) {
			t.Errorf("%s reply %02d contains an HTML template marker", label, attempt.index)
		}
	}

	// Let close-time accounting and journal writes settle before closing the
	// synthetic hour; route-failure replies themselves are never byte_count.
	time.Sleep(250 * time.Millisecond)
	if current := dpharness.Status(t, h); !equalT067bStatusCounters(before, current) {
		t.Errorf("GetStatus changed visible counters before the frozen hour completed")
	}
	h.AdvanceCounterHour(t)
	after := dpharness.Status(t, h)
	afterRequests, afterBytes := t067bCounterTotals(after)
	got := t067bCaseResult{requests: afterRequests - beforeRequests, bytes: afterBytes - beforeBytes}
	if got.requests != t067bRequestCount || got.bytes != 0 {
		t.Errorf("%s counter delta = requests %d, bytes %d; want exactly +%d and +0",
			label, got.requests, got.bytes, t067bRequestCount)
	}
	for _, row := range after.GetCounters() {
		if row.GetRoute() != "TOR" || row.GetHourBucket() != expectedHour {
			t.Errorf("%s counter row route/hour=%s/%d, want TOR/%d", label, row.GetRoute(), row.GetHourBucket(), expectedHour)
		}
	}
	if len(after.GetCounters()) != 1 {
		t.Errorf("%s completed hour has %d counter rows, want exactly one TOR bucket", label, len(after.GetCounters()))
	}

	time.Sleep(250 * time.Millisecond)
	journalAfter := h.Journal.String()
	journalDelta := t067bJournalDelta(journalBefore, journalAfter)
	loginvariants.AssertOnlyAllowedLines(t, journalDelta)
	loginvariants.AssertNoSubHourTimestamp(t, journalDelta)
	logSecrets := append(append([][]byte{}, secrets...), additionalSecrets...)
	loginvariants.AssertNoSecrets(t, journalDelta, logSecrets...)
	if strings.Contains(strings.ToLower(journalDelta), "<!doctype html>") {
		t.Errorf("%s request-window journal delta contains an HTML template marker", label)
	}
	return got
}

func t067bRunAttempts(h *dpharness.Harness, label string, rep byte) []t067bAttempt {
	results := make(chan t067bAttempt, t067bRequestCount)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(t067bRequestCount)
	for i := 0; i < t067bRequestCount; i++ {
		go func(index int) {
			defer workers.Done()
			<-start
			results <- t067bAttemptSocks5(h, label, index, rep)
		}(i)
	}
	close(start)
	workers.Wait()
	close(results)

	attempts := make([]t067bAttempt, 0, t067bRequestCount)
	for result := range results {
		attempts = append(attempts, result)
	}
	return attempts
}

func t067bAttemptSocks5(h *dpharness.Harness, label string, index int, rep byte) t067bAttempt {
	dest := t067bDestination(label, index)
	result := t067bAttempt{index: index, dest: dest}
	deadline := t067bQuickClientDeadline
	if rep == 0x06 {
		deadline = t067bClientDeadline
	}
	conn, err := net.DialTimeout("tcp", h.ProxyAddr, 5*time.Second)
	if err != nil {
		result.err = fmt.Errorf("dial proxy: %w", err)
		return result
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(deadline)); err != nil {
		result.err = fmt.Errorf("set client deadline: %w", err)
		return result
	}
	write := func(data []byte) error {
		n, err := conn.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	}
	readN := func(n int) ([]byte, error) {
		buf := make([]byte, n)
		_, err := io.ReadFull(conn, buf)
		return buf, err
	}
	fail := func(where string, err error) t067bAttempt {
		result.err = fmt.Errorf("%s: %w", where, err)
		return result
	}
	if err := write([]byte{0x05, 0x01, 0x02}); err != nil {
		return fail("write method greeting", err)
	}
	if got, err := readN(2); err != nil || !bytes.Equal(got, []byte{0x05, 0x02}) {
		if err == nil {
			err = fmt.Errorf("method reply=% x, want 05 02", got)
		}
		return fail("read method reply", err)
	}
	username := refusalIdentity(t067bToken, "t067b-"+label, dest)
	user, pass := []byte(username), []byte(t067bToken)
	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if err := write(auth); err != nil {
		return fail("write RFC 1929 credentials", err)
	}
	if got, err := readN(2); err != nil || !bytes.Equal(got, []byte{0x01, 0x00}) {
		if err == nil {
			err = fmt.Errorf("auth reply=% x, want 01 00", got)
		}
		return fail("read RFC 1929 reply", err)
	}
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(dest))}
	request = append(request, []byte(dest)...)
	request = append(request, 0x01, 0xbb)
	started := time.Now()
	if err := write(request); err != nil {
		return fail("write CONNECT request", err)
	}
	reply, err := readN(10)
	result.elapsed = time.Since(started)
	if err != nil {
		return fail("read fixed failure reply", err)
	}
	result.reply = reply
	trailing, err := io.ReadAll(conn)
	if err != nil {
		return fail("read to EOF", err)
	}
	result.full = append(append([]byte(nil), reply...), trailing...)
	if len(trailing) != 0 {
		result.err = fmt.Errorf("received %d trailing bytes after fixed reply", len(trailing))
	}
	return result
}

func t067bRefusingUpstream(t *testing.T) (string, *atomic.Int64, <-chan t067bConnect, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var dials atomic.Int64
	connects := make(chan t067bConnect, t067bRequestCount)
	finished := make(chan struct{})
	go func() {
		var handlers sync.WaitGroup
		defer func() {
			_ = listener.Close()
			handlers.Wait()
			close(finished)
		}()
		for i := 0; i < t067bRequestCount; i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			handlers.Add(1)
			go func(conn net.Conn) {
				defer handlers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
				reader := bufio.NewReader(conn)
				read := func(n int) ([]byte, error) {
					buf := make([]byte, n)
					_, err := io.ReadFull(reader, buf)
					return buf, err
				}
				header, err := read(2)
				if err != nil || header[0] != 5 {
					return
				}
				methods, err := read(int(header[1]))
				if err != nil || !bytes.Contains(methods, []byte{2}) {
					return
				}
				if _, err = conn.Write([]byte{5, 2}); err != nil {
					return
				}
				authHead, err := read(2)
				if err != nil || authHead[0] != 1 {
					return
				}
				if _, err = read(int(authHead[1])); err != nil {
					return
				}
				passLen, err := read(1)
				if err != nil || passLen[0] != 0 {
					return
				}
				password, err := read(int(passLen[0]))
				if err != nil || len(password) != 0 {
					return
				}
				if _, err = conn.Write([]byte{1, 0}); err != nil {
					return
				}
				reqHead, err := read(5)
				if err != nil || !bytes.Equal(reqHead[:4], []byte{5, 1, 0, 3}) {
					return
				}
				addressPort, err := read(int(reqHead[4]) + 2)
				if err != nil {
					return
				}
				host := string(addressPort[:len(addressPort)-2])
				port := uint16(addressPort[len(addressPort)-2])<<8 | uint16(addressPort[len(addressPort)-1])
				connects <- t067bConnect{host: host, port: port}
				_, _ = conn.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
				_, _ = io.WriteString(conn, t067bRefusalSentinel)
			}(conn)
		}
	}()
	return listener.Addr().String(), &dials, connects, finished
}

func t067bDestination(label string, index int) string {
	return fmt.Sprintf("t067b-%s-%02d-fixture.onion", label, index)
}

func t067bCounterTotals(resp *grpcpb.StatusResponse) (requests, byteCount uint64) {
	for _, row := range resp.GetCounters() {
		requests += row.GetRequestCount()
		byteCount += row.GetByteCount()
	}
	return requests, byteCount
}

func equalT067bStatusCounters(a, b *grpcpb.StatusResponse) bool {
	ar, ab := t067bCounterTotals(a)
	br, bb := t067bCounterTotals(b)
	return ar == br && ab == bb && len(a.GetCounters()) == len(b.GetCounters())
}

func t067bLoadLeakCorpus(t *testing.T, path string) [][]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read T064 leak corpus %q: %v", path, err)
	}
	var corpus [][]byte
	for _, entry := range strings.Fields(string(data)) {
		if !strings.HasPrefix(entry, "#") {
			corpus = append(corpus, []byte(entry))
		}
	}
	if len(corpus) == 0 {
		t.Fatal("T064 leak corpus is empty")
	}
	return corpus
}

func t067bJournalDelta(before, after string) string {
	if strings.HasPrefix(after, before) {
		return after[len(before):]
	}
	return after
}
