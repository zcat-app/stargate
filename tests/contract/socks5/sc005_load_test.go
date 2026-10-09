// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/integration"
)

const (
	sc005Token       = "11111111111111111111111111111111"
	sc005BadPassword = "22222222222222222222222222222222"
	sc005ConnBudget  = 64 << 10
	sc005AbsCeiling  = 512 << 20
	sc005Hold        = 60 * time.Second
)

// TestSC005ConcurrentSOCKS5Load pins SC-005's pool behavior and T093's HMAC
// memory falsifier on Linux, where the child process RSS is observable.
func TestSC005ConcurrentSOCKS5Load(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SC-005 RSS gate requires Linux /proc child metrics")
	}
	if len(sc005BadPassword) != 32 || !isLowerHex(sc005BadPassword) || sc005BadPassword == sc005Token {
		t.Fatal("invalid-auth fixture must be a distinct 32-character lowercase-hex value")
	}

	upstream := integration.NewServer(integration.AcceptAndRelay)
	upstreamAddr, err := upstream.Start()
	if err != nil {
		t.Fatal("start synthetic upstream")
	}
	t.Cleanup(func() { _ = upstream.Close() })

	h := dpharness.Start(t, dpharness.WithControlPlane(), dpharness.WithUpstream(upstreamAddr), dpharness.WithSuppressFailureJournal())
	dpharness.Reload(t, h, 1, []*grpcpb.TokenVerifier{dpharness.MintToken(t, sc005Token)})
	waitForWatchEventsDial(t, h.CP)
	time.Sleep(100 * time.Millisecond) // let boot and auth-generation diagnostics quiesce
	journalBefore := h.Journal.String()

	idle, err := readProcessMemory(h.PID)
	if err != nil {
		t.Fatal("read idle DP memory metrics")
	}
	relativeCeiling := idle.hwm + 200*sc005ConnBudget
	watch := newRSSWatch(h.PID, h.Cmd.Process, relativeCeiling, sc005AbsCeiling)
	defer watch.stop()

	floodStarted := time.Now()
	attempts := 0
	for _, count := range []int{1, 2, 4, 8, 16, 32, 64, 128, 200} {
		remaining := 30*time.Second - time.Since(floodStarted)
		if remaining <= 0 {
			t.Fatal("invalid-auth flood exceeded 30-second phase deadline")
		}
		latencies, cohortErr := runInvalidAuthCohort(h.ProxyAddr, count, watch, remaining)
		attempts += count
		if cohortErr != nil {
			t.Fatalf("invalid-auth cohort concurrency=%d failed: %v", count, cohortErr)
		}
		watch.check(t)
		for _, conn := range watch.snapshotClients() {
			_ = conn.Close()
		}
		watch.setClients(nil)
		if count == 200 {
			t.Logf("invalid-auth final cohort: concurrency=%d attempts=%d auth_latency_mean=%s auth_latency_max=%s", count, len(latencies), meanDuration(latencies), maxDuration(latencies))
		}
	}
	floodWall := time.Since(floodStarted)
	watch.stop()
	if err := watch.sample(); err != nil {
		watch.fail(err)
	}
	watch.check(t)
	floodPeak := watch.metrics()
	if floodPeak.rss > sc005AbsCeiling || floodPeak.hwm > sc005AbsCeiling || floodPeak.hwm > relativeCeiling {
		t.Fatalf("DP flood memory ceiling exceeded: peak_rss=%d peak_hwm=%d baseline_hwm=%d relative_ceiling=%d absolute_ceiling=%d", floodPeak.rss, floodPeak.hwm, idle.hwm, relativeCeiling, sc005AbsCeiling)
	}
	assertJournalUnchanged(t, journalBefore, h.Journal.String())
	t.Logf("invalid-auth flood: attempts=%d wall=%s idle_rss=%d idle_hwm=%d peak_rss=%d peak_hwm=%d hwm_delta=%d relative_ceiling=%d absolute_ceiling=%d max_concurrency=200", attempts, floodWall, idle.rss, idle.hwm, floodPeak.rss, floodPeak.hwm, floodPeak.hwm-idle.hwm, relativeCeiling, sc005AbsCeiling)

	poolStarted := time.Now()
	clients, fillErr := fillAuthenticatedPool(h.ProxyAddr, 200)
	if fillErr != nil {
		closeAll(clients)
		t.Fatalf("authenticated pool did not fill: %v", fillErr)
	}
	t.Cleanup(func() { closeAll(clients) })
	fillWall := time.Since(poolStarted)
	if fillWall > 30*time.Second {
		t.Fatalf("authenticated pool fill took %s, exceeds 30s", fillWall)
	}
	if upstream.ConnectCount() != 200 {
		t.Fatalf("synthetic upstream CONNECT count=%d, want 200", upstream.ConnectCount())
	}
	assertJournalUnchanged(t, journalBefore, h.Journal.String())
	t.Logf("authenticated pool fill: connections=200 fill_wall=%s auth_latency=reported per flood cohort", fillWall)

	if err := holdBidirectional(clients, sc005Hold); err != nil {
		t.Fatalf("authenticated 200-client bidirectional hold failed: %v", err)
	}
	assertJournalUnchanged(t, journalBefore, h.Journal.String())
	t.Logf("authenticated pool hold: connections=200 duration=%s all_clients_round_tripped=true", sc005Hold)
}

type processMemory struct{ rss, hwm int64 }

func readProcessMemory(pid int) (processMemory, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return processMemory{}, err
	}
	var out processMemory
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		value, parseErr := strconv.ParseInt(fields[1], 10, 64)
		if parseErr != nil {
			continue
		}
		switch fields[0] {
		case "VmRSS:":
			out.rss = value * 1024
		case "VmHWM:":
			out.hwm = value * 1024
		}
	}
	if out.rss == 0 || out.hwm == 0 {
		return processMemory{}, fmt.Errorf("required VmRSS/VmHWM metrics missing")
	}
	return out, nil
}

type rssWatch struct {
	pid, relativeCeiling, absoluteCeiling int64
	process                               *os.Process
	mu                                    sync.Mutex
	clients                               []net.Conn
	peakRSS, peakHWM                      int64
	breach                                chan error
	stopCh                                chan struct{}
	stopped                               chan struct{}
	stopOnce                              sync.Once
}

func newRSSWatch(pid int, process *os.Process, relativeCeiling, absoluteCeiling int64) *rssWatch {
	w := &rssWatch{
		pid: int64(pid), process: process,
		relativeCeiling: relativeCeiling, absoluteCeiling: absoluteCeiling,
		breach: make(chan error, 1), stopCh: make(chan struct{}), stopped: make(chan struct{}),
	}
	if err := w.sample(); err != nil {
		w.fail(err)
	}
	go w.sampleLoop()
	return w
}

func (w *rssWatch) sampleLoop() {
	defer close(w.stopped)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			if err := w.sample(); err != nil {
				w.fail(err)
				return
			}
		}
	}
}

func (w *rssWatch) sample() error {
	got, err := readProcessMemory(int(w.pid))
	if err != nil {
		return fmt.Errorf("DP RSS sampler could not read child metrics")
	}
	w.mu.Lock()
	if got.rss > w.peakRSS {
		w.peakRSS = got.rss
	}
	if got.hwm > w.peakHWM {
		w.peakHWM = got.hwm
	}
	breach := got.rss > w.absoluteCeiling || got.hwm > w.absoluteCeiling || got.hwm > w.relativeCeiling
	w.mu.Unlock()
	if breach {
		return fmt.Errorf("DP RSS ceiling exceeded during invalid-auth flood")
	}
	return nil
}

func (w *rssWatch) fail(err error) {
	_ = w.process.Kill()
	w.closeClients()
	select {
	case w.breach <- err:
	default:
	}
}

func (w *rssWatch) check(t *testing.T) {
	t.Helper()
	select {
	case err := <-w.breach:
		t.Fatalf("memory safety monitor stopped the data plane: %v", err)
	default:
	}
}

func (w *rssWatch) setClients(clients []net.Conn) {
	w.mu.Lock()
	w.clients = append(w.clients[:0], clients...)
	w.mu.Unlock()
}

func (w *rssWatch) snapshotClients() []net.Conn {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]net.Conn(nil), w.clients...)
}

func (w *rssWatch) closeClients() {
	for _, conn := range w.snapshotClients() {
		_ = conn.Close()
	}
}

func (w *rssWatch) metrics() processMemory {
	w.mu.Lock()
	defer w.mu.Unlock()
	return processMemory{rss: w.peakRSS, hwm: w.peakHWM}
}

func (w *rssWatch) stop() {
	w.stopOnce.Do(func() { close(w.stopCh) })
	<-w.stopped
}

func runInvalidAuthCohort(proxyAddr string, count int, watch *rssWatch, timeout time.Duration) ([]time.Duration, error) {
	clients := make([]net.Conn, 0, count)
	phaseDeadline := time.Now().Add(timeout)
	closeClients := func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
	}
	for i := 0; i < count; i++ {
		remaining := time.Until(phaseDeadline)
		if remaining <= 0 {
			closeClients()
			return nil, fmt.Errorf("flood phase exceeded 30-second deadline")
		}
		dialTimeout := min(remaining, 3*time.Second)
		conn, err := net.DialTimeout("tcp", proxyAddr, dialTimeout)
		if err != nil {
			closeClients()
			return nil, fmt.Errorf("client setup failed")
		}
		clients = append(clients, conn)
		watch.setClients(clients)
		_ = conn.SetDeadline(phaseDeadline)
		if err := writeFull(conn, []byte{0x05, 0x01, 0x02}); err != nil {
			_ = conn.Close()
			closeClients()
			return nil, fmt.Errorf("client method negotiation write failed")
		}
		var method [2]byte
		if _, err := io.ReadFull(conn, method[:]); err != nil || method != [2]byte{0x05, 0x02} {
			_ = conn.Close()
			closeClients()
			return nil, fmt.Errorf("client method negotiation reply mismatch")
		}
		select {
		case err := <-watch.breach:
			closeClients()
			return nil, err
		default:
		}
	}
	watch.setClients(clients)
	barrier := make(chan struct{})
	type result struct {
		latency time.Duration
		err     error
	}
	results := make(chan result, count)
	for _, conn := range clients {
		go func(c net.Conn) {
			<-barrier
			start := time.Now()
			req := []byte{0x01, 0x01, 'x', byte(len(sc005BadPassword))}
			req = append(req, sc005BadPassword...)
			if err := writeFull(c, req); err != nil {
				results <- result{err: fmt.Errorf("auth request write failed")}
				return
			}
			var reply [2]byte
			if _, err := io.ReadFull(c, reply[:]); err != nil || reply != [2]byte{0x01, 0xff} {
				results <- result{err: fmt.Errorf("auth failure reply mismatch")}
				return
			}
			results <- result{latency: time.Since(start)}
		}(conn)
	}
	close(barrier)
	latencies := make([]time.Duration, 0, count)
	deadline := time.NewTimer(time.Until(phaseDeadline))
	defer deadline.Stop()
	for received := 0; received < count; received++ {
		select {
		case result := <-results:
			if result.err != nil {
				closeClients()
				return latencies, result.err
			}
			latencies = append(latencies, result.latency)
		case err := <-watch.breach:
			closeClients()
			return latencies, err
		case <-deadline.C:
			closeClients()
			return latencies, fmt.Errorf("cohort exceeded 30-second deadline")
		}
	}
	return latencies, nil
}

func fillAuthenticatedPool(proxyAddr string, count int) ([]net.Conn, error) {
	barrier := make(chan struct{})
	phaseDeadline := time.Now().Add(30 * time.Second)
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, count)
	for i := 0; i < count; i++ {
		go func(index int) {
			<-barrier
			conn, err := openAuthenticatedTunnel(proxyAddr, index, phaseDeadline)
			results <- result{conn: conn, err: err}
		}(i)
	}
	close(barrier)
	deadline := time.NewTimer(time.Until(phaseDeadline))
	defer deadline.Stop()
	clients := make([]net.Conn, 0, count)
	var firstErr error
	deadlineCh := deadline.C
	for received := 0; received < count; {
		select {
		case result := <-results:
			received++
			if result.err != nil && firstErr == nil {
				closeAll(clients)
				clients = nil
				firstErr = result.err
			}
			if result.conn != nil {
				if firstErr != nil || result.err != nil {
					_ = result.conn.Close()
				} else {
					clients = append(clients, result.conn)
				}
			}
		case <-deadlineCh:
			deadlineCh = nil
			if firstErr == nil {
				firstErr = fmt.Errorf("pool fill exceeded 30-second deadline")
			}
			closeAll(clients)
			clients = nil
		}
	}
	if firstErr != nil {
		closeAll(clients)
		return nil, firstErr
	}
	return clients, nil
}

func openAuthenticatedTunnel(proxyAddr string, index int, phaseDeadline time.Time) (net.Conn, error) {
	remaining := time.Until(phaseDeadline)
	if remaining <= 0 {
		return nil, fmt.Errorf("pool fill exceeded 30-second deadline")
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, min(remaining, 5*time.Second))
	if err != nil {
		return nil, fmt.Errorf("client dial failed")
	}
	_ = conn.SetDeadline(phaseDeadline)
	if err := writeFull(conn, []byte{0x05, 0x01, 0x02}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("method negotiation write failed")
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil || method != [2]byte{0x05, 0x02} {
		_ = conn.Close()
		return nil, fmt.Errorf("method negotiation reply mismatch")
	}
	uname := []byte(fmt.Sprintf("sg1:%064x", index+1))
	req := []byte{0x01, byte(len(uname))}
	req = append(req, uname...)
	req = append(req, byte(len(sc005Token)))
	req = append(req, sc005Token...)
	if err := writeFull(conn, req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("auth request write failed")
	}
	var authReply [2]byte
	if _, err := io.ReadFull(conn, authReply[:]); err != nil || authReply != [2]byte{0x01, 0x00} {
		_ = conn.Close()
		return nil, fmt.Errorf("auth success reply mismatch")
	}
	dest := []byte(fmt.Sprintf("t079a-%03d.onion", index))
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(dest))}
	request = append(request, dest...)
	request = append(request, 0x01, 0xbb)
	if err := writeFull(conn, request); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT request write failed")
	}
	var reply [10]byte
	want := [10]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply != want {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT success reply mismatch")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func holdBidirectional(clients []net.Conn, duration time.Duration) error {
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan error, len(clients))
	counts := make([]atomic.Int64, len(clients))
	windowCount := int(duration / time.Second)
	activity := make([][]int, len(clients))
	for i := range activity {
		activity[i] = make([]int, windowCount)
	}
	holdStarted := time.Now()
	for i, conn := range clients {
		wg.Add(1)
		go func(index int, c net.Conn) {
			defer wg.Done()
			var sequence uint64
			for {
				select {
				case <-stop:
					return
				default:
				}
				sequence++
				frame := make([]byte, 16)
				binary.LittleEndian.PutUint32(frame[:4], uint32(index))
				binary.LittleEndian.PutUint64(frame[4:12], sequence)
				binary.LittleEndian.PutUint32(frame[12:], uint32(index)^uint32(sequence))
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if err := writeFull(c, frame); err != nil {
					errs <- fmt.Errorf("client %d write failed", index)
					return
				}
				var echoed [16]byte
				if _, err := io.ReadFull(c, echoed[:]); err != nil || !bytes.Equal(echoed[:], frame) {
					errs <- fmt.Errorf("client %d echo mismatch or close", index)
					return
				}
				counts[index].Add(1)
				elapsed := time.Since(holdStarted)
				if elapsed < duration {
					window := int(elapsed / time.Second)
					activity[index][window]++
				}
				time.Sleep(100 * time.Millisecond)
			}
		}(i, conn)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	var holdErr error
	select {
	case holdErr = <-errs:
	case <-timer.C:
	}
	close(stop)
	if holdErr != nil {
		closeAll(clients)
	}
	wg.Wait()
	if holdErr == nil {
		select {
		case holdErr = <-errs:
		default:
		}
	}
	if holdErr != nil {
		return holdErr
	}
	for i := range clients {
		if counts[i].Load() == 0 {
			return fmt.Errorf("client %d was starved during hold", i)
		}
		for window, successes := range activity[i] {
			if successes == 0 {
				return fmt.Errorf("client %d had no round trip in hold window %d", i, window)
			}
		}
	}
	return nil
}

func writeFull(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func closeAll(clients []net.Conn) {
	for _, conn := range clients {
		_ = conn.Close()
	}
}

func assertJournalUnchanged(t *testing.T, before, after string) {
	t.Helper()
	if before == after {
		return
	}
	changed := absInt(len(before) - len(after))
	limit := len(before)
	if len(after) < limit {
		limit = len(after)
	}
	for i := 0; i < limit; i++ {
		if before[i] != after[i] {
			changed++
		}
	}
	t.Fatalf("captured child output changed during load (changed byte count=%d)", changed)
}

func isLowerHex(value string) bool {
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func meanDuration(values []time.Duration) time.Duration {
	var total time.Duration
	for _, value := range values {
		total += value
	}
	if len(values) == 0 {
		return 0
	}
	return total / time.Duration(len(values))
}

func maxDuration(values []time.Duration) time.Duration {
	var max time.Duration
	for _, value := range values {
		if value > max {
			max = value
		}
	}
	return max
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
