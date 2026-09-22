// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/auth"
	"github.com/zcat-app/stargate/data-plane/internal/controlclient"
	pb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

var midHour = time.Date(2026, 9, 4, 10, 30, 0, 0, time.UTC)

type testClock struct{ seconds atomic.Int64 }

func (c *testClock) now() time.Time  { return time.Unix(c.seconds.Load(), 0) }
func (c *testClock) set(t time.Time) { c.seconds.Store(t.Unix()) }
func fixture() (*Counters, *testClock) {
	clock := &testClock{}
	clock.set(midHour)
	return NewWithClock(clock.now), clock
}
func assertRows(t *testing.T, got *pb.StatusResponse, want ...*pb.RouteCounter) {
	t.Helper()
	if !proto.Equal(got, &pb.StatusResponse{Counters: want}) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
}
func row(offset int, requests, bytes uint64) *pb.RouteCounter {
	return &pb.RouteCounter{Route: "TOR", HourBucket: uint64(midHour.Unix()/3600) + uint64(offset), RequestCount: requests, ByteCount: bytes}
}

func TestCurrentHourNeverVisible(t *testing.T) {
	c := New()
	for i := 0; i < 20; i++ {
		c.AuthPassedRequest()
		c.AddForwardedBytes(13)
		if rows := c.Snapshot().GetCounters(); len(rows) != 0 {
			t.Fatalf("current-hour traffic exposed by poll %d: %v", i, rows)
		}
	}
}

func TestCompletedPublicationRolloverAndLongLivedCompletion(t *testing.T) {
	c, clock := fixture()
	for i := 0; i < 3; i++ {
		c.AuthPassedRequest()
	}
	c.AddForwardedBytes(100)
	c.AddForwardedBytes(23)
	assertRows(t, c.Snapshot())
	clock.set(midHour.Truncate(time.Hour).Add(time.Hour - time.Second))
	assertRows(t, c.Snapshot())
	clock.set(midHour.Truncate(time.Hour).Add(time.Hour))
	first := c.Snapshot()
	assertRows(t, first, row(0, 3, 123))
	// Two tunnels complete after admission's bucket was published; no retroactive edit.
	clock.set(midHour.Add(2 * time.Hour))
	c.AddForwardedBytes(7)
	c.AddForwardedBytes(5)
	assertRows(t, c.Snapshot(), row(0, 3, 123))
	clock.set(midHour.Add(3 * time.Hour))
	assertRows(t, c.Snapshot(), row(0, 3, 123), row(2, 0, 12))
	assertRows(t, first, row(0, 3, 123))
	first.Counters[0].RequestCount = 99
	assertRows(t, c.Snapshot(), row(0, 3, 123), row(2, 0, 12))
}

func TestClockRegressionCannotReopenPublishedHour(t *testing.T) {
	c, clock := fixture()
	c.AuthPassedRequest()
	clock.set(midHour.Add(time.Hour))
	assertRows(t, c.Snapshot(), row(0, 1, 0))
	for _, instant := range []time.Time{midHour, midHour.Add(-10 * time.Hour), time.Unix(-3600, 0)} {
		clock.set(instant)
		c.AuthPassedRequest()
		c.AddForwardedBytes(5)
		assertRows(t, c.Snapshot(), row(0, 1, 0))
	}
	clock.set(midHour.Add(2 * time.Hour))
	assertRows(t, c.Snapshot(), row(0, 1, 0), row(1, 3, 15))
}

func TestRetentionCutoffAndForwardJump(t *testing.T) {
	c, clock := fixture()
	c.AuthPassedRequest()
	c.AddForwardedBytes(31)
	clock.set(midHour.Add(time.Hour))
	c.AuthPassedRequest()
	clock.set(midHour.Truncate(time.Hour).Add(168*time.Hour - time.Second))
	assertRows(t, c.Snapshot(), row(0, 1, 31), row(1, 1, 0))
	clock.set(midHour.Truncate(time.Hour).Add(168 * time.Hour))
	assertRows(t, c.Snapshot(), row(1, 1, 0))
	clock.set(midHour) // Expiry never reverses.
	assertRows(t, c.Snapshot(), row(1, 1, 0))
	c.AddForwardedBytes(100) // Completion is counted even if its admission row expired.
	clock.set(midHour.Add(169 * time.Hour))
	assertRows(t, c.Snapshot(), row(168, 0, 100))
	clock.set(midHour.Add(1000 * time.Hour))
	assertRows(t, c.Snapshot())
	if len(c.buckets) != 0 {
		t.Fatal("expired rows remain in memory")
	}
}

func TestIdleCleanupAndCancellation(t *testing.T) {
	c, clock := fixture()
	c.AuthPassedRequest()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wake := make(chan time.Time)
	waiting := make(chan time.Duration)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.run(ctx, func(d time.Duration) <-chan time.Time { waiting <- d; return wake })
	}()
	wait := func() {
		t.Helper()
		select {
		case d := <-waiting:
			if d <= 0 || d > time.Hour {
				t.Fatalf("invalid hour-boundary wait %v", d)
			}
		case <-done:
			t.Fatal("worker exited before cleanup")
		case <-time.After(time.Second):
			t.Fatal("worker did not wait")
		}
	}
	wait()
	clock.set(midHour.Add(168 * time.Hour))
	wake <- clock.now()
	wait()
	// No Snapshot call: this falsifies lazy read-only expiry.
	c.mu.Lock()
	n := len(c.buckets)
	c.mu.Unlock()
	if n != 0 {
		t.Fatal("idle worker retained expired traffic")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop with owner")
	}
}

func TestDisabledRetention(t *testing.T) {
	c, clock := fixture()
	c.AuthPassedRequest()
	c.Disable()
	c.AuthPassedRequest()
	c.AddForwardedBytes(17)
	clock.set(midHour.Add(time.Hour))
	assertRows(t, c.Snapshot())
	if len(c.buckets) != 0 {
		t.Fatal("disabled retention kept private traffic")
	}
	assertRows(t, New().Snapshot()) // A fresh process store cannot recover traffic.
}

// Actual UDS + production mTLS/version interceptors, using synthetic local keys.
func statusRPC(t *testing.T, c *Counters) func() *pb.StatusResponse {
	t.Helper()
	dir, err := os.MkdirTemp("", "sg-counter-rpc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	cert := func(role string, id controlclient.Identity) tls.Certificate {
		t.Helper()
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, role+".pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := controlclient.DeriveCert(key, id)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	dp, cp := cert("dp", controlclient.DPIdentity), cert("cp", controlclient.CPIdentity)
	server := controlclient.NewServer(auth.NewTokenStore(), func(*auth.Generation) error { return nil }, c.Snapshot, slog.New(slog.NewTextHandler(io.Discard, nil)))
	gs, err := controlclient.NewGRPCServer(server, controlclient.ServerTLSConfig(dp, filepath.Join(dir, "cp.pub")))
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("unix", filepath.Join(dir, "dp.sock"))
	if err != nil {
		t.Fatal(err)
	}
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	cc, err := grpc.NewClient("unix://"+lis.Addr().String(), grpc.WithTransportCredentials(controlclient.NewTransportCredentials(controlclient.ClientTLSConfig(cp, filepath.Join(dir, "dp.pub")))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cc.Close() })
	client := pb.NewControlClient(cc)
	return func() *pb.StatusResponse {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ctx = metadata.AppendToOutgoingContext(ctx, "x-stargate-proto-major", "1", "x-stargate-proto-minor", "0", "x-stargate-capabilities", "reload-tokens,watch-events,get-status-minimum")
		r, err := client.GetStatus(ctx, &pb.StatusRequest{})
		if err != nil {
			t.Errorf("GetStatus: %v", err)
			return &pb.StatusResponse{}
		}
		return r
	}
}

func TestRPCRepeatedPollingConcurrencyRetentionAndRollback(t *testing.T) {
	c, clock := fixture()
	read := statusRPC(t, c)
	assertRows(t, read())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				c.AuthPassedRequest()
				c.AddForwardedBytes(13)
				if len(read().GetCounters()) != 0 {
					t.Error("concurrent RPC leaked active counts")
				}
			}
		}()
	}
	wg.Wait()
	clock.set(midHour.Add(time.Hour))
	assertRows(t, read(), row(0, 320, 4160))
	clock.set(midHour)
	c.AddForwardedBytes(101)
	for i := 0; i < 10; i++ {
		assertRows(t, read(), row(0, 320, 4160))
	}
	clock.set(midHour.Add(2 * time.Hour))
	assertRows(t, read(), row(0, 320, 4160), row(1, 0, 101))
	clock.set(midHour.Add(168 * time.Hour))
	assertRows(t, read(), row(1, 0, 101))
	clock.set(midHour.Add(169 * time.Hour))
	assertRows(t, read())
	clock.set(midHour)
	assertRows(t, read())
}

func TestConcurrentRolloverPreservesTotals(t *testing.T) {
	c, clock := fixture()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.AuthPassedRequest()
				c.AddForwardedBytes(17)
			}
		}()
	}
	clock.set(midHour.Add(time.Hour))
	// Reading can close the previous hour concurrently with in-flight increments.
	for i := 0; i < 20; i++ {
		c.Snapshot()
	}
	wg.Wait()
	clock.set(midHour.Add(2 * time.Hour))
	var requests, bytes uint64
	for _, r := range c.Snapshot().GetCounters() {
		requests += r.RequestCount
		bytes += r.ByteCount
	}
	if requests != 8000 || bytes != 136000 {
		t.Fatalf("rollover lost totals: %d/%d", requests, bytes)
	}
}
