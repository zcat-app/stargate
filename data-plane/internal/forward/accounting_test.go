// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package forward

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// pausedIO holds a successful underlying operation before countingConn can add
// its result. Channels force the audited interleaving without scheduler sleeps.
type pausedIO struct {
	net.Conn
	write                   bool
	paused, release, closed chan struct{}
	closeOnce               sync.Once
}

func (c *pausedIO) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !c.write && n > 0 {
		close(c.paused)
		<-c.release
	}
	return n, err
}

func (c *pausedIO) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if c.write && n > 0 {
		close(c.paused)
		<-c.release
	}
	return n, err
}

func (c *pausedIO) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() { close(c.closed) })
	return err
}

type flushRecorder struct {
	mu    sync.Mutex
	calls int
	bytes uint64
}

func (c *flushRecorder) AddForwardedBytes(n uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.bytes += n
}

func (c *flushRecorder) snapshot() (int, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.bytes
}

func awaitAccounting(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func TestConcurrentCloseWaitsForAccounting(t *testing.T) {
	for _, write := range []bool{false, true} {
		name := "read"
		if write {
			name = "write"
		}
		t.Run(name, func(t *testing.T) {
			client, peer := net.Pipe()
			upstream, remote := net.Pipe()
			paused := &pausedIO{Conn: upstream, write: write, paused: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
			var release sync.Once
			t.Cleanup(func() {
				release.Do(func() { close(paused.release) })
				client.Close()
				peer.Close()
				upstream.Close()
				remote.Close()
			})
			counts := &flushRecorder{}
			counted := &countingConn{Conn: paused, counts: counts}
			done := make(chan struct{})
			go func() { bridge(client, counted); close(done) }()
			const payload = "hello"
			if write {
				go func() { _, _ = peer.Write([]byte(payload)) }()
				buf := make([]byte, len(payload))
				if _, err := io.ReadFull(remote, buf); err != nil || string(buf) != payload {
					t.Fatalf("underlying transfer = %q, %v", buf, err)
				}
			} else {
				if _, err := remote.Write([]byte(payload)); err != nil {
					t.Fatal(err)
				}
			}
			awaitAccounting(t, paused.paused, "successful I/O before accounting")
			if write {
				remote.Close()
			} else {
				peer.Close()
			}
			awaitAccounting(t, paused.closed, "upstream shutdown while accounting is paused")
			if calls, n := counts.snapshot(); calls != 0 || n != 0 {
				t.Errorf("premature flush: calls=%d bytes=%d; accounting is still paused", calls, n)
			}
			release.Do(func() { close(paused.release) })
			awaitAccounting(t, done, "both pumps and final accounting")
			if calls, n := counts.snapshot(); calls != 1 || n != uint64(len(payload)) {
				t.Errorf("final flush: calls=%d bytes=%d, want 1 and %d", calls, n, len(payload))
			}
		})
	}
}

// ioEntered exposes which pump operation is waiting on a real net.Pipe. Neither
// endpoint supplies an idle deadline; termination must actively cancel the I/O.
type ioEntered struct {
	net.Conn
	read, write  chan struct{}
	rOnce, wOnce sync.Once
}

func (c *ioEntered) Read(p []byte) (int, error) {
	c.rOnce.Do(func() { close(c.read) })
	return c.Conn.Read(p)
}

func (c *ioEntered) Write(p []byte) (int, error) {
	c.wOnce.Do(func() { close(c.write) })
	return c.Conn.Write(p)
}

func TestBridgeCancelsBlockedIOBeforeJoining(t *testing.T) {
	for _, operation := range []string{"client-read", "client-write", "upstream-read", "upstream-write"} {
		t.Run(operation, func(t *testing.T) {
			client, peer := net.Pipe()
			upstream, remote := net.Pipe()
			t.Cleanup(func() { client.Close(); peer.Close(); upstream.Close(); remote.Close() })
			c := &ioEntered{Conn: client, read: make(chan struct{}), write: make(chan struct{})}
			u := &ioEntered{Conn: upstream, read: make(chan struct{}), write: make(chan struct{})}
			counts := &flushRecorder{}
			done := make(chan struct{})
			go func() { bridge(c, &countingConn{Conn: u, counts: counts}); close(done) }()
			var wantBytes uint64
			switch operation {
			case "client-read":
				awaitAccounting(t, c.read, operation)
				remote.Close()
			case "client-write":
				if _, err := remote.Write([]byte("hello")); err != nil {
					t.Fatal(err)
				}
				awaitAccounting(t, c.write, operation)
				// End the other pump without closing the client's write half.
				if err := client.SetReadDeadline(time.Now()); err != nil {
					t.Fatal(err)
				}
				wantBytes = 5 // preserve upstream-boundary accounting semantics
			case "upstream-read":
				awaitAccounting(t, u.read, operation)
				peer.Close()
			case "upstream-write":
				if _, err := peer.Write([]byte("hello")); err != nil {
					t.Fatal(err)
				}
				awaitAccounting(t, u.write, operation)
				if err := upstream.SetReadDeadline(time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			awaitAccounting(t, done, "shutdown with "+operation+" blocked")
			if calls, n := counts.snapshot(); calls != 1 || n != wantBytes {
				t.Fatalf("final flush: calls=%d bytes=%d, want 1 and %d", calls, n, wantBytes)
			}
		})
	}
}
