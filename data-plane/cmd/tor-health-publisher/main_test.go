// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"context"
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
	listener   net.Listener
	mu         sync.Mutex
	commands   []string
	reply      string
	stalled    bool
	rejectAuth bool
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
		reply, stalled, rejectAuth := f.reply, f.stalled, f.rejectAuth
		f.mu.Unlock()
		switch {
		case strings.HasPrefix(line, "AUTHENTICATE "):
			if rejectAuth {
				_, _ = io.WriteString(c, "515 Authentication failed\r\n")
			} else {
				_, _ = io.WriteString(c, "250 OK\r\n")
			}
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

const readyTor = "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n"

func queryFixture(t *testing.T, reply string) (config, *fakeTor) {
	t.Helper()
	d := t.TempDir()
	c := config{cookiePath: filepath.Join(d, "cookie"), torSocket: filepath.Join(d, "tor.sock")}
	if err := os.WriteFile(c.cookiePath, []byte("0123456789abcdefghijklmnopqrstuv"), 0600); err != nil {
		t.Fatal(err)
	}
	return c, startFakeTor(t, c.torSocket, reply)
}
func TestFixedExchangeAndRecovery(t *testing.T) {
	c, f := queryFixture(t, readyTor)
	if torHealth(c) != readyReply {
		t.Fatal("READY control failed")
	}
	time.Sleep(10 * time.Millisecond)
	commands := f.snapshot()
	if len(commands) != 3 || !strings.HasPrefix(commands[0], "AUTHENTICATE ") || commands[1] != "GETINFO status/bootstrap-phase" || commands[2] != "QUIT" {
		t.Fatal("unexpected fixed exchange")
	}
	_ = f.listener.Close()
	if torHealth(c) != unavailable {
		t.Fatal("dead Tor accepted")
	}
	f = startFakeTor(t, c.torSocket, readyTor)
	if torHealth(c) != readyReply {
		t.Fatal("socket recreation failed")
	}
	f.mu.Lock()
	f.rejectAuth = true
	f.mu.Unlock()
	if torHealth(c) != unavailable {
		t.Fatal("rejected authentication accepted")
	}
}
func TestCookieTypeAndTimeout(t *testing.T) {
	c, f := queryFixture(t, readyTor)
	_ = os.Remove(c.cookiePath)
	if err := unix.Mkfifo(c.cookiePath, 0600); err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	if torHealth(c) != unavailable || time.Since(begin) > time.Second {
		t.Fatal("FIFO not refused promptly")
	}
	_ = os.Remove(c.cookiePath)
	_ = os.WriteFile(c.cookiePath, make([]byte, 33), 0600)
	if torHealth(c) != unavailable || len(f.snapshot()) != 0 {
		t.Fatal("oversized cookie accepted")
	}
	_ = os.WriteFile(c.cookiePath, make([]byte, 32), 0600)
	f.mu.Lock()
	f.stalled = true
	f.mu.Unlock()
	begin = time.Now()
	if torHealth(c) != unavailable || time.Since(begin) > 5*time.Second {
		t.Fatal("query deadline exceeded")
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
			c, _ := queryFixture(t, reply)
			got := torHealth(c)
			if got != "UNAVAILABLE/1\n" {
				t.Fatalf("got %q", got)
			}
		})
	}
}

func TestAutonomousLoopHasOneAttemptAndCompletionPause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var starts, ends []time.Time
	runPublisher(ctx, func() {
		starts = append(starts, time.Now())
		time.Sleep(30 * time.Millisecond)
		ends = append(ends, time.Now())
		if len(starts) == 3 {
			cancel()
		}
	})
	if len(starts) != 3 || len(ends) != 3 {
		t.Fatal("unexpected attempt count")
	}
	for i := 1; i < len(starts); i++ {
		if starts[i].Sub(ends[i-1]) < time.Second {
			t.Fatal("query overlaps or skips completion pause")
		}
	}
}

// The seam delays a real regular-file read; O_NONBLOCK/FIFO checks do not
// establish a deadline for this operation. No runtime input controls the seam.
func TestDelayedRegularCookieIOBudget(t *testing.T) {
	c, f := queryFixture(t, readyTor)
	release := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	defer finish()
	entered := make(chan struct{}, 1)
	query := newQueryReader(func(path string) ([]byte, error) { entered <- struct{}{}; <-release; return readCookie(path) })
	result := make(chan string, 1)
	go func() { result <- query(c) }()
	<-entered
	select {
	case got := <-result:
		if got != unavailable {
			t.Fatal("delayed cookie became READY")
		}
	case <-time.After(torWindow + time.Second):
		t.Fatal("regular cookie I/O escaped total attempt budget")
	}
	for i := 0; i < 3; i++ {
		if got := query(c); got != unavailable {
			t.Fatal("pending worker accepted")
		}
	}
	select {
	case <-entered:
		t.Fatal("another cookie worker started while one was blocked")
	default:
	}
	if len(f.snapshot()) != 0 {
		t.Fatal("blocked cookie caused Tor commands")
	}
	finish()
	limit := time.Now().Add(time.Second)
	for time.Now().Before(limit) {
		if query(c) == readyReply {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("cookie recovery did not produce a fresh READY")
}
