// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package listener

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const plannedFramingLimit = 200

// acceptedListener counts connections returned to the serving loop. Dial
// completion alone is not an admission observation: the kernel may queue a
// connection while Serve is correctly waiting for a framing permit.
type connectionCounter interface {
	connectionCounts() (accepted, closed int64)
}

type acceptedListener struct {
	net.Listener
	accepted atomic.Int64
	closed   atomic.Int64
}

type trackedConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.onClose)
	return err
}

func (l *acceptedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.accepted.Add(1)
	return &trackedConn{Conn: c, onClose: func() { l.closed.Add(1) }}, nil
}

func (l *acceptedListener) connectionCounts() (int64, int64) {
	return l.accepted.Load(), l.closed.Load()
}

func listenAccepted(t *testing.T) *acceptedListener {
	t.Helper()
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	l := &acceptedListener{Listener: base}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// serveHarness installs cleanup before Serve starts or a client is dialed.
// Work has a shared seven-second deadline; cleanup gets at most three more
// seconds to close owned endpoints and join the accept loop and handlers.
type serveHarness struct {
	t               *testing.T
	l               net.Listener
	deps            *Deps
	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	result          error
	started         bool
	deadline        time.Time
	cleanupDeadline time.Time
	mu              sync.Mutex
	clients         []net.Conn
	unblock         []func()
	stopOnce        sync.Once
}

func newServeHarness(t *testing.T, l net.Listener, deps *Deps) *serveHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &serveHarness{t: t, l: l, deps: deps, ctx: ctx, cancel: cancel, done: make(chan struct{}), deadline: time.Now().Add(7 * time.Second)}
	t.Cleanup(func() { h.stop(); h.awaitCleanup() })
	return h
}

func (h *serveHarness) start() {
	h.t.Helper()
	if h.started {
		h.t.Fatal("Serve harness started twice")
	}
	h.started = true
	go func() { h.result = Serve(h.ctx, h.l, h.deps); close(h.done) }()
}

func (h *serveHarness) remaining() time.Duration {
	d := time.Until(h.deadline)
	if d <= 0 {
		h.t.Fatal("shared 7s test-case deadline exhausted")
	}
	return d
}

func (h *serveHarness) own(c net.Conn) net.Conn {
	h.t.Helper()
	h.mu.Lock()
	h.clients = append(h.clients, c)
	h.mu.Unlock()
	h.refresh(c)
	return c
}

func (h *serveHarness) refresh(c net.Conn) {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	if deadline.After(h.deadline) {
		deadline = h.deadline
	}
	if err := c.SetDeadline(deadline); err != nil {
		h.t.Fatalf("set fixture connection deadline: %v", err)
	}
}

func (h *serveHarness) dial(addr net.Addr) net.Conn {
	h.t.Helper()
	budget := h.remaining()
	if budget > time.Second {
		budget = time.Second
	}
	c, err := net.DialTimeout("tcp", addr.String(), budget)
	if err != nil {
		h.t.Fatalf("dial loopback fixture: %v", err)
	}
	return h.own(c)
}

func (h *serveHarness) onStop(fn func()) {
	h.mu.Lock()
	h.unblock = append(h.unblock, fn)
	h.mu.Unlock()
}

func (h *serveHarness) stop() {
	h.stopOnce.Do(func() {
		h.mu.Lock()
		h.cleanupDeadline = time.Now().Add(3 * time.Second)
		if latest := h.deadline.Add(3 * time.Second); h.cleanupDeadline.After(latest) {
			h.cleanupDeadline = latest
		}
		callbacks := append([]func(){}, h.unblock...)
		clients := append([]net.Conn{}, h.clients...)
		h.mu.Unlock()
		for _, fn := range callbacks {
			fn()
		}
		h.cancel()
		_ = h.l.Close()
		for _, c := range clients {
			_ = c.Close()
		}
	})
}

func (h *serveHarness) await(t *testing.T, want error) {
	t.Helper()
	h.mu.Lock()
	deadline := h.cleanupDeadline
	h.mu.Unlock()
	if deadline.IsZero() {
		deadline = time.Now().Add(3 * time.Second)
		if latest := h.deadline.Add(3 * time.Second); deadline.After(latest) {
			deadline = latest
		}
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		t.Fatal("shared work and cleanup deadline exhausted")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-h.done:
		if want == nil {
			if h.result != nil {
				t.Fatalf("Serve error = %v, want nil", h.result)
			}
		} else if !errors.Is(h.result, want) {
			t.Fatalf("Serve error = %v, want %v", h.result, want)
		}
	case <-timer.C:
		t.Fatalf("Serve did not return within shared test budget")
	}
	h.awaitClosed(t, deadline)
}

func (h *serveHarness) awaitClosed(t *testing.T, deadline time.Time) {
	t.Helper()
	counts, ok := h.l.(connectionCounter)
	if !ok {
		return
	}
	want, _ := counts.connectionCounts()
	for time.Now().Before(deadline) {
		got, closed := counts.connectionCounts()
		if closed >= got && got >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	got, closed := counts.connectionCounts()
	t.Fatalf("closed %d of %d accepted handlers before test deadline", closed, got)
}

func (h *serveHarness) awaitCleanup() {
	if !h.started {
		return
	}
	h.mu.Lock()
	deadline := h.cleanupDeadline
	h.mu.Unlock()
	if deadline.IsZero() {
		return
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-h.done:
	case <-timer.C:
		h.t.Errorf("Serve cleanup did not join within 3s")
		return
	}
	h.awaitClosed(h.t, deadline)
}

func waitAccepted(t *testing.T, l *acceptedListener, want int64, deadline time.Time) {
	t.Helper()
	for time.Now().Before(deadline) {
		if l.accepted.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("accepted %d connections, want at least %d before shared case deadline", l.accepted.Load(), want)
}

func waitServe(t *testing.T, h *serveHarness, want error) { h.await(t, want) }

func waitServeResult(t *testing.T, h *serveHarness, want error) {
	t.Helper()
	timer := time.NewTimer(time.Until(h.deadline))
	defer timer.Stop()
	select {
	case <-h.done:
		if !errors.Is(h.result, want) {
			t.Fatalf("Serve error = %v, want %v", h.result, want)
		}
	case <-timer.C:
		t.Fatal("Serve did not return before the shared work deadline")
	}
}

func (h *serveHarness) finish(t *testing.T, want error) {
	t.Helper()
	h.stop()
	h.await(t, want)
}

func (h *serveHarness) waitSignal(t *testing.T, ch <-chan struct{}, message string) {
	t.Helper()
	budget := h.remaining()
	if budget > 2*time.Second {
		budget = 2 * time.Second
	}
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
		t.Fatal(message)
	}
}

func TestServeBoundsAcceptedFramingAndAdmitsAfterRelease(t *testing.T) {
	l := listenAccepted(t)
	deps := &Deps{Auth: &stubAuth{}, Forward: &stubForward{called: make(chan struct{})}, Audit: &stubAudit{}}
	h := newServeHarness(t, l, deps)
	h.start()
	clients := make([]net.Conn, plannedFramingLimit+1)
	for i := range clients {
		clients[i] = h.dial(l.Addr())
	}
	waitAccepted(t, l, plannedFramingLimit, h.deadline)
	time.Sleep(100 * time.Millisecond)
	if got := l.accepted.Load(); got != plannedFramingLimit {
		t.Fatalf("accepted %d stalled framing connections with limit %d", got, plannedFramingLimit)
	}
	_ = clients[0].Close() // EOF before the first protocol byte releases one slot.
	waitAccepted(t, l, plannedFramingLimit+1, h.deadline)
	// Cancellation itself must release Serve's capacity wait. Keep the listener
	// and the remaining clients open until Serve returns so cleanup cannot be
	// the event that unblocks Accept or the permit wait.
	h.cancel()
	h.waitSignal(t, h.done, "Serve did not return after context cancellation while capacity was full")
	if h.result != nil {
		t.Fatalf("Serve error after capacity-wait cancellation = %v, want nil", h.result)
	}
	h.finish(t, nil)
}

type timeoutAcceptError struct{}

func (timeoutAcceptError) Error() string { return "accept timeout" }
func (timeoutAcceptError) Timeout() bool { return true }

type temporaryNonTimeoutAcceptError struct{}

func (temporaryNonTimeoutAcceptError) Error() string   { return "temporary accept resource pressure" }
func (temporaryNonTimeoutAcceptError) Temporary() bool { return true }
func (temporaryNonTimeoutAcceptError) Timeout() bool   { return false }

type scriptedListener struct {
	mu        sync.Mutex
	calls     int
	accepted  atomic.Int64
	closed    atomic.Int64
	steps     []func() (net.Conn, error)
	addr      net.Addr
	closedCh  chan struct{}
	closeOnce sync.Once
}

func newScriptedListener(steps ...func() (net.Conn, error)) *scriptedListener {
	return &scriptedListener{steps: steps, addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, closedCh: make(chan struct{})}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	if len(l.steps) == 0 {
		closed := l.closedCh
		l.mu.Unlock()
		<-closed
		return nil, net.ErrClosed
	}
	step := l.steps[0]
	l.steps = l.steps[1:]
	l.mu.Unlock()
	c, err := step()
	if err != nil {
		return nil, err
	}
	l.accepted.Add(1)
	return &trackedConn{Conn: c, onClose: func() { l.closed.Add(1) }}, nil
}
func (l *scriptedListener) Close() error   { l.closeOnce.Do(func() { close(l.closedCh) }); return nil }
func (l *scriptedListener) Addr() net.Addr { return l.addr }
func (l *scriptedListener) callCount() int { l.mu.Lock(); defer l.mu.Unlock(); return l.calls }
func (l *scriptedListener) connectionCounts() (int64, int64) {
	return l.accepted.Load(), l.closed.Load()
}

func TestServeDoesNotReleaseOnAuthUntilFullTargetArrives(t *testing.T) {
	l := listenAccepted(t)
	auth := &stubAuth{accept: true}
	forward := &stubForward{called: make(chan struct{})}
	h := newServeHarness(t, l, &Deps{Auth: auth, Forward: forward, Audit: &stubAudit{}})
	h.start()
	clients := make([]net.Conn, plannedFramingLimit+1)
	for i := range clients {
		clients[i] = h.dial(l.Addr())
	}
	waitAccepted(t, l, plannedFramingLimit, h.deadline)
	for i := 0; i < plannedFramingLimit; i++ {
		h.refresh(clients[i])
		if _, err := clients[i].Write([]byte{0x05, 0x01, 0x02}); err != nil {
			t.Fatalf("greeting write %d: %v", i, err)
		}
		var method [2]byte
		if _, err := io.ReadFull(clients[i], method[:]); err != nil || method != [2]byte{0x05, 0x02} {
			t.Fatalf("greeting reply %d = %x, %v", i, method, err)
		}
		if _, err := clients[i].Write([]byte{0x01, 0x01, 'u', 0x01, 'p'}); err != nil {
			t.Fatalf("auth write %d: %v", i, err)
		}
		var authReply [2]byte
		if _, err := io.ReadFull(clients[i], authReply[:]); err != nil || authReply != [2]byte{0x01, 0x00} {
			t.Fatalf("auth reply %d = %x, %v", i, authReply, err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if got := l.accepted.Load(); got != plannedFramingLimit {
		t.Fatalf("accepted %d before target framing, want %d", got, plannedFramingLimit)
	}
	h.refresh(clients[0])
	if _, err := clients[0].Write([]byte{0x05, 0x01, 0x00, 0x03, 0x01, 'x', 0x00, 0x50}); err != nil {
		t.Fatalf("target request write: %v", err)
	}
	waitAccepted(t, l, plannedFramingLimit+1, h.deadline)
	h.waitSignal(t, forward.called, "fully framed request did not reach Forward")
	if got := auth.count(); got != plannedFramingLimit {
		t.Fatalf("auth calls = %d, want %d", got, plannedFramingLimit)
	}
	h.finish(t, nil)
}

type mutableVerifier struct {
	mu     sync.Mutex
	accept bool
}

func (v *mutableVerifier) set(accept bool) { v.mu.Lock(); v.accept = accept; v.mu.Unlock() }
func (v *mutableVerifier) VerifyPassword([]byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.accept
}

func clientAuth(t *testing.T, h *serveHarness, c net.Conn, accept bool) {
	t.Helper()
	h.refresh(c)
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("greeting write: %v", err)
	}
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil || method != [2]byte{0x05, 0x02} {
		t.Fatalf("method reply = %x, %v", method, err)
	}
	if _, err := c.Write([]byte{0x01, 0x01, 'u', 0x01, 'p'}); err != nil {
		t.Fatalf("auth write: %v", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("auth reply: %v", err)
	}
	want := [2]byte{0x01, 0xff}
	if accept {
		want[1] = 0x00
	}
	if reply != want {
		t.Fatalf("auth reply = %x, want %x", reply, want)
	}
}

func expectClientEOF(t *testing.T, c net.Conn, what string) {
	t.Helper()
	var b [1]byte
	if _, err := c.Read(b[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("%s close error = %v, want EOF", what, err)
	}
}

func TestExpectClientEOFHandlesAlreadyClosedPeer(t *testing.T) {
	client, peer := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}
	if err := peer.Close(); err != nil {
		t.Fatalf("close peer: %v", err)
	}
	expectClientEOF(t, client, "already-closed peer")
}

func TestServeReleasesPermitOnProtocolExitPaths(t *testing.T) {
	l := listenAccepted(t)
	verifier := &mutableVerifier{}
	h := newServeHarness(t, l, &Deps{Auth: verifier, Forward: &stubForward{called: make(chan struct{})}, Audit: &stubAudit{}})
	h.start()
	clients := make([]net.Conn, plannedFramingLimit+6)
	for i := range clients {
		clients[i] = h.dial(l.Addr())
	}
	waitAccepted(t, l, plannedFramingLimit, h.deadline)
	_ = clients[0].Close()
	waitAccepted(t, l, plannedFramingLimit+1, h.deadline)
	h.refresh(clients[1])
	if _, err := clients[1].Write([]byte{'G'}); err != nil {
		t.Fatalf("invalid protocol write: %v", err)
	}
	expectClientEOF(t, clients[1], "invalid first byte")
	waitAccepted(t, l, plannedFramingLimit+2, h.deadline)
	h.refresh(clients[2])
	if _, err := clients[2].Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("no-method write: %v", err)
	}
	var noMethod [2]byte
	if _, err := io.ReadFull(clients[2], noMethod[:]); err != nil || noMethod != [2]byte{0x05, 0xff} {
		t.Fatalf("no-method reply = %x, %v", noMethod, err)
	}
	expectClientEOF(t, clients[2], "no acceptable method")
	waitAccepted(t, l, plannedFramingLimit+3, h.deadline)
	verifier.set(false)
	clientAuth(t, h, clients[3], false)
	expectClientEOF(t, clients[3], "authentication rejection")
	waitAccepted(t, l, plannedFramingLimit+4, h.deadline)
	verifier.set(true)
	clientAuth(t, h, clients[4], true)
	h.refresh(clients[4])
	if _, err := clients[4].Write([]byte{0x05, 0x02, 0x00, 0x03, 0x01, 'x', 0x00, 0x50}); err != nil {
		t.Fatalf("unsupported command request: %v", err)
	}
	wantFailure := []byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	gotFailure := make([]byte, len(wantFailure))
	if _, err := io.ReadFull(clients[4], gotFailure); err != nil || string(gotFailure) != string(wantFailure) {
		t.Fatalf("unsupported-command reply = %x, %v", gotFailure, err)
	}
	expectClientEOF(t, clients[4], "unsupported command")
	waitAccepted(t, l, plannedFramingLimit+5, h.deadline)
	clientAuth(t, h, clients[5], true)
	h.refresh(clients[5])
	if _, err := clients[5].Write([]byte{0x05, 0x01}); err != nil {
		t.Fatalf("partial request write: %v", err)
	}
	_ = clients[5].Close()
	waitAccepted(t, l, plannedFramingLimit+6, h.deadline)
	h.finish(t, nil)
}
func TestServeRetriesAcceptTimeoutsBeforeTerminalError(t *testing.T) {
	client, server := net.Pipe()
	terminal := errors.New("permanent accept failure")
	l := newScriptedListener(
		func() (net.Conn, error) { return nil, timeoutAcceptError{} },
		func() (net.Conn, error) { return nil, timeoutAcceptError{} },
		func() (net.Conn, error) { return nil, timeoutAcceptError{} },
		func() (net.Conn, error) { return server, nil },
		func() (net.Conn, error) { return nil, terminal },
	)
	h := newServeHarness(t, l, &Deps{Auth: &stubAuth{}, Forward: &stubForward{called: make(chan struct{})}, Audit: &stubAudit{}})
	h.own(client)
	h.own(server)
	h.start()
	h.waitSignal(t, h.done, "Serve did not reach terminal Accept error")
	if !errors.Is(h.result, terminal) {
		t.Fatalf("Serve error after temporary Accept failures = %v, want terminal %v", h.result, terminal)
	}
	h.refresh(client)
	if _, err := client.Write([]byte{'G'}); err != nil {
		t.Fatalf("write test request: %v", err)
	}
	expectClientEOF(t, client, "actual HandleConn after temporary errors")
	waitServe(t, h, terminal)
	if got := l.callCount(); got != 5 {
		t.Fatalf("Accept calls = %d, want 5 including 3 temporary and terminal errors", got)
	}
}

func TestServeRetriesNonTimeoutTemporaryAcceptErrorsBeforeTerminalError(t *testing.T) {
	client, server := net.Pipe()
	terminal := errors.New("permanent accept failure")
	temporary := fmt.Errorf("wrapped accept: %w", temporaryNonTimeoutAcceptError{})
	l := newScriptedListener(
		func() (net.Conn, error) { return nil, temporary },
		func() (net.Conn, error) { return nil, temporary },
		func() (net.Conn, error) { return nil, temporary },
		func() (net.Conn, error) { return server, nil },
		func() (net.Conn, error) { return nil, terminal },
	)
	h := newServeHarness(t, l, &Deps{Auth: &stubAuth{}, Forward: &stubForward{called: make(chan struct{})}, Audit: &stubAudit{}})
	h.own(client)
	h.own(server)
	h.start()
	h.waitSignal(t, h.done, "Serve did not recover from temporary resource pressure and reach the terminal Accept error")
	if !errors.Is(h.result, terminal) {
		t.Fatalf("Serve error after temporary Accept failures = %v, want terminal %v", h.result, terminal)
	}
	h.refresh(client)
	if _, err := client.Write([]byte{'G'}); err != nil {
		t.Fatalf("write test request: %v", err)
	}
	expectClientEOF(t, client, "actual HandleConn after non-timeout temporary errors")
	waitServe(t, h, terminal)
	if got := l.callCount(); got != 5 {
		t.Fatalf("Accept calls = %d, want 5 including 3 non-timeout temporary and terminal errors", got)
	}
}

func TestServeTemporaryAcceptBackoffStopsOnCancellation(t *testing.T) {
	l := &alwaysTemporaryListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}}
	h := newServeHarness(t, l, &Deps{Auth: &stubAuth{}, Forward: &stubForward{called: make(chan struct{})}, Audit: &stubAudit{}})
	h.start()
	delay := 100 * time.Millisecond
	if left := h.remaining(); delay > left {
		delay = left
	}
	time.Sleep(delay)
	h.finish(t, nil)
	if got := l.callCount(); got >= 20 {
		t.Fatalf("temporary Accept retried %d times in 100ms; want <20", got)
	}
}

type alwaysTemporaryListener struct {
	mu    sync.Mutex
	calls int
	addr  net.Addr
}

func (l *alwaysTemporaryListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	l.mu.Unlock()
	return nil, temporaryNonTimeoutAcceptError{}
}
func (l *alwaysTemporaryListener) Close() error   { return nil }
func (l *alwaysTemporaryListener) Addr() net.Addr { return l.addr }
func (l *alwaysTemporaryListener) callCount() int { l.mu.Lock(); defer l.mu.Unlock(); return l.calls }

type barrierForward struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	count   atomic.Int64
}

func (f *barrierForward) unblock() { f.once.Do(func() { close(f.release) }) }

func (f *barrierForward) Forward(_ net.Conn, _ []byte, _ string) error {
	f.count.Add(1)
	f.entered <- struct{}{}
	<-f.release
	return nil
}

func sendValidRequest(t *testing.T, h *serveHarness, c net.Conn) {
	t.Helper()
	h.refresh(c)
	if _, err := c.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("greeting write: %v", err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if greeting != [2]byte{0x05, 0x02} {
		t.Fatalf("greeting reply = %x, want 0502", greeting)
	}
	if _, err := c.Write([]byte{0x01, 0x01, 'u', 0x01, 'p'}); err != nil {
		t.Fatalf("auth write: %v", err)
	}
	var authReply [2]byte
	if _, err := io.ReadFull(c, authReply[:]); err != nil {
		t.Fatalf("auth reply: %v", err)
	}
	if authReply != [2]byte{0x01, 0x00} {
		t.Fatalf("auth reply = %x, want 0100", authReply)
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00, 0x03, 0x01, 'x', 0x00, 0x50}); err != nil {
		t.Fatalf("request write: %v", err)
	}
}

func TestServeReleasesFramingPermitBeforeForwarding(t *testing.T) {
	l := listenAccepted(t)
	const forwarding = 32
	fwd := &barrierForward{entered: make(chan struct{}, forwarding), release: make(chan struct{})}
	audit := &stubAudit{}
	h := newServeHarness(t, l, &Deps{Auth: &stubAuth{accept: true}, Forward: fwd, Audit: audit})
	h.onStop(fwd.unblock)
	h.start()
	sendDone := make(chan struct{}, forwarding)
	for i := 0; i < forwarding; i++ {
		c := h.dial(l.Addr())
		go func(conn net.Conn) { defer func() { sendDone <- struct{}{} }(); sendValidRequest(t, h, conn) }(c)
	}
	for i := 0; i < forwarding; i++ {
		h.waitSignal(t, fwd.entered, "valid request did not reach Forward")
	}
	for i := 0; i < forwarding; i++ {
		h.waitSignal(t, sendDone, "request writer did not finish")
	}
	if got := audit.count(); got != forwarding {
		t.Fatalf("auth-pass count = %d while Forward held, want %d", got, forwarding)
	}
	for i := 0; i < plannedFramingLimit; i++ {
		h.dial(l.Addr())
	}
	waitAccepted(t, l, forwarding+plannedFramingLimit, h.deadline)
	if got := fwd.count.Load(); got != forwarding {
		t.Fatalf("Forward calls = %d while barrier held, want %d", got, forwarding)
	}
	h.finish(t, nil)
}

type controlledTimeout struct{}

func (controlledTimeout) Error() string { return "controlled framing timeout" }
func (controlledTimeout) Timeout() bool { return true }

type deadlineFailConn struct {
	net.Conn
	gate <-chan struct{}
}

func (c *deadlineFailConn) Read([]byte) (int, error) { <-c.gate; return 0, controlledTimeout{} }

func TestServeReleasesPermitWhenFramingReadTimesOut(t *testing.T) {
	const blocked = plannedFramingLimit - 1
	clients := make([]net.Conn, 0, blocked+2)
	steps := make([]func() (net.Conn, error), 0, plannedFramingLimit+2)
	for i := 0; i < blocked; i++ {
		client, server := net.Pipe()
		clients = append(clients, client, server)
		steps = append(steps, func() (net.Conn, error) { return server, nil })
	}
	gate := make(chan struct{})
	var gateOnce sync.Once
	unblock := func() { gateOnce.Do(func() { close(gate) }) }
	timeoutClient, timeoutServer := net.Pipe()
	clients = append(clients, timeoutClient, timeoutServer)
	steps = append(steps, func() (net.Conn, error) { return &deadlineFailConn{Conn: timeoutServer, gate: gate}, nil })
	sentinelClient, sentinelServer := net.Pipe()
	clients = append(clients, sentinelClient, sentinelServer)
	terminal := errors.New("end of controlled listener")
	steps = append(steps, func() (net.Conn, error) { return sentinelServer, nil }, func() (net.Conn, error) { return nil, terminal })
	l := newScriptedListener(steps...)
	h := newServeHarness(t, l, &Deps{Auth: &stubAuth{}, Forward: &stubForward{called: make(chan struct{})}, Audit: &stubAudit{}})
	for _, c := range clients {
		h.own(c)
	}
	h.onStop(unblock)
	h.start()
	for l.callCount() < plannedFramingLimit && time.Now().Before(h.deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := l.callCount(); got != plannedFramingLimit {
		t.Fatalf("Accept calls before timeout release = %d, want %d", got, plannedFramingLimit)
	}
	unblock()
	h.refresh(sentinelClient)
	if _, err := sentinelClient.Write([]byte{'G'}); err != nil {
		t.Fatalf("sentinel request write: %v", err)
	}
	expectClientEOF(t, sentinelClient, "request after timeout permit release")
	// Peer EOF alone does not prove that handleConn has returned, released
	// its permit, and let Serve process the scripted terminal Accept error.
	// Wait for Serve's bounded result before asserting the final call count;
	// canceling first could suppress that error and make this test schedule-dependent.
	waitServeResult(t, h, terminal)
	if got := l.callCount(); got != plannedFramingLimit+2 {
		t.Fatalf("Accept calls = %d, want timeout release then terminal error", got)
	}
	h.finish(t, terminal)
}
func TestServePermanentAcceptErrorIsReturned(t *testing.T) {
	want := errors.New("listener failed permanently")
	l := newScriptedListener(func() (net.Conn, error) { return nil, want })
	h := newServeHarness(t, l, &Deps{Auth: &stubAuth{}, Forward: &stubForward{called: make(chan struct{})}, Audit: &stubAudit{}})
	h.start()
	waitServe(t, h, want)
	if got := l.callCount(); got != 1 {
		t.Fatalf("Accept calls = %d, want 1", got)
	}
}
