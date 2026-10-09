//go:build docker && linux
// +build docker,linux

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	tor "github.com/zcat-app/stargate/tests/contract/tor"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

const (
	t070aOverallWait = 30 * time.Minute
	t070aCircuitWait = 15 * time.Second
	t070aSocketWait  = 10 * time.Second
	t070aCaptureMax  = 1 << 20
	t070aPollEvery   = time.Second
)

// TestT070aCircuitDropMidstream is a release-tag live acceptance test. The
// deterministic forward package test owns exact byte equality; this lane
// establishes a calibrated in-flight TLS stream, kills its attributed circuit,
// and observes the bounded Tor/client close surfaces.
func TestT070aCircuitDropMidstream(t *testing.T) {
	if os.Getenv("STARGATE_RUN_NETWORK_TESTS") != "1" {
		t.Skip("STARGATE_RUN_NETWORK_TESTS != 1 — release-tag test; set to opt in")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("T070a requires the Docker CLI: %v", err)
	}
	checkCtx, checkCancel := context.WithTimeout(context.Background(), t070ExecWait)
	_, daemonErr := t070Run(checkCtx, t070ExecWait, "docker", "info")
	checkCancel()
	if daemonErr != nil {
		t.Fatalf("T070a requires a reachable Docker daemon: %v", daemonErr)
	}

	repoRoot := t131FindRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	example := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, path := range []string{composeFile, example} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("required Local stack input unavailable: %v", err)
		}
	}
	project, err := t070ProjectName()
	if err != nil {
		t.Fatalf("create isolated Compose project name: %v", err)
	}
	envDir := t.TempDir()
	envFile := filepath.Join(envDir, "local.env")
	seed, err := os.ReadFile(example)
	if err != nil {
		t.Fatalf("read Local profile environment template: %v", err)
	}
	if err := os.WriteFile(envFile, seed, 0o600); err != nil {
		t.Fatalf("create private Local profile environment: %v", err)
	}
	markerPath := os.Getenv("STARGATE_T070_UNSAFE_MARKER")
	if markerPath != "/tmp/stargate-t070a-live.unsafe" {
		t.Fatalf("T070a host runner did not provide its separate unsafe marker")
	}

	ctx, cancel := context.WithTimeout(context.Background(), t070aOverallWait)
	var capture *t070LiveCapture
	var captureMu sync.Mutex
	var projectOwned bool
	var projectMu sync.Mutex
	var unsafeMarker string
	var markerMu sync.Mutex
	buildxConfig := &t070BuildxConfig{}
	initProcess := &t070InitStartGate{}
	var cleanupOnce sync.Once
	initShutdown := func() bool { return initProcess.shutdown(5*time.Second, 10*time.Second, 5*time.Second) }
	cleanup := func(report bool) {
		cleanupOnce.Do(func() {
			if !initShutdown() {
				if report {
					t.Errorf("T070a init process group remains; leave marker and project resources for inspection")
				}
				return
			}
			if err := buildxConfig.removeAfterProcessStop(true); err != nil {
				if report {
					t.Errorf("private Buildx config cleanup failed after init stopped: %v", err)
				}
				return
			}
			captureMu.Lock()
			activeCapture := capture
			captureMu.Unlock()
			if activeCapture != nil {
				activeCapture.stop()
			}
			projectMu.Lock()
			ownsProject := projectOwned
			projectMu.Unlock()
			if !ownsProject {
				return
			}
			dCtx, dCancel := context.WithTimeout(context.Background(), t070CleanupWait)
			defer dCancel()
			if out, downErr := t070Compose(dCtx, project, composeFile, envFile, "down", "--volumes", "--remove-orphans"); downErr != nil {
				if report {
					t.Errorf("project-scoped T070a Compose cleanup failed (output length %d): %v", len(out), downErr)
				}
				return
			}
			remaining, listErr := t070ProjectResources(dCtx, project)
			if listErr != nil || len(remaining) != 0 {
				if report {
					t.Errorf("T070a cleanup left project resources or could not inspect them (count=%d error=%v)", len(remaining), listErr)
				}
				return
			}
			markerMu.Lock()
			marker := unsafeMarker
			markerMu.Unlock()
			if marker != "" {
				if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
					if report {
						t.Errorf("T070a project is empty but unsafe marker removal failed: %v", err)
					}
					return
				}
			}
		})
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			cancel()
			cleanup(false)
			os.Exit(1)
		case <-ctx.Done():
		}
	}()
	t.Cleanup(func() {
		signal.Stop(sigCh)
		cancel()
		cleanup(true)
	})

	if resources, err := t070ProjectResources(ctx, project); err != nil || len(resources) != 0 {
		t.Fatalf("fresh T070a project already owns resources (count=%d error=%v)", len(resources), err)
	}
	projectMu.Lock()
	projectOwned = true
	projectMu.Unlock()
	services, err := t070Compose(ctx, project, composeFile, envFile, "config", "--services")
	if err != nil || !t070SameStrings(strings.Fields(string(services)), t070ExpectedServices) {
		t.Fatalf("Local Compose service inventory differs from the T070 reviewed set (error=%v)", err)
	}
	buildxDir, err := buildxConfig.prepare(os.Getenv("STARGATE_T070_BUILDX_PLUGIN"), t070BuildxSHA256)
	if err != nil {
		t.Fatalf("prepare isolated Buildx plugin config: %v", err)
	}
	marker, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("T070a unsafe marker is stale or could not be created: %v", err)
	}
	markerMu.Lock()
	unsafeMarker = markerPath
	markerMu.Unlock()
	if _, err := fmt.Fprintf(marker, "starting project=%s\n", project); err != nil {
		_ = marker.Close()
		t.Fatalf("write T070a unsafe marker: %v", err)
	}
	if err := marker.Sync(); err != nil {
		_ = marker.Close()
		t.Fatalf("sync T070a unsafe marker: %v", err)
	}
	if err := marker.Close(); err != nil {
		t.Fatalf("close T070a unsafe marker: %v", err)
	}
	initCtx, initCancel := context.WithTimeout(ctx, t070InitWait)
	initArgs := t070InitCommandArgs(repoRoot)
	initCmd := exec.Command(initArgs[0], initArgs[1:]...)
	initCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	initCmd.WaitDelay = 2 * time.Second
	shimDir, buildOverride, overrideMarker, realDocker, err := t070InstallDockerShim(t, project, composeFile, envFile)
	if err != nil {
		initCancel()
		t.Fatalf("prepare private Compose build override: %v", err)
	}
	initCmd.Env = t070InitEnvironment(os.Environ(), buildxDir)
	initCmd.Env = append(initCmd.Env,
		"PATH="+shimDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STARGATE_PROJECT="+project,
		"STARGATE_COMPOSE_FILE="+composeFile,
		"STARGATE_ENV_DIR="+envDir,
		"STARGATE_ENV_FILE="+envFile,
		"T070_REAL_DOCKER="+realDocker,
		"T070_COMPOSE_BUILD_OVERRIDE="+buildOverride,
		"T070_COMPOSE_OVERRIDE_MARKER="+overrideMarker,
		"STARGATE_HEALTHCHECK_TIMEOUT=600")
	initOutput := &t070BoundedOutput{limit: 8 << 20}
	initCmd.Stdout, initCmd.Stderr = initOutput, initOutput
	if !initProcess.beginStart() {
		initCancel()
		t.Fatal("T070a init launch was canceled by cleanup")
	}
	if err := initCmd.Start(); err != nil {
		initProcess.finishStart(0, nil)
		initCancel()
		t.Fatalf("start scripts/stargate init process group: %v", err)
	}
	waitDone := make(chan struct{})
	initProcess.finishStart(initCmd.Process.Pid, waitDone)
	initResult := make(chan error, 1)
	var initErr error
	go func() {
		initResult <- initCmd.Wait()
		close(waitDone)
	}()
	if err := os.WriteFile(markerPath, []byte(fmt.Sprintf("project=%s pgid=%d\n", project, initCmd.Process.Pid)), 0o600); err != nil {
		initCancel()
		t.Fatalf("record T070a init process group: %v", err)
	}
	select {
	case <-waitDone:
		initErr = <-initResult
	case <-initCtx.Done():
		initErr = initCtx.Err()
	}
	if !initShutdown() {
		initCancel()
		t.Fatal("T070a init process group remains after bounded TERM/KILL; unsafe marker retained")
	}
	initCancel()
	if initErr != nil || initOutput.overflowed() {
		t.Fatalf("scripts/stargate init did not complete (error=%v output_overflow=%t safe_init=%s)", initErr, initOutput.overflowed(), strings.Join(t070InitFailureNotes(initOutput.bytes()), ","))
	}
	if marker, err := os.ReadFile(overrideMarker); err != nil || string(marker) != "applied\n" {
		t.Fatalf("T070a init missed the exact-project Tor build override (error=%v)", err)
	}
	if err := t070AssertProjectServices(ctx, project); err != nil {
		t.Fatalf("post-init project inventory differs from the isolated Local stack: %v", err)
	}

	token, err := t059NewToken()
	if err != nil {
		t.Fatalf("generate test bearer token: %v", err)
	}
	if err := t070SeedToken(ctx, project, token); err != nil {
		t.Fatalf("seed private token into T070a control-config volume: %v", err)
	}
	if out, err := t070Compose(ctx, project, composeFile, envFile, "restart", "stargate-control"); err != nil {
		t.Fatalf("restart only control plane to load token (output length %d): %v", len(out), err)
	}
	dpID, err := t070RunningServiceID(ctx, project, composeFile, envFile, "stargate-dp")
	if err != nil {
		t.Fatalf("resolve running T070a data-plane container: %v", err)
	}
	logging, err := t070Run(ctx, t070ExecWait, "docker", "inspect", "--format", `{{.HostConfig.LogConfig.Type}}`, dpID)
	if err != nil || strings.TrimSpace(string(logging)) != "none" {
		t.Fatalf("Local data-plane Docker LogConfig.Type is not none (inspect error=%v)", err)
	}
	newCapture := t070StartLiveCapture(ctx, t, dpID)
	captureMu.Lock()
	if ctx.Err() != nil {
		captureMu.Unlock()
		newCapture.stop()
		t.Fatalf("T070a live output capture started after cleanup cancellation")
	}
	capture = newCapture
	captureMu.Unlock()
	t.Cleanup(func() { newCapture.stop() })
	if err := t070PositiveControl(ctx, token); err != nil {
		t.Fatalf("bounded authenticated SOCKS positive control failed before T070a probe: %v", err)
	}
	capture.requireAlive(t, "after the authenticated SOCKS positive control")

	t070aRunCircuitProbe(t, ctx, project, composeFile, envFile, token, capture)
}

func t070aRunCircuitProbe(t *testing.T, ctx context.Context, project, composeFile, envFile, token string, capture *t070LiveCapture) {
	t.Helper()
	cfg := tor.ControlPortConfig{Project: project, ComposeFile: composeFile, EnvFile: envFile}

	profile := "t070a-" + strings.TrimPrefix(project, t070ProjectPrefix)
	username := t126PartitionUsername(token, profile, t070ReferenceOnion)
	if !strings.HasPrefix(username, "sg1:") || len(username) > 255 {
		t.Fatalf("generated partition username has invalid RFC 1929 bounds (length %d)", len(username))
	}
	if username == t131PartitionUsername(token, t070ReferenceOnion) {
		t.Fatal("T070 readiness positive-control username collided with the tested full-profile partition")
	}
	conn, err := t070aSOCKSConnect(ctx, username, token, t070ReferenceOnion, t070ReferencePort)
	if err != nil {
		t.Fatalf("authenticated SOCKS5 CONNECT to pinned onion failed: %v", err)
	}
	defer conn.Close()
	tee := &t070aCaptureConn{Conn: conn, limit: t070aCaptureMax}
	tlsConn := tls.Client(tee, &tls.Config{
		ServerName:         t070ReferenceOnion,
		InsecureSkipVerify: true, // test only: TLS is a transport probe, not a trust decision
	})
	if err := tlsConn.SetDeadline(time.Now().Add(t070aCircuitWait)); err != nil {
		t.Fatalf("set TLS handshake deadline: %v", err)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake to pinned onion failed: %v", err)
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear TLS handshake deadline: %v", err)
	}
	if err := tlsConn.SetWriteDeadline(time.Now().Add(t070aSocketWait)); err != nil {
		t.Fatalf("set incomplete-request write deadline: %v", err)
	}
	partial := []byte("GET / HTTP/1.1\r\nHost: " + t070ReferenceOnion + "\r\nX-Stargate-T070a-Pending: ")
	if _, err := tlsConn.Write(partial); err != nil {
		t.Fatalf("write deliberately incomplete HTTP request headers: %v", err)
	}
	if _, err := tlsConn.Write([]byte("still-waiting")); err != nil {
		t.Fatalf("client TLS tunnel stopped accepting writes before circuit close: %v", err)
	}
	if err := tlsConn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear incomplete-request write deadline: %v", err)
	}
	target := fmt.Sprintf("%s:%d", t070ReferenceOnion, t070ReferencePort)
	streamID, circuitID, err := t070aWaitAttributedStream(ctx, cfg, target, username)
	if err != nil {
		t.Fatalf("calibrate exact live stream/circuit attribution: %v", err)
	}

	readCh := make(chan t070aReadResult, 1)
	go func() {
		var b [1]byte
		n, err := tlsConn.Read(b[:])
		readCh <- t070aReadResult{n: n, err: err, completed: time.Now()}
	}()
	select {
	case r := <-readCh:
		t.Fatalf("calibration failed: pending TLS read completed before circuit kill (n=%d err=%v)", r.n, r.err)
	case <-time.After(500 * time.Millisecond):
	}
	capture.requireAlive(t, "before exact circuit close")

	closeControl, cancelCloseControl, err := t070aPrepareControl(ctx, cfg, time.Now().Add(t070aCircuitWait))
	if err != nil {
		t.Fatalf("prepare authenticated control session for exact circuit close: %v", err)
	}
	defer func() {
		_ = closeControl.Close()
		cancelCloseControl()
	}()
	snapshotDeadline := time.Now().Add(t070aCircuitWait)
	circuitsBeforeClose, built, err := t070aUsernameCircuitSnapshot(ctx, closeControl, username, circuitID, snapshotDeadline)
	if err != nil || !built {
		t.Fatalf("exact circuit was not still BUILT with the complete username in the immediate pre-close snapshot (error=%v)", err)
	}
	select {
	case r := <-readCh:
		t.Fatalf("calibration failed: TLS read completed during the fresh pre-close circuit snapshot (n=%d err=%v)", r.n, r.err)
	default:
	}
	closeDeadline := time.Now().Add(t070aCircuitWait)
	dispatchCh := make(chan time.Time, 1)
	_, err = t070aControlSessionCommand(ctx, closeControl, closeDeadline, "CLOSECIRCUIT "+circuitID, false, func(dispatchedAt time.Time) error {
		if err := tlsConn.SetReadDeadline(dispatchedAt.Add(t070aCircuitWait)); err != nil {
			return err
		}
		dispatchCh <- dispatchedAt
		return nil
	})
	if err != nil {
		t.Fatalf("CLOSECIRCUIT exact attributed circuit failed: %v", err)
	}
	var closeDispatchedAt time.Time
	select {
	case closeDispatchedAt = <-dispatchCh:
	default:
		t.Fatal("CLOSECIRCUIT command completed without its dispatch marker")
	}
	var postKill t070aReadResult
	select {
	case postKill = <-readCh:
	case <-time.After(t070aCircuitWait + time.Second):
		t.Fatal("TLS read did not unblock after its Tor circuit was closed")
	}
	if t070aReadPredatesClose(postKill, closeDispatchedAt) {
		t.Fatalf("TLS read completed before CLOSECIRCUIT dispatch (n=%d err=%v)", postKill.n, postKill.err)
	}
	if postKill.n != 0 || !t070aIsTransportCloseError(postKill.err) {
		t.Fatalf("post-kill TLS read returned n=%d err=%v; want a non-timeout transport close with no plaintext", postKill.n, postKill.err)
	}

	// TLS may buffer ciphertext internally. Drain the underlying TCP socket
	// only after its TLS reader has stopped, and before test cleanup can close it.
	if err := conn.SetReadDeadline(time.Now().Add(t070aSocketWait)); err != nil {
		t.Fatalf("set raw client drain deadline: %v", err)
	}
	_, drainErr := io.Copy(io.Discard, tee)
	if !t070aIsCloseError(drainErr) {
		t.Fatalf("underlying client TCP socket did not drain to EOF/RST: %v", drainErr)
	}
	if tee.overflowed() {
		t.Fatal("bounded TLS tunnel capture overflowed")
	}
	if err := t070aAssertStreamClosed(ctx, closeControl, streamID, circuitID); err != nil {
		t.Fatalf("Tor stream-status after raw EOF/RST did not show termination: %v", err)
	}
	if err := t070aNoReplacementCircuit(ctx, username, circuitsBeforeClose, 10*time.Second, func(deadline time.Time) ([]string, error) {
		return t070aControlSessionCommand(ctx, closeControl, deadline, "GETINFO circuit-status", false, nil)
	}); err != nil {
		t.Fatalf("bounded Tor circuit-status retry observation failed: %v", err)
	}
	if err := closeControl.Close(); err != nil {
		t.Fatalf("close Tor control session after bounded retry observation: %v", err)
	}
	cancelCloseControl()
	capture.requireAlive(t, "through circuit close and bounded retry observation")
	diagnostics := capture.stopAndBytes(t)
	loginvariants.AssertOnlyAllowedLines(t, diagnostics)
	loginvariants.AssertNoSecrets(t, diagnostics, []byte(token), []byte(username), []byte(t070ReferenceOnion))
	if diagnostics != "" {
		t.Fatalf("data-plane attached output was not empty (captured bytes=%d)", len(diagnostics))
	}
	if err := t070AssertProjectServices(ctx, project); err != nil {
		t.Fatalf("project service set changed during T070a: %v", err)
	}
	t.Logf("T070a observed exact stream %s on its BUILT partition circuit close; TLS ciphertext bytes captured=%d (opaque)", streamID, tee.count())
}

func t070aSOCKSConnect(ctx context.Context, username, token, host string, port uint16) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, t070ControlWait)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: t070SocketWait}).DialContext(dialCtx, "tcp", "127.0.0.1:8881")
	if err != nil {
		return nil, err
	}
	deadline, ok := dialCtx.Deadline()
	if !ok {
		deadline = time.Now().Add(t070ControlWait)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { _ = conn.Close(); return nil, err }
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return fail(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil || method != [2]byte{0x05, 0x02} {
		return fail(errors.New("SOCKS5 username/password method was not selected"))
	}
	if len(username) == 0 || len(username) > 255 || len(token) == 0 || len(token) > 255 || len(host) > 255 {
		return fail(errors.New("SOCKS5 test field exceeds its protocol bound"))
	}
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(token)))
	auth = append(auth, token...)
	if _, err := conn.Write(auth); err != nil {
		return fail(err)
	}
	var authReply [2]byte
	if _, err := io.ReadFull(conn, authReply[:]); err != nil || authReply != [2]byte{0x01, 0x00} {
		return fail(errors.New("SOCKS5 bearer authentication was not accepted"))
	}
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, host...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}
	reply, err := t070ReadSOCKSReply(conn)
	if err != nil || len(reply) < 2 || reply[0] != 0x05 || reply[1] != 0x00 {
		return fail(errors.New("live authenticated SOCKS CONNECT did not succeed"))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	return conn, nil
}

type t070aCaptureConn struct {
	net.Conn
	mu       sync.Mutex
	limit    int
	read     []byte
	written  []byte
	overflow bool
}

type t070aReadResult struct {
	n         int
	err       error
	completed time.Time
}

func (c *t070aCaptureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.record(&c.read, p[:n])
	}
	return n, err
}

func (c *t070aCaptureConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.record(&c.written, p[:n])
	}
	return n, err
}

func (c *t070aCaptureConn) record(dst *[]byte, p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	remaining := c.limit - len(c.read) - len(c.written)
	if len(p) > remaining {
		c.overflow = true
		p = p[:max(remaining, 0)]
	}
	*dst = append(*dst, p...)
}

func (c *t070aCaptureConn) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.read) + len(c.written)
}

func (c *t070aCaptureConn) overflowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overflow
}

func t070aIsCloseError(err error) bool {
	return err == nil || t070aIsTransportCloseError(err)
}

func t070aIsTransportCloseError(err error) bool {
	if err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED)
}

func t070aReadPredatesClose(result t070aReadResult, dispatchedAt time.Time) bool {
	return !result.completed.IsZero() && !result.completed.After(dispatchedAt)
}

func t070aWithinDeadline[T any](ctx context.Context, deadline time.Time, operation func(context.Context) (T, error)) (T, error) {
	var zero T
	if !time.Now().Before(deadline) {
		return zero, context.DeadlineExceeded
	}
	opCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// Run in the owner goroutine so callers never race Close against a control
	// operation. ControlPort cancellation joins process teardown for up to
	// 5.25s; that bounded cleanup can delay return, but any result completed at
	// or after the phase deadline is still a failure.
	value, err := operation(opCtx)
	if ctx.Err() != nil {
		return zero, ctx.Err()
	}
	if !time.Now().Before(deadline) {
		return zero, context.DeadlineExceeded
	}
	return value, err
}

func t070aPrepareControl(ctx context.Context, cfg tor.ControlPortConfig, deadline time.Time) (*tor.ControlPort, context.CancelFunc, error) {
	cookie, err := t070aWithinDeadline(ctx, deadline, func(opCtx context.Context) ([]byte, error) {
		cookie, err := tor.ReadCookie(opCtx, cfg)
		if err != nil {
			return nil, errors.New("read Tor control cookie failed")
		}
		return cookie, nil
	})
	if err != nil {
		return nil, nil, errors.New("read Tor control cookie within preparation deadline failed")
	}
	// This one authenticated session carries the pre-close snapshot, close,
	// post-close status and 10-second observation queries. Its lifetime covers
	// those sequential phase caps plus teardown slack; each command still gets
	// its own shorter phase deadline.
	sessionCtx, cancelSession := context.WithDeadline(ctx, deadline.Add(6*t070aCircuitWait+t070aSocketWait+t070aPollEvery))
	control, err := tor.Connect(sessionCtx, cfg)
	if err != nil {
		cancelSession()
		return nil, nil, errors.New("connect Tor control socket failed")
	}
	if !time.Now().Before(deadline) {
		_ = control.Close()
		cancelSession()
		return nil, nil, context.DeadlineExceeded
	}
	_, err = t070aWithinDeadline(ctx, deadline, func(opCtx context.Context) ([]string, error) {
		return nil, control.AuthenticateContext(opCtx, cookie)
	})
	if err != nil {
		_ = control.Close()
		cancelSession()
		return nil, nil, errors.New("authenticate prepared Tor control session within deadline failed")
	}
	return control, cancelSession, nil
}

func t070aControlSessionCommand(ctx context.Context, control *tor.ControlPort, deadline time.Time, command string, closeAfter bool, onDispatch func(time.Time) error) ([]string, error) {
	return t070aWithinDeadline(ctx, deadline, func(opCtx context.Context) ([]string, error) {
		var lines []string
		var err error
		if onDispatch != nil {
			lines, err = control.CommandContextAfterFlush(opCtx, command, onDispatch)
		} else {
			lines, err = control.CommandContext(opCtx, command)
		}
		if err != nil {
			return nil, err
		}
		if closeAfter {
			if err := control.Close(); err != nil {
				return nil, errors.New("close Tor control session failed")
			}
		}
		return lines, nil
	})
}

func t070aControlCommand(ctx context.Context, cfg tor.ControlPortConfig, deadline time.Time, command string, onDispatch func(time.Time) error) ([]string, error) {
	return t070aWithinDeadline(ctx, deadline, func(opCtx context.Context) ([]string, error) {
		cookie, err := tor.ReadCookie(opCtx, cfg)
		if err != nil {
			return nil, errors.New("read Tor control cookie failed")
		}
		control, err := tor.Connect(opCtx, cfg)
		if err != nil {
			return nil, errors.New("connect Tor control socket failed")
		}
		if err := control.AuthenticateContext(opCtx, cookie); err != nil {
			_ = control.Close()
			return nil, errors.New("authenticate Tor control session failed")
		}
		var lines []string
		var commandErr error
		if onDispatch != nil {
			lines, commandErr = control.CommandContextAfterFlush(opCtx, command, onDispatch)
		} else {
			lines, commandErr = control.CommandContext(opCtx, command)
		}
		closeErr := control.Close()
		if commandErr != nil {
			return nil, errors.New("Tor control command failed")
		}
		if closeErr != nil {
			return nil, errors.New("close Tor control session failed")
		}
		return lines, nil
	})
}

func t070aWaitAttributedStream(ctx context.Context, cfg tor.ControlPortConfig, target, username string) (string, string, error) {
	deadline := time.Now().Add(t070aCircuitWait)
	for time.Now().Before(deadline) {
		streams, err := t070aControlCommand(ctx, cfg, deadline, "GETINFO stream-status", nil)
		if err != nil {
			return "", "", errors.New("stream-status query failed within attribution deadline")
		}
		var streamID, circuitID string
		for _, line := range streams {
			fields := t070aStatusFields(line, "stream-status=")
			if len(fields) < 4 || fields[3] != target || t059TerminalStreamStates[fields[1]] {
				continue
			}
			if streamID != "" {
				return "", "", errors.New("multiple nonterminal streams match the exact target; attribution is ambiguous")
			}
			streamID, circuitID = fields[0], fields[2]
		}
		if streamID != "" && circuitID != "0" {
			circuits, err := t070aControlCommand(ctx, cfg, deadline, "GETINFO circuit-status", nil)
			if err != nil {
				return "", "", errors.New("circuit-status query failed within attribution deadline")
			}
			wantTag := `SOCKS_USERNAME="` + username + `"`
			builtAttribution := false
			for _, line := range circuits {
				if !strings.Contains(line, wantTag) {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				if fields[0] == circuitID && strings.Contains(line, " BUILT ") {
					builtAttribution = true
				}
			}
			if builtAttribution {
				return streamID, circuitID, nil
			}
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(min(500*time.Millisecond, time.Until(deadline))):
		}
	}
	return "", "", errors.New("exact nonterminal target stream was not observed on a BUILT circuit with the complete username")
}

func t070aUsernameCircuitSnapshot(ctx context.Context, control *tor.ControlPort, username, circuitID string, deadline time.Time) (map[string]struct{}, bool, error) {
	lines, err := t070aControlSessionCommand(ctx, control, deadline, "GETINFO circuit-status", false, nil)
	if err != nil {
		return nil, false, errors.New("circuit-status snapshot failed before exact circuit close")
	}
	wantTag := `SOCKS_USERNAME="` + username + `"`
	baseline := make(map[string]struct{})
	built := false
	for _, line := range lines {
		if !strings.Contains(line, wantTag) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return nil, false, errors.New("Tor exposed a malformed exact-username circuit row")
		}
		baseline[fields[0]] = struct{}{}
		if fields[0] == circuitID && strings.Contains(line, " BUILT ") {
			built = true
		}
	}
	return baseline, built, nil
}

func t070aAssertStreamClosed(ctx context.Context, control *tor.ControlPort, streamID, originalCircuitID string) error {
	deadline := time.Now().Add(t070aCircuitWait)
	lines, err := t070aControlSessionCommand(ctx, control, deadline, "GETINFO stream-status", false, nil)
	if err != nil {
		return errors.New("stream-status query failed within post-close deadline")
	}
	found := false
	for _, line := range lines {
		fields := t070aStatusFields(line, "stream-status=")
		if len(fields) == 0 || fields[0] != streamID {
			continue
		}
		if found {
			return errors.New("Tor returned duplicate rows for the selected stream")
		}
		found = true
		if len(fields) < 3 {
			return errors.New("Tor returned a malformed row for the selected stream")
		}
		if fields[1] != "CLOSED" && fields[1] != "FAILED" {
			return errors.New("selected stream remains nonterminal or DETACHED after raw EOF/RST")
		}
		if fields[2] != "0" && fields[2] != originalCircuitID {
			return errors.New("selected stream was reassigned to another nonzero circuit")
		}
	}
	// Tor's current-status view may already have removed a closed stream. The
	// exact ID was observed live before CLOSECIRCUIT and raw EOF/RST is separate evidence.
	return nil
}

func t070aStatusFields(line, prefix string) []string {
	line = strings.TrimPrefix(line, prefix)
	return strings.Fields(line)
}

func t070aNoReplacementCircuit(ctx context.Context, username string, baseline map[string]struct{}, window time.Duration, snapshot func(time.Time) ([]string, error)) error {
	deadline := time.Now().Add(window)
	wantTag := `SOCKS_USERNAME="` + username + `"`
	for time.Now().Before(deadline) {
		lines, err := snapshot(deadline)
		if err != nil {
			return errors.New("circuit-status snapshot failed before bounded retry observation window ended")
		}
		if !time.Now().Before(deadline) {
			return errors.New("circuit-status snapshot completed after bounded retry observation window")
		}
		for _, line := range lines {
			if !strings.Contains(line, wantTag) {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				return errors.New("Tor exposed a malformed exact-username circuit row")
			}
			if _, present := baseline[fields[0]]; !present {
				return errors.New("Tor exposed a new circuit carrying the exact partition username")
			}
		}
		pause := min(t070aPollEvery, time.Until(deadline))
		if pause <= 0 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pause):
		}
	}
	return nil
}

func TestT070aNoReplacementCircuitObservation(t *testing.T) {
	const username = "sg1:t070a-observation"
	baseline := map[string]struct{}{"41": {}}
	t.Run("reuses snapshot path for the full window", func(t *testing.T) {
		calls := 0
		var firstDeadline time.Time
		started := time.Now()
		err := t070aNoReplacementCircuit(context.Background(), username, baseline, 1100*time.Millisecond, func(deadline time.Time) ([]string, error) {
			calls++
			if firstDeadline.IsZero() {
				firstDeadline = deadline
			} else if !deadline.Equal(firstDeadline) {
				t.Error("circuit snapshots did not share one absolute observation deadline")
			}
			return []string{`41 BUILT $A SOCKS_USERNAME="sg1:t070a-observation"`}, nil
		})
		if err != nil {
			t.Fatalf("bounded observation with only baseline IDs failed: %v", err)
		}
		if calls < 2 {
			t.Fatalf("observation made %d circuit snapshots; want repeated samples", calls)
		}
		if elapsed := time.Since(started); elapsed < 1100*time.Millisecond {
			t.Fatalf("observation ended after %s; want the full configured window", elapsed)
		}
	})
	t.Run("rejects a new exact-username circuit", func(t *testing.T) {
		err := t070aNoReplacementCircuit(context.Background(), username, baseline, time.Second, func(time.Time) ([]string, error) {
			return []string{`42 BUILT $B SOCKS_USERNAME="sg1:t070a-observation"`}, nil
		})
		if err == nil || !strings.Contains(err.Error(), "new circuit") {
			t.Fatalf("new exact-username circuit result = %v; want rejection", err)
		}
	})
	t.Run("rejects query failure", func(t *testing.T) {
		want := errors.New("synthetic snapshot failure")
		err := t070aNoReplacementCircuit(context.Background(), username, baseline, time.Second, func(time.Time) ([]string, error) {
			return nil, want
		})
		if err == nil || !strings.Contains(err.Error(), "snapshot failed") {
			t.Fatalf("snapshot failure result = %v; want bounded query failure", err)
		}
	})
	t.Run("rejects a late result", func(t *testing.T) {
		err := t070aNoReplacementCircuit(context.Background(), username, baseline, 10*time.Millisecond, func(time.Time) ([]string, error) {
			time.Sleep(15 * time.Millisecond)
			return []string{`41 BUILT $A SOCKS_USERNAME="sg1:t070a-observation"`}, nil
		})
		if err == nil || !strings.Contains(err.Error(), "completed after") {
			t.Fatalf("late snapshot result = %v; want deadline rejection", err)
		}
	})
}

func TestT070aDeadlineAndCloseEvidence(t *testing.T) {
	dispatchedAt := time.Now()
	if !t070aReadPredatesClose(t070aReadResult{completed: dispatchedAt.Add(-time.Nanosecond)}, dispatchedAt) {
		t.Fatal("read completed before command dispatch was accepted as close evidence")
	}
	if t070aReadPredatesClose(t070aReadResult{completed: dispatchedAt.Add(time.Nanosecond)}, dispatchedAt) {
		t.Fatal("read completed after command dispatch was classified as pre-dispatch")
	}
	for _, err := range []error{
		os.ErrDeadlineExceeded,
		&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
		context.DeadlineExceeded,
	} {
		if t070aIsTransportCloseError(err) {
			t.Fatalf("deadline error %T was accepted as transport-close evidence", err)
		}
	}
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, syscall.ECONNRESET, syscall.ECONNABORTED} {
		if !t070aIsTransportCloseError(err) {
			t.Fatalf("transport-close error %v was rejected", err)
		}
	}
	cleanupComplete := false
	deadline := time.Now().Add(30 * time.Millisecond)
	late, err := t070aWithinDeadline(context.Background(), deadline, func(opCtx context.Context) ([]string, error) {
		<-opCtx.Done()
		time.Sleep(20 * time.Millisecond) // model the bounded ControlPort cancellation join
		cleanupComplete = true
		return []string{"late"}, nil
	})
	if !cleanupComplete {
		t.Fatal("deadline wrapper returned before operation cancellation cleanup completed")
	}
	if late != nil {
		t.Fatalf("late operation result %q was returned", late)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late control result error = %v, want deadline exceeded", err)
	}
}
