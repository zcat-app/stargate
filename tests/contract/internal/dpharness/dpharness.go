// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package dpharness hosts the shared data-plane process harness for
// contract tests under tests/contract/. It boots one data-plane binary
// configured for local-process testing (loopback proxy listener, temp
// IPC/state/keys dirs, no live control plane) and exposes the surface
// contract tests probe: the dialable proxy address, the captured
// stderr/stdout journal, and the process PID.
//
// Why this lives here and not next to tests/contract/control-grpc/
// dpharness_test.go: the latter is a `_test.go` file in package
// `controlgrpc`, which Go's internal-package rule makes unimportable from
// other test packages (tests/contract/socks5/, tests/contract/torrc/,
// etc.). Putting the shared boot surface in a non-`_test.go` file under
// tests/contract/internal/dpharness/ lets every contract test package
// within this module import it without duplicating the ~150-line DP
// boot dance. The existing tests/contract/control-grpc/dpharness_test.go
// is deliberately NOT refactored to import from here — that is a
// follow-up; this package is the canonical location new contract tests
// should reach for.
//
// Test-defined harness contract for the data-plane process (mirrors the
// env-var interface authored tests-first in
// tests/contract/control-grpc/dpharness_test.go for T045 / T050):
//
//	STARGATE_IPC_DIR     dir hosting dp.sock and where control.sock is
//	                     dialed        (default /run/stargate)
//	STARGATE_STATE_DIR   dir holding dp-snapshot.json
//	                     (default /var/lib/stargate)
//	STARGATE_KEYS_DIR    ed25519 key material dir
//	                     (default /etc/stargate/keys)
//	STARGATE_LISTEN_ADDR proxy listen address
//	                     (default 127.0.0.1:8881; FR-010's bind check
//	                     still applies — loopback literals only)
package dpharness

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// Harness is one booted data-plane process plus the probes a contract
// test needs. Each Start call produces an independent instance so
// generation / token-list state never leaks between sub-tests.
type Harness struct {
	ProxyAddr string // 127.0.0.1:<port>; STARGATE_LISTEN_ADDR
	Journal   *LockedBuffer
	PID       int
	Cmd       *exec.Cmd
}

// Start content-gates, builds, boots, and waits for the proxy listener
// of one data-plane process. Skips (never fails) while the
// implementation files this harness gates on do not exist yet — the
// skip self-lifts when T042 (listener/socks5.go) + T045
// (controlclient/server.go) + T050 (cmd/stargate-proxy/main.go) land.
// Once they exist, a broken build or a failing contract is FAIL, not
// SKIP (precedent: tests/contract/control-grpc/dpharness_test.go).
func Start(t *testing.T) *Harness {
	t.Helper()
	repoRoot := FindRepoRoot(t)

	// Content gate: T042 (listener) + T045 (gRPC server hosting
	// ReloadTokens on dp.sock) + T050 (main wiring boot order +
	// listener). All three are needed to exercise the port-8881 inbound
	// surface end-to-end. T023 is tests-first for T042, so this skip is
	// the red→green transition: the test exists RED-but-SKIP until T042
	// lands, then drives the implementation to satisfy the byte contract.
	for _, gate := range []string{
		filepath.Join(repoRoot, "data-plane", "internal", "listener", "socks5.go"),
		filepath.Join(repoRoot, "data-plane", "internal", "controlclient", "server.go"),
		filepath.Join(repoRoot, "data-plane", "cmd", "stargate-proxy", "main.go"),
	} {
		if _, err := os.Stat(gate); err != nil {
			t.Skipf("blocked: %s absent — port-8881 inbound surface not implemented yet (T042/T045/T050); this skip self-lifts when all three land", gate)
		}
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not on PATH (environmental, like T019b's docker-daemon skip): %v", err)
	}

	binPath := buildDPOnce(t)

	// IPC dir via MkdirTemp, NOT t.TempDir: sun_path on Linux caps UDS
	// paths at ~108 bytes and t.TempDir embeds the full test name.
	ipcDir, err := os.MkdirTemp("", "stargate-contract-ipc")
	if err != nil {
		t.Fatalf("mktemp ipc dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(ipcDir) })
	stateDir := t.TempDir()
	keysDir := t.TempDir()

	proxyAddr := FreeLoopbackAddr(t)
	journal := &LockedBuffer{}

	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(),
		"STARGATE_IPC_DIR="+ipcDir,
		"STARGATE_STATE_DIR="+stateDir,
		"STARGATE_KEYS_DIR="+keysDir,
		"STARGATE_LISTEN_ADDR="+proxyAddr,
	)
	cmd.Stderr = journal
	cmd.Stdout = journal
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting data-plane process: %v", err)
	}
	t.Cleanup(func() { stop(t, cmd, journal) })

	// dp.sock is the gRPC surface T045 hosts; waiting on it ensures the
	// DP finished its boot sequence past the control-plane client init.
	// The proxy listener wait below is the load-bearing one for tests
	// that only probe port 8881 — we keep both so a regression that
	// breaks dp.sock binding surfaces here, not in a downstream test.
	sockPath := filepath.Join(ipcDir, "dp.sock")
	WaitFor(t, "dp.sock to appear", 20*time.Second, journal, func() bool {
		_, err := os.Stat(sockPath)
		return err == nil
	})
	WaitFor(t, "proxy listener to accept", 20*time.Second, journal, func() bool {
		c, err := net.DialTimeout("tcp", proxyAddr, 250*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})

	return &Harness{
		ProxyAddr: proxyAddr,
		Journal:   journal,
		PID:       cmd.Process.Pid,
		Cmd:       cmd,
	}
}

// buildDPOnce compiles the data-plane binary exactly once per `go test`
// invocation; every sub-test boots the same artifact. The build output
// lands under os.TempDir (not t.TempDir) because the path is shared
// across sub-tests; the OS owns its lifecycle.
var (
	buildOnce sync.Once
	binPath   string
	binErr    error
)

func buildDPOnce(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "stargate-contract-bin")
		if err != nil {
			binErr = err
			return
		}
		binPath = filepath.Join(dir, "stargate-proxy")
		repoRoot := FindRepoRoot(t)
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/stargate-proxy")
		cmd.Dir = filepath.Join(repoRoot, "data-plane")
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("go build ./cmd/stargate-proxy: %w\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatalf("building data-plane binary: %v", binErr)
	}
	return binPath
}

// stop terminates the DP process: SIGINT first (exercising whatever
// graceful path T050 wires), SIGKILL after a bounded grace window so a
// hung process can never wedge the test run.
func stop(t *testing.T, cmd *exec.Cmd, journal *LockedBuffer) {
	t.Helper()
	if cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	done := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	if t.Failed() {
		t.Logf("data-plane journal:\n%s", journal.String())
	}
}

// FreeLoopbackAddr reserves an ephemeral loopback port by binding and
// immediately releasing it. The small close-to-rebind race is acceptable
// in a test harness; a collision surfaces as a boot failure with the
// journal attached.
func FreeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving loopback port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// WaitFor polls until cond is true or the deadline passes; on timeout
// it fails with the DP journal so boot problems are diagnosable from CI
// logs.
func WaitFor(t *testing.T, what string, timeout time.Duration, journal *LockedBuffer, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s\ndata-plane journal:\n%s", timeout, what, journal.String())
}

// FindRepoRoot walks up from this file's source location to the
// directory containing go.work (the workspace root). Working-directory
// independence per the T019b precedent: `go test` may run from any cwd.
func FindRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate harness source path")
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("repo root (containing go.work) not found by walking up from " + filepath.Dir(thisFile))
	return ""
}

// LockedBuffer is a mutex-guarded byte buffer safe for concurrent writes
// from the child process pipe pump and reads from test assertions.
type LockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *LockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *LockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
