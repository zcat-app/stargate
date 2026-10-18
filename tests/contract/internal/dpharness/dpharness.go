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
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/fakecp"
)

// Harness is one booted data-plane process plus the probes a contract
// test needs. Each Start call produces an independent instance so
// generation / token-list state never leaks between sub-tests.
type Harness struct {
	CounterTime      time.Time
	counterClockPath string
	ProxyAddr        string // 127.0.0.1:<port>; STARGATE_LISTEN_ADDR
	UpstreamAddr     string // loopback fake upstream (fake_socks5_tor); empty in tests that don't forward
	IPCDir           string // dir hosting dp.sock + where control.sock is dialed
	StateDir         string // private directory holding the acknowledged auth snapshot
	TempDir          string // private /tmp directory passed to the child as TMPDIR
	AbsTmpProbePath  string // one reserved absolute /tmp leaf observed without walking shared-host paths
	KeysDir          string // inter-plane key set (T130: dp.sock dials need CP-shaped TLS creds)
	Journal          *LockedBuffer
	PID              int
	Cmd              *exec.Cmd
	// CP is the TLS fake control plane booted by WithControlPlane; nil
	// otherwise. The DP dials it over the §4 mutual-pin TLS handshake.
	CP *fakecp.Server
	// RPCRequests records the actual DP-to-CP WatchEvents request payloads
	// and incoming metadata when WithControlPlaneRequestCapture is selected.
	RPCRequests *RPCRequestCapture
}

// Option configures Start at construction time. The zero Option set
// reproduces the T023 behaviour (no upstream override, no before-boot
// callback) — Start(t) with no opts is the minimal DP boot.
type Option func(*startConfig)

type startConfig struct {
	counterClock           *time.Time
	countersDisabled       bool
	beforeBoot             func(ipcDir string)
	upstream               string // empty = use production default (unix:///run/stargate-tor/tor-socks.sock)
	controlPlane           bool   // seed inter-plane keys + host the TLS fake CP
	controlPlaneCapture    bool   // capture actual WatchEvents request messages/metadata
	suppressFailureJournal bool
}

// WithCounterClock selects a test binary using production runWithCounters wiring.
// Only traffic accounting receives this clock; TLS, sockets and deadlines use real time.
func WithCounterClock(now time.Time) Option {
	return func(c *startConfig) { c.counterClock = &now }
}

func WithCountersDisabled() Option { return func(c *startConfig) { c.countersDisabled = true } }

// AdvanceCounterHour closes one synthetic hour. Status remains an ordinary RPC;
// tests must explicitly advance time, preserving meaningful negative assertions.
func (h *Harness) AdvanceCounterHour(t *testing.T) {
	t.Helper()
	if h.counterClockPath == "" {
		t.Fatal("counter clock not enabled")
	}
	h.CounterTime = h.CounterTime.Add(time.Hour)
	writeCounterClock(t, h.counterClockPath, h.CounterTime)
}
func writeCounterClock(t *testing.T, path string, now time.Time) {
	t.Helper()
	if err := os.WriteFile(path+".new", []byte(strconv.FormatInt(now.Unix(), 10)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

// WithBeforeBoot registers a callback invoked AFTER the IPC dir is
// created and BEFORE the DP process starts. Mirrors T021's startDPWith
// pattern: tests host a fake control plane on ${ipcDir}/control.sock
// here so the DP's first WatchEvents dial succeeds (or host any other
// pre-DP fixture that needs the ipcDir).
func WithBeforeBoot(fn func(ipcDir string)) Option {
	return func(c *startConfig) { c.beforeBoot = fn }
}

// WithUpstream overrides the production Unix adapter using the existing
// synthetic loopback-to-Unix test fixture (typically the dial addr of a
// fake_socks5_tor.Server from tests/integration). This is the test-defined
// choke point T047 and T050 must honour; the env-var interface it implies
// (STARGATE_TOR_SOCKS_ADDR) is the new contract surface this option pins.
func WithUpstream(addr string) Option {
	return func(c *startConfig) { c.upstream = addr }
}

// WithControlPlane boots the DP against a LIVE wire-auth §4 control
// plane: SeedInterPlaneKeys fills the keys dir, and a TLS fake CP
// (fakecp.StartTLS) hosts control.sock BEFORE the DP process starts, so
// the DP's WatchEvents client — which refuses unauthenticated inter-plane
// dials (controlclient NewClient, wire-auth.md §4) — actually connects
// and consumes the programmable event stream. Tests assert delivery via
// h.CP (Send / DialCount / LatestStream / CloseFromServer).
//
// This is the forced-fixture lift T050 §Analysis records: the previous
// plaintext-fake-CP fixtures predate wire-auth.md (T095) and cannot serve
// the TLS-mandatory client. Keys are seeded on EVERY Start (T130: dp.sock
// is served over mTLS on every boot; a keyless boot would serve no dp.sock
// at all and fail Start's boot wait) — WithControlPlane's increment is
// hosting the TLS fake CP so the first WatchEvents dial succeeds, nothing
// more.
func WithControlPlane() Option {
	return func(c *startConfig) { c.controlPlane = true }
}

// WithControlPlaneRequestCapture hosts the same mutually-pinned TLS Events
// service but retains each real WatchEvents request in a bounded private
// capture for privacy contract tests. The observed fixture never injects
// events, so the DP's ordinary request stream remains independent of CP data.
func WithControlPlaneRequestCapture() Option {
	return func(c *startConfig) {
		c.controlPlane = true
		c.controlPlaneCapture = true
	}
}

// WithSuppressFailureJournal prevents raw child output from being printed
// when Start's boot waits or process cleanup fail. Privacy-sensitive load
// probes use this because the child's complete output is an unfiltered
// diagnostic channel; ordinary callers retain the default journal behavior.
func WithSuppressFailureJournal() Option {
	return func(c *startConfig) { c.suppressFailureJournal = true }
}

// Start content-gates, builds, boots, and waits for the proxy listener
// of one data-plane process. Skips (never fails) while the
// implementation files this harness gates on do not exist yet — the
// skip self-lifts when T042 (listener/socks5.go) + T045
// (controlclient/server.go) + T050 (cmd/stargate-proxy/main.go) land.
// Once they exist, a broken build or a failing contract is FAIL, not
// SKIP (precedent: tests/contract/control-grpc/dpharness_test.go).
//
// Per-sub-test content gates for surfaces beyond the boot-minimum
// (T044 auth/token.go, T047 forward/tor.go, T045 client.go for
// WatchEvents) are the test's responsibility — call RequireFile from
// the test before exercising the surface that depends on it.
func Start(t *testing.T, opts ...Option) *Harness {
	t.Helper()
	cfg := startConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	repoRoot := FindRepoRoot(t)

	// Content gate: T042 (listener) + T045 (gRPC server hosting
	// ReloadTokens on dp.sock) + T050 (main wiring boot order +
	// listener). All three are needed to exercise the port-8881 inbound
	// surface end-to-end. This is the boot-minimum gate; tests with
	// larger dependency surfaces add per-sub-test RequireFile calls.
	for _, gate := range []string{
		filepath.Join(repoRoot, "data-plane", "internal", "listener", "socks5.go"),
		filepath.Join(repoRoot, "data-plane", "internal", "controlclient", "server.go"),
		filepath.Join(repoRoot, "data-plane", "cmd", "stargate-proxy", "main.go"),
	} {
		RequireFile(t, gate, "port-8881 inbound surface not implemented yet (T042/T045/T050); this skip self-lifts when all three land")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not on PATH (environmental, like T019b's docker-daemon skip): %v", err)
	}

	binPath := buildDPOnce(t, cfg.counterClock != nil)

	// IPC dir via MkdirTemp, NOT t.TempDir: sun_path on Linux caps UDS
	// paths at ~108 bytes and t.TempDir embeds the full test name.
	ipcDir, err := os.MkdirTemp("", "stargate-contract-ipc")
	if err != nil {
		t.Fatalf("mktemp ipc dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(ipcDir) })
	stateDir := t.TempDir()
	var tempDir string
	if cfg.controlPlaneCapture {
		tempDir, err = os.MkdirTemp("/tmp", "stargate-contract-private-tmp-")
		if err != nil {
			t.Fatalf("create private /tmp observation directory: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(tempDir) })
	}
	var absTmpProbePath string
	if cfg.controlPlaneCapture {
		probe, err := os.CreateTemp("/tmp", "stargate-contract-absolute-tmp-probe-")
		if err != nil {
			t.Fatalf("reserve exact absolute /tmp observation path: %v", err)
		}
		absTmpProbePath = probe.Name()
		if err := probe.Close(); err != nil {
			t.Fatalf("close reserved absolute /tmp observation path: %v", err)
		}
		if err := os.Remove(absTmpProbePath); err != nil {
			t.Fatalf("clear reserved absolute /tmp observation path: %v", err)
		}
		t.Cleanup(func() { _ = os.Remove(absTmpProbePath) })
	}
	keysDir := t.TempDir()
	// Write the test pepper to the keys dir so the booted DP's
	// candidate-side HMAC (T044) and MintToken agree on the verifier
	// key (data-model.md §1.7; T093 tests-first contract surface).
	WritePepper(t, keysDir)
	// T130: seeded UNCONDITIONALLY. dp.sock is a mutual-TLS surface
	// (wire-auth.md §4 as amended): the DP serves it ONLY with TLS
	// material, so a keys-less boot now serves no dp.sock at all and the
	// boot wait below would time out. The WatchEvents-client rationale
	// (identity + pin on disk before start) still applies; when
	// cfg.controlPlane is set, a matching TLS fake CP must additionally
	// own control.sock before the first dial (initial backoff would
	// otherwise race the delivery assertions).
	SeedInterPlaneKeys(t, keysDir)

	proxyAddr := FreeLoopbackAddr(t)
	journal := &LockedBuffer{}
	var hCP *fakecp.Server

	cmd := exec.Command(binPath)
	var counterClockPath string
	var counterTime time.Time
	if cfg.counterClock != nil {
		counterClockPath = filepath.Join(stateDir, "test-counter-clock")
		counterTime = *cfg.counterClock
		writeCounterClock(t, counterClockPath, counterTime)
		cmd = exec.Command(binPath, "-test.run=^TestCounterClockProcess$")
	}
	env := append(os.Environ(),
		"STARGATE_IPC_DIR="+ipcDir,
		"STARGATE_STATE_DIR="+stateDir,
		"STARGATE_KEYS_DIR="+keysDir,
		"STARGATE_LISTEN_ADDR="+proxyAddr,
		"STARGATE_TRAFFIC_COUNTERS=true",
	)
	if tempDir != "" {
		env = append(env, "TMPDIR="+tempDir)
	}
	if cfg.upstream != "" {
		// Test-defined env-var interface: T047 / T050 must read this
		// and override the production unix:///run/stargate-tor/tor-socks.sock default when set.
		// The Unix adapter matches production; no DP destination DNS or TCP dial.
		env = append(env, "STARGATE_TOR_SOCKS_ADDR="+UnixUpstream(t, cfg.upstream))
	}
	if counterClockPath != "" {
		env = append(env, "STARGATE_TEST_COUNTER_CLOCK="+counterClockPath)
	}
	if cfg.countersDisabled {
		env = append(env, "STARGATE_TRAFFIC_COUNTERS=false")
	}
	cmd.Env = env
	cmd.Stderr = journal
	cmd.Stdout = journal
	var rpcRequests *RPCRequestCapture
	if cfg.controlPlaneCapture {
		rpcRequests = startControlPlaneRequestCapture(t, ipcDir, keysDir)
	} else if cfg.controlPlane {
		hCP = fakecp.StartTLS(t, ipcDir, keysDir)
	}
	if cfg.beforeBoot != nil {
		cfg.beforeBoot(ipcDir)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting data-plane process: %v", err)
	}
	t.Cleanup(func() { stop(t, cmd, journal, cfg.suppressFailureJournal) })

	// dp.sock is the gRPC surface T045 hosts; waiting on it ensures the
	// DP finished its boot sequence past the control-plane client init.
	// The proxy listener wait below is the load-bearing one for tests
	// that only probe port 8881 — we keep both so a regression that
	// breaks dp.sock binding surfaces here, not in a downstream test.
	sockPath := filepath.Join(ipcDir, "dp.sock")
	WaitFor(t, "dp.sock to appear", 20*time.Second, journal, func() bool {
		_, err := os.Stat(sockPath)
		return err == nil
	}, cfg.suppressFailureJournal)
	WaitFor(t, "proxy listener to accept", 20*time.Second, journal, func() bool {
		c, err := net.DialTimeout("tcp", proxyAddr, 250*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, cfg.suppressFailureJournal)

	return &Harness{
		CounterTime:      counterTime,
		counterClockPath: counterClockPath,
		ProxyAddr:        proxyAddr,
		UpstreamAddr:     cfg.upstream,
		IPCDir:           ipcDir,
		StateDir:         stateDir,
		TempDir:          tempDir,
		AbsTmpProbePath:  absTmpProbePath,
		KeysDir:          keysDir,
		Journal:          journal,
		PID:              cmd.Process.Pid,
		Cmd:              cmd,
		CP:               hCP,
		RPCRequests:      rpcRequests,
	}
}

const (
	maxCapturedWatchRequests = 8
	maxCapturedRPCBytes      = 16 << 10
	maxCapturedMetadataItems = 64
)

// CapturedRPCRequest is one bounded, actual request received by the test CP.
// Payload is the deterministic protobuf wire encoding; metadata is copied
// from the authenticated stream context. Neither contains DP-local pointers.
type CapturedRPCRequest struct {
	Method   string
	Payload  []byte
	Metadata map[string][]string
}

// RPCRequestCapture is bounded by the finite WatchEvents connection cardinality
// and fails closed if a capture is omitted or grows beyond test limits.
type RPCRequestCapture struct {
	mu       sync.Mutex
	requests []CapturedRPCRequest
	err      string
}

func (c *RPCRequestCapture) Snapshot() ([]CapturedRPCRequest, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]CapturedRPCRequest, len(c.requests))
	for i, req := range c.requests {
		out[i] = CapturedRPCRequest{Method: req.Method, Payload: append([]byte(nil), req.Payload...), Metadata: make(map[string][]string, len(req.Metadata))}
		for key, values := range req.Metadata {
			out[i].Metadata[key] = append([]string(nil), values...)
		}
	}
	return out, c.err
}

// Record observes one actual WatchEvents request received by the fake CP.
func (c *RPCRequestCapture) Record(req *grpcpb.WatchEventsRequest, md metadata.MD) error {
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(req)
	if err != nil {
		return c.fail("WatchEvents request capture marshal failed")
	}
	if len(payload) > maxCapturedRPCBytes || len(md) > maxCapturedMetadataItems {
		return c.fail("WatchEvents request capture limit exceeded")
	}
	copyMD := make(map[string][]string, len(md))
	items := 0
	metadataBytes := 0
	for key, values := range md {
		items += 1 + len(values)
		metadataBytes += len(key)
		for _, value := range values {
			metadataBytes += len(value)
		}
		copyMD[key] = append([]string(nil), values...)
	}
	if items > maxCapturedMetadataItems || metadataBytes > maxCapturedRPCBytes-len(payload) {
		return c.fail("WatchEvents request capture limit exceeded")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != "" {
		return fmt.Errorf("%s", c.err)
	}
	if len(c.requests) >= maxCapturedWatchRequests {
		c.err = "WatchEvents request capture limit exceeded"
		return fmt.Errorf("%s", c.err)
	}
	c.requests = append(c.requests, CapturedRPCRequest{
		Method:   "/stargate.v1.Events/WatchEvents",
		Payload:  payload,
		Metadata: copyMD,
	})
	return nil
}

// fail records a fixed-size observer error so rejected captures cannot be
// mistaken for a complete snapshot and untrusted metadata cannot inflate the
// retained diagnostic. This affects test evidence collection only.
func (c *RPCRequestCapture) fail(message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == "" {
		c.err = message
	}
	return fmt.Errorf("%s", c.err)
}

type requestCaptureEventsServer struct {
	grpcpb.UnimplementedEventsServer
	capture *RPCRequestCapture
}

func (s *requestCaptureEventsServer) WatchEvents(req *grpcpb.WatchEventsRequest, stream grpcpb.Events_WatchEventsServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	if err := s.capture.Record(req, md); err != nil {
		return err
	}
	<-stream.Context().Done()
	return nil
}

func startControlPlaneRequestCapture(t *testing.T, ipcDir, keysDir string) *RPCRequestCapture {
	t.Helper()
	cpPriv, err := fakecp.LoadSigner(filepath.Join(keysDir, "cp.priv"))
	if err != nil {
		t.Fatalf("request-capture CP: load seeded cp.priv: %v", err)
	}
	cert, err := fakecp.SelfSigned(cpPriv, "stargate-cp")
	if err != nil {
		t.Fatalf("request-capture CP: derive pinned certificate: %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, //nolint:gosec // exact peer pin below is the fixture trust decision
		VerifyPeerCertificate: fakecp.PinVerifier(filepath.Join(keysDir, "dp.pub")),
		ClientAuth:            tls.RequireAnyClientCert,
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{"h2"},
	}
	socketPath := filepath.Join(ipcDir, "control.sock")
	_ = os.Remove(socketPath)
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("request-capture CP: listen on control.sock: %v", err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	capture := &RPCRequestCapture{}
	grpcpb.RegisterEventsServer(srv, &requestCaptureEventsServer{capture: capture})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.GracefulStop()
		_ = lis.Close()
		_ = os.Remove(socketPath)
	})
	return capture
}

// RequireFile content-gates a sub-test on a file existing. Skips (never
// fails) when absent, with the supplied reason naming the ticket the
// skip lifts under. Use for per-sub-test dependencies beyond the boot-
// minimum gate inside Start (e.g. T044 auth/token.go, T047 forward/
// tor.go, T045 client.go for WatchEvents consumption).
func RequireFile(t *testing.T, path, reason string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("blocked: %s absent — %s", path, reason)
	}
}

// SockPath returns the absolute path to dp.sock in this harness's IPC
// dir. Tests dial it via grpc.NewClient("unix://"+h.SockPath()) to
// reach the DP-hosted ReloadTokens / GetStatus surface.
func (h *Harness) SockPath() string {
	return filepath.Join(h.IPCDir, "dp.sock")
}

// buildDPOnce compiles the data-plane binary exactly once per `go test`
// invocation; every sub-test boots the same artifact. The build output
// lands under os.TempDir (not t.TempDir) because the path is shared
// across sub-tests; the OS owns its lifecycle.
var builds [2]struct {
	once sync.Once
	path string
	err  error
}

func buildDPOnce(t *testing.T, clock bool) string {
	t.Helper()
	index := 0
	if clock {
		index = 1
	}
	b := &builds[index]
	b.once.Do(func() {
		dir, err := os.MkdirTemp("", "stargate-contract-bin")
		if err != nil {
			b.err = err
			return
		}
		b.path = filepath.Join(dir, "stargate-proxy")
		args := []string{"build", "-o", b.path, "./cmd/stargate-proxy"}
		if clock {
			args = []string{"test", "-c", "-o", b.path, "./cmd/stargate-proxy"}
		}
		cmd := exec.Command("go", args...)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Dir = filepath.Join(FindRepoRoot(t), "data-plane")
		if out, err := cmd.CombinedOutput(); err != nil {
			b.err = fmt.Errorf("building DP: %w\n%s", err, out)
		}
	})
	if b.err != nil {
		t.Fatal(b.err)
	}
	return b.path
}

// stop terminates the DP process: SIGINT first (exercising whatever
// graceful path T050 wires), SIGKILL after a bounded grace window so a
// hung process can never wedge the test run.
func stop(t *testing.T, cmd *exec.Cmd, journal *LockedBuffer, suppressFailureJournal bool) {
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
	if t.Failed() && !suppressFailureJournal {
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
// it fails with the DP journal unless suppression was requested.
func WaitFor(t *testing.T, what string, timeout time.Duration, journal *LockedBuffer, cond func() bool, suppressFailureJournal bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	if suppressFailureJournal {
		t.Fatalf("timed out after %s waiting for %s", timeout, what)
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
