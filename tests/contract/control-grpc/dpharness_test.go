// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package controlgrpc hosts the contract tests for the inter-plane gRPC
// surface declared in specs/001-tor-route/contracts/control-grpc.md.
//
// This file is the shared data-plane process harness. The tests here
// observe the data plane EXTERNALLY only — gRPC on dp.sock, SOCKS5 auth
// bytes on the port-8881 listener, dp-snapshot.json bytes, and captured
// stderr. tests/contract is a separate Go module, so importing
// data-plane/internal/... is impossible by Go's internal-package rule;
// that structural wall is what makes these contract tests, not unit tests.
//
// ── Test-defined harness contract for T045 / T050 ──────────────────────
//
// No spec pins a local-process configuration surface for the data plane
// (the compose deployment uses fixed absolute paths). The env-var
// interface below is therefore defined HERE, tests-first (Principle VII),
// and the implementation tickets T045 (DP gRPC server) and T050 (DP main)
// must either conform to it or amend this single choke point:
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
//
// Mutual-ed25519 credentials on dp.sock are deliberately NOT wired here:
// the transport-invariant contract (including the auth mechanism) is
// T022's scope. The dial site in startDP is the single seam where the
// control-plane credentials attach; once T045 enforces mutual auth, this
// insecure dial fails loudly (fail-not-skip) and forces that update.
package controlgrpc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/dpharness"
	"github.com/zcat-app/stargate/tests/contract/internal/fakecp"
	"github.com/zcat-app/stargate/tests/internal/loginvariants"
)

// dpHarness is one booted data-plane process plus the probes the contract
// cases need. Each sub-test boots its own instance so generation state
// never leaks between cases.
type dpHarness struct {
	client    grpcpb.ControlClient
	conn      *grpc.ClientConn
	proxyAddr string // 127.0.0.1:<port> SOCKS5 listener
	stateDir  string // holds dp-snapshot.json
	journal   *lockedBuffer
	pid       int    // DP process PID; T022 reads /proc/<pid>/net/tcp
	ipcDir    string // dir hosting dp.sock + where control.sock is dialed
}

func (h *dpHarness) snapshotPath() string {
	return filepath.Join(h.stateDir, "dp-snapshot.json")
}

// buildDPOnce compiles the data-plane binary exactly once per `go test`
// invocation; every sub-test boots the same artifact. The build output
// lands under os.TempDir (not t.TempDir) because the path is shared
// across sub-tests; the OS owns its lifecycle.
var buildDPOnce sync.Once
var builtDPPath string
var builtDPErr error

// startDP content-gates, builds, boots, and connects to one data-plane
// process. Skips (never fails) while the implementation this test gates
// does not exist yet — T019b sub-test (c) precedent: the gate files are a
// proxy for "the DP is runnable"; once they exist, a broken build or a
// failing contract is FAIL, not SKIP.
func startDP(t *testing.T) *dpHarness {
	return startDPWith(t, nil)
}

// startDPWith is the extension point for tests that need to host a service
// in the DP's IPC dir BEFORE the DP process boots. T021 hosts a fake
// control plane on control.sock so the DP's WatchEvents dial succeeds on
// the first try; beforeBoot runs after the IPC dir is created and before
// cmd.Start(), with the resolved ipcDir as its argument. nil is the no-op.
func startDPWith(t *testing.T, beforeBoot func(ipcDir string)) *dpHarness {
	return startDPWithUpstream(t, "", beforeBoot)
}

// startDPWithUpstream is the extension point for tests that need BOTH a
// pre-boot IPC-dir hook AND a fake Tor upstream. upstreamAddr overrides
// the production tor:9050 dial target via STARGATE_TOR_SOCKS_ADDR (the
// same env-var contract tests/contract/internal/dpharness.WithUpstream
// pins). Empty upstreamAddr leaves the DP at its default (tor:9050,
// unreachable in the hermetic test — the route-phase probe then observes
// ROUTE_DOWN from the upstream-dial failure, never from an admission gate
// per data-model.md §2 / T090). Added by T090 so the WatchEvents
// admission-invariance sub-test can prove forwarding succeeds without a
// SidecarEvent (Principle II; sol-review B3).
func startDPWithUpstream(t *testing.T, upstreamAddr string, beforeBoot func(ipcDir string)) *dpHarness {
	return startDPWithSeed(t, upstreamAddr, beforeBoot, nil)
}

// startDPWithSeed is the extension point for tests that must place state
// in the DP's state or keys dir BEFORE the process boots — T020a
// pre-populates the cold-start dp-snapshot.json and seeds the inter-plane
// key material. seed runs after the pepper is written and before
// cmd.Start(), with both resolved dirs; nil is the no-op (the
// startDPWithUpstream shape).
func startDPWithSeed(t *testing.T, upstreamAddr string, beforeBoot func(ipcDir string), seed func(stateDir, keysDir string)) *dpHarness {
	t.Helper()
	repoRoot := findRepoRoot(t)

	// Content gate: T045 (DP gRPC server hosting ReloadTokens on dp.sock)
	// and T050 (DP main wiring boot order + listener). Both are needed to
	// exercise this contract end-to-end.
	for _, gate := range []string{
		filepath.Join(repoRoot, "data-plane", "internal", "controlclient", "server.go"),
		filepath.Join(repoRoot, "data-plane", "cmd", "stargate-proxy", "main.go"),
	} {
		if _, err := os.Stat(gate); err != nil {
			t.Skipf("blocked: %s absent — DP ReloadTokens surface not implemented yet (T045/T050); this skip self-lifts when both land", gate)
		}
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not on PATH (environmental, like T019b's docker-daemon skip): %v", err)
	}

	buildDPOnce.Do(func() {
		dir, err := os.MkdirTemp("", "stargate-t020-bin")
		if err != nil {
			builtDPErr = err
			return
		}
		builtDPPath = filepath.Join(dir, "stargate-proxy")
		cmd := exec.Command("go", "build", "-o", builtDPPath, "./cmd/stargate-proxy")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		cmd.Dir = filepath.Join(repoRoot, "data-plane")
		if out, err := cmd.CombinedOutput(); err != nil {
			builtDPErr = fmt.Errorf("go build ./cmd/stargate-proxy: %w\n%s", err, out)
		}
	})
	if builtDPErr != nil {
		t.Fatalf("building data-plane binary: %v", builtDPErr)
	}

	// IPC dir via MkdirTemp, NOT t.TempDir: sun_path on Linux caps UDS
	// paths at ~108 bytes and t.TempDir embeds the full test name.
	ipcDir, err := os.MkdirTemp("", "t020ipc")
	if err != nil {
		t.Fatalf("mktemp ipc dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(ipcDir) })
	stateDir := t.TempDir()
	keysDir := t.TempDir()
	// T130: dp.sock is a mutual-TLS surface — the DP serves it ONLY with
	// TLS material, so the harness seeds the full inter-plane key set
	// (wire-auth.md §6.1 layout; the helper SeedInterPlaneKeys was written
	// for the fake-CP path and is now used for the DP boot too) and dials
	// with CP-shaped credentials below.
	dpharness.SeedInterPlaneKeys(t, keysDir)
	// Write the test pepper so the booted DP's candidate-side HMAC
	// (T044) and mintToken agree on the verifier key (data-model.md
	// §1.7; T093 tests-first contract surface).
	dpharness.WritePepper(t, keysDir)
	if seed != nil {
		seed(stateDir, keysDir)
	}

	proxyAddr := freeLoopbackAddr(t)
	journal := &lockedBuffer{}

	cmd := exec.Command(builtDPPath)
	cmd.Env = append(os.Environ(),
		"STARGATE_IPC_DIR="+ipcDir,
		"STARGATE_STATE_DIR="+stateDir,
		"STARGATE_KEYS_DIR="+keysDir,
		"STARGATE_LISTEN_ADDR="+proxyAddr,
	)
	if upstreamAddr != "" {
		cmd.Env = append(cmd.Env, "STARGATE_TOR_SOCKS_ADDR="+dpharness.UnixUpstream(t, upstreamAddr))
	}
	cmd.Stderr = journal
	cmd.Stdout = journal
	if beforeBoot != nil {
		beforeBoot(ipcDir)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting data-plane process: %v", err)
	}
	t.Cleanup(func() { stopDP(t, cmd, journal) })

	sockPath := filepath.Join(ipcDir, "dp.sock")
	waitFor(t, "dp.sock to appear", 20*time.Second, journal, func() bool {
		_, err := os.Stat(sockPath)
		return err == nil
	})
	waitFor(t, "proxy listener to accept", 20*time.Second, journal, func() bool {
		c, err := net.DialTimeout("tcp", proxyAddr, 250*time.Millisecond)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})

	// T130: the seam is wired. The harness plays the CP: self-signed cert
	// from cp.priv, byte-pin dp.pub (§3), TLS 1.3, ALPN h2 — the same
	// shape the Java ReloadTokensClient presents (CpTls.clientContext).
	cpPriv, err := fakecp.LoadSigner(filepath.Join(keysDir, "cp.priv"))
	if err != nil {
		t.Fatalf("loading seeded cp.priv: %v", err)
	}
	cpCert, err := fakecp.SelfSigned(cpPriv, "stargate-cp-test")
	if err != nil {
		t.Fatalf("deriving CP test cert: %v", err)
	}
	conn, err := grpc.NewClient("unix://"+sockPath,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates:          []tls.Certificate{cpCert},
			InsecureSkipVerify:    true, //nolint:gosec // pinned peer public key IS the verifier (wire-auth.md §4)
			VerifyPeerCertificate: fakecp.PinVerifier(filepath.Join(keysDir, "dp.pub")),
			MinVersion:            tls.VersionTLS13,
			NextProtos:            []string{"h2"},
		})))
	if err != nil {
		t.Fatalf("grpc.NewClient(unix://%s): %v", sockPath, err)
	}
	t.Cleanup(func() { conn.Close() })

	return &dpHarness{
		client:    grpcpb.NewControlClient(conn),
		conn:      conn,
		proxyAddr: proxyAddr,
		stateDir:  stateDir,
		journal:   journal,
		pid:       cmd.Process.Pid,
		ipcDir:    ipcDir,
	}
}

// stopDP terminates the DP process: SIGINT first (exercising whatever
// graceful path T050 wires), SIGKILL after a bounded grace window so a
// hung process can never wedge the test run.
func stopDP(t *testing.T, cmd *exec.Cmd, journal *lockedBuffer) {
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

// reloadErr is the goroutine-safe RPC wrapper (no *testing.T calls) the
// concurrency case needs; reload is the fatal-on-transport-error wrapper
// every sequential case uses. The §5.1 wire-version metadata rides every
// dp.sock RPC (T050 fixture lift): the DP's server interceptor rejects a
// metadata-less RPC with FailedPrecondition before any handler runs
// (wire-auth.md §5.2). Keys mirror data-plane/internal/protoversion —
// the local-mirror pattern this module cannot import around.
func (h *dpHarness) reloadErr(gen uint64, tokens []*grpcpb.TokenVerifier) (*grpcpb.ReloadTokensResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx,
		"x-stargate-proto-major", "1",
		"x-stargate-proto-minor", "0",
		"x-stargate-capabilities", "reload-tokens,watch-events,get-status-minimum")
	return h.client.ReloadTokens(ctx,
		&grpcpb.ReloadTokensRequest{Generation: gen, Tokens: tokens},
		grpc.WaitForReady(true))
}

func (h *dpHarness) reload(t *testing.T, gen uint64, tokens []*grpcpb.TokenVerifier) *grpcpb.ReloadTokensResponse {
	t.Helper()
	resp, err := h.reloadErr(gen, tokens)
	if err != nil {
		t.Fatalf("ReloadTokens(generation=%d) transport error: %v", gen, err)
	}
	return resp
}

// mintToken delegates to the canonical dpharness.MintToken (single HMAC
// mint implementation under the shared TestPepper; data-model.md §1.5).
// Kept as a package-local name so the T020 + watch_events call sites read
// without the dpharness. qualifier; the HMAC logic is NOT duplicated here.
func mintToken(t *testing.T, plaintext string) *grpcpb.TokenVerifier {
	t.Helper()
	return dpharness.MintToken(t, plaintext)
}

// randomBytes backs the malformed-length cases; content is irrelevant,
// only length is under test.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("reading %d random bytes: %v", n, err)
	}
	return b
}

// socks5AuthOK runs the RFC 1929 username/password sub-negotiation from
// contracts/socks5-auth.md against the DP's proxy listener and reports
// whether the offered password (the bearer token plaintext) authenticated:
// reply 0x01 0x00 → true, 0x01 0xFF → false. Anything outside the
// contract's byte shapes is a fatal contract violation, not a false.
// The request phase after auth is out of scope here — admission is not
// CP-gated (data-model.md §2; Principle II; sol-review B3; remediated
// by T090), so with no CP and no `HEALTHY` event the forward path still
// attempts the fixed upstream. T020a pins the cold-start forwarding
// outcome (reachable upstream → forward; unreachable → ROUTE_DOWN).
func (h *dpHarness) socks5AuthOK(t *testing.T, password string) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", h.proxyAddr, err)
	}
	defer conn.Close()
	// Generous deadline: each auth attempt costs the DP one HMAC op
	// per stored token (~50 ms nominal, more on loaded CI hardware).
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Method negotiation: offer USERNAME/PASSWORD only.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	methods := make([]byte, 2)
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if methods[0] != 0x05 || methods[1] != 0x02 {
		t.Fatalf("method selection = %#02x %#02x, want 0x05 0x02 (contracts/socks5-auth.md §\"Auth method negotiation\")", methods[0], methods[1])
	}

	// RFC 1929 sub-negotiation. The username is the stream-isolation key;
	// any value is acceptable to the auth contract.
	user := []byte("t020")
	pass := []byte(password)
	req := append([]byte{0x01, byte(len(user))}, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write userpass sub-negotiation: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read userpass reply: %v", err)
	}
	if reply[0] != 0x01 {
		t.Fatalf("userpass reply version = %#02x, want 0x01 (RFC 1929 §2)", reply[0])
	}
	switch reply[1] {
	case 0x00:
		return true
	case 0xFF:
		return false
	default:
		t.Fatalf("userpass reply status = %#02x, want 0x00 or 0xFF (contracts/socks5-auth.md §\"Auth failure response\")", reply[1])
		return false
	}
}

// requireAuth asserts the auth outcome for a plaintext, with a message
// tying the probe back to the ReloadTokens clause under test.
func (h *dpHarness) requireAuth(t *testing.T, plaintext string, want bool, why string) {
	t.Helper()
	if got := h.socks5AuthOK(t, plaintext); got != want {
		t.Errorf("SOCKS5 auth with %q = %v, want %v — %s", plaintext, got, want, why)
	}
}

// snapshotFile mirrors data-model.md §1.4's informal schema (amended
// by T092: schemaVersion 2, verifier-only — no per-token salt).
type snapshotFile struct {
	SchemaVersion int    `json:"schemaVersion"`
	Generation    uint64 `json:"generation"`
	LoadedAt      string `json:"loadedAt"`
	Verifiers     []struct {
		Verifier string `json:"verifier"`
	} `json:"verifiers"`
}

// snapshotBytes returns the raw dp-snapshot.json content, or nil when the
// file does not exist (valid pre-first-OK state).
func (h *dpHarness) snapshotBytes(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(h.snapshotPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("reading %s: %v", h.snapshotPath(), err)
	}
	return b
}

func (h *dpHarness) readSnapshot(t *testing.T) snapshotFile {
	t.Helper()
	raw := h.snapshotBytes(t)
	if raw == nil {
		t.Fatalf("%s does not exist — contract requires persist before returning APPLY_STATUS_OK", h.snapshotPath())
	}
	var s snapshotFile
	if err := json.Unmarshal(raw, &s); err != nil {
		// Content deliberately redacted: the snapshot holds base64
		// verifier material, and failure output lands in CI logs — same
		// index-only hygiene as assertNoSecretLeak.
		t.Fatalf("unmarshal %s (data-model.md §1.4 shape): %v (%d bytes, content redacted)", h.snapshotPath(), err, len(raw))
	}
	return s
}

// verifiersEqual reports whether the base64-encoded verifier string
// read from dp-snapshot.json equals the raw verifier bytes pushed over
// the RPC (data-model.md §1.4 persist-content fidelity check).
func verifiersEqual(b64 string, raw []byte) bool {
	return b64 == base64.StdEncoding.EncodeToString(raw)
}

// assertNoSecretLeak scans the captured journal for every rendering of
// every secret handed to the DP — the contract's final bullet: the data
// plane MUST NOT log the hash bytes, the salt bytes, or any token label.
// Failure messages name only the secret's index and encoding, never the
// bytes, so a failing run cannot itself leak into CI logs.
//
// Delegates to the canonical loginvariants scanner (T101 acceptance #1:
// one scanner implementation). The legacy local copy that lived here
// omitted the raw-plaintext encoding (review A2 path #1); consolidating
// on loginvariants.AssertNoSecrets closes that gap — a verifier logging
// the offered token as a cleartext string no longer passes this
// assertion. Call sites are unchanged (same (t, harness, secrets...) shape).
func assertNoSecretLeak(t *testing.T, h *dpHarness, secrets ...[]byte) {
	t.Helper()
	loginvariants.AssertNoSecrets(t, h.journal.String(), secrets...)
}

// journalContains reports whether the captured journal has the substring,
// case-insensitively.
func (h *dpHarness) journalContains(needle string) bool {
	return strings.Contains(strings.ToLower(h.journal.String()), strings.ToLower(needle))
}

// lockedBuffer is a mutex-guarded byte buffer safe for concurrent writes
// from the child process pipe pump and reads from test assertions.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freeLoopbackAddr reserves an ephemeral loopback port by binding and
// immediately releasing it. The small close-to-rebind race is acceptable
// in a test harness; a collision surfaces as a boot failure with the
// journal attached.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving loopback port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// waitFor polls until cond is true or the deadline passes; on timeout it
// fails with the DP journal so boot problems are diagnosable from CI logs.
func waitFor(t *testing.T, what string, timeout time.Duration, journal *lockedBuffer, cond func() bool) {
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

// findRepoRoot walks up from this file's source location to the directory
// containing go.work (the workspace root). Working-directory independence
// per the T019b precedent: `go test` may run from any cwd.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate test source path")
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
