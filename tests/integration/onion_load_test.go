// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// T033 constants.
//
// composeProject namespaces every compose invocation so the test never
// collides with operator-authored state brought up under the default
// project name. The reference onion is DuckDuckGo's v3 onion address
// (spec.md §"User Story 1") — the stable, publicly reachable target the
// spec pins for US1.
//
// Timeouts: bootstrap can take several minutes on a cold guard selection;
// the per-request timeout absorbs Tor circuit-build + onion rendezvous
// latency (two orders of magnitude slower than clearnet); the route-wait
// window absorbs Tor circuit-build + any transient dial retry — admission
// is not CP-gated (data-model.md §2; Principle II; sol-review B3;
// remediated by T090), so the DP forwards as soon as the listener is up.
const (
	t033Project   = "stargate-t033-test"
	t033Onion     = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	t033DPAddr    = "127.0.0.1:8881"
	t033ReqWait   = 90 * time.Second  // retry window for the onion load (route-enable + circuit-build slack)
	t033ReqDead   = 120 * time.Second // per-attempt HTTP client timeout
	t033BootWait  = 5 * time.Minute   // Tor bootstrap (cold guard selection)
	t033ExecDead  = 15 * time.Second  // docker compose exec deadline (nc control-socket probe)
	t033PollEvery = 5 * time.Second

	// t033ControlSocket is tor's only control endpoint (torrc contract
	// invariant #3; T162 removed TCP 9051).
	t033ControlSocket = "/var/lib/tor/control/tor-control.sock"
)

// t033ProfileID is the partition's fixed browser-profile id (the
// foundation-boundaries reference vector's).
var t033ProfileID = strings.Repeat("11", 32)

// TestOnionLoad is the US1 MVP gate (T033): bring up the full
// local-profile stack, load the spec's reference onion through port 8881
// via SOCKS5h, and assert (a) page bytes received and (b) Tor reports an
// established circuit. Test-first per Constitution Principle VII —
// self-skips until T047 (forward/tor.go), T050 (main.go), and the
// control plane land; the test is the target the implementation lands
// against.
//
// Release-tag cadence: requires the real Tor network + the reference
// onion service. Gated by STARGATE_RUN_NETWORK_TESTS=1 +
// STARGATE_TEST_TOKEN=<bearer>. Not run by verify.sh (which gates only
// the data-plane Go module). DNS-leak and egress-consensus properties
// are gated separately by T034/T034f.
//
// OPERATOR PREREQUISITES (current Local topology; T126/T131 runbook): run
// only on a disposable Linux Docker host or VM
// (tests/live-e2e/local-topology/README.md) with the `stargate-dp`
// AppArmor profile loaded in enforce mode and the DP owner rules
// installed, and with the init-equivalent key/pepper and volume-root
// provisioning (scripts/stargate init steps 2–3) done for THIS project's
// (stargate-t033-test) volumes. The harness does not seed the token: the
// operator also writes tokens.yaml (spec FR-017 shape, carrying
// STARGATE_TEST_TOKEN) and the keys/ mountpoint into
// stargate-t033-test_stargate-control-config before the run — the step
// T059's t059SeedToken automates for its own project.
func TestOnionLoad(t *testing.T) {
	// --- Self-skip guards ------------------------------------------------
	// The test is authored BEFORE the implementation it verifies. Each
	// guard self-skips (not fails) when a prerequisite is absent —
	// matching T019b sub-test (c)'s content-gate pattern.

	if os.Getenv("STARGATE_RUN_NETWORK_TESTS") != "1" {
		t.Skip("STARGATE_RUN_NETWORK_TESTS != 1 — release-tag test (needs real Tor network + reference onion); set to opt in")
	}
	token := os.Getenv("STARGATE_TEST_TOKEN")
	if token == "" {
		t.Skip("STARGATE_TEST_TOKEN unset — bearer token required to authenticate through port 8881")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker daemon unreachable: %v", err)
	}

	repoRoot := t033FindRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, p := range []string{composeFile, envFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("required file missing: %v", err)
		}
	}

	// Content gates: the implementation tickets T033 verifies. Skip
	// (not fail) when the implementation hasn't landed yet — the test
	// is the target.
	dpMain := filepath.Join(repoRoot, "data-plane", "cmd", "stargate-proxy", "main.go")
	if _, err := os.Stat(dpMain); err != nil {
		t.Skipf("blocked: %s absent — T050 (DP main) not landed", dpMain)
	}
	fwdTor := filepath.Join(repoRoot, "data-plane", "internal", "forward", "tor.go")
	if _, err := os.Stat(fwdTor); err != nil {
		t.Skipf("blocked: %s absent — T047 (forward/tor.go) not landed", fwdTor)
	}
	// The full vertical needs the control plane to push the token generation
	// (Tor's torrc is baked into its image, T087/T089); without CP sources
	// there is nothing to build.
	if t033CountSuffix(filepath.Join(repoRoot, "control-plane"), ".java") == 0 {
		t.Skip("blocked: no .java sources under control-plane/ — CP not buildable (cannot push tokens)")
	}

	ctx := context.Background()

	// Register cleanup BEFORE compose-up. If up partially succeeds then
	// fails, t.Fatalf fires and the already-registered cleanup tears the
	// stack down. `compose down` on a never-brought-up project is a no-op.
	t.Cleanup(func() {
		dCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if out, err := t033Compose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// Signal-safe teardown (redteam finding). t.Cleanup fires on
	// t.Fatalf and recovered panics but NOT on signal-induced process
	// death (SIGINT/SIGTERM). Since the stack is brought up detached
	// (up -d below), an orphaned stargate-t033-test project would keep
	// the Tor sidecar's circuit alive — exposing the operator's IP to
	// their entry guard(s) after they believe the test ended. This
	// handler ensures compose-down runs even on Ctrl-C during the long
	// bootstrap or load window. compose-down is idempotent, so a double
	// teardown (this + t.Cleanup on a fatal path) is harmless.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		dCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if out, err := t033Compose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "signal %v: compose down (best-effort): %v\n%s", sig, err, out)
		}
		os.Exit(1)
	}()

	// --- Bring up the full stack ----------------------------------------
	// --build forces a rebuild against current Dockerfiles so the test
	// exercises on-disk state, not a stale cached tag. Scoped to the three
	// services the route needs (T059/T126/T131's set): tor-observer's image
	// is an init-written local image ID, and the example env's placeholder
	// makes a list-less up fail pulling it (T182 live finding).
	t.Log("bringing up tor + data plane + control plane…")
	upCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if out, err := t033Compose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor", "stargate-dp", "stargate-control"); err != nil {
		t.Fatalf("docker compose up: %v\n%s", err, out)
	}

	// --- Wait for Tor bootstrap -----------------------------------------
	// The control-socket exchange mirrors T032/T131:
	// AUTHENTICATE <cookie-hex> then GETINFO status/bootstrap-phase,
	// grepping for PROGRESS=100. The cookie is located via find — robust
	// to the T087 DataDirectory discrepancy (/var/lib/tor/.tor vs
	// /var/lib/tor).
	t.Log("waiting for Tor bootstrap…")
	if err := t033WaitForBootstrap(ctx, t, composeFile, envFile, t033BootWait); err != nil {
		t.Fatalf("Tor did not bootstrap within %s: %v", t033BootWait, err)
	}

	// --- Load the onion via SOCKS5h through port 8881 -------------------
	// Retry within a bounded window to absorb Tor circuit-build + onion
	// rendezvous latency. Admission is not CP-gated (data-model.md §2;
	// T090), so the DP forwards as soon as the listener is up — the
	// retry window is for Tor, not for a route-enable event.
	t.Logf("loading https://%s/ via SOCKS5h through %s …", t033Onion, t033DPAddr)
	body, ok := t033TryLoadOnion(ctx, t, token, t033ReqWait)
	if !ok {
		t.Fatalf("onion load did not succeed within %s", t033ReqWait)
	}
	t.Logf("OK: received %d bytes from %s", len(body), t033Onion)

	// --- Assert Tor established a circuit -------------------------------
	t.Log("querying Tor circuit-status…")
	cs, err := t033CircuitStatus(ctx, composeFile, envFile)
	if err != nil {
		t.Fatalf("circuit-status query: %v", err)
	}
	if !strings.Contains(cs, "BUILT") {
		t.Errorf("expected ≥1 BUILT circuit in circuit-status; got:\n%s", cs)
	} else {
		t.Logf("OK: circuit-status reports established circuit(s)")
	}
}

// t033TryLoadOnion retries the HTTPS GET via SOCKS5h within a bounded
// window, returning the body on the first success. The retry absorbs
// transient Tor circuit-build + onion rendezvous latency. Admission is
// not CP-gated (data-model.md §2; T090), so no route-enable wait is
// involved. Each attempt logs its error so a dead route, auth failure,
// or TLS issue surfaces in the test output for diagnosis.
func t033TryLoadOnion(ctx context.Context, t *testing.T, token string, window time.Duration) ([]byte, bool) {
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		body, err := t033LoadOnion(ctx, token)
		if err == nil {
			return body, true
		}
		t.Logf("load attempt failed (will retry until %s): %v", deadline.Format(time.TimeOnly), err)
		time.Sleep(t033PollEvery)
	}
	return nil, false
}

// t033LoadOnion issues GET https://<reference-onion>/ via SOCKS5h through
// the data plane's loopback port 8881. The SOCKS5 UNAME is the complete
// `sg1:` partition the browser derives for this normal-mode, default-
// container onion navigation (contracts/foundation-boundaries.md; T172/
// T173), via T126's reference-vector-pinned t126PartitionUsername, and
// PASSWD is the bearer token, per contracts/socks5-auth.md
// §"Username/password sub-negotiation".
//
// proxy.SOCKS5 with a domain target uses ATYP=0x03 DOMAIN — SOCKS5h, no
// local DNS resolution of the .onion name (FR-007, Principle III). TLS
// verification is left at the default (no InsecureSkipVerify): a privacy
// tool MUST NOT silently skip cert verification, and DuckDuckGo's onion
// serves a valid certificate.
func t033LoadOnion(ctx context.Context, token string) ([]byte, error) {
	dialer, err := proxy.SOCKS5("tcp", t033DPAddr, &proxy.Auth{
		// Partition — stream-isolation key (not a credential).
		User:     t126PartitionUsername(token, t033ProfileID, t033Onion),
		Password: token, // bearer token — the credential the DP validates
	}, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dialer: %w", err)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		TLSClientConfig: &tls.Config{},
	}
	client := &http.Client{Transport: transport, Timeout: t033ReqDead}

	reqCtx, cancel := context.WithTimeout(ctx, t033ReqDead)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "https://"+t033Onion+"/", nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d (want 200)", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty body")
	}
	return body, nil
}

// t033WaitForBootstrap polls the Tor control port (via
// `docker compose exec tor`) for bootstrap completion. The cookie is
// located via find — robust to the T087 DataDirectory discrepancy.
// Returns nil when PROGRESS=100 is observed.
func t033WaitForBootstrap(ctx context.Context, t *testing.T, composeFile, envFile string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := t033ExecTor(ctx, composeFile, envFile, t033BootstrapProbe)
		if err == nil && strings.Contains(out, "PROGRESS=100") {
			t.Logf("Tor bootstrapped:\n%s", strings.TrimSpace(out))
			return nil
		}
		time.Sleep(t033PollEvery)
	}
	return fmt.Errorf("no PROGRESS=100 within %s", timeout)
}

// t033CircuitStatus queries GETINFO circuit-status via
// `docker compose exec tor`. The response contains one line per circuit;
// a BUILT status means Tor established a usable circuit through the
// network.
func t033CircuitStatus(ctx context.Context, composeFile, envFile string) (string, error) {
	return t033ExecTor(ctx, composeFile, envFile, t033CircuitStatusProbe)
}

// t033BootstrapProbe and t033CircuitStatusProbe are the shell snippets
// run inside the tor container. They mirror T131's t131WaitBootstrapped:
// locate the auth cookie (find — T087), hex-encode it, then drive the
// exchange over tor's private ControlSocket via `nc -q 1 -U`. The
// `find | head -1` is robust to any DataDirectory location (a hardcoded
// path would miss the cookie at /var/lib/tor/.tor/control_auth_cookie).
const (
	t033BootstrapProbe = `COOKIE=$(find /var/lib/tor -name control_auth_cookie 2>/dev/null | head -1)` +
		` && [ -n "$COOKIE" ]` +
		` && HEX=$(od -An -tx1 "$COOKIE" | tr -d ' \n')` +
		` && { printf 'AUTHENTICATE %s\r\n' "$HEX"` +
		`      ; printf 'GETINFO status/bootstrap-phase\r\n'` +
		`      ; printf 'QUIT\r\n'` +
		`      ; } | nc -q 1 -U ` + t033ControlSocket

	t033CircuitStatusProbe = `COOKIE=$(find /var/lib/tor -name control_auth_cookie 2>/dev/null | head -1)` +
		` && [ -n "$COOKIE" ]` +
		` && HEX=$(od -An -tx1 "$COOKIE" | tr -d ' \n')` +
		` && { printf 'AUTHENTICATE %s\r\n' "$HEX"` +
		`      ; printf 'GETINFO circuit-status\r\n'` +
		`      ; printf 'QUIT\r\n'` +
		`      ; } | nc -q 1 -U ` + t033ControlSocket
)

// t033ExecTor runs a shell command inside the tor service container via
// `docker compose exec -T` (the -T disables TTY allocation, required for
// non-interactive/CI contexts). The compose project context resolves the
// service name to the project-scoped container name.
func t033ExecTor(ctx context.Context, composeFile, envFile, shellCmd string) (string, error) {
	dCtx, cancel := context.WithTimeout(ctx, t033ExecDead)
	defer cancel()
	out, err := t033ComposeRaw(dCtx, composeFile, envFile, "exec", "-T", "tor", "sh", "-c", shellCmd)
	return string(out), err
}

// t033Compose runs a docker compose subcommand under the test's project
// name and returns combined output as a string.
func t033Compose(ctx context.Context, composeFile, envFile string, args ...string) (string, error) {
	out, err := t033ComposeRaw(ctx, composeFile, envFile, args...)
	return string(out), err
}

// t033ComposeRaw is the byte-returning core of t033Compose.
func t033ComposeRaw(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	full := append([]string{
		"-p", t033Project,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, full...)...)
	return cmd.CombinedOutput()
}

// t033FindRepoRoot walks up from this test file's source location to find
// the directory containing compose/docker-compose.local.yml. Does NOT
// rely on the working directory — `go test` may be invoked from any cwd
// (CI matrices, IDE runners, container validation paths). Mirrors T019b.
func t033FindRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed — cannot locate test source path")
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "compose", "docker-compose.local.yml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("repo root (containing compose/docker-compose.local.yml) not found by walking up from " + filepath.Dir(thisFile))
	return ""
}

// t033CountSuffix counts files with the given suffix under root (depth-
// unlimited). Used for the "control plane buildable?" content gate.
func t033CountSuffix(root, suffix string) int {
	count := 0
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, suffix) {
			count++
		}
		return nil
	})
	return count
}
