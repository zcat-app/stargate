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
// Timeouts (T208). Three separate allowances follow compose-up, so that
// none consumes another's budget:
//
//   - bootstrap can take several minutes on a cold guard selection;
//   - token delivery: the data plane authenticates no request until the
//     control plane's first delivery is acknowledged, and that took 97 s
//     from control-plane start in the emulated guest (2026-10-04
//     measurement, specs/001-tor-route/evidence/T208-live-results.json).
//     The test waits for `scripts/stargate status` to read ACKNOWLEDGED
//     within its own allowance; expiry fails the test and names token
//     delivery. Admission is still not gated on a sidecar event
//     (data-model.md §2; Principle II; T090): this wait is for the
//     credential, not for a route-enable signal;
//   - the retry window is for Tor alone and opens at the acknowledgement.
//     390 s fits three attempts that Tor fails after its 120 s
//     SocksTimeout. An attempt already running when the window closes
//     finishes.
//
// The per-attempt client timeout is the data plane's upstream deadline
// (contracts/socks5-auth.md §"Deadlines" row 1, mirrored below because this
// module cannot import the data plane's internal constant) plus an
// allowance for TLS and page transfer, so a slow attempt ends with the
// data plane's reply class and not with this client's own timeout.
//
// Worst case after compose-up: bootstrap 5 m + delivery 5 m + window
// 6.5 m + one in-flight attempt 5.2 m + control 5.2 m ≈ 27 m; with the
// 10 m compose-up bound the go-test timeout must exceed 37 m.
const (
	t033Project       = "stargate-t033-test"
	t033Onion         = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	t033DPAddr        = "127.0.0.1:8881"
	t033UpstreamDead  = 250 * time.Second                    // the data plane's upstream deadline (contract row 1)
	t033TransferSlack = 60 * time.Second                     // TLS handshake + page transfer after the SOCKS reply
	t033ReqDead       = t033UpstreamDead + t033TransferSlack // per-attempt client timeout
	t033ReqWait       = 390 * time.Second                    // retry window for the onion load, opened at ACKNOWLEDGED
	t033DeliveryWait  = 5 * time.Minute                      // token delivery to read ACKNOWLEDGED after bootstrap
	t033StatusDead    = 60 * time.Second                     // one `scripts/stargate status` call (it bounds each Docker call itself)
	t033BootWait      = 5 * time.Minute                      // Tor bootstrap (cold guard selection)
	t033ExecDead      = 15 * time.Second                     // docker compose exec deadline (nc control-socket probe)
	t033PollEvery     = 5 * time.Second

	// t033ControlSocket is tor's only control endpoint (torrc contract
	// invariant #3; T162 removed TCP 9051).
	t033ControlSocket = "/var/lib/tor/control/tor-control.sock"
)

// t033ProfileID is the partition's fixed browser-profile id (the
// foundation-boundaries reference vector's).
var t033ProfileID = strings.Repeat("11", 32)

// TestOnionLoad is the US1 MVP gate (T033): bring up the full
// local-profile stack, wait for token delivery to be acknowledged, load
// the spec's reference onion through port 8881 via SOCKS5h, and assert
// (a) page bytes received and (b) Tor reports an established circuit.
// After the verdict it loads T059's second onion once as a control and
// logs the result; the control never changes the verdict (T208).
// Test-first per Constitution Principle VII —
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
	// The gate first waits, within its own allowance, for the control
	// plane's token delivery to read ACKNOWLEDGED: until then the data
	// plane denies every request, which is not what the retry window
	// measures. The window then retries within a bound that absorbs Tor's
	// descriptor fetch + rendezvous latency. Admission is not gated on a
	// sidecar event (data-model.md §2; T090) — the retry window is for
	// Tor, not for a route-enable event.
	t.Logf("loading https://%s/ via SOCKS5h through %s …", t033Onion, t033DPAddr)
	gate := t033Gate{
		deliveryStatus: func(ctx context.Context) (int, string, error) {
			return t033DeliveryStatus(ctx, repoRoot, composeFile, envFile)
		},
		loadReference: func(ctx context.Context) ([]byte, error) { return t033LoadOnion(ctx, token) },
		loadControl:   func(ctx context.Context) error { return t033LoadControl(ctx, token) },
		now:           time.Now,
		sleep:         time.Sleep,
		logf:          t.Logf,
		deliveryWait:  t033DeliveryWait,
		window:        t033ReqWait,
		poll:          t033PollEvery,
	}
	body, err := gate.run(ctx)
	if err != nil {
		t.Fatalf("%v", err)
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

// t033Gate is the timed part of TestOnionLoad that follows Tor bootstrap,
// with its effects injected so the gate logic runs hermetically in
// onion_load_gate_test.go (T208). deliveryStatus is one `scripts/stargate
// status` call (exit code, printed state); loadReference is one attempt at
// the reference onion; loadControl is the single control load.
type t033Gate struct {
	deliveryStatus func(ctx context.Context) (exit int, state string, err error)
	loadReference  func(ctx context.Context) ([]byte, error)
	loadControl    func(ctx context.Context) error
	now            func() time.Time
	sleep          func(time.Duration)
	logf           func(format string, args ...any)
	deliveryWait   time.Duration
	window         time.Duration
	poll           time.Duration
}

// run is the gate: wait for token delivery, retry the reference onion
// within the window, then load the control once. The returned verdict is
// the reference onion's alone (spec.md User Story 1); the control result
// is logged for diagnosis and never returned.
func (g t033Gate) run(ctx context.Context) ([]byte, error) {
	if err := g.awaitDelivery(ctx); err != nil {
		return nil, err
	}
	body, err := g.loadWithinWindow(ctx)
	started := g.now()
	controlErr := g.loadControl(ctx)
	g.logf("T033 control onion (not part of the verdict): class=%s duration=%s err=%v",
		t033ReplyClass(controlErr), g.now().Sub(started).Round(time.Millisecond), controlErr)
	return body, err
}

// awaitDelivery polls `scripts/stargate status` until it exits 0
// (ACKNOWLEDGED). Exits 20 (state unavailable), 30 (PENDING), 50 (UNKNOWN)
// and 70 (Docker did not answer in time) mean not yet. Any other exit, a
// status command that could not run, or expiry of the allowance is an
// error that names token delivery, so a delivery problem is never reported
// as an onion-load failure. The allowance is a hard bound: each status
// call's context ends with it, no call starts once it is spent, and an
// answer that arrives after it — an acknowledgement included — is expiry.
func (g t033Gate) awaitDelivery(ctx context.Context) error {
	started := g.now()
	deadline := started.Add(g.deliveryWait)
	lastExit, lastState := -1, "no answer"
	expired := func() error {
		return fmt.Errorf("token delivery was not ACKNOWLEDGED within %s (last `stargate status` exit %d: %s)",
			g.deliveryWait, lastExit, lastState)
	}
	for {
		remaining := deadline.Sub(g.now())
		if remaining <= 0 {
			return expired()
		}
		callCtx, cancel := context.WithTimeout(ctx, remaining)
		exit, state, err := g.deliveryStatus(callCtx)
		cancel()
		if err == nil {
			lastExit, lastState = exit, state
		}
		if !g.now().Before(deadline) {
			return expired()
		}
		if err != nil {
			return fmt.Errorf("token delivery: `stargate status` could not run: %w", err)
		}
		switch exit {
		case 0:
			g.logf("T033 token delivery: %s after %s", state, g.now().Sub(started).Round(time.Millisecond))
			return nil
		case 20, 30, 50, 70: // not yet
		default:
			return fmt.Errorf("token delivery: `stargate status` exit %d (%s) is not a not-yet state", exit, state)
		}
		g.sleep(min(g.poll, deadline.Sub(g.now())))
	}
}

// loadWithinWindow retries the HTTPS GET via SOCKS5h within the window,
// returning the body on the first success. The retry absorbs Tor's
// descriptor fetch + onion rendezvous latency. No attempt starts after the
// window has closed; one already running finishes. Each attempt logs its
// duration and reply class (the live record T208 acceptance 8 needs) and
// its error, so a dead route, an auth denial or a TLS issue surfaces in
// the test output for diagnosis.
func (g t033Gate) loadWithinWindow(ctx context.Context) ([]byte, error) {
	deadline := g.now().Add(g.window)
	for n := 1; g.now().Before(deadline); n++ {
		started := g.now()
		body, err := g.loadReference(ctx)
		g.logf("T033 attempt %d: class=%s duration=%s", n, t033ReplyClass(err), g.now().Sub(started).Round(time.Millisecond))
		if err == nil {
			return body, nil
		}
		g.logf("load attempt failed (will retry until %s): %v", deadline.Format(time.TimeOnly), err)
		g.sleep(g.poll)
	}
	return nil, fmt.Errorf("onion load did not succeed within %s", g.window)
}

// t033ReplyClass labels one attempt's outcome for the live record. The
// SOCKS5 replies are read from x/net's error text (the surface
// forward/tor.go's classify and t059ClassifyDialErr key on; pinned against
// real client bytes by TestT033ReplyClassFromRealClientErrors): 0x04 is
// Tor's failure reply relayed as ROUTE_REFUSED, 0x06 the data plane's own
// deadline, 0x03 an unreachable sidecar. "other" covers TLS, HTTP and
// transfer errors.
func t033ReplyClass(err error) string {
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "username/password authentication failed"):
		return "auth-denied"
	case strings.Contains(msg, "unknown error network unreachable"):
		return "0x03"
	case strings.Contains(msg, "unknown error host unreachable"):
		return "0x04"
	case strings.Contains(msg, "unknown error TTL expired"):
		return "0x06"
	case strings.Contains(msg, "unknown error "):
		return "socks-reply-other"
	case strings.Contains(msg, "connection refused"):
		return "listener-unreachable"
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(msg, "context deadline exceeded") || strings.Contains(msg, "Client.Timeout"):
		return "client-timeout"
	default:
		return "other"
	}
}

// t033DeliveryStatus runs `scripts/stargate status` once and returns its
// exit code and its first output line (validated vocabulary only; the
// command never prints token material). It is addressed to this test's
// own compose project through STARGATE_PROJECT, STARGATE_COMPOSE_FILE and
// STARGATE_ENV_FILE; pointing the env file at the tracked example means
// the command's env-file bootstrap finds it present and creates nothing
// in the checkout. The call ends with ctx (the gate passes the remaining
// delivery allowance) or after t033StatusDead, whichever is sooner.
func t033DeliveryStatus(ctx context.Context, repoRoot, composeFile, envFile string) (int, string, error) {
	sCtx, cancel := context.WithTimeout(ctx, t033StatusDead)
	defer cancel()
	cmd := exec.CommandContext(sCtx, "bash", filepath.Join(repoRoot, "scripts", "stargate"), "status")
	cmd.Env = append(os.Environ(),
		"STARGATE_PROJECT="+t033Project,
		"STARGATE_COMPOSE_FILE="+composeFile,
		"STARGATE_ENV_FILE="+envFile,
	)
	out, err := cmd.Output()
	state, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, state, nil
	case sCtx.Err() != nil:
		return 0, "", fmt.Errorf("no answer within its bound (%s per call, or what was left of the delivery allowance): %w", t033StatusDead, sCtx.Err())
	case errors.As(err, &exitErr) && exitErr.ExitCode() > 0:
		return exitErr.ExitCode(), state, nil
	default:
		return 0, "", err
	}
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
	return t033Fetch(ctx, token, t033Onion, "https://"+t033Onion+"/")
}

// t033LoadControl loads the second onion T059 uses (t059OnionB, plain
// HTTP on port 80) once through the same port 8881, with that onion's own
// partition username so it shares no circuit with the reference load. It
// tells a failure of the reference onion apart from a route that reaches
// no onion at all; TestOnionLoad's verdict does not depend on it.
func t033LoadControl(ctx context.Context, token string) error {
	_, err := t033Fetch(ctx, token, t059OnionB, fmt.Sprintf("http://%s:%d/", t059OnionB, t059OnionBPrt))
	return err
}

// t033Fetch issues one GET for url through the data plane with the
// partition username of onion (the first-party site of the navigation).
func t033Fetch(ctx context.Context, token, onion, url string) ([]byte, error) {
	dialer, err := proxy.SOCKS5("tcp", t033DPAddr, &proxy.Auth{
		// Partition — stream-isolation key (not a credential).
		User:     t126PartitionUsername(token, t033ProfileID, onion),
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
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
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
