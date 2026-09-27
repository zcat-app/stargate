//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// stack_smoke_test.go is T131: the full-path stack acceptance — ONE
// authenticated SOCKS5 CONNECT through the data plane's host-published
// 127.0.0.1:8881 to the spec-pinned reference onion, asserting the tunnel
// carries application bytes. It is the structural cure for the T059
// cascade's root cause (the audit of 2026-09-07): the full stack — DP +
// CP + tor with the inter-plane channel up — had never been executed
// before T059's live phase, and every per-defect fix had been validated
// against its own symptom layer instead of the full path (T125 round 1
// was approved, landed, and falsified 49 minutes later). This test makes
// the full path itself the cheap, repeatable validation target: green
// means images build (T122), the host publish is reachable (T125), the
// CP boots (T129), the inter-plane mTLS channel is up and the token
// generation was pushed (T130), the DP authenticates and forwards via
// SOCKS5h (FR-006/FR-007), and onion rendezvous completes.
//
// RED IS THE DESIGNED STATE: T130 is open at landing time — the smoke
// test's AUTH-rejected failure IS its current expected output (test-first
// red for an unfixed product bug). Every stack fix behind it (T130,
// T123, T124) validates by flipping THIS test green, not by per-ticket
// symptom probes.
//
// Deliberately minimal: one assertion covering the whole pyramid above
// it. Isolation semantics live in T059/T126 (same package, same
// machinery); the smoke test asserts the path works once, not how
// streams separate. Bring-up reuses the T059-landed compensations
// (two-phase up: tor bootstrapped before the planes — T124's product
// fix obsoletes the split; token seed with the pre-created keys/
// mountpoint — T123's). Those compensations are DELETED by the product
// fixes that obsolete them, and this file shrinks with them.
//
// Operator prerequisite (T059 §Residue, same runbook): before the live
// run, the init-equivalent provisioning must exist for THIS project's
// volumes — ed25519 keypairs + 32-byte pepper in
// <project>_stargate-keys (cp.priv 0600 5101:5100, dp.priv 0600
// 5102:5100, pubs 0644, pepper 0640 cp:ipc) and the volume-root
// ownership initialisation (stargate-keys 5101:5100 0750,
// stargate-ipc 5102:5100 0770, stargate-control-state /
// stargate-dp-state / stargate-tor-config 0750) — scripts/stargate
// init steps 2–3 scoped to the project's volume names.
//
// stargate:cadence docker — named Docker job
// (STARGATE_TEST_TAGS=docker scripts/verify.sh); the hermetic PR gate
// compile-checks via the go-workspace vet pass and accounts this suite
// SKIP[docker]. Live invocation:
//
//	cd tests/integration && go test -tags docker -run TestStackSmoke -v -timeout 50m
package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

// T131 constants. The compose project is THIS suite's own (never shared
// with a sibling suite — T058a's live-found split-project failure; the
// shared-runner hoist is T121). Deadlines mirror T059's: per-phase up
// windows, bootstrap under the suite's own 5-minute deadline (T124's
// healthcheck window is bypassed by the two-phase bring-up). Stacked
// worst case with T132: up 10m + boot 5m + up 10m + two CONNECT/read
// windows of 13m (cold CP) and 6m (recovery) + stop 0.5m + restart 2m
// = 46.5m. The 48-minute suite context and 50-minute go-test outer bound
// leave cleanup room.
const (
	t131Project = "stargate-t131-test"
	t131DPAddr  = "127.0.0.1:8881" // FR-005; host-published DP loopback

	t131Onion    = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	t131OnionPrt = 443 // served (TLS); T033 proved this port through the DP

	t131UpDead      = 10 * time.Minute
	t131BootDead    = 5 * time.Minute
	t131ConnectWait = 3 * time.Minute
	// As in T173's live fixture, a TCG-emulated JVM gets a separate cold
	// startup budget. Recovery and individual wire/read deadlines stay 3m.
	t131InitialWait = 10 * time.Minute
	t131PollEvery   = 5 * time.Second
	t131StreamPoll  = 2 * time.Second
	t131ExecDead    = 15 * time.Second
	t132StopDead    = 30 * time.Second
	t132RestartDead = 2 * time.Minute
	t131OverallDead = 48 * time.Minute // suite ctx; test -timeout 50m is outer
)

// The independently pinned foundation-boundaries.md reference vector
// calibrates the test client's complete SOCKS partition username.
func TestT131PartitionUsernameReferenceVector(t *testing.T) {
	token := strings.Repeat("0f1e2d3c", 4)
	onion := strings.Repeat("abcd2345", 7) + ".onion"
	const want = "sg1:1940cde7068246610f120ee0926ad88113942aa2e83d71ba649deab843077a06"
	if got := t131PartitionUsername(token, onion); got != want {
		t.Fatalf("foundation-boundaries.md reference username = %q, want %q", got, want)
	}
}

// TestStackSmoke brings up the stack, seeds a token, carries application
// bytes through authenticated SOCKS, then proves T132 DP-only recovery.
func TestStackSmoke(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable: %v\n%s", err, out)
	}

	repoRoot := t131FindRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, p := range []string{composeFile, envFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("required file missing: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), t131OverallDead)
	defer cancel()

	// Signal-safe teardown (T033's redteam finding, carried by both
	// landed siblings): t.Cleanup does NOT run on signal-induced process
	// death, and an orphaned project keeps the tor sidecar's live
	// entry-guard circuits after the operator believes the test ended.
	// compose-down is idempotent, so the double teardown with t.Cleanup
	// is harmless.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		dCtx, dCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dCancel()
		if out, err := t131Compose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "signal %v: compose down (best-effort): %v\n%s", sig, err, out)
		}
		os.Exit(1)
	}()

	// Cleanup BEFORE up (T019b ordering): a partially-successful up must
	// not orphan the project; `down` on a never-upped project is a no-op.
	t.Cleanup(func() {
		dCtx, dCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer dCancel()
		if out, err := t131Compose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// Phase 1: tor up + bootstrapped under this suite's own deadline (the
	// T059-landed compensation for T124's ~150 s healthcheck window; the
	// scoped phase-2 up never recreates the healthy tor container).
	t.Log("phase 1: tor up + bootstrap…")
	upCtx, upCancel := context.WithTimeout(ctx, t131UpDead)
	if out, err := t131Compose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		upCancel()
		t.Fatalf("docker compose up tor: %v\n%s", err, out)
	}
	upCancel()
	t131WaitBootstrapped(t, ctx, composeFile, envFile)

	// Seed the token BEFORE the CP's first start (T059-landed shape:
	// tokens.yaml + pre-created keys/ mountpoint in the config volume,
	// created under compose's labels so down --volumes still reaps it).
	token, err := t059NewToken() // project-agnostic (same module/package)
	if err != nil {
		t.Fatalf("generate bearer token: %v", err)
	}
	if err := t131SeedToken(ctx, token); err != nil {
		t.Fatalf("seed token into %s_stargate-control-config: %v", t131Project, err)
	}

	// Phase 2: the planes (scoped — a list-less up would rebuild tor and
	// re-race its healthcheck window; the T059 live-run finding).
	t.Log("phase 2: data plane + control plane up…")
	up2Ctx, up2Cancel := context.WithTimeout(ctx, t131UpDead)
	defer up2Cancel()
	if out, err := t131Compose(up2Ctx, composeFile, envFile, "up", "-d", "--build", "stargate-dp", "stargate-control"); err != nil {
		t.Fatalf("docker compose up (planes): %v\n%s", err, out)
	}

	// THE assertion: one authenticated CONNECT through the full path,
	// retried within a bounded window (absorbs the CP's argon2id load +
	// ReloadTokens push latency — and, until T130 lands, demonstrates the
	// auth-rejected failure this test exists to catch).
	t.Logf("smoke: authenticated CONNECT through %s to the reference onion…", t131DPAddr)
	conn := t131ConnectWithRetry(t, ctx, composeFile, envFile, token, t131InitialWait)

	// Application bytes through the tunnel: a minimal HTTP request over
	// the established CONNECT (TLS is the onion's problem, not the
	// tunnel's — ANY byte back proves the tunnel carries data; the
	// reference onion's TLS handshake begins with server bytes on write).
	n, err := fmt.Fprintf(conn, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", t131Onion)
	if err != nil || n == 0 {
		t.Fatalf("write through tunnel failed (wrote %d): %v — the CONNECT succeeded but the tunnel does not carry data", n, err)
	}
	one := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(t131ConnectWait))
	if _, err := io.ReadFull(conn, one); err != nil {
		t.Fatalf("no application byte through the tunnel within %s: %v — CONNECT established but the path carries no data (upstream/rendezvous broken)", t131ConnectWait, err)
	}
	t.Logf("OK: full path live — authenticated CONNECT through %s established and carrying application bytes", t131DPAddr)
	_ = conn.Close()

	// T132's live sibling: remove the DP's authority snapshot during a
	// DP-only restart. With CP still running, admission must recover through
	// exact-generation ReloadTokens re-delivery (Constitution Principle II).
	t.Run("T132_DPOnlyRestartRecovery", func(t *testing.T) {
		stopCtx, stopCancel := context.WithTimeout(ctx, t132StopDead)
		defer stopCancel()
		if out, err := t131Compose(stopCtx, composeFile, envFile, "stop", "stargate-dp"); err != nil {
			t.Fatalf("stop only DP: %v\n%s", err, out)
		}
		cp, err := t131Compose(ctx, composeFile, envFile, "ps", "--status", "running", "--quiet", "stargate-control")
		if err != nil || len(strings.TrimSpace(string(cp))) == 0 {
			t.Fatalf("CP must remain running during DP restart: %v\n%s", err, cp)
		}
		// A retained snapshot could make this probe pass without a CP push.
		// Remove exactly the test project's DP snapshot while its process is
		// stopped; keep the CP database and process intact.
		clear := exec.CommandContext(ctx, "docker", "run", "--rm", "--user", "0:0",
			"--entrypoint", "sh", "-v", t131Project+"_stargate-dp-state:/state",
			"stargate/tor:local", "-c",
			"test -f /state/dp-snapshot.json && rm /state/dp-snapshot.json")
		if out, err := clear.CombinedOutput(); err != nil {
			t.Fatalf("remove stopped DP snapshot: %v\n%s", err, out)
		}
		startCtx, startCancel := context.WithTimeout(ctx, t132RestartDead)
		defer startCancel()
		if out, err := t131Compose(startCtx, composeFile, envFile, "up", "-d", "--no-deps", "stargate-dp"); err != nil {
			t.Fatalf("restart only DP: %v\n%s", err, out)
		}
		cp, err = t131Compose(ctx, composeFile, envFile, "ps", "--status", "running", "--quiet", "stargate-control")
		if err != nil || len(strings.TrimSpace(string(cp))) == 0 {
			t.Fatalf("CP stopped during DP-only restart: %v\n%s", err, cp)
		}
		forwarded := t131ConnectWithRetry(t, ctx, composeFile, envFile, token, t131ConnectWait)
		defer forwarded.Close()
		n, err := fmt.Fprintf(forwarded, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", t131Onion)
		if err != nil || n == 0 {
			t.Fatalf("write through recovered tunnel failed (wrote %d): %v", n, err)
		}
		one := make([]byte, 1)
		_ = forwarded.SetReadDeadline(time.Now().Add(t131ConnectWait))
		if _, err := io.ReadFull(forwarded, one); err != nil {
			t.Fatalf("no application byte through recovered tunnel within %s: %v", t131ConnectWait, err)
		}
	})
}

// t131ConnectWithRetry issues the authenticated CONNECT until it
// establishes or the window closes, failing with the T059-style
// classification (AUTH vs ROUTE) and the planes' log tails — the
// diagnostics that name which layer of the pyramid is broken.
func t131ConnectWithRetry(t *testing.T, ctx context.Context, composeFile, envFile, token string, wait time.Duration) net.Conn {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	var lastErr error
	for {
		if waitCtx.Err() != nil {
			t.Fatalf("authentication wait expired: %v (last error: %v)", waitCtx.Err(), lastErr)
		}
		conn, err := t131Connect(waitCtx, token)
		if err == nil {
			return conn
		}
		lastErr = err
		if waitCtx.Err() != nil {
			t.Fatalf("authenticated CONNECT through %s not established within %s: %s\n%s\n%s",
				t131DPAddr, wait, t131Classify(err),
				t131LogTail(t, ctx, composeFile, envFile, "stargate-dp"),
				t131LogTail(t, ctx, composeFile, envFile, "stargate-control"))
		}
		time.Sleep(t131StreamPoll)
	}
}

// t131Connect issues one SOCKS5 CONNECT through the DP: UNAME is the full
// token-keyed first-party partition (foundation-boundaries.md), PASSWD is
// the bearer token, and ATYP=domain keeps destination DNS out of the DP.
func t131Connect(ctx context.Context, token string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", t131DPAddr, &proxy.Auth{
		User:     t131PartitionUsername(token, t131Onion),
		Password: token,
	}, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dialer: %w", err)
	}
	dCtx, cancel := context.WithTimeout(ctx, t131ConnectWait)
	defer cancel()
	return dialer.(proxy.ContextDialer).DialContext(dCtx, "tcp", fmt.Sprintf("%s:%d", t131Onion, t131OnionPrt))
}

// t131PartitionUsername mirrors the browser's bounded JSON tuple for this
// fixed normal-profile/onion fixture; the reference-vector test pins bytes.
func t131PartitionUsername(token, onion string) string {
	message, _ := json.Marshal([]string{
		"stargate-isolation-v1", strings.Repeat("11", 32), "normal", "firefox-default", "onion:" + onion,
	}) // []string has no unsupported values or cycle that can fail Marshal.
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(message)
	return "sg1:" + hex.EncodeToString(mac.Sum(nil))
}

// t131Classify names the broken layer — the T059 classifier's AUTH and
// ROUTE branches (both ROUTE surfaces: published-port reachability and
// upstream refusal).
func t131Classify(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "username/password authentication failed"):
		return "AUTH: SOCKS5 auth rejected — token generation not loaded/pushed (T130: inter-plane channel)?"
	case strings.Contains(msg, "connection refused"):
		return "ROUTE: DP listener unreachable on the published port (T125 surface)"
	case strings.Contains(msg, "unknown error "):
		return "ROUTE: upstream (tor sidecar) refused the CONNECT — rendezvous/descriptor failure (see the DP log tail)"
	default:
		return "UNCLASSIFIED: " + msg
	}
}

// t131LogTail returns a bounded service log tail for failure forensics
// (SafeLogging applies to tor only; the DP/CP logs are startup-class).
func t131LogTail(t *testing.T, ctx context.Context, composeFile, envFile, service string) string {
	t.Helper()
	eCtx, cancel := context.WithTimeout(ctx, t131ExecDead)
	defer cancel()
	out, err := t131Compose(eCtx, composeFile, envFile, "logs", "--tail", "10", service)
	if err != nil {
		return fmt.Sprintf("— %s logs unavailable: %v", service, err)
	}
	return fmt.Sprintf("— %s log tail:\n%s", service, strings.TrimSpace(string(out)))
}

// t131SeedToken provisions this suite's config volume before the CP's
// first start — the T059-landed seed step (minus its redundant FR-017
// shape re-check: both suites share t059NewToken, which guarantees the
// 32-hex shape by construction) with this suite's project:
// create under compose's labels (so down --volumes reaps it), pre-create
// the keys/ mountpoint (T123 compensation), write tokens.yaml (FR-017
// shape) on stdin (token never in argv).
func t131SeedToken(ctx context.Context, token string) error {
	vol := t131Project + "_stargate-control-config"
	create := exec.CommandContext(ctx, "docker", "volume", "create",
		"--label", "com.docker.compose.project="+t131Project,
		"--label", "com.docker.compose.volume=stargate-control-config",
		vol)
	if out, err := create.CombinedOutput(); err != nil {
		return fmt.Errorf("create config volume: %v: %s", err, out)
	}
	tokensYAML := fmt.Sprintf("tokens:\n  - label: t131-smoke\n    token: %s\n", token)
	write := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--user", "0:0",
		"--entrypoint", "sh",
		"-v", vol+":/tgt", "stargate/tor:local",
		"-c", "mkdir -p /tgt/keys && cat > /tgt/tokens.yaml")
	write.Stdin = strings.NewReader(tokensYAML)
	if out, err := write.CombinedOutput(); err != nil {
		return fmt.Errorf("write tokens.yaml into volume: %v: %s", err, out)
	}
	return nil
}

// t131WaitBootstrapped polls Tor's private control socket for PROGRESS=100
// (T162's current torrc contract; this suite's project + deadlines).
func t131WaitBootstrapped(t *testing.T, ctx context.Context, composeFile, envFile string) {
	t.Helper()
	deadline := time.Now().Add(t131BootDead)
	shell := `COOKIE=$(find /var/lib/tor -name control_auth_cookie 2>/dev/null | head -1)` +
		` && [ -n "$COOKIE" ]` +
		` && HEX=$(od -An -tx1 "$COOKIE" | tr -d ' \n')` +
		` && { printf 'AUTHENTICATE %s\r\n' "$HEX"` +
		`      ; printf 'GETINFO status/bootstrap-phase\r\n'` +
		`      ; printf 'QUIT\r\n'` +
		`      ; } | nc -q 1 -U /var/lib/tor/control/tor-control.sock`
	for {
		eCtx, cancel := context.WithTimeout(ctx, t131ExecDead)
		out, err := t131Compose(eCtx, composeFile, envFile, "exec", "-T", "tor", "sh", "-c", shell)
		cancel()
		if err == nil && strings.Contains(string(out), "PROGRESS=100") {
			t.Logf("OK: tor bootstrapped")
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("tor did not reach PROGRESS=100 within %s (last: %q, err: %v)", t131BootDead, strings.TrimSpace(string(out)), err)
		}
		time.Sleep(t131PollEvery)
	}
}

// t131Compose runs a compose subcommand under this suite's project.
func t131Compose(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	full := append([]string{
		"compose", "-p", t131Project,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	return exec.CommandContext(ctx, "docker", full...).CombinedOutput()
}

// t131FindRepoRoot walks up from this file to compose/docker-compose.local.yml
// (T033's shape; cwd-independent).
func t131FindRepoRoot(t *testing.T) string {
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
	t.Fatal("repo root not found by walking up from " + filepath.Dir(thisFile))
	return ""
}
