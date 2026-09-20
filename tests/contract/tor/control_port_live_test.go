//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// control_port_live_test.go is T062's live self-test: it gates the Go
// control-port client (control_port.go) against the production tor image,
// cold volume — the same posture live_sidecar_test.go (T032/T087) gates the
// shell-path exchange with. T032 proved the AUTHENTICATE+GETINFO exchange
// works from a shell; this suite proves the GO client path a US2 depends
// on: ReadCookie from the authoritative path (invariant #11), Connect over
// the in-container nc transport (FR-012 — no host reachability), a single
// interleaved session carrying many sequential commands (M3), and reply
// parsing against real tor shapes (M4), including GETINFO circuit-status —
// the surface every T058/T058a/T059–T061 assertion reads through.
//
// stargate:cadence docker — this suite BRINGS UP the tor service and needs
// the live Tor network for bootstrap, so it is build-tagged out of the
// hermetic PR gate and runs in the named Docker job
// (`STARGATE_TEST_TAGS=docker scripts/verify.sh`), or manually:
//
//	cd tests/contract && go test -tags docker ./tor/ -run TestControlPortLive -v -timeout 20m
//
// Skip guards mirror T019b/T032 (docker CLI absent / daemon unreachable).
package tor

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cpComposeProject namespaces every compose invocation this suite issues so
// it never collides with operator-authored state or sibling suites
// (stargate-t019b-test, stargate-t032-test). Pre-registered cleanup tears
// the project down regardless of which subtest failed.
const cpComposeProject = "stargate-t062-test"

const (
	cpUpDeadline      = 5 * time.Minute  // compose build + start (mirrors T019b/T032)
	cpBootDeadline    = 5 * time.Minute  // tor bootstrap on the live network (T032's deadline)
	cpPollEvery       = 2 * time.Second  // control-port poll cadence (T032's pace)
	cpCircuitGrace    = 90 * time.Second // BUILT-circuit wait after PROGRESS=100
	cpOverallDeadline = 18 * time.Minute // whole-suite ctx (test -timeout 20m is the outer bound)
)

// TestControlPortLive — see the file header for what each subtest pins
// (T062 §Acceptance #3, cases (a)–(e)).
func TestControlPortLive(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cpOverallDeadline)
	defer cancel()

	repoRoot := findRepoRoot(t) // same package under -tags docker (port_exposure_test.go)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, p := range []string{composeFile, envFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("required file missing: %v", err)
		}
	}

	// Cleanup BEFORE up (T019b's ordering rationale: a partially-successful
	// up must not orphan the project when the subtest aborts).
	t.Cleanup(func() {
		downCtx, downCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer downCancel()
		if out, err := cpCompose(downCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	upCtx, upCancel := context.WithTimeout(ctx, cpUpDeadline)
	defer upCancel()
	if out, err := cpCompose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("docker compose up -d --build tor: %v\n%s", err, out)
	}

	cfg := ControlPortConfig{Project: cpComposeProject, ComposeFile: composeFile, EnvFile: envFile}

	var (
		conn   *ControlPort
		cookie []byte
	)
	t.Cleanup(func() {
		if conn != nil {
			_ = conn.Close()
		}
	})

	// (a) LiveAuthenticatesWithCookieFromVolume — ReadCookie out of the
	// running container (the invariant-#11 path; the T087 wrong-path
	// regression surfaces here as a loud read failure), then Connect +
	// Authenticate on the exec/nc transport. Polled to a deadline: tor
	// writes the cookie and starts listening during startup, so a first
	// attempt inside that window may race — the poll absorbs it without
	// weakening the assertion (anything still failing at the deadline is a
	// hard failure with the last error attached).
	t.Run("LiveAuthenticatesWithCookieFromVolume", func(t *testing.T) {
		deadline := time.Now().Add(cpBootDeadline)
		var lastErr error
		for {
			if time.Now().After(deadline) {
				t.Fatalf("no authenticated control session within %s (cookie read + connect + AUTHENTICATE): %v",
					cpBootDeadline, lastErr)
			}
			var err error
			var c *ControlPort
			cookie, err = ReadCookie(ctx, cfg)
			if err == nil {
				c, err = Connect(ctx, cfg)
				if err == nil {
					err = c.Authenticate(cookie)
					if err == nil {
						conn = c
						break
					}
				}
				if c != nil {
					_ = c.Close()
				}
			}
			lastErr = err
			time.Sleep(cpPollEvery)
		}
		if len(cookie) == 0 {
			t.Fatal("authenticated session but cookie empty — impossible state")
		}
		t.Logf("OK: cookie (%d bytes) read from %s and AUTHENTICATE accepted", len(cookie), CookieAuthPath)
	})

	// Guard for the remaining subtests: they share the session (a) built.
	authed := func(t *testing.T) {
		if conn == nil {
			t.Fatal("no authenticated session — LiveAuthenticatesWithCookieFromVolume failed")
		}
	}

	// (b) LiveGETCONFControlSocketRoundTrip — one command, one parsed reply:
	// GETCONF ControlSocket must report the invariant-#3 private listener. Proves
	// framing + parsing against a real tor reply (M4 at runtime).
	t.Run("LiveGETCONFControlSocketRoundTrip", func(t *testing.T) {
		authed(t)
		lines, err := conn.Command("GETCONF ControlSocket")
		if err != nil {
			t.Fatalf("GETCONF ControlSocket: %v", err)
		}
		if len(lines) == 0 || !strings.Contains(strings.Join(lines, "\n"), "ControlSocket=/var/lib/tor/control/tor-control.sock") {
			t.Errorf("GETCONF ControlSocket reply %q does not report the invariant-#3 private socket", lines)
		} else {
			t.Logf("OK: GETCONF ControlSocket → %q", lines)
		}
	})

	// (c) LiveBootstrapPollViaSession — MANY sequential Commands on ONE
	// session until PROGRESS=100. This is the interleaved request/response
	// shape (M3): a dump-then-read regression deadlocks or desyncs exactly
	// here, and the subtest deadline turns it into a named failure.
	t.Run("LiveBootstrapPollViaSession", func(t *testing.T) {
		authed(t)
		deadline := time.Now().Add(cpBootDeadline)
		var last string
		for {
			lines, err := conn.Command("GETINFO status/bootstrap-phase")
			if err != nil {
				t.Fatalf("GETINFO status/bootstrap-phase mid-poll: %v (last: %s)", err, last)
			}
			last = strings.Join(lines, " | ")
			if strings.Contains(last, "PROGRESS=100") {
				t.Logf("OK: bootstrapped: %s", truncate(last))
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("tor did not reach PROGRESS=100 within %s; last phase: %s", cpBootDeadline, truncate(last))
			}
			time.Sleep(cpPollEvery)
		}
	})

	// (d) LiveCircuitStatusParses — post-bootstrap GETINFO circuit-status,
	// the exact surface T058/T058a/T059–T061 read circuit IDs through,
	// parsed through the data-block path (dot-stuffing included). After
	// PROGRESS=100 tor builds client circuits unprompted; ≥1 BUILT entry
	// must appear within the grace window.
	t.Run("LiveCircuitStatusParses", func(t *testing.T) {
		authed(t)
		deadline := time.Now().Add(cpCircuitGrace)
		var lines []string
		var err error
		built := false
		for {
			lines, err = conn.Command("GETINFO circuit-status")
			if err != nil {
				t.Fatalf("GETINFO circuit-status: %v", err)
			}
			for _, ln := range lines {
				if strings.Contains(ln, " BUILT ") {
					built = true
					break
				}
			}
			if built || time.Now().After(deadline) {
				break
			}
			time.Sleep(cpPollEvery)
		}
		if !built {
			t.Errorf("no BUILT circuit in circuit-status within %s of bootstrap (%d reply lines) — "+
				"tor built no client circuits; US2 consumers would read an empty isolation surface",
				cpCircuitGrace, len(lines))
			return
		}
		t.Logf("OK: circuit-status parsed; %d reply lines, BUILT present", len(lines))
	})

	// (e) LiveAuthFailureStaysSecret — a deliberately wrong cookie must
	// fail with an error that names the failure and NEVER echoes cookie
	// bytes: not the bad hex we sent, and not the real cookie's hex (M5).
	// Fresh session: tor rejects and closes on failed AUTHENTICATE, so the
	// main session must not be the one holding the bag.
	t.Run("LiveAuthFailureStaysSecret", func(t *testing.T) {
		authed(t)
		bad := bytes.Repeat([]byte{0xa5}, 32)
		badHex := hex.EncodeToString(bad)
		realHex := hex.EncodeToString(cookie)
		c, err := Connect(ctx, cfg)
		if err != nil {
			t.Fatalf("Connect (second session): %v", err)
		}
		defer c.Close()
		authErr := c.Authenticate(bad)
		if authErr == nil {
			t.Fatal("AUTHENTICATE with a wrong cookie succeeded — cookie auth is not actually enforced (invariant #4 regression)")
		}
		if strings.Contains(authErr.Error(), badHex) {
			t.Errorf("auth-failure error leaks the attempted cookie hex (M5 violation): %s", truncate(authErr.Error()))
		}
		if strings.Contains(authErr.Error(), realHex) {
			t.Errorf("auth-failure error leaks the REAL cookie hex (M5 violation): %s", truncate(authErr.Error()))
		}
		t.Logf("OK: rejected cookie auth: %s", truncate(authErr.Error()))
	})
}

// cpCompose runs `docker compose -p <cpComposeProject> …` — same shape as
// T019b's dockerCompose, which bakes ITS project const in; re-implemented
// for this suite's own project name (the T032 re-implementation precedent).
// A future hoist can parameterize the project across all three.
func cpCompose(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	full := append([]string{
		"compose", "-p", cpComposeProject,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	return exec.CommandContext(ctx, "docker", full...).CombinedOutput()
}
