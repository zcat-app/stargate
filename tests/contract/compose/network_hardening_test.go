//go:build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package compose verifies the T162 local topology against the Docker daemon.
// The host-netns DP is not started here: the installer and packet-level tests
// must establish its host policy before any DP process is admitted.
package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	// Aliased because this suite's own package is compose (T180).
	composecli "github.com/zcat-app/stargate/tests/contract/internal/compose"
	// The T181 readiness probe rides the cookie-authenticated control-port
	// helper every live suite shares (FR-012 compose-internal transport).
	"github.com/zcat-app/stargate/tests/contract/tor"
)

const composeProject = "stargate-t162-topology-test"

func TestLocalTorRuntimeTopology(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker CLI unavailable")
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("Docker daemon unavailable: %v: %s", err, out)
	}
	root := findRepoRoot(t)
	composeFile := filepath.Join(root, "compose/docker-compose.local.yml")
	envFile := filepath.Join(root, "compose/env/local.env.example")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		stopCtx, stop := context.WithTimeout(context.Background(), 90*time.Second)
		defer stop()
		if out, err := composecli.Run(stopCtx, composeProject, composeFile, envFile, "down", "-v", "--remove-orphans"); err != nil {
			t.Errorf("cleanup disposable Tor topology: %v: %s", err, out)
		}
	})
	if out, err := composecli.Run(ctx, composeProject, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("start Tor: %v: %s", err, out)
	}
	idBytes, err := composecli.Run(ctx, composeProject, composeFile, envFile, "ps", "-q", "tor")
	if err != nil || strings.TrimSpace(string(idBytes)) == "" {
		t.Fatalf("Tor container missing: %v: %s", err, idBytes)
	}
	id := strings.TrimSpace(string(idBytes))
	var inspected struct {
		HostConfig struct {
			ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
			CapDrop        []string          `json:"CapDrop"`
			SecurityOpt    []string          `json:"SecurityOpt"`
			Memory         int64             `json:"Memory"`
			PidsLimit      *int64            `json:"PidsLimit"`
			Tmpfs          map[string]string `json:"Tmpfs"`
		} `json:"HostConfig"`
		NetworkSettings struct {
			Networks map[string]json.RawMessage `json:"Networks"`
			Ports    map[string]json.RawMessage `json:"Ports"`
		} `json:"NetworkSettings"`
		Mounts []struct {
			Destination string `json:"Destination"`
		} `json:"Mounts"`
	}
	out, err := exec.CommandContext(ctx, "docker", "inspect", id).CombinedOutput()
	if err != nil {
		t.Fatalf("inspect Tor: %v: %s", err, out)
	}
	var result []json.RawMessage
	if err := json.Unmarshal(out, &result); err != nil || len(result) != 1 {
		t.Fatalf("decode Tor inspect: %v", err)
	}
	if err := json.Unmarshal(result[0], &inspected); err != nil {
		t.Fatalf("decode Tor inspect entry: %v", err)
	}
	if len(inspected.NetworkSettings.Networks) != 1 {
		t.Fatalf("Tor network count=%d, want egress only", len(inspected.NetworkSettings.Networks))
	}
	if _, ok := inspected.NetworkSettings.Networks[composeProject+"_stargate-egress"]; !ok {
		t.Fatalf("Tor missing sole egress network: %v", inspected.NetworkSettings.Networks)
	}
	if len(inspected.NetworkSettings.Ports) != 0 {
		t.Fatalf("Tor has published/exposed TCP ports: %v", inspected.NetworkSettings.Ports)
	}
	_, hasTmp := inspected.HostConfig.Tmpfs["/tmp"]
	_, hasRun := inspected.HostConfig.Tmpfs["/run"]
	if !inspected.HostConfig.ReadonlyRootfs || !contains(inspected.HostConfig.CapDrop, "ALL") ||
		!contains(inspected.HostConfig.SecurityOpt, "no-new-privileges:true") ||
		inspected.HostConfig.Memory <= 0 || inspected.HostConfig.PidsLimit == nil || *inspected.HostConfig.PidsLimit <= 0 ||
		!hasTmp || !hasRun {
		t.Fatalf("Tor runtime hardening drift: %+v", inspected.HostConfig)
	}
	for _, mount := range inspected.Mounts {
		if mount.Destination == "/run/stargate-tor-observer" || mount.Destination == "/var/run/docker.sock" {
			t.Fatalf("Tor has forbidden mount %s", mount.Destination)
		}
	}
	// Readiness wait (T181): T152 (046f2dd) removed Docker health metadata
	// (Constitution III; FR-012 "Tor's Docker healthcheck is disabled"), so
	// the pre-T181 Docker health poll is unsatisfiable by construction.
	// Readiness is observed ONLY through the T174-sanctioned channel: a
	// cookie-authenticated control-port probe over the compose-internal
	// exec transport, carrying the suite's original 5-minute deadline.
	// waitForTorBootstrap enforces that deadline across the blocking
	// transport calls themselves (a stalled session is cut AT the
	// deadline; a reply landing after it can never become success) and
	// fails loudly with the last transport diagnostics, never silently.
	cfg := tor.ControlPortConfig{Project: composeProject, ComposeFile: composeFile, EnvFile: envFile}
	if _, err := waitForTorBootstrap(ctx, cfg, time.Now().Add(5*time.Minute), 3*time.Second, torBootstrapProbe); err != nil {
		t.Fatalf("Tor readiness: %v", err)
	}
}

// bootstrapProbeFunc is one authenticated readiness attempt; waitForTorBootstrap
// injects it so the deadline-enforcement regressions can drive a controlled
// transport without Docker.
type bootstrapProbeFunc func(ctx context.Context, cfg tor.ControlPortConfig) (phase string, done bool, err error)

// waitForTorBootstrap polls probe until tor reports PROGRESS=100 or the
// readiness deadline expires. Startup races (cookie not yet written, control
// socket not yet listening) surface as attempt errors absorbed until the
// deadline — the session-establishment poll in control_port_live_test.go is
// the reference shape.
func waitForTorBootstrap(ctx context.Context, cfg tor.ControlPortConfig, deadline time.Time, pollEvery time.Duration, probe bootstrapProbeFunc) (string, error) {
	var lastPhase string
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return lastPhase, fmt.Errorf("readiness wait aborted (%s); last phase %q; last transport error: %v", err, lastPhase, lastErr)
		}
		// The deadline bounds the blocking transport calls themselves, not
		// just the gaps between attempts (T181 round 2, finding 1): each
		// attempt runs under a context capped at the remaining readiness
		// window, so a stalled session is cut AT the deadline.
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return lastPhase, fmt.Errorf("no PROGRESS=100 within the readiness deadline; last phase %q; last transport error: %v", lastPhase, lastErr)
		}
		attemptCtx, cancel := context.WithTimeout(ctx, remaining)
		phase, done, err := probe(attemptCtx, cfg)
		cancel()
		if err == nil {
			lastPhase, lastErr = phase, nil
			// A reply landing after the deadline can never become success.
			if done && !time.Now().After(deadline) {
				return lastPhase, nil
			}
			if done {
				return lastPhase, fmt.Errorf("bootstrap reply arrived after the readiness deadline; last phase %q", lastPhase)
			}
		} else {
			lastErr = err
		}
		time.Sleep(pollEvery)
	}
}

// torBootstrapProbe performs one authenticated control-port readiness
// attempt on a fresh session (ControlPort's discard-after-error rule makes
// reconnect — never same-session retry — the safe shape) and reports the
// last observed bootstrap phase and whether PROGRESS=100 was reached.
func torBootstrapProbe(ctx context.Context, cfg tor.ControlPortConfig) (phase string, done bool, err error) {
	cookie, err := tor.ReadCookie(ctx, cfg)
	if err != nil {
		return "", false, err
	}
	conn, err := tor.Connect(ctx, cfg)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Authenticate(cookie); err != nil {
		return "", false, err
	}
	lines, err := conn.Command("GETINFO status/bootstrap-phase")
	if err != nil {
		return "", false, err
	}
	phase = strings.Join(lines, " | ")
	return phase, strings.Contains(phase, "PROGRESS=100"), nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

// TestReadinessChannelContract pins the suite's readiness observation
// channel (T181; Constitution III / FR-012): readiness must be established
// ONLY through the cookie-authenticated compose-internal control-port
// probe, and Docker health metadata must never be read — T152 (046f2dd)
// removed that journal by design, so a Docker health poll is unsatisfiable
// by construction and rots this opt-in suite red invisibly (the
// docker-cadence family has no periodic green gate). Source-contract
// shape, same family as the torrc byte-golden (T029) and the compose argv
// pins (T121): a resurrected health poll — or a readiness wait that no
// longer rides the control-port bootstrap probe — fails here before the
// suite can rot again. The needles are assembled at runtime so this
// contract's own source cannot satisfy or violate itself.
func TestReadinessChannelContract(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot find test source")
	}
	src, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read suite source: %v", err)
	}
	healthKey := []byte("State" + ".Health")
	if bytes.Contains(src, healthKey) {
		t.Errorf("suite reads Docker health metadata (%s) — removed by T152 (Constitution III); readiness must ride the authenticated control-port probe", healthKey)
	}
	bootstrapProbe := []byte("GETINFO status/" + "bootstrap-phase")
	if !bytes.Contains(src, bootstrapProbe) {
		// Interpolated: the literal must exist ONLY in the production probe
		// call, so this diagnostic cannot satisfy its own assertion (T181
		// round 2, finding 2).
		t.Errorf("suite lacks the authenticated readiness probe (%s over the cookie-authenticated compose-internal channel)", bootstrapProbe)
	}
}

// TestBootstrapDeadlineEnforcement (T181 round 2, finding 1) pins the
// readiness deadline as an enforced bound on the blocking transport calls
// themselves, not just the gaps between attempts: a control session that
// stops replying is cut AT the deadline, and a bootstrap reply physically
// arriving after it can never become success. Hermetic — the injected
// probe stands in for the transport, so no Docker is required.
func TestBootstrapDeadlineEnforcement(t *testing.T) {
	t.Run("StalledTransportIsCutAtDeadline", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		deadline := time.Now().Add(300 * time.Millisecond)
		start := time.Now()
		_, err := waitForTorBootstrap(parent, tor.ControlPortConfig{}, deadline, 20*time.Millisecond,
			func(ctx context.Context, _ tor.ControlPortConfig) (string, bool, error) {
				// A control session that stops replying: the blocking
				// read may only end when the readiness deadline cancels it.
				<-ctx.Done()
				return "", false, ctx.Err()
			})
		if err == nil {
			t.Fatal("stalled transport past the readiness deadline must fail, got success")
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("stalled transport must be cut at the readiness deadline; took %s (deadline 300ms + bounded cleanup)", elapsed)
		}
	})
	t.Run("LateSuccessIsRejected", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		deadline := time.Now().Add(100 * time.Millisecond)
		_, err := waitForTorBootstrap(parent, tor.ControlPortConfig{}, deadline, 10*time.Millisecond,
			func(context.Context, tor.ControlPortConfig) (string, bool, error) {
				// A reply physically arriving after the deadline.
				time.Sleep(250 * time.Millisecond)
				return "NOTICE BOOTSTRAP PROGRESS=100 TAG=done", true, nil
			})
		if err == nil {
			t.Fatal("a bootstrap reply arriving after the readiness deadline must not become success")
		}
	})
}

// fakeTorTransport stands in for the `docker` executable the control-port
// helper spawns: `compose exec -T tor cat <cookie>` returns a fixed cookie,
// `compose exec -T tor nc -U <socket>` speaks just enough control protocol
// for one readiness attempt. T181_FAKE_TOR_STALL selects the phase that stops
// replying. Stalls `exec` into sleep so the process the helper's
// exec.CommandContext kills is the one holding the pipes — a forked sleep
// would keep stdout open past the kill and mask the probe's cancellation.
const fakeTorTransport = `#!/bin/sh
case " $* " in
*" cat "*)
	[ "$T181_FAKE_TOR_STALL" = cookie ] && exec sleep 10
	printf 'fake-cookie-0123456789abcdef0123'
	exit 0 ;;
*" nc "*)
	while IFS= read -r line; do
		case "$line" in
		AUTHENTICATE*)
			[ "$T181_FAKE_TOR_STALL" = auth ] && exec sleep 10
			printf '250 OK\r\n' ;;
		GETINFO*)
			[ "$T181_FAKE_TOR_STALL" = getinfo ] && exec sleep 10
			printf '250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\r\n250 OK\r\n' ;;
		QUIT*)
			printf '250 closing connection\r\n'
			exit 0 ;;
		esac
	done
	exit 0 ;;
esac
echo "fake docker: unexpected argv: $*" >&2
exit 64
`

// TestBootstrapProbeTransportDeadline (T181 acceptance #5) drives the REAL
// torBootstrapProbe through waitForTorBootstrap over a controlled executable
// transport, so the deadline is proven to reach the blocking operations
// themselves: a stall at cookie retrieval, at the AUTHENTICATE reply and at
// the GETINFO reply each fails within the readiness deadline plus a bounded
// cleanup allowance, naming the stalled phase. TestBootstrapDeadlineEnforcement
// pins the wrapper; this pins the probe's context propagation — detaching
// ReadCookie/Connect from the supplied ctx lets the 10s stall run out and
// fails the elapsed bound. The positive control shows the same fake reaches
// PROGRESS=100, so each stall case fails for its stall, not a broken fake.
// Hermetic: the fake shadows docker on PATH; no daemon is contacted.
func TestBootstrapProbeTransportDeadline(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeTorTransport), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	cfg := tor.ControlPortConfig{
		Project:     "t181-fake-transport",
		ComposeFile: filepath.Join(bin, "compose.yml"),
		EnvFile:     filepath.Join(bin, "fake.env"),
	}
	const (
		readinessWindow = 500 * time.Millisecond
		// Cleanup allowance: process kill + pipe EOF + Close's wait on an
		// already-dead session — far below the fake's 10s stall.
		elapsedBound = readinessWindow + 1500*time.Millisecond
	)

	t.Run("PositiveControl", func(t *testing.T) {
		t.Setenv("T181_FAKE_TOR_STALL", "none")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		phase, err := waitForTorBootstrap(ctx, cfg, time.Now().Add(5*time.Second), 50*time.Millisecond, torBootstrapProbe)
		if err != nil {
			t.Fatalf("unstalled fake transport must reach bootstrap completion: %v", err)
		}
		if !strings.Contains(phase, "PROGRESS=100") {
			t.Fatalf("positive control phase = %q, want PROGRESS=100", phase)
		}
	})

	for _, tc := range []struct {
		stall, wantErr, notErr string
	}{
		{stall: "cookie", wantErr: "read control cookie"},
		{stall: "auth", wantErr: "authenticate:"},
		{stall: "getinfo", wantErr: "control port closed mid-reply", notErr: "authenticate:"},
	} {
		t.Run("Stall_"+tc.stall, func(t *testing.T) {
			t.Setenv("T181_FAKE_TOR_STALL", tc.stall)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			start := time.Now()
			_, err := waitForTorBootstrap(ctx, cfg, start.Add(readinessWindow), 50*time.Millisecond, torBootstrapProbe)
			elapsed := time.Since(start)
			if err == nil {
				t.Fatalf("%s stall past the readiness deadline must fail, got success", tc.stall)
			}
			if elapsed > elapsedBound {
				t.Fatalf("%s stall must be cut at the readiness deadline; took %s (bound %s = %s window + cleanup)", tc.stall, elapsed, elapsedBound, readinessWindow)
			}
			if !strings.Contains(err.Error(), tc.wantErr) || (tc.notErr != "" && strings.Contains(err.Error(), tc.notErr)) {
				t.Fatalf("%s stall error does not name the stalled phase (want %q): %v", tc.stall, tc.wantErr, err)
			}
		})
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot find test source")
	}
	for dir := filepath.Dir(source); ; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "compose/docker-compose.local.yml")); err == nil {
			return dir
		}
		if filepath.Dir(dir) == dir {
			t.Fatalf("repository root not found above %s", source)
		}
	}
}
