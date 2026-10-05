// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// stream_isolation_dp_uname_test.go is T126: the runtime gate for the data
// plane's UNAME-forwarding contract (FR-007) as the load-bearing hop of
// FR-002's per-first-party isolation. It issues two PARALLEL authenticated
// SOCKS5 CONNECTs through the DP's loopback port 8881 to the SAME real
// onion, with two DISTINCT complete `sg1:` partition usernames
// (contracts/foundation-boundaries.md), and asserts at Tor's control
// socket that the two streams attached to distinct, non-zero, BUILT
// circuits.
//
// Why same target (T059's honest-mechanism note): two DIFFERENT onion
// destinations force distinct rendezvous circuits regardless of
// credentials, so T059 cannot see a DP that fused, dropped or
// constant-folded the upstream username. With one destination the only
// thing keeping the streams apart is tor's IsolateSOCKSAuth acting on the
// credential the DP forwards (forward/tor.go dialUpstream: username
// intact, empty password). A fusing DP presents one credential twice and
// tor consolidates both streams onto one circuit — T060's live-pinned
// behaviour — so the distinct-circuit assertion fails.
//
// Calibration control (the credential-fusion failure mode, reproduced):
// the same machinery then sends one partition twice through the DP and
// must observe ONE shared circuit. Without it, a green distinct-circuit
// result could mean "tor built two rendezvous circuits anyway", not "the
// DP kept the credentials apart"; a failing control marks this run
// uncalibrated rather than green.
//
// The first pair varies only the browser-profile id (the production way one
// target gets two usernames: distinct profiles, modes or containers). T155
// adds the device (second bearer token) and first-party-site axes as further
// subtests of this stack (partition_axes_test.go), one axis per pair.
// The helper is pinned to the foundation-boundaries reference vector by a
// hermetic test below, so a drift in the tuple shape fails in the PR gate.
//
// Circuits are read through the landed T062 control helper
// (tests/contract/tor, Unix ControlSocket since T162) rather than T059's
// shell-level t059ControlProbe (`nc -U`, T182). Two streams to
// one target cannot be attributed by target string, so the assertion
// counts exactly two live streams at the target and compares their
// circuit IDs (T060's machinery); no attribution is needed.
//
// OPERATOR PREREQUISITES (T059/T131 runbook, plus the current Local
// topology): run on a disposable Linux Docker host or VM
// (tests/live-e2e/local-topology/README.md) with the `stargate-dp`
// AppArmor profile and owner rules installed, and the init-equivalent
// key/pepper and volume-root provisioning (scripts/stargate init steps
// 2–3) done for THIS project's volumes. The harness automates only the
// tokens.yaml seed, the keys/ mountpoint and the two-phase bring-up.
//
// stargate:cadence release — T059's cadence: real Tor network, a live
// onion service, Docker. The hermetic PR gate compiles and vets this file
// and runs the reference-vector test; the live body env-skips. Live:
//
//	cd tests/integration && STARGATE_RUN_NETWORK_TESTS=1 \
//		go test -run TestStreamIsolationDPUNAMEForwarding -v -timeout 50m
package integration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

	"golang.org/x/net/proxy"

	tor "github.com/zcat-app/stargate/tests/contract/tor"
)

// T126 constants. The project is this suite's own (cross-suite isolation;
// T058a's split-project finding). Deadlines follow T131: the first pair
// absorbs the CP's cold start (10m), the calibration pair gets T059's 3m.
// Stacked worst case: up 10m + boot 5m + up 10m + connect 10m + streams
// 1.5m + drain 1.5m + connect 3m + streams 1.5m = 42.5m under a 45m suite
// context and a 50m go-test outer bound.
const (
	t126Project = "stargate-t126-test"
	t126DPAddr  = "127.0.0.1:8881" // FR-005; host-loopback DP listener

	// Spec-pinned reference onion (spec.md §"User Story 1"; port 443 proven
	// through the DP by T033/T131). Same constant as T059's target A.
	t126Onion    = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	t126OnionPrt = 443

	t126UpDead       = 10 * time.Minute
	t126BootDead     = 5 * time.Minute
	t126InitialWait  = 10 * time.Minute // cold CP: token load + ReloadTokens push (T131)
	t126ConnectWait  = 3 * time.Minute  // per-dial window after the CP is warm
	t126StreamWait   = 90 * time.Second
	t126DrainWait    = 90 * time.Second
	t126PollEvery    = 5 * time.Second
	t126StreamPoll   = 2 * time.Second
	t126ExecDead     = 15 * time.Second
	t126OverallDead  = 45 * time.Minute
	t126PartitionLen = 68 // "sg1:" + 64 hex (foundation-boundaries.md)
)

// Profile ids for the three partitions: two distinct ones for the
// assertion and a third, unused by it, for the calibration pair — so the
// control's circuit can never be one the assertion pair already built.
var (
	t126ProfileA   = strings.Repeat("aa", 32)
	t126ProfileB   = strings.Repeat("bb", 32)
	t126ProfileCal = strings.Repeat("cc", 32)
)

// TestT126PartitionUsernameReferenceVector pins the harness's partition
// derivation to the independently computed foundation-boundaries.md vector.
func TestT126PartitionUsernameReferenceVector(t *testing.T) {
	token := strings.Repeat("0f1e2d3c", 4)
	onion := strings.Repeat("abcd2345", 7) + ".onion"
	const want = "sg1:1940cde7068246610f120ee0926ad88113942aa2e83d71ba649deab843077a06"
	if got := t126PartitionUsername(token, strings.Repeat("11", 32), onion); got != want {
		t.Fatalf("foundation-boundaries.md reference username = %q, want %q", got, want)
	}
}

// t126SignalChildEnv selects the child-process role of
// TestT126SignalTrapReleasedAfterStop. Real signals are exercised only in
// that child: under -tags docker the sibling suites leave SIGTERM handlers
// registered that tear down and os.Exit(1), so a synthetic signal to the
// shared test process would kill it mid-run (round-2 review).
const t126SignalChildEnv = "STARGATE_T126_SIGNAL_CHILD"

// Child output markers the parent asserts on.
const (
	t126MarkTeardown = "T126-TEARDOWN"
	t126MarkExit     = "T126-EXIT"
	t126MarkNextDone = "NEXT-CLEANUP-DONE"
	t126ChildExit    = 3 // the injected T126 exit status, distinct from test failures
)

// TestT126SignalTrapReleasedAfterStop pins the teardown handler's
// lifetime in an isolated child process (the test binary re-executed with
// t126SignalChildEnv). "active": the installed trap tears down and exits
// on SIGTERM (positive control). "stopped": after stop, a subsequent
// handler receives SIGTERM and completes a deliberately delayed cleanup
// with no T126 callback and no premature exit. The parent never receives a
// synthetic signal, and a parent-side sentinel checks that.
func TestT126SignalTrapReleasedAfterStop(t *testing.T) {
	if mode := os.Getenv(t126SignalChildEnv); mode != "" {
		t126SignalChild(mode) // never returns
	}
	sentinel := make(chan os.Signal, 1)
	signal.Notify(sentinel, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sentinel)

	run := func(t *testing.T, mode string) (string, int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestT126SignalTrapReleasedAfterStop$", "-test.count=1")
		cmd.Env = append(os.Environ(), t126SignalChildEnv+"="+mode)
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("child %s did not run: %v\n%s", mode, err, out)
			}
			code = ee.ExitCode()
		}
		return string(out), code
	}

	t.Run("ActiveTrapHandlesSignal", func(t *testing.T) {
		out, code := run(t, "active")
		if code != t126ChildExit || !strings.Contains(out, t126MarkTeardown) || !strings.Contains(out, t126MarkExit) {
			t.Fatalf("installed trap did not tear down and exit on SIGTERM (exit %d) — control is uncalibrated:\n%s", code, out)
		}
	})

	t.Run("StoppedTrapIgnoresLaterSignal", func(t *testing.T) {
		out, code := run(t, "stopped")
		if code != 0 || !strings.Contains(out, t126MarkNextDone) ||
			strings.Contains(out, t126MarkTeardown) || strings.Contains(out, t126MarkExit) {
			t.Fatalf("stopped T126 trap acted on a later signal or preempted the next handler's cleanup (exit %d):\n%s", code, out)
		}
	})

	select {
	case sig := <-sentinel:
		t.Fatalf("parent test process received %v — signals must stay inside the child", sig)
	default:
	}
}

// t126SignalChild is the child-process body; it always ends in os.Exit.
func t126SignalChild(mode string) {
	teardown := func(os.Signal) { fmt.Println(t126MarkTeardown) }
	exit := func(int) {
		fmt.Println(t126MarkExit)
		os.Exit(t126ChildExit)
	}
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		fmt.Println("find own process:", err)
		os.Exit(1)
	}
	switch mode {
	case "active":
		_ = t126TrapSignals(teardown, exit)
		_ = self.Signal(syscall.SIGTERM)
		time.Sleep(5 * time.Second) // the trap's exit ends the child first
		fmt.Println("active trap never exited")
		os.Exit(1)
	case "stopped":
		stop := t126TrapSignals(teardown, exit)
		stop()
		next := make(chan os.Signal, 1)
		signal.Notify(next, syscall.SIGTERM)
		_ = self.Signal(syscall.SIGTERM)
		select {
		case <-next:
		case <-time.After(5 * time.Second):
			fmt.Println("subsequent handler never received SIGTERM")
			os.Exit(1)
		}
		// Deliberately delayed cleanup: a leaked T126 handler would print and
		// exit during this window, preempting the marker below.
		time.Sleep(500 * time.Millisecond)
		fmt.Println(t126MarkNextDone)
		os.Exit(0)
	}
	fmt.Println("unknown child mode:", mode)
	os.Exit(1)
}

// TestT126ControlPhaseDeadlines pins that a control transport which
// accepts a command but never replies cannot hold a poll past its phase
// budget, and that the transport is released (its context cancelled).
// Positive controls prove the same loops succeed on replying transports.
func TestT126ControlPhaseDeadlines(t *testing.T) {
	const budget = 300 * time.Millisecond
	const slack = 2 * time.Second // scheduling + one clipped pause
	target := t126Onion + ":443"

	hung := func(released chan<- struct{}) t126ControlFn {
		return func(ctx context.Context, _ string) ([]string, error) {
			<-ctx.Done()
			released <- struct{}{}
			return nil, ctx.Err()
		}
	}
	for name, run := range map[string]func(t126ControlFn) error{
		"Bootstrap": func(c t126ControlFn) error { return t126WaitBootstrapped(context.Background(), c, budget) },
		"Streams": func(c t126ControlFn) error {
			_, err := t126WaitStreams(context.Background(), c, target, 2, budget)
			return err
		},
	} {
		t.Run(name+"HungTransportFailsWithinPhase", func(t *testing.T) {
			released := make(chan struct{}, 16)
			start := time.Now()
			err := run(hung(released))
			if err == nil {
				t.Fatal("hung transport reported success")
			}
			if elapsed := time.Since(start); elapsed > budget+slack {
				t.Fatalf("poll held %s against a %s phase budget", elapsed, budget)
			}
			select {
			case <-released:
			case <-time.After(slack):
				t.Fatal("hung transport was never released (context not cancelled)")
			}
		})
	}

	t.Run("RespondingTransportSucceeds", func(t *testing.T) {
		ok := func(_ context.Context, command string) ([]string, error) {
			switch command {
			case "GETINFO status/bootstrap-phase":
				return []string{"status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done", "OK"}, nil
			case "GETINFO stream-status":
				return []string{"stream-status=", "7 SUCCEEDED 28 " + target, "8 SUCCEEDED 31 " + target, "9 CLOSED 5 " + target, "OK"}, nil
			}
			return nil, fmt.Errorf("unexpected command %q", command)
		}
		if err := t126WaitBootstrapped(context.Background(), ok, budget); err != nil {
			t.Fatalf("bootstrap on responding transport: %v", err)
		}
		circ, err := t126WaitStreams(context.Background(), ok, target, 2, budget)
		if err != nil || len(circ) != 2 || circ[0] != "28" || circ[1] != "31" {
			t.Fatalf("streams on responding transport = %v, %v; want [28 31]", circ, err)
		}
	})
}

// TestStreamIsolationDPUNAMEForwarding is T126: same target, distinct
// partitions, through port 8881 → distinct BUILT circuits; same partition
// twice → one shared circuit (calibration).
func TestStreamIsolationDPUNAMEForwarding(t *testing.T) {
	if os.Getenv("STARGATE_RUN_NETWORK_TESTS") != "1" {
		t.Skip("STARGATE_RUN_NETWORK_TESTS != 1 — release-tag test (needs real Tor network + a live onion service); set to opt in")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon unreachable: %v\n%s", err, out)
	}

	repoRoot := t059FindRepoRoot(t) // project-agnostic, same package
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	for _, p := range []string{composeFile, envFile} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("required file missing: %v", err)
		}
	}
	cfg := tor.ControlPortConfig{Project: t126Project, ComposeFile: composeFile, EnvFile: envFile}

	ctx, cancel := context.WithTimeout(context.Background(), t126OverallDead)
	defer cancel()

	// Signal-safe teardown (T033's redteam finding: an orphaned project keeps
	// tor's circuits, and the operator's IP at its entry guards, alive after
	// the test ended). The handler is scoped to this test's lifetime: its
	// stop is registered BEFORE the compose-down cleanup so it runs after it
	// (t.Cleanup is LIFO) — teardown stays signal-protected, and once the
	// test ends a later signal belongs to whichever suite is then active.
	stopTrap := t126TrapSignals(func(sig os.Signal) {
		dCtx, dCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dCancel()
		if out, err := t126Compose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			fmt.Fprintf(os.Stderr, "signal %v: compose down (best-effort): %v\n%s", sig, err, out)
		}
	}, os.Exit)
	t.Cleanup(stopTrap)
	// Cleanup BEFORE up (T019b ordering).
	t.Cleanup(func() {
		dCtx, dCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer dCancel()
		if out, err := t126Compose(dCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// Failure forensics for every live fatal path (acceptance #1): bounded
	// DP and tor tails (tor's is SafeLogging-scrubbed); an unavailable log is
	// reported inline rather than masking the primary failure.
	forensics := func() string {
		return t126LogTail(ctx, composeFile, envFile, "stargate-dp", 12) + "\n" +
			t126LogTail(ctx, composeFile, envFile, "tor", 15)
	}
	// Control commands open a short per-operation session (t126LiveControl)
	// so every read is bounded by its phase deadline (t126Op).
	ctl := t126LiveControl(cfg)

	// Phase 1: tor up and bootstrapped under this suite's own deadline, then
	// the planes in a scoped up that leaves the healthy tor untouched
	// (T059's live-run findings, carried by T131).
	t.Log("phase 1: tor up + bootstrap…")
	upCtx, upCancel := context.WithTimeout(ctx, t126UpDead)
	if out, err := t126Compose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		upCancel()
		t.Fatalf("docker compose up tor: %v\n%s", err, out)
	}
	upCancel()
	if err := t126WaitBootstrapped(ctx, ctl, t126BootDead); err != nil {
		t.Fatalf("%v\n%s", err, forensics())
	}
	t.Log("OK: tor bootstrapped")

	token, err := t059NewToken() // FR-017 shape by construction
	if err != nil {
		t.Fatalf("generate bearer token: %v", err)
	}
	// T155: a second device token so the device axis can be exercised live.
	if err := t126SeedToken(ctx, token, t155DeviceTwoToken); err != nil {
		t.Fatalf("seed token into %s_stargate-control-config: %v", t126Project, err)
	}

	t.Log("phase 2: data plane + control plane up…")
	up2Ctx, up2Cancel := context.WithTimeout(ctx, t126UpDead)
	defer up2Cancel()
	if out, err := t126Compose(up2Ctx, composeFile, envFile, "up", "-d", "--build", "stargate-dp", "stargate-control"); err != nil {
		t.Fatalf("docker compose up (planes): %v\n%s", err, out)
	}

	target := fmt.Sprintf("%s:%d", t126Onion, t126OnionPrt)
	userA := t126PartitionUsername(token, t126ProfileA, t126Onion)
	userB := t126PartitionUsername(token, t126ProfileB, t126Onion)
	userCal := t126PartitionUsername(token, t126ProfileCal, t126Onion)
	for _, u := range []string{userA, userB, userCal} {
		if len(u) != t126PartitionLen || !strings.HasPrefix(u, "sg1:") {
			t.Fatalf("partition username has wrong shape (len %d)", len(u))
		}
	}
	if userA == userB || userA == userCal || userB == userCal {
		t.Fatal("partition usernames are not pairwise distinct — the dial matrix would not test isolation")
	}

	// The assertion: distinct partitions, same target, through the DP.
	t.Run("DistinctPartitionsSameTargetDiverge", func(t *testing.T) {
		c1, c2 := t126ParallelConnect(t, ctx, composeFile, envFile, token, userA, userB, t126InitialWait)
		defer c1.Close()
		defer c2.Close()
		circ, err := t126WaitStreams(ctx, ctl, target, 2, t126StreamWait)
		if err != nil {
			t.Fatalf("%v\n%s", err, forensics())
		}
		if circ[0] == "0" || circ[1] == "0" {
			t.Fatalf("stream(s) reported unattached (CircID 0): %v\n%s", circ, forensics())
		}
		if circ[0] == circ[1] {
			t.Fatalf("ISOLATION: DISTINCT partition usernames to the SAME target shared circuit %s through %s — "+
				"the DP fused, dropped or constant-folded the upstream SOCKS5 username "+
				"(FR-007 / forward/tor.go dialUpstream), collapsing FR-002 isolation\n%s", circ[0], t126DPAddr, forensics())
		}
		for _, id := range circ {
			built, err := t126CircuitBuilt(ctx, ctl, id)
			if err != nil || !built {
				t.Errorf("circuit %s not found BUILT in GETINFO circuit-status (err: %v) — "+
					"stream-status and circuit-status disagree (parsing bug or tor surface change)\n%s", id, err, forensics())
			}
		}
		t.Logf("OK: distinct partitions → distinct circuits %s / %s, both BUILT", circ[0], circ[1])
	})

	// Calibration: the fused-credential input must be observable as sharing.
	t.Run("CalibrationSamePartitionShares", func(t *testing.T) {
		if _, err := t126WaitStreams(ctx, ctl, target, 0, t126DrainWait); err != nil {
			t.Fatalf("drain before calibration: %v\n%s", err, forensics())
		}
		c1, c2 := t126ParallelConnect(t, ctx, composeFile, envFile, token, userCal, userCal, t126ConnectWait)
		defer c1.Close()
		defer c2.Close()
		circ, err := t126WaitStreams(ctx, ctl, target, 2, t126StreamWait)
		if err != nil {
			t.Fatalf("%v\n%s", err, forensics())
		}
		if circ[0] == "0" || circ[0] != circ[1] {
			t.Fatalf("CALIBRATION: SAME partition through %s attached to circuits %v, not one shared circuit — "+
				"this run cannot observe credential fusion, so the distinct-circuit result above is "+
				"uncalibrated (T060's same-credential consolidation no longer holds?)\n%s", t126DPAddr, circ, forensics())
		}
		t.Logf("OK: calibration — same partition shares circuit %s", circ[0])
	})

	// T155: the device and first-party-site axes, one axis different per pair,
	// same target, against the calibration above (partition_axes_test.go).
	base := t155Cred{user: userA, token: token}
	t.Run("DeviceAxisDivergesSameTarget", func(t *testing.T) {
		device := t155Cred{user: t126PartitionUsername(t155DeviceTwoToken, t126ProfileA, t126Onion), token: t155DeviceTwoToken}
		t155RunAxisPair(t, ctx, ctl, composeFile, envFile, target, "device", base, device, forensics)
	})
	t.Run("SiteAxisDivergesSameTarget", func(t *testing.T) {
		site := t155Cred{user: t126PartitionUsername(token, t126ProfileA, t155SiteTwoOnion), token: token}
		t155RunAxisPair(t, ctx, ctl, composeFile, envFile, target, "first-party site", base, site, forensics)
	})
}

// t126PartitionUsername derives the browser's `sg1:` partition for a
// normal-mode, default-container onion navigation
// (contracts/foundation-boundaries.md: HMAC-SHA-256 keyed by the bearer
// over the JSON tuple, lowercase hex).
func t126PartitionUsername(token, profileID, onion string) string {
	message, _ := json.Marshal([]string{
		"stargate-isolation-v1", profileID, "normal", "firefox-default", "onion:" + onion,
	}) // []string cannot fail Marshal.
	mac := hmac.New(sha256.New, []byte(token))
	_, _ = mac.Write(message)
	return "sg1:" + hex.EncodeToString(mac.Sum(nil))
}

// t126ParallelConnect dials two CONNECTs through the DP behind one starting
// gun, each retrying independently within wait, and returns both held-open
// tunnels. On failure it reports both outcomes with T059's AUTH/ROUTE
// classification and bounded DP/tor log tails (tor's is SafeLogging-scrubbed).
func t126ParallelConnect(t *testing.T, ctx context.Context, composeFile, envFile, token, user0, user1 string, wait time.Duration) (net.Conn, net.Conn) {
	t.Helper()
	type result struct {
		idx  int
		conn net.Conn
		err  error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for i, user := range []string{user0, user1} {
		go func(idx int, user string) {
			<-start
			wCtx, wCancel := context.WithTimeout(ctx, wait)
			defer wCancel()
			var lastErr error
			for {
				conn, err := t126Connect(wCtx, user, token)
				if err == nil {
					results <- result{idx: idx, conn: conn}
					return
				}
				lastErr = err
				if wCtx.Err() != nil {
					results <- result{idx: idx, err: lastErr}
					return
				}
				time.Sleep(t126StreamPoll)
			}
		}(i, user)
	}
	close(start)

	var conns [2]net.Conn
	var errs [2]error
	for n := 0; n < 2; n++ {
		r := <-results
		conns[r.idx], errs[r.idx] = r.conn, r.err
	}
	if errs[0] != nil || errs[1] != nil {
		for _, c := range conns {
			if c != nil {
				_ = c.Close()
			}
		}
		t.Fatalf("parallel CONNECT through %s did not establish both streams within %s\n  #0: %s\n  #1: %s\n%s\n%s",
			t126DPAddr, wait, t059ClassifyDialErr(errs[0]), t059ClassifyDialErr(errs[1]),
			t126LogTail(ctx, composeFile, envFile, "stargate-dp", 12),
			t126LogTail(ctx, composeFile, envFile, "tor", 15))
	}
	return conns[0], conns[1]
}

// t126Connect issues one SOCKS5 CONNECT through the DP: UNAME = the complete
// partition, PASSWD = the bearer (DP-facing only; never forwarded to tor),
// ATYP=domain so the DP never resolves the destination (FR-007).
func t126Connect(ctx context.Context, user, token string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", t126DPAddr, &proxy.Auth{User: user, Password: token}, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dialer: %w", err)
	}
	dCtx, cancel := context.WithTimeout(ctx, t126ConnectWait)
	defer cancel()
	return dialer.(proxy.ContextDialer).DialContext(dCtx, "tcp", fmt.Sprintf("%s:%d", t126Onion, t126OnionPrt))
}

// t126TrapSignals installs the SIGINT/SIGTERM teardown for this test and
// returns a stop that unregisters the channel and joins the handler
// goroutine. After stop, a later signal is never observed here, so a
// completed T126 cannot tear down or exit the process under a subsequent
// suite (round-1 review). teardown and exit are injected so the lifetime
// is pinned hermetically (TestT126SignalTrapReleasedAfterStop).
func t126TrapSignals(teardown func(os.Signal), exit func(int)) (stop func()) {
	sigCh := make(chan os.Signal, 1)
	done := make(chan struct{})
	finished := make(chan struct{})
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		defer close(finished)
		select {
		case sig := <-sigCh:
			teardown(sig)
			exit(1)
		case <-done:
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(sigCh)
			close(done)
			<-finished
		})
	}
}

// t126ControlFn issues one control command under ctx. The live transport
// is exec.CommandContext-backed, so cancelling ctx kills the docker exec
// and releases a blocked read.
type t126ControlFn func(ctx context.Context, command string) ([]string, error)

// t126LiveControl opens one authenticated session per operation through
// the T062 helper (cookie read, nc -U session, AUTHENTICATE, command,
// Close). A short session per poll means no read can outlive the context
// its operation was given.
func t126LiveControl(cfg tor.ControlPortConfig) t126ControlFn {
	return func(ctx context.Context, command string) ([]string, error) {
		cookie, err := tor.ReadCookie(ctx, cfg)
		if err != nil {
			return nil, err
		}
		c, err := tor.Connect(ctx, cfg)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if err := c.Authenticate(cookie); err != nil {
			return nil, err
		}
		return c.Command(command)
	}
}

// t126Op runs one control command bounded by the earlier of the phase
// deadline and t126ExecDead. The select returns at the bound even if a
// transport ignored cancellation; the live one exits on cancel.
func t126Op(ctx context.Context, ctl t126ControlFn, phaseDeadline time.Time, command string) ([]string, error) {
	bound := time.Now().Add(t126ExecDead)
	if phaseDeadline.Before(bound) {
		bound = phaseDeadline
	}
	opCtx, cancel := context.WithDeadline(ctx, bound)
	defer cancel()
	type reply struct {
		lines []string
		err   error
	}
	ch := make(chan reply, 1)
	go func() {
		lines, err := ctl(opCtx, command)
		ch <- reply{lines, err}
	}()
	select {
	case r := <-ch:
		return r.lines, r.err
	case <-opCtx.Done():
		return nil, fmt.Errorf("control %q: %w", command, opCtx.Err())
	}
}

// t126Pause sleeps for the poll interval, clipped to the phase deadline so
// a poll loop never overshoots its budget by a full interval.
func t126Pause(poll time.Duration, deadline time.Time) {
	if left := time.Until(deadline); left < poll {
		poll = left
	}
	if poll > 0 {
		time.Sleep(poll)
	}
}

// t126WaitBootstrapped polls status/bootstrap-phase until PROGRESS=100
// within wait. CONNECTs before full bootstrap fail in ways that would
// masquerade as the property; transport errors retry (tor may still be
// starting) and the last one is reported at the deadline.
func t126WaitBootstrapped(ctx context.Context, ctl t126ControlFn, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	var last string
	var lastErr error
	for {
		lines, err := t126Op(ctx, ctl, deadline, "GETINFO status/bootstrap-phase")
		if err == nil {
			last = strings.Join(lines, " | ")
			if strings.Contains(last, "PROGRESS=100") {
				return nil
			}
		}
		lastErr = err
		if !time.Now().Before(deadline) {
			return fmt.Errorf("tor not bootstrapped within %s (last phase: %q, last error: %v)", wait, last, lastErr)
		}
		t126Pause(t126PollEvery, deadline)
	}
}

// t126WaitStreams polls until exactly want live (non-terminal) streams
// target the destination and returns their circuit IDs. It errors at the
// deadline — a count that never lands is either the property failing or a
// broken environment, and both must be loud (T058a/T060 discipline).
func t126WaitStreams(ctx context.Context, ctl t126ControlFn, target string, want int, wait time.Duration) ([]string, error) {
	deadline := time.Now().Add(wait)
	var states []string
	var lastErr error
	for {
		lines, err := t126Op(ctx, ctl, deadline, "GETINFO stream-status")
		lastErr = err
		if err == nil {
			var circIDs []string
			states = states[:0]
			for _, ln := range lines {
				// <StreamID> <Status> <CircID> <Target>; the single-stream reply
				// form prefixes "stream-status=" onto the first field only.
				f := strings.Fields(ln)
				if len(f) < 4 || f[3] != target || t059TerminalStreamStates[f[1]] {
					continue
				}
				circIDs = append(circIDs, f[2])
				states = append(states, f[1])
			}
			if len(circIDs) == want {
				return circIDs, nil
			}
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("expected exactly %d live stream(s) to %s within %s; last saw states %v (last error: %v)",
				want, target, wait, states, lastErr)
		}
		t126Pause(t126StreamPoll, deadline)
	}
}

// t126CircuitBuilt cross-checks a stream's circuit is BUILT in GETINFO
// circuit-status — tor's circuit-level surface must agree with its
// stream-level one. One bounded operation.
func t126CircuitBuilt(ctx context.Context, ctl t126ControlFn, circID string) (bool, error) {
	lines, err := t126Op(ctx, ctl, time.Now().Add(t126ExecDead), "GETINFO circuit-status")
	if err != nil {
		return false, err
	}
	for _, ln := range lines {
		if strings.HasPrefix(ln, circID+" ") && strings.Contains(ln, " BUILT ") {
			return true, nil
		}
	}
	return false, nil
}

// t126SeedToken is T059's seed step for this project: create the config
// volume under compose's labels (so down --volumes reaps it), pre-create the
// keys/ mountpoint, and write tokens.yaml (FR-017 shape) on stdin so the
// token never reaches argv.
func t126SeedToken(ctx context.Context, tokens ...string) error {
	vol := t126Project + "_stargate-control-config"
	create := exec.CommandContext(ctx, "docker", "volume", "create",
		"--label", "com.docker.compose.project="+t126Project,
		"--label", "com.docker.compose.volume=stargate-control-config",
		vol)
	if out, err := create.CombinedOutput(); err != nil {
		return fmt.Errorf("create config volume: %v: %s", err, out)
	}
	write := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--user", "0:0",
		"--entrypoint", "sh",
		"-v", vol+":/tgt", "stargate/tor:local",
		"-c", "mkdir -p /tgt/keys && cat > /tgt/tokens.yaml")
	var yaml strings.Builder
	yaml.WriteString("tokens:\n")
	for i, token := range tokens {
		fmt.Fprintf(&yaml, "  - label: t126-test-%d\n    token: %s\n", i+1, token)
	}
	write.Stdin = strings.NewReader(yaml.String())
	if out, err := write.CombinedOutput(); err != nil {
		return fmt.Errorf("write tokens.yaml into volume: %v: %s", err, out)
	}
	return nil
}

// t126LogTail returns a bounded service log tail for failure forensics;
// a logs failure is reported inline, never fatal.
func t126LogTail(ctx context.Context, composeFile, envFile, service string, n int) string {
	eCtx, cancel := context.WithTimeout(ctx, t126ExecDead)
	defer cancel()
	out, err := t126Compose(eCtx, composeFile, envFile, "logs", "--tail", fmt.Sprint(n), service)
	if err != nil {
		return fmt.Sprintf("— %s logs unavailable: %v", service, err)
	}
	return fmt.Sprintf("— %s log tail:\n%s", service, strings.TrimSpace(string(out)))
}

// t126Compose runs a compose subcommand under this suite's project.
func t126Compose(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	full := append([]string{"compose", "-p", t126Project, "-f", composeFile, "--env-file", envFile}, args...)
	return exec.CommandContext(ctx, "docker", full...).CombinedOutput()
}
