//go:build docker && linux
// +build docker,linux

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zcat-app/stargate/tests/internal/loginvariants"
	"golang.org/x/sys/unix"
)

const (
	t070ReferenceOnion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
	t070ReferencePort  = 443
	t070DownOnion      = "t070-route-down-controlled-address.onion"
	t070ProjectPrefix  = "stargate-t070-"
	t070OverallWait    = 30 * time.Minute
	t070InitWait       = 20 * time.Minute
	t070ControlWait    = 5 * time.Minute
	t070ExecWait       = 90 * time.Second
	t070CleanupWait    = 90 * time.Second
	t070SocketWait     = 30 * time.Second
	t070CaptureLimit   = 1 << 20
	t070DockerSocket   = "/var/run/docker.sock"
	t070BuildxSHA256   = "912118a5a65bf2f13dd7c2e5912857c50f43842bf4ec0f4378bcb28af66aaac3"
)

var t070ExpectedServices = []string{"stargate-control", "stargate-dp", "tor", "tor-observer"}

// TestT070IntegratedRouteDown exercises T172's selected failure through the
// deployed Local stack. The real onion control proves admission, Tor routing,
// and test connectivity before Tor is stopped; only then does the test inspect
// the fixed route-down bytes and the host's actual no-egress DROP counters.
func TestT070IntegratedRouteDown(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("T070 requires the Docker CLI: %v", err)
	}
	checkCtx, checkCancel := context.WithTimeout(context.Background(), t070ExecWait)
	_, daemonErr := t070Run(checkCtx, t070ExecWait, "docker", "info")
	checkCancel()
	if daemonErr != nil {
		t.Fatalf("T070 requires a reachable Docker daemon: %v", daemonErr)
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

	ctx, cancel := context.WithTimeout(context.Background(), t070OverallWait)
	var capture *t070LiveCapture
	var captureMu sync.Mutex
	var projectOwnershipMu sync.Mutex
	var markerMu sync.Mutex
	var unsafeMarkerPath string
	buildxConfig := &t070BuildxConfig{}
	initProcess := &t070InitStartGate{}
	projectOwned := false
	var cleanupOnce sync.Once
	initShutdown := func() bool { return initProcess.shutdown(5*time.Second, 10*time.Second, 5*time.Second) }
	cleanup := func(report bool) {
		cleanupOnce.Do(func() {
			if !initShutdown() {
				if report {
					t.Errorf("T070 init process group did not exit; unsafe marker retained and project/host cleanup must not proceed")
				} else {
					fmt.Fprintln(os.Stderr, "T070 signal cleanup: init process group remains; unsafe marker retained")
				}
				return
			}
			if err := buildxConfig.removeAfterProcessStop(true); err != nil {
				if report {
					t.Errorf("private Buildx config cleanup failed after init process exit: %v", err)
				} else {
					fmt.Fprintln(os.Stderr, "T070 signal cleanup: private Buildx config cleanup failed after init process exit")
				}
				return
			}
			captureMu.Lock()
			activeCapture := capture
			captureMu.Unlock()
			if activeCapture != nil {
				activeCapture.stop()
			}
			projectOwnershipMu.Lock()
			ownsProject := projectOwned
			projectOwnershipMu.Unlock()
			if !ownsProject {
				return
			}
			dCtx, dCancel := context.WithTimeout(context.Background(), t070CleanupWait)
			defer dCancel()
			out, downErr := t070Compose(dCtx, project, composeFile, envFile, "down", "--volumes", "--remove-orphans")
			if downErr != nil {
				if report {
					t.Errorf("project-scoped Compose cleanup failed: %v (output length %d)", downErr, len(out))
				} else {
					fmt.Fprintf(os.Stderr, "T070 signal cleanup: Compose down failed: %v\n", downErr)
				}
				return
			}
			remaining, listErr := t070ProjectResources(dCtx, project)
			if listErr != nil || len(remaining) != 0 {
				if report {
					t.Errorf("project-scoped cleanup did not remove all project containers, volumes, and networks (remaining=%d, inspect error=%v)", len(remaining), listErr)
				} else {
					fmt.Fprintf(os.Stderr, "T070 signal cleanup: project resources remain or could not be inspected\n")
				}
				return
			}
			markerMu.Lock()
			marker := unsafeMarkerPath
			markerMu.Unlock()
			if marker != "" {
				if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
					if report {
						t.Errorf("T070 resources are empty but unsafe marker removal failed: %v", err)
					} else {
						fmt.Fprintln(os.Stderr, "T070 signal cleanup: unsafe marker removal failed; host restoration must not proceed")
					}
					return
				}
			}
			if report {
				t.Logf("project-scoped cleanup removed only %s containers, volumes, and networks; no project resources remain", project)
			}
		})
	}

	// Go test does not run t.Cleanup on a signal-induced process exit. The
	// unique project name confines this handler and the ordinary cleanup to
	// resources created by this test; the outer host-boundary runner restores
	// the separately managed host policy after this process exits.
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
		t.Fatalf("fresh T070 project already has Docker containers, volumes, or networks (count=%d, inspect error=%v)", len(resources), err)
	}
	projectOwnershipMu.Lock()
	projectOwned = true
	projectOwnershipMu.Unlock()
	services, err := t070Compose(ctx, project, composeFile, envFile, "config", "--services")
	if err != nil || !t070SameStrings(strings.Fields(string(services)), t070ExpectedServices) {
		t.Fatalf("Local Compose service inventory differs from the reviewed T070 set (config error=%v)", err)
	}
	configDir, err := buildxConfig.prepare(os.Getenv("STARGATE_T070_BUILDX_PLUGIN"), t070BuildxSHA256)
	if err != nil {
		t.Fatalf("prepare isolated Buildx plugin config: %v", err)
	}
	markerPath := os.Getenv("STARGATE_T070_UNSAFE_MARKER")
	if markerPath != "/tmp/stargate-t070-live.unsafe" {
		t.Fatalf("T070 host helper did not provide the required unsafe marker path")
	}
	marker, err := os.OpenFile(markerPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("T070 unsafe marker is stale or could not be created: %v", err)
	}
	markerMu.Lock()
	unsafeMarkerPath = markerPath
	markerMu.Unlock()
	if _, err := fmt.Fprintf(marker, "starting project=%s\n", project); err != nil {
		_ = marker.Close()
		t.Fatalf("write T070 unsafe marker: %v", err)
	}
	if err := marker.Sync(); err != nil {
		_ = marker.Close()
		t.Fatalf("sync T070 unsafe marker: %v", err)
	}
	if err := marker.Close(); err != nil {
		t.Fatalf("close T070 unsafe marker: %v", err)
	}
	initCtx, initCancel := context.WithTimeout(ctx, t070InitWait)
	initArgs := t070InitCommandArgs(repoRoot)
	initCmd := exec.Command(initArgs[0], initArgs[1:]...)
	initCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// WaitDelay bounds Cmd's output-copying goroutines; the process-group
	// barrier below is what actually terminates and verifies the full tree.
	initCmd.WaitDelay = 2 * time.Second
	shimDir, buildOverride, overrideMarker, realDocker, err := t070InstallDockerShim(t, project, composeFile, envFile)
	if err != nil {
		initCancel()
		t.Fatalf("prepare private test-only Compose build override: %v", err)
	}
	pathValue := shimDir + string(os.PathListSeparator) + os.Getenv("PATH")
	initCmd.Env = t070InitEnvironment(os.Environ(), configDir)
	initCmd.Env = append(initCmd.Env,
		"PATH="+pathValue,
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
		t.Fatalf("T070 init launch was canceled by cleanup before process start")
	}
	if err := initCmd.Start(); err != nil {
		initProcess.finishStart(0, nil)
		initCancel()
		t.Fatalf("start isolated scripts/stargate init process group: %v", err)
	}
	waitDone := make(chan struct{})
	initProcess.finishStart(initCmd.Process.Pid, waitDone)
	var commandErr error
	go func() {
		commandErr = initCmd.Wait()
		close(waitDone)
	}()
	if err := os.WriteFile(markerPath, []byte(fmt.Sprintf("project=%s pgid=%d\n", project, initCmd.Process.Pid)), 0o600); err != nil {
		initCancel()
		t.Fatalf("record T070 init process group in unsafe marker: %v", err)
	}
	var initErr error
	select {
	case <-waitDone:
		initErr = commandErr
	case <-initCtx.Done():
		initErr = initCtx.Err()
	}
	if !initShutdown() {
		initCancel()
		t.Fatalf("scripts/stargate init process group remains after bounded TERM/KILL; unsafe marker retained")
	}
	if initErr == nil {
		initErr = commandErr
	}
	initCancel()
	if initErr != nil || initOutput.overflowed() {
		initNotes := t070InitFailureNotes(initOutput.bytes())
		containerSummary := t070ProjectContainerStates(project)
		marker, markerErr := os.ReadFile(overrideMarker)
		overrideApplied := markerErr == nil && string(marker) == "applied\n"
		t.Fatalf("scripts/stargate init did not complete (error=%v, output_overflow=%t, tor_build_override_applied=%t, safe_init_markers=%s, safe_container_states=%s)",
			initErr, initOutput.overflowed(), overrideApplied, strings.Join(initNotes, ","), containerSummary)
	}
	if marker, err := os.ReadFile(overrideMarker); err != nil || string(marker) != "applied\n" {
		t.Fatalf("T070 init did not use its exact-project Tor build-network override (marker error=%v)", err)
	}
	if err := t070AssertProjectServices(ctx, project); err != nil {
		t.Fatalf("post-init project inventory is not the isolated four-service Local stack: %v", err)
	}

	token, err := t059NewToken()
	if err != nil {
		t.Fatalf("generate test bearer token: %v", err)
	}
	if err := t070SeedToken(ctx, project, token); err != nil {
		t.Fatalf("seed private test token into the T070 control-config volume: %v", err)
	}
	if out, err := t070Compose(ctx, project, composeFile, envFile, "restart", "stargate-control"); err != nil {
		t.Fatalf("restart only the T070 control plane to load the token (output length %d): %v", len(out), err)
	}

	dpID, err := t070RunningServiceID(ctx, project, composeFile, envFile, "stargate-dp")
	if err != nil {
		t.Fatalf("resolve running T070 data-plane container: %v", err)
	}
	logging, err := t070Run(ctx, t070ExecWait, "docker", "inspect", "--format", `{{.HostConfig.LogConfig.Type}}`, dpID)
	if err != nil || strings.TrimSpace(string(logging)) != "none" {
		t.Fatalf("T070 expected the Local data plane's disabled Docker log driver before attaching (inspect error=%v)", err)
	}
	newCapture := t070StartLiveCapture(ctx, t, dpID)
	captureMu.Lock()
	capture = newCapture
	captureMu.Unlock()
	t.Cleanup(func() { capture.stop() })

	t.Log("T070 positive control: authenticated SOCKS5 CONNECT to the pinned live onion")
	if err := t070PositiveControl(ctx, token); err != nil {
		t.Fatalf("live Tor/SOCKS positive control failed before route-down probe: %v", err)
	}
	capture.requireAlive(t, "after live positive control")

	if err := t070AssertDropBoundary(ctx); err != nil {
		t.Fatalf("host no-direct-egress boundary is not measurable: %v", err)
	}
	beforeStop, err := t070DropCounters(ctx)
	if err != nil {
		t.Fatalf("snapshot IPv4 and IPv6 STARGATE_DP_OUT DROP counters: %v", err)
	}
	if out, err := t070Compose(ctx, project, composeFile, envFile, "stop", "tor"); err != nil {
		t.Fatalf("stop only this project's Tor service (output length %d): %v", len(out), err)
	}
	if err := t070AssertStoppedService(ctx, project, composeFile, envFile, "tor"); err != nil {
		t.Fatalf("T070 Tor-only stop was not observed: %v", err)
	}
	afterStop, err := t070DropCounters(ctx)
	if err != nil {
		t.Fatalf("read host egress counters after Tor stop: %v", err)
	}
	if beforeStop != afterStop {
		t.Fatalf("host direct-egress DROP counter changed while only Tor was stopping")
	}

	beforeProbe, err := t070DropCounters(ctx)
	if err != nil {
		t.Fatalf("snapshot host egress counters immediately before route-down request: %v", err)
	}
	fullReply, err := t070RouteDownProbe(ctx, token)
	if err != nil {
		t.Fatalf("authenticated SOCKS5 route-down probe failed: %v", err)
	}
	want := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(fullReply, want) {
		t.Fatalf("SOCKS5 ROUTE_DOWN reply was not the exact fixed ten-byte response (length=%d)", len(fullReply))
	}
	capture.requireAlive(t, "during the request window")
	afterProbe, err := t070DropCounters(ctx)
	if err != nil {
		t.Fatalf("read host egress counters after route-down request: %v", err)
	}
	if beforeProbe != afterProbe {
		t.Fatalf("IPv4 or IPv6 STARGATE_DP_OUT DROP counter increased during the failed route request")
	}

	diagnostics := capture.stopAndBytes(t)
	corpus, err := t070LoadLeakCorpus(filepath.Join(repoRoot, "tests", "contract", "error-template", "leak-corpus.txt"))
	if err != nil {
		t.Fatalf("load committed shared leak corpus: %v", err)
	}
	secrets := append(corpus, []byte(token), []byte(t131PartitionUsername(token, t070ReferenceOnion)),
		[]byte(t131PartitionUsername(token, t070DownOnion)), []byte(t070ReferenceOnion), []byte(t070DownOnion))
	loginvariants.AssertNoSecrets(t, string(fullReply), secrets...)
	loginvariants.AssertNoSecrets(t, diagnostics, secrets...)
	loginvariants.AssertOnlyAllowedLines(t, diagnostics)

	if err := t070AssertProjectServices(ctx, project, "tor"); err != nil {
		t.Fatalf("project service set changed during the test: %v", err)
	}
}

func t070ProjectName() (string, error) {
	if requested := os.Getenv("STARGATE_T070_PROJECT"); requested != "" {
		if !strings.HasPrefix(requested, t070ProjectPrefix) || len(requested) > 63 {
			return "", errors.New("STARGATE_T070_PROJECT must use the stargate-t070- prefix and be at most 63 characters")
		}
		for _, r := range requested {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
				return "", errors.New("STARGATE_T070_PROJECT contains a character invalid for a Compose project name")
			}
		}
		if requested[len(t070ProjectPrefix):] == "" {
			return "", errors.New("STARGATE_T070_PROJECT must include a suffix after its required prefix")
		}
		return requested, nil
	}
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return t070ProjectPrefix + hex.EncodeToString(suffix[:]), nil
}

func t070SameStrings(got, want []string) bool {
	got, want = append([]string(nil), got...), append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	return strings.Join(got, "\x00") == strings.Join(want, "\x00")
}

type t070RunHooks struct {
	signalGroup func(int, syscall.Signal) error
	waitLeader  func(int) error
	waitCommand func(*exec.Cmd) error
}

func t070Run(ctx context.Context, timeout time.Duration, command string, args ...string) ([]byte, error) {
	return t070RunWithHooks(ctx, timeout, t070RunHooks{
		signalGroup: func(pgid int, signal syscall.Signal) error { return syscall.Kill(-pgid, signal) },
		waitLeader:  t070WaitLeaderUnreaped,
		waitCommand: func(cmd *exec.Cmd) error { return cmd.Wait() },
	}, command, args...)
}

func t070WaitLeaderUnreaped(pid int) error {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

type t070RunSignalGate struct {
	mu      sync.Mutex
	pgid    int
	enabled bool
	signal  func(int, syscall.Signal) error
	termErr error
}

func (g *t070RunSignalGate) signalLocked(sig syscall.Signal) error {
	if !g.enabled {
		return os.ErrProcessDone
	}
	err := g.signal(g.pgid, sig)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	if sig == syscall.SIGTERM && err != nil {
		g.termErr = errors.Join(g.termErr, err)
	}
	return err
}

func (g *t070RunSignalGate) cancel() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.signalLocked(syscall.SIGTERM)
}

func t070RunWithHooks(ctx context.Context, timeout time.Duration, hooks t070RunHooks, command string, args ...string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, command, args...)
	gate := &t070RunSignalGate{signal: hooks.signalGroup}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = gate.cancel
	cmd.WaitDelay = time.Second
	if filepath.Base(command) == "docker" {
		cmd.Env = t070LocalDockerEnvironment(os.Environ())
	}
	out := &t070BoundedOutput{limit: 8 << 20}
	cmd.Stdout, cmd.Stderr = out, out
	// Publish the process group and enable signaling atomically before a context
	// cancellation watcher can signal a partially initialized group.
	gate.mu.Lock()
	err := cmd.Start()
	if err == nil {
		gate.pgid = cmd.Process.Pid
		gate.enabled = true
	}
	gate.mu.Unlock()
	if err != nil {
		return out.bytes(), err
	}
	waitLeader := hooks.waitLeader
	if waitLeader == nil {
		waitLeader = t070WaitLeaderUnreaped
	}
	waitCommand := hooks.waitCommand
	if waitCommand == nil {
		waitCommand = func(cmd *exec.Cmd) error { return cmd.Wait() }
	}
	leaderErr := waitLeader(cmd.Process.Pid)
	var cleanupErr error
	gate.mu.Lock()
	if leaderErr == nil {
		if err := gate.signalLocked(syscall.SIGKILL); err != nil && !errors.Is(err, os.ErrProcessDone) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	gate.enabled = false
	termErr := gate.termErr
	gate.mu.Unlock()
	if leaderErr != nil {
		cleanupErr = errors.Join(cleanupErr, leaderErr)
		// Start CommandContext's bounded WaitDelay path before reaping: a waitid
		// failure may leave descendants holding inherited output descriptors.
		cancel()
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}
	err = waitCommand(cmd)
	err = errors.Join(err, cleanupErr, termErr)
	if out.overflowed() {
		err = errors.Join(err, errors.New("command output exceeded bounded capture"))
	}
	return out.bytes(), err
}

func t070WaitForPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if parseErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("process did not publish pid file %s", path)
	return 0
}

func t070PIDStoppedOrZombie(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	closeParen := bytes.LastIndexByte(data, ')')
	return closeParen >= 0 && len(data) > closeParen+2 && data[closeParen+2] == 'Z'
}

func t070WaitStoppedOrZombie(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if t070PIDStoppedOrZombie(pid) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("process %d remained live after process-group cleanup", pid)
}

func TestT070RunCancellationStopsInheritedPipeChild(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	done := make(chan error, 1)
	go func() {
		_, err := t070Run(ctx, 10*time.Second, "bash", "-c", `sleep 30 & echo $! > "$1"; wait`, "bash", pidFile)
		done <- err
	}()
	child := t070WaitForPIDFile(t, pidFile)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled command unexpectedly succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled command remained blocked on inherited output pipes")
	}
	t070WaitStoppedOrZombie(t, child)
}

func TestT070RunKillsPipeHoldersAfterLeaderExit(t *testing.T) {
	for _, exitCode := range []int{0, 7} {
		t.Run(strconv.Itoa(exitCode), func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			var finalKillSawUnreapedLeader bool
			hooks := t070RunHooks{
				signalGroup: func(pgid int, sig syscall.Signal) error {
					if sig == syscall.SIGKILL {
						var info unix.Siginfo
						if err := unix.Waitid(unix.P_PID, pgid, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil); err == nil {
							finalKillSawUnreapedLeader = true
						}
					}
					return syscall.Kill(-pgid, sig)
				},
				waitLeader: t070WaitLeaderUnreaped,
			}
			started := time.Now()
			out, err := t070RunWithHooks(context.Background(), 5*time.Second, hooks, "bash", "-c", `sleep 30 & echo $! > "$1"; exit "$2"`, "bash", pidFile, strconv.Itoa(exitCode))
			if time.Since(started) > 3*time.Second {
				t.Fatalf("command waited on inherited pipes after leader exit: %s", time.Since(started))
			}
			if exitCode == 0 && err != nil {
				t.Fatalf("successful leader returned error: %v", err)
			}
			if exitCode != 0 {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != exitCode {
					t.Fatalf("nonzero leader status was not retained: %v", err)
				}
			}
			if !finalKillSawUnreapedLeader {
				t.Fatal("final process-group KILL did not observe the direct leader unreaped")
			}
			child := t070WaitForPIDFile(t, pidFile)
			t070WaitStoppedOrZombie(t, child)
			if len(out) != 0 {
				t.Fatalf("unexpected command output: %q", out)
			}
		})
	}
}

func TestT070RunPreservesNormalOutputAndFailure(t *testing.T) {
	out, err := t070Run(context.Background(), 3*time.Second, "bash", "-c", `printf stdout; printf stderr >&2`)
	if err != nil || !bytes.Contains(out, []byte("stdout")) || !bytes.Contains(out, []byte("stderr")) {
		t.Fatalf("successful output was not retained: out=%q err=%v", out, err)
	}
	out, err = t070Run(context.Background(), 3*time.Second, "bash", "-c", `printf failure; exit 9`)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 9 || !bytes.Contains(out, []byte("failure")) {
		t.Fatalf("ordinary nonzero result was not retained: out=%q err=%v", out, err)
	}
}

func TestT070RunRetainsFinalGroupSignalFailure(t *testing.T) {
	signalFailure := errors.New("injected final process-group signal failure")
	hooks := t070RunHooks{
		signalGroup: func(_ int, sig syscall.Signal) error {
			if sig == syscall.SIGKILL {
				return signalFailure
			}
			return nil
		},
	}
	_, err := t070RunWithHooks(context.Background(), time.Second, hooks, "bash", "-c", "exit 0")
	if !errors.Is(err, signalFailure) {
		t.Fatalf("cleanup signal failure was lost after command success: %v", err)
	}
}

func TestT070RunDoesNotSignalBeforeSuccessfulStart(t *testing.T) {
	calls := 0
	hooks := t070RunHooks{
		signalGroup: func(int, syscall.Signal) error { calls++; return nil },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := t070RunWithHooks(ctx, time.Second, hooks, "bash", "-c", "exit 0"); err == nil {
		t.Fatal("pre-canceled command unexpectedly succeeded")
	}
	if _, err := t070RunWithHooks(context.Background(), time.Second, hooks, "/no/such/t070-command"); err == nil {
		t.Fatal("missing command unexpectedly started")
	}
	if calls != 0 {
		t.Fatalf("signaled process group before successful Start: %d calls", calls)
	}
}

func TestT070RunCancellationCannotCrossFinalizationGate(t *testing.T) {
	killEntered := make(chan struct{})
	releaseKill := make(chan struct{})
	var mu sync.Mutex
	var signals []syscall.Signal
	gate := &t070RunSignalGate{
		pgid:    12345,
		enabled: true,
		signal: func(_ int, sig syscall.Signal) error {
			mu.Lock()
			signals = append(signals, sig)
			mu.Unlock()
			if sig == syscall.SIGKILL {
				close(killEntered)
				<-releaseKill
			}
			return nil
		},
	}
	finalized := make(chan struct{})
	go func() {
		gate.mu.Lock()
		_ = gate.signalLocked(syscall.SIGKILL)
		gate.enabled = false
		gate.mu.Unlock()
		close(finalized)
	}()
	select {
	case <-killEntered:
	case <-time.After(time.Second):
		t.Fatal("finalization did not enter the signal gate")
	}
	canceled := make(chan error, 1)
	go func() { canceled <- gate.cancel() }()
	select {
	case <-canceled:
		t.Fatal("cancellation crossed the gate while final KILL was in progress")
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseKill)
	<-finalized
	if err := <-canceled; !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("late cancellation did not see a closed signal gate: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(signals) != 1 || signals[0] != syscall.SIGKILL {
		t.Fatalf("unexpected process-group signals across finalization: %v", signals)
	}
}

func TestT070RunWaitFailureClosesGateAndStillWaitsOnce(t *testing.T) {
	waitFailure := errors.New("injected waitid failure")
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	leaderFile := filepath.Join(t.TempDir(), "leader.pid")
	var signals, waits int
	hooks := t070RunHooks{
		signalGroup: func(int, syscall.Signal) error { signals++; return nil },
		waitLeader: func(int) error {
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(pidFile); err == nil {
					return waitFailure
				}
				time.Sleep(5 * time.Millisecond)
			}
			return errors.New("child readiness timed out")
		},
		waitCommand: func(cmd *exec.Cmd) error { waits++; return cmd.Wait() },
	}
	started := time.Now()
	_, err := t070RunWithHooks(context.Background(), 30*time.Second, hooks, "bash", "-c", `echo $$ > "$1"; sleep 30 & echo $! > "$2"; wait`, "bash", leaderFile, pidFile)
	if !errors.Is(err, waitFailure) {
		t.Fatalf("waitid failure was lost: %v", err)
	}
	if time.Since(started) > 3*time.Second {
		t.Fatalf("waitid failure cleanup exceeded its bounded wait: %s", time.Since(started))
	}
	if waits != 1 {
		t.Fatalf("cmd.Wait called %d times; want exactly once", waits)
	}
	if signals != 0 {
		t.Fatalf("closed signal gate allowed %d process-group signals after waitid failure", signals)
	}
	child := t070WaitForPIDFile(t, pidFile)
	leader := t070WaitForPIDFile(t, leaderFile)
	_ = syscall.Kill(-leader, syscall.SIGKILL)
	t070WaitStoppedOrZombie(t, child)
}

func t070InitCommandArgs(repoRoot string) []string {
	return []string{"bash", filepath.Join(repoRoot, "scripts", "stargate"), "init"}
}

type t070BuildxConfig struct {
	mu   sync.Mutex
	path string
}

func (c *t070BuildxConfig) prepare(sourcePath, expectedDigest string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	path, err := t070PrepareBuildxConfig(sourcePath, expectedDigest)
	if err != nil {
		return "", err
	}
	c.path = path
	return path, nil
}

func (c *t070BuildxConfig) removeAfterProcessStop(processStopped bool) error {
	if !processStopped {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.path == "" {
		return nil
	}
	if err := os.RemoveAll(c.path); err != nil {
		return err
	}
	c.path = ""
	return nil
}

func t070PrepareBuildxConfig(sourcePath, expectedDigest string) (string, error) {
	if sourcePath == "" {
		return "", errors.New("Buildx plugin source is not configured")
	}
	info, err := os.Stat(sourcePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("Buildx plugin source is missing or not executable")
	}
	pluginBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		return "", errors.New("Buildx plugin source could not be read")
	}
	configDir, err := os.MkdirTemp("", "stargate-t070-docker-config-")
	if err != nil {
		return "", errors.New("private Buildx Docker config could not be created")
	}
	cleanup := func(err error) (string, error) {
		_ = os.RemoveAll(configDir)
		return "", err
	}
	if err := os.Chmod(configDir, 0o700); err != nil {
		return cleanup(errors.New("private Buildx Docker config permissions could not be set"))
	}
	pluginDir := filepath.Join(configDir, "cli-plugins")
	if err := os.Mkdir(pluginDir, 0o700); err != nil {
		return cleanup(errors.New("private Buildx plugin directory could not be created"))
	}
	pluginPath := filepath.Join(pluginDir, "docker-buildx")
	if err := os.WriteFile(pluginPath, pluginBytes, 0o700); err != nil {
		return cleanup(errors.New("private Buildx plugin copy could not be written"))
	}
	if err := os.Chmod(pluginPath, 0o700); err != nil {
		return cleanup(errors.New("private Buildx plugin permissions could not be set"))
	}
	copiedBytes, err := os.ReadFile(pluginPath)
	if err != nil {
		return cleanup(errors.New("private Buildx plugin copy could not be verified"))
	}
	if !bytes.Equal(copiedBytes, pluginBytes) || fmt.Sprintf("%x", sha256.Sum256(copiedBytes)) != expectedDigest {
		return cleanup(errors.New("private Buildx plugin copy does not match the reviewed digest"))
	}
	return configDir, nil
}

func t070InitEnvironment(parent []string, dockerConfig string) []string {
	localDockerEnv := t070LocalDockerEnvironment(parent)
	child := make([]string, 0, len(localDockerEnv)+1)
	for _, entry := range localDockerEnv {
		key, _, _ := strings.Cut(entry, "=")
		if key == "DOCKER_CONFIG" {
			continue
		}
		child = append(child, entry)
	}
	return append(child, "DOCKER_CONFIG="+dockerConfig)
}

func t070LocalDockerEnvironment(parent []string) []string {
	child := make([]string, 0, len(parent)+1)
	for _, entry := range parent {
		key, _, _ := strings.Cut(entry, "=")
		if key == "DOCKER_CONTEXT" || key == "DOCKER_HOST" {
			continue
		}
		child = append(child, entry)
	}
	return append(child, "DOCKER_HOST=unix://"+t070DockerSocket)
}

func t070EnvValue(env []string, key string) string {
	for _, entry := range env {
		name, value, found := strings.Cut(entry, "=")
		if found && name == key {
			return value
		}
	}
	return ""
}

func t070HasEnv(env []string, key string) bool {
	for _, entry := range env {
		name, _, found := strings.Cut(entry, "=")
		if found && name == key {
			return true
		}
	}
	return false
}

// t070InitStartGate makes launch and cleanup mutually exclusive: shutdown either
// closes the gate before launch, or waits until a launched process group is
// published before signaling it.
type t070InitStartGate struct {
	mu           sync.Mutex
	closed       bool
	starting     bool
	started      chan struct{}
	pgid         int
	waitDone     <-chan struct{}
	shutdownOnce sync.Once
	resolved     bool
}

func (g *t070InitStartGate) beginStart() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.starting || g.pgid != 0 {
		return false
	}
	g.starting = true
	g.started = make(chan struct{})
	return true
}

func (g *t070InitStartGate) finishStart(pgid int, waitDone <-chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.starting {
		return
	}
	g.pgid = pgid
	g.waitDone = waitDone
	g.starting = false
	close(g.started)
}

func (g *t070InitStartGate) shutdown(startWait, termWait, killWait time.Duration) bool {
	g.shutdownOnce.Do(func() {
		g.mu.Lock()
		g.closed = true
		starting, started := g.starting, g.started
		g.mu.Unlock()
		if starting {
			timer := time.NewTimer(startWait)
			defer timer.Stop()
			select {
			case <-started:
			case <-timer.C:
				g.resolved = false
				return
			}
		}
		g.mu.Lock()
		pgid, waitDone := g.pgid, g.waitDone
		g.mu.Unlock()
		g.resolved = pgid == 0 || t070StopProcessGroup(pgid, waitDone, termWait, killWait)
	})
	return g.resolved
}

func t070ProcessGroupExists(pgid int) bool {
	if pgid <= 0 {
		return false
	}
	err := syscall.Kill(-pgid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func t070StopProcessGroup(pgid int, waitDone <-chan struct{}, termWait, killWait time.Duration) bool {
	if pgid <= 0 {
		return true
	}
	if t070ProcessGroupExists(pgid) {
		if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			return false
		}
	}
	if t070WaitProcessGroupGone(pgid, waitDone, termWait) {
		return true
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return false
	}
	return t070WaitProcessGroupGone(pgid, waitDone, killWait)
}

func t070WaitProcessGroupGone(pgid int, waitDone <-chan struct{}, bound time.Duration) bool {
	deadline := time.NewTimer(bound)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		groupGone := !t070ProcessGroupExists(pgid)
		waited := false
		select {
		case <-waitDone:
			waited = true
		default:
		}
		if groupGone && waited {
			return true
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			return false
		}
	}
}

func t070InstallDockerShim(t *testing.T, project, composeFile, envFile string) (shimDir, overridePath, markerPath, realDocker string, err error) {
	t.Helper()
	realDocker, err = exec.LookPath("docker")
	if err != nil {
		return "", "", "", "", err
	}
	privateDir, err := os.MkdirTemp(t.TempDir(), "docker-shim-")
	if err != nil {
		return "", "", "", "", err
	}
	if err := os.Chmod(privateDir, 0o700); err != nil {
		return "", "", "", "", err
	}
	overridePath = filepath.Join(privateDir, "tor-build-network.yml")
	override := []byte("services:\n  tor:\n    build:\n      network: host\n")
	if err := os.WriteFile(overridePath, override, 0o600); err != nil {
		return "", "", "", "", err
	}
	if err := os.Chmod(overridePath, 0o600); err != nil {
		return "", "", "", "", err
	}
	markerPath = filepath.Join(privateDir, "compose-up-override-used")
	shim := `#!/usr/bin/env bash
set -euo pipefail
umask 077
args=("$@")
n=${#args[@]}
if (( n == 10 )) && \
   [[ ${args[0]} == compose && \
      ${args[1]} == -p && ${args[2]} == "${STARGATE_PROJECT:-}" && \
      ${args[3]} == -f && ${args[4]} == "${STARGATE_COMPOSE_FILE:-}" && \
      ${args[5]} == --env-file && ${args[6]} == "${STARGATE_ENV_FILE:-}" && \
      ${args[7]} == up && ${args[8]} == -d && ${args[9]} == --build ]]; then
  printf 'applied\n' > "${T070_COMPOSE_OVERRIDE_MARKER:?}"
  exec "${T070_REAL_DOCKER:?}" compose --progress=plain "${args[@]:1:6}" -f "${T070_COMPOSE_BUILD_OVERRIDE:?}" "${args[@]:7}"
fi
exec "${T070_REAL_DOCKER:?}" "$@"
`
	shimPath := filepath.Join(privateDir, "docker")
	if err := os.WriteFile(shimPath, []byte(shim), 0o700); err != nil {
		return "", "", "", "", err
	}
	return privateDir, overridePath, markerPath, realDocker, nil
}

func t070InitFailureNotes(output []byte) []string {
	allowed := map[string]string{
		"stargate init: observer image build failed; refusing deployment.":                         "observer_image_build_failed",
		"stargate init: observer image did not yield a content digest; refusing deployment.":       "observer_image_digest_missing",
		"stargate init: observer image/source identity changed during build; refusing deployment.": "observer_source_identity_mismatch",
		"stargate init: docker compose up failed.":                                                 "compose_up_failed",
	}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		if marker := allowed[strings.TrimSpace(line)]; marker != "" {
			seen[marker] = true
		}
	}
	markers := make([]string, 0, len(seen))
	for marker := range seen {
		markers = append(markers, marker)
	}
	sort.Strings(markers)
	return markers
}

func t070ProjectContainerStates(project string) string {
	ctx, cancel := context.WithTimeout(context.Background(), t070ExecWait)
	defer cancel()
	label := "label=com.docker.compose.project=" + project
	ids, err := t070Run(ctx, t070ExecWait, "docker", "ps", "-aq", "--filter", label)
	if err != nil {
		return "container_inventory_unavailable"
	}
	containerIDs := strings.Fields(string(ids))
	if len(containerIDs) == 0 {
		return "no_project_containers"
	}
	format := `{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Status}}|{{.State.ExitCode}}`
	args := append([]string{"inspect", "--format", format}, containerIDs...)
	output, err := t070Run(ctx, t070ExecWait, "docker", args...)
	if err != nil {
		return "container_inspection_unavailable"
	}
	var states []string
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 3 {
			return "container_inspection_invalid"
		}
		service, status := fields[0], fields[1]
		knownService := false
		for _, expected := range t070ExpectedServices {
			if expected == service {
				knownService = true
				break
			}
		}
		if !knownService {
			service = "unknown_service"
		}
		switch status {
		case "created", "restarting", "running", "removing", "paused", "exited", "dead":
		default:
			status = "unknown_state"
		}
		exitCode, err := strconv.Atoi(fields[2])
		if err != nil || exitCode < 0 || exitCode > 255 {
			exitCode = -1
		}
		states = append(states, fmt.Sprintf("%s-%s-%d", service, status, exitCode))
	}
	sort.Strings(states)
	return strings.Join(states, "+")
}

func TestT070ProcessGroupShutdownOnCancellation(t *testing.T) {
	gate := &t070InitStartGate{}
	if !gate.beginStart() {
		t.Fatal("fresh T070 start gate rejected launch")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.Command("bash", "-c", "sleep 30 & wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal("start synthetic process group")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	pgid := cmd.Process.Pid
	gate.finishStart(pgid, done)
	cancel()
	<-ctx.Done()
	if !gate.shutdown(time.Second, time.Second, 2*time.Second) || t070ProcessGroupExists(pgid) {
		t.Fatal("cancellation did not terminate and reap the synthetic process group")
	}
}

func TestT070ShutdownBeforeLaunchClosesStartGate(t *testing.T) {
	gate := &t070InitStartGate{}
	if !gate.shutdown(time.Second, time.Second, time.Second) {
		t.Fatal("shutdown of an unstarted init group was not resolved")
	}
	if gate.beginStart() {
		t.Fatal("closed T070 start gate allowed a child to launch after cleanup")
	}
}

func TestT070ShutdownWaitsForPublishedLaunch(t *testing.T) {
	gate := &t070InitStartGate{}
	if !gate.beginStart() {
		t.Fatal("fresh T070 start gate rejected launch")
	}
	shutdownDone := make(chan bool, 1)
	go func() { shutdownDone <- gate.shutdown(time.Second, time.Second, 2*time.Second) }()
	deadline := time.Now().Add(time.Second)
	for {
		gate.mu.Lock()
		closed := gate.closed
		gate.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shutdown did not close the launch gate")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-shutdownDone:
		t.Fatal("shutdown returned before the in-flight launch was published")
	default:
	}
	cmd := exec.Command("bash", "-c", "sleep 30 & wait")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal("start synthetic init child")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	gate.finishStart(cmd.Process.Pid, done)
	select {
	case ok := <-shutdownDone:
		if !ok || t070ProcessGroupExists(cmd.Process.Pid) {
			t.Fatal("shutdown did not terminate the published init process group")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("shutdown did not finish within its bounded process-group deadline")
	}
}

func TestT070ProcessGroupShutdownKillsTermResistantDescendant(t *testing.T) {
	ready := filepath.Join(t.TempDir(), "term-handler-ready")
	cmd := exec.Command("bash", "-c", `bash -c 'trap "" TERM; : > "$1"; exec sleep 30' bash "$1" & wait`, "bash", ready)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal("start synthetic process group with TERM-resistant child")
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	pgid := cmd.Process.Pid
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
			<-done
			t.Fatal("TERM-resistant descendant did not install its handler before the test")
		}
		time.Sleep(time.Millisecond)
	}
	if !t070StopProcessGroup(pgid, done, 100*time.Millisecond, 2*time.Second) || t070ProcessGroupExists(pgid) {
		t.Fatal("KILL fallback did not remove the TERM-resistant process group")
	}
}

func TestT070DockerShimPreservesExactInitUpAndOtherCommands(t *testing.T) {
	project := "stargate-t070-shim-test"
	composeFile := filepath.Join(t.TempDir(), "compose.yml")
	envFile := filepath.Join(t.TempDir(), "local.env")
	shimDir, override, marker, _, err := t070InstallDockerShim(t, project, composeFile, envFile)
	if err != nil {
		t.Fatal("prepare private Docker shim")
	}
	recorderDir := t.TempDir()
	recorder := filepath.Join(recorderDir, "docker-recorder")
	argsFile := filepath.Join(recorderDir, "args")
	recorderScript := `#!/bin/sh
printf '%s\n' "$@" > "$T070_TEST_ARGS"
exit "${T070_TEST_EXIT:-0}"
`
	if err := os.WriteFile(recorder, []byte(recorderScript), 0o700); err != nil {
		t.Fatal("create Docker CLI recorder")
	}
	for key, value := range map[string]string{
		"STARGATE_PROJECT":             project,
		"STARGATE_COMPOSE_FILE":        composeFile,
		"STARGATE_ENV_FILE":            envFile,
		"T070_REAL_DOCKER":             recorder,
		"T070_COMPOSE_BUILD_OVERRIDE":  override,
		"T070_COMPOSE_OVERRIDE_MARKER": marker,
		"T070_TEST_ARGS":               argsFile,
	} {
		t.Setenv(key, value)
	}
	initArgs := []string{"compose", "-p", project, "-f", composeFile, "--env-file", envFile, "up", "-d", "--build"}
	cmd := exec.Command(filepath.Join(shimDir, "docker"), initArgs...)
	if err := cmd.Run(); err != nil {
		t.Fatal("run exact init Compose command through shim")
	}
	got, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal("read Docker CLI recorder")
	}
	want := strings.Join([]string{"compose", "--progress=plain", "-p", project, "-f", composeFile, "--env-file", envFile, "-f", override, "up", "-d", "--build"}, "\n") + "\n"
	if string(got) != want {
		t.Fatal("exact init command did not receive only the intended plain-progress and build-override arguments")
	}
	if markerBytes, err := os.ReadFile(marker); err != nil || string(markerBytes) != "applied\n" {
		t.Fatal("exact init command did not set the override marker")
	}
	otherArgs := []string{"compose", "-p", project, "-f", composeFile, "--env-file", envFile, "ps"}
	cmd = exec.Command(filepath.Join(shimDir, "docker"), otherArgs...)
	if err := cmd.Run(); err != nil {
		t.Fatal("run unmatched Compose command through shim")
	}
	got, err = os.ReadFile(argsFile)
	if err != nil || string(got) != strings.Join(otherArgs, "\n")+"\n" {
		t.Fatal("unmatched Compose command was changed by the shim")
	}
	t.Setenv("T070_TEST_EXIT", "23")
	cmd = exec.Command(filepath.Join(shimDir, "docker"), initArgs...)
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 {
		t.Fatal("exact init shim did not preserve the Docker CLI exit status")
	}
}

func TestT070InitCommandArgsRemainExact(t *testing.T) {
	got := strings.Join(t070InitCommandArgs("/repo"), "\x00")
	want := strings.Join([]string{"bash", "/repo/scripts/stargate", "init"}, "\x00")
	if got != want {
		t.Fatal("T070 changed the exact scripts/stargate init invocation")
	}
}

func TestT070BuildxEnvironmentBoundary(t *testing.T) {
	source := filepath.Join(t.TempDir(), "docker-buildx")
	payload := []byte("reviewed buildx plugin fixture")
	if err := os.WriteFile(source, payload, 0o700); err != nil {
		t.Fatal("create executable Buildx fixture")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	configDir, err := t070PrepareBuildxConfig(source, digest)
	if err != nil {
		t.Fatal("prepare private Buildx config")
	}
	t.Cleanup(func() { _ = os.RemoveAll(configDir) })
	plugin := filepath.Join(configDir, "cli-plugins", "docker-buildx")
	copied, err := os.ReadFile(plugin)
	if err != nil || !bytes.Equal(copied, payload) {
		t.Fatal("private Buildx plugin copy does not match the source bytes")
	}
	for path, want := range map[string]os.FileMode{
		configDir:                               0o700,
		filepath.Join(configDir, "cli-plugins"): 0o700,
		plugin:                                  0o700,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatal("private Buildx config and plugin permissions are not 0700")
		}
	}
	entries, err := os.ReadDir(configDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "cli-plugins" {
		t.Fatal("Buildx config contains files beyond the isolated plugin directory")
	}
	pluginEntries, err := os.ReadDir(filepath.Join(configDir, "cli-plugins"))
	if err != nil || len(pluginEntries) != 1 || pluginEntries[0].Name() != "docker-buildx" {
		t.Fatal("Buildx plugin directory contains unexpected files")
	}

	parentEnv := []string{"DOCKER_CONFIG=/user/docker", "DOCKER_CONTEXT=user-context", "DOCKER_HOST=tcp://remote.invalid:2375", "PATH=/bin"}
	childEnv := t070InitEnvironment(parentEnv, configDir)
	if got := t070EnvValue(childEnv, "DOCKER_CONFIG"); got != configDir {
		t.Fatal("init child did not receive the isolated DOCKER_CONFIG")
	}
	if got := t070EnvValue(parentEnv, "DOCKER_CONFIG"); got != "/user/docker" {
		t.Fatal("init environment construction mutated the parent environment")
	}
	if got := t070EnvValue(childEnv, "DOCKER_HOST"); got != "unix://"+t070DockerSocket {
		t.Fatal("init child is not pinned to the local Docker socket")
	}
	if t070HasEnv(childEnv, "DOCKER_CONTEXT") {
		t.Fatal("init child retained a Docker context override")
	}
	cliEnv := t070LocalDockerEnvironment(parentEnv)
	if got := t070EnvValue(cliEnv, "DOCKER_HOST"); got != "unix://"+t070DockerSocket || t070HasEnv(cliEnv, "DOCKER_CONTEXT") {
		t.Fatal("T070 Docker CLI environment is not pinned to the local socket")
	}
	if got := t070EnvValue(cliEnv, "DOCKER_CONFIG"); got != "/user/docker" {
		t.Fatal("isolated Buildx config escaped the init child environment")
	}
}

func TestT070BuildxConfigRejectsUnsafePluginInputs(t *testing.T) {
	t.Setenv("STARGATE_T070_BUILDX_PLUGIN", "")
	if _, err := t070PrepareBuildxConfig(os.Getenv("STARGATE_T070_BUILDX_PLUGIN"), t070BuildxSHA256); err == nil {
		t.Fatal("missing Buildx plugin was accepted")
	}
	nonExecutable := filepath.Join(t.TempDir(), "non-executable-buildx")
	if err := os.WriteFile(nonExecutable, []byte("plugin"), 0o600); err != nil {
		t.Fatal("create non-executable Buildx fixture")
	}
	if _, err := t070PrepareBuildxConfig(nonExecutable, t070BuildxSHA256); err == nil {
		t.Fatal("non-executable Buildx plugin was accepted")
	}
	mismatch := filepath.Join(t.TempDir(), "mismatched-buildx")
	if err := os.WriteFile(mismatch, []byte("unexpected plugin"), 0o700); err != nil {
		t.Fatal("create mismatched Buildx fixture")
	}
	if _, err := t070PrepareBuildxConfig(mismatch, t070BuildxSHA256); err == nil {
		t.Fatal("Buildx plugin with an unreviewed digest was accepted")
	}
}

func TestT070BuildxDigestMatchesReviewedPin(t *testing.T) {
	const reviewed = "912118a5a65bf2f13dd7c2e5912857c50f43842bf4ec0f4378bcb28af66aaac3"
	if t070BuildxSHA256 != reviewed {
		t.Fatal("T070 Buildx SHA-256 differs from the reviewed plugin pin")
	}
}

func TestT070BuildxConfigCleanupWaitsForInitExit(t *testing.T) {
	configDir := t.TempDir()
	marker := filepath.Join(configDir, "plugin")
	if err := os.WriteFile(marker, []byte("plugin"), 0o600); err != nil {
		t.Fatal("create synthetic private config")
	}
	config := &t070BuildxConfig{path: configDir}
	if err := config.removeAfterProcessStop(false); err != nil {
		t.Fatal("cleanup attempted before init process stop")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("private config was removed before the init process group stopped")
	}
	if err := config.removeAfterProcessStop(true); err != nil {
		t.Fatal("cleanup after confirmed init process stop failed")
	}
	if _, err := os.Stat(configDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("private config remained after confirmed init process stop")
	}
}

func TestT070HostRunnerCleanupFailureGuards(t *testing.T) {
	runner := os.Getenv("STARGATE_T070_HOST_RUNNER")
	if runner == "" {
		t.Skip("set STARGATE_T070_HOST_RUNNER to exercise the ignored host-runner cleanup safely")
	}
	harness := `source "$1"
trap - EXIT INT TERM HUP
repo="${T070_STUB_REPO:?}"
project=stargate-t070-stub
compose=/stub/compose.yml
env_example=/stub/local.env
profile=/stub/profile
unsafe_marker="$repo/no-unsafe-marker"
owned=1
cleanup_rc=0
cleanup_failed=0
restore_step=not_started
restore_mutation_attempted=0
stub_profile=loaded
record() { printf '%s\n' "$*" >> "$T070_STUB_LOG"; }
docker_bounded() {
  local limit=$1
  shift
  record "docker $*"
  case "$1" in
    compose) return "${T070_STUB_COMPOSE_RC:-0}" ;;
    ps) return "${T070_STUB_INVENTORY_RC:-0}" ;;
    *) return 0 ;;
  esac
}
firewall_bounded() {
  local fw=$1
  shift
  record "firewall $fw $*"
  if [[ "$T070_STUB_CASE" == firewall_* && "$fw" == iptables && "$1" == -D ]]; then
    return "${T070_STUB_POLICY_RC:-23}"
  fi
  if [[ "$1" == -S && "$T070_STUB_CASE" == firewall_* ]]; then
    printf '%s\n' '-N STARGATE_DP_OUT' '-A OUTPUT -m owner --uid-owner 5102 -j STARGATE_DP_OUT' '-A STARGATE_DP_OUT -j DROP'
  elif [[ "$1" == -S && "${2:-}" == OUTPUT ]]; then
    printf '%s\n' '-P OUTPUT ACCEPT'
  elif [[ "$1" == -S ]]; then
    printf '%s\n' '-P OUTPUT ACCEPT'
  fi
  return 0
}
apparmor_profiles() {
  record 'apparmor profiles'
  if [[ "$stub_profile" == loaded ]]; then printf '%s\n' 'stargate-dp (enforce)'; fi
}
apparmor_remove() {
  record 'apparmor remove'
  if [[ "$T070_STUB_CASE" == apparmor_* ]]; then
    return "${T070_STUB_POLICY_RC:-23}"
  fi
  stub_profile=removed
  return 0
}
run_rc=0
cleanup
`
	tmp := t.TempDir()
	harnessPath := filepath.Join(tmp, "runner-cleanup-harness.sh")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o700); err != nil {
		t.Fatal("write host-runner cleanup harness")
	}
	cases := []struct {
		name       string
		composeRC  string
		inventory  string
		policyRC   string
		wantAbsent []string
		wantOutput string
	}{
		{name: "compose failure", composeRC: "23", wantAbsent: []string{"firewall "}, wantOutput: "teardown did not pass every required check"},
		{name: "compose timeout", composeRC: "124", wantAbsent: []string{"firewall "}, wantOutput: "teardown did not pass every required check"},
		{name: "inventory failure", inventory: "23", wantAbsent: []string{"firewall "}, wantOutput: "resource inventory failed"},
		{name: "inventory timeout", inventory: "124", wantAbsent: []string{"firewall "}, wantOutput: "resource inventory failed"},
		{name: "firewall failure", policyRC: "23", wantAbsent: []string{"firewall ip6tables", "apparmor remove", "returned to baseline"}, wantOutput: "policy may be partially restored"},
		{name: "firewall timeout", policyRC: "124", wantAbsent: []string{"firewall ip6tables", "apparmor remove", "returned to baseline"}, wantOutput: "policy may be partially restored"},
		{name: "apparmor failure", policyRC: "23", wantAbsent: []string{"firewall iptables -S OUTPUT", "returned to baseline"}, wantOutput: "policy may be partially restored"},
		{name: "apparmor timeout", policyRC: "124", wantAbsent: []string{"firewall iptables -S OUTPUT", "returned to baseline"}, wantOutput: "policy may be partially restored"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "runner.log")
			cmd := exec.Command("bash", harnessPath, runner)
			cmd.Env = append(os.Environ(),
				"T070_STUB_REPO="+tmp,
				"T070_STUB_LOG="+logPath,
				"T070_STUB_CASE="+strings.ReplaceAll(tc.name, " ", "_"),
				"T070_STUB_COMPOSE_RC="+tc.composeRC,
				"T070_STUB_INVENTORY_RC="+tc.inventory,
				"T070_STUB_POLICY_RC="+tc.policyRC)
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("runner cleanup did not return failure (error=%v)", err)
			}
			logBytes, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal("read stub operation log")
			}
			logText, outputText := string(logBytes), string(output)
			if !strings.Contains(outputText, tc.wantOutput) || strings.Contains(outputText, "returned to baseline") {
				t.Fatal("runner emitted an inaccurate cleanup status")
			}
			for _, forbidden := range tc.wantAbsent {
				if strings.Contains(logText, forbidden) || strings.Contains(outputText, forbidden) {
					t.Fatalf("runner performed forbidden later operation or emitted false success: %s", forbidden)
				}
			}
		})
	}
}

func TestT070HostRunnerCommandsHaveFiniteTimeouts(t *testing.T) {
	runner := os.Getenv("STARGATE_T070_HOST_RUNNER")
	if runner == "" {
		t.Skip("set STARGATE_T070_HOST_RUNNER to exercise the ignored host-runner wrappers")
	}
	harness := `source "$1"
trap - EXIT INT TERM HUP
profile=/stub/profile
timeout() { printf '%s\n' "$*" >> "$T070_STUB_LOG"; return 0; }
docker_bounded 20s info
firewall_bounded iptables -S OUTPUT
apparmor_profiles
apparmor_remove
`
	tmp := t.TempDir()
	harnessPath := filepath.Join(tmp, "runner-bounds-harness.sh")
	logPath := filepath.Join(tmp, "runner-bounds.log")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o700); err != nil {
		t.Fatal("write host-runner bounds harness")
	}
	cmd := exec.Command("bash", harnessPath, runner)
	cmd.Env = append(os.Environ(), "T070_STUB_LOG="+logPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run bounded wrapper stubs (output=%s): %v", output, err)
	}
	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal("read bounded wrapper arguments")
	}
	want := "--signal=TERM --kill-after=3s 20s docker info\n" +
		"--signal=TERM --kill-after=3s 12s iptables -w 5 -S OUTPUT\n" +
		"--signal=TERM --kill-after=3s 5s cat /sys/kernel/security/apparmor/profiles\n" +
		"--signal=TERM --kill-after=3s 12s apparmor_parser -R /stub/profile\n"
	if string(got) != want {
		t.Fatal("Docker, firewall, or AppArmor wrapper lost its finite TERM/KILL timeout")
	}
}

func t070Compose(ctx context.Context, project, composeFile, envFile string, args ...string) ([]byte, error) {
	full := []string{"compose", "-p", project, "-f", composeFile, "--env-file", envFile}
	full = append(full, args...)
	return t070Run(ctx, t070ExecWait, "docker", full...)
}

func t070ProjectResources(ctx context.Context, project string) ([]string, error) {
	containers, err := t070Run(ctx, t070ExecWait, "docker", "ps", "-aq", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return nil, err
	}
	volumes, err := t070Run(ctx, t070ExecWait, "docker", "volume", "ls", "-q", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return nil, err
	}
	networks, err := t070Run(ctx, t070ExecWait, "docker", "network", "ls", "-q", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return nil, err
	}
	resources := strings.Fields(string(containers))
	for _, volume := range strings.Fields(string(volumes)) {
		resources = append(resources, "volume:"+volume)
	}
	for _, network := range strings.Fields(string(networks)) {
		resources = append(resources, "network:"+network)
	}
	return resources, nil
}

func t070AssertProjectServices(ctx context.Context, project string, expectedStopped ...string) error {
	ids, err := t070Run(ctx, t070ExecWait, "docker", "ps", "-aq", "--filter", "label=com.docker.compose.project="+project)
	if err != nil {
		return err
	}
	stopped := make(map[string]bool, len(expectedStopped))
	for _, service := range expectedStopped {
		stopped[service] = true
	}
	got := make([]string, 0, len(t070ExpectedServices))
	for _, id := range strings.Fields(string(ids)) {
		out, err := t070Run(ctx, t070ExecWait, "docker", "inspect", "--format", `{{ index .Config.Labels "com.docker.compose.service" }} {{.State.Running}}`, id)
		if err != nil {
			return err
		}
		fields := strings.Fields(string(out))
		if len(fields) != 2 {
			return errors.New("a T070 project container lacks its Compose service identity")
		}
		wantRunning := !stopped[fields[0]]
		if (fields[1] == "true") != wantRunning {
			return errors.New("a T070 project container has an unexpected running state")
		}
		got = append(got, fields[0])
	}
	if !t070SameStrings(got, t070ExpectedServices) {
		return fmt.Errorf("project owns %d running services; expected the four Local services", len(got))
	}
	return nil
}

func t070RunningServiceID(ctx context.Context, project, composeFile, envFile, service string) (string, error) {
	out, err := t070Compose(ctx, project, composeFile, envFile, "ps", "-q", service)
	if err != nil {
		return "", err
	}
	ids := strings.Fields(string(out))
	if len(ids) != 1 {
		return "", fmt.Errorf("expected one running %s service, found %d", service, len(ids))
	}
	return ids[0], nil
}

func t070AssertStoppedService(ctx context.Context, project, composeFile, envFile, service string) error {
	id, err := t070Run(ctx, t070ExecWait, "docker", "compose", "-p", project, "-f", composeFile, "--env-file", envFile,
		"ps", "-aq", service)
	if err != nil {
		return err
	}
	ids := strings.Fields(string(id))
	if len(ids) != 1 {
		return fmt.Errorf("expected one owned %s container after stop, found %d", service, len(ids))
	}
	out, err := t070Run(ctx, t070ExecWait, "docker", "inspect", "--format", `{{.State.Running}}`, ids[0])
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "false" {
		return errors.New("selected Tor service is still running")
	}
	return nil
}

func t070SeedToken(ctx context.Context, project, token string) error {
	vol := project + "_stargate-control-config"
	content := fmt.Sprintf("tokens:\n  - label: t070-integration\n    token: %s\n", token)
	cmdCtx, cancel := context.WithTimeout(ctx, t070ExecWait)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, "docker", "run", "--rm", "-i", "--user", "0:0", "--entrypoint", "sh",
		"-v", vol+":/tgt", "stargate/tor:local", "-c", "test -d /tgt/keys && cat > /tgt/tokens.yaml")
	cmd.Stdin = strings.NewReader(content)
	out := &t070BoundedOutput{limit: 64 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil || out.overflowed() {
		return errors.New("scoped Docker token seeding command did not complete")
	}
	return nil
}

func t070PositiveControl(ctx context.Context, token string) error {
	deadline := time.Now().Add(t070ControlWait)
	var lastErr error
	for time.Now().Before(deadline) {
		attemptCtx, cancel := context.WithDeadline(ctx, deadline)
		conn, err := t070SOCKSConnect(attemptCtx, token, t070ReferenceOnion, t070ReferencePort)
		cancel()
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("no positive SOCKS success reply within %s (last attempt: %v)", t070ControlWait, lastErr)
}

func t070SOCKSConnect(ctx context.Context, token, host string, port uint16) (net.Conn, error) {
	conn, err := (&net.Dialer{Timeout: t070SocketWait}).DialContext(ctx, "tcp", "127.0.0.1:8881")
	if err != nil {
		return nil, err
	}
	return t070SOCKSConnectOnConn(ctx, token, host, port, conn)
}

func t070SOCKSConnectOnConn(ctx context.Context, token, host string, port uint16, conn net.Conn) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(t070ControlWait)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stopCancel()
	fail := func(err error) (net.Conn, error) { _ = conn.Close(); return nil, err }
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if err := t070WriteAll(conn, []byte{0x05, 0x01, 0x02}); err != nil {
		return fail(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil || !bytes.Equal(method, []byte{0x05, 0x02}) {
		return fail(errors.New("SOCKS5 username/password method was not selected"))
	}
	username := t131PartitionUsername(token, host)
	if len(username) > 255 || len(token) > 255 {
		return fail(errors.New("test credential exceeds RFC 1929 field bound"))
	}
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(token)))
	auth = append(auth, token...)
	if err := t070WriteAll(conn, auth); err != nil {
		return fail(err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil || !bytes.Equal(authReply, []byte{0x01, 0x00}) {
		return fail(errors.New("SOCKS5 bearer authentication was not accepted"))
	}
	if len(host) > 255 {
		return fail(errors.New("test target exceeds SOCKS5 domain bound"))
	}
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	request = append(request, host...)
	request = append(request, byte(port>>8), byte(port))
	if err := t070WriteAll(conn, request); err != nil {
		return fail(err)
	}
	reply, err := t070ReadSOCKSReply(conn)
	if err != nil {
		return fail(err)
	}
	if len(reply) < 2 || reply[0] != 0x05 || reply[1] != 0x00 {
		return fail(errors.New("authenticated live onion CONNECT did not return REP success"))
	}
	return conn, nil
}

func t070ReadSOCKSReply(conn net.Conn) ([]byte, error) {
	first := make([]byte, 4)
	if _, err := io.ReadFull(conn, first); err != nil {
		return nil, err
	}
	if first[0] != 0x05 || first[2] != 0 {
		return nil, errors.New("SOCKS5 reply has an invalid version or reserved byte")
	}
	reply := append([]byte(nil), first...)
	switch first[3] {
	case 0x01:
		rest := make([]byte, 6)
		_, err := io.ReadFull(conn, rest)
		return append(reply, rest...), err
	case 0x04:
		rest := make([]byte, 18)
		_, err := io.ReadFull(conn, rest)
		return append(reply, rest...), err
	case 0x03:
		length := []byte{0}
		if _, err := io.ReadFull(conn, length); err != nil {
			return nil, err
		}
		rest := make([]byte, int(length[0])+2)
		_, err := io.ReadFull(conn, rest)
		return append(append(reply, length[0]), rest...), err
	default:
		return nil, errors.New("SOCKS5 reply used an unsupported address type")
	}
}

func t070WriteAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func t070RouteDownProbe(ctx context.Context, token string) ([]byte, error) {
	conn, err := (&net.Dialer{Timeout: t070SocketWait}).DialContext(ctx, "tcp", "127.0.0.1:8881")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(t070SocketWait)); err != nil {
		return nil, err
	}
	if err := t070WriteAll(conn, []byte{0x05, 0x01, 0x02}); err != nil {
		return nil, err
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil || !bytes.Equal(method, []byte{0x05, 0x02}) {
		return nil, errors.New("route-down request did not negotiate username/password authentication")
	}
	username := t131PartitionUsername(token, t070DownOnion)
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(token)))
	auth = append(auth, token...)
	if err := t070WriteAll(conn, auth); err != nil {
		return nil, err
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil || !bytes.Equal(authReply, []byte{0x01, 0x00}) {
		return nil, errors.New("route-down probe bearer authentication was not accepted")
	}
	if len(t070DownOnion) > 255 {
		return nil, errors.New("synthetic route-down target exceeds SOCKS5 domain bound")
	}
	request := []byte{0x05, 0x01, 0x00, 0x03, byte(len(t070DownOnion))}
	request = append(request, t070DownOnion...)
	request = append(request, 0x01, 0xbb)
	if err := t070WriteAll(conn, request); err != nil {
		return nil, err
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, errors.New("route-down reply was incomplete or failed to arrive before the bounded deadline")
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err := t070RequireImmediateEOF(conn); err != nil {
		return nil, errors.New("route-down response did not close at EOF immediately after its first ten bytes")
	}
	return reply, nil
}

func t070RequireImmediateEOF(conn net.Conn) error {
	var trailing [1]byte
	n, err := conn.Read(trailing[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		return errors.New("response had trailing data or did not close at EOF")
	}
	return nil
}

func t070AssertDropBoundary(ctx context.Context) error {
	for _, family := range []string{"iptables", "ip6tables"} {
		output, err := t070Run(ctx, t070ExecWait, family, "-w", "-S", "OUTPUT")
		if err != nil {
			return errors.New("host OUTPUT rule list is unavailable for one address family")
		}
		if !t070ExactFirstOutputOwnerRule(string(output)) {
			return errors.New("DP owner rule is not first in host OUTPUT for one address family")
		}
		rules, err := t070Run(ctx, t070ExecWait, family, "-w", "-S", "STARGATE_DP_OUT")
		if err != nil {
			return errors.New("STARGATE_DP_OUT chain is unavailable for one address family")
		}
		if !t070ValidDropBoundaryChain(string(rules)) {
			return errors.New("host no-egress chain does not contain the expected loopback exception and terminal DROP")
		}
	}
	return nil
}

func t070ExactFirstOutputOwnerRule(output string) bool {
	const expected = "-A OUTPUT -m owner --uid-owner 5102 -j STARGATE_DP_OUT"
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "-A OUTPUT ") {
			return strings.TrimSpace(line) == expected
		}
	}
	return false
}

func t070ValidDropBoundaryChain(output string) bool {
	var rules []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "-N STARGATE_DP_OUT" {
			continue
		}
		if !strings.HasPrefix(line, "-A STARGATE_DP_OUT ") {
			return false
		}
		rules = append(rules, line)
	}
	if len(rules) != 2 {
		return false
	}
	validLoopbackRule := rules[0] == "-A STARGATE_DP_OUT -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" ||
		rules[0] == "-A STARGATE_DP_OUT -o lo -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
	return validLoopbackRule && rules[1] == "-A STARGATE_DP_OUT -j DROP"
}

func TestT070ValidDropBoundaryChain(t *testing.T) {
	valid := "-N STARGATE_DP_OUT\n-A STARGATE_DP_OUT -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n-A STARGATE_DP_OUT -j DROP\n"
	if !t070ValidDropBoundaryChain(valid) {
		t.Fatal("valid firewall chain declaration and exact rules were rejected")
	}
	canonical := "-N STARGATE_DP_OUT\n-A STARGATE_DP_OUT -o lo -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n-A STARGATE_DP_OUT -j DROP\n"
	if !t070ValidDropBoundaryChain(canonical) {
		t.Fatal("iptables canonical conntrack-state ordering was rejected")
	}
	for _, invalid := range []string{
		"-N STARGATE_DP_OUT\n-A STARGATE_DP_OUT -o lo -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n",
		valid + "-A STARGATE_DP_OUT -j DROP\n",
		"-N STARGATE_DP_OUT\n-A STARGATE_DP_OUT -j ACCEPT\n-A STARGATE_DP_OUT -j DROP\n",
		"-N STARGATE_DP_OUT\n-A STARGATE_DP_OUT -o lo -m conntrack --ctstate RELATED,ESTABLISHED,NEW -j ACCEPT\n-A STARGATE_DP_OUT -j DROP\n",
		"-N STARGATE_DP_OUT\n-A STARGATE_DP_OUT -o lo -m conntrack --ctstate ESTABLISHED -j ACCEPT\n-A STARGATE_DP_OUT -j DROP\n",
		valid + "-X unexpected\n",
	} {
		if t070ValidDropBoundaryChain(invalid) {
			t.Fatal("malformed or extended firewall chain was accepted")
		}
	}
}

func TestT070OutputOwnerRuleMustBeExactFirstRule(t *testing.T) {
	valid := "-P OUTPUT ACCEPT\n-A OUTPUT -m owner --uid-owner 5102 -j STARGATE_DP_OUT\n"
	if !t070ExactFirstOutputOwnerRule(valid) {
		t.Fatal("exact first OUTPUT owner jump was rejected")
	}
	for _, invalid := range []string{
		"-P OUTPUT ACCEPT\n-A OUTPUT -o lo -m owner --uid-owner 5102 -j STARGATE_DP_OUT\n",
		"-P OUTPUT ACCEPT\n-A OUTPUT -j ACCEPT\n-A OUTPUT -m owner --uid-owner 5102 -j STARGATE_DP_OUT\n",
	} {
		if t070ExactFirstOutputOwnerRule(invalid) {
			t.Fatal("restricted, reordered, or mismatched first OUTPUT rule was accepted")
		}
	}
}

func TestT070RouteDownRequiresImmediateEOF(t *testing.T) {
	t.Run("clean EOF", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		_ = server.Close()
		if err := t070RequireImmediateEOF(client); err != nil {
			t.Fatal("immediate EOF was rejected")
		}
	})
	t.Run("trailing byte", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		go func() { _, _ = server.Write([]byte{0x7f}) }()
		if err := t070RequireImmediateEOF(client); err == nil {
			t.Fatal("one trailing byte was accepted")
		}
	})
	t.Run("non-EOF read error", func(t *testing.T) {
		if err := t070RequireImmediateEOF(t070ReadErrorConn{readErr: errors.New("synthetic read failure")}); err == nil {
			t.Fatal("non-EOF read error was accepted")
		}
	})
}

type t070ReadErrorConn struct {
	net.Conn
	readErr error
}

func (c t070ReadErrorConn) Read([]byte) (int, error) { return 0, c.readErr }

func TestT070DockerAttachRequiresUpgradeHandshake(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal("listen on synthetic Docker Unix socket")
	}
	release := make(chan struct{})
	attachSeen := make(chan bool, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"ApiVersion":"1.45"}`)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1.45/containers/abcdef0123456789/attach" ||
			r.URL.Query().Get("stream") != "1" || r.URL.Query().Get("stdout") != "1" ||
			r.URL.Query().Get("stderr") != "1" || r.URL.Query().Get("stdin") != "0" ||
			r.Header.Get("Upgrade") != "tcp" || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			attachSeen <- false
			http.Error(w, "unexpected attach request", http.StatusBadRequest)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			attachSeen <- false
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			attachSeen <- false
			return
		}
		_, _ = io.WriteString(rw, "HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n")
		_ = rw.Flush()
		_, _ = conn.Write([]byte("live-stream"))
		attachSeen <- true
		<-release
		_ = conn.Close()
	})}
	serveDone := make(chan struct{})
	go func() { _ = server.Serve(listener); close(serveDone) }()
	defer func() {
		close(release)
		_ = server.Close()
		<-serveDone
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	body, transport, err := t070DockerAttach(ctx, socketPath, "abcdef0123456789")
	if err != nil {
		t.Fatal("Docker attach upgrade handshake was rejected")
	}
	defer transport.CloseIdleConnections()
	defer body.Close()
	if ok := <-attachSeen; !ok {
		t.Fatal("Docker daemon did not receive the bounded live stdout/stderr request")
	}
	stream := make([]byte, len("live-stream"))
	if _, err := io.ReadFull(body, stream); err != nil || string(stream) != "live-stream" {
		t.Fatal("confirmed Docker attach stream did not carry the live test frame")
	}
}

func TestT070DockerAttachRejectsUnconfirmedConnection(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal("listen on synthetic Docker Unix socket")
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			_, _ = io.WriteString(w, `{"ApiVersion":"1.45"}`)
			return
		}
		http.Error(w, "attach unavailable", http.StatusServiceUnavailable)
	})}
	serveDone := make(chan struct{})
	go func() { _ = server.Serve(listener); close(serveDone) }()
	defer func() { _ = server.Close(); <-serveDone }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if body, transport, err := t070DockerAttach(ctx, socketPath, "abcdef0123456789"); err == nil {
		_ = body.Close()
		transport.CloseIdleConnections()
		t.Fatal("Docker attach without an HTTP upgrade was treated as confirmed")
	}
}

func TestT070SOCKSHandshakeUsesAttemptDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tracked := &t070TrackedConn{Conn: client, readStarted: make(chan struct{}, 1), writeStarted: make(chan struct{}, 1), deadlines: make(chan time.Time, 4)}
	peerDone := make(chan error, 1)
	go func() { peerDone <- t070SyntheticSOCKSPeer(server) }()
	attemptCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	conn, err := t070SOCKSConnectOnConn(attemptCtx, "token", "example.onion", 443, tracked)
	if err != nil {
		t.Fatal("synthetic authenticated SOCKS handshake failed")
	}
	_ = conn.Close()
	deadline := <-tracked.deadlines
	ctxDeadline, ok := attemptCtx.Deadline()
	if !ok || deadline != ctxDeadline || time.Until(deadline) < 250*time.Second {
		t.Fatal("SOCKS handshake did not retain the bounded attempt deadline of at least 250 seconds")
	}
	if err := <-peerDone; err != nil {
		t.Fatal("synthetic SOCKS peer failed")
	}
}

func TestT070SOCKSHandshakeCancellationInterruptsBlockedIO(t *testing.T) {
	for _, direction := range []string{"read", "write"} {
		t.Run(direction, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			tracked := &t070TrackedConn{Conn: client, readStarted: make(chan struct{}, 1), writeStarted: make(chan struct{}, 1), deadlines: make(chan time.Time, 4)}
			peerReady := make(chan struct{})
			peerRelease := make(chan struct{})
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(peerRelease) })
			if direction == "read" {
				go func() {
					_, _ = io.CopyN(io.Discard, server, 3)
					close(peerReady)
					<-peerRelease
				}()
			} else {
				close(peerReady)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				conn, err := t070SOCKSConnectOnConn(ctx, "token", "example.onion", 443, tracked)
				if conn != nil {
					_ = conn.Close()
				}
				done <- err
			}()
			<-peerReady
			if direction == "read" {
				<-tracked.readStarted
			} else {
				<-tracked.writeStarted
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled SOCKS handshake returned success")
				}
			case <-time.After(time.Second):
				t.Fatal("context cancellation did not interrupt blocked SOCKS I/O")
			}
			releaseOnce.Do(func() { close(peerRelease) })
			_ = client.Close()
		})
	}
}

type t070TrackedConn struct {
	net.Conn
	readStarted  chan struct{}
	writeStarted chan struct{}
	deadlines    chan time.Time
}

func (c *t070TrackedConn) Read(p []byte) (int, error) {
	select {
	case c.readStarted <- struct{}{}:
	default:
	}
	return c.Conn.Read(p)
}

func (c *t070TrackedConn) Write(p []byte) (int, error) {
	select {
	case c.writeStarted <- struct{}{}:
	default:
	}
	return c.Conn.Write(p)
}

func (c *t070TrackedConn) SetDeadline(deadline time.Time) error {
	select {
	case c.deadlines <- deadline:
	default:
	}
	return c.Conn.SetDeadline(deadline)
}

func t070SyntheticSOCKSPeer(conn net.Conn) error {
	greeting := make([]byte, 3)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		return err
	}
	userPassHeader := make([]byte, 2)
	if _, err := io.ReadFull(conn, userPassHeader); err != nil {
		return err
	}
	user := make([]byte, int(userPassHeader[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	passwordLen := []byte{0}
	if _, err := io.ReadFull(conn, passwordLen); err != nil {
		return err
	}
	password := make([]byte, int(passwordLen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return err
	}
	requestHeader := make([]byte, 5)
	if _, err := io.ReadFull(conn, requestHeader); err != nil {
		return err
	}
	target := make([]byte, int(requestHeader[4])+2)
	if _, err := io.ReadFull(conn, target); err != nil {
		return err
	}
	_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

type t070Counters struct{ v4, v6 uint64 }

func t070DropCounters(ctx context.Context) (t070Counters, error) {
	counters := make([]uint64, 2)
	for i, family := range []string{"iptables", "ip6tables"} {
		out, err := t070Run(ctx, t070ExecWait, family, "-w", "-nvx", "-L", "STARGATE_DP_OUT")
		if err != nil {
			return t070Counters{}, errors.New("cannot read STARGATE_DP_OUT counters in both IP families")
		}
		found := false
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[2] != "DROP" {
				continue
			}
			if found {
				return t070Counters{}, errors.New("egress chain has multiple DROP rules")
			}
			packets, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				return t070Counters{}, errors.New("DROP packet counter is not an unsigned integer")
			}
			counters[i], found = packets, true
		}
		if !found {
			return t070Counters{}, errors.New("egress chain has no DROP counter")
		}
	}
	return t070Counters{v4: counters[0], v6: counters[1]}, nil
}

func t070LoadLeakCorpus(path string) ([][]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var corpus [][]byte
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			corpus = append(corpus, []byte(line))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(corpus) == 0 {
		return nil, errors.New("shared leak corpus is empty")
	}
	return corpus, nil
}

type t070BoundedOutput struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (b *t070BoundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	originalLength := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.overflow = true
		return originalLength, nil
	}
	if len(p) > remaining {
		b.overflow = true
		p = p[:remaining]
	}
	_, _ = b.buf.Write(p)
	return originalLength, nil
}

func (b *t070BoundedOutput) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.buf.Bytes())
}

func (b *t070BoundedOutput) overflowed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.overflow
}

type t070LiveCapture struct {
	cancel    context.CancelFunc
	body      io.ReadCloser
	transport *http.Transport
	out       *t070BoundedOutput
	done      chan error
	stopMu    sync.Once
}

func t070StartLiveCapture(ctx context.Context, t *testing.T, containerID string) *t070LiveCapture {
	t.Helper()
	if os.Getenv("DOCKER_CONTEXT") != "" || os.Getenv("DOCKER_HOST") != "unix://"+t070DockerSocket {
		t.Fatalf("T070 diagnostics require the explicitly pinned local Docker Unix socket")
	}
	streamCtx, cancel := context.WithCancel(ctx)
	body, transport, err := t070DockerAttach(streamCtx, t070DockerSocket, containerID)
	if err != nil {
		cancel()
		t.Fatalf("Docker daemon did not confirm the live DP stdout/stderr attach handshake (logging driver none forbids docker logs)")
	}
	capture := &t070LiveCapture{
		cancel:    cancel,
		body:      body,
		transport: transport,
		out:       &t070BoundedOutput{limit: t070CaptureLimit},
		done:      make(chan error, 1),
	}
	go func() {
		_, readErr := io.Copy(capture.out, body)
		capture.done <- readErr
	}()
	capture.requireAlive(t, "before the first request")
	return capture
}

func t070DockerAttach(ctx context.Context, socketPath, containerID string) (io.ReadCloser, *http.Transport, error) {
	if !regexp.MustCompile(`^[a-fA-F0-9]{12,64}$`).MatchString(containerID) {
		return nil, nil, errors.New("invalid Docker container identity")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: t070ExecWait}).DialContext(ctx, "unix", socketPath)
		},
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client := &http.Client{Transport: transport}
	closeTransport := func(err error) (io.ReadCloser, *http.Transport, error) {
		transport.CloseIdleConnections()
		return nil, nil, err
	}
	versionReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/version", nil)
	if err != nil {
		return closeTransport(errors.New("create Docker API version request"))
	}
	versionResp, err := client.Do(versionReq)
	if err != nil {
		return closeTransport(errors.New("Docker API version request failed"))
	}
	var version struct {
		APIVersion string `json:"ApiVersion"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(versionResp.Body, 64<<10)).Decode(&version)
	_ = versionResp.Body.Close()
	if versionResp.StatusCode != http.StatusOK || decodeErr != nil || !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version.APIVersion) {
		return closeTransport(errors.New("Docker API version response was invalid"))
	}
	attachURL := "http://docker/v" + version.APIVersion + "/containers/" + url.PathEscape(containerID) + "/attach?stream=1&stdout=1&stderr=1&stdin=0"
	attachReq, err := http.NewRequestWithContext(ctx, http.MethodPost, attachURL, nil)
	if err != nil {
		return closeTransport(errors.New("create Docker attach request"))
	}
	attachReq.Header.Set("Connection", "Upgrade")
	attachReq.Header.Set("Upgrade", "tcp")
	attachResp, err := client.Do(attachReq)
	if err != nil {
		return closeTransport(errors.New("Docker attach request failed"))
	}
	if attachResp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(attachResp.Header.Get("Upgrade"), "tcp") {
		_ = attachResp.Body.Close()
		return closeTransport(errors.New("Docker attach did not complete the TCP upgrade handshake"))
	}
	return attachResp.Body, transport, nil
}

func (c *t070LiveCapture) requireAlive(t *testing.T, phase string) {
	t.Helper()
	select {
	case <-c.done:
		t.Fatalf("live DP diagnostics reader exited %s", phase)
	default:
	}
	if c.out.overflowed() {
		t.Fatalf("live DP diagnostics exceeded the bounded %d-byte capture", t070CaptureLimit)
	}
}

func (c *t070LiveCapture) stop() {
	if c == nil {
		return
	}
	c.stopMu.Do(func() {
		select {
		case <-c.done:
		default:
			c.cancel()
			_ = c.body.Close()
			c.transport.CloseIdleConnections()
			select {
			case <-c.done:
			case <-time.After(5 * time.Second):
			}
		}
	})
}

func (c *t070LiveCapture) stopAndBytes(t *testing.T) string {
	t.Helper()
	c.requireAlive(t, "at the end of the route-down request window")
	c.stop()
	if c.out.overflowed() {
		t.Fatalf("live DP diagnostics exceeded the bounded %d-byte capture", t070CaptureLimit)
	}
	return string(c.out.bytes())
}
