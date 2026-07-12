//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// live_sidecar_test.go is the live-sidecar gate named by
// contracts/torrc.md §"live_sidecar_test.go" and FR-011 (spec.md §"Sidecar
// configuration"). It closes the gap between "the rendered file contains
// IsolateSOCKSAuth" (gated statically by T029's byte-match and T030's
// parsed-directive invariants) and "Tor actually loaded IsolateSOCKSAuth" —
// a syntactically valid torrc whose flag Tor silently ignores (a renderer
// typo that Tor accepts-but-warns on, an alias change, or directive drift
// across Tor versions) would pass every static gate and still break
// per-first-party stream isolation (Principle III).
//
// Constitution Principle VII (tests-first for privacy-critical paths) lands
// here as: this gate exists before the data-plane forwarder (T047) ships,
// pinning the Tor-side load behaviour T047's outbound contract depends on.
//
// Test shape: bring up the tor sidecar from compose/docker-compose.local.yml
// with the rendered v1 torrc seeded into the stargate-tor-config named
// volume, wait for bootstrap, then AUTHENTICATE over the cookie-authenticated
// control port and assert GETCONF SocksPort reports both IsolateClientAddr
// and IsolateSOCKSAuth.
//
// Decoupling from the control plane (T037 TorrcRenderer): stargate-control
// is not buildable at /start time (no .java files under control-plane/ —
// same content-gating state T019b self-skips on for stargate-dp). T032's
// contract is "given the rendered torrc, Tor loads these flags", NOT "the
// control plane renders correctly" (that is T037, gated by T029 byte-match
// + T037's JUnit test). The test seeds the volume with the exact wantTorrc
// golden T029 pins — no third transcription. When T037 lands the seed step
// becomes redundant for the rendering path, but T032 still independently
// verifies Tor-side load behaviour (two failure modes, two tests).
//
// Control-port access: the cookie file lives on stargate-tor-state, mounted
// only into the tor service. A bridge-network probe container can dial
// tor:9051 (T019b sub-test (c) proves reachability) but cannot read the
// cookie to authenticate. T032 runs the AUTHENTICATE+GETCONF+QUIT exchange
// inside the tor container as USER tor (which owns the cookie), mirroring
// the sidecars/tor/Dockerfile HEALTHCHECK exactly. T062 will land a Go-side
// TCP+cookie client in Phase 4 (US2); T032 (Phase 3) cannot depend on it.
//
// The test consumes the package-level wantTorrc golden pinned by T029
// rather than re-transcribing the torrc, and reuses the same digest-pinned
// alpine probe image as T019b (tests/contract/tor/port_exposure_test.go) for
// the seed container — a future ticket may hoist that pin into a shared
// constant if more contract tests need ephemeral probe images.
//
// NOT executed by the hermetic PR run of scripts/verify.sh: this file is
// build-tagged `//go:build docker` (T076 §Acceptance #4 — live/Docker
// cadence is kept separate from the hermetic PR gate). verify.sh
// compile-checks it via `go vet -tags docker` and accounts it SKIP[docker]
// in the hermetic PR run. The named Docker job executes it via
// `STARGATE_TEST_TAGS=docker scripts/verify.sh`, or manually:
// `cd tests/contract && go test -tags docker ./torrc/ -run TestLiveSidecarGETCONFSocksPort -v -timeout 15m`.
// The sibling torrc tests (invariants, no_bridges, render_byte_match) are
// hermetic and run in the PR gate. Same self-invocation model as T029/T030/T031.
package torrc

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
)

// liveComposeProject namespaces every compose invocation this test issues so
// the test never collides with operator-authored state brought up under the
// default project name. `docker compose down --volumes --remove-orphans` in
// t.Cleanup tears the whole stack down regardless of which services started.
// Mirrors T019b's composeProject pattern (tests/contract/tor/).
const liveComposeProject = "stargate-t032-test"

// liveProbeImage is the ephemeral container image used to seed the
// stargate-tor-config named volume with the rendered torrc before the tor
// service starts. SAME digest-pinned alpine image T019b uses for its bridge
// reachability probe (tests/contract/tor/port_exposure_test.go) — kept in
// lock-step so a deliberate pin rotation rolls both spots together. See
// T019b's probeImage comment for the bump procedure and Principle IV
// rationale.
const liveProbeImage = "alpine:3@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

// bootstrapDeadline caps the wait for Tor to reach BOOTSTRAP PROGRESS=100
// after the seeded tor service starts. Tor bootstrap depends on the host
// network + live Tor network (guard selection, consensus download); 5
// minutes matches T019b's compose `up` timeout ceiling and is generous for a
// healthy first-run bootstrap. Exceeding it fails the test for environmental
// reasons (network partition, slow guards) — the bootstrap-phase response is
// surfaced in the failure message for diagnosis.
const bootstrapDeadline = 5 * time.Minute

// bootstrapPollInterval paces the control-port bootstrap-phase poll. Tor's
// bootstrap is observable as a PROGRESS=N counter on
// `GETINFO status/bootstrap-phase`; polling every 2s catches completion
// within ~2s without hammering the control port while Tor is still building
// circuits.
const bootstrapPollInterval = 2 * time.Second

// TestLiveSidecarGETCONFSocksPort gates FR-011 / contracts/torrc.md invariant
// #1 at the live-sidecar layer: bring up the tor sidecar with the rendered
// v1 torrc seeded into the stargate-tor-config volume, wait for bootstrap,
// then query GETCONF SocksPort over the cookie-authenticated control port
// and assert the response carries both IsolateClientAddr and
// IsolateSOCKSAuth (the privacy-load-bearing half — per-first-party stream
// isolation depends on it, Principle III).
//
// Subtests:
//   - TorBootstrapsWithRenderedTorrc: the rendered torrc parses cleanly and
//     Tor reaches PROGRESS=100 (a syntactically invalid torrc or an
//     unrecognised directive fails bootstrap or refuses to start).
//   - GETCONFReportsIsolateClientAddr: Tor loaded the IsolateClientAddr flag.
//   - GETCONFReportsIsolateSOCKSAuth: Tor loaded IsolateSOCKSAuth (the
//     privacy-load-bearing half of invariant #1).
//
// Self-skips when the docker daemon is unreachable or the docker CLI is not
// on PATH (mirrors T019b's skip conditions). Does NOT skip on control-plane
// unbuilt — the test seeds the volume directly with the wantTorrc golden.
func TestLiveSidecarGETCONFSocksPort(t *testing.T) {
	ctx := context.Background()

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		t.Skipf("docker SDK client init failed (daemon unreachable?): %v", err)
	}
	defer cli.Close()
	if _, err := cli.Ping(ctx); err != nil {
		t.Skipf("docker daemon ping failed (daemon unreachable?): %v", err)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker CLI not on PATH: %v", err)
	}

	// Reuse the package-level findRepoRoot pinned by T029 (walks up to the
	// dir containing specs/001-tor-route/contracts/torrc.md); the compose
	// file + env live under compose/ at that same root.
	repoRoot := findRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	if _, err := os.Stat(composeFile); err != nil {
		t.Fatalf("compose file missing: %v", err)
	}
	if _, err := os.Stat(envFile); err != nil {
		t.Fatalf("env file missing: %v", err)
	}

	// Register cleanup BEFORE any compose invocation. If `up --no-start`
	// partially succeeds (volume + network created) but compose returns
	// non-zero (build cache failure, daemon hiccup), t.Fatalf would fire
	// here — and only previously-registered Cleanups run on Fatalf.
	// Pre-registration is the standard idempotent-test pattern; `compose
	// down` on a never-brought-up project is a no-op. Mirrors T019b.
	t.Cleanup(func() {
		downCtx, dcancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer dcancel()
		if out, err := liveDockerCompose(downCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// (1) Create the tor container + its named volumes WITHOUT starting it.
	// `up --no-start` builds the image and creates the container, volumes,
	// and network but does not run the ENTRYPOINT — so tor never reads
	// /etc/tor/torrc. This gives the seed step (2) a fresh named volume to
	// write into before the first tor start. `--build` is belt-and-braces:
	// forces a rebuild against the current Dockerfile so the test
	// exercises the on-disk contract (mirrors T019b's stance).
	noStartCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if out, err := liveDockerCompose(noStartCtx, composeFile, envFile, "up", "--no-start", "--build", "tor"); err != nil {
		t.Fatalf("docker compose up --no-start tor: %v\n%s", err, out)
	}

	// (2) Seed the stargate-tor-config named volume with the rendered torrc
	// BEFORE the tor service starts. Resolves the actual volume name via
	// the SDK's label filter rather than string-concatenating the
	// undocumented `<project>_<volume>` Compose v2 convention (mirrors
	// T019b's lookupComposeNetwork stance on network names).
	volumeName, err := lookupComposeVolume(ctx, cli, liveComposeProject, "stargate-tor-config")
	if err != nil {
		t.Fatalf("lookup stargate-tor-config volume for project %q: %v — "+
			"did `up --no-start` actually create the volume?", liveComposeProject, err)
	}
	if err := seedTorrcVolume(ctx, volumeName, []byte(wantTorrc)); err != nil {
		t.Fatalf("seeding rendered torrc into volume %s: %v", volumeName, err)
	}
	t.Logf("seeded %d-byte rendered torrc into volume %s", len(wantTorrc), volumeName)

	// (3) Start the tor service with the seeded volume mounted :ro. The
	// image is already built (step 1); no `--build` needed here.
	upCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	if out, err := liveDockerCompose(upCtx, composeFile, envFile, "up", "-d", "tor"); err != nil {
		t.Fatalf("docker compose up -d tor (after seed): %v\n%s", err, out)
	}

	// (4) Bootstrap wait — gates "the rendered torrc parses cleanly and Tor
	// starts". A torrc with a syntactically invalid directive or an
	// unrecognised flag (the exact regression this test exists to catch)
	// fails bootstrap or refuses to start, surfacing here rather than in
	// the GETCONF assertion where the failure mode would be opaque.
	t.Run("TorBootstrapsWithRenderedTorrc", func(t *testing.T) {
		phase, err := waitForBootstrap(ctx, composeFile, envFile, bootstrapDeadline)
		if err != nil {
			t.Fatalf("Tor did not bootstrap with the rendered torrc within %s: %v\n"+
				"last bootstrap-phase response: %s\n"+
				"(a syntactically invalid torrc or an unrecognised directive would "+
				"surface here — check `docker compose -p %s logs tor` for tor's "+
				"config-parse diagnostics)",
				bootstrapDeadline, err, phase, liveComposeProject)
		}
		t.Logf("Tor bootstrapped: %s", strings.TrimSpace(phase))
	})

	// (5) The GETCONF assertion — the contract T032 exists to gate. The
	// exchange runs inside the tor container as USER tor (cookie owner),
	// mirroring the sidecars/tor/Dockerfile HEALTHCHECK. Parse the response
	// in Go for clear, named failure messages.
	getconfOut, err := getconfSocksPort(ctx, composeFile, envFile)
	if err != nil {
		t.Fatalf("GETCONF SocksPort over control port: %v\noutput:\n%s", err, getconfOut)
	}
	t.Logf("GETCONF SocksPort response:\n%s", getconfOut)

	socksPortValue, err := parseGetconfValue(getconfOut, "SocksPort")
	if err != nil {
		t.Fatalf("parsing GETCONF SocksPort response: %v\nraw output:\n%s", err, getconfOut)
	}

	// Row 1 — IsolateClientAddr (the non-privacy-load-bearing half; still
	// required by contracts/torrc.md invariant #1).
	t.Run("GETCONFReportsIsolateClientAddr", func(t *testing.T) {
		if !containsToken(socksPortValue, "IsolateClientAddr") {
			t.Errorf("GETCONF SocksPort %q does NOT carry IsolateClientAddr — "+
				"contracts/torrc.md invariant #1 (FR-011). Tor did not load "+
				"the flag the rendered torrc carries; check `docker compose "+
				"-p %s logs tor` for a config-parse warning.",
				socksPortValue, liveComposeProject)
		}
	})

	// Row 1 — IsolateSOCKSAuth (privacy-load-bearing: per-first-party stream
	// isolation depends on it, Principle III).
	t.Run("GETCONFReportsIsolateSOCKSAuth", func(t *testing.T) {
		if !containsToken(socksPortValue, "IsolateSOCKSAuth") {
			t.Errorf("GETCONF SocksPort %q does NOT carry IsolateSOCKSAuth — "+
				"contracts/torrc.md invariant #1 (privacy-load-bearing: "+
				"per-first-party stream isolation depends on it, Principle III). "+
				"Tor did not load the flag the rendered torrc carries; check "+
				"`docker compose -p %s logs tor` for a config-parse warning.",
				socksPortValue, liveComposeProject)
		}
	})
}

// waitForBootstrap polls Tor's GETINFO status/bootstrap-phase over the
// cookie-authenticated control port until PROGRESS=100 appears, or deadline
// elapses. Returns the final phase response (for diagnostics on timeout).
// The exchange runs inside the tor container via `docker compose exec`,
// mirroring the Dockerfile HEALTHCHECK: read the cookie file at
// /var/lib/tor/control_auth_cookie (owned by tor, readable by USER tor),
// hex-encode it, AUTHENTICATE, ask for bootstrap-phase, QUIT.
//
// Errors during the poll (control port not yet listening, tor still
// starting) do NOT terminate the wait — they are recorded as the last-seen
// diagnostic and the poll continues until the deadline.
func waitForBootstrap(ctx context.Context, composeFile, envFile string, deadline time.Duration) (string, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	var lastDiagnostics string
	for {
		out, err := liveTorControl(deadlineCtx, composeFile, envFile, "GETINFO status/bootstrap-phase")
		if err == nil {
			lastDiagnostics = out
			// Tor reports bootstrap completion as `PROGRESS=100` in a line
			// shaped `250-status/bootstrap-phase=*NOTICE BOOTSTRAP ... PROGRESS=100`.
			if strings.Contains(out, "PROGRESS=100") {
				return out, nil
			}
		} else {
			// Control port not yet listening, cookie not yet written, or tor
			// still starting — record the raw output + error for diagnostics
			// and keep polling until the deadline.
			lastDiagnostics = out + "\n(poll error: " + err.Error() + ")"
		}
		select {
		case <-deadlineCtx.Done():
			return lastDiagnostics, deadlineCtx.Err()
		case <-time.After(bootstrapPollInterval):
		}
	}
}

// getconfSocksPort issues GETCONF SocksPort over the cookie-authenticated
// control port and returns the raw control-port response. The exchange
// runs inside the tor container via `docker compose exec` as USER tor
// (cookie owner), mirroring the Dockerfile HEALTHCHECK.
func getconfSocksPort(ctx context.Context, composeFile, envFile string) (string, error) {
	return liveTorControl(ctx, composeFile, envFile, "GETCONF SocksPort")
}

// parseGetconfValue extracts the value of the given keyword from a Tor
// control-port GETCONF response. A single-keyword GETCONF response is
// normally `250 <Keyword>=<value>` (space separator, one line); a
// multi-keyword or long-value response uses the continuation form
// `250-<Keyword>=<value>` (hyphen separator) with a `250 OK` terminator.
// This parser accepts both so a future Tor version that switches the
// single-keyword shape to the continuation form does not silently break
// the assertion. Tor wraps values containing spaces in double quotes
// (control-protocol quoted-string escaping), which this function strips.
// Returns an error if no matching line is found, so a malformed response
// (e.g. `513 Bad Keyword`, `552 Unrecognized option`) surfaces as a named
// failure rather than a silent empty-string assertion miss.
func parseGetconfValue(raw, keyword string) (string, error) {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		// Match `250 <Keyword>=` or `250-<Keyword>=` — both are valid
		// GETCONF reply shapes (space = single-line, hyphen = continuation).
		if !strings.HasPrefix(line, "250") {
			continue
		}
		rest := strings.TrimPrefix(line, "250")
		rest = strings.TrimPrefix(rest, "-") // continuation-line hyphen, if present
		rest = strings.TrimSpace(rest)
		value, ok := strings.CutPrefix(rest, keyword+"=")
		if !ok {
			continue
		}
		// Tor wraps values containing spaces in double-quotes (control
		// protocol quoted-string escaping). Strip them when present so
		// containsToken sees the bare flag tokens.
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		return value, nil
	}
	// Surface Tor error replies by name: a 5xx line means Tor rejected
	// the keyword (config-parse failure, unrecognised directive — the
	// exact regression this test exists to catch).
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "5") || strings.HasPrefix(line, "6") {
			return "", fmt.Errorf("tor control error in response: %q", line)
		}
	}
	return "", fmt.Errorf("no `250 %s=` or `250-%s=` line in control-port response:\n%s", keyword, keyword, raw)
}

// seedTorrcVolume writes the rendered torrc bytes into the stargate-tor-config
// named volume (resolved by lookupComposeVolume) via an ephemeral alpine
// container mounting the volume RW. The file is written mode 0644 so the tor
// service's non-root USER tor can read it (the volume is mounted :ro in the
// tor service; the seed container mounts it RW for the write). The torrc
// bytes flow through the container's stdin to avoid shell-escaping the
// em-dashes and newlines in the golden.
//
// Shells out to `docker run` rather than the SDK ContainerCreate +
// ContainerStart + ContainerWait dance for the same reason T019b documents
// at its ephemeral-probe step: the SDK path is finicky about API-version
// drift between the auto-negotiated client and the host daemon, while the
// CLI is stable across daemon versions.
func seedTorrcVolume(ctx context.Context, volumeName string, torrcBytes []byte) error {
	pullCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	pull := exec.CommandContext(pullCtx, "docker", "pull", liveProbeImage)
	if out, err := pull.CombinedOutput(); err != nil {
		return fmt.Errorf("docker pull %s: %v\n%s", liveProbeImage, err, out)
	}

	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "docker",
		"run", "--rm", "-i",
		"--volume", volumeName+":/etc/tor",
		liveProbeImage,
		"sh", "-c", "cat > /etc/tor/torrc && chmod 0644 /etc/tor/torrc",
	)
	cmd.Stdin = bytes.NewReader(torrcBytes)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("seed container write of /etc/tor/torrc: %v\n%s", err, out)
	}
	return nil
}

// lookupComposeVolume resolves the actual docker volume name for a
// (project, composeVolumeName) pair via the SDK's label-based filter.
// Returns the docker volume's `Name` field (the runtime identifier
// `docker run --volume` accepts), NOT the compose-logical name. An error
// means the volume was not found — typically an `up --no-start` failure or
// a project-name mismatch. Mirrors T019b's lookupComposeNetwork stance on
// avoiding the undocumented `<project>_<name>` Compose v2 mangling.
func lookupComposeVolume(ctx context.Context, cli *client.Client, project, composeVolume string) (string, error) {
	f := filters.NewArgs()
	f.Add("label", "com.docker.compose.project="+project)
	f.Add("label", "com.docker.compose.volume="+composeVolume)
	resp, err := cli.VolumeList(ctx, volume.ListOptions{Filters: f})
	if err != nil {
		return "", fmt.Errorf("VolumeList: %w", err)
	}
	if len(resp.Volumes) == 0 {
		return "", fmt.Errorf("no docker volume found with labels project=%q volume=%q "+
			"(did `up --no-start` actually create %q?)", project, composeVolume, composeVolume)
	}
	return resp.Volumes[0].Name, nil
}

// liveTorControl runs a single Tor control-port command inside the tor
// container via `docker compose exec -T`, wrapping it in the cookie-auth
// AUTHENTICATE ... QUIT exchange that mirrors the sidecars/tor/Dockerfile
// HEALTHCHECK. The command is passed as $1 to the inner sh (not interpolated
// into the script string) so a command containing spaces is handled as a
// single argv entry by Go's exec and reaches the inner sh as one positional
// arg — no shell-quoting risk. Returns the combined control-port response
// (stdout+stderr) and any exec error.
//
// `-T` disables TTY allocation so the output is captureable in a
// non-interactive context; without it compose complains "the input device is
// not a TTY" when stdin is not a terminal.
//
// Cookie-path discovery: tor writes control_auth_cookie to its DataDirectory.
// The Dockerfile ENTRYPOINT (`tor -f /etc/tor/torrc`) does NOT pass
// `--defaults-torrc /etc/tor/torrc-defaults`, so Debian's defaults file
// (which would set `DataDirectory /var/lib/tor`) is never loaded — tor
// falls back to its compile-time default of `$HOME/.tor` =
// `/var/lib/tor/.tor` for USER tor (HOME=/var/lib/tor). The Dockerfile
// HEALTHCHECK hardcodes `/var/lib/tor/control_auth_cookie` and is therefore
// also stale (a pre-existing T014 bug, out of T032's scope to fix). This
// helper locates the cookie via `find /var/lib/tor` so it is robust to
// tor's effective DataDirectory — whether `/var/lib/tor` (torrc-defaults
// loaded) or `/var/lib/tor/.tor` (compile-time default). A follow-up should
// either fix the ENTRYPOINT to pass `--defaults-torrc` or update the
// HEALTHCHECK + contract comment to reflect the actual path.
func liveTorControl(ctx context.Context, composeFile, envFile, command string) (string, error) {
	const script = `COOKIE_FILE="$(find /var/lib/tor -name control_auth_cookie -print -quit)"
COOKIE_HEX="$(od -An -tx1 "$COOKIE_FILE" | tr -d ' \n')"
{ printf 'AUTHENTICATE %s\r\n' "$COOKIE_HEX"
  printf '%s\r\n' "$1"
  printf 'QUIT\r\n'
} | nc 127.0.0.1 9051`
	args := []string{
		"compose",
		"-p", liveComposeProject,
		"-f", composeFile,
		"--env-file", envFile,
		"exec",
		"-T", // disable TTY allocation for non-interactive capture
		"tor",
		"sh", "-c", script, "torctrl", command,
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// liveDockerCompose runs `docker compose -p <liveComposeProject> -f <file>
// --env-file <env> <args...>` and returns the combined stdout+stderr. Same
// shape as T019b's dockerCompose helper (tests/contract/tor/); not importable
// across packages, so re-implemented here per the same convention T029 uses
// for findRepoRoot. A future ticket may hoist the shared compose-runline +
// label-lookup helpers into tests/contract/internal/ when T058/T058a (Phase 4)
// land and also need live-sidecar bring-up.
func liveDockerCompose(ctx context.Context, composeFile, envFile string, args ...string) (string, error) {
	full := append([]string{
		"compose",
		"-p", liveComposeProject,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	cmd := exec.CommandContext(ctx, "docker", full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
