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
// T087 amended the test to the image-baked-torrc posture (FR-011 amended by
// T089): the safe torrc is baked into the Tor image at build time
// (sidecars/tor/Dockerfile COPY), so the test no longer seeds the
// stargate-tor-config volume. The test brings up the production tor image
// cold (no harness-seeded config) and asserts:
//
//  1. No Docker health-probe history is retained (Constitution III).
//     Authenticated GETINFO still verifies live bootstrap independently.
//  2. The control cookie is exactly at /var/lib/tor/control_auth_cookie
//     (not /var/lib/tor/.tor/...) — DataDirectory /var/lib/tor is explicit
//     in the baked torrc (invariant #11; sol-review B2+M3). The prior
//     find-based workaround (T032) was robust to any DataDirectory and
//     therefore masked exactly this regression.
//  3. GETCONF for every torrc directive matches the golden — Tor loaded
//     what the image baked.
//
// Control access: the cookie and private ControlSocket stay inside Tor.
// This test runs the AUTHENTICATE+GETCONF+QUIT exchange in that container
// as USER tor (which owns the cookie). Production current health is served
// by the isolated observer; Docker health probes retain no event history.
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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

// liveComposeProject namespaces every compose invocation this test issues so
// the test never collides with operator-authored state brought up under the
// default project name. `docker compose down --volumes --remove-orphans` in
// t.Cleanup tears the whole stack down regardless of which services started.
// Mirrors T019b's composeProject pattern (tests/contract/tor/).
const liveComposeProject = "stargate-t032-test"

// bootstrapDeadline caps the wait for Tor to reach BOOTSTRAP PROGRESS=100
// after the tor service starts. Tor bootstrap depends on the host
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

// getconfCases is the table of torrc directives this test GETCONFs over the
// live control port, asserting Tor loaded what the image baked. The static
// tests (T029 byte-match, T030 invariants, T031 no-bridges) gate the golden
// itself; this table gates that Tor did not silently ignore a directive
// (alias change, flag drift across Tor versions). Each case names the
// contract invariant it maps to for clear failure messages.
var getconfCases = []struct {
	directive string
	expected  string
	invariant string
	match     func(value string) bool
}{
	{"SocksPort", "unix:/run/tor-fabric/private/tor-socks.sock IsolateClientAddr IsolateSOCKSAuth", "#1/#2", func(v string) bool {
		return containsToken(v, "unix:/run/tor-fabric/private/tor-socks.sock") && containsToken(v, "IsolateClientAddr") && containsToken(v, "IsolateSOCKSAuth")
	}},
	{"ControlSocket", "/var/lib/tor/control/tor-control.sock", "#3", func(v string) bool {
		return strings.Contains(v, "/var/lib/tor/control/tor-control.sock")
	}},
	{"CookieAuthentication", "1", "#3", func(v string) bool { return v == "1" }},
	{"CookieAuthFileGroupReadable", "1", "#4", func(v string) bool { return v == "1" }},
	{"DataDirectory", "/var/lib/tor", "#11", func(v string) bool { return v == "/var/lib/tor" }},
	{"ClientUseIPv6", "0", "#5", func(v string) bool { return v == "0" }},
	{"AvoidDiskWrites", "1", "#6", func(v string) bool { return v == "1" }},
	{"UseBridges", "0", "#7", func(v string) bool { return v == "0" }},
	{"Log", "notice file /dev/null", "#8", func(v string) bool {
		return v == "notice file /dev/null"
	}},
	{"SafeLogging", "1", "#8", func(v string) bool { return v == "1" }},
}

// TestLiveSidecarGETCONFSocksPort gates FR-011 / contracts/torrc.md invariant
// #1 at the live-sidecar layer: bring up the tor sidecar from the production
// image (no harness-seeded config — the torrc is image-baked per T087/T089),
// wait for authenticated bootstrap, then assert no Docker health history,
// the control cookie is at the authoritative path, and GETCONF for every
// torrc directive matches the golden.
//
// Subtests:
//   - TorBootstrapsWithImageBakedTorrc: the image-baked torrc parses cleanly
//     and Tor reaches PROGRESS=100 (a syntactically invalid torrc or an
//     unrecognised directive fails bootstrap or refuses to start).
//   - NoDockerHealthHistory: Docker retains no timestamped health probes.
//   - CookieAtAuthoritativePath: the control cookie is exactly at
//     /var/lib/tor/control_auth_cookie and NOT at /var/lib/tor/.tor/...
//     (the compile-time default $HOME/.tor = /var/lib/tor/.tor for USER tor
//     when DataDirectory is not explicit — invariant #11).
//   - GETCONFMatchesEveryInvariant: GETCONF for each directive in the
//     getconfCases table matches the expected value (Tor loaded what the
//     image baked — FR-011).
//   - GETCONFReportsIsolateClientAddr: (kept for clarity) SocksPort carries
//     IsolateClientAddr (invariant #1).
//   - GETCONFReportsIsolateSOCKSAuth: (privacy-load-bearing) SocksPort
//     carries IsolateSOCKSAuth (per-first-party stream isolation depends on
//     it, Principle III).
//
// Self-skips when the docker daemon is unreachable or the docker CLI is not
// on PATH (mirrors T019b's skip conditions).
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

	// Register cleanup BEFORE any compose invocation. If `up` partially
	// succeeds (network created) but compose returns non-zero (build cache
	// failure, daemon hiccup), t.Fatalf would fire here — and only
	// previously-registered Cleanups run on Fatalf. Pre-registration is the
	// standard idempotent-test pattern; `compose down` on a never-brought-up
	// project is a no-op. Mirrors T019b.
	t.Cleanup(func() {
		downCtx, dcancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer dcancel()
		if out, err := liveDockerCompose(downCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// (1) Build + start tor cold (no harness-seeded config — the torrc is
	// image-baked per T087). `--build` forces a rebuild against the current
	// Dockerfile so the test exercises the on-disk contract (mirrors T019b's
	// stance). The tor service no longer mounts stargate-tor-config at
	// /etc/tor (T087 dropped that mount — a :ro volume at /etc/tor would
	// shadow the image-baked torrc); Tor loads /etc/tor/torrc from the image
	// with no dependency on the control plane (Constitution Principle II /
	// sol-review B2).
	upCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if out, err := liveDockerCompose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("docker compose up -d --build tor (cold volume, image-baked torrc): %v\n%s", err, out)
	}

	// (2) Bootstrap wait — gates "the image-baked torrc parses cleanly and
	// Tor reaches PROGRESS=100". A torrc with a syntactically invalid
	// directive or an unrecognised flag (the exact regression this test
	// exists to catch) fails bootstrap or refuses to start, surfacing here
	// rather than in the GETCONF assertion where the failure mode would be
	// opaque.
	t.Run("TorBootstrapsWithImageBakedTorrc", func(t *testing.T) {
		phase, err := waitForBootstrap(ctx, composeFile, envFile, bootstrapDeadline)
		if err != nil {
			t.Fatalf("Tor did not bootstrap with the image-baked torrc within %s: %v\n"+
				"last bootstrap-phase response: %s\n"+
				"(a syntactically invalid torrc or an unrecognised directive would "+
				"surface here — check `docker compose -p %s logs tor` for tor's "+
				"config-parse diagnostics)",
				bootstrapDeadline, err, phase, liveComposeProject)
		}
		t.Logf("Tor bootstrapped: %s", strings.TrimSpace(phase))
	})

	// The live authenticated bootstrap probe above retains the cold-volume
	// cookie-path regression. Docker must not retain timestamped probe history.
	t.Run("ColdVolumeHasNoDockerHealthHistory", func(t *testing.T) {
		f := filters.NewArgs()
		f.Add("label", "com.docker.compose.project="+liveComposeProject)
		f.Add("label", "com.docker.compose.service=tor")
		list, err := cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
		if err != nil || len(list) != 1 {
			t.Fatal("expected one Tor container", err)
		}
		inspected, err := cli.ContainerInspect(ctx, list[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if inspected.State == nil || !inspected.State.Running {
			t.Fatal("Tor is not running")
		}
		if inspected.State.Health != nil {
			t.Fatal("Docker retained health-probe history")
		}
	})

	// (4) Image-baked torrc byte-equality — the image /etc/tor/torrc
	// MUST equal the wantTorrc golden byte-for-byte (FR-011; invariant
	// #13). GETCONF (step 6) only returns directives you ask for, so a
	// build-time swap that adds a privacy-hostile extra (HiddenServiceDir,
	// Bridge lines, Log debug file) would pass every GETCONF check. This
	// subtest closes that gap by reading the file out of the running
	// container and comparing to the golden — the byte-for-byte chain link
	// T087's §Analysis §Residue promised and render_byte_match_test.go
	// documents (redteam M1).
	t.Run("ImageBakedTorrcMatchesGolden", func(t *testing.T) {
		out, err := liveDockerCompose(ctx, composeFile, envFile,
			"exec", "-T", "tor", "cat", "/etc/tor/torrc")
		if err != nil {
			t.Fatalf("docker compose exec tor cat /etc/tor/torrc: %v\n%s", err, out)
		}
		if out != wantTorrc {
			t.Errorf("image-baked /etc/tor/torrc does NOT equal the wantTorrc "+
				"golden byte-for-byte (FR-011 / invariant #13) — a build-time "+
				"swap added or removed content the GETCONF checks do not cover.\n"+
				"image bytes: %d, golden bytes: %d",
				len(out), len(wantTorrc))
		} else {
			t.Logf("OK: image /etc/tor/torrc == wantTorrc golden (%d bytes)", len(out))
		}
	})

	// (5) Cookie at authoritative path — the specific regression T087 fixes.
	// With DataDirectory /var/lib/tor explicit in the image-baked torrc, the
	// cookie MUST land at /var/lib/tor/control_auth_cookie and NOT at
	// /var/lib/tor/.tor/control_auth_cookie (the compile-time default
	// $HOME/.tor = /var/lib/tor/.tor for USER tor). The prior find-based
	// workaround (T032) was robust to any DataDirectory and therefore masked
	// exactly this regression — the deterministic path assertion below is
	// what catches a DataDirectory regression going forward.
	t.Run("CookieAtAuthoritativePath", func(t *testing.T) {
		if out, err := liveDockerCompose(ctx, composeFile, envFile,
			"exec", "-T", "tor", "test", "-f", "/var/lib/tor/control_auth_cookie"); err != nil {
			t.Errorf("control cookie NOT at /var/lib/tor/control_auth_cookie "+
				"(invariant #11 — DataDirectory /var/lib/tor):\n"+
				"  exec error: %v\n  output: %s\n"+
				"(check GETCONF DataDirectory in the GETCONFMatchesEveryInvariant subtest)",
				err, out)
		} else {
			t.Logf("OK: cookie at /var/lib/tor/control_auth_cookie")
		}
		// The wrong path must NOT exist — its presence would mean Tor fell
		// back to $HOME/.tor despite the explicit DataDirectory.
		if _, err := liveDockerCompose(ctx, composeFile, envFile,
			"exec", "-T", "tor", "test", "-f", "/var/lib/tor/.tor/control_auth_cookie"); err == nil {
			// test -f exited 0 → the wrong-path cookie EXISTS → regression.
			t.Errorf("control cookie ALSO at /var/lib/tor/.tor/control_auth_cookie — " +
				"Tor fell back to $HOME/.tor despite DataDirectory /var/lib/tor " +
				"in the image-baked torrc (invariant #11 regression)")
		}
	})

	// (6) GETCONF for every torrc directive — Tor loaded what the image
	// baked. The static tests (T029/T030/T031) gate the golden; this gate
	// catches a directive Tor silently ignores (alias change, flag drift
	// across Tor versions). Both endpoints are Unix sockets. The native SOCKS
	// directory and raw control socket remain Tor-private (FR-012).
	t.Run("GETCONFMatchesEveryInvariant", func(t *testing.T) {
		for _, tc := range getconfCases {
			out, err := liveTorControl(ctx, composeFile, envFile, "GETCONF "+tc.directive)
			if err != nil {
				t.Errorf("GETCONF %s: control-port exchange failed: %v\noutput: %s",
					tc.directive, err, out)
				continue
			}
			val, err := parseGetconfValue(out, tc.directive)
			if err != nil {
				t.Errorf("GETCONF %s: parse error: %v\nraw output: %s",
					tc.directive, err, out)
				continue
			}
			if !tc.match(val) {
				t.Errorf("GETCONF %s=%q does not match expected %q "+
					"(contracts/torrc.md invariant %s — Tor did not load what "+
					"the image baked)",
					tc.directive, val, tc.expected, tc.invariant)
			} else {
				t.Logf("OK: GETCONF %s=%q (invariant %s)", tc.directive, val, tc.invariant)
			}
		}
	})

	// (7) SocksPort isolation flags — kept as named subtests for clear,
	// privacy-load-bearing failure messages (per-first-party stream
	// isolation depends on IsolateSOCKSAuth, Principle III). These overlap
	// with GETCONFMatchesEveryInvariant's SocksPort row but give a sharper
	// signal on the privacy-critical flag specifically.
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
				"the flag the image-baked torrc carries; check `docker compose "+
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
				"Tor did not load the flag the image-baked torrc carries; check "+
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
// Cookie path: the image-baked torrc pins DataDirectory /var/lib/tor
// (contracts/torrc.md invariant #11, T087), so the cookie lands at the
// deterministic path /var/lib/tor/control_auth_cookie. The prior T032
// implementation used `find /var/lib/tor -name control_auth_cookie` to be
// robust to any DataDirectory; T087 removed that workaround because it
// masked the exact regression (cookie at /var/lib/tor/.tor/...) the
// deterministic path assertion now catches.
func liveTorControl(ctx context.Context, composeFile, envFile, command string) (string, error) {
	const script = `COOKIE_HEX="$(od -An -tx1 /var/lib/tor/control_auth_cookie | tr -d ' \n')"
{ printf 'AUTHENTICATE %s\r\n' "$COOKIE_HEX"
  printf '%s\r\n' "$1"
  printf 'QUIT\r\n'
} | nc -U /var/lib/tor/control/tor-control.sock`
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
