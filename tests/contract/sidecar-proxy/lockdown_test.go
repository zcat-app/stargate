// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package sidecarproxy hosts the runtime contract test for the
// docker-socket-proxy lockdown invariants (T019c). The static structural
// properties of compose/docker-compose.local.yml — env keys present, no
// host-published ports, docker.sock mounted only by the proxy — are gated
// at PR cadence by tests/contract/compose/local_compose_test.sh (M3/M4/M5)
// without starting containers. The test in this package BRINGS UP the
// proxy (plus the tor sidecar it observes) and asserts the pinned image's
// runtime HTTP behaviour under that env, catching what the static layer
// cannot: an upstream image whose flag DEFAULTS differ from the
// "unset means deny" assumption. That gap is real — the pinned 0.3.0
// image defaults VERSION and PING to ALLOW (probed at T019c /start),
// which is why the compose file sets them to 0 explicitly.
//
// The property under test is the C1-remediation trust boundary from
// SECURITY-DECISIONS.md ("CP compromise ≠ host root"): the proxy exposes
// exactly the GET-only observe surface SidecarMonitor (T039) needs —
// /events and the containers section — and nothing else.
//
// See specs/000-architecture/spec.md §16.1 for the lockdown contract and
// specs/001-tor-route/research.md §5 for the harness-language decision.
package sidecarproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// composeProject namespaces every compose invocation this test issues so
// the test never collides with operator-authored state or T019b's project.
const composeProject = "stargate-t019c-test"

// proxyBase is the in-network URL SidecarMonitor (T039) will use — the
// compose service name doubles as the DNS name on stargate-internal.
const proxyBase = "http://docker-socket-proxy:2375"

// probeImage is the ephemeral in-network HTTP prober. curl (not T019b's
// alpine+nc) because the lockdown contract is about exact HTTP status
// codes (`-w %{http_code}`), which busybox wget cannot report reliably.
// Pinned by sha256 multi-arch OCI index digest per Constitution Principle
// IV; resolved via `docker buildx imagetools inspect curlimages/curl:8.11.1`
// at T019c /start. Bumping is a deliberate pin-rotation decision
// (SECURITY-DECISIONS.md rotation policy).
const probeImage = "curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69"

// seedTorrc is the minimal torrc this test writes into the
// stargate-tor-config volume before starting the tor service. The CP's
// TorrcRenderer (T037) has not landed, and the tor image's ENTRYPOINT is
// fatal on a missing -f file — without seeding, tor crash-loops and
// sub-test (b)'s State.Health assertion would race the restart cycle.
// DisableNetwork 1 keeps a contract test from generating real Tor-network
// egress (Constitution Principle III hygiene — this test needs a running
// container with a HEALTHCHECK, not a bootstrapped Tor). SocksPort 0
// closes the one listener the default torrc would open.
const seedTorrc = "DataDirectory /var/lib/tor\nLog notice stdout\nDisableNetwork 1\nSocksPort 0\n"

// TestSocketProxyLockdown gates the five runtime invariants from the
// T019c ticket §Acceptance after bringing up the tor and
// docker-socket-proxy services from compose/docker-compose.local.yml:
//
//	(a) PostSurfaceDenied — every POST returns 403 (POST=0).
//	(b) ContainerInspectSurfaceForSidecarMonitor — GET /containers/{tor}/json
//	    is 200 with State.Status and State.Health.Status populated.
//	(c) EventsStreamDelivers — GET /events streams container transitions.
//	(d) DenyByDefaultSurface — non-granted endpoints (incl. /version and
//	    /_ping, which the upstream image would otherwise allow) return 403.
//	(e) HostCannotReachProxy — no host-published binding; host dial fails.
func TestSocketProxyLockdown(t *testing.T) {
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

	repoRoot := findRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "compose", "docker-compose.local.yml")
	envFile := filepath.Join(repoRoot, "compose", "env", "local.env.example")
	if _, err := os.Stat(composeFile); err != nil {
		t.Fatalf("compose file missing: %v", err)
	}
	if _, err := os.Stat(envFile); err != nil {
		t.Fatalf("env file missing: %v", err)
	}

	// Cleanup registered BEFORE bring-up (T019b rationale: only
	// previously-registered Cleanups run on Fatalf; registering after a
	// partially-successful `up` would orphan the project's containers).
	t.Cleanup(func() {
		downCtx, dcancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer dcancel()
		if out, err := dockerCompose(downCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// Create (build, don't start) tor first so its named volumes exist,
	// seed the torrc, THEN start. Full-stack bring-up is impossible today —
	// the DP/CP images cannot build until their main sources land (same
	// constraint T019b documents); tor + docker-socket-proxy is exactly
	// the surface this contract covers.
	createCtx, ccancel := context.WithTimeout(ctx, 10*time.Minute)
	defer ccancel()
	if out, err := dockerCompose(createCtx, composeFile, envFile, "create", "--build", "tor"); err != nil {
		t.Fatalf("docker compose create tor: %v\n%s", err, out)
	}

	// Resolve the tor-config volume via compose labels (NOT the
	// undocumented `<project>_<name>` naming convention — same rationale
	// as lookupComposeNetwork below) and write the seed torrc into it.
	// --user 0 because the volume root is root-owned and the curl image's
	// default user is unprivileged; the tor user only needs read (0644).
	cfgVolume, err := lookupComposeVolume(ctx, cli, composeProject, "stargate-tor-config")
	if err != nil {
		t.Fatalf("lookup stargate-tor-config volume for project %q: %v", composeProject, err)
	}
	pullCtx, pcancel := context.WithTimeout(ctx, 90*time.Second)
	defer pcancel()
	if out, err := exec.CommandContext(pullCtx, "docker", "pull", probeImage).CombinedOutput(); err != nil {
		t.Fatalf("docker pull %s: %v\n%s", probeImage, err, out)
	}
	seedCtx, scancel := context.WithTimeout(ctx, 30*time.Second)
	defer scancel()
	seedCmd := exec.CommandContext(seedCtx, "docker",
		"run", "--rm", "--user", "0", "--entrypoint", "/bin/sh",
		"-v", cfgVolume+":/etc/tor",
		probeImage,
		"-c", fmt.Sprintf("printf '%%s' '%s' > /etc/tor/torrc && chmod 0644 /etc/tor/torrc", seedTorrc),
	)
	if out, err := seedCmd.CombinedOutput(); err != nil {
		t.Fatalf("seed torrc into %s: %v\n%s", cfgVolume, err, out)
	}

	upCtx, ucancel := context.WithTimeout(ctx, 5*time.Minute)
	defer ucancel()
	if out, err := dockerCompose(upCtx, composeFile, envFile, "up", "-d", "tor", "docker-socket-proxy"); err != nil {
		t.Fatalf("docker compose up tor docker-socket-proxy: %v\n%s", err, out)
	}

	torName := waitForRunning(ctx, t, cli, "tor")
	waitForRunning(ctx, t, cli, "docker-socket-proxy")

	networkName, err := lookupComposeNetwork(ctx, cli, composeProject, "stargate-internal")
	if err != nil {
		t.Fatalf("lookup stargate-internal network for project %q: %v", composeProject, err)
	}

	// curlCode runs an ephemeral in-network probe and returns the HTTP
	// status code as a string ("403"). In-network probing is the only
	// honest vantage point: the proxy is compose-internal by design, so
	// this is the exact path a (possibly compromised) CP would use.
	curlCode := func(t *testing.T, method, path string) string {
		t.Helper()
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		args := []string{"run", "--rm", "--network", networkName, probeImage,
			"-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "10"}
		switch method {
		case "GET":
			// curl's default method.
		case "HEAD":
			// -I sends a real HEAD; -X HEAD would keep curl waiting for
			// a body that never comes.
			args = append(args, "-I")
		default:
			args = append(args, "-X", method)
		}
		args = append(args, proxyBase+path)
		out, err := exec.CommandContext(runCtx, "docker", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("probe %s %s: %v\n%s", method, path, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	t.Run("PostSurfaceDenied", func(t *testing.T) {
		// (a) POST=0: the write surface (spawn/kill/exec/pull) is the
		// host-root-escalation path T017a's trust rationale forbids.
		for _, path := range []string{
			"/containers/create",
			"/containers/" + torName + "/kill",
			"/containers/" + torName + "/exec",
			"/images/create",
		} {
			if code := curlCode(t, "POST", path); code != "403" {
				t.Errorf("lockdown violation: POST %s returned %s, want 403 (POST=0)", path, code)
			} else {
				t.Logf("OK: POST %s -> 403", path)
			}
		}
	})

	t.Run("ContainerInspectSurfaceForSidecarMonitor", func(t *testing.T) {
		// (b) The exact read surface SidecarMonitor (T039) polls. Assert
		// the fields are POPULATED, not that health is "healthy" — the
		// seeded torrc gives tor no ControlPort, so the image healthcheck
		// reports "starting" and later "unhealthy"; both prove the field
		// exists on the wire, which is what T039 depends on.
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(runCtx, "docker",
			"run", "--rm", "--network", networkName, probeImage,
			"-s", "-w", "\n%{http_code}", "-m", "10",
			proxyBase+"/containers/"+torName+"/json",
		).CombinedOutput()
		if err != nil {
			t.Fatalf("probe GET /containers/%s/json: %v\n%s", torName, err, out)
		}
		raw := string(out)
		cut := strings.LastIndex(raw, "\n")
		if cut < 0 {
			t.Fatalf("probe output has no status-code line: %q", raw)
		}
		body, code := raw[:cut], strings.TrimSpace(raw[cut+1:])
		if code != "200" {
			t.Fatalf("GET /containers/%s/json returned %s, want 200 (CONTAINERS=1 broken?)", torName, code)
		}
		var insp struct {
			State struct {
				Status string `json:"Status"`
				Health *struct {
					Status string `json:"Status"`
				} `json:"Health"`
			} `json:"State"`
		}
		if err := json.Unmarshal([]byte(body), &insp); err != nil {
			t.Fatalf("decode inspect body: %v\nbody: %.512s", err, body)
		}
		if insp.State.Status == "" {
			t.Error("State.Status empty — SidecarMonitor's status field missing from the proxied inspect response")
		}
		if insp.State.Health == nil || insp.State.Health.Status == "" {
			t.Error("State.Health.Status empty — SidecarMonitor's health field missing from the proxied inspect response")
		}
		t.Logf("OK: 200 with State.Status=%q State.Health.Status=%v", insp.State.Status, insp.State.Health)
	})

	t.Run("EventsStreamDelivers", func(t *testing.T) {
		// (c) The long-poll channel T039 depends on. Open the stream
		// first, then trigger a container transition; -m bounds the
		// stream, so curl exiting 28 (timeout) is the EXPECTED shape —
		// the assertion is on captured events, not the exit code.
		const eventsPath = "/events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D"
		type streamResult struct {
			out string
			err error
		}
		ch := make(chan streamResult, 1)
		go func() {
			runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(runCtx, "docker",
				"run", "--rm", "--network", networkName, probeImage,
				"-s", "-N", "-m", "10", proxyBase+eventsPath,
			).CombinedOutput()
			ch <- streamResult{string(out), err}
		}()

		// Let the stream connect, then generate container-lifecycle
		// events (create/start/die/destroy) with a trivial ephemeral run.
		time.Sleep(2 * time.Second)
		trigCtx, tcancel := context.WithTimeout(ctx, 20*time.Second)
		defer tcancel()
		if out, err := exec.CommandContext(trigCtx, "docker", "run", "--rm", probeImage, "--version").CombinedOutput(); err != nil {
			t.Fatalf("event-trigger container: %v\n%s", err, out)
		}

		res := <-ch
		if !strings.Contains(res.out, `"Type":"container"`) {
			t.Errorf("no container event captured through the proxy (EVENTS=1 broken?): curl err=%v\noutput: %.1024s", res.err, res.out)
		} else {
			t.Logf("OK: events stream delivered container transitions (%d bytes)", len(res.out))
		}
	})

	t.Run("DenyByDefaultSurface", func(t *testing.T) {
		// (d) Everything outside the granted surface is 403 — INCLUDING
		// /version and /_ping, which the pinned upstream image defaults
		// to ALLOW (probed at T019c /start; the compose file sets
		// VERSION=0 and PING=0 explicitly to close them). A 200 here
		// means the compose lockdown regressed OR an image bump changed
		// the flag semantics.
		// The last two probes vary the REQUEST SHAPE, not just the path
		// (T019c redteam minor finding): the proxy's ACLs are
		// version-prefix-aware regexes plus a method filter, so a probe
		// set of unversioned GETs alone would stay green across an
		// upstream bump that regressed either mechanism. /v1.43/version
		// exercises the `^(/v[\d.]+)?` prefix arm; HEAD /_ping exercises
		// the method filter with the Docker SDK's negotiation shape.
		for _, probe := range []struct{ method, path string }{
			{"GET", "/info"},
			{"GET", "/version"},
			{"GET", "/_ping"},
			{"GET", "/networks"},
			{"GET", "/volumes"},
			{"POST", "/networks/create"},
			{"POST", "/volumes/create"},
			{"POST", "/swarm/init"},
			{"GET", "/v1.43/version"},
			{"HEAD", "/_ping"},
		} {
			if code := curlCode(t, probe.method, probe.path); code != "403" {
				t.Errorf("deny-by-default violation: %s %s returned %s, want 403", probe.method, probe.path, code)
			} else {
				t.Logf("OK: %s %s -> 403", probe.method, probe.path)
			}
		}
	})

	t.Run("HostCannotReachProxy", func(t *testing.T) {
		// (e) Parallels T019b's FR-012 invariant for tor:9050: the proxy
		// (a host-root-equivalent pivot per T017a) must not be reachable
		// from outside the compose-internal network.
		f := filters.NewArgs()
		f.Add("label", "com.docker.compose.project="+composeProject)
		f.Add("label", "com.docker.compose.service=docker-socket-proxy")
		list, err := cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
		if err != nil {
			t.Fatalf("ContainerList (docker-socket-proxy by label): %v", err)
		}
		if len(list) == 0 {
			t.Fatal("no docker-socket-proxy container found by compose labels — did `up -d` actually start it?")
		}
		for _, c := range list {
			insp, err := cli.ContainerInspect(ctx, c.ID)
			if err != nil {
				t.Fatalf("ContainerInspect %s: %v", c.ID, err)
			}
			if insp.NetworkSettings == nil {
				t.Fatalf("ContainerInspect %s returned nil NetworkSettings", c.ID)
			}
			if binding, ok := insp.NetworkSettings.Ports[nat.Port("2375/tcp")]; ok && len(binding) > 0 {
				t.Errorf("lockdown violation: proxy container %s has published binding for 2375/tcp: %+v", c.ID, binding)
			} else {
				t.Logf("OK: proxy container %s has no published binding for 2375/tcp", c.ID)
			}
		}

		// Any non-nil dial error satisfies the property; we do not
		// string-match the error class (T019b's non-over-narrow-match
		// rationale: another host-side listener on 2375 would be the
		// same violation with a different error shape).
		d := net.Dialer{Timeout: 500 * time.Millisecond}
		if conn, dialErr := d.Dial("tcp", "127.0.0.1:2375"); dialErr == nil {
			conn.Close()
			t.Error("lockdown violation: host successfully dialled 127.0.0.1:2375 — proxy is published to host")
		} else {
			t.Logf("OK: host dial 127.0.0.1:2375 failed as expected: %v", dialErr)
		}
	})
}

// waitForRunning polls (by compose labels) until the named service's
// container reports State.Running, and returns the container's runtime
// name (compose names it `<project>-<service>-1`; the on-wire inspect
// path in sub-tests (a)/(b) needs the real name, not the service key).
// Polling replaces a fixed settle sleep: tor needs a moment to parse the
// seeded torrc, and a crash-looping container must FAIL here loudly
// rather than race the sub-tests.
func waitForRunning(ctx context.Context, t *testing.T, cli *client.Client, service string) string {
	t.Helper()
	f := filters.NewArgs()
	f.Add("label", "com.docker.compose.project="+composeProject)
	f.Add("label", "com.docker.compose.service="+service)
	deadline := time.Now().Add(60 * time.Second)
	lastState := "unknown"
	for time.Now().Before(deadline) {
		list, err := cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
		if err != nil {
			t.Fatalf("ContainerList (%s by label): %v", service, err)
		}
		if len(list) > 0 {
			insp, err := cli.ContainerInspect(ctx, list[0].ID)
			if err != nil {
				t.Fatalf("ContainerInspect %s: %v", list[0].ID, err)
			}
			if insp.State != nil && insp.State.Running {
				return strings.TrimPrefix(insp.Name, "/")
			}
			if insp.State != nil {
				lastState = insp.State.Status
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("service %q not Running within 60s (last state: %s) — crash loop? check `docker compose -p %s logs %s`", service, lastState, composeProject, service)
	return ""
}

// lookupComposeVolume resolves the docker volume name for a
// (project, composeVolumeName) pair via compose labels — same rationale
// as lookupComposeNetwork: `<project>_<name>` is an undocumented
// convention that shifts across Compose versions.
func lookupComposeVolume(ctx context.Context, cli *client.Client, project, composeVolume string) (string, error) {
	f := filters.NewArgs()
	f.Add("label", "com.docker.compose.project="+project)
	f.Add("label", "com.docker.compose.volume="+composeVolume)
	vols, err := cli.VolumeList(ctx, volume.ListOptions{Filters: f})
	if err != nil {
		return "", fmt.Errorf("VolumeList: %w", err)
	}
	if len(vols.Volumes) == 0 {
		return "", fmt.Errorf("no docker volume found with labels project=%q volume=%q (did `create` run?)", project, composeVolume)
	}
	return vols.Volumes[0].Name, nil
}

// lookupComposeNetwork, dockerCompose, and findRepoRoot mirror
// tests/contract/tor/port_exposure_test.go (T019b). They live in a
// different package, and at ~40 shared lines duplication beats
// restructuring the contract module around an internal helper package;
// hoist when a third contract surface needs them (research.md §5 names
// the candidates).

func lookupComposeNetwork(ctx context.Context, cli *client.Client, project, composeNetwork string) (string, error) {
	f := filters.NewArgs()
	f.Add("label", "com.docker.compose.project="+project)
	f.Add("label", "com.docker.compose.network="+composeNetwork)
	nets, err := cli.NetworkList(ctx, network.ListOptions{Filters: f})
	if err != nil {
		return "", fmt.Errorf("NetworkList: %w", err)
	}
	if len(nets) == 0 {
		return "", fmt.Errorf("no docker network found with labels project=%q network=%q (did `up` actually attach %q?)", project, composeNetwork, composeNetwork)
	}
	return nets[0].Name, nil
}

func dockerCompose(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	full := append([]string{
		"-p", composeProject,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, full...)...)
	return cmd.CombinedOutput()
}

func findRepoRoot(t *testing.T) string {
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
