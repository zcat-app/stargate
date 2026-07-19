//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package tor hosts the runtime contract tests for the Tor sidecar's
// network-exposure invariants. The static structural properties of
// compose/docker-compose.local.yml are gated by
// tests/contract/compose/local_compose_test.sh (T015) — that test runs at
// PR cadence under scripts/verify.sh gate 4 and starts no daemon
// containers. The tests in this package BRING UP the tor service and
// assert the runtime state matches the compose-file contract, catching
// any silent regression a daemon-side change (image rewrite, compose
// plugin behaviour drift, network re-attachment) could introduce between
// static-test runs.
//
// See specs/001-tor-route/spec.md §"FR-012" for the contract and
// specs/001-tor-route/research.md §5 for the harness-language decision
// (Go, sharing the data-plane toolchain).
//
// stargate:cadence docker — this package BRINGS UP the tor service, so it
// is build-tagged (`//go:build docker`) out of the hermetic PR gate and
// runs in the named Docker job (T076 §Acceptance #4). scripts/verify.sh
// compile-checks it via `go vet -tags docker` and accounts it SKIP[docker]
// in the hermetic PR run; `STARGATE_TEST_TAGS=docker scripts/verify.sh`
// (the named job) executes it. The t.Skip guards below stay as
// defense-in-depth for the named job on Docker-less hosts.
package tor

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// composeProject namespaces every compose invocation this test issues so
// the test never collides with operator-authored state brought up under
// the default project name. `docker compose down --volumes` in t.Cleanup
// tears the whole stack down regardless of which services started.
const composeProject = "stargate-t019b-test"

// socksPort and controlPort mirror FR-012 (spec.md). They are the Tor
// sidecar's SocksPort and ControlPort respectively; both MUST be
// compose-internal only (no host publication).
const (
	socksPort   = "9050/tcp"
	controlPort = "9051/tcp"
)

// probeImage is the ephemeral container image used by sub-test (c) to
// verify tor:9050 is reachable on the compose-internal bridge network.
// Pinned by sha256 multi-arch OCI index digest per Constitution Principle
// IV ("All external components are referenced by image digest, never by
// mutable tag"). The digest was resolved via
// `docker buildx imagetools inspect alpine:3` and tracks the alpine:3
// rolling tag at resolution time. Bumping alpine here is a deliberate
// supply-chain decision (pin rotation cadence per SECURITY-DECISIONS.md
// rotation policy); a future ticket can hoist this into a shared
// const file if more contract tests need ephemeral probe images.
const probeImage = "alpine:3@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

// TestTorPortExposure gates FR-012's three runtime invariants after
// bringing up the tor service from compose/docker-compose.local.yml:
//
//  1. HostCannotReachTorPorts — host netns dial to 127.0.0.1:{9050,9051}
//     fails (Tor ports not bound on host).
//  2. TorContainerHasNoPublishedPorts — docker inspect (Docker SDK) shows
//     no published binding for either port.
//  3. StargateDPNamespaceCanReachTorSocksPort — tor:9050 IS reachable on
//     the stargate-internal bridge network (FR-007 not broken by
//     over-restricting). Self-skips until the stargate-dp image becomes
//     buildable (content-gated on data-plane/cmd/stargate-proxy/main.go).
func TestTorPortExposure(t *testing.T) {
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

	// Bring up tor only. Full-stack bring-up is impossible today — the
	// stargate-dp image cannot build until data-plane/cmd/stargate-proxy/
	// main.go lands (data-plane/Dockerfile does `COPY cmd/ ./cmd/` and
	// fails the cache key lookup when that path is absent). The control
	// plane is in the same state. Sub-test (c) conditionally brings up
	// stargate-dp once its main.go exists.
	//
	// `--build` is belt-and-braces: docker compose's default is to reuse
	// an existing image tag, which for `stargate/tor:local` could be stale
	// from a prior local run. Forcing a rebuild against the current
	// Dockerfile guarantees the test exercises the on-disk contract.
	upCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	// Register cleanup BEFORE the compose-up call. If `up` partially
	// succeeds (tor container created/started) but compose returns
	// non-zero (build cache failure, daemon hiccup), t.Fatalf would fire
	// here — and only previously-registered Cleanups run on Fatalf.
	// Registering after `up` would orphan the tor container + network +
	// volumes under the stargate-t019b-test project name, colliding with
	// a subsequent run. Pre-registration is the standard idempotent-test
	// pattern; `compose down` on a never-brought-up project is a no-op.
	t.Cleanup(func() {
		downCtx, dcancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer dcancel()
		// Best-effort — failures here are surfaced via t.Log, not t.Fatal,
		// because a cleanup panic would mask the real test failure.
		if out, err := dockerCompose(downCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	if out, err := dockerCompose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("docker compose up tor: %v\n%s", err, out)
	}

	// Settle briefly so tor is fully listening on its in-container ports
	// before we probe. The contract we are asserting is "no listener on
	// the host" — if we dialled during tor's startup window we'd see
	// connection-refused either way, which is the SAME result we assert
	// post-start. Settling removes that ambiguity.
	time.Sleep(3 * time.Second)

	t.Run("HostCannotReachTorPorts", func(t *testing.T) {
		for _, port := range []uint16{9050, 9051} {
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			d := net.Dialer{Timeout: 500 * time.Millisecond}
			conn, dialErr := d.Dial("tcp", addr)
			if dialErr == nil {
				conn.Close()
				t.Errorf("FR-012 violation: host successfully dialled %s — Tor port is published to host (expected connection-refused)", addr)
				continue
			}
			// Any non-nil error satisfies FR-012 ("MUST NOT be published to
			// the host"); connection-refused is the expected specific shape
			// when nothing else on the host binds the port. We do NOT
			// string-match the error class — a future test environment
			// where something else binds these ports would surface as a
			// different error string but the same FR-012 violation
			// (host-side listener present), which we want caught, not
			// papered over with an over-narrow match.
			t.Logf("OK: dial %s failed as expected: %v", addr, dialErr)
		}
	})

	t.Run("TorContainerHasNoPublishedPorts", func(t *testing.T) {
		f := filters.NewArgs()
		f.Add("label", "com.docker.compose.project="+composeProject)
		f.Add("label", "com.docker.compose.service=tor")
		list, err := cli.ContainerList(ctx, container.ListOptions{
			All:     true,
			Filters: f,
		})
		if err != nil {
			t.Fatalf("ContainerList (tor by label): %v", err)
		}
		if len(list) == 0 {
			t.Fatal("no tor container found by compose project/service labels — did `up -d tor` actually start?")
		}
		for _, c := range list {
			insp, err := cli.ContainerInspect(ctx, c.ID)
			if err != nil {
				t.Fatalf("ContainerInspect %s: %v", c.ID, err)
			}
			if insp.NetworkSettings == nil {
				t.Fatalf("ContainerInspect %s returned nil NetworkSettings", c.ID)
			}
			for _, portKey := range []string{socksPort, controlPort} {
				if binding, ok := insp.NetworkSettings.Ports[nat.Port(portKey)]; ok && len(binding) > 0 {
					t.Errorf("FR-012 violation: tor container %s has published binding for %s: %+v", c.ID, portKey, binding)
				} else {
					t.Logf("OK: tor container %s has no published binding for %s", c.ID, portKey)
				}
			}
		}
	})

	t.Run("StargateDPNamespaceCanReachTorSocksPort", func(t *testing.T) {
		// (c) self-lifts when data-plane/cmd/stargate-proxy/main.go lands.
		// The content gate is a proxy for "stargate-dp image is buildable":
		// data-plane/Dockerfile does `COPY cmd/ ./cmd/` and fails the
		// cache key lookup when that path is absent. A future edit that
		// adds the file but breaks the build silently surfaces here as a
		// (c) FAILURE (build fail → fail-not-skip), which is desired.
		dpMain := filepath.Join(repoRoot, "data-plane", "cmd", "stargate-proxy", "main.go")
		if _, err := os.Stat(dpMain); err != nil {
			t.Skipf("blocked: %s absent — stargate-dp image not buildable yet; lift this skip when the DP-main ticket lands", dpMain)
		}

		// Bring up stargate-dp. Compose's `--wait` would block on the
		// container's healthcheck, which the scratch-based image does not
		// define; we instead poll container state directly via the SDK
		// below.
		upCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		if out, err := dockerCompose(upCtx, composeFile, envFile, "up", "-d", "--build", "stargate-dp"); err != nil {
			t.Fatalf("docker compose up stargate-dp: %v\n%s", err, out)
		}

		// Ephemeral probe container attached to the same compose network
		// as stargate-dp, doing `nc -z -w 2 tor 9050`. Why ephemeral and
		// NOT `docker exec stargate-dp nc ...`: stargate-dp's runtime
		// image is FROM scratch (no shell, no nc, no /bin anything) — see
		// data-plane/Dockerfile. The ephemeral-on-same-network check
		// verifies the bridge-reachability property FR-012 actually
		// constrains (a future regression that re-attaches tor to a
		// different docker network is caught statically by T015's
		// local_compose_test.sh M3/M4). Documented in ticket §Analysis
		// residue.
		//
		// FR-012's wording says "only the data plane container needs
		// SocksPort access" — that is descriptive of design intent, NOT
		// enforceable by Compose today (a bridge network exposes L3
		// reachability to every attached container, no per-container ACL).
		// The residue is honestly stated: this test verifies bridge-
		// reachability, not per-container ACL isolation; the latter is
		// not enforceable via Compose and is accepted as design residue.

		// Resolve the actual compose-internal network name via the SDK
		// rather than string-concatenating the Compose v2 `<project>_<name>`
		// convention. The convention is undocumented and shifts across
		// Compose versions (e.g. `--compatibility` flips v1-style naming;
		// project-name sanitization mangles dots/dashes). Filter by the
		// `com.docker.compose.project` + `com.docker.compose.network`
		// labels — symmetric with how sub-test (b) finds the tor container.
		networkName, err := lookupComposeNetwork(ctx, cli, composeProject, "stargate-internal")
		if err != nil {
			t.Fatalf("lookup stargate-internal network for project %q: %v", composeProject, err)
		}

		// Pull the probe image (digest-pinned via probeImage). Cold pulls
		// bounded so a registry slow-path does not blow past the test
		// deadline.
		pullCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		pull := exec.CommandContext(pullCtx, "docker", "pull", probeImage)
		if out, err := pull.CombinedOutput(); err != nil {
			t.Fatalf("docker pull %s: %v\n%s", probeImage, err, out)
		}

		// Shell out to `docker run` rather than the SDK ContainerCreate +
		// ContainerStart + ContainerWait dance. The SDK path is finicky
		// about API-version drift between the auto-negotiated client and
		// the host daemon (ContainerWait's condition enum has moved
		// across versions); the CLI is stable across daemon versions.
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(runCtx, "docker",
			"run", "--rm",
			"--network", networkName,
			probeImage,
			"nc", "-z", "-w", "2", "tor", "9050",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("FR-007 violation: nc probe to tor:9050 from %s failed: %v\n%s", networkName, err, bytes.TrimSpace(out))
		} else {
			t.Logf("OK: nc probe to tor:9050 succeeded from %s", networkName)
		}
	})
}

// lookupComposeNetwork resolves the actual docker network name for a
// (project, composeNetworkName) pair via the SDK's label-based filter.
// Returns the docker network's `Name` field (the runtime identifier
// `docker run --network` accepts), NOT the compose-logical name. Empty
// string + nil error means "network exists but has empty Name" (should
// not happen in practice). An error means the network was not found —
// typically a compose-up failure or a project-name mismatch.
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

// dockerCompose runs `docker compose -p <composeProject> -f <file>
// --env-file <env> <args...>` and returns the combined stdout+stderr.
func dockerCompose(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	full := append([]string{
		"-p", composeProject,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose"}, full...)...)
	return cmd.CombinedOutput()
}

// findRepoRoot walks up from this test file's source location to find the
// directory containing compose/docker-compose.local.yml. We do NOT rely
// on the working directory because `go test` may be invoked from any cwd
// (CI matrices, IDE runners, container validation paths).
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
