//go:build docker
// +build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package compose hosts the runtime contract tests for the local Compose
// stack's network segmentation + per-container hardening (T094b).
//
// The STATIC topology (network count, internal:true flags, per-service
// membership, Tor as sole egress attachee) is gated by
// tests/contract/compose/local_compose_test.sh (M13) at PR cadence under
// scripts/verify.sh gate 4 — that test renders the compose file via
// `docker compose config` and starts no daemon containers. The tests here
// BRING UP the stack and assert the RUNTIME properties a silent daemon-
// side change (network re-attachment, hardening-flag drift at runtime,
// egress actually being blocked) could regress between static-test runs:
//
//   - Tor bootstraps healthy on the split topology (it kept its egress).
//   - The DP and CP networks have no public egress (internal:true enforced).
//   - The intended internal paths resolve (DP-net → tor:9050,
//     CP-net → tor:9051).
//   - The application planes are mutually unreachable (no shared network:
//     the CP service name does not resolve from the DP net, and vice-versa)
//     — content-gated on DP/CP buildability, since a service name that
//     fails to resolve because its container was never started is NOT
//     isolation (the property is statically gated by M13 meanwhile).
//   - Each buildable container runs the hardened shape (read-only rootfs,
//     cap_drop ALL, no-new-privileges, mem + pids limits, tmpfs /tmp+/run).
//   - The internal networks have no clearnet DNS-tunnel side-channel: the
//     embedded resolver (127.0.0.11) returns SERVFAIL for external names
//     (the load-bearing check that "Tor is the only egress" actually holds).
//   - The cross-plane tor-port residue is pinned as expected-reachable
//     (tor binds 0.0.0.0 on both ports and is multi-homed): wider than the
//     design-intent DP→{tor:9050}; CP→{tor:9051} matrix, but still
//     Tor-transiting — see THREAT-MODEL §5.8.
//
// stargate:cadence docker — this package BRINGS UP the tor service, so it
// is build-tagged (`//go:build docker`) out of the hermetic PR gate and
// runs in the named Docker job (T076 §Acceptance #4). scripts/verify.sh
// compile-checks it via `go vet -tags docker` and accounts it SKIP[docker]
// in the hermetic PR run; `STARGATE_TEST_TAGS=docker scripts/verify.sh`
// (the named job) executes it. The t.Skip guards below stay as
// defense-in-depth for the named job on Docker-less hosts.
//
// DP/CP reachability is asserted via ephemeral probes attached to each
// network rather than from inside the DP/CP containers themselves: the
// data-plane and control-plane images are NOT buildable today
// (data-plane/cmd/stargate-proxy/main.go is absent — same content-gate
// T019b's sub-test (c) uses), but the egress/isolation properties are
// properties of the NETWORK, which exists once tor (attached to all three
// networks) is up. The DP/CP CONTAINER hardening inspection self-skips on
// that content-gate and lifts when their main.go lands.
package compose

import (
	"bytes"
	"context"
	"fmt"
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
)

// composeProject namespaces every compose invocation this test issues so
// the test never collides with operator-authored state brought up under
// the default project name. `docker compose down --volumes --remove-orphans`
// in t.Cleanup tears the whole stack down regardless of which services
// started. Mirrors T019b/T032's per-package composeProject pattern.
const composeProject = "stargate-t094b-test"

// probeImage is the ephemeral container image used to assert reachability
// from inside each network's namespace. Digest-pinned per Constitution
// Principle IV; mirrors T019b's pin so the two suites exercise the same
// supply-chain-trusted probe. A future ticket may hoist this into a shared
// const file if more contract tests need ephemeral probe images.
const probeImage = "alpine:3@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"

// healthDeadline caps the wait for Docker to report State.Health.Status ==
// "healthy" after `up`. The Tor Dockerfile HEALTHCHECK runs every 30s with
// a 60s start-period; once bootstrapped the next run reports healthy.
// Matches T032's stance (generous for slow daemon response + slow guards).
const healthDeadline = 5 * time.Minute

// healthPollInterval paces the State.Health.Status poll via the Docker SDK.
const healthPollInterval = 5 * time.Second

// The four compose networks T094b+T125 define (compose-logical names, NOT
// the runtime `<project>_<name>` identifiers). See the tickets' grounding
// decisions for why this is a 4-net model and why stargate-internal is the
// preserved DP↔tor transport name (T019b references it by literal).
const (
	netEgress = "stargate-egress"   // NOT internal — Tor's sole egress path.
	netDPTor  = "stargate-internal" // internal:true — DP↔tor:9050 (FR-007).
	netCPTor  = "stargate-cp-tor"   // internal:true — CP↔tor:9051 (cookie ControlPort).
	// T125 round 2: carries the DP's host-loopback publish. NOT internal —
	// Docker silently discards published ports on internal:true networks
	// (the live finding that reopened T125) — but with IP masquerade
	// DISABLED so attached containers still have no internet egress.
	netHost = "stargate-host"
)

// dpMainGate / cpMainGate are PER-PLANE content-gates that mirror T019b's
// sub-test (c): the DP/CP images are unbuildable until their main packages
// land, so each plane's CONTAINER hardening inspection self-skips per plane
// rather than fails. The gates are independent because the planes ship in
// separate tickets — a future CP-main ticket may land before the DP-main
// ticket, and per-plane gates ensure each plane's hardening is inspected the
// moment that plane becomes buildable (a single combined gate would silently
// skip the CP when CP-main lands first).
var (
	dpMainGate = filepath.Join("data-plane", "cmd", "stargate-proxy", "main.go")
	cpMainGate = filepath.Join("control-plane", "runtime", "src", "main") // Quarkus runtime app source tree.
)

// TestNetworkSplitAndHardening gates T094b's runtime invariants after
// bringing up the tor service from compose/docker-compose.local.yml.
//
// Sub-tests map to acceptance #1 (a)–(d) plus the hardening inspection:
//
//   - TorBootstrapsHealthy (c)
//   - InternalNetsHaveNoPublicEgress (a)/(b): TCP + DNS-exfil negative paths
//   - ApplicationPlanesMutuallyUnreachable (a)/(b): no shared network
//   - IntendedPathsResolve (d): DP-net→tor:9050, CP-net→tor:9051
//   - CrossPlaneTorPortResidue_DocumentedAndExpectedReachable: pins the
//     actual (wider) tor-port reach matrix as residue (redteam Major)
//   - NetworkTopologyAppliedAtRuntime: 4 nets, internal flags take effect
//   - HostNetCarriesPublishWithoutEgress (T125): publish-capable net is
//     masquerade-off (publish works, egress stays dead)
//   - TorContainerHardened: read-only/caps/security_opt/limits/tmpfs
//   - AppPlaneContainersHardened: content-gated on DP/CP buildability
//
// Self-skips when the docker daemon is unreachable or the docker CLI is
// absent (mirrors T019b/T032 skip conditions).
func TestNetworkSplitAndHardening(t *testing.T) {
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

	// Register cleanup BEFORE the compose-up call: a partial `up` (networks
	// created) that then returns non-zero would orphan resources under this
	// project name on t.Fatalf. `compose down` on a never-brought-up project
	// is a no-op. Mirrors T019b/T032.
	t.Cleanup(func() {
		downCtx, dcancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer dcancel()
		if out, err := dockerCompose(downCtx, composeFile, envFile, "down", "--volumes", "--remove-orphans"); err != nil {
			t.Logf("docker compose down (best-effort cleanup): %v\n%s", err, out)
		}
	})

	// Bring up tor only. tor is attached to three of the four networks, so
	// compose creates those three regardless of DP/CP being started; the
	// fourth (stargate-host, T125) is created by the DP bring-up in the
	// per-plane loop below (buildable since T050) — the network exists for
	// the HostNetCarriesPublishWithoutEgress probe whether or not the DP
	// process stays up. Full-stack bring-up is impossible today (fresh
	// volumes lack the operator-provisioned keys/pepper — T059 §Residue);
	// the AppPlaneContainers hardening sub-test inspects config, not
	// runtime health, so a DP that exits on missing pepper is still
	// inspectable. `--build` forces a rebuild against the current
	// Dockerfile so the test exercises the on-disk contract (mirrors
	// T019b).
	upCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if out, err := dockerCompose(upCtx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("docker compose up -d --build tor: %v\n%s", err, out)
	}

	// Cold-pull the probe image (digest-pinned) so a registry slow-path
	// cannot blow past a probe's own deadline below.
	pullCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(pullCtx, "docker", "pull", probeImage).CombinedOutput(); err != nil {
		t.Fatalf("docker pull %s: %v\n%s", probeImage, err, out)
	}

	// Conditionally bring up each application plane INDEPENDENTLY. The DP/CP
	// runtime sub-tests below (mutual-unreachability + container hardening)
	// are only meaningful when the relevant plane(s) are actually running:
	// Docker Compose DNS does NOT register service names for containers that
	// were never created, so a name-resolution probe is vacuous until then.
	// Per-plane gates (not a single combined gate): the planes ship in
	// separate tickets, so each plane is brought up + inspected the moment it
	// builds. `up -d` on already-running services is a no-op (safe re-entry).
	dpBuildable := pathExists(filepath.Join(repoRoot, dpMainGate))
	cpBuildable := pathExists(filepath.Join(repoRoot, cpMainGate))
	if dpBuildable || cpBuildable {
		upAppCtx, cancelApp := context.WithTimeout(ctx, 8*time.Minute)
		defer cancelApp()
		for _, p := range []struct {
			name      string
			buildable bool
		}{
			{"stargate-dp", dpBuildable},
			{"stargate-control", cpBuildable},
		} {
			if !p.buildable {
				continue
			}
			if out, err := dockerCompose(upAppCtx, composeFile, envFile, "up", "-d", "--build", p.name); err != nil {
				t.Fatalf("docker compose up -d --build %s: %v\n%s", p.name, err, out)
			}
		}
	}
	// The mutual-unreachability probe needs BOTH planes running + registered.
	appPlanesUp := dpBuildable && cpBuildable

	// Resolve runtime network names (the undocumented `<project>_<name>`
	// convention is unstable across compose versions — resolve by labels).
	// The egress net's runtime name is resolved implicitly by
	// assertNetInternal below; only the two internal nets are probed.
	netDPTorName := mustResolveNet(t, ctx, cli, netDPTor)
	netCPTorName := mustResolveNet(t, ctx, cli, netCPTor)

	// (c) Tor alone bootstraps. Proves the egress net actually carries Tor's
	// outbound traffic to the Tor network (the load-bearing egress proof).
	t.Run("TorBootstrapsHealthy", func(t *testing.T) {
		status, err := waitForHealth(ctx, cli, composeProject, "tor", healthDeadline)
		if err != nil {
			t.Fatalf("tor did not reach State.Health.Status == healthy within %s: %v\n"+
				"last status: %s\n(check `docker compose -p %s logs tor`; read_only/cap_drop\n"+
				"hardening that breaks bootstrap surfaces here)",
				healthDeadline, err, status, composeProject)
		}
		t.Logf("OK: State.Health.Status == healthy (egress net carries Tor traffic)")
	})

	// (a)/(b) negative public-egress path — TCP AND DNS. A probe on each
	// internal:true network must have neither a route to a public IP nor a
	// clearnet DNS-tunnel side-channel:
	//   - TCP: Docker's internal flag removes the bridge's default route, so
	//     the kernel has no route to the public address and nc exits non-zero.
	//   - DNS: Docker's embedded resolver (127.0.0.11) returns SERVFAIL for
	//     external names on internal networks (verified empirically — the
	//     same names resolve on a non-internal bridge). Without this, a
	//     compromised container could DNS-tunnel exfil data
	//     (<b32>.attacker.com → host resolver → internet), bypassing "Tor is
	//     the only egress" entirely. This is the load-bearing assertion that
	//     the Tor-only-egress claim actually holds.
	// stargate-egress is NOT probed here — Tor's bootstrap above is its
	// egress proof (no arbitrary outbound connection from the test).
	t.Run("InternalNetsHaveNoPublicEgress", func(t *testing.T) {
		for _, netName := range []string{netDPTorName, netCPTorName} {
			out, err := probeNet(ctx, netName, "nc", "-z", "-w", "3", "1.1.1.1", "80")
			if err == nil {
				t.Errorf("internal net %q reached public 1.1.1.1:80 — internal:true TCP egress block NOT enforced:\n%s",
					netName, bytes.TrimSpace(out))
			} else {
				t.Logf("OK: probe on internal net %q could not TCP-reach 1.1.1.1:80: %v", netName, err)
			}
			out, err = probeNet(ctx, netName, "nslookup", "example.com", "127.0.0.11")
			if err == nil {
				t.Errorf("internal net %q resolved external name example.com via 127.0.0.11 — DNS-exfil side-channel open (clearnet bypass of the Tor-only egress):\n%s",
					netName, bytes.TrimSpace(out))
			} else {
				t.Logf("OK: probe on internal net %q could not resolve example.com via 127.0.0.11 (DNS exfil blocked): %v", netName, err)
			}
			// Authoritative routing-table confirmation: no default route on
			// an internal net (busybox `ip route` lists routes literally;
			// absence of a `default` line is the deterministic signal,
			// independent of the nc/nslookup behavioural probes above).
			out, _ = probeNet(ctx, netName, "ip", "route")
			if bytes.Contains(out, []byte("default")) {
				t.Errorf("internal net %q has a default route — internal:true did NOT remove the gateway:\n%s", netName, bytes.TrimSpace(out))
			} else {
				t.Logf("OK: no default route on internal net %q (ip route: %q)", netName, bytes.TrimSpace(out))
			}
		}
	})

	// (a)/(b) application planes mutually unreachable — RUNTIME proof.
	// IMPORTANT: this sub-test is content-gated on appPlanesUp. A service
	// name that fails to resolve because its container was never started is
	// NOT network isolation — it would pass under any topology. The probe is
	// only discriminative once both planes are running (a regression that
	// re-attached CP to the DP net would then resolve stargate-control and
	// fail this test). The no-shared-network property is statically gated at
	// PR cadence by M13 in the meantime; this sub-test supplies the runtime
	// confirmation once the DP/CP images build.
	t.Run("ApplicationPlanesMutuallyUnreachable", func(t *testing.T) {
		if !appPlanesUp {
			t.Skipf("blocked: %s absent — DP/CP not started; the service-name DNS probe is only discriminative when both planes run. The no-shared-network property is statically gated by local_compose_test.sh M13 meanwhile.", dpMainGate)
		}
		// DP net must NOT resolve stargate-control (CP surface unreachable).
		if _, err := probeNet(ctx, netDPTorName, "nc", "-z", "-w", "2", "stargate-control", "8443"); err == nil {
			t.Errorf("DP net %q resolved/reached stargate-control — CP is reachable from the DP network (no-shared-network invariant broken)",
				netDPTorName)
		} else {
			t.Logf("OK: stargate-control does not resolve from DP net %q (CP not on the DP network)", netDPTorName)
		}
		// CP net must NOT resolve stargate-dp (DP SOCKS surface unreachable).
		if _, err := probeNet(ctx, netCPTorName, "nc", "-z", "-w", "2", "stargate-dp", "8881"); err == nil {
			t.Errorf("CP net %q resolved/reached stargate-dp:8881 — DP SOCKS surface reachable from the CP network (no-shared-network invariant broken)",
				netCPTorName)
		} else {
			t.Logf("OK: stargate-dp does not resolve from CP net %q (DP not on the CP network)", netCPTorName)
		}
	})

	// (d) intended internal paths resolve. DP-net reaches tor:9050
	// (FR-007); CP-net reaches tor:9051 (cookie ControlPort, T094a).
	t.Run("IntendedPathsResolve", func(t *testing.T) {
		if out, err := probeNet(ctx, netDPTorName, "nc", "-z", "-w", "2", "tor", "9050"); err != nil {
			t.Errorf("FR-007: DP net %q cannot reach tor:9050:\n%s", netDPTorName, bytes.TrimSpace(out))
		} else {
			t.Logf("OK: DP net %q reaches tor:9050", netDPTorName)
		}
		if out, err := probeNet(ctx, netCPTorName, "nc", "-z", "-w", "2", "tor", "9051"); err != nil {
			t.Errorf("T094a: CP net %q cannot reach tor:9051:\n%s", netCPTorName, bytes.TrimSpace(out))
		} else {
			t.Logf("OK: CP net %q reaches tor:9051", netCPTorName)
		}
	})

	// Cross-plane tor-port residue (redteam Major, Principle V). tor binds
	// SocksPort + ControlPort on 0.0.0.0 (contracts/torrc.md) and is multi-
	// homed across all three networks, so the ACTUAL L3 reach matrix is
	// wider than the design-intent DP→{tor:9050}; CP→{tor:9051}: CP can also
	// reach tor:9050 (unauthenticated SOCKS — a Tor-transiting exfil channel
	// that bypasses DP routing + per-first-party stream isolation) and DP can
	// also reach tor:9051 (inert: the auth cookie is volume-isolated to tor).
	// These are EXPECTED reachable today; this sub-test pins that so a future
	// torrc change (per-interface binds, T087 scope) that CLOSES them fails
	// here and forces this sub-test + THREAT-MODEL §5.8 to update in lockstep
	// rather than silently breaking. The residue does NOT breach "Tor is the
	// sole egress TCB" — the exfil transits Tor (see §5.8).
	t.Run("CrossPlaneTorPortResidue_DocumentedAndExpectedReachable", func(t *testing.T) {
		// CP-net → tor:9050 (the "other" port for CP). Expected REACHABLE.
		if _, err := probeNet(ctx, netCPTorName, "nc", "-z", "-w", "2", "tor", "9050"); err != nil {
			t.Errorf("CP net %q can no longer reach tor:9050 — if T087 pinned per-interface port binds and closed this cross-plane residue, flip this to expect-unreachable and update THREAT-MODEL §5.8 in lockstep; otherwise this is a regression: %v",
				netCPTorName, err)
		} else {
			t.Logf("RESIDUE (expected today): CP net %q reaches tor:9050 — tor binds 0.0.0.0 + is multi-homed; Tor-transiting SOCKS surface bypassing DP stream isolation. Documented in THREAT-MODEL §5.8; closing needs T087.",
				netCPTorName)
		}
		// DP-net → tor:9051 (the "other" port for DP). Expected REACHABLE (inert).
		if _, err := probeNet(ctx, netDPTorName, "nc", "-z", "-w", "2", "tor", "9051"); err != nil {
			t.Errorf("DP net %q can no longer reach tor:9051 — if T087 pinned per-interface port binds, flip this to expect-unreachable and update THREAT-MODEL §5.8 in lockstep; otherwise regression: %v",
				netDPTorName, err)
		} else {
			t.Logf("RESIDUE (expected today): DP net %q reaches tor:9051 — inert (ControlPort cookie is volume-isolated to tor). Documented in THREAT-MODEL §5.8.",
				netDPTorName)
		}
	})

	// Runtime confirmation that compose actually applied the internal flags
	// the static M13 asserts from the config render (defense-in-depth: a
	// compose-plugin behaviour drift that silently dropped internal:true
	// would pass M13 but fail here).
	t.Run("NetworkTopologyAppliedAtRuntime", func(t *testing.T) {
		assertNetInternal(t, ctx, cli, netEgress, false)
		assertNetInternal(t, ctx, cli, netDPTor, true)
		assertNetInternal(t, ctx, cli, netCPTor, true)
		// Tor is attached to all three. Verified via the tor container's own
		// NetworkSettings.Networks map — authoritative for attachments; the
		// network-list response does not reliably populate its Containers map.
		netEgressName := mustResolveNet(t, ctx, cli, netEgress)
		torInsp := mustInspectByService(t, ctx, cli, "tor")
		if torInsp.NetworkSettings == nil || torInsp.NetworkSettings.Networks == nil {
			t.Fatal("tor container NetworkSettings.Networks is nil")
		}
		for logical, runtimeName := range map[string]string{
			netEgress: netEgressName,
			netDPTor:  netDPTorName,
			netCPTor:  netCPTorName,
		} {
			if _, ok := torInsp.NetworkSettings.Networks[runtimeName]; !ok {
				t.Errorf("tor is NOT attached to network %q (runtime %q); attachments: %v",
					logical, runtimeName, networkNames(torInsp.NetworkSettings.Networks))
			} else {
				t.Logf("OK: tor attached to %q", logical)
			}
		}
	})

	// T125 round 2: the DP's host-facing publish must actually WORK, and
	// the net that carries it must not hand the DP internet egress.
	// Docker silently DISCARDS published ports on internal:true networks
	// (the live finding that reopened T125: the container config carried
	// the binding while NetworkSettings.Ports was null), so the DP rides
	// stargate-host — a NON-internal bridge with IP masquerade disabled:
	// the publish path (docker-proxy / DNAT from the host, which sits on
	// the bridge) works, while originated traffic leaves with a private
	// source address and dies upstream. Both halves are load-bearing:
	//   - masquerade ON  → DP gains direct clearnet egress (Principle III
	//     broken: Tor is no longer the sole egress);
	//   - masquerade OFF but net internal → publish discarded (FR-005
	//     unreachable; the exact regression this sub-test exists to catch).
	// Accepted residue (documented, not probed): the Docker embedded
	// resolver on a non-internal network forwards external names, so a
	// COMPROMISED DP retains a DNS side-channel even with IP egress
	// blocked — SECURITY-DECISIONS.md (T125 entry) records the acceptance;
	// the runtime no-DNS-leak behaviour itself is gated by T034.
	t.Run("HostNetCarriesPublishWithoutEgress", func(t *testing.T) {
		if !dpBuildable {
			t.Skipf("blocked: %s absent — T050 (DP main) not landed; stargate-host is DP-only and is not created without the DP service", dpMainGate)
		}
		ri, err := inspectComposeNet(ctx, cli, netHost)
		if err != nil {
			t.Fatalf("inspect network %q: %v", netHost, err)
		}
		if ri.Internal {
			t.Errorf("network %q is internal:true — Docker discards published ports on internal networks; the DP's host publish would be dead (the T125 live regression)", netHost)
		} else {
			t.Logf("OK: network %q Internal=false (publish-capable)", netHost)
		}
		masq, ok := ri.Options["com.docker.network.bridge.enable_ip_masquerade"]
		if !ok || masq != "false" {
			t.Errorf("network %q enable_ip_masquerade = %q (present=%v), want \"false\" — with NAT the DP gains direct clearnet egress (Principle III: Tor must be the sole egress)",
				netHost, masq, ok)
		} else {
			t.Logf("OK: network %q enable_ip_masquerade=false (no egress)", netHost)
		}

		// Negative egress path on the host net: TCP must fail. (No
		// default-route check here — a non-internal bridge legitimately HAS
		// a default route via its gateway; the masquerade-less design kills
		// egress upstream of the host, not in the container's routing
		// table.)
		netHostName := mustResolveNet(t, ctx, cli, netHost)
		out, err := probeNet(ctx, netHostName, "nc", "-z", "-w", "5", "1.1.1.1", "80")
		if err == nil {
			t.Errorf("host net %q reached public 1.1.1.1:80 — masquerade-off not enforced; the DP has direct clearnet egress:\n%s",
				netHostName, bytes.TrimSpace(out))
		} else {
			t.Logf("OK: probe on host net %q could not TCP-reach 1.1.1.1:80 (egress blocked as designed): %v", netHostName, err)
		}

		// The publish itself: the DP container's runtime port map must
		// carry the loopback binding — the assertion whose absence let the
		// discarded-publish regression through. (A full host→8881 SOCKS
		// handshake is the live suite's positive control, T059.)
		dpInsp := mustInspectByService(t, ctx, cli, "stargate-dp")
		bindings, ok := dpInsp.HostConfig.PortBindings["8881/tcp"]
		if !ok || len(bindings) == 0 {
			t.Errorf("DP container has no 8881/tcp PortBindings — the host publish is gone (FR-005 unreachable)")
		} else if bindings[0].HostIP != "127.0.0.1" {
			t.Errorf("DP 8881/tcp published on %q, want 127.0.0.1 (FR-005 loopback-only)", bindings[0].HostIP)
		} else {
			t.Logf("OK: DP 8881/tcp published on %s:%s", bindings[0].HostIP, bindings[0].HostPort)
		}
	})

	// Hardening inspection — the buildable container first.
	t.Run("TorContainerHardened", func(t *testing.T) {
		insp := mustInspectByService(t, ctx, cli, "tor")
		assertHardened(t, "tor", insp)
	})

	// DP/CP container hardening — PER-PLANE content-gate. Each plane is
	// inspected the moment IT becomes buildable (independent gates, so CP-
	// main landing before DP-main still inspects the CP). Tor hardening
	// already ran above; this lifts per-plane as each main ticket lands.
	t.Run("AppPlaneContainersHardened", func(t *testing.T) {
		planes := []struct {
			svc       string
			buildable bool
		}{
			{"stargate-dp", dpBuildable},
			{"stargate-control", cpBuildable},
		}
		inspected := false
		for _, p := range planes {
			if !p.buildable {
				continue
			}
			insp := mustInspectByService(t, ctx, cli, p.svc)
			assertHardened(t, p.svc, insp)
			inspected = true
		}
		if !inspected {
			t.Skipf("blocked: neither %s nor %s present — DP/CP images not buildable yet; per-plane hardening inspection lifts as each plane's main ticket lands (tor hardening above already runs)", dpMainGate, cpMainGate)
		}
	})
}

// assertHardened asserts the per-container hardened shape mandated by arch
// §8 + T094b acceptance #3: read-only rootfs, cap_drop ALL, no-new-
// privileges, explicit mem + pids limits, tmpfs /tmp + /run. Only the
// documented named volumes remain writable (verified statically by M7).
func assertHardened(t *testing.T, svc string, insp container.InspectResponse) {
	t.Helper()
	hc := insp.HostConfig
	if hc == nil {
		t.Fatalf("%s: HostConfig nil", svc)
	}
	if !hc.ReadonlyRootfs {
		t.Errorf("%s: read_only NOT set (arch §8: read-only rootfs; only named volumes writable)", svc)
	} else {
		t.Logf("OK: %s read_only=true", svc)
	}
	if !sliceContains(hc.CapDrop, "ALL") {
		t.Errorf("%s: cap_drop does not include ALL (got %v)", svc, hc.CapDrop)
	} else {
		t.Logf("OK: %s cap_drop includes ALL", svc)
	}
	if !sliceContains(hc.SecurityOpt, "no-new-privileges:true") {
		t.Errorf("%s: security_opt missing no-new-privileges:true (got %v)", svc, hc.SecurityOpt)
	} else {
		t.Logf("OK: %s no-new-privileges:true", svc)
	}
	if hc.Memory <= 0 {
		t.Errorf("%s: mem_limit not set (got %d)", svc, hc.Memory)
	} else {
		t.Logf("OK: %s mem_limit=%d bytes", svc, hc.Memory)
	}
	if hc.PidsLimit == nil || *hc.PidsLimit <= 0 {
		t.Errorf("%s: pids_limit not set (got %v)", svc, hc.PidsLimit)
	} else {
		t.Logf("OK: %s pids_limit=%d", svc, *hc.PidsLimit)
	}
	if hc.Tmpfs == nil {
		t.Errorf("%s: no tmpfs mounts (expected /tmp + /run)", svc)
	} else {
		for _, d := range []string{"/tmp", "/run"} {
			if _, ok := hc.Tmpfs[d]; !ok {
				t.Errorf("%s: tmpfs missing %q (got %v)", svc, d, hc.Tmpfs)
			}
		}
		if hc.Tmpfs["/tmp"] != "" || hc.Tmpfs["/run"] != "" {
			// empty-string tmpfs options are the norm; non-empty would be a
			// surprising extra (size/mode) worth surfacing, not failing.
			t.Logf("note: %s tmpfs carries options: %+v", svc, hc.Tmpfs)
		}
	}
}

// probeNet runs an ephemeral digest-pinned container on the given runtime
// network name and returns its combined output + error. Why ephemeral and
// not `docker exec` into the application containers: their runtime images
// are FROM scratch / distroless with no shell or nc (see data-plane/
// Dockerfile), and the reachability property belongs to the NETWORK, not
// the container. Mirrors T019b sub-test (c)'s ephemeral-probe rationale.
func probeNet(ctx context.Context, networkName string, args ...string) ([]byte, error) {
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	full := append([]string{"run", "--rm", "--network", networkName, probeImage}, args...)
	cmd := exec.CommandContext(runCtx, "docker", full...)
	return cmd.CombinedOutput()
}

// assertNetInternal asserts the compose-logical network has the expected
// Docker `Internal` flag at runtime.
func assertNetInternal(t *testing.T, ctx context.Context, cli *client.Client, composeNet string, wantInternal bool) {
	t.Helper()
	ri, err := inspectComposeNet(ctx, cli, composeNet)
	if err != nil {
		t.Fatalf("inspect network %q: %v", composeNet, err)
	}
	if ri.Internal != wantInternal {
		t.Errorf("network %q Internal flag = %v, want %v (runtime drift from the rendered config)", composeNet, ri.Internal, wantInternal)
	} else {
		t.Logf("OK: network %q Internal=%v", composeNet, ri.Internal)
	}
}

// inspectComposeNet resolves the runtime network for a (project, logical)
// pair and returns its Inspect response.
func inspectComposeNet(ctx context.Context, cli *client.Client, composeNet string) (network.Inspect, error) {
	f := filters.NewArgs()
	f.Add("label", "com.docker.compose.project="+composeProject)
	f.Add("label", "com.docker.compose.network="+composeNet)
	nets, err := cli.NetworkList(ctx, network.ListOptions{Filters: f})
	if err != nil {
		return network.Inspect{}, fmt.Errorf("NetworkList: %w", err)
	}
	if len(nets) == 0 {
		return network.Inspect{}, fmt.Errorf("no docker network found with labels project=%q network=%q", composeProject, composeNet)
	}
	return nets[0], nil
}

// mustResolveNet resolves a compose-logical network to its runtime docker
// Name (`docker run --network` accepts), failing the test if absent.
func mustResolveNet(t *testing.T, ctx context.Context, cli *client.Client, composeNet string) string {
	t.Helper()
	ri, err := inspectComposeNet(ctx, cli, composeNet)
	if err != nil {
		t.Fatalf("resolve network %q: %v", composeNet, err)
	}
	return ri.Name
}

// networkNames returns the runtime network names a container is attached
// to (the keys of its NetworkSettings.Networks map), for error diagnostics.
func networkNames(nets map[string]*network.EndpointSettings) []string {
	out := make([]string, 0, len(nets))
	for name := range nets {
		out = append(out, name)
	}
	return out
}

// containerIDByService locates a container by compose project+service labels.
func containerIDByService(ctx context.Context, cli *client.Client, project, service string) (string, error) {
	f := filters.NewArgs()
	f.Add("label", "com.docker.compose.project="+project)
	f.Add("label", "com.docker.compose.service="+service)
	list, err := cli.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {
		return "", fmt.Errorf("ContainerList (%s): %w", service, err)
	}
	if len(list) == 0 {
		return "", fmt.Errorf("no %q container found for project %q (did `up` start it?)", service, project)
	}
	return list[0].ID, nil
}

// mustInspectByService inspects a container by compose service, failing
// the test if absent.
func mustInspectByService(t *testing.T, ctx context.Context, cli *client.Client, service string) container.InspectResponse {
	t.Helper()
	id, err := containerIDByService(ctx, cli, composeProject, service)
	if err != nil {
		t.Fatalf("locate %s container: %v", service, err)
	}
	insp, err := cli.ContainerInspect(ctx, id)
	if err != nil {
		t.Fatalf("ContainerInspect %s (%s): %v", service, id, err)
	}
	return insp
}

// waitForHealth polls a container's State.Health.Status via the Docker SDK
// until "healthy" or deadline. Mirrors T032's waitForHealth (locate by
// compose labels, NOT the unstable `<project>-<service>-1` convention).
func waitForHealth(ctx context.Context, cli *client.Client, project, service string, deadline time.Duration) (string, error) {
	deadlineCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	f := filters.NewArgs()
	f.Add("label", "com.docker.compose.project="+project)
	f.Add("label", "com.docker.compose.service="+service)
	var lastStatus string
	for {
		list, err := cli.ContainerList(deadlineCtx, container.ListOptions{All: true, Filters: f})
		if err != nil {
			return lastStatus, fmt.Errorf("ContainerList (%s): %w", service, err)
		}
		if len(list) == 0 {
			lastStatus = "(container not found)"
		} else {
			insp, err := cli.ContainerInspect(deadlineCtx, list[0].ID)
			if err != nil {
				return lastStatus, fmt.Errorf("ContainerInspect %s: %w", list[0].ID, err)
			}
			if insp.State != nil && insp.State.Health != nil {
				lastStatus = string(insp.State.Health.Status)
				if lastStatus == "healthy" {
					return lastStatus, nil
				}
			} else if insp.State != nil {
				lastStatus = "State.Status=" + string(insp.State.Status) + " (no Health)"
			}
		}
		select {
		case <-deadlineCtx.Done():
			return lastStatus, deadlineCtx.Err()
		case <-time.After(healthPollInterval):
		}
	}
}

// sliceContains reports whether a string slice contains a value
// (case-sensitive). CapDrop/SecurityOpt come back as []string from the SDK.
func sliceContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// pathExists reports whether a path exists on disk (file or directory). Used
// for the per-plane buildability content-gates.
func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// dockerCompose runs `docker compose -p <composeProject> -f <file>
// --env-file <env> <args...>` and returns combined stdout+stderr. Mirrors
// T019b/T032 (per-package duplication; the helpers are small and keeping
// them co-located avoids a cross-module test-helper refactor).
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
// directory containing compose/docker-compose.local.yml. `go test` may be
// invoked from any cwd; we never rely on it. Mirrors T019b.
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
