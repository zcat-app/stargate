//go:build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package tor

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const composeProject = "stargate-t162-socket-test"

// TestTorSocketCallerMatrix uses real Tor sockets and the actual volume
// permissions, not a mock TCP listener. CP's missing mount is pinned by the
// separate Compose structural gate; here a deliberately attached CP-identity
// negative control proves that group DAC still refuses the SOCKS hardlink.
func TestTorSocketCallerMatrix(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker CLI unavailable")
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("Docker daemon unavailable: %v (%s)", err, out)
	}
	repo := findRepoRoot(t)
	composeFile := filepath.Join(repo, "compose/docker-compose.local.yml")
	envFile := filepath.Join(repo, "compose/env/local.env.example")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 2*time.Minute)
		defer stop()
		if out, err := dockerCompose(cleanupCtx, composeFile, envFile, "down", "-v", "--remove-orphans"); err != nil {
			t.Errorf("cleanup disposable Tor stack: %v: %s", err, out)
		}
	})
	if out, err := dockerCompose(ctx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("start Tor: %v: %s", err, out)
	}
	volume := composeVolume(t, "stargate-tor-dp-fabric")
	stateVolume := composeVolume(t, "stargate-tor-state")
	torID, err := dockerCompose(ctx, composeFile, envFile, "ps", "-q", "tor")
	if err != nil || len(bytes.TrimSpace(torID)) == 0 {
		t.Fatalf("Tor container missing: %v: %s", err, torID)
	}
	ports, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", strings.TrimSpace(string(torID))).CombinedOutput()
	if err != nil || strings.TrimSpace(string(ports)) != "{}" {
		t.Fatalf("Tor published ports or inspect failure: %v: %s", err, ports)
	}

	checkMatrix := func(label string) {
		t.Helper()
		out, err := socketProbe(ctx, volume, "5102:5100", true, `printf '\005\001\002' | nc -q 1 -U /run/stargate-tor/tor-socks.sock | od -An -tx1`)
		if err != nil || strings.TrimSpace(string(out)) != "05 02" {
			t.Fatalf("%s DP→SOCKS failed: %v: %s", label, err, out)
		}
		out, err = dockerCompose(ctx, composeFile, envFile, "exec", "-T", "tor", "sh", "-c",
			`printf 'PROTOCOLINFO 1\r\nQUIT\r\n' | nc -q 1 -U /var/lib/tor/control/tor-control.sock`)
		if err != nil || !bytes.Contains(out, []byte("250-PROTOCOLINFO 1")) {
			t.Fatalf("%s Tor-local raw control positive control failed: %v: %s", label, err, out)
		}
		for _, probe := range []struct {
			name    string
			user    string
			dpGroup bool
		}{
			{name: "CP", user: "5101:5100"},
			{name: "unprivileged", user: "6000:6000"},
		} {
			out, err = socketProbe(ctx, volume, probe.user, probe.dpGroup,
				`printf '\005\001\002' | nc -q 1 -U /run/stargate-tor/tor-socks.sock`)
			if err == nil || !bytes.Contains(out, []byte("Permission denied")) {
				t.Fatalf("%s %s unexpectedly reached SOCKS: %v: %s", label, probe.name, err, out)
			}
		}
		for _, probe := range []struct {
			name    string
			user    string
			dpGroup bool
		}{
			{name: "CP", user: "5101:5100"},
			{name: "DP", user: "5102:5100", dpGroup: true},
		} {
			// Actual deployed consumer view: neither plane receives Tor state.
			out, err = socketProbe(ctx, volume, probe.user, probe.dpGroup,
				`printf 'PROTOCOLINFO 1\r\n' | nc -q 1 -U /var/lib/tor/control/tor-control.sock`)
			if err == nil || !socketPathDenied(out) {
				t.Fatalf("%s %s reached raw control through consumer view: %v: %s", label, probe.name, err, out)
			}
			// Adversarially attach the real state volume to make the socket
			// positively present; Tor's 0700 directory must still deny dial.
			out, err = stateSocketProbe(ctx, stateVolume, probe.user,
				`printf 'PROTOCOLINFO 1\r\n' | nc -q 1 -U /var/lib/tor/control/tor-control.sock`)
			if err == nil || !bytes.Contains(out, []byte("Permission denied")) {
				t.Fatalf("%s %s reached mounted raw control: %v: %s", label, probe.name, err, out)
			}
			// A mistaken re-exposure into the DP fabric root must be caught
			// by a connection attempt, not merely an absent-state-file check.
			out, err = socketProbe(ctx, volume, probe.user, probe.dpGroup,
				`printf 'PROTOCOLINFO 1\r\n' | nc -q 1 -U /run/stargate-tor/tor-control.sock`)
			if err == nil || !socketPathDenied(out) {
				t.Fatalf("%s %s reached control on DP fabric: %v: %s", label, probe.name, err, out)
			}
		}
	}
	checkMatrix("initial")
	if out, err := dockerCompose(ctx, composeFile, envFile, "restart", "tor"); err != nil {
		t.Fatalf("restart Tor: %v: %s", err, out)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, err := socketProbe(ctx, volume, "5102:5100", true, `printf '\005\001\002' | nc -q 1 -U /run/stargate-tor/tor-socks.sock | od -An -tx1`)
		if err == nil && strings.TrimSpace(string(out)) == "05 02" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SOCKS re-exposure not recovered after Tor restart: %v: %s", err, out)
		}
		time.Sleep(500 * time.Millisecond)
	}
	checkMatrix("after restart")
	for _, port := range []string{"9050", "9051"} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 300*time.Millisecond)
		if err == nil {
			conn.Close()
			t.Errorf("Tor legacy TCP port %s is reachable on host loopback", port)
		}
	}
}

func socketPathDenied(out []byte) bool {
	return bytes.Contains(out, []byte("Permission denied")) ||
		bytes.Contains(out, []byte("No such file"))
}

func stateSocketProbe(ctx context.Context, volume, user, script string) ([]byte, error) {
	args := []string{"run", "--rm", "--network", "none", "--user", user,
		"--entrypoint", "/bin/sh", "-v", volume + ":/var/lib/tor:ro",
		"stargate/tor:local", "-c", script}
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}

func socketProbe(ctx context.Context, volume, user string, dpGroup bool, script string) ([]byte, error) {
	args := []string{"run", "--rm", "--network", "none", "--user", user}
	if dpGroup {
		args = append(args, "--group-add", "5200")
	}
	args = append(args, "--entrypoint", "/bin/sh", "-v", volume+":/run/stargate-tor:ro", "stargate/tor:local", "-c", script)
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}

func composeVolume(t *testing.T, logical string) string {
	t.Helper()
	cmd := exec.Command("docker", "volume", "ls", "--filter", "label=com.docker.compose.project="+composeProject,
		"--filter", "label=com.docker.compose.volume="+logical, "--format", "{{.Name}}")
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) == "" || strings.Contains(strings.TrimSpace(string(out)), "\n") {
		t.Fatalf("resolve %s volume: %v: %s", logical, err, out)
	}
	return strings.TrimSpace(string(out))
}

func dockerCompose(ctx context.Context, composeFile, envFile string, args ...string) ([]byte, error) {
	base := []string{"compose", "-p", composeProject, "-f", composeFile, "--env-file", envFile}
	return exec.CommandContext(ctx, "docker", append(base, args...)...).CombinedOutput()
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
