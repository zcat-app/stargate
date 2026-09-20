//go:build docker

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package compose verifies the T162 local topology against the Docker daemon.
// The host-netns DP is not started here: the installer and packet-level tests
// must establish its host policy before any DP process is admitted.
package compose

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
		if out, err := dockerCompose(stopCtx, composeFile, envFile, "down", "-v", "--remove-orphans"); err != nil {
			t.Errorf("cleanup disposable Tor topology: %v: %s", err, out)
		}
	})
	if out, err := dockerCompose(ctx, composeFile, envFile, "up", "-d", "--build", "tor"); err != nil {
		t.Fatalf("start Tor: %v: %s", err, out)
	}
	idBytes, err := dockerCompose(ctx, composeFile, envFile, "ps", "-q", "tor")
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
	deadline := time.Now().Add(5 * time.Minute)
	for {
		health, err := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Health.Status}}", id).CombinedOutput()
		if err != nil {
			t.Fatalf("Tor health inspect: %v: %s", err, health)
		}
		if strings.TrimSpace(string(health)) == "healthy" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Tor did not bootstrap healthy: %s", health)
		}
		time.Sleep(3 * time.Second)
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
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
