// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Package compose hosts the one shared `docker compose` project runner for
// the docker-cadence contract suites (T121 hoist; precedent anticipated by
// live_sidecar_test.go's pre-hoist note). Until T121 every suite baked its
// own project const into a private copy of this runner — deliberate
// duplication so no suite could ever reuse a sibling's runner and point
// `up` at the sibling's project while its exec transports used its own
// (the live split-brain failure T058a §Notes #1 records). The hoist keeps
// the isolation property by construction: the project is ALWAYS a caller
// argument — this package names no project itself — and each suite still
// owns its project CONST at its call sites (T121 acceptance #2).
//
// All subcommands issued through this runner (up/down/ps/exec/logs) ride
// the compose-internal transports of FR-012 — the runner never publishes a
// host port and never inspects payloads; it is plumbing only.
package compose

import (
	"context"
	"os/exec"
)

// Args builds the shared `docker compose` argv prefix:
// compose -p <project> -f <composeFile> --env-file <envFile> <args...>.
// The -p token leads so every subcommand is namespaced before any file is
// read; suites append their subcommand verbatim. Pinned by
// compose_test.go (TestArgsNamesSuiteProject).
func Args(project, composeFile, envFile string, args ...string) []string {
	return append([]string{
		"compose",
		"-p", project,
		"-f", composeFile,
		"--env-file", envFile,
	}, args...)
}

// Run executes `docker compose -p <project> -f <composeFile>
// --env-file <envFile> <args...>` and returns combined stdout+stderr —
// the contract every pre-hoist private runner (dockerCompose/cpCompose/
// ulCompose/isoCompose/liveDockerCompose) already had, so call sites keep
// their error-reporting shapes unchanged.
func Run(ctx context.Context, project, composeFile, envFile string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "docker", Args(project, composeFile, envFile, args...)...).CombinedOutput()
}
