// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package compose

import (
	"reflect"
	"testing"
)

// TestArgsNamesSuiteProject pins the exact argv shape every docker-cadence
// suite hands to `docker`: project (-p) FIRST, then compose file, then env
// file, then the suite's subcommand verbatim. The -p token is the whole
// point of the T121 hoist: it namespaces up/down/ps/exec/logs/exec so one
// suite never addresses a sibling's project — the split-brain failure T058a
// §Notes #1 recorded live (up ran against a sibling's project while the
// exec transports used this suite's own). A regression that drops, reorders
// or renames the -p token fails here before any suite splits across two
// projects at runtime.
func TestArgsNamesSuiteProject(t *testing.T) {
	got := Args("stargate-t058a-test", "/repo/compose/docker-compose.local.yml",
		"/repo/compose/env/local.env.example", "up", "-d", "--build", "tor")
	want := []string{
		"compose",
		"-p", "stargate-t058a-test",
		"-f", "/repo/compose/docker-compose.local.yml",
		"--env-file", "/repo/compose/env/local.env.example",
		"up", "-d", "--build", "tor",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("argv mismatch:\n got  %q\n want %q", got, want)
	}
}

// TestArgsKeepsProjectsDistinct pins the cross-suite isolation property
// acceptance #2 of T121 protects: two suites' argv must differ in exactly
// the project token, so no shared-helper regression can fuse two suites
// onto one compose project (parallel CI runs, operator state collisions).
func TestArgsKeepsProjectsDistinct(t *testing.T) {
	const file, env = "/repo/compose/docker-compose.local.yml", "/repo/compose/env/local.env.example"
	a := Args("stargate-t019b-test", file, env, "down", "--volumes")
	b := Args("stargate-t032-test", file, env, "down", "--volumes")
	if reflect.DeepEqual(a, b) {
		t.Fatalf("distinct suites produced identical argv %q — projects fused", a)
	}
	if a[2] != "stargate-t019b-test" || b[2] != "stargate-t032-test" {
		t.Fatalf("project token drifted: a=%q b=%q", a[2], b[2])
	}
	for i := range a {
		if i == 2 {
			continue
		}
		if a[i] != b[i] {
			t.Fatalf("argv differs beyond the project token at %d: %q vs %q", i, a[i], b[i])
		}
	}
}
