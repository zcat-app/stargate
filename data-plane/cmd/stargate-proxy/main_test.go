// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/audit"
)

func TestTrafficCounterConfiguration(t *testing.T) {
	for _, tc := range []struct {
		value          string
		enabled, valid bool
	}{
		{"true", true, true}, {"false", false, true}, {"", false, false}, {"1", false, false}, {"FALSE", false, false}, {"untrusted detail", false, false},
	} {
		enabled, err := trafficCountersEnabled(tc.value)
		if (err == nil) != tc.valid || (tc.valid && enabled != tc.enabled) {
			t.Errorf("configuration %q = %v, %v", tc.value, enabled, err)
		}
		if err != nil && strings.Contains(err.Error(), tc.value) && tc.value != "" {
			t.Error("configuration error echoed input")
		}
	}
}

// Compiled only by go test -c: the ordinary shipped binary cannot read this clock.
// The contract harness opts in explicitly; all other process tests use go build.
func TestCounterClockProcess(t *testing.T) {
	path := os.Getenv("STARGATE_TEST_COUNTER_CLOCK")
	if path == "" {
		return
	}
	now := func() time.Time {
		raw, err := os.ReadFile(path)
		if err != nil {
			panic("test counter clock unreadable")
		}
		seconds, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			panic("test counter clock invalid")
		}
		return time.Unix(seconds, 0)
	}
	os.Exit(runWithCounters(func() *audit.Counters { return audit.NewWithClock(now) }))
}

// This is a packaging control: the accelerated clock's environment reader must
// be absent from the ordinary go-build artifact used outside counter fixtures.
func TestProductionCounterClockUnavailable(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "proxy")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("STARGATE_TEST_COUNTER_CLOCK")) {
		t.Fatal("test clock shipped in production binary")
	}
}
