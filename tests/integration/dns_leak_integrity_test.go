//go:build linux

// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// These deterministic regressions exercise the real data-plane binary and
// fake SOCKS upstream while replacing only packet observation. The session
// still sends its before/after control datagrams and completes routed
// CONNECTs; the synthetic observer records the controls and injects a single
// capture fault between them without requiring CAP_NET_RAW.
func TestT206CaptureReadErrorRejectsOtherwiseCleanVerdict(t *testing.T) {
	res := t034RunSessionWithCaptureFault(t, 3*time.Second, nil, "read-error")
	assertT206OnlyCaptureFault(t, res)
	for _, health := range res.captureHealth {
		if health.readErrorCount == 0 || health.firstReadError == "" {
			t.Fatal("read-error fault was not injected during the bracketed routed session")
		}
	}
	var bounded t034CaptureHealth
	for range 100 {
		bounded.recordReadError(strings.Repeat("x", t034MaxReadErrorDiagnosticBytes*2))
	}
	if bounded.readErrorCount != 100 || len(bounded.firstReadError) != t034MaxReadErrorDiagnosticBytes {
		t.Fatalf("capture error diagnostics are not bounded: count=%d retained_bytes=%d", bounded.readErrorCount, len(bounded.firstReadError))
	}
}

func TestT206PacketDropRejectsOtherwiseCleanVerdict(t *testing.T) {
	res := t034RunSessionWithCaptureFault(t, 3*time.Second, nil, "drop")
	assertT206OnlyCaptureFault(t, res)
	dropped := false
	for _, health := range res.captureHealth {
		dropped = dropped || health.drops != 0
	}
	if !dropped {
		t.Fatal("packet-drop fault was not injected during the bracketed routed session")
	}
}

func assertT206OnlyCaptureFault(t *testing.T, res t034Result) {
	t.Helper()
	if res.completed == 0 || res.completed != res.issued || res.upstreamPartitions != res.wantPartitions {
		t.Fatalf("fault session did not complete the real routed forwarding/partition controls: completed=%d issued=%d partitions=%d/%d", res.completed, res.issued, res.upstreamPartitions, res.wantPartitions)
	}
	if len(res.controls) != 2 {
		t.Fatalf("want successful before and after controls, got %d control windows", len(res.controls))
	}
	err := t034Verdict(res)
	if !errors.Is(err, errT034CaptureIntegrity) {
		t.Fatalf("zero-leak verdict must reject only the injected capture-integrity fault, got %v", err)
	}
	// Clear only the injected fault. The exact same records, controls, routed
	// forwarding, and partition evidence must then satisfy the verdict.
	clean := res
	clean.captureHealth = make(map[string]t034CaptureHealth, len(res.captureHealth))
	for iface, health := range res.captureHealth {
		health.readErrorCount = 0
		health.firstReadError = ""
		health.drops = 0
		health.queueFreezes = 0
		clean.captureHealth[iface] = health
	}
	if err := t034Verdict(clean); err != nil {
		t.Fatalf("fault was not the sole failed guard: %v", err)
	}
	for iface, health := range clean.captureHealth {
		health.statsKnown = false
		clean.captureHealth[iface] = health
	}
	if err := t034Verdict(clean); !errors.Is(err, errT034CaptureIntegrity) {
		t.Fatalf("zero-leak verdict accepted unreadable final packet-socket statistics: %v", err)
	}
	for iface, health := range clean.captureHealth {
		health.statsKnown = true
		clean.captureHealth[iface] = health
	}
	egressIface := clean.ifaces[len(clean.ifaces)-1]
	health := clean.captureHealth[egressIface]
	health.queueFreezes = 1
	clean.captureHealth[egressIface] = health
	if err := t034Verdict(clean); !errors.Is(err, errT034CaptureIntegrity) {
		t.Fatalf("zero-leak verdict accepted a packet-ring queue freeze: %v", err)
	}
}
