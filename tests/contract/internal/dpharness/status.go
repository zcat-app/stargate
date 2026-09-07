// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// status.go — the GetStatus probe contract tests use to read the data
// plane's aggregate counters (data-model.md §3) through the DP-hosted
// Control service on dp.sock (contracts/control-grpc.md §"GetStatus
// (minimum subset)"). In v1 the contract-test harness is the RPC's only
// caller (research.md §11); the counter-contract tickets T025c / T025d /
// T067b probe through this one seam rather than re-dialing ad hoc, so
// the probe shape has a single choke point to amend.
//
// The §5.3 wire-version metadata is attached HERE, not left to callers:
// the DP's server interceptor rejects a metadata-less RPC with
// FailedPrecondition before any handler runs (wireprobe's `nomajor` mode
// pins that rejection), so a probe without the keys measures nothing but
// the interceptor. The key names and values mirror
// data-plane/internal/protoversion, which this module cannot import
// (tests/contract is a separate Go module; internal-package rule) — the
// same local-mirror pattern tests/contract/compose/wireprobe uses. A
// future stargate.v2 bump edits both mirrors alongside the proto package
// rename (arch §5.3).
package dpharness

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// The §5.3 wire-version metadata keys and this harness's values,
// mirroring data-plane/internal/protoversion (see the package comment
// for why the mirror lives here and not behind an import).
const (
	probeMetaMajor = "x-stargate-proto-major"
	probeMetaMinor = "x-stargate-proto-minor"
	probeMetaCaps  = "x-stargate-capabilities"

	probeMajor = "1"
	probeMinor = "0"
	probeCaps  = "reload-tokens,watch-events,get-status-minimum"
)

// Status returns the data plane's point-in-time counter snapshot via the
// DP-hosted GetStatus RPC. Fatal on transport error. The read itself
// increments nothing on the DP side — that property is exactly what
// T025c's no-traffic sandwich verifies end-to-end, so the probe staying
// a pure read is load-bearing for every delta asserted through it.
func Status(t *testing.T, h *Harness) *grpcpb.StatusResponse {
	t.Helper()
	resp, err := StatusErr(h)
	if err != nil {
		t.Fatalf("GetStatus transport error: %v", err)
	}
	return resp
}

// StatusErr is the goroutine-safe probe (no *testing.T calls), symmetric
// with ReloadErr; Status is the fatal wrapper sequential cases use.
func StatusErr(h *Harness) (*grpcpb.StatusResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx,
		probeMetaMajor, probeMajor,
		probeMetaMinor, probeMinor,
		probeMetaCaps, probeCaps)
	conn, closeFn, err := dialControlTLS(h)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	client := grpcpb.NewControlClient(conn)
	return client.GetStatus(ctx, &grpcpb.StatusRequest{}, grpc.WaitForReady(true))
}
