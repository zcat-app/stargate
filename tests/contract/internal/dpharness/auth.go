// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Auth helpers shared across contract tests that exercise the data
// plane's bearer-token path: argon2id token minting (mirrors data-
// model.md §1.5 params) and a ReloadTokens gRPC client wrapper.
//
// The argon2id constants below MUST mirror
// specs/001-tor-route/data-model.md §1.5 and
// data-plane/internal/auth/params.go byte-for-byte. The mirror is
// deliberate, not accidental duplication: this module cannot import
// the data plane's internal package (Go's internal rule + the
// contract-test/production-code wall), so agreeing on the values from
// two independent declarations is itself the cross-plane params-
// agreement check — a drifted constant surfaces as an auth-probe
// failure here. The same discipline already applies in
// tests/contract/control-grpc/dpharness_test.go.
package dpharness

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

const (
	argonTime        uint32 = 3
	argonMemoryKiB   uint32 = 64 * 1024
	argonParallelism uint8  = 4
	argonHashLen     uint32 = 32
	argonSaltLen     uint32 = 16
)

// MintToken argon2id-hashes a known plaintext under a fresh random
// salt, yielding the wire shape the control plane would push (data-
// model.md §1.2: per-token salt; §1.5 params). The returned TokenHash
// is suitable for ReloadTokensRequest.Tokens.
//
// Tests that need DETERMINISTIC salt (e.g. snapshot-restore cold-start
// tests that pre-write dp-snapshot.json with a known {hash, salt})
// should construct the *grpcpb.TokenHash literal directly rather than
// call this helper.
func MintToken(t *testing.T, plaintext string) *grpcpb.TokenHash {
	t.Helper()
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("reading random salt: %v", err)
	}
	hash := argon2.IDKey([]byte(plaintext), salt, argonTime, argonMemoryKiB, argonParallelism, argonHashLen)
	return &grpcpb.TokenHash{Hash: hash, Salt: salt}
}

// Reload pushes a fresh token generation to the data plane via the
// ReloadTokens RPC (hosted on dp.sock per T045). Returns the apply
// response so the caller can assert APPLY_STATUS_OK or
// APPLY_STATUS_STALE_GENERATION as their contract demands. Fatal on
// transport error — a non-fatal wrapper (ReloadErr) is provided for
// tests that need to probe the RPC under contention (T020's
// concurrency case).
func Reload(t *testing.T, h *Harness, generation uint64, tokens []*grpcpb.TokenHash) *grpcpb.ReloadTokensResponse {
	t.Helper()
	resp, err := ReloadErr(h, generation, tokens)
	if err != nil {
		t.Fatalf("ReloadTokens(generation=%d) transport error: %v", generation, err)
	}
	return resp
}

// ReloadErr is the goroutine-safe RPC wrapper (no *testing.T calls)
// concurrency tests need. Reload is the fatal-on-transport-error
// wrapper every sequential case uses.
func ReloadErr(h *Harness, generation uint64, tokens []*grpcpb.TokenHash) (*grpcpb.ReloadTokensResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := grpc.NewClient("unix://"+h.SockPath(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("grpc.NewClient(unix://%s): %w", h.SockPath(), err)
	}
	defer conn.Close()
	client := grpcpb.NewControlClient(conn)
	return client.ReloadTokens(ctx,
		&grpcpb.ReloadTokensRequest{Generation: generation, Tokens: tokens},
		grpc.WaitForReady(true))
}
