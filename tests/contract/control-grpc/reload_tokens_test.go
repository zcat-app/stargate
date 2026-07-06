// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the ReloadTokens RPC — specs/001-tor-route/contracts/
// control-grpc.md §"ReloadTokens · Tests" rows 1–5, one sub-test per row.
//
// Each sub-test boots its own data-plane process (startDP content-gates
// on T045/T050 and self-skips until they land — see dpharness_test.go),
// pushes generations over dp.sock exactly as the control plane would, and
// observes the outcome ONLY through the DP's external surfaces: the RPC
// response, the SOCKS5 auth bytes on the proxy listener, dp-snapshot.json,
// and the captured journal.
package controlgrpc

import (
	"encoding/base64"
	"os"
	"sync"
	"testing"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

func TestReloadTokens(t *testing.T) {
	// Contract row 1: new generation applied atomically; subsequent
	// inbound proxy auth uses the new hashes. Two pushes prove the swap
	// both ways — each generation's plaintext authenticates while it is
	// current and stops authenticating once replaced.
	t.Run("HappyPathAppliesNewGeneration", func(t *testing.T) {
		h := startDP(t)
		tokA := mintToken(t, "t020-plain-alpha")
		tokB := mintToken(t, "t020-plain-bravo")

		resp := h.reload(t, 1, []*grpcpb.TokenHash{tokA})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("generation 1 status = %v, want APPLY_STATUS_OK", resp.GetStatus())
		}
		if resp.GetAppliedGeneration() != 1 {
			t.Errorf("applied_generation = %d, want 1", resp.GetAppliedGeneration())
		}

		// Persist-before-return: the snapshot must already hold the new
		// generation in the data-model.md §1.4 shape when the RPC returns.
		snap := h.readSnapshot(t)
		if snap.SchemaVersion != 1 {
			t.Errorf("snapshot schemaVersion = %d, want 1", snap.SchemaVersion)
		}
		if snap.Generation != 1 {
			t.Errorf("snapshot generation = %d, want 1", snap.Generation)
		}
		if len(snap.Hashes) != 1 {
			t.Fatalf("snapshot hashes count = %d, want 1", len(snap.Hashes))
		}
		// Persist-content fidelity: the on-disk hash/salt must be exactly
		// what was pushed — a DP persisting garbage while keeping the
		// right value in memory would otherwise pass here and only break
		// at cold-start restore (T020a). Messages carry no byte values
		// (index-only hygiene, same as assertNoSecretLeak).
		if snap.Hashes[0].Hash != base64.StdEncoding.EncodeToString(tokA.GetHash()) {
			t.Error("snapshot hashes[0].hash does not base64-match the pushed hash (data-model.md §1.4; value redacted)")
		}
		if snap.Hashes[0].Salt != base64.StdEncoding.EncodeToString(tokA.GetSalt()) {
			t.Error("snapshot hashes[0].salt does not base64-match the pushed salt (data-model.md §1.4; value redacted)")
		}

		h.requireAuth(t, "t020-plain-alpha", true, "generation 1's plaintext must authenticate after APPLY_STATUS_OK")
		h.requireAuth(t, "t020-plain-bravo", false, "a never-loaded plaintext must not authenticate")

		resp = h.reload(t, 2, []*grpcpb.TokenHash{tokB})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("generation 2 status = %v, want APPLY_STATUS_OK", resp.GetStatus())
		}
		if resp.GetAppliedGeneration() != 2 {
			t.Errorf("applied_generation = %d, want 2", resp.GetAppliedGeneration())
		}
		h.requireAuth(t, "t020-plain-bravo", true, "the NEW generation's plaintext must authenticate after the swap")
		h.requireAuth(t, "t020-plain-alpha", false, "the REPLACED generation's plaintext must stop authenticating")
		if got := h.readSnapshot(t).Generation; got != 2 {
			t.Errorf("snapshot generation after second push = %d, want 2", got)
		}

		assertNoSecretLeak(t, h, tokA.GetHash(), tokA.GetSalt(), tokB.GetHash(), tokB.GetSalt(),
			[]byte("t020-plain-alpha"), []byte("t020-plain-bravo"))
	})

	// Contract row 2: request.generation <= current →
	// APPLY_STATUS_STALE_GENERATION and no state change. Covers both the
	// equal and the strictly-lower shape of "<=".
	t.Run("StaleGenerationRejected", func(t *testing.T) {
		h := startDP(t)
		tokA := mintToken(t, "t020-plain-alpha")
		tokB := mintToken(t, "t020-plain-bravo")
		tokC := mintToken(t, "t020-plain-charlie")

		h.reload(t, 1, []*grpcpb.TokenHash{tokA})
		resp := h.reload(t, 2, []*grpcpb.TokenHash{tokB})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("setup: generation 2 status = %v, want APPLY_STATUS_OK", resp.GetStatus())
		}
		before := h.snapshotBytes(t)

		for _, staleGen := range []uint64{2, 1} {
			resp := h.reload(t, staleGen, []*grpcpb.TokenHash{tokC})
			if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION {
				t.Errorf("generation %d (current 2) status = %v, want APPLY_STATUS_STALE_GENERATION", staleGen, resp.GetStatus())
			}
			// applied_generation reports the generation in effect — the
			// unchanged current one, not the rejected request's.
			if resp.GetAppliedGeneration() != 2 {
				t.Errorf("generation %d applied_generation = %d, want 2 (unchanged)", staleGen, resp.GetAppliedGeneration())
			}
		}

		if after := h.snapshotBytes(t); string(after) != string(before) {
			t.Error("snapshot changed on a stale push — stale generations must leave persisted state untouched")
		}
		h.requireAuth(t, "t020-plain-bravo", true, "the current generation's plaintext must survive stale pushes")
		h.requireAuth(t, "t020-plain-charlie", false, "a stale push's tokens must never become live")

		assertNoSecretLeak(t, h, tokA.GetHash(), tokA.GetSalt(), tokB.GetHash(), tokB.GetSalt(),
			tokC.GetHash(), tokC.GetSalt(),
			[]byte("t020-plain-alpha"), []byte("t020-plain-bravo"), []byte("t020-plain-charlie"))
	})

	// Contract row 3: hash must be exactly 32 bytes and salt exactly 16;
	// any mismatch → APPLY_STATUS_INVALID with no generation change. The
	// generation number is not consumed by a rejected push.
	t.Run("InvalidHashLengthRejected", func(t *testing.T) {
		h := startDP(t)
		tokA := mintToken(t, "t020-plain-alpha")
		h.reload(t, 1, []*grpcpb.TokenHash{tokA})
		before := h.snapshotBytes(t)

		cases := []struct {
			name  string
			token *grpcpb.TokenHash
		}{
			{"hash 31B", &grpcpb.TokenHash{Hash: randomBytes(t, 31), Salt: randomBytes(t, 16)}},
			{"hash 33B", &grpcpb.TokenHash{Hash: randomBytes(t, 33), Salt: randomBytes(t, 16)}},
			{"salt 15B", &grpcpb.TokenHash{Hash: randomBytes(t, 32), Salt: randomBytes(t, 15)}},
			{"salt 17B", &grpcpb.TokenHash{Hash: randomBytes(t, 32), Salt: randomBytes(t, 17)}},
		}
		malformed := make([][]byte, 0, len(cases)*2)
		for _, c := range cases {
			resp := h.reload(t, 2, []*grpcpb.TokenHash{c.token})
			if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_INVALID {
				t.Errorf("%s: status = %v, want APPLY_STATUS_INVALID", c.name, resp.GetStatus())
			}
			if resp.GetAppliedGeneration() != 1 {
				t.Errorf("%s: applied_generation = %d, want 1 (unchanged)", c.name, resp.GetAppliedGeneration())
			}
			malformed = append(malformed, c.token.GetHash(), c.token.GetSalt())
		}

		if after := h.snapshotBytes(t); string(after) != string(before) {
			t.Error("snapshot changed on an invalid push — malformed tokens must leave persisted state untouched")
		}
		h.requireAuth(t, "t020-plain-alpha", true, "the current generation must survive invalid pushes")

		// The rejected generation number was not consumed: a valid push
		// with the same number now succeeds.
		tokB := mintToken(t, "t020-plain-bravo")
		if resp := h.reload(t, 2, []*grpcpb.TokenHash{tokB}); resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Errorf("valid generation 2 after invalid attempts: status = %v, want APPLY_STATUS_OK", resp.GetStatus())
		}

		// Contract's no-logging bullet applies to REJECTED bytes too —
		// "token format violations never log the offending bytes"
		// (data-model.md §1.6).
		assertNoSecretLeak(t, h, append(malformed,
			tokA.GetHash(), tokA.GetSalt(), tokB.GetHash(), tokB.GetSalt(),
			[]byte("t020-plain-alpha"), []byte("t020-plain-bravo"))...)
	})

	// Contract row 4: snapshot persist failure → still APPLY_STATUS_OK
	// (in-memory truth wins; the snapshot is only a cold-start cache) and
	// a snapshot-write-failure journal line. The read-only parent dir here
	// is the local-process equivalent of the contract's read-only mount.
	t.Run("SnapshotPersistFailureStillOK", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root: a read-only parent dir does not block root writes, so the persist-failure simulation cannot work")
		}
		h := startDP(t)
		tokA := mintToken(t, "t020-plain-alpha")
		tokB := mintToken(t, "t020-plain-bravo")
		h.reload(t, 1, []*grpcpb.TokenHash{tokA})

		if err := os.Chmod(h.stateDir, 0o555); err != nil {
			t.Fatalf("chmod state dir read-only: %v", err)
		}
		// Restore before t.TempDir's removal (LIFO ordering) so cleanup
		// can delete the directory.
		t.Cleanup(func() { _ = os.Chmod(h.stateDir, 0o755) })

		resp := h.reload(t, 2, []*grpcpb.TokenHash{tokB})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("status with unwritable snapshot dir = %v, want APPLY_STATUS_OK (in-memory truth wins)", resp.GetStatus())
		}
		if resp.GetAppliedGeneration() != 2 {
			t.Errorf("applied_generation = %d, want 2", resp.GetAppliedGeneration())
		}
		h.requireAuth(t, "t020-plain-bravo", true, "the new generation must be live despite the failed persist")
		h.requireAuth(t, "t020-plain-alpha", false, "the replaced generation must be gone despite the failed persist")

		if !h.journalContains("snapshot") {
			t.Error("journal has no snapshot-write-failure line — contract row 4 requires the failure to be journaled (a line class T025a's allowlist reserves)")
		}
		// Atomic write via os.Rename (data-model.md §1.4): a failed write
		// must leave the previous snapshot intact, not truncated.
		if got := h.readSnapshot(t).Generation; got != 1 {
			t.Errorf("on-disk snapshot generation after failed persist = %d, want 1 (previous content intact)", got)
		}

		assertNoSecretLeak(t, h, tokA.GetHash(), tokA.GetSalt(), tokB.GetHash(), tokB.GetSalt(),
			[]byte("t020-plain-alpha"), []byte("t020-plain-bravo"))
	})

	// Contract row 5: generations N and N+1 pushed in parallel converge
	// on N+1; the older one is stale on retry. The contract requires
	// convergence, not a particular interleaving — the gen-2 push MUST
	// apply; the gen-1 push is OK (applied then replaced) or STALE
	// (lost the race), both within contract.
	t.Run("ConcurrentReloadsConverge", func(t *testing.T) {
		h := startDP(t)
		tok1 := mintToken(t, "t020-plain-alpha")
		tok2 := mintToken(t, "t020-plain-bravo")

		var wg sync.WaitGroup
		var resp1, resp2 *grpcpb.ReloadTokensResponse
		var err1, err2 error
		wg.Add(2)
		go func() { defer wg.Done(); resp1, err1 = h.reloadErr(1, []*grpcpb.TokenHash{tok1}) }()
		go func() { defer wg.Done(); resp2, err2 = h.reloadErr(2, []*grpcpb.TokenHash{tok2}) }()
		wg.Wait()
		if err1 != nil || err2 != nil {
			t.Fatalf("transport errors: gen1=%v gen2=%v", err1, err2)
		}
		if resp2.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("generation 2 status = %v, want APPLY_STATUS_OK regardless of interleaving", resp2.GetStatus())
		}
		if s := resp1.GetStatus(); s != grpcpb.ApplyStatus_APPLY_STATUS_OK && s != grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION {
			t.Errorf("generation 1 status = %v, want APPLY_STATUS_OK or APPLY_STATUS_STALE_GENERATION", s)
		}

		retry := h.reload(t, 1, []*grpcpb.TokenHash{mintToken(t, "t020-plain-charlie")})
		if retry.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION {
			t.Errorf("generation 1 retry status = %v, want APPLY_STATUS_STALE_GENERATION", retry.GetStatus())
		}
		if retry.GetAppliedGeneration() != 2 {
			t.Errorf("converged applied_generation = %d, want 2", retry.GetAppliedGeneration())
		}
		h.requireAuth(t, "t020-plain-bravo", true, "the higher generation's plaintext must be live after convergence")
		h.requireAuth(t, "t020-plain-alpha", false, "the lower generation's plaintext must not be live after convergence")
		if got := h.readSnapshot(t).Generation; got != 2 {
			t.Errorf("snapshot generation after convergence = %d, want 2", got)
		}

		assertNoSecretLeak(t, h, tok1.GetHash(), tok1.GetSalt(), tok2.GetHash(), tok2.GetSalt(),
			[]byte("t020-plain-alpha"), []byte("t020-plain-bravo"), []byte("t020-plain-charlie"))
	})
}
