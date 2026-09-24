// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for the ReloadTokens RPC — specs/001-tor-route/contracts/
// control-grpc.md §"ReloadTokens · Tests" rows 1–6, one sub-test per row.
//
// Each sub-test boots its own data-plane process (startDP content-gates
// on T045/T050 and self-skips until they land — see dpharness_test.go),
// pushes generations over dp.sock exactly as the control plane would, and
// observes the outcome ONLY through the DP's external surfaces: the RPC
// response, the SOCKS5 auth bytes on the proxy listener, dp-snapshot.json,
// and the captured journal.
//
// T093 (remediates: T020) reworked this suite off the retired
// grpcpb.TokenHash{hash,salt} onto grpcpb.TokenVerifier{verifier} + the
// HMAC mint helper (data-model.md §1.5, amended by T092 / sol-review
// B5+M1): single shared pepper, no per-token salt, schemaVersion 3
// verifier-only snapshot, and durable replay/conflict sub-test (row 6).
package controlgrpc

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	integration "github.com/zcat-app/stargate/tests/integration"
)

func TestReloadTokens(t *testing.T) {
	// Contract row 1: new generation applied atomically; subsequent
	// inbound proxy auth uses the new verifiers. Two pushes prove the
	// swap both ways — each generation's plaintext authenticates while
	// it is current and stops authenticating once replaced.
	t.Run("HappyPathAppliesNewGeneration", func(t *testing.T) {
		h := startDP(t)
		tokA := mintToken(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		tokB := mintToken(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")

		resp := h.reload(t, 1, []*grpcpb.TokenVerifier{tokA})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("generation 1 status = %v, want APPLY_STATUS_OK", resp.GetStatus())
		}
		if resp.GetAppliedGeneration() != 1 {
			t.Errorf("applied_generation = %d, want 1", resp.GetAppliedGeneration())
		}
		if resp.GetAcknowledgmentVersion() != 1 || string(resp.GetCommitment()) != string(authSetCommitment([]*grpcpb.TokenVerifier{tokA})) {
			t.Fatal("generation 1 lacked the exact durable auth-set-v1 acknowledgment")
		}

		// Persist-before-return: the snapshot must already hold the new
		// generation in the data-model.md §1.4 shape when the RPC returns.
		snap := h.readSnapshot(t)
		if snap.SchemaVersion != 3 || snap.AuthSetVersion != 1 {
			t.Errorf("snapshot versions = %d/%d, want 3/1", snap.SchemaVersion, snap.AuthSetVersion)
		}
		if snap.Generation != 1 {
			t.Errorf("snapshot generation = %d, want 1", snap.Generation)
		}
		if len(snap.Verifiers) != 1 {
			t.Fatalf("snapshot verifiers count = %d, want 1", len(snap.Verifiers))
		}
		// Persist-content fidelity: the on-disk verifier must be exactly
		// what was pushed — a DP persisting garbage while keeping the
		// right value in memory would otherwise pass here and only break
		// at cold-start restore (T020a). Messages carry no byte values
		// (index-only hygiene, same as assertNoSecretLeak).
		if !verifiersEqual(snap.Verifiers[0].Verifier, tokA.GetVerifier()) {
			t.Error("snapshot verifiers[0].verifier does not base64-match the pushed verifier (data-model.md §1.4; value redacted)")
		}

		h.requireAuth(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", true, "generation 1's plaintext must authenticate after APPLY_STATUS_OK")
		h.requireAuth(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", false, "a never-loaded plaintext must not authenticate")

		resp = h.reload(t, 2, []*grpcpb.TokenVerifier{tokB})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("generation 2 status = %v, want APPLY_STATUS_OK", resp.GetStatus())
		}
		if resp.GetAppliedGeneration() != 2 {
			t.Errorf("applied_generation = %d, want 2", resp.GetAppliedGeneration())
		}
		h.requireAuth(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", true, "the NEW generation's plaintext must authenticate after the swap")
		h.requireAuth(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", false, "the REPLACED generation's plaintext must stop authenticating")
		if got := h.readSnapshot(t).Generation; got != 2 {
			t.Errorf("snapshot generation after second push = %d, want 2", got)
		}

		assertNoSecretLeak(t, h, tokA.GetVerifier(), tokB.GetVerifier(),
			[]byte("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"), []byte("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"))
	})

	// Contract row 2: exact same-generation content is idempotent; equal
	// different content and lower generations are conflicts with no mutation.
	t.Run("ReplayAndStaleConflict", func(t *testing.T) {
		h := startDP(t)
		tokA := mintToken(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		tokB := mintToken(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")
		tokC := mintToken(t, "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2")

		h.reload(t, 1, []*grpcpb.TokenVerifier{tokA})
		resp := h.reload(t, 2, []*grpcpb.TokenVerifier{tokB})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("setup: generation 2 status = %v, want APPLY_STATUS_OK", resp.GetStatus())
		}
		before := h.snapshotBytes(t)
		replay := h.reload(t, 2, []*grpcpb.TokenVerifier{tokB})
		if replay.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK ||
			replay.GetAcknowledgmentVersion() != 1 ||
			string(replay.GetCommitment()) != string(authSetCommitment([]*grpcpb.TokenVerifier{tokB})) {
			t.Fatal("exact same-generation replay was not durably acknowledged")
		}

		for _, staleGen := range []uint64{2, 1} {
			resp := h.reload(t, staleGen, []*grpcpb.TokenVerifier{tokC})
			if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION {
				t.Errorf("generation %d (current 2) status = %v, want APPLY_STATUS_STALE_GENERATION", staleGen, resp.GetStatus())
			}
			// applied_generation reports the generation in effect — the
			// unchanged current one, not the rejected request's.
			if resp.GetAppliedGeneration() != 2 {
				t.Errorf("generation %d applied_generation = %d, want 2 (unchanged)", staleGen, resp.GetAppliedGeneration())
			}
			// current_generation is diagnostic only; it must never authorize
			// a retry that relabels the stale content.
			if resp.GetCurrentGeneration() != 2 {
				t.Errorf("generation %d current_generation = %d, want 2 (diagnostic echo)", staleGen, resp.GetCurrentGeneration())
			}
		}

		if after := h.snapshotBytes(t); string(after) != string(before) {
			t.Error("snapshot changed on a stale push — stale generations must leave persisted state untouched")
		}
		h.requireAuth(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", true, "the current generation's plaintext must survive stale pushes")
		h.requireAuth(t, "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2", false, "a stale push's tokens must never become live")

		assertNoSecretLeak(t, h, tokA.GetVerifier(), tokB.GetVerifier(), tokC.GetVerifier(),
			[]byte("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"), []byte("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"), []byte("c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"))
	})

	// Contract row 3: verifier must be exactly 32 bytes; any mismatch →
	// APPLY_STATUS_INVALID with no generation change. T092 dropped the
	// per-token salt (single shared pepper → no salt-length rows); only
	// the verifier-length cases remain. The generation number is not
	// consumed by a rejected push.
	t.Run("InvalidVerifierLengthRejected", func(t *testing.T) {
		h := startDP(t)
		tokA := mintToken(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		h.reload(t, 1, []*grpcpb.TokenVerifier{tokA})
		before := h.snapshotBytes(t)

		cases := []struct {
			name  string
			token *grpcpb.TokenVerifier
		}{
			{"verifier 31B", &grpcpb.TokenVerifier{Verifier: randomBytes(t, 31)}},
			{"verifier 33B", &grpcpb.TokenVerifier{Verifier: randomBytes(t, 33)}},
		}
		malformed := make([][]byte, 0, len(cases))
		for _, c := range cases {
			resp := h.reload(t, 2, []*grpcpb.TokenVerifier{c.token})
			if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_INVALID {
				t.Errorf("%s: status = %v, want APPLY_STATUS_INVALID", c.name, resp.GetStatus())
			}
			if resp.GetAppliedGeneration() != 1 {
				t.Errorf("%s: applied_generation = %d, want 1 (unchanged)", c.name, resp.GetAppliedGeneration())
			}
			malformed = append(malformed, c.token.GetVerifier())
		}

		if after := h.snapshotBytes(t); string(after) != string(before) {
			t.Error("snapshot changed on an invalid push — malformed verifiers must leave persisted state untouched")
		}
		h.requireAuth(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", true, "the current generation must survive invalid pushes")

		// The rejected generation number was not consumed: a valid push
		// with the same number now succeeds.
		tokB := mintToken(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")
		if resp := h.reload(t, 2, []*grpcpb.TokenVerifier{tokB}); resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Errorf("valid generation 2 after invalid attempts: status = %v, want APPLY_STATUS_OK", resp.GetStatus())
		}

		// Contract's no-logging bullet applies to REJECTED bytes too —
		// "token format violations never log the offending bytes"
		// (data-model.md §1.6).
		assertNoSecretLeak(t, h, append(malformed,
			tokA.GetVerifier(), tokB.GetVerifier(),
			[]byte("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"), []byte("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"))...)
	})

	t.Run("SerializedOldControlPlaneToNewDataPlaneFailsClosed", func(t *testing.T) {
		h := startDP(t)
		tok := mintToken(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		resp, err := h.reloadLegacyErr(1, []*grpcpb.TokenVerifier{tok})
		if resp != nil || status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("legacy serialized request = %v / %v, want nil / FailedPrecondition",
				resp, status.Code(err))
		}
		if snapshot := h.snapshotBytes(t); snapshot != nil {
			t.Fatal("legacy request created authority state on the new DP")
		}
		h.requireAuth(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", false,
			"a missing durable envelope must never authorize its legacy verifier")
	})

	// Contract row 4: a real filesystem failure returns non-success and
	// leaves the previous in-memory authority live. The final-path directory
	// obstruction works for uid 0 as well as unprivileged test runners.
	t.Run("SnapshotPersistFailureIsPending", func(t *testing.T) {
		h := startDP(t)
		tokA := mintToken(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		tokB := mintToken(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")
		h.reload(t, 1, []*grpcpb.TokenVerifier{tokA})

		previous := h.snapshotBytes(t)
		path := h.snapshotPath()
		backup := filepath.Join(h.stateDir, "acknowledged.snapshot")
		if err := os.Rename(path, backup); err != nil {
			t.Fatalf("preserve acknowledged snapshot: %v", err)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatalf("obstruct snapshot final path: %v", err)
		}
		restored := false
		t.Cleanup(func() {
			if !restored {
				_ = os.Remove(path)
				_ = os.Rename(backup, path)
			}
		})

		resp, err := h.reloadErr(2, []*grpcpb.TokenVerifier{tokB})
		if status.Code(err) != codes.Unavailable || resp != nil {
			t.Fatalf("persist failure = response %v / code %v, want nil / Unavailable", resp, status.Code(err))
		}
		h.requireAuth(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", true, "previous acknowledged authority must remain live after failed persistence")
		h.requireAuth(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", false, "unacknowledged candidate must not become live")

		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(backup, path); err != nil {
			t.Fatal(err)
		}
		restored = true
		if got := h.snapshotBytes(t); string(got) != string(previous) {
			t.Error("restored acknowledged snapshot bytes changed during failed delivery")
		}

		assertNoSecretLeak(t, h, tokA.GetVerifier(), tokB.GetVerifier(),
			[]byte("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"), []byte("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"))
	})

	t.Run("AcknowledgedRevocationSurvivesSIGKILLRestart", func(t *testing.T) {
		h := startDP(t)
		tokA := mintToken(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		h.reload(t, 1, []*grpcpb.TokenVerifier{tokA})
		revoked := h.reload(t, 2, nil)
		if revoked.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK || revoked.GetAcknowledgmentVersion() != 1 {
			t.Fatal("revoke-all was not durably acknowledged")
		}
		h.killAndWait(t)
		restarted := startDPWithState(t, h.stateDir)
		restarted.requireAuth(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", false,
			"acknowledged revocation must survive process crash and CP-down restart")
		replay := restarted.reload(t, 2, nil)
		if replay.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK || replay.GetAcknowledgmentVersion() != 1 {
			t.Fatal("restarted revoke-all authority was not idempotently acknowledged")
		}
	})

	t.Run("EstablishedPipeSurvivesRevocation", func(t *testing.T) {
		requireForwardPath(t)
		upstream := integration.NewServer(integration.AcceptAndRelay)
		upstreamAddr, err := upstream.Start()
		if err != nil {
			t.Fatalf("starting fake upstream: %v", err)
		}
		t.Cleanup(func() { _ = upstream.Close() })

		h := startDPWithUpstream(t, upstreamAddr, nil)
		tokA := mintToken(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		tokB := mintToken(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")
		h.reload(t, 1, []*grpcpb.TokenVerifier{tokA})

		pipe := t020aDialAuthenticatedConnect(t, h, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		defer pipe.Close()
		reply := make([]byte, 10)
		if _, err := io.ReadFull(pipe, reply); err != nil || reply[1] != 0x00 {
			t.Fatalf("establish relay pipe: reply=% x err=%v", reply, err)
		}

		h.reload(t, 2, []*grpcpb.TokenVerifier{tokB})
		payload := []byte("t159-established-pipe")
		if _, err := pipe.Write(payload); err != nil {
			t.Fatalf("write established pipe after reload: %v", err)
		}
		echo := make([]byte, len(payload))
		if _, err := io.ReadFull(pipe, echo); err != nil || string(echo) != string(payload) {
			t.Fatalf("established pipe did not survive reload: err=%v", err)
		}
		h.requireAuth(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", false,
			"revoked credential must fail new admission while its established pipe survives")
		h.requireAuth(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", true,
			"replacement credential must authorize new admission")
	})

	// Contract row 5: generations N and N+1 pushed in parallel converge
	// on N+1; the older one is stale on retry. The contract requires
	// convergence, not a particular interleaving — the gen-2 push MUST
	// apply; the gen-1 push is OK (applied then replaced) or STALE
	// (lost the race), both within contract.
	t.Run("ConcurrentReloadsConverge", func(t *testing.T) {
		h := startDP(t)
		tok1 := mintToken(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		tok2 := mintToken(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")

		var wg sync.WaitGroup
		var resp1, resp2 *grpcpb.ReloadTokensResponse
		var err1, err2 error
		wg.Add(2)
		go func() { defer wg.Done(); resp1, err1 = h.reloadErr(1, []*grpcpb.TokenVerifier{tok1}) }()
		go func() { defer wg.Done(); resp2, err2 = h.reloadErr(2, []*grpcpb.TokenVerifier{tok2}) }()
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

		retry := h.reload(t, 1, []*grpcpb.TokenVerifier{mintToken(t, "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2")})
		if retry.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION {
			t.Errorf("generation 1 retry status = %v, want APPLY_STATUS_STALE_GENERATION", retry.GetStatus())
		}
		if retry.GetAppliedGeneration() != 2 {
			t.Errorf("converged applied_generation = %d, want 2", retry.GetAppliedGeneration())
		}
		h.requireAuth(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", true, "the higher generation's plaintext must be live after convergence")
		h.requireAuth(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", false, "the lower generation's plaintext must not be live after convergence")
		if got := h.readSnapshot(t).Generation; got != 2 {
			t.Errorf("snapshot generation after convergence = %d, want 2", got)
		}

		assertNoSecretLeak(t, h, tok1.GetVerifier(), tok2.GetVerifier(),
			[]byte("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"), []byte("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"), []byte("c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2"))
	})

	// Contract row 6: restoring stale CP content cannot ratchet it past a
	// later acknowledged revocation. Only exact current content replays.
	t.Run("RestoredStaleAuthorityCannotRenumber", func(t *testing.T) {
		h := startDP(t)
		tokA := mintToken(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0")
		tokB := mintToken(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")

		// The DP is at generation 2 (e.g. it accepted pushes from a
		// prior CP session before the restart the handshake simulates).
		h.reload(t, 1, []*grpcpb.TokenVerifier{tokA})
		h.reload(t, 2, []*grpcpb.TokenVerifier{tokB})

		// A restored CP proposes old content at both its original generation
		// and the DP's current generation. Neither may be relabelled.
		lower := h.reload(t, 1, []*grpcpb.TokenVerifier{tokA})
		if lower.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION {
			t.Fatalf("lower stale proposal status = %v, want STALE", lower.GetStatus())
		}
		staleResp := h.reload(t, 2, []*grpcpb.TokenVerifier{tokA})
		if staleResp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION {
			t.Fatalf("stale proposal (gen 2, current 2) status = %v, want APPLY_STATUS_STALE_GENERATION", staleResp.GetStatus())
		}
		if staleResp.GetAcknowledgmentVersion() != 0 {
			t.Fatal("conflicting stale content carried a durable acknowledgment marker")
		}
		replay := h.reload(t, 2, []*grpcpb.TokenVerifier{tokB})
		if replay.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK || replay.GetAcknowledgmentVersion() != 1 {
			t.Fatal("exact current authority did not replay idempotently")
		}

		// The converged generation's token list is live; the stale
		// proposal's tokens never became live.
		h.requireAuth(t, "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1", true, "the reconciled generation's plaintext must be live")
		h.requireAuth(t, "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", false, "the stale proposal's plaintext must not be live")
		if got := h.readSnapshot(t).Generation; got != 2 {
			t.Errorf("snapshot generation after stale restore attempts = %d, want 2", got)
		}

		assertNoSecretLeak(t, h, tokA.GetVerifier(), tokB.GetVerifier(),
			[]byte("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"), []byte("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"))
	})
}
