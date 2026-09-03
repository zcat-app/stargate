// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Contract test for cold-start snapshot restore — the Principle II
// survival property (FR-013 last-known-token-list invariant; arch §5.5
// "control plane down at startup").
//
// Every sub-test pre-populates dp-snapshot.json in the harness state dir
// BEFORE the data plane boots, boots with NO control plane reachable (no
// control.sock is ever hosted in the IPC dir — the DP's WatchEvents dials
// fail and back off), and observes the DP EXTERNALLY only: SOCKS5
// auth/reply bytes on port 8881, ReloadTokens on dp.sock,
// dp-snapshot.json bytes, and the captured journal.
//
// The seeded snapshot is the schemaVersion 2 verifiers-only shape
// (data-model.md §1.4, amended by T092 — superseding this ticket's
// pre-T092 "{hash, salt}" wording) carrying the base64 HMAC-SHA-256 tag
// of a known plaintext minted under the harness pepper (§1.5). The
// sub-test for the T092 amendment seeds the retired v1 shape and asserts
// it is ignored, never misparsed.
//
// Sub-tests (ticket §Acceptance):
//   - RestoresSnapshotWithCPUnreachable            (a) + stale-generation probe
//   - Port8881ServesDuringWatchEventsBackoff       (b)
//   - NewGenerationReplacesColdStartSnapshot       (c)
//   - ForwardsWithoutHealthyEvent                  (d) reachable upstream [T047 gate]
//   - RouteDownByteExactWhenUpstreamUnreachable    (d) unreachable upstream [T047 gate]
//   - StaleV1SnapshotIgnoredServesNoTokens         (T092 amendment)
//
// "The CP comes up" in (c) is modelled as the production ReloadTokens
// push over dp.sock — the only CP→DP generation-delivery path in v1 —
// exactly as T020's suite plays the CP role. No fake control plane is
// hosted anywhere in this suite: the DP is under test precisely in its
// control-plane-unreachable mode.
package controlgrpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	integration "github.com/zcat-app/stargate/tests/integration"
)

// t020a fixtures. The plaintexts are 32-char lowercase hex (FR-017): the
// auth path's format gate rejects anything else, so a non-hex "known
// plaintext" would fail auth for the wrong reason. Both values are the
// data-model.md §1.1 example tokens — test fixtures, not secrets.
const (
	t020aPlaintextP1 = "9f2c3a14b8d7e60f5a3c2e1d0b9c8a7f"
	t020aPlaintextP2 = "1a2b3c4d5e6f70819a8b7c6d5e4f3a2b"
	t020aSnapshotGen = uint64(7)
)

// seedV2Snapshot writes a schemaVersion 2 dp-snapshot.json (data-model.md
// §1.4) carrying the single verifier minted under the harness pepper for
// plaintext, at the given generation — the exact shape T046's writer
// persists and T046's RestoreSnapshot consumes at cold start.
func seedV2Snapshot(t *testing.T, stateDir string, generation uint64, plaintext string) {
	t.Helper()
	doc := map[string]any{
		"schemaVersion": 2,
		"generation":    generation,
		"loadedAt":      "2026-05-17T14:00:00Z",
		"verifiers": []map[string]string{
			{"verifier": base64.StdEncoding.EncodeToString(mintToken(t, plaintext).GetVerifier())},
		},
	}
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling v2 snapshot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "dp-snapshot.json"), blob, 0o600); err != nil {
		t.Fatalf("writing seeded v2 snapshot: %v", err)
	}
}

// seedV1Snapshot writes the retired schemaVersion 1 {hash, salt} shape
// with a plausible hash value (the plaintext's verifier under the harness
// pepper — bytes a misparsing DP could resurface as a working verifier)
// and a generation HIGHER than the fresh push later in the sub-test, so a
// wrongly-accepted v1 file fails the sub-test twice over: once by
// authenticating the plaintext, once by staling the fresh push
// (data-model.md §1.4 T092 note: ignore, never misparse).
func seedV1Snapshot(t *testing.T, stateDir string, plaintext string) {
	t.Helper()
	doc := map[string]any{
		"schemaVersion": 1,
		"generation":    3,
		"loadedAt":      "2026-05-17T14:00:00Z",
		"hashes": []map[string]string{
			{
				"hash": base64.StdEncoding.EncodeToString(mintToken(t, plaintext).GetVerifier()),
				"salt": base64.StdEncoding.EncodeToString([]byte("t020a-v1-salt-padding")),
			},
		},
	}
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshalling v1 snapshot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "dp-snapshot.json"), blob, 0o600); err != nil {
		t.Fatalf("writing seeded v1 snapshot: %v", err)
	}
}

// seedInterPlaneKeys writes a fresh ed25519 keypair as the DP's wire-auth
// material — dp.priv as PKCS#8 PEM, cp.pub as PKIX PEM, the exact paths
// controlclient.DeriveDPTLS reads (wire-auth.md §2/§3). With the material
// present, the booted DP's WatchEvents client actually runs and retries;
// without it the boot degrades before the client starts and sub-test (b)
// would pass vacuously. The pin is never exercised here — no CP is ever
// hosted, so no handshake ever completes.
func seedInterPlaneKeys(t *testing.T, keysDir string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 keypair: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalling dp.priv: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshalling cp.pub: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	if err := os.WriteFile(filepath.Join(keysDir, "dp.priv"), privPEM, 0o600); err != nil {
		t.Fatalf("writing dp.priv: %v", err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "cp.pub"), pubPEM, 0o600); err != nil {
		t.Fatalf("writing cp.pub: %v", err)
	}
}

// t020aDialAuthenticatedConnect drives method negotiation + RFC 1929
// username/password auth + the RFC 1928 §4 CONNECT request against the
// harness's proxy listener and returns the open connection positioned
// immediately after the request write — the caller reads the 10-byte
// request-phase reply. Fatals on any auth-phase contract breach (those
// are not what this suite asserts) and never interpolates the plaintext
// into failure text — it is the one secret in scope, and failure output
// lands in CI logs (index-only hygiene, same discipline as
// assertNoSecretLeak).
func t020aDialAuthenticatedConnect(t *testing.T, h *dpHarness, plaintext string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy %s: %v", h.proxyAddr, err)
	}
	// 30 s covers HMAC auth + the worst-case forward dial
	// (contracts/socks5-auth.md §"Deadlines"); the ROUTE_DOWN sub-test
	// tightens the deadline before its post-reply EOF read.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	methods := make([]byte, 2)
	if _, err := io.ReadFull(conn, methods); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if methods[0] != 0x05 || methods[1] != 0x02 {
		t.Fatalf("method selection = %#02x %#02x, want 0x05 0x02 (socks5-auth.md §\"Auth method negotiation\")", methods[0], methods[1])
	}

	user := []byte("t020a")
	req := append([]byte{0x01, byte(len(user))}, user...)
	req = append(req, byte(len(plaintext)))
	req = append(req, plaintext...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write userpass sub-negotiation: %v", err)
	}
	authRep := make([]byte, 2)
	if _, err := io.ReadFull(conn, authRep); err != nil {
		t.Fatalf("read userpass reply: %v", err)
	}
	if authRep[0] != 0x01 || authRep[1] != 0x00 {
		t.Fatalf("auth failed: userpass reply = %#02x %#02x — the offered plaintext is not in the DP's current generation", authRep[0], authRep[1])
	}

	// CONNECT to 198.51.100.1:443 (TEST-NET-2, unroutable) — a valid IPv4
	// ATYP request shape; the destination itself is irrelevant to the
	// reply assertions (same target as the T021 route probes).
	connectReq := []byte{0x05, 0x01, 0x00, 0x01, 0xc6, 0x33, 0x64, 0x01, 0x01, 0xbb}
	if _, err := conn.Write(connectReq); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	return conn
}

// t020aWaitRestored polls for T046's implemented restore journal line.
// The boot sequence (T050) invokes RestoreSnapshot before the listener
// opens, but the probe polls rather than assuming the ordering.
func t020aWaitRestored(t *testing.T, h *dpHarness) {
	t.Helper()
	waitFor(t, "journal to record the snapshot restore", 20*time.Second, h.journal, func() bool {
		return h.journalContains("snapshot restored")
	})
}

func TestColdStartSnapshotRestore(t *testing.T) {
	// Ticket assertion (a): with no CP reachable, the DP authenticates
	// from the snapshot-restored generation (FR-013; arch §5.5;
	// Principle II). The stale-generation probe proves the restored
	// generation NUMBER is live, not just the verifier set.
	t.Run("RestoresSnapshotWithCPUnreachable", func(t *testing.T) {
		h := startDPWithSeed(t, "", nil, func(stateDir, _ string) {
			seedV2Snapshot(t, stateDir, t020aSnapshotGen, t020aPlaintextP1)
		})
		t020aWaitRestored(t, h)

		h.requireAuth(t, t020aPlaintextP1, true, "the snapshot-restored generation must authenticate with the CP unreachable (FR-013; arch §5.5; Principle II)")
		h.requireAuth(t, t020aPlaintextP2, false, "a plaintext absent from the snapshot must not authenticate")

		// A CP proposal at the snapshot's generation is stale, and the
		// response echoes the DP's current generation for reconciliation
		// (data-model.md §1.3; T092). A DP that booted on an empty store
		// would report current 0 and APPLY this push instead.
		resp := h.reload(t, t020aSnapshotGen, []*grpcpb.TokenVerifier{mintToken(t, t020aPlaintextP2)})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION {
			t.Fatalf("push at the snapshot's generation status = %v, want APPLY_STATUS_STALE_GENERATION (the restored generation must be the live one)", resp.GetStatus())
		}
		if resp.GetCurrentGeneration() != t020aSnapshotGen {
			t.Errorf("current_generation = %d, want %d — the snapshot's generation must be restored, not the empty store", resp.GetCurrentGeneration(), t020aSnapshotGen)
		}
		h.requireAuth(t, t020aPlaintextP2, false, "a stale push's tokens must never become live")

		assertNoSecretLeak(t, h, mintToken(t, t020aPlaintextP1).GetVerifier(), mintToken(t, t020aPlaintextP2).GetVerifier(),
			[]byte(t020aPlaintextP1), []byte(t020aPlaintextP2))
	})

	// Ticket assertion (b): the WatchEvents dial fails (no control.sock)
	// and the DP retries on the §"WatchEvents" backoff WITHOUT blocking
	// port 8881 — serving continues across ≥2 initial backoff steps
	// (Principle II). The backoff schedule's arithmetic is pinned by the
	// controlclient unit tests (injected rng) and T021 row 3's live
	// reconnect; this sub-test pins the cold-start survival property.
	t.Run("Port8881ServesDuringWatchEventsBackoff", func(t *testing.T) {
		h := startDPWithSeed(t, "", nil, func(stateDir, keysDir string) {
			seedV2Snapshot(t, stateDir, t020aSnapshotGen, t020aPlaintextP1)
			seedInterPlaneKeys(t, keysDir)
		})

		// The degraded-mode warning is client.go's warn-once transition on
		// the first failed dial; its appearance proves the client is up,
		// so the serving probes below coexist with a live retry loop
		// rather than passing vacuously.
		waitFor(t, "the WatchEvents client to enter degraded mode", 20*time.Second, h.journal, func() bool {
			return h.journalContains("control channel degraded")
		})

		deadline := time.Now().Add(2500 * time.Millisecond)
		probes := 0
		for time.Now().Before(deadline) {
			if !h.socks5AuthOK(t, t020aPlaintextP1) {
				t.Fatalf("auth probe #%d failed during the WatchEvents backoff wait — port 8881 stopped serving while the CP is unreachable (Principle II)", probes+1)
			}
			probes++
			time.Sleep(250 * time.Millisecond)
		}
		t.Logf("port 8881 served %d auth probes across the backoff window", probes)

		assertNoSecretLeak(t, h, mintToken(t, t020aPlaintextP1).GetVerifier(), []byte(t020aPlaintextP1))
	})

	// Ticket assertion (c): once the CP pushes a fresh generation, the DP
	// atomic-swaps and the snapshot's plaintext is no longer honoured —
	// the snapshot is a cold-start cache, not a persistent fallback layer
	// beyond the current generation (data-model.md §1.3).
	t.Run("NewGenerationReplacesColdStartSnapshot", func(t *testing.T) {
		h := startDPWithSeed(t, "", nil, func(stateDir, _ string) {
			seedV2Snapshot(t, stateDir, t020aSnapshotGen, t020aPlaintextP1)
		})
		t020aWaitRestored(t, h)

		// "The CP comes up": in v1 the CP's only generation-delivery path
		// is the ReloadTokens push over dp.sock — the harness plays the
		// CP role exactly as T020's suite does. The DP remains in its
		// control-plane-unreachable mode throughout; that must not matter.
		tokP2 := mintToken(t, t020aPlaintextP2)
		resp := h.reload(t, t020aSnapshotGen+1, []*grpcpb.TokenVerifier{tokP2})
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("fresh generation %d status = %v, want APPLY_STATUS_OK", t020aSnapshotGen+1, resp.GetStatus())
		}

		h.requireAuth(t, t020aPlaintextP2, true, "the newly pushed generation must authenticate after the atomic swap")
		h.requireAuth(t, t020aPlaintextP1, false, "the cold-start snapshot's plaintext must stop authenticating once a fresh generation lands")

		// Persist-before-OK (contract row 4): the snapshot file was
		// rewritten to the new generation, still the v2 verifier shape.
		snap := h.readSnapshot(t)
		if snap.SchemaVersion != 2 {
			t.Errorf("rewritten snapshot schemaVersion = %d, want 2", snap.SchemaVersion)
		}
		if snap.Generation != t020aSnapshotGen+1 {
			t.Errorf("rewritten snapshot generation = %d, want %d", snap.Generation, t020aSnapshotGen+1)
		}
		if len(snap.Verifiers) != 1 || !verifiersEqual(snap.Verifiers[0].Verifier, tokP2.GetVerifier()) {
			t.Error("rewritten snapshot verifiers do not match the pushed generation (data-model.md §1.4 fidelity; value redacted)")
		}

		assertNoSecretLeak(t, h, tokP2.GetVerifier(), mintToken(t, t020aPlaintextP1).GetVerifier(),
			[]byte(t020aPlaintextP1), []byte(t020aPlaintextP2))
	})

	// Ticket assertion (d), reachable-upstream half: with NO SidecarEvent
	// of any kind ever arriving (no CP has ever been reachable), the
	// request phase forwards through the reachable upstream — the bridge
	// engages; admission is not CP-gated (data-model.md §2; FR-009;
	// Principle II; sol-review B3).
	t.Run("ForwardsWithoutHealthyEvent", func(t *testing.T) {
		requireForwardPath(t)

		upstream := integration.NewServer(integration.AcceptAndRelay)
		upstreamAddr, err := upstream.Start()
		if err != nil {
			t.Fatalf("starting fake upstream: %v", err)
		}
		t.Cleanup(func() { _ = upstream.Close() })

		h := startDPWithSeed(t, upstreamAddr, nil, func(stateDir, _ string) {
			seedV2Snapshot(t, stateDir, t020aSnapshotGen, t020aPlaintextP1)
		})

		conn := t020aDialAuthenticatedConnect(t, h, t020aPlaintextP1)
		defer conn.Close()
		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatalf("read CONNECT reply: %v", err)
		}
		if rep[1] != 0x00 {
			t.Fatalf("forward reply REP = %#02x, want 0x00 — the upstream is reachable, so a route failure here means a CP-coupled admission gate suppressed the dial (reply=% x)", rep[1], rep)
		}

		// The bridge is a transparent byte pipe (Principle I): a payload
		// must round-trip through the DP and the fake upstream's echo
		// relay.
		payload := []byte("stargate-t020a-echo-roundtrip")
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write payload through the bridge: %v", err)
		}
		echo := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, echo); err != nil {
			t.Fatalf("read echoed payload: %v", err)
		}
		if string(echo) != string(payload) {
			t.Error("echo round-trip mismatch — the bridge did not relay bytes transparently")
		}

		assertNoSecretLeak(t, h, mintToken(t, t020aPlaintextP1).GetVerifier(), []byte(t020aPlaintextP1))
	})

	// Ticket assertion (d), unreachable-upstream half: the upstream dial
	// alone decides the route error — byte-exact ROUTE_DOWN
	// (socks5-auth.md §"SOCKS5 request-phase failures (post-auth)"),
	// then close, with no leaked reason text. No upstream override means
	// the DP dials its production default (tor:9050), unreachable in the
	// hermetic environment; per data-model.md §2 / T090 the ROUTE_DOWN
	// can only come from that failed dial, never from an admission gate.
	t.Run("RouteDownByteExactWhenUpstreamUnreachable", func(t *testing.T) {
		requireForwardPath(t)

		h := startDPWithSeed(t, "", nil, func(stateDir, _ string) {
			seedV2Snapshot(t, stateDir, t020aSnapshotGen, t020aPlaintextP1)
		})

		conn := t020aDialAuthenticatedConnect(t, h, t020aPlaintextP1)
		defer conn.Close()
		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatalf("read CONNECT reply: %v", err)
		}
		want := []byte{0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		if string(rep) != string(want) {
			t.Fatalf("reply = % x, want % x (byte-exact ROUTE_DOWN: REP 0x03, zeroed BND.ADDR/BND.PORT)", rep, want)
		}

		// After the 10-byte reply the DP MUST close: zero further bytes,
		// clean EOF — no reason text, no error-template bytes on the
		// SOCKS5 path (the byte-exact match above already excludes any
		// template content; this bounds the tail).
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var tail [64]byte
		n, err := conn.Read(tail[:])
		if n != 0 || (err != nil && !errors.Is(err, io.EOF)) {
			t.Fatalf("after the ROUTE_DOWN reply: read n=%d err=%v — want a clean close (0, EOF); the DP must write nothing further", n, err)
		}

		assertNoSecretLeak(t, h, mintToken(t, t020aPlaintextP1).GetVerifier(), []byte(t020aPlaintextP1))
	})

	// T092 amendment sub-test: a stale schemaVersion 1 snapshot is
	// IGNORED (warning journaled, no tokens served) rather than misparsed
	// — parsing v1 {hash, salt} pairs as v2 verifiers would authenticate
	// nothing and silently break routing (data-model.md §1.4). The
	// Principle II property itself is unchanged: the DP keeps serving
	// port 8881 the whole time.
	t.Run("StaleV1SnapshotIgnoredServesNoTokens", func(t *testing.T) {
		h := startDPWithSeed(t, "", nil, func(stateDir, _ string) {
			seedV1Snapshot(t, stateDir, t020aPlaintextP1)
		})

		waitFor(t, "journal to record the v1 snapshot ignore", 20*time.Second, h.journal, func() bool {
			return h.journalContains("snapshot restore ignored")
		})

		// Serve NO tokens: not even the plaintext whose verifier the v1
		// file plausibly carries (a misparse would resurface it — the
		// seeded hash is the real verifier bytes), and no other either
		// (the store stays at the empty/revoke-all generation).
		h.requireAuth(t, t020aPlaintextP1, false, "a stale v1 snapshot must serve no tokens — ignored, not misparsed (data-model.md §1.4, T092)")
		h.requireAuth(t, t020aPlaintextP2, false, "no plaintext may authenticate from an ignored snapshot")

		// …until the CP pushes a fresh generation (the amendment's
		// serve-no-tokens-UNTIL clause): the store is fully functional. A
		// wrongly-accepted v1 file would stale this push (its generation
		// is 3), so OK here double-checks the ignore.
		tokP2 := mintToken(t, t020aPlaintextP2)
		if resp := h.reload(t, 1, []*grpcpb.TokenVerifier{tokP2}); resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
			t.Fatalf("fresh generation after the ignored v1 snapshot status = %v, want APPLY_STATUS_OK", resp.GetStatus())
		}
		h.requireAuth(t, t020aPlaintextP2, true, "the DP must serve tokens again once the CP pushes a fresh generation")
		h.requireAuth(t, t020aPlaintextP1, false, "the ignored v1 file's plaintext must stay dead")

		assertNoSecretLeak(t, h, tokP2.GetVerifier(), mintToken(t, t020aPlaintextP1).GetVerifier(),
			[]byte(t020aPlaintextP1), []byte(t020aPlaintextP2))
	})
}
