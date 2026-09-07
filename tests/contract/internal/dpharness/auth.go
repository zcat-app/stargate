// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Auth helpers shared across contract tests that exercise the data
// plane's bearer-token path: HMAC-SHA-256 verifier minting under the
// install-time pepper (data-model.md §1.5, amended by T092 / sol-review
// B5+M1) and a ReloadTokens gRPC client wrapper.
//
// The verifier is HMAC-SHA-256(pepper, token) under a single shared
// pepper — NO per-token salt. A candidate's tag is computed once per
// request and compared against every stored verifier (constant-time;
// data-model.md §1.5). This retired the prior argon2id + per-token-salt
// shape that T020/leak_test.go were authored against; T093 migrated
// every caller off the retired grpcpb.TokenHash onto grpcpb.TokenVerifier.
//
// TestPepper is the fixed HMAC key the harness writes to
// $STARGATE_KEYS_DIR/pepper.key (data-model.md §1.7 — "alongside the
// inter-plane ed25519 keypairs") and mints verifiers under. It is a
// TEST constant (the production pepper is openssl-rand-generated at
// install time); its fixed value lets the mint helper and the DP agree
// without a shared runtime channel. The data-plane impl (T044) reads
// it from the keys dir at boot; the test-defined PepperFile path is the
// contract surface T044/T088 conform to (tests-first, Constitution
// Principle VII).
package dpharness

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"crypto/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"github.com/zcat-app/stargate/tests/contract/internal/fakecp"
)

// PepperLen is the install-time pepper length in bytes (data-model.md
// §1.5: 32). Shared by both planes; the DP receives ready-made
// verifiers and never needs this from the RPC, but the harness writes
// exactly this many bytes to the pepper file.
const PepperLen = 32

// PepperFile is the test-defined pepper location relative to
// STARGATE_KEYS_DIR (data-model.md §1.7). T044/T088 conform to this
// path; the harness writes TestPepper here at boot.
const PepperFile = "pepper.key"

// TestPepper is the fixed 32-byte HMAC key the contract-test harness
// uses to mint verifiers AND writes to the keys dir so the DP's
// candidate-side HMAC (T044) agrees. A fixed test value (not
// crypto-random) is deliberate: a deterministic key lets mint + verify
// agree without a runtime handshake, and the pepper is never a real
// secret in the test environment (no production tokens exist). The
// recognizable pattern is a leak-scan aid, not a security boundary.
var TestPepper = [PepperLen]byte{
	0x53, 0x54, 0x47, 0x54, 0x54, 0x45, 0x53, 0x54, // "STGTTTEST"
	0x2d, 0x50, 0x45, 0x50, 0x50, 0x45, 0x52, 0x2d, // "-PEPPER-"
	0x46, 0x49, 0x58, 0x45, 0x44, 0x2d, 0x4b, 0x45, // "FIXED-KE"
	0x59, 0x2d, 0x33, 0x32, 0x42, 0x2d, 0x2d, 0x2d, // "Y-32B---"
}

// WritePepper writes TestPepper to keysDir/pepper.key so the booted DP
// and the MintToken helper agree on the HMAC key. Called from the
// harness boot path (dpharness.Start). Idempotent.
func WritePepper(t *testing.T, keysDir string) {
	t.Helper()
	path := filepath.Join(keysDir, PepperFile)
	if err := os.WriteFile(path, TestPepper[:], 0o600); err != nil {
		t.Fatalf("writing test pepper to %s: %v", path, err)
	}
}

// SeedInterPlaneKeys writes a fresh, internally-coherent ed25519
// keypair set in the stargate-keys layout (wire-auth.md §6.1) so the
// booted DP and the TLS fake CP cross-authenticate (§3): the DP derives
// its cert from dp.priv and pins cp.pub; the fake CP derives its cert
// from cp.priv and byte-pins dp.pub. PEM encodings match
// controlclient.LoadPrivateKey/LoadPeerPublicKey (PKCS#8 private,
// PKIX public). Modes mirror the production ownership intent (0600
// private, 0644 public); the local-process tier's UIDs are the test
// runner's own, so the §6.1 numeric ownership table does not apply
// here.
//
// Called from the WithControlPlane boot path; also usable directly by
// in-package harnesses (tests/contract/control-grpc) that boot the DP
// with their own fixture functions. Re-seeding OVERWRITES prior keys —
// each boot gets one coherent set.
func SeedInterPlaneKeys(t *testing.T, keysDir string) {
	t.Helper()
	dpPub, dpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating dp ed25519 keypair: %v", err)
	}
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating cp ed25519 keypair: %v", err)
	}
	writeKey := func(name string, block *pem.Block, mode os.FileMode) {
		t.Helper()
		path := filepath.Join(keysDir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(block), mode); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}
	dpPKCS8, err := x509.MarshalPKCS8PrivateKey(dpPriv)
	if err != nil {
		t.Fatalf("marshalling dp.priv: %v", err)
	}
	cpPKCS8, err := x509.MarshalPKCS8PrivateKey(cpPriv)
	if err != nil {
		t.Fatalf("marshalling cp.priv: %v", err)
	}
	dpSPKI, err := x509.MarshalPKIXPublicKey(dpPub)
	if err != nil {
		t.Fatalf("marshalling dp.pub: %v", err)
	}
	cpSPKI, err := x509.MarshalPKIXPublicKey(cpPub)
	if err != nil {
		t.Fatalf("marshalling cp.pub: %v", err)
	}
	writeKey("dp.priv", &pem.Block{Type: "PRIVATE KEY", Bytes: dpPKCS8}, 0o600)
	writeKey("cp.priv", &pem.Block{Type: "PRIVATE KEY", Bytes: cpPKCS8}, 0o600)
	writeKey("dp.pub", &pem.Block{Type: "PUBLIC KEY", Bytes: dpSPKI}, 0o644)
	writeKey("cp.pub", &pem.Block{Type: "PUBLIC KEY", Bytes: cpSPKI}, 0o644)
}

// MintToken HMAC-SHA-256-tags a known plaintext under TestPepper,
// yielding the 32-byte verifier wire shape the control plane would push
// (data-model.md §1.2/§1.5: HMAC-SHA-256 under the install-time pepper;
// no per-token salt — a single shared pepper makes the candidate's tag
// independent of which slot it is compared against).
//
// Tests that need a DETERMINISTIC verifier (e.g. snapshot-restore
// cold-start tests that pre-write dp-snapshot.json with a known
// verifier) should construct the *grpcpb.TokenVerifier literal directly
// rather than call this helper.
func MintToken(t *testing.T, plaintext string) *grpcpb.TokenVerifier {
	t.Helper()
	mac := hmac.New(sha256.New, TestPepper[:])
	mac.Write([]byte(plaintext))
	return &grpcpb.TokenVerifier{Verifier: mac.Sum(nil)}
}

// Reload pushes a fresh token generation to the data plane via the
// ReloadTokens RPC (hosted on dp.sock per T045). Returns the apply
// response so the caller can assert APPLY_STATUS_OK or
// APPLY_STATUS_STALE_GENERATION as their contract demands. Fatal on
// transport error — a non-fatal wrapper (ReloadErr) is provided for
// tests that need to probe the RPC under contention (T020's
// concurrency case).
func Reload(t *testing.T, h *Harness, generation uint64, tokens []*grpcpb.TokenVerifier) *grpcpb.ReloadTokensResponse {
	t.Helper()
	resp, err := ReloadErr(h, generation, tokens)
	if err != nil {
		t.Fatalf("ReloadTokens(generation=%d) transport error: %v", generation, err)
	}
	return resp
}

// ReloadErr is the goroutine-safe RPC wrapper (no *testing.T calls)
// concurrency tests need. Reload is the fatal-on-transport-error
// wrapper every sequential case uses. The §5.1 wire-version metadata is
// attached here (same keys as StatusErr / status.go, which documents the
// local-mirror rationale): the DP's server interceptor rejects a
// metadata-less RPC with FailedPrecondition before any handler runs
// (wire-auth.md §5.2), so a probe without the keys measures nothing but
// the interceptor.
// dialControlTLS builds the CP-shaped TLS transport for dp.sock dials
// (T130): self-signed cert from the seeded cp.priv, byte-pin dp.pub (§3),
// TLS 1.3, ALPN h2 — the same shape the Java ReloadTokensClient and the
// control-grpc harness present. A plaintext dial no longer reaches dp.sock
// (the DP serves it only with TLS material; wire-auth.md §4 as amended).
func dialControlTLS(h *Harness) (grpc.ClientConnInterface, func(), error) {
	cpPriv, err := fakecp.LoadSigner(filepath.Join(h.KeysDir, "cp.priv"))
	if err != nil {
		return nil, nil, fmt.Errorf("loading seeded cp.priv: %w", err)
	}
	cpCert, err := fakecp.SelfSigned(cpPriv, "stargate-cp-harness")
	if err != nil {
		return nil, nil, fmt.Errorf("deriving CP harness cert: %w", err)
	}
	conn, err := grpc.NewClient("unix://"+h.SockPath(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates:          []tls.Certificate{cpCert},
			InsecureSkipVerify:    true, //nolint:gosec // pinned peer public key IS the verifier (wire-auth.md §4)
			VerifyPeerCertificate: fakecp.PinVerifier(filepath.Join(h.KeysDir, "dp.pub")),
			MinVersion:            tls.VersionTLS13,
			NextProtos:            []string{"h2"},
		})))
	if err != nil {
		return nil, nil, fmt.Errorf("grpc.NewClient(unix://%s): %w", h.SockPath(), err)
	}
	return conn, func() { _ = conn.Close() }, nil
}

func ReloadErr(h *Harness, generation uint64, tokens []*grpcpb.TokenVerifier) (*grpcpb.ReloadTokensResponse, error) {
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
	return client.ReloadTokens(ctx,
		&grpcpb.ReloadTokensRequest{Generation: generation, Tokens: tokens},
		grpc.WaitForReady(true))
}
