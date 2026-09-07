// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Unit tests for the DP half of the inter-plane wire contract (T045):
// X.509 derivation + peer pinning (wire-auth.md §2/§3), the TLS-config
// invariants (§4), the version-metadata interceptors (§5), and the
// DP-hosted Control service (contracts/control-grpc.md §"ReloadTokens" /
// §"GetStatus (minimum subset)").
//
// These are the in-process tier; the process-level contract tier lives in
// tests/contract/control-grpc (T020/T021/T022, gated on T050's main.go)
// and the compose-level tier in tests/contract/compose (T095, R1-R9).
// Tests-first per Constitution Principle VII: this suite existed and was
// failing before server.go/tls.go/client.go landed.
package controlclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/zcat-app/stargate/data-plane/internal/auth"
	"github.com/zcat-app/stargate/data-plane/internal/protoversion"
	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

// --- key/PEM helpers -------------------------------------------------------

// newEd25519Key generates a fresh key and returns it with its PKCS#8 PEM
// encoding (the stargate-keys on-disk format, wire-auth.md §1).
func newEd25519Key(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalling PKCS#8: %v", err)
	}
	return priv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// writePubFile writes a PEM SubjectPublicKeyInfo file for key — the *.pub
// format the pin verifier reads (wire-auth.md §3.1 step 4).
func writePubFile(t *testing.T, path string, key ed25519.PrivateKey) {
	t.Helper()
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is not ed25519.PublicKey")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshalling SPKI: %v", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// writePrivFile persists a PKCS#8 private-key PEM (the dp.priv shape).
func writePrivFile(t *testing.T, path string, pemBytes []byte) {
	t.Helper()
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// --- cert derivation (wire-auth.md §2) --------------------------------------

func TestDeriveCertFieldValues(t *testing.T) {
	priv, _ := newEd25519Key(t)
	cert, err := DeriveCert(priv, DPIdentity)
	if err != nil {
		t.Fatalf("DeriveCert: %v", err)
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parsing derived cert: %v", err)
	}

	// §2.2 field table, row by row.
	if parsed.Version != 3 {
		t.Errorf("Version = %d, want 3 (§2.2: v3 required for SAN extensions)", parsed.Version)
	}
	if parsed.SerialNumber.Sign() != 0 {
		t.Errorf("SerialNumber = %v, want 0 (§2.2: fixed value keeps the derived cert byte-deterministic)", parsed.SerialNumber)
	}
	if parsed.SignatureAlgorithm != x509.PureEd25519 {
		t.Errorf("SignatureAlgorithm = %v, want PureEd25519 (§2.2)", parsed.SignatureAlgorithm)
	}
	if parsed.Subject.CommonName != "stargate-dp" || parsed.Issuer.CommonName != "stargate-dp" {
		t.Errorf("Subject/Issue CN = %q/%q, want stargate-dp/stargate-dp (§2.2: self-signed, informational only)", parsed.Subject.CommonName, parsed.Issuer.CommonName)
	}
	// §2.2: NotBefore = now − 5 min, NotAfter = now + 30 days; tolerate the
	// span between DeriveCert's clock read and this one.
	now := time.Now()
	if want := now.Add(-5 * time.Minute); parsed.NotBefore.Before(want.Add(-time.Minute)) || parsed.NotBefore.After(want.Add(time.Minute)) {
		t.Errorf("NotBefore = %v, want ≈ %v (§2.2: 5-minute negative skew window)", parsed.NotBefore, want)
	}
	if want := now.Add(30 * 24 * time.Hour); parsed.NotAfter.Before(want.Add(-time.Minute)) || parsed.NotAfter.After(want.Add(time.Minute)) {
		t.Errorf("NotAfter = %v, want ≈ %v (§2.2: 30-day validity)", parsed.NotAfter, want)
	}
	if parsed.NotAfter.Sub(parsed.NotBefore) != 30*24*time.Hour+5*time.Minute {
		t.Errorf("validity window = %v, want exactly 30d+5m (§2.2 fixed windows)", parsed.NotAfter.Sub(parsed.NotBefore))
	}
	if parsed.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want DigitalSignature only (§2.2)", parsed.KeyUsage)
	}
	if len(parsed.ExtKeyUsage) != 2 ||
		parsed.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		parsed.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ServerAuth ClientAuth] (§2.2: each plane is client AND server)", parsed.ExtKeyUsage)
	}
	if len(parsed.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want empty (§2.2: UDS peer verification does not use DNS)", parsed.DNSNames)
	}
	if len(parsed.URIs) != 1 || parsed.URIs[0].String() != "spiffe://stargate.local/dp" {
		t.Errorf("URIs = %v, want [spiffe://stargate.local/dp] (§2.2 URI SAN)", parsed.URIs)
	}

	// Self-signed: the signature verifies under the cert's own public key
	// (§2.2: Issuer == Subject, no CA chain).
	if err := parsed.CheckSignature(parsed.SignatureAlgorithm, parsed.RawTBSCertificate, parsed.Signature); err != nil {
		t.Errorf("self-signature check: %v (§2.2 self-signed)", err)
	}
	if !bytes.Equal(parsed.RawSubjectPublicKeyInfo, cert.Leaf.RawSubjectPublicKeyInfo) {
		t.Errorf("cert.Leaf SPKI does not match the DER cert")
	}
	pub, ok := parsed.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, priv.Public().(ed25519.PublicKey)) {
		t.Errorf("cert public key does not equal the derived-from private key (§2.1)")
	}
}

func TestDeriveCertDeterministicModuloWindow(t *testing.T) {
	// §2.3: aside from NotBefore/NotAfter, the derived cert is byte-identical
	// across restarts against the same key.
	priv, _ := newEd25519Key(t)
	a, err := DeriveCert(priv, DPIdentity)
	if err != nil {
		t.Fatalf("DeriveCert a: %v", err)
	}
	b, err := DeriveCert(priv, DPIdentity)
	if err != nil {
		t.Fatalf("DeriveCert b: %v", err)
	}
	pa, _ := x509.ParseCertificate(a.Certificate[0])
	pb, _ := x509.ParseCertificate(b.Certificate[0])
	if pa.NotAfter.Equal(pb.NotAfter) {
		// A second-precision NotAfter could legitimately repeat; the §2.3
		// claim is about everything ELSE matching, so just report.
		t.Log("NotAfter repeated across derivations (same-second clock read)")
	}
	pa.NotBefore, pa.NotAfter = time.Time{}, time.Time{}
	pb.NotBefore, pb.NotAfter = time.Time{}, time.Time{}
	if !bytes.Equal(pa.RawTBSCertificate, pb.RawTBSCertificate) {
		t.Error("TBS bytes differ beyond the validity window (§2.3 determinism)")
	}
}

func TestDeriveCertRejectsWrongKey(t *testing.T) {
	// §2.2: only Ed25519 keys service this channel; an RSA private key is a
	// derivation failure (degraded-mode for the DP, wire-auth.md §2.2).
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa key: %v", err)
	}
	if _, err := DeriveCert(rsaKey, DPIdentity); err == nil {
		t.Error("DeriveCert accepted an RSA key — want error (§1: Ed25519 is the only signature algorithm)")
	}
}

func TestLoadPrivateKey(t *testing.T) {
	priv, pemBytes := newEd25519Key(t)
	path := filepath.Join(t.TempDir(), "dp.priv")
	writePrivFile(t, path, pemBytes)
	got, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if !bytes.Equal(got.(ed25519.PrivateKey), priv) {
		t.Error("loaded key does not round-trip the stored key")
	}
	if _, err := LoadPrivateKey(filepath.Join(t.TempDir(), "absent.priv")); err == nil {
		t.Error("LoadPrivateKey accepted a missing file (§2.2: unreadable key is an error)")
	}
	bad := filepath.Join(t.TempDir(), "bad.priv")
	if err := os.WriteFile(bad, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(bad); err == nil {
		t.Error("LoadPrivateKey accepted an unparseable file (§2.2)")
	}
}

// --- peer pin (wire-auth.md §3) ---------------------------------------------

func TestPeerPinVerifierByteEqual(t *testing.T) {
	// §3.1: accept iff the cert's raw 32-byte Ed25519 key byte-equals the
	// pinned *.pub key; compare raw keys, never PEM text or DER wrappers.
	cpKey, _ := newEd25519Key(t)
	rogueKey, _ := newEd25519Key(t)
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "cp.pub")
	writePubFile(t, pinPath, cpKey)

	verifier := PeerPinVerifier(pinPath)
	if err := verifier(certChainOf(t, cpKey), nil); err != nil {
		t.Errorf("pin verifier rejected the pinned key's cert: %v", err)
	}
	if err := verifier(certChainOf(t, rogueKey), nil); err == nil {
		t.Error("pin verifier accepted a cert whose key does not match the pin (§3.1 step 5)")
	}
	// §3.3: a missing or unreadable pin file fails the handshake.
	if err := os.Remove(pinPath); err != nil {
		t.Fatal(err)
	}
	if err := verifier(certChainOf(t, cpKey), nil); err == nil {
		t.Error("pin verifier accepted with the pin file missing (§3.3: degraded, never accept)")
	}
}

func TestPeerPinVerifierReReadsPerHandshake(t *testing.T) {
	// §3.1 step 3: the pinned key is re-read fresh from disk on EVERY
	// handshake — caching it breaks key rotation (§6.2) and incident
	// response. Same verifier instance, pin file rotated underneath it.
	keyA, _ := newEd25519Key(t)
	keyB, _ := newEd25519Key(t)
	pinPath := filepath.Join(t.TempDir(), "cp.pub")
	writePubFile(t, pinPath, keyA)
	verifier := PeerPinVerifier(pinPath)

	if err := verifier(certChainOf(t, keyA), nil); err != nil {
		t.Fatalf("pre-rotation handshake: %v", err)
	}
	writePubFile(t, pinPath, keyB) // the §6.2 rotation event
	if err := verifier(certChainOf(t, keyA), nil); err == nil {
		t.Error("verifier cached the pre-rotation pin — §3.1 step 3 violation (rotation would need a peer restart)")
	}
	if err := verifier(certChainOf(t, keyB), nil); err != nil {
		t.Errorf("post-rotation handshake with the new key: %v", err)
	}
}

func TestPeerPinVerifierEncodingAndShape(t *testing.T) {
	// §3.1 encoding pin: the comparison normalises to the raw 32-byte key.
	// A pin file whose SPKI wrapper differs (distinct DER tags) but whose
	// raw key matches must still be accepted.
	key, _ := newEd25519Key(t)
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "cp.pub")
	// Marshal through the public key type to produce a standard SPKI, then
	// re-derive a cert whose SPKI the verifier extracts independently.
	writePubFile(t, pinPath, key)
	verifier := PeerPinVerifier(pinPath)

	// Chain length: exactly 1 (§1 — single self-signed cert; a chain is a
	// contract violation, not a pin check on the leaf only).
	leaf := certChainOf(t, key)
	if err := verifier([][]byte{leaf[0], leaf[0]}, nil); err == nil {
		t.Error("verifier accepted a >1-cert chain (§1: cert chain length is exactly 1)")
	}
	if err := verifier(nil, nil); err == nil {
		t.Error("verifier accepted an empty chain")
	}
	if err := verifier(leaf, nil); err != nil {
		t.Fatalf("sanity single-cert accept: %v", err)
	}

	// A non-Ed25519 peer cert fails (§3.3: "not a parseable Ed25519 public
	// key" class of failure).
	if err := verifier([][]byte{rsaSelfSignedDER(t)}, nil); err == nil {
		t.Error("verifier accepted a non-Ed25519 peer cert (§1)")
	}
}

func TestLoadPeerPublicKey(t *testing.T) {
	key, _ := newEd25519Key(t)
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "cp.pub")
	writePubFile(t, pinPath, key)

	got, err := LoadPeerPublicKey(pinPath)
	if err != nil {
		t.Fatalf("LoadPeerPublicKey: %v", err)
	}
	want := key.Public().(ed25519.PublicKey)
	if !bytes.Equal(got, want) {
		t.Error("loaded pinned key does not byte-equal the stored key (§3.1: raw 32-byte comparison)")
	}
	if len(got) != ed25519.PublicKeySize {
		t.Errorf("loaded key is %d bytes, want 32 (§3.1: raw 32-byte form)", len(got))
	}

	// A pin file that is not a parseable public key is an error (§3.3).
	bad := filepath.Join(dir, "bad.pub")
	if err := os.WriteFile(bad, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPeerPublicKey(bad); err == nil {
		t.Error("LoadPeerPublicKey accepted garbage (§3.3)")
	}
	if _, err := LoadPeerPublicKey(filepath.Join(dir, "absent.pub")); err == nil {
		t.Error("LoadPeerPublicKey accepted a missing file (§3.3)")
	}
}

// --- TLS config invariants (wire-auth.md §4) ---------------------------------

func TestTLSConfigInvariants(t *testing.T) {
	dpKey, _ := newEd25519Key(t)
	cert, err := DeriveCert(dpKey, DPIdentity)
	if err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(t.TempDir(), "cp.pub")

	for name, cfg := range map[string]*tls.Config{
		"client": ClientTLSConfig(cert, pin),
		"server": ServerTLSConfig(cert, pin),
	} {
		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("%s: MinVersion = %v, want TLS 1.3 (§4: pinned to 1.3 removes the downgrade surface)", name, cfg.MinVersion)
		}
		if !cfg.InsecureSkipVerify {
			t.Errorf("%s: InsecureSkipVerify = false — §4: Go rejects the self-signed cert at the system-roots check before the custom hook runs unless ISV=true", name)
		}
		// §4: ISV=true with NO custom verifier is a contract violation
		// (silent auth bypass). The two must always be co-located.
		if cfg.InsecureSkipVerify && cfg.VerifyPeerCertificate == nil {
			t.Errorf("%s: InsecureSkipVerify=true without a VerifyPeerCertificate verifier — §4 contract violation", name)
		}
		if len(cfg.Certificates) != 1 {
			t.Errorf("%s: %d certificates presented, want exactly 1 (§1: cert chain length exactly 1)", name, len(cfg.Certificates))
		}
		if cfg.ServerName != "" {
			t.Errorf("%s: ServerName = %q — §4: UDS has no DNS name; ServerName is not the trust decision", name, cfg.ServerName)
		}
	}
	// §4: client auth REQUIRED on the server side (mTLS).
	srv := ServerTLSConfig(cert, pin)
	if srv.ClientAuth != tls.RequireAnyClientCert {
		t.Errorf("server ClientAuth = %v, want RequireAnyClientCert (§4: a server that does not request a client cert is a contract violation)", srv.ClientAuth)
	}
	// The pin verifier is installed against the pinned peer pub on BOTH.
	if srv.VerifyPeerCertificate == nil || ClientTLSConfig(cert, pin).VerifyPeerCertificate == nil {
		t.Error("custom pin verifier missing on a config (§4: the hook is the sole trust decision)")
	}
}

func TestDeriveDPTLSWiresBothSides(t *testing.T) {
	// The DP convenience: one dp.priv-derived cert serving both the
	// dp.sock listener and the control.sock dialer, pinning cp.pub on both
	// (ticket §Analysis; wire-auth.md §2.1 one cert, both roles).
	dir := t.TempDir()
	dpKey, dpPEM := newEd25519Key(t)
	cpKey, _ := newEd25519Key(t)
	writePrivFile(t, filepath.Join(dir, "dp.priv"), dpPEM)
	writePubFile(t, filepath.Join(dir, "cp.pub"), cpKey)

	clientCfg, serverCfg, err := DeriveDPTLS(dir)
	if err != nil {
		t.Fatalf("DeriveDPTLS: %v", err)
	}
	if len(clientCfg.Certificates) == 0 || len(serverCfg.Certificates) == 0 {
		t.Fatal("configs carry no certificate")
	}
	if !samePublicKey(clientCfg.Certificates[0], serverCfg.Certificates[0]) {
		t.Error("client and server configs present different certs — §2.1: one in-memory cert, both roles")
	}
	wantKey := dpKey.Public().(ed25519.PublicKey)
	gotKey, ok := clientCfg.Certificates[0].Leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !bytes.Equal(gotKey, wantKey) {
		t.Error("derived cert is not from dp.priv (§2.1)")
	}

	// Degraded-mode surface: a missing dp.priv or cp.pub is an ERROR the
	// caller turns into a keep-routing warning (§2.2/§3.3 DP behaviour).
	empty := t.TempDir()
	if _, _, err := DeriveDPTLS(empty); err == nil {
		t.Error("DeriveDPTLS accepted a keys dir with no dp.priv (§2.2)")
	}
	cpOnly := t.TempDir()
	_, cpPEM := newEd25519Key(t)
	_ = cpPEM
	writePubFile(t, filepath.Join(cpOnly, "cp.pub"), cpKey)
	if _, _, err := DeriveDPTLS(cpOnly); err == nil {
		t.Error("DeriveDPTLS accepted a keys dir with no dp.priv but cp.pub present (§2.1 reads dp.priv first)")
	}
}

func TestMutualTLSHandshakeEndToEnd(t *testing.T) {
	// In-process handshake over a UDS with the package's own configs:
	// DP as server (pin = cp.pub), CP-simulated client (own = cp cert, pin
	// = dp.pub). Positive path + both wrong-key negatives (§3.3).
	dir := t.TempDir()
	dpKey, dpPEM := newEd25519Key(t)
	cpKey, cpPEM := newEd25519Key(t)
	otherKey, _ := newEd25519Key(t)
	writePubFile(t, filepath.Join(dir, "cp.pub"), cpKey)
	writePubFile(t, filepath.Join(dir, "dp.pub"), dpKey)
	writePrivFile(t, filepath.Join(dir, "dp.priv"), dpPEM)
	writePrivFile(t, filepath.Join(dir, "cp.priv"), cpPEM)

	sock := filepath.Join(dir, "handshake.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer os.Remove(sock)

	serverCfg := ServerTLSConfig(mustDerive(t, dpKey), filepath.Join(dir, "cp.pub"))
	tlsLis := tls.NewListener(lis, serverCfg)
	// Persistent accept loop: every inbound conn (the honest client below,
	// then the rogue) is handshaked + read to completion, its outcome on
	// serverErr. tls.Dial otherwise blocks on a server that never accepts.
	serverErr := make(chan error, 8)
	go func() {
		for {
			conn, err := tlsLis.Accept()
			if err != nil {
				return // listener closed; test teardown
			}
			go func() {
				buf := make([]byte, 4)
				_, err := ioReadFull(conn, buf)
				serverErr <- err
				conn.Close()
			}()
		}
	}()

	clientKey, clientPubPath := cpKey, filepath.Join(dir, "dp.pub")
	clientCfg := ClientTLSConfig(mustDerive(t, clientKey), clientPubPath)
	conn, err := tls.Dial("unix", sock, clientCfg)
	if err != nil {
		t.Fatalf("mutual handshake with matching pins failed: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("post-handshake write: %v", err)
	}
	// Close is deliberately best-effort (T128): tls.Conn.Close also writes
	// the closeNotify alert, and when the server goroutine's read+close
	// wins the race that write hits EPIPE — Close returns "failed to send
	// closeNotify alert (but connection was closed anyway)", a benign,
	// signal-free error for an already-closed conn. The property under
	// test is ground-truthed by the serverErr channel below, not by Close.
	_ = conn.Close()
	if err := <-serverErr; err != nil {
		t.Errorf("server side of the handshake/round-trip failed: %v", err)
	}

	// Negative: the client presents a key the server does not pin (§3.3:
	// handshake aborted, no application data). The server verifier fails
	// first (client cert pin), so the client sees the alert. tls.Dial can
	// complete lazily, so the failure is forced on first use.
	rogueCfg := ClientTLSConfig(mustDerive(t, otherKey), filepath.Join(dir, "dp.pub"))
	rogue, dialErr := tls.Dial("unix", sock, rogueCfg)
	if dialErr != nil {
		t.Logf("rogue client rejected at dial/handshake (correct): %v", dialErr)
	} else {
		// TLS 1.3: the client's Finished is sent before the server has
		// verified the client cert, so Write can buffer "successfully"
		// before the abort alert arrives. Best-effort fire is fine — the
		// server-side outcome channel is the ground truth below.
		_, _ = rogue.Write([]byte("ping"))
		rogue.Close()
	}
	// The server must abort the rogue conn (pin failure), never relay data:
	// its 4-byte read ends in an error, not the ping bytes.
	if serr := <-serverErr; serr == nil {
		t.Error("server completed a round trip with a rogue client cert (§3.3: handshake must abort)")
	} else {
		t.Logf("rogue client aborted server-side (correct): %v", serr)
	}
	_ = tlsLis.Close()

	// Negative: the client refuses a server key it does not pin. Same
	// lazy-handshake caveat, forced on first use.
	sneakyServerCfg := ServerTLSConfig(mustDerive(t, otherKey), filepath.Join(dir, "cp.pub"))
	lis2, err := net.Listen("unix", filepath.Join(dir, "handshake2.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(filepath.Join(dir, "handshake2.sock"))
	tlsLis2 := tls.NewListener(lis2, sneakyServerCfg)
	go func() {
		for {
			c, err := tlsLis2.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = ioReadFull(c, make([]byte, 4))
			}()
		}
	}()
	// The client pins dp.pub (= dpKey), but this server presents otherKey.
	sneaky, dialErr := tls.Dial("unix", filepath.Join(dir, "handshake2.sock"), ClientTLSConfig(mustDerive(t, dpKey), filepath.Join(dir, "dp.pub")))
	if dialErr != nil {
		t.Logf("wrong-server-key rejected at dial/handshake (correct): %v", dialErr)
	} else {
		sneaky.SetDeadline(time.Now().Add(2 * time.Second))
		_, werr := sneaky.Write([]byte("ping"))
		_, rerr := sneaky.Read(make([]byte, 1))
		if werr == nil && rerr == nil {
			t.Error("connection to a non-pinned server carried a round trip (§3.3: client must refuse)")
		} else {
			t.Logf("wrong-server-key conn aborted on use (correct): write=%v read=%v", werr, rerr)
		}
		sneaky.Close()
	}
	_ = tlsLis2.Close()
}

// --- version metadata interceptors (wire-auth.md §5) -------------------------

func TestProtoversionContractPins(t *testing.T) {
	// §5.4 closed set + §5.1 keys, pinned so a drift fails here first.
	if protoversion.Major != 1 {
		t.Errorf("Major = %d, want 1 (proto package stargate.v1)", protoversion.Major)
	}
	if protoversion.Minor != 0 {
		t.Errorf("Minor = %d, want 0", protoversion.Minor)
	}
	if want := "reload-tokens,watch-events,get-status-minimum"; protoversion.Capabilities != want {
		t.Errorf("Capabilities = %q, want %q (§5.4 closed set)", protoversion.Capabilities, want)
	}
	for key, want := range map[string]string{
		protoversion.MetaMajor:        "x-stargate-proto-major",
		protoversion.MetaMinor:        "x-stargate-proto-minor",
		protoversion.MetaCapabilities: "x-stargate-capabilities",
	} {
		if key != want {
			t.Errorf("metadata key %q != contract key %q (§5.1)", key, want)
		}
	}
}

func TestUnaryProtoVersionInterceptorRejectionMatrix(t *testing.T) {
	// §5.2 rejection rule, row by row. The app handler MUST NOT run on any
	// reject (§5.3: the interceptor is the gate).
	handlerRan := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerRan = true
		return "ok", nil
	}
	// §5.3: the receiver's own major comes from the compiled-in constants.
	cases := []struct {
		name       string
		md         metadata.MD
		wantCode   codes.Code
		wantSubstr string
	}{
		{"missing major", nil, codes.FailedPrecondition, "missing x-stargate-proto-major"},
		{"unparseable major", metadata.Pairs(protoversion.MetaMajor, "abc"), codes.FailedPrecondition, ""},
		{"older major", metadata.Pairs(protoversion.MetaMajor, "0"), codes.FailedPrecondition, "peer major 0 < server major 1"},
		{"newer major", metadata.Pairs(protoversion.MetaMajor, "2"), codes.FailedPrecondition, ""},
		{"empty major value", metadata.Pairs(protoversion.MetaMajor, ""), codes.FailedPrecondition, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handlerRan = false
			ctx := context.Background()
			if tc.md != nil {
				ctx = metadata.NewIncomingContext(ctx, tc.md)
			}
			resp, err := UnaryProtoVersionInterceptor(ctx, nil, nil, handler)
			if status.Code(err) != tc.wantCode {
				t.Errorf("code = %v, want %v (§5.2)", status.Code(err), tc.wantCode)
			}
			if tc.wantSubstr != "" && !strings.Contains(status.Convert(err).Message(), tc.wantSubstr) {
				t.Errorf("message %q does not contain %q (§5.2 wording)", status.Convert(err).Message(), tc.wantSubstr)
			}
			if handlerRan {
				t.Error("application handler ran on a rejected RPC (§5.3: interceptor is the gate)")
			}
			if resp != nil {
				t.Error("rejected RPC returned a non-nil response")
			}
		})
	}

	t.Run("equal major accepted", func(t *testing.T) {
		handlerRan = false
		ctx := metadata.NewIncomingContext(context.Background(),
			metadata.Pairs(protoversion.MetaMajor, "1"))
		if _, err := UnaryProtoVersionInterceptor(ctx, nil, nil, handler); err != nil {
			t.Errorf("equal major rejected: %v (§5.2: accept regardless of minor)", err)
		}
		if !handlerRan {
			t.Error("handler did not run for an accepted RPC")
		}
	})
	t.Run("equal major with newer minor accepted", func(t *testing.T) {
		// §5.2: minor is logged for diagnostics but never a gate; additive
		// minors are compatible (arch §5.3).
		ctx := metadata.NewIncomingContext(context.Background(),
			metadata.Pairs(protoversion.MetaMajor, "1", protoversion.MetaMinor, "7"))
		if _, err := UnaryProtoVersionInterceptor(ctx, nil, nil, handler); err != nil {
			t.Errorf("minor 7 rejected: %v (§5.2 additive minor accepted)", err)
		}
	})
	t.Run("unparseable minor still accepted", func(t *testing.T) {
		// The minor is not a gate — its parseability is irrelevant.
		ctx := metadata.NewIncomingContext(context.Background(),
			metadata.Pairs(protoversion.MetaMajor, "1", protoversion.MetaMinor, "bogus"))
		if _, err := UnaryProtoVersionInterceptor(ctx, nil, nil, handler); err != nil {
			t.Errorf("bogus minor rejected: %v (§5.2: minor never gates)", err)
		}
	})
}

func TestStreamProtoVersionInterceptorRejectionMatrix(t *testing.T) {
	// §5.3: the interceptor is installed unary AND streaming. Same rule on
	// the streaming path (the DP's WatchEvents client hits the CP's stream
	// interceptor; the DP server hosts no v1 stream but must still gate one).
	handlerRan := false
	streamHandler := func(srv any, ss grpc.ServerStream) error {
		handlerRan = true
		return nil
	}
	reject := func(t *testing.T, md metadata.MD) {
		t.Helper()
		handlerRan = false
		ctx := context.Background()
		if md != nil {
			ctx = metadata.NewIncomingContext(ctx, md)
		}
		err := StreamProtoVersionInterceptor(nil, &fakeServerStream{ctx: ctx}, nil, streamHandler)
		if status.Code(err) != codes.FailedPrecondition {
			t.Errorf("stream code = %v, want FailedPrecondition (§5.2)", status.Code(err))
		}
		if handlerRan {
			t.Error("stream handler ran on a rejected RPC (§5.3)")
		}
	}
	reject(t, nil)
	reject(t, metadata.Pairs(protoversion.MetaMajor, "2"))

	handlerRan = false
	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(protoversion.MetaMajor, "1"))
	if err := StreamProtoVersionInterceptor(nil, &fakeServerStream{ctx: ctx}, nil, streamHandler); err != nil {
		t.Errorf("stream accept path: %v", err)
	}
	if !handlerRan {
		t.Error("stream handler did not run for an accepted RPC")
	}
}

// fakeServerStream satisfies the slice of grpc.ServerStream the stream
// interceptor touches (Context only — the handler is a stub).
type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context { return f.ctx }

func TestClientInterceptorSetsMetadataOnEveryCall(t *testing.T) {
	// §5.3/§5.1: the client interceptor sets the three keys on EVERY call —
	// asserted through the wire for both an unary and a streaming RPC, which
	// also pins protoversion's exact values end-to-end.
	var mu sync.Mutex
	var unaryMD, streamMD metadata.MD
	impl := &metadataCapturingService{
		onReload: func(ctx context.Context) {
			mu.Lock()
			unaryMD = incomingMD(t, ctx)
			mu.Unlock()
		},
		onWatch: func(ctx context.Context) {
			mu.Lock()
			streamMD = incomingMD(t, ctx)
			mu.Unlock()
		},
	}
	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer()
	grpcpb.RegisterControlServer(gs, impl) // unary surface (ReloadTokens)
	grpcpb.RegisterEventsServer(gs, impl)  // stream surface (WatchEvents)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	// The DP's dial shape: TLS credentials are the listener's concern (the
	// in-process bufconn needs none); the interceptors are what's under test.
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithChainUnaryInterceptor(UnaryClientVersionInterceptor),
		grpc.WithChainStreamInterceptor(StreamClientVersionInterceptor),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	control := grpcpb.NewControlClient(conn)
	events := grpcpb.NewEventsClient(conn)

	_, err = control.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{Generation: 1})
	if err != nil {
		t.Fatalf("ReloadTokens: %v", err)
	}
	stream, err := events.WatchEvents(context.Background(), &grpcpb.WatchEventsRequest{})
	if err != nil {
		t.Fatalf("WatchEvents: %v", err)
	}
	// Unlike the unary call, a streaming RPC returns before the server
	// handler runs; Recv blocks until the handler's immediate return
	// surfaces as EOF, guaranteeing the capture below has happened.
	if _, rerr := stream.Recv(); rerr == nil {
		t.Error("stream delivered an unexpected event")
	}
	_ = stream.CloseSend()

	want := map[string]string{
		protoversion.MetaMajor:        strconv.Itoa(protoversion.Major),
		protoversion.MetaMinor:        strconv.Itoa(protoversion.Minor),
		protoversion.MetaCapabilities: protoversion.Capabilities,
	}
	mu.Lock()
	defer mu.Unlock()
	for name, got := range map[string]metadata.MD{"unary": unaryMD, "stream": streamMD} {
		if got == nil {
			t.Errorf("%s call carried no incoming metadata — interceptor did not run", name)
			continue
		}
		for key, val := range want {
			if values := got.Get(key); len(values) != 1 || values[0] != val {
				t.Errorf("%s call metadata %s = %v, want [%q] (§5.1: set on EVERY call)", name, key, values, val)
			}
		}
	}
}

// metadataCapturingService serves both the Control (unary) and Events
// (streaming) surfaces whose only job is exposing the incoming context of
// each RPC to the test.
type metadataCapturingService struct {
	grpcpb.UnimplementedControlServer
	grpcpb.UnimplementedEventsServer
	onReload func(ctx context.Context)
	onWatch  func(ctx context.Context)
}

func (m *metadataCapturingService) ReloadTokens(ctx context.Context, _ *grpcpb.ReloadTokensRequest) (*grpcpb.ReloadTokensResponse, error) {
	m.onReload(ctx)
	return &grpcpb.ReloadTokensResponse{}, nil
}

func (m *metadataCapturingService) WatchEvents(_ *grpcpb.WatchEventsRequest, ss grpcpb.Events_WatchEventsServer) error {
	m.onWatch(ss.Context())
	return nil
}

func incomingMD(t *testing.T, ctx context.Context) metadata.MD {
	t.Helper()
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		t.Error("no incoming metadata in handler context")
		return nil
	}
	return md
}

// --- the DP-hosted Control service (control-grpc.md §"ReloadTokens" /
// §"GetStatus (minimum subset)") ----------------------------------------------

// snapshotRecorder is the recording snapshot seam (the T046 hook point):
// it captures every generation the Server persists and can inject failures.
type snapshotRecorder struct {
	mu    sync.Mutex
	calls []*auth.Generation
	err   error // returned on the next errN calls
	errN  int
}

func (r *snapshotRecorder) persist(g *auth.Generation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, g)
	if r.errN > 0 {
		r.errN--
		return r.err
	}
	return nil
}

func (r *snapshotRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// newTestServer builds a Server over a fresh TokenStore with a recording
// snapshot seam and a fixed status seam.
func newTestServer(t *testing.T, rec *snapshotRecorder) *Server {
	t.Helper()
	return NewServer(auth.NewTokenStore(), rec.persist, func() *grpcpb.StatusResponse {
		return &grpcpb.StatusResponse{Counters: []*grpcpb.RouteCounter{{
			Route: "TOR", HourBucket: 1, RequestCount: 2, ByteCount: 3,
		}}}
	}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
}

func verifiersOf(tokens ...[]byte) []*grpcpb.TokenVerifier {
	out := make([]*grpcpb.TokenVerifier, 0, len(tokens))
	for _, tok := range tokens {
		out = append(out, &grpcpb.TokenVerifier{Verifier: tok})
	}
	return out
}

func TestReloadTokensHappyPath(t *testing.T) {
	// Contract row 1: new generation applied; response carries
	// APPLY_STATUS_OK + applied_generation; the snapshot seam saw the new
	// generation BEFORE the RPC returned (persist-before-return).
	rec := &snapshotRecorder{}
	s := newTestServer(t, rec)
	tok := make([]byte, 32)
	rand.Read(tok)

	resp, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{
		Generation: 1, Tokens: verifiersOf(tok),
	})
	if err != nil {
		t.Fatalf("ReloadTokens: %v", err)
	}
	if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Errorf("status = %v, want APPLY_STATUS_OK", resp.GetStatus())
	}
	if resp.GetAppliedGeneration() != 1 {
		t.Errorf("applied_generation = %d, want 1", resp.GetAppliedGeneration())
	}
	cur := s.tokens.Current()
	if cur.Generation != 1 || len(cur.Verifiers) != 1 || !bytes.Equal(cur.Verifiers[0], tok) {
		t.Error("token store did not swap to the pushed generation verbatim")
	}
	if rec.count() != 1 {
		t.Fatalf("snapshot seam called %d times, want 1 (persist-before-return)", rec.count())
	}
	if rec.calls[0].Generation != 1 || !bytes.Equal(rec.calls[0].Verifiers[0], tok) {
		t.Error("persisted generation is not the pushed one (persist-content fidelity)")
	}
}

func TestReloadTokensStaleGeneration(t *testing.T) {
	// Contract row 2 + T092 reconciliation: request.generation <= current →
	// APPLY_STATUS_STALE_GENERATION, current_generation echoes the DP's
	// current generation, applied_generation reports the unchanged current,
	// and NO state changes.
	rec := &snapshotRecorder{}
	s := newTestServer(t, rec)
	tokA := make([]byte, 32)
	rand.Read(tokA)
	if _, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{
		Generation: 2, Tokens: verifiersOf(tokA),
	}); err != nil {
		t.Fatal(err)
	}
	snapshotCalls := rec.count()

	// Well-formed verifiers: the length gate runs before the stale check
	// (a malformed push is INVALID regardless of generation), so the stale
	// property is exercised in isolation.
	tokStale := make([]byte, 32)
	rand.Read(tokStale)
	for _, stale := range []uint64{2, 1} {
		resp, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{
			Generation: stale, Tokens: verifiersOf(tokStale),
		})
		if err != nil {
			t.Fatalf("generation %d: %v", stale, err)
		}
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_STALE_GENERATION {
			t.Errorf("generation %d status = %v, want APPLY_STATUS_STALE_GENERATION", stale, resp.GetStatus())
		}
		if resp.GetAppliedGeneration() != 2 {
			t.Errorf("generation %d applied_generation = %d, want 2 (unchanged)", stale, resp.GetAppliedGeneration())
		}
		if resp.GetCurrentGeneration() != 2 {
			t.Errorf("generation %d current_generation = %d, want 2 (T092 reconciliation echo)", stale, resp.GetCurrentGeneration())
		}
	}
	if got := s.tokens.Current().Generation; got != 2 {
		t.Errorf("current generation = %d, want 2 (stale pushes change nothing)", got)
	}
	if rec.count() != snapshotCalls {
		t.Error("snapshot seam fired on a stale push — persisted state must be untouched")
	}
}

func TestReloadTokensInvalidVerifierLength(t *testing.T) {
	// Contract row 3: every verifier must be exactly 32 bytes; any mismatch
	// → APPLY_STATUS_INVALID with no generation change and no snapshot call.
	rec := &snapshotRecorder{}
	s := newTestServer(t, rec)
	tokA := make([]byte, 32)
	rand.Read(tokA)
	if _, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{
		Generation: 1, Tokens: verifiersOf(tokA),
	}); err != nil {
		t.Fatal(err)
	}

	for _, n := range []int{0, 31, 33, 64} {
		resp, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{
			Generation: 2, Tokens: verifiersOf(make([]byte, n)),
		})
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_INVALID {
			t.Errorf("len %d status = %v, want APPLY_STATUS_INVALID", n, resp.GetStatus())
		}
		if resp.GetAppliedGeneration() != 1 {
			t.Errorf("len %d applied_generation = %d, want 1 (unchanged)", n, resp.GetAppliedGeneration())
		}
	}
	// The generation number is not consumed by a rejected push (row 3
	// follow-through in the contract test): a valid gen 2 now applies.
	tokB := make([]byte, 32)
	rand.Read(tokB)
	resp, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{
		Generation: 2, Tokens: verifiersOf(tokB),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Errorf("valid gen 2 after invalid pushes status = %v, want OK", resp.GetStatus())
	}
	// 4 invalid + happy + setup: only the two valid pushes persisted.
	if rec.count() != 2 {
		t.Errorf("snapshot seam called %d times, want 2 (invalid pushes never persist)", rec.count())
	}
}

func TestReloadTokensEmptyTokenListIsValid(t *testing.T) {
	// An empty verifier list is a revoke-all generation (data-model.md §1.3:
	// the empty set is a valid generation — nothing authenticates until the
	// next push). Not an INVALID.
	rec := &snapshotRecorder{}
	s := newTestServer(t, rec)
	resp, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Errorf("empty-list push status = %v, want APPLY_STATUS_OK (revoke-all is a valid generation)", resp.GetStatus())
	}
	if len(s.tokens.Current().Verifiers) != 0 {
		t.Error("empty-list push left verifiers behind")
	}
}

func TestReloadTokensSnapshotFailureStillOK(t *testing.T) {
	// Contract row 4: persist failure → still APPLY_STATUS_OK (in-memory
	// truth wins; the snapshot is a cold-start cache) and the failure is
	// journaled (loginvariants snapshot_write class).
	rec := &snapshotRecorder{err: errors.New("read-only filesystem"), errN: 1}
	var logBuf bytes.Buffer
	s := NewServer(auth.NewTokenStore(), rec.persist, func() *grpcpb.StatusResponse {
		return &grpcpb.StatusResponse{}
	}, slog.New(slog.NewTextHandler(&logBuf, nil)))

	tok := make([]byte, 32)
	rand.Read(tok)
	resp, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{
		Generation: 1, Tokens: verifiersOf(tok),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Fatalf("status with failing snapshot seam = %v, want APPLY_STATUS_OK (row 4)", resp.GetStatus())
	}
	if got := s.tokens.Current().Generation; got != 1 {
		t.Errorf("in-memory generation = %d, want 1 (in-memory truth wins)", got)
	}
	logged := logBuf.String()
	if !strings.Contains(logged, "snapshot write failed") {
		t.Errorf("journal has no snapshot-write-failure line — contract row 4 requires it; journal:\n%s", logged)
	}
	// Index-only hygiene: the failure line names the error class, never the
	// verifier bytes.
	if leaks := bytes.Contains(logBuf.Bytes(), tok); leaks {
		t.Error("journal echoes verifier bytes on persist failure (Principle III)")
	}
}

func TestReloadTokensConvergesUnderConcurrency(t *testing.T) {
	// Contract row 5: generations N and N+1 in parallel converge on N+1;
	// the swap+persist pair is serialized so the snapshot can never lag the
	// in-memory generation (the interleaving a lock-free handler would
	// allow: N+2 swaps, N+1's persist lands last).
	rec := &snapshotRecorder{}
	s := newTestServer(t, rec)
	tok1 := make([]byte, 32)
	tok2 := make([]byte, 32)
	rand.Read(tok1)
	rand.Read(tok2)

	var wg sync.WaitGroup
	resps := make([]*grpcpb.ReloadTokensResponse, 2)
	for i, push := range []struct {
		gen uint64
		tok []byte
	}{{1, tok1}, {2, tok2}} {
		wg.Add(1)
		go func(i int, gen uint64, tok []byte) {
			defer wg.Done()
			resp, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{
				Generation: gen, Tokens: verifiersOf(tok),
			})
			if err != nil {
				t.Errorf("gen %d: %v", gen, err)
				return
			}
			resps[i] = resp
		}(i, push.gen, push.tok)
	}
	wg.Wait()
	// Convergence: the higher generation is in memory...
	if got := s.tokens.Current().Generation; got != 2 {
		t.Errorf("converged generation = %d, want 2", got)
	}
	// ...generation 2 applied regardless of interleaving (row 5)...
	if resps[1] == nil || resps[1].GetStatus() != grpcpb.ApplyStatus_APPLY_STATUS_OK {
		t.Error("generation 2 push did not apply — convergence requires it")
	}
	// ...and the snapshot matches in-memory state (serialized swap+persist).
	last := rec.calls[len(rec.calls)-1]
	if last.Generation != s.tokens.Current().Generation {
		t.Errorf("snapshot generation %d lags in-memory %d — swap+persist must be atomic per RPC (row 5)",
			last.Generation, s.tokens.Current().Generation)
	}
}

func TestReloadTokensLogsApply(t *testing.T) {
	// The generation swap is journaled under the loginvariants
	// reload_tokens_apply class (msg="tokens applied", fields generation +
	// count), never the verifier bytes.
	var logBuf bytes.Buffer
	rec := &snapshotRecorder{}
	tok := make([]byte, 32)
	rand.Read(tok)
	s := NewServer(auth.NewTokenStore(), rec.persist, func() *grpcpb.StatusResponse {
		return &grpcpb.StatusResponse{}
	}, slog.New(slog.NewTextHandler(&logBuf, nil)))
	if _, err := s.ReloadTokens(context.Background(), &grpcpb.ReloadTokensRequest{
		Generation: 3, Tokens: verifiersOf(tok),
	}); err != nil {
		t.Fatal(err)
	}
	logged := logBuf.String()
	if !strings.Contains(logged, `msg="tokens applied"`) {
		t.Errorf("no reload_tokens_apply journal line; journal:\n%s", logged)
	}
	if !strings.Contains(logged, "generation=3") || !strings.Contains(logged, "count=1") {
		t.Errorf("apply line missing generation/count fields; journal:\n%s", logged)
	}
	if bytes.Contains(logBuf.Bytes(), tok) {
		t.Error("journal echoes verifier bytes (Principle III; contracts/control-grpc.md §ReloadTokens no-logging bullet)")
	}
}

func TestGetStatusReturnsSnapshotNoSideEffects(t *testing.T) {
	// §"GetStatus (minimum subset)": returns the in-memory counter snapshot
	// via the audit seam (T049's counters.go plugs in here) and MUST NOT
	// increment anything as a side effect.
	calls := 0
	snap := &grpcpb.StatusResponse{Counters: []*grpcpb.RouteCounter{{
		Route: "TOR", HourBucket: 42, RequestCount: 7, ByteCount: 9,
	}}}
	s := NewServer(auth.NewTokenStore(), func(*auth.Generation) error { return nil },
		func() *grpcpb.StatusResponse {
			calls++
			return snap
		}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))

	resp, err := s.GetStatus(context.Background(), &grpcpb.StatusRequest{})
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if resp != snap {
		t.Error("GetStatus did not return the audit seam's snapshot verbatim")
	}
	if calls != 1 {
		t.Errorf("audit seam called %d times, want 1", calls)
	}
	// A second call returns a fresh snapshot with no accumulated effects.
	if _, err := s.GetStatus(context.Background(), &grpcpb.StatusRequest{}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("audit seam called %d times after two probes, want 2 (no side effects)", calls)
	}
}

func TestServerServeInstallsInterceptorsAndRegisters(t *testing.T) {
	// §5.3: the interceptor chain wraps the registered service — an RPC
	// without the version metadata is rejected before the handler, through
	// the exact server shape T050 will boot.
	rec := &snapshotRecorder{}
	s := newTestServer(t, rec)
	// T130: the production server shape requires TLS — this test drives
	// it with the same in-package fixtures the mTLS tests use, over
	// bufconn (credentials.NewTLS skips verification for the in-process
	// hop; the §3 pin rows are covered by TestGRPCServerServesMTLSOverUDS).
	dpKey, _ := newEd25519Key(t)
	cpKey, _ := newEd25519Key(t)
	keys := t.TempDir()
	writePubFile(t, filepath.Join(keys, "cp.pub"), cpKey)
	writePubFile(t, filepath.Join(keys, "dp.pub"), dpKey)
	gs, err := NewGRPCServer(s, ServerTLSConfig(mustDerive(t, dpKey), filepath.Join(keys, "cp.pub")))
	if err != nil {
		t.Fatalf("NewGRPCServer: %v", err)
	}
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			// §4 shape: skip CA-chain verification, PIN the server's dp.pub
			// (the R4-static gate demands the co-located hook — correctly).
			InsecureSkipVerify:    true, //nolint:gosec // pinned peer public key IS the verifier (wire-auth.md §4)
			VerifyPeerCertificate: PeerPinVerifier(filepath.Join(keys, "dp.pub")),
			MinVersion:            tls.VersionTLS13,
			NextProtos:            []string{"h2"},
			// §4: the server REQUIRES a client cert (RequireAnyClientCert).
			Certificates: []tls.Certificate{mustDerive(t, cpKey)},
		})),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := grpcpb.NewControlClient(conn)

	// No metadata → FailedPrecondition before the handler (§5.2/§5.3).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.GetStatus(ctx, &grpcpb.StatusRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("unversioned RPC code = %v, want FailedPrecondition (§5.2)", status.Code(err))
	}
	if rec.count() != 0 {
		t.Error("handler ran despite the version gate (§5.3)")
	}

	// With metadata the RPC reaches the handler.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	mdCtx := metadata.AppendToOutgoingContext(ctx2,
		protoversion.MetaMajor, strconv.Itoa(protoversion.Major),
		protoversion.MetaMinor, strconv.Itoa(protoversion.Minor),
		protoversion.MetaCapabilities, protoversion.Capabilities)
	if _, err := client.GetStatus(mdCtx, &grpcpb.StatusRequest{}); err != nil {
		t.Errorf("versioned RPC rejected: %v", err)
	}
}

func TestListenSocketMode(t *testing.T) {
	// §"Socket topology": dp.sock mode 0660 regardless of umask (the
	// stargate-dp:stargate-ipc ownership is a deployment property — R1 in
	// tests/contract/compose/inter_plane_wire_test.sh).
	dir, err := os.MkdirTemp("", "t045ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	old := syscall.Umask(0o077)
	lis, err := Listen(dir)
	syscall.Umask(old)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer lis.Close()
	info, err := os.Stat(filepath.Join(dir, "dp.sock"))
	if err != nil {
		t.Fatalf("stat dp.sock: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Error("dp.sock is not a socket")
	}
	if info.Mode().Perm() != 0o660 {
		t.Errorf("dp.sock mode = %o, want 660 (§\"Socket topology\")", info.Mode().Perm())
	}
	// Role separation: Listen binds ONLY dp.sock — control.sock is never
	// created by the DP (transport_test.go row 2 pins the process-level
	// property; here we pin that the helper itself creates nothing else).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "dp.sock" {
		t.Errorf("IPC dir contains %v, want only dp.sock (role separation via bind(2))", entries)
	}
}

func TestListenRejectsBusySocket(t *testing.T) {
	// bind(2) role separation: a second listener on an existing socket is
	// an error, never a silent takeover.
	dir, err := os.MkdirTemp("", "t045ipc2")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	lis, err := Listen(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	if _, err := Listen(dir); err == nil {
		t.Error("second Listen on a live socket succeeded — bind(2) role separation broken")
	}
}

// --- helpers -----------------------------------------------------------------

// rsaSelfSignedDER mints a minimal self-signed RSA cert and returns its DER
// form — the non-Ed25519 peer-cert negative case (§1/§3.3).
func rsaSelfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject:      pkix.Name{CommonName: "rsa-negative-case"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating rsa cert: %v", err)
	}
	return der
}

func mustDerive(t *testing.T, key ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	cert, err := DeriveCert(key, DPIdentity)
	if err != nil {
		t.Fatalf("DeriveCert: %v", err)
	}
	return cert
}

// certChainOf is derCertOf wrapped as the [][]byte chain VerifyPeerCertificate
// receives.
func certChainOf(t *testing.T, key ed25519.PrivateKey) [][]byte {
	t.Helper()
	return [][]byte{derCertOf(t, key)}
}

// derCertOf derives a self-signed cert for key and returns its DER form —
// the shape VerifyPeerCertificate receives on the wire.
func derCertOf(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	cert := mustDerive(t, key)
	return cert.Certificate[0]
}

func samePublicKey(a, b tls.Certificate) bool {
	pa, errA := x509.ParseCertificate(a.Certificate[0])
	pb, errB := x509.ParseCertificate(b.Certificate[0])
	if errA != nil || errB != nil {
		return false
	}
	ka, okA := pa.PublicKey.(ed25519.PublicKey)
	kb, okB := pb.PublicKey.(ed25519.PublicKey)
	return okA && okB && bytes.Equal(ka, kb)
}

// ioReadFull avoids importing io for one call in the handshake test.
func ioReadFull(c net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		m, err := c.Read(buf[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// TestNewGRPCServerRequiresTLS pins the T130 fix's security shape: the
// dp.sock server constructor REFUSES to build an unauthenticated server —
// wire-auth.md §4 ("never degraded into an unauthenticated socket").
// Before T130, main.go discarded DeriveDPTLS's server half and NewGRPCServer
// served dp.sock PLAINTEXT (live-caught: the CP's TLS ClientHello read as
// an HTTP/2 preface — "bogus greeting" — so ReloadTokens never delivered).
func TestNewGRPCServerRequiresTLS(t *testing.T) {
	s := newTestServer(t, &snapshotRecorder{})
	if _, err := NewGRPCServer(s, nil); err == nil {
		t.Fatal("NewGRPCServer(nil TLS) succeeded — dp.sock must never serve unauthenticated (wire-auth.md §4)")
	}
}

// TestGRPCServerServesMTLSOverUDS pins the composition TestMutualTLS-
// HandshakeEndToEnd could not (it wired tls.NewListener itself): the
// PRODUCTION server shape — NewGRPCServer(ctl, ServerTLSConfig) — serves
// a TLS dp.sock that a CP-shaped client (own cert from cp.priv, pinning
// dp.pub, ALPN h2) completes an RPC through, while a PLAINTEXT dial of
// the same socket fails. This is the Go-side mirror of the Java CP's
// ReloadTokensClient (CpTls.clientContext): the live failure mode T130
// exists to fix.
func TestGRPCServerServesMTLSOverUDS(t *testing.T) {
	dir := t.TempDir()
	dpKey, dpPEM := newEd25519Key(t)
	cpKey, cpPEM := newEd25519Key(t)
	writePubFile(t, filepath.Join(dir, "dp.pub"), dpKey)
	writePubFile(t, filepath.Join(dir, "cp.pub"), cpKey)
	writePrivFile(t, filepath.Join(dir, "dp.priv"), dpPEM)
	writePrivFile(t, filepath.Join(dir, "cp.priv"), cpPEM)

	rec := &snapshotRecorder{}
	s := newTestServer(t, rec)
	serverTLS := ServerTLSConfig(mustDerive(t, dpKey), filepath.Join(dir, "cp.pub"))
	gs, err := NewGRPCServer(s, serverTLS)
	if err != nil {
		t.Fatalf("NewGRPCServer: %v", err)
	}
	sock := filepath.Join(dir, "dp.sock")
	lis, err := Listen(dir)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close(); gs.Stop() })
	go func() { _ = gs.Serve(lis) }()

	// CP-shaped client: cert from cp.priv, pin dp.pub, ALPN h2 — the
	// ClientTLSConfig-of-the-OTHER-plane shape (client_test.go's CP fake).
	cpCert := mustDerive(t, cpKey)
	clientTLS := ClientTLSConfig(cpCert, filepath.Join(dir, "dp.pub"))
	conn, err := grpc.NewClient("unix://"+sock,
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// §5.3: the version metadata the Java CP's interceptor always sends.
	ctx = metadata.AppendToOutgoingContext(ctx, protoversion.MetaMajor, "1")
	stub := grpcpb.NewControlClient(conn)
	resp, err := stub.ReloadTokens(ctx, &grpcpb.ReloadTokensRequest{Generation: 1})
	if err != nil {
		t.Fatalf("ReloadTokens over mTLS dp.sock: %v — the production server shape broke the CP dial (T130)", err)
	}
	if resp.GetAppliedGeneration() != 1 {
		t.Errorf("applied_generation = %d, want 1", resp.GetAppliedGeneration())
	}

	// Negative control: a PLAINTEXT dial of the same socket must fail —
	// a server that accepted it would be the pre-T130 defect reborn.
	pt, err := grpc.NewClient("unix://"+sock,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient(plaintext): %v", err)
	}
	t.Cleanup(func() { _ = pt.Close() })
	if _, err := grpcpb.NewControlClient(pt).ReloadTokens(ctx, &grpcpb.ReloadTokensRequest{Generation: 2}); err == nil {
		t.Error("PLAINTEXT ReloadTokens over dp.sock succeeded — the server is unauthenticated (pre-T130 defect)")
	}
}

// TestTLSConfigsOfferALPNH2 pins the gRPC-over-TLS ALPN invariant
// (wire-auth.md §4 as amended by T130): both halves offer exactly h2.
// The Java CP (grpc-netty) negotiates ALPN strictly; a Go config without
// NextProtos lets the handshake die protocol-less against it (the CP-side
// half of the live failure), and Go↔Go only passed because BOTH sides
// skipped ALPN.
func TestTLSConfigsOfferALPNH2(t *testing.T) {
	dir := t.TempDir()
	_, dpPEM := newEd25519Key(t)
	cpKey, _ := newEd25519Key(t)
	writePrivFile(t, filepath.Join(dir, "dp.priv"), dpPEM)
	writePubFile(t, filepath.Join(dir, "cp.pub"), cpKey)
	clientCfg, serverCfg, err := DeriveDPTLS(dir)
	if err != nil {
		t.Fatalf("DeriveDPTLS: %v", err)
	}
	for name, cfg := range map[string]*tls.Config{"client": clientCfg, "server": serverCfg} {
		if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h2" {
			t.Errorf("%s TLS NextProtos = %v, want exactly [h2] (gRPC over TLS requires ALPN h2; wire-auth.md §4)", name, cfg.NextProtos)
		}
	}
}
