// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// tls.go — the DP's inter-plane TLS material, consuming
// specs/001-tor-route/contracts/wire-auth.md VERBATIM (T095 §Acceptance #5):
// self-signed Ed25519 X.509 derivation from dp.priv (§2), peer public-key
// pinning against the peer's *.pub (§3), and the TLS-config invariants
// (§4). No wire-shape detail originates here — a gap in the contract lands
// as a wire-auth.md fix (T095 rework), never an invention in this file.
package controlclient

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"
)

// Identity is the X.509 subject identity a plane's derived cert carries
// (wire-auth.md §2.2). The CN is informational only; the URI SAN is
// defence-in-depth behind the §3 peer-pin, which remains the sole trust
// decision (§4.1).
type Identity struct {
	CommonName string
	SPIFFEID   string
}

// DPIdentity is the data plane's §2.2 identity: CN=stargate-dp,
// URI SAN spiffe://stargate.local/dp — the same `dp` token as the keyfile
// names (dp.priv/dp.pub), so every identifier names the same entity.
var DPIdentity = Identity{CommonName: "stargate-dp", SPIFFEID: "spiffe://stargate.local/dp"}

// CPIdentity is the control plane's §2.2 identity. It is not used by DP
// production code (the CP derives its own cert in Java, T038); it exists so
// the in-process tests can simulate the CP side of the wire with the same
// derivation code paths.
var CPIdentity = Identity{CommonName: "stargate-cp", SPIFFEID: "spiffe://stargate.local/cp"}

// Cert validity windows (§2.2) — fixed values so any change lands in a
// wire-auth.md review, not silently (the §2.2 note on the operator-visible
// 30-day window; SECURITY-DECISIONS.md T095 entry).
const (
	notBeforeSkew = -5 * time.Minute
	certValidity  = 30 * 24 * time.Hour
)

// DeriveCert derives the plane's self-signed X.509 v3 leaf from its own
// Ed25519 private key (§2.1) — in memory only, never persisted; re-derived
// on every process start (§6.2 transient-cert rotation). Field values per
// §2.2. A non-Ed25519 key is a derivation error (§1: Ed25519 is the only
// signature algorithm on this channel).
func DeriveCert(key crypto.Signer, id Identity) (tls.Certificate, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("tls: key is %T, want ed25519 (wire-auth.md §1)", key.Public())
	}
	spiffe, err := url.Parse(id.SPIFFEID)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls: parsing SPIFFE ID: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Version:               3, // §2.2: required for the SAN extension
		SerialNumber:          big.NewInt(0),
		SignatureAlgorithm:    x509.PureEd25519,
		Subject:               pkix.Name{CommonName: id.CommonName},
		Issuer:                pkix.Name{CommonName: id.CommonName}, // self-signed ⇒ Issuer == Subject
		NotBefore:             now.Add(notBeforeSkew),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, // §2.2: both roles
		DNSNames:              nil,                                                                        // §2.2: UDS peer verification does not use DNS
		URIs:                  []*url.URL{spiffe},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls: creating self-signed cert: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls: parsing just-created cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// LoadPrivateKey reads and parses the plane's PKCS#8 PEM private key
// (§1 key format, per scripts/subcommands/init). The caller (T050 boot)
// treats an error as a degraded-mode warning and keeps routing (§2.2 DP
// behaviour); the error names the path, never key bytes (Principle III).
func LoadPrivateKey(path string) (crypto.Signer, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tls: reading private key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("tls: %s contains no PEM block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tls: parsing %s: %w", path, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tls: %s holds a %T, not a signer", path, key)
	}
	return signer, nil
}

// LoadPeerPublicKey reads the pinned peer public key from a *.pub file and
// normalises it to the raw 32-byte Ed25519 form (§3.1 step 4: the pin
// compares raw keys, never PEM text or SPKI wrappers). The verifier re-reads
// through this function fresh from disk on every handshake (§3.1 step 3 —
// the property that makes §6.2 key rotation live without a peer restart);
// callers must not cache its result.
func LoadPeerPublicKey(path string) (ed25519.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tls: reading peer pin %s: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("tls: %s contains no PEM block", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("tls: parsing peer pin %s: %w", path, err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("tls: peer pin %s holds %T, want ed25519 (wire-auth.md §1)", path, parsed)
	}
	return pub, nil
}

// PeerPinVerifier returns the VerifyPeerCertificate hook that authenticates
// the peer by public-key pinning (§3.1): extract the raw Ed25519 key from
// the peer cert's leaf, re-read the pinned key fresh from disk, accept iff
// the two 32-byte keys are byte-equal. CA-chain validation is NOT used
// (§3) — the single-self-signed-cert design has no chain to build.
//
// The pinned file is read on EVERY invocation, never cached (§3.1 step 3).
// A chain of more than one cert is a contract violation (§1: chain length
// is exactly 1) and is rejected rather than pinned on its leaf.
func PeerPinVerifier(peerPubPath string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) != 1 {
			return fmt.Errorf("tls: peer presented %d certs, want exactly 1 (wire-auth.md §1)", len(rawCerts))
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("tls: parsing peer cert: %w", err)
		}
		peerKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("tls: peer cert key is %T, want ed25519 (wire-auth.md §1)", cert.PublicKey)
		}
		pinned, err := LoadPeerPublicKey(peerPubPath) // fresh from disk, every handshake (§3.1 step 3)
		if err != nil {
			return err
		}
		if !peerKey.Equal(pinned) {
			// §3.3: the handshake aborts (Go surfaces this as an
			// unknown-ca-class alert); no application RPC is dispatched.
			return errors.New("tls: peer public key does not match the pinned key (wire-auth.md §3.1)")
		}
		return nil
	}
}

// ClientTLSConfig is the §4 client configuration for the control.sock dial:
// our single in-memory cert as the client identity, the peer-pin hook as
// the sole trust decision against cp.pub, TLS 1.3 only.
//
// InsecureSkipVerify=true is required and load-bearing here: Go's
// crypto/tls couples the knob to the custom hook — with it false, the
// self-signed cert is rejected at the system-roots check BEFORE
// VerifyPeerCertificate runs; with it true, normal CA/hostname
// verification is skipped AND VerifyPeerCertificate still runs (§4). A
// configuration setting InsecureSkipVerify=true with no
// VerifyPeerCertificate callback is a contract violation (silent auth
// bypass) — the invariant test TestTLSConfigInvariants pins the pair.
func ClientTLSConfig(cert tls.Certificate, peerPubPath string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// wire-auth.md §4 (cited verbatim — see the comment above):
		// InsecureSkipVerify=true disables normal CA-chain + hostname
		// verification but STILL invokes VerifyPeerCertificate, which is
		// the sole trust decision here. Never unset, never shipped without
		// the pin hook alongside.
		InsecureSkipVerify:    true, //nolint:gosec // pinned peer public key IS the verifier (wire-auth.md §4)
		VerifyPeerCertificate: PeerPinVerifier(peerPubPath),
		MinVersion:            tls.VersionTLS13,
		// T130: gRPC over TLS requires ALPN h2 (wire-auth.md §4 as
		// amended). The Java CP (grpc-netty) negotiates ALPN strictly; a
		// protocol-less handshake dies against it. Go↔Go only ever passed
		// because BOTH sides skipped ALPN — mutually consistent, mutually
		// underspecified (the T063 lesson). The server config (below)
		// inherits this via the shared constructor.
		NextProtos: []string{"h2"},
	}
}

// ServerTLSConfig is the §4 server configuration for dp.sock: same cert,
// client auth REQUIRED (mTLS; a server that does not request a client cert
// is a contract violation), client certs pinned against cp.pub — the CP is
// the only legitimate dialer of dp.sock.
func ServerTLSConfig(cert tls.Certificate, peerPubPath string) *tls.Config {
	cfg := ClientTLSConfig(cert, peerPubPath)
	cfg.ClientAuth = tls.RequireAnyClientCert // §4: client auth REQUIRED; verification is the pin hook's job
	return cfg
}

// DeriveDPTLS is the boot-time one-shot (§2.1): read dp.priv, derive the
// single in-memory cert, and return the (client, server) TLS pair — the
// client half for the control.sock dial, the server half for dp.sock, both
// pinning cp.pub. The caller (T050) treats an error as a degraded-mode
// warning and keeps routing port 8881 (§2.2/§3.3; Constitution Principle
// II); without the TLS material the inter-plane gRPC surface does not come
// up at all — it is never degraded into an unauthenticated socket.
func DeriveDPTLS(keysDir string) (client, server *tls.Config, err error) {
	priv, err := LoadPrivateKey(keysPath(keysDir, "dp.priv"))
	if err != nil {
		return nil, nil, err
	}
	cert, err := DeriveCert(priv, DPIdentity)
	if err != nil {
		return nil, nil, err
	}
	pin := keysPath(keysDir, "cp.pub")
	if _, err := LoadPeerPublicKey(pin); err != nil {
		// Availability fail-fast for the operator: the per-handshake
		// re-read (§3.1 step 3) would surface this anyway, but a boot that
		// knows the pin file is missing says so now (§3.3 degraded mode).
		return nil, nil, err
	}
	return ClientTLSConfig(cert, pin), ServerTLSConfig(cert, pin), nil
}

func keysPath(keysDir, name string) string {
	return keysDir + "/" + name
}
