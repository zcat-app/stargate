// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Command wireprobe is the R4-R9 runtime-tier probe for
// tests/contract/compose/inter_plane_wire_test.sh (the T095 runtime lift,
// authored by T045 — the first impl ticket whose diff turned the gate red).
// It runs INSIDE a container mounted with the stargate-ipc volume and (as
// uid 5101:5100) the stargate-keys volume, i.e. as the control plane's
// identity, and exercises the inter-plane wire contract from OUTSIDE the
// code under test:
//
//	status    — full mTLS GetStatus with correct §5 metadata (positive path;
//	            after R9's key rotation this is also the per-handshake
//	            pin-re-read proof: a running DP accepts the new CP identity)
//	major     — GetStatus with x-stargate-proto-major=-major; exit 0 iff the
//	            §5.2 rejection rule holds (FailedPrecondition unless major==1)
//	minor     — GetStatus with minor=-minor, major=1; exit 0 iff accepted
//	            (additive minors are compatible, wire-auth.md §5.2)
//	nomajor   — GetStatus with the major key absent; exit 0 iff rejected
//	wrongkey  — presents a rogue client key; exit 0 iff the DP aborts the
//	            handshake (wire-auth.md §3.3)
//	proxy     — host-side SOCKS5 liveness probe against 127.0.0.1:8881
//	            (R8: the listener + auth surface survive a CP restart);
//	            expects the auth-failure reply 01 FF (no valid token)
//	rotate    — generates a fresh Ed25519 keypair and installs it as
//	            cp.priv/cp.pub atomically (write-tmp + rename, §6.2
//	            rotation order); run as 5101:5100 with the keys volume RW
//
// TLS is deliberately REIMPLEMENTED here instead of importing
// data-plane/internal/controlclient: Go's internal-package rule already
// forbids the import from tests/contract, and an independent outside view
// is what makes this a contract probe — a bug shared with the
// implementation would hide from both.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
)

const (
	metaMajor   = "x-stargate-proto-major"
	metaMinor   = "x-stargate-proto-minor"
	metaCaps    = "x-stargate-capabilities"
	capsV1      = "reload-tokens,watch-events,get-status-minimum"
	defaultKeys = "/etc/stargate/keys"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: wireprobe <status|major|minor|nomajor|wrongkey|proxy|rotate> [flags]")
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	socket := fs.String("socket", "/run/stargate/dp.sock", "unix socket path to dial")
	keysDir := fs.String("keys-dir", defaultKeys, "stargate-keys mount (cp.priv/cp.pub/dp.pub)")
	major := fs.Int("major", 1, "x-stargate-proto-major to send (major mode)")
	minor := fs.Int("minor", 0, "x-stargate-proto-minor to send (minor mode)")
	proxyAddr := fs.String("proxy-addr", "127.0.0.1:8881", "host:port for proxy mode")
	timeout := fs.Duration("timeout", 15*time.Second, "per-RPC deadline")
	_ = fs.Parse(os.Args[2:])

	var err error
	switch mode {
	case "status":
		err = probeStatus(*socket, *keysDir, 1, 0, *timeout)
	case "major":
		err = probeMajor(*socket, *keysDir, *major, *timeout)
	case "minor":
		err = probeMinor(*socket, *keysDir, *minor, *timeout)
	case "nomajor":
		err = probeNoMajor(*socket, *keysDir, *timeout)
	case "wrongkey":
		err = probeWrongKey(*socket, *keysDir, *timeout)
	case "proxy":
		err = probeProxy(*proxyAddr)
	case "rotate":
		err = rotateCPKeys(*keysDir)
	default:
		fatal("unknown mode %q", mode)
	}
	if err != nil {
		fatal("%s: %v", mode, err)
	}
	fmt.Printf("wireprobe: %s OK\n", mode)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "wireprobe: FAIL: "+format+"\n", args...)
	os.Exit(1)
}

// --- probe-side wire contract (independent outside view) ---------------------

// loadSigner reads a PKCS#8 PEM private key (stargate-keys format).
func loadSigner(path string) (ed25519.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: %T, want ed25519", path, key)
	}
	return priv, nil
}

// selfSigned derives the minimal self-signed Ed25519 cert (wire-auth.md §2.2
// field values — same shape as the planes derive; the identity is whatever
// key material this probe presents).
func selfSigned(key ed25519.PrivateKey, cn string) (tls.Certificate, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return tls.Certificate{}, errors.New("not an ed25519 key")
	}
	tmpl := &x509.Certificate{
		Version:               3,
		SerialNumber:          big.NewInt(0),
		SignatureAlgorithm:    x509.PureEd25519,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// pinVerifier is the §3.1 peer-pin hook: raw 32-byte Ed25519 key from the
// peer cert, byte-equal against the pinned *.pub read fresh per handshake.
func pinVerifier(peerPubPath string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) != 1 {
			return fmt.Errorf("peer sent %d certs, want 1", len(rawCerts))
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		peerKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("peer key %T, want ed25519", cert.PublicKey)
		}
		pemBytes, err := os.ReadFile(peerPubPath)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return fmt.Errorf("%s: no PEM block", peerPubPath)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		pinned, ok := parsed.(ed25519.PublicKey)
		if !ok || !peerKey.Equal(pinned) {
			return errors.New("peer public key does not match the pinned key")
		}
		return nil
	}
}

// clientConfig is the §4 probe client config: own cert + pin hook + TLS 1.3.
func clientConfig(cert tls.Certificate, peerPub string) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, // see wire-auth.md §4: the pin hook is the verifier
		VerifyPeerCertificate: pinVerifier(peerPub),
		MinVersion:            tls.VersionTLS13,
	}
}

// dialControl connects to the DP's dp.sock as the CP identity (uid-5101
// key material) and returns a Control client.
func dialControl(socket, keysDir string, cert tls.Certificate) (grpcpb.ControlClient, func(), error) {
	cfg := clientConfig(cert, keysDir+"/dp.pub")
	conn, err := grpc.NewClient("unix://"+socket,
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, nil, err
	}
	return grpcpb.NewControlClient(conn), func() { _ = conn.Close() }, nil
}

// getStatus sends GetStatus with the given version metadata.
func getStatus(ctx context.Context, cc grpcpb.ControlClient, major, minor string) (codes.Code, error) {
	ctx = metadata.AppendToOutgoingContext(ctx,
		metaMajor, major, metaMinor, minor, metaCaps, capsV1)
	_, err := cc.GetStatus(ctx, &grpcpb.StatusRequest{})
	return status.Code(err), err
}

// --- modes -------------------------------------------------------------------

func probeStatus(socket, keysDir string, major, minor int, d time.Duration) error {
	priv, err := loadSigner(keysDir + "/cp.priv")
	if err != nil {
		return err
	}
	cert, err := selfSigned(priv, "stargate-cp")
	if err != nil {
		return err
	}
	cc, closeFn, err := dialControl(socket, keysDir, cert)
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	code, err := getStatus(ctx, cc, strconv.Itoa(major), strconv.Itoa(minor))
	if err != nil && code != codes.OK {
		return fmt.Errorf("GetStatus with correct metadata: code=%v err=%v", code, err)
	}
	return nil
}

func probeMajor(socket, keysDir string, major int, d time.Duration) error {
	priv, err := loadSigner(keysDir + "/cp.priv")
	if err != nil {
		return err
	}
	cert, err := selfSigned(priv, "stargate-cp")
	if err != nil {
		return err
	}
	cc, closeFn, err := dialControl(socket, keysDir, cert)
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	code, err := getStatus(ctx, cc, strconv.Itoa(major), "0")
	if major == protomajor {
		// The compiled-in v1 major must be accepted.
		if code != codes.OK {
			return fmt.Errorf("major %d accepted-expected but got code=%v err=%v", major, code, err)
		}
		return nil
	}
	if code != codes.FailedPrecondition {
		return fmt.Errorf("major %d: code=%v, want FailedPrecondition (wire-auth.md §5.2)", major, code)
	}
	return nil
}

func probeMinor(socket, keysDir string, minor int, d time.Duration) error {
	priv, err := loadSigner(keysDir + "/cp.priv")
	if err != nil {
		return err
	}
	cert, err := selfSigned(priv, "stargate-cp")
	if err != nil {
		return err
	}
	cc, closeFn, err := dialControl(socket, keysDir, cert)
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	// Additive minors are compatible: any minor with the current major is
	// accepted (wire-auth.md §5.2; arch §5.3).
	code, err := getStatus(ctx, cc, "1", strconv.Itoa(minor))
	if code != codes.OK {
		return fmt.Errorf("minor %d: code=%v err=%v, want accepted (additive minor)", minor, code, err)
	}
	return nil
}

func probeNoMajor(socket, keysDir string, d time.Duration) error {
	priv, err := loadSigner(keysDir + "/cp.priv")
	if err != nil {
		return err
	}
	cert, err := selfSigned(priv, "stargate-cp")
	if err != nil {
		return err
	}
	cc, closeFn, err := dialControl(socket, keysDir, cert)
	if err != nil {
		return err
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	// Deliberately WITHOUT the metadata keys.
	_, err = cc.GetStatus(ctx, &grpcpb.StatusRequest{})
	if code := status.Code(err); code != codes.FailedPrecondition {
		return fmt.Errorf("metadata-less GetStatus: code=%v, want FailedPrecondition (§5.2)", code)
	}
	return nil
}

func probeWrongKey(socket, keysDir string, d time.Duration) error {
	// Rogue client identity: the DP pins its clients against cp.pub, so the
	// handshake must abort (§3.3) regardless of what the probe sends after.
	_, rogue, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	cert, err := selfSigned(rogue, "rogue-peer")
	if err != nil {
		return err
	}
	cc, closeFn, err := dialControl(socket, keysDir, cert)
	if err != nil {
		return err // transport rejected the handshake — correct
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	_, err = cc.GetStatus(ctx, &grpcpb.StatusRequest{})
	if err == nil {
		return errors.New("rogue-key client completed an RPC — DP accepted an unpinned peer (§3.3 contract violation)")
	}
	return nil // any RPC failure is the abort surfacing
}

func probeProxy(addr string) error {
	// R8 liveness: the DP's proxy listener + auth surface answer on 8881
	// even with the CP down. No valid token is presented, so the correct
	// reply is the RFC 1929 auth-failure shape 01 FF (contracts/
	// socks5-auth.md) — proof the listener is alive AND authenticating.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("proxy listener unreachable: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return fmt.Errorf("method negotiation: %w", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x02 {
		return fmt.Errorf("method selection % x, want 05 02", greeting)
	}
	req := []byte{0x01, 0x04, 'p', 'r', 'o', 'b', 0x03, 'b', 'a', 'd'}
	if _, err := conn.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("auth reply: %w", err)
	}
	if reply[0] != 0x01 || reply[1] != 0xFF {
		return fmt.Errorf("auth reply % x, want 01 ff (auth-failure shape)", reply)
	}
	return nil
}

func rotateCPKeys(keysDir string) error {
	// §6.2 rotation: fresh Ed25519 keypair, write-tmp + rename for BOTH
	// files, modes/ownership per §6.1. Run as 5101:5100 with the keys
	// volume mounted RW. openssl is avoided so the probe is the only tool
	// needed; Go's crypto generates the PKCS#8/SPKI PEMs directly.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	privTmp := keysDir + "/.cp.priv.new"
	pubTmp := keysDir + "/.cp.pub.new"
	if err := os.WriteFile(privTmp, privPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pubTmp, pubPEM, 0o644); err != nil {
		return err
	}
	// Rename is atomic within the volume; the rotated plane must be DOWN
	// during the rename per §6.2 (the R9 row stops the CP first).
	if err := os.Rename(privTmp, keysDir+"/cp.priv"); err != nil {
		return err
	}
	if err := os.Rename(pubTmp, keysDir+"/cp.pub"); err != nil {
		return err
	}
	return nil
}

// protomajor is the runtime-tier major under test (the proto package is
// stargate.v1 — structural row S6 pins the source of this constant).
const protomajor = 1
