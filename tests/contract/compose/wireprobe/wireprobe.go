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
//	counters  — authenticated GetStatus response as JSON for T155's live
//	            completed-hour publication assertions (test harness only)
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
//	observer  — T191: authenticates to the Tor observer's health socket as
//	            the CP (cp.priv signs the challenge, observer.pub verifies
//	            the reply) and requires one health token; exit 0 iff the
//	            observer accepted this CP identity
//	observer-refused — the negative: exit 0 iff the observer greeted the
//	            caller and then closed without accepting it (a stale pin)
//	resume    — T155 (A-1): a TLS 1.3 session ticket offered across a CP
//	            key rotation; exit 0 iff the running DP resumes the ticket
//	            before the rotation (positive control) and, after it,
//	            completes no RPC for the old identity, resumed or full, while
//	            the rotated identity is accepted. Rotates cp.* itself (keys
//	            volume RW, CP stopped: §6.2 rotation order). See probeResume.
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
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

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
		fatal("usage: wireprobe <status|counters|major|minor|nomajor|wrongkey|proxy|rotate|resume|observer|observer-refused> [flags]")
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
	case "counters":
		err = probeCounters(*socket, *keysDir, *timeout)
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
	case "resume":
		err = probeResume(*socket, *keysDir, *timeout)
	case "observer", "observer-refused":
		path := *socket
		if path == "/run/stargate/dp.sock" {
			path = "/run/stargate-tor-observer/health.sock"
		}
		var accepted bool
		accepted, err = probeObserver(path, *keysDir, *timeout)
		if err == nil && accepted != (mode == "observer") {
			err = fmt.Errorf("observer accepted=%v, want %v", accepted, mode == "observer")
		}
	default:
		fatal("unknown mode %q", mode)
	}
	if err != nil {
		fatal("%s: %v", mode, err)
	}
	if mode != "counters" {
		fmt.Printf("wireprobe: %s OK\n", mode)
	}
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

func probeCounters(socket, keysDir string, d time.Duration) error {
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
	ctx = metadata.AppendToOutgoingContext(ctx, metaMajor, "1", metaMinor, "0", metaCaps, capsV1)
	response, err := cc.GetStatus(ctx, &grpcpb.StatusRequest{})
	if err != nil {
		return fmt.Errorf("authenticated GetStatus counters: %w", err)
	}
	encoded, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(response)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, string(encoded))
	return err
}

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

// probeObserver speaks the CP side of the observer challenge
// (foundation-boundaries.md T164): read OBS/1 + server nonce, send CP/1 +
// client nonce + the CP signature over the transcript, then require OK/1 +
// the observer's signature, verified against observer.pub. accepted=false
// with a nil error means the observer greeted the caller and closed without
// OK/1 (it refused the CP key); any other deviation is an error, so a missing
// socket can never pass as a refusal.
func probeObserver(socket, keysDir string, d time.Duration) (bool, error) {
	priv, err := loadSigner(keysDir + "/cp.priv")
	if err != nil {
		return false, err
	}
	observerPub, err := loadPublic(keysDir + "/observer.pub")
	if err != nil {
		return false, err
	}
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(d))
	var greeting [6 + 32]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil || string(greeting[:6]) != "OBS/1\n" {
		return false, fmt.Errorf("observer greeting: %v", err)
	}
	var clientNonce [32]byte
	if _, err := rand.Read(clientNonce[:]); err != nil {
		return false, err
	}
	transcript := append(append([]byte{}, greeting[6:]...), clientNonce[:]...)
	signature := ed25519.Sign(priv, append([]byte("stargate-observer/1 client\n"), transcript...))
	if _, err := conn.Write(append(append([]byte("CP/1\n"), clientNonce[:]...), signature...)); err != nil {
		return false, err
	}
	var reply [5 + ed25519.SignatureSize]byte
	n, err := io.ReadFull(conn, reply[:])
	if n == 0 && errors.Is(err, io.EOF) {
		return false, nil // closed without accepting: the observer refused this CP key
	}
	if err != nil || string(reply[:5]) != "OK/1\n" {
		return false, fmt.Errorf("observer reply after %d bytes: %v", n, err)
	}
	if !ed25519.Verify(observerPub, append([]byte("stargate-observer/1 server\n"), transcript...), reply[5:]) {
		return false, errors.New("observer proof does not verify against observer.pub")
	}
	if _, err := io.WriteString(conn, "HEALTH/1\n"); err != nil {
		return false, err
	}
	if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
		return false, err
	}
	token, err := io.ReadAll(io.LimitReader(conn, 64))
	if err != nil {
		return false, err
	}
	switch string(token) {
	case "READY/1\n", "NOT_READY/1\n", "UNAVAILABLE/1\n":
		return true, nil
	}
	return false, fmt.Errorf("observer token %q is not in the closed vocabulary", token)
}

// loadPublic reads a PKIX PEM Ed25519 public key (stargate-keys format).
func loadPublic(path string) (ed25519.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: %T, want ed25519", path, parsed)
	}
	return pub, nil
}

// --- resume: session tickets across a peer-pin rotation (T155 A-1) ---------

// countingCache wraps the client session cache and counts lookups that return
// a stored session, i.e. handshakes in which this client offered a ticket.
type countingCache struct {
	tls.ClientSessionCache
	mu     sync.Mutex
	offers int
}

func (c *countingCache) Get(key string) (*tls.ClientSessionState, bool) {
	session, ok := c.ClientSessionCache.Get(key)
	if ok && session != nil {
		c.mu.Lock()
		c.offers++
		c.mu.Unlock()
	}
	return session, ok
}

func (c *countingCache) offered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offers
}

// handshakeRecord is what the client saw of one TLS handshake.
type handshakeRecord struct {
	peerVerified bool
	resumed      bool
	err          error
}

// recordingCreds records every client handshake gRPC performs, so a result
// can name whether the server resumed the offered session.
type recordingCreds struct {
	credentials.TransportCredentials
	config *tls.Config
	mu     *sync.Mutex
	log    *[]handshakeRecord
}

func (r recordingCreds) ClientHandshake(ctx context.Context, authority string, raw net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// gRPC discards TLSInfo when Handshake fails. Observe this specific raw
	// connection after the normal current-DP-pin check, including error paths.
	// Go 1.26.3 validates selectedIdentity before DidResume; its callback runs
	// before server Finished, so this witnesses selected PSK, not completed TLS.
	cfg := r.config.Clone()
	verify := cfg.VerifyConnection
	var observed sync.Mutex
	var rec handshakeRecord
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if err := verify(state); err != nil {
			return err
		}
		observed.Lock()
		rec.peerVerified, rec.resumed = true, state.DidResume
		observed.Unlock()
		return nil
	}
	conn, info, err := credentials.NewTLS(cfg).ClientHandshake(ctx, authority, raw)
	observed.Lock()
	rec.err = err
	r.mu.Lock()
	*r.log = append(*r.log, rec)
	r.mu.Unlock()
	observed.Unlock()
	return conn, info, err
}

func (r recordingCreds) Clone() credentials.TransportCredentials {
	return recordingCreds{TransportCredentials: r.TransportCredentials.Clone(), config: r.config.Clone(), mu: r.mu, log: r.log}
}

// resumeAttempt is one fresh gRPC connection (one TLS handshake) and one
// GetStatus with correct §5 metadata.
type resumeAttempt struct {
	handshakes []handshakeRecord
	offered    bool  // the client offered a cached ticket
	rpcErr     error // nil: the DP accepted the peer and answered
}

func (a resumeAttempt) String() string {
	first := "none"
	if len(a.handshakes) > 0 {
		first = fmt.Sprintf("pin_verified=%v resumed=%v", a.handshakes[0].peerVerified, a.handshakes[0].resumed)
		if a.handshakes[0].err != nil {
			first += " failed: " + a.handshakes[0].err.Error()
		}
	}
	rpc := "answered"
	if a.rpcErr != nil {
		rpc = "refused: " + status.Code(a.rpcErr).String()
	}
	return fmt.Sprintf("ticket_offered=%v handshakes=%d first_handshake=[%s] rpc=%s", a.offered, len(a.handshakes), first, rpc)
}

func attemptStatus(socket, keysDir string, cert tls.Certificate, cache *countingCache, d time.Duration) resumeAttempt {
	cfg := clientConfig(cert, keysDir+"/dp.pub")
	// The client verifier must also hold on resumption (the DP's dp.pub is
	// not rotated here; VerifyPeerCertificate alone would be skipped).
	cfg.VerifyPeerCertificate = nil
	pin := pinVerifier(keysDir + "/dp.pub")
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		raw := make([][]byte, 0, len(state.PeerCertificates))
		for _, cert := range state.PeerCertificates {
			raw = append(raw, cert.Raw)
		}
		return pin(raw, nil)
	}
	// A fixed ServerName keys the session cache, so every attempt with the
	// same cache looks up the same ticket.
	cfg.ServerName = "stargate-dp"
	before := 0
	if cache != nil {
		cfg.ClientSessionCache = cache
		before = cache.offered()
	}
	var mu sync.Mutex
	var log []handshakeRecord
	creds := recordingCreds{TransportCredentials: credentials.NewTLS(cfg), config: cfg, mu: &mu, log: &log}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(creds))
	if err != nil {
		return resumeAttempt{rpcErr: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	_, rpcErr := getStatus(ctx, grpcpb.NewControlClient(conn), "1", "0")
	cancel()
	_ = conn.Close()
	mu.Lock()
	defer mu.Unlock()
	return resumeAttempt{handshakes: append([]handshakeRecord(nil), log...), offered: cache != nil && cache.offered() > before, rpcErr: rpcErr}
}

// probeResume is T155's live A-1 check (wire-auth.md §2.4 "Revocation/
// rotation"; Constitution II: identity rotation cannot become an auth bypass).
// The Go DP keeps TLS 1.3 resumption and must re-check the CURRENT cp.pub on a
// resumed handshake (VerifyConnection, T135). The sequence:
//
//  1. old CP identity, full handshake, GetStatus answered (a ticket is issued);
//  2. same identity and cache: the DP resumed the session and answered.
//     Positive control: the live DP issues and accepts tickets. Step 4 must
//     independently witness selected PSK; its error does not prove a cause;
//  3. rotate cp.priv/cp.pub in place (§6.2; the CP must be stopped);
//  4. old identity offers the step-1 ticket: no RPC may be answered, and the
//     handshake must show the resumed path (not a declined ticket). A DP that
//     skipped the pin check on resumed handshakes (VerifyPeerCertificate only,
//     the T135 defect) answers it, so this step is the falsifier;
//  5. old identity, no cache (full handshake): no RPC may be answered;
//  6. rotated identity, full handshake: answered (the DP re-read the pin and
//     is serving, so steps 4-5 are refusals, not an outage).
func probeResume(socket, keysDir string, d time.Duration) error {
	oldPriv, err := loadSigner(keysDir + "/cp.priv")
	if err != nil {
		return err
	}
	oldCert, err := selfSigned(oldPriv, "stargate-cp")
	if err != nil {
		return err
	}
	cache := &countingCache{ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	report := func(step string, a resumeAttempt) { fmt.Printf("wireprobe: resume %s: %s\n", step, a) }

	full := attemptStatus(socket, keysDir, oldCert, cache, d)
	report("1-old-full", full)
	if full.rpcErr != nil || len(full.handshakes) != 1 || !full.handshakes[0].peerVerified || full.handshakes[0].resumed {
		return fmt.Errorf("step 1: the old identity's full handshake was not answered: %v", full.rpcErr)
	}
	resumed := attemptStatus(socket, keysDir, oldCert, cache, d)
	report("2-old-resumed-before-rotation", resumed)
	if resumed.rpcErr != nil || !resumed.offered || len(resumed.handshakes) != 1 || !resumed.handshakes[0].peerVerified || !resumed.handshakes[0].resumed {
		return errors.New("step 2 (positive control): the DP did not resume the offered ticket before rotation; the post-rotation result would not test resumption")
	}
	if err := rotateCPKeys(keysDir); err != nil {
		return fmt.Errorf("step 3: rotation: %w", err)
	}
	fmt.Println("wireprobe: resume 3-rotated: cp.priv/cp.pub replaced")
	stale := attemptStatus(socket, keysDir, oldCert, cache, d)
	report("4-old-ticket-after-rotation", stale)
	if !stale.offered {
		return errors.New("step 4: the client did not offer the cached ticket; the probe did not exercise resumption")
	}
	if stale.rpcErr == nil {
		return errors.New("step 4: the DP answered the OLD CP identity on a resumed session after rotation — resumption bypassed the current pin (wire-auth.md §2.4, §3.1)")
	}
	// A cached ticket and an error cannot distinguish selected PSK from an
	// abort or declined ticket. Require this raw attempt's pin-verified witness;
	// neither prior success nor a later retry supplies it (Constitution VII).
	if h := stale.handshakes; len(h) != 1 || !h[0].peerVerified || !h[0].resumed {
		return errors.New("step 4: the DP did not take the resumed path with a current-DP-pin-verified witness (ticket declined, incomplete flight, abort or ambiguous retries); the refusal does not test resumption")
	}
	oldFull := attemptStatus(socket, keysDir, oldCert, nil, d)
	report("5-old-full-after-rotation", oldFull)
	if oldFull.rpcErr == nil {
		return errors.New("step 5: the DP answered the OLD CP identity on a full handshake after rotation")
	}
	newPriv, err := loadSigner(keysDir + "/cp.priv")
	if err != nil {
		return err
	}
	newCert, err := selfSigned(newPriv, "stargate-cp")
	if err != nil {
		return err
	}
	rotated := attemptStatus(socket, keysDir, newCert, nil, d)
	report("6-rotated-full", rotated)
	if rotated.rpcErr != nil {
		return fmt.Errorf("step 6: the rotated identity was not answered: %v", rotated.rpcErr)
	}
	return nil
}

// protomajor is the runtime-tier major under test (the proto package is
// stargate.v1 — structural row S6 pins the source of this constant).
const protomajor = 1
