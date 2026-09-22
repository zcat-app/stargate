// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/zcat-app/stargate/data-plane/internal/auth"
	"github.com/zcat-app/stargate/data-plane/internal/forward"
	"github.com/zcat-app/stargate/data-plane/internal/listener"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc/credentials"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func datedCert(t *testing.T, key ed25519.PrivateKey, before, after time.Time) tls.Certificate {
	t.Helper()
	cert := mustDerive(t, key)
	leaf := *cert.Leaf
	leaf.NotBefore, leaf.NotAfter = before, after
	der, err := x509.CreateCertificate(rand.Reader, &leaf, &leaf, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate = [][]byte{der}
	cert.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Spec-derived falsifier: matching keys alone never authorize an invalid date,
// including the restored PeerCertificates supplied during Go TLS resumption.
func TestPeerValidityFullAndResumed(t *testing.T) {
	key, _ := newEd25519Key(t)
	pin := filepath.Join(t.TempDir(), "peer.pub")
	writePubFile(t, pin, key)
	now := time.Now()
	for _, tc := range []struct {
		name          string
		before, after time.Time
		valid         bool
	}{
		{"current", now.Add(-time.Hour), now.Add(time.Hour), true},
		{"expired", now.Add(-time.Hour), now.Add(-time.Second), false},
		{"future", now.Add(time.Minute), now.Add(time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := datedCert(t, key, tc.before, tc.after)
			for _, resumed := range []bool{false, true} {
				err := PeerPinConnectionVerifier(pin)(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert.Leaf}, DidResume: resumed})
				if (err == nil) != tc.valid {
					t.Errorf("resumed=%v accepted=%v want %v", resumed, err == nil, tc.valid)
				}
			}
		})
	}
}

func TestDPIdentityRenewsAfterLongCPOutage(t *testing.T) {
	dir := t.TempDir()
	dp, pem := newEd25519Key(t)
	cp, _ := newEd25519Key(t)
	writePrivFile(t, filepath.Join(dir, "dp.priv"), pem)
	writePubFile(t, filepath.Join(dir, "dp.pub"), dp)
	writePubFile(t, filepath.Join(dir, "cp.pub"), cp)
	client, server, err := DeriveDPTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(31 * 24 * time.Hour)
	for name, cfg := range map[string]*tls.Config{"client": client, "server": server} {
		t.Run(name, func(t *testing.T) {
			// First test the before-expiry threshold, then a much longer outage.
			beforeExpiry := time.Now().Add(29*24*time.Hour + time.Hour)
			cfg.Time = func() time.Time { return beforeExpiry }
			if cfg.GetClientCertificate != nil {
				cert, e := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
				if e != nil {
					t.Fatal(e)
				}
				if !cert.Leaf.NotAfter.After(beforeExpiry.Add(29 * 24 * time.Hour)) {
					t.Fatal("identity not renewed before expiry")
				}
			}
			future = time.Now().Add(65 * 24 * time.Hour)
			cfg.Time = func() time.Time { return future }
			var cert *tls.Certificate
			if len(cfg.Certificates) > 0 {
				cert = &cfg.Certificates[0]
			}
			if name == "client" && cfg.GetClientCertificate != nil {
				cert, err = cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
			}
			if name == "server" && cfg.GetCertificate != nil {
				cert, err = cfg.GetCertificate(&tls.ClientHelloInfo{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if !cert.Leaf.NotAfter.After(future.Add(29 * 24 * time.Hour)) {
				t.Fatal("identity was not renewed before presentation after CP outage")
			}
			if !cert.Leaf.PublicKey.(ed25519.PublicKey).Equal(dp.Public()) {
				t.Fatal("renewal changed pinned key")
			}
		})
	}
}

// An uncooperative authenticated peer need not send GOAWAY or any bytes:
// each local endpoint must close an idle transport on its own deadline.
func TestTransportLifetimeBothRoles(t *testing.T) {
	for _, localServer := range []bool{false, true} {
		t.Run(fmt.Sprint(localServer), func(t *testing.T) {
			dir := t.TempDir()
			cp, _ := newEd25519Key(t)
			dp, _ := newEd25519Key(t)
			writePubFile(t, filepath.Join(dir, "cp.pub"), cp)
			writePubFile(t, filepath.Join(dir, "dp.pub"), dp)
			serverCfg := ServerTLSConfig(mustDerive(t, dp), filepath.Join(dir, "cp.pub"))
			clientCfg := ClientTLSConfig(mustDerive(t, cp), filepath.Join(dir, "dp.pub"))
			serverCreds := credentials.NewTLS(serverCfg)
			clientCreds := credentials.NewTLS(clientCfg)
			if localServer {
				serverCreds = transportCredentials(serverCfg, 50*time.Millisecond)
			} else {
				clientCreds = transportCredentials(clientCfg, 50*time.Millisecond)
			}
			a, b := net.Pipe()
			t.Cleanup(func() { a.Close(); b.Close() })
			ready := make(chan net.Conn, 1)
			go func() {
				conn, _, err := serverCreds.ServerHandshake(a)
				if err != nil {
					a.Close()
					ready <- nil
					return
				}
				ready <- conn
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			client, _, err := clientCreds.ClientHandshake(ctx, "localhost", b)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server := <-ready
			if server == nil {
				t.Fatal("server handshake failed")
			}
			defer server.Close()
			local := client
			if localServer {
				local = server
			}
			local.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			_, err = local.Read(make([]byte, 1))
			if err == nil {
				t.Fatal("idle transport remained readable")
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				t.Fatal("transport survived its mandatory lifetime")
			}
		})
	}
}

func TestExpiredSessionRejectedOnRealResumptionBothRoles(t *testing.T) {
	for _, serverRole := range []bool{true, false} {
		t.Run(fmt.Sprint(serverRole), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			cp, _ := newEd25519Key(t)
			dp, _ := newEd25519Key(t)
			writePubFile(t, filepath.Join(dir, "cp.pub"), cp)
			writePubFile(t, filepath.Join(dir, "dp.pub"), dp)
			expires := time.Now().Add(time.Hour).Truncate(time.Second)
			cpCert, dpCert := mustDerive(t, cp), mustDerive(t, dp)
			if serverRole {
				cpCert = datedCert(t, cp, time.Now().Add(-time.Hour), expires)
			} else {
				dpCert = datedCert(t, dp, time.Now().Add(-time.Hour), expires)
			}
			sc := ServerTLSConfig(dpCert, filepath.Join(dir, "cp.pub"))
			cc := ClientTLSConfig(cpCert, filepath.Join(dir, "dp.pub"))
			cc.ServerName = "peer"
			cc.ClientSessionCache = tls.NewLRUClientSessionCache(1)
			observed := make(chan bool, 8)
			local := cc
			if serverRole {
				local = sc
			}
			var clockOffset atomic.Int64
			peerPath := filepath.Join(dir, "dp.pub")
			if serverRole {
				peerPath = filepath.Join(dir, "cp.pub")
			}
			// Keep TLS ticket retention time fixed while advancing the authorization clock;
			// otherwise crypto/tls itself falls back to a full handshake for expired tickets.
			check := peerPinConnectionVerifier(peerPath, func() time.Time { return time.Now().Add(time.Duration(clockOffset.Load())) })
			local.VerifyConnection = func(s tls.ConnectionState) error { observed <- s.DidResume; return check(s) }
			lis, err := net.Listen("unix", filepath.Join(dir, "tls.sock"))
			if err != nil {
				t.Fatal(err)
			}
			defer lis.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					raw, e := lis.Accept()
					if e != nil {
						return
					}
					conn := tls.Server(raw, sc)
					conn.SetDeadline(time.Now().Add(time.Second))
					b := make([]byte, 1)
					if _, e = io.ReadFull(conn, b); e == nil {
						conn.Write(b)
					}
					raw.Close()
				}
			}()
			defer func() { lis.Close(); <-done }()
			probe := func() error {
				raw, e := net.Dial("unix", lis.Addr().String())
				if e != nil {
					return e
				}
				defer raw.Close()
				conn := tls.Client(raw, cc)
				conn.SetDeadline(time.Now().Add(time.Second))
				if _, e = conn.Write([]byte{42}); e != nil {
					return e
				}
				_, e = io.ReadFull(conn, make([]byte, 1))
				return e
			}
			for i := 0; i < 2; i++ {
				if err = probe(); err != nil {
					t.Fatal(err)
				}
				if resumed := <-observed; resumed != (i == 1) {
					t.Fatalf("handshake%d resumed=%v", i, resumed)
				}
			}
			clockOffset.Store(int64(2 * time.Hour))
			if probe() == nil {
				t.Fatal("expired restored identity accepted")
			}
			if !<-observed {
				t.Fatal("negative test did not exercise actual resumption")
			}
		})
	}
}

type routingCounters struct{}

func (routingCounters) AuthPassedRequest()       {}
func (routingCounters) AddForwardedBytes(uint64) {}

// Renewal and IPC loss must neither expire the retained token generation nor
// interrupt an existing production byte pipe. The local sidecar is an echo
// fixture: this proves transport/routing independence, not live Tor anonymity.
func TestRoutingSurvivesRenewalDuringCPOutage(t *testing.T) {
	dir := writeKeysDir(t, newKeyFixture(t), newKeyFixture(t))
	clientTLS, _, err := DeriveDPTLS(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cp, err := NewClient(ClientConfig{ControlSocket: filepath.Join(dir, "absent.sock"), TLS: clientTLS,
		Sink: &recordingSink{}, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), fastBackoff: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cp.conn.Close()
	done := make(chan struct{})
	go func() { defer close(done); cp.Run(ctx) }()
	defer func() { cancel(); <-done }()
	upstream, err := net.Listen("unix", filepath.Join(dir, "tor.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		for {
			conn, e := upstream.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				read := func(n int) []byte {
					b := make([]byte, n)
					_, e := io.ReadFull(conn, b)
					if e != nil {
						return nil
					}
					return b
				}
				h := read(2)
				if h == nil {
					return
				}
				if read(int(h[1])) == nil {
					return
				}
				conn.Write([]byte{5, 2})
				h = read(2)
				if h == nil {
					return
				}
				if read(int(h[1])) == nil {
					return
				}
				h = read(1)
				if h == nil {
					return
				}
				if read(int(h[0])) == nil {
					return
				}
				conn.Write([]byte{1, 0})
				h = read(4)
				if h == nil || h[3] != 3 {
					return
				}
				h = read(1)
				if h == nil {
					return
				}
				if read(int(h[0])+2) == nil {
					return
				}
				conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				io.Copy(conn, conn)
			}()
		}
	}()
	store := auth.NewTokenStore()
	var pepper [auth.PepperLen]byte
	token := "0123456789abcdef0123456789abcdef"
	mac := hmac.New(sha256.New, pepper[:])
	mac.Write([]byte(token))
	store.Swap(&auth.Generation{Generation: 7, Verifiers: [][]byte{mac.Sum(nil)}})
	route, err := net.Listen("unix", filepath.Join(dir, "route.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	deps := &listener.Deps{Auth: auth.NewTokenVerifier(pepper, store), Forward: forward.New("unix://"+upstream.Addr().String(), routingCounters{}), Audit: routingCounters{}}
	go func() {
		for {
			conn, e := route.Accept()
			if e != nil {
				return
			}
			go listener.HandleConn(conn, deps)
		}
	}()
	dial := func() net.Conn {
		d, e := proxy.SOCKS5("unix", route.Addr().String(), &proxy.Auth{User: "test-partition", Password: token}, proxy.Direct)
		if e != nil {
			t.Fatal(e)
		}
		conn, e := d.Dial("tcp", "example.invalid:443")
		if e != nil {
			t.Fatal(e)
		}
		return conn
	}
	echo := func(c net.Conn) {
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, e := c.Write([]byte("opaque")); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 6)
		if _, e := io.ReadFull(c, b); e != nil {
			t.Fatal(e)
		}
		if string(b) != "opaque" {
			t.Fatal("pipe changed bytes")
		}
	}
	established := dial()
	defer established.Close()
	echo(established)
	future := time.Now().Add(31 * 24 * time.Hour)
	clientTLS.Time = func() time.Time { return future }
	renewed, err := clientTLS.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if !renewed.Leaf.NotAfter.After(future) {
		t.Fatal("renewal failed")
	}
	echo(established)
	fresh := dial()
	defer fresh.Close()
	echo(fresh)
	if store.Current().Generation != 7 {
		t.Fatal("IPC outage changed retained auth generation")
	}
}
