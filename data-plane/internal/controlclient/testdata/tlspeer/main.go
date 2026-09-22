// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// Synthetic Go peer for the Java cross-plane tests. No deployed keys or network.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/zcat-app/stargate/data-plane/internal/auth"
	"github.com/zcat-app/stargate/data-plane/internal/controlclient"
	pb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
func certAt(key ed25519.PrivateKey, date string) tls.Certificate {
	cert := must(controlclient.DeriveCert(key, controlclient.DPIdentity))
	leaf := *cert.Leaf
	switch date {
	case "expired":
		leaf.NotBefore = time.Now().Add(-48 * time.Hour)
		leaf.NotAfter = time.Now().Add(-time.Hour)
	case "future":
		leaf.NotBefore = time.Now().Add(time.Hour)
		leaf.NotAfter = time.Now().Add(48 * time.Hour)
	}
	cert.Certificate = [][]byte{must(x509.CreateCertificate(rand.Reader, &leaf, &leaf, key.Public(), key))}
	cert.Leaf = must(x509.ParseCertificate(cert.Certificate[0]))
	return cert
}

func main() {
	mode, keys, sock := os.Args[1], os.Args[2], os.Args[3]
	key := must(controlclient.LoadPrivateKey(filepath.Join(keys, "dp.priv"))).(ed25519.PrivateKey)
	pin := filepath.Join(keys, "cp.pub")
	if mode == "serve" {
		cfg := controlclient.ServerTLSConfig(certAt(key, os.Args[4]), pin)
		verify := cfg.VerifyConnection
		cfg.VerifyConnection = func(s tls.ConnectionState) error {
			f := must(os.OpenFile(filepath.Join(keys, "handshakes"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600))
			fmt.Fprintln(f, s.DidResume)
			f.Close()
			return verify(s)
		}
		store := auth.NewTokenStore()
		ctl := controlclient.NewServer(store, func(*auth.Generation) error { return nil }, func() *pb.StatusResponse { return &pb.StatusResponse{} }, slog.New(slog.NewTextHandler(io.Discard, nil)))
		gs := grpc.NewServer(grpc.Creds(controlclient.NewTransportCredentials(cfg)),
			grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionAge: 500 * time.Millisecond, MaxConnectionAgeGrace: 0}),
			grpc.UnaryInterceptor(controlclient.UnaryProtoVersionInterceptor))
		pb.RegisterControlServer(gs, ctl)
		lis := must(net.Listen("unix", sock))
		defer lis.Close()
		go gs.Serve(lis)
		fmt.Println("READY")
		bufio.NewReader(os.Stdin).ReadString('\n')
		gs.Stop()
		return
	}
	cfg := controlclient.ClientTLSConfig(certAt(key, "current"), pin)
	cfg.ServerName = "stargate-cp"
	cfg.ClientSessionCache = tls.NewLRUClientSessionCache(1)
	if mode == "hold" {
		raw := must(net.Dial("unix", sock))
		defer raw.Close()
		conn := tls.Client(raw, cfg)
		conn.SetDeadline(time.Now().Add(14 * time.Second))
		if err := conn.Handshake(); err != nil {
			panic(err)
		}
		if _, err := conn.Write(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}...)); err != nil {
			panic(err)
		}
		maxAge := false
		for {
			h := make([]byte, 9)
			_, err := io.ReadFull(conn, h)
			if err != nil {
				if err == io.EOF && maxAge {
					fmt.Println("PASS")
					return
				}
				panic(fmt.Sprintf("no bounded max-age closure: %v", err))
			}
			size := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
			if size > 65536 {
				panic("unexpected frame size")
			}
			body := make([]byte, size)
			if _, err = io.ReadFull(conn, body); err != nil {
				panic(err)
			}
			if h[3] == 4 && h[4]&1 == 0 {
				conn.Write([]byte{0, 0, 0, 4, 1, 0, 0, 0, 0})
			}
			if h[3] == 7 && bytes.Contains(body, []byte("max_age")) {
				maxAge = true
			}
			// Deliberately never ACK PING or obey GOAWAY: local closure must still win.
		}
	}
	probe := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		raw, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
		if err != nil {
			return err
		}
		defer raw.Close()
		conn := tls.Client(raw, cfg)
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if err = conn.HandshakeContext(ctx); err != nil {
			return err
		}
		if conn.ConnectionState().DidResume {
			return fmt.Errorf("Java reused session authorization")
		}
		// Read a real HTTP/2 SETTINGS response; client-side TLS success alone
		// does not establish that the server accepted the client's certificate.
		_, err = conn.Write(append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}...))
		if err != nil {
			return err
		}
		_, err = io.ReadFull(conn, make([]byte, 9))
		return err
	}
	if err := probe(); err != nil {
		panic(err)
	}
	if err := probe(); err != nil {
		panic(err)
	}
	for _, date := range []string{"expired", "future"} {
		cfg.Certificates = []tls.Certificate{certAt(key, date)}
		if probe() == nil {
			panic("Java accepted " + date + " peer")
		}
	}
	cfg.Certificates = []tls.Certificate{certAt(key, "current")}
	pub, newKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	der := must(x509.MarshalPKIXPublicKey(pub))
	if err = os.WriteFile(filepath.Join(keys, "dp.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0644); err != nil {
		panic(err)
	}
	if probe() == nil {
		panic("Java accepted old pin on reconnect")
	}
	cfg.Certificates = []tls.Certificate{certAt(newKey, "current")}
	if err = probe(); err != nil {
		panic(err)
	}
	fmt.Println("PASS")
}
