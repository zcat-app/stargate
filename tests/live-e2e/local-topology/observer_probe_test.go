// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func eventFixture(t *testing.T) (string, tls.Certificate) {
	t.Helper()
	keys := t.TempDir()
	var cp tls.Certificate
	for _, name := range []string{"cp", "dp"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keys, name+".priv"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		der, err = x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keys, name+".pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
			t.Fatal(err)
		}
		if name == "cp" {
			template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			der, err = x509.CreateCertificate(rand.Reader, template, template, pub, priv)
			if err != nil {
				t.Fatal(err)
			}
			cp = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
		}
	}
	return keys, cp
}

func TestEventSubscriberPinAndValidity(t *testing.T) {
	keys, cert := eventFixture(t)
	cfg, err := eventTLS(keys)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if err := cfg.VerifyConnection(state); err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = time.Now().Add(-time.Second)
	if cfg.VerifyConnection(state) == nil {
		t.Fatal("accepted expired CP")
	}
	leaf.NotAfter = time.Now().Add(time.Hour)
	leaf.NotBefore = time.Now().Add(time.Minute)
	if cfg.VerifyConnection(state) == nil {
		t.Fatal("accepted future CP")
	}
	leaf.NotBefore = time.Now().Add(-time.Minute)
	other, _ := eventFixture(t)
	replacement, err := os.ReadFile(filepath.Join(other, "cp.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keys, "cp.pub"), replacement, 0600); err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyConnection(state) == nil {
		t.Fatal("accepted replaced CP pin")
	}
}

func TestEventSubscriberIdentityWireShape(t *testing.T) {
	keys, _ := eventFixture(t)
	cfg, err := eventTLS(keys)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "stargate-dp" || !cert.BasicConstraintsValid ||
		len(cert.ExtKeyUsage) != 2 || cert.NotAfter.Sub(cert.NotBefore) < 30*24*time.Hour ||
		len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://stargate.local/dp" {
		t.Fatal("subscriber identity differs from wire-auth section 2.2")
	}
}

func TestEventTokensRejectRawDetailsAndFalseLifecycle(t *testing.T) {
	for _, kind := range []grpcpb.EventKind{grpcpb.EventKind_EVENT_KIND_STOPPED, grpcpb.EventKind_EVENT_KIND_RESTARTED, grpcpb.EventKind_EVENT_KIND_CRASHED} {
		if _, err := eventToken(&grpcpb.SidecarEvent{Sidecar: "tor", Kind: kind}); err == nil {
			t.Fatal("accepted false lifecycle")
		}
	}
	for _, event := range []*grpcpb.SidecarEvent{
		{Sidecar: "tor", Kind: grpcpb.EventKind_EVENT_KIND_STARTED, Detail: "raw-private-marker"},
		{Sidecar: "other", Kind: grpcpb.EventKind_EVENT_KIND_STARTED, Detail: "container_start"},
	} {
		token, err := eventToken(event)
		if err == nil || token != "" {
			t.Fatal("exported unknown event content")
		}
	}
}

type eventServer struct {
	grpcpb.UnimplementedEventsServer
}

func (eventServer) WatchEvents(_ *grpcpb.WatchEventsRequest, stream grpcpb.Events_WatchEventsServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	if strings.Join(md.Get("x-stargate-proto-major"), "") != "1" {
		return context.Canceled
	}
	for _, event := range []*grpcpb.SidecarEvent{
		{Sidecar: "tor", Kind: grpcpb.EventKind_EVENT_KIND_STARTED, Detail: "container_start"},
		{Sidecar: "tor", Kind: grpcpb.EventKind_EVENT_KIND_HEALTHY, Detail: "healthcheck_pass"},
		{Sidecar: "tor", Kind: grpcpb.EventKind_EVENT_KIND_UNHEALTHY, Detail: "healthcheck_fail"},
		{Sidecar: "tor", Kind: grpcpb.EventKind_EVENT_KIND_HEALTHY, Detail: "raw-private-marker"},
	} {
		if err := stream.Send(event); err != nil {
			return err
		}
	}
	return nil
}

func TestAuthenticatedEventSocketExportsOnlyFiniteTokens(t *testing.T) {
	keys, cert := eventFixture(t)
	socket := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	// This server requires the exact disposable DP public key as its positive auth control.
	dp, err := readPublic(filepath.Join(keys, "dp.pub"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 || !state.PeerCertificates[0].PublicKey.(ed25519.PublicKey).Equal(dp) {
				return context.Canceled
			}
			return nil
		}}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)))
	grpcpb.RegisterEventsServer(server, eventServer{})
	go server.Serve(listener)
	defer server.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var output bytes.Buffer
	if err := watchEvents(ctx, socket, keys, &output); err == nil {
		t.Fatal("accepted raw detail")
	}
	if output.String() != "SUBSCRIBED\nSTARTED\nHEALTHY\nUNHEALTHY\n" {
		t.Fatalf("unexpected finite output %q", output.String())
	}
}
