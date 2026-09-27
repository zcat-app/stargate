// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

package fakecp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// T132: a Go peer can accept a protocol-less TLS connection, hiding the
// missing h2 offer that grpc-netty rejects (wire-auth.md §4).
func TestStartTLSNegotiatesH2(t *testing.T) {
	keysDir := t.TempDir()
	ipcDir := t.TempDir()
	writeKeyPair := func(name string) ed25519.PrivateKey {
		t.Helper()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keysDir, name+".priv"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keysDir, name+".pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0600); err != nil {
			t.Fatal(err)
		}
		return priv
	}
	writeKeyPair("cp")
	dpPriv := writeKeyPair("dp")
	StartTLS(t, ipcDir, keysDir)
	cert, err := SelfSigned(dpPriv, "stargate-dp")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("unix", filepath.Join(ipcDir, "control.sock"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(conn, &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, //nolint:gosec // wire-auth §4: pin hook is the sole verifier
		VerifyPeerCertificate: PinVerifier(filepath.Join(keysDir, "cp.pub")),
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{"h2"},
	})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("fake CP negotiated ALPN %q, want exactly h2 (wire-auth.md §4)", got)
	}
	// grpc-go can insert h2 for its own transport. Inspect the fixture's
	// tls.Config itself so this test fails if a future library default masks
	// an omitted explicit pin (the T130 failure mode).
	file, err := parser.ParseFile(token.NewFileSet(), "fakecp.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(file, func(node ast.Node) bool {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "StartTLS" {
			return true
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "NextProtos" {
					continue
				}
				protocols, ok := kv.Value.(*ast.CompositeLit)
				if !ok || len(protocols.Elts) != 1 {
					continue
				}
				value, ok := protocols.Elts[0].(*ast.BasicLit)
				if !ok || value.Kind != token.STRING {
					continue
				}
				name, err := strconv.Unquote(value.Value)
				found = err == nil && name == "h2"
			}
			return true
		})
		return false
	})
	if !found {
		t.Fatal("fake CP StartTLS must pin NextProtos to exactly [h2], independent of grpc-go defaults")
	}
}
