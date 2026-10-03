// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// observer_probe is copied into the disposable CP container. It executes as
// UID 5101 in the CP's actual mount and network namespaces; it never prints
// a key, Tor reply, destination, or arbitrary peer text.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	grpcpb "github.com/zcat-app/stargate/proto/stargate/v1/grpcpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

const (
	socketPath = "/run/stargate-tor-observer/health.sock"
	cpKeyPath  = "/etc/stargate/keys/cp.priv"
	peerPath   = "/etc/stargate/keys/observer.pub"
)

func main() {
	if err := probe(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "observer probe: refused or invalid result")
		os.Exit(1)
	}
}

func probe(args []string) error {
	if len(args) < 1 {
		return errors.New("missing mode")
	}
	switch args[0] {
	case "publication-boundary":
		if len(args) != 1 || os.Getuid() != 5103 || os.Getgid() != 5100 {
			return errors.New("wrong observer identity")
		}
		var fs syscall.Statfs_t
		if syscall.Statfs("/run/tor-health", &fs) != nil || fs.Type != 0x01021994 {
			return errors.New("not tmpfs")
		}
		file, err := os.OpenFile("/run/tor-health/probe-write", os.O_CREATE|os.O_WRONLY, 0600)
		if err == nil {
			file.Close()
			return errors.New("observer can write publication")
		}
		if !errors.Is(err, syscall.EROFS) {
			return errors.New("write not denied by read-only mount")
		}
		fmt.Println("PUBLICATION_READONLY_TMPFS")
		return nil
	case "raw-positive":
		if len(args) != 1 || os.Getuid() != 5103 {
			return errors.New("wrong Tor identity")
		}
		cookie, err := os.ReadFile("/var/lib/tor/control_auth_cookie")
		if err != nil || len(cookie) != 32 {
			return errors.New("cookie control failed")
		}
		conn, err := net.DialTimeout("unix", "/var/lib/tor/control/tor-control.sock", time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, err = io.WriteString(conn, "AUTHENTICATE "+hex.EncodeToString(cookie)+"\r\n")
		if err != nil {
			return err
		}
		var reply [8]byte
		if _, err = io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "250 OK\r\n" {
			return errors.New("Tor auth control failed")
		}
		_, _ = io.WriteString(conn, "QUIT\r\n")
		fmt.Println("RAW_AUTHORITY_POSITIVE")
		return nil
	case "raw-authority":
		if len(args) != 1 || (os.Getuid() != 5101 && os.Getuid() != 5103) {
			return errors.New("wrong authority probe identity")
		}
		// Probe the actual operations, with no permission-elevating user override.
		// Emit finite capability results only: cookie/reply bytes never leave here.
		readable, connected := false, false
		for _, path := range []string{"/run/tor-control/control_auth_cookie", "/var/lib/tor/control_auth_cookie"} {
			file, err := os.Open(path)
			if err == nil {
				var cookie [32]byte
				_, err = io.ReadFull(file, cookie[:])
				readable = readable || err == nil
				_ = file.Close()
			}
		}
		for _, path := range []string{"/run/tor-control/tor-control.sock", "/var/lib/tor/control/tor-control.sock", "/run/stargate-tor/tor-socks.sock", "/run/tor-fabric/private/tor-socks.sock"} {
			conn, err := net.DialTimeout("unix", path, time.Second)
			if err == nil {
				connected = true
				_ = conn.Close()
			}
		}
		if readable || connected {
			fmt.Printf("RAW_AUTHORITY_EXPOSED cookie=%t socket=%t\n", readable, connected)
			return errors.New("raw authority exposed")
		}
		fmt.Println("RAW_AUTHORITY_DENIED")
		return nil
	case "events":
		// Host-only disposable test subscriber. Nothing is installed in DP/CP;
		// the parent consumes finite tokens through a private anonymous pipe.
		if len(args) != 3 || !filepath.IsAbs(args[1]) || !filepath.IsAbs(args[2]) {
			return errors.New("invalid event arguments")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		return watchEvents(ctx, args[1], args[2], os.Stdout)
	case "identity":
		if len(args) != 1 || os.Getuid() != 5101 || os.Getgid() != 5100 {
			return errors.New("wrong CP identity")
		}
		groups, err := os.Getgroups()
		if err != nil {
			return err
		}
		for _, group := range groups {
			if group == 5103 || group == 5200 {
				return errors.New("forbidden group")
			}
		}
		for _, path := range []string{
			"/run/tor/control_auth_cookie", "/run/tor-control/control_auth_cookie",
			"/var/lib/tor/control_auth_cookie", "/var/lib/tor/control/tor-control.sock",
			"/run/stargate-tor/tor-socks.sock", "/etc/stargate/observer-keys/observer.priv",
		} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				return errors.New("forbidden path visible")
			}
		}
		if _, err := os.Lstat(socketPath); err != nil {
			return errors.New("health socket absent")
		}
		fmt.Println("IDENTITY_OK")
		return nil
	case "tcp":
		if len(args) != 2 {
			return errors.New("missing address")
		}
		conn, err := net.DialTimeout("tcp", args[1], 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return errors.New("CP reached TCP")
		}
		fmt.Println("TCP_REFUSED")
		return nil
	case "health", "request", "wrong-auth", "absent-auth", "no-eof":
		if (args[0] == "request" && len(args) != 2) ||
			(args[0] != "request" && len(args) != 1) {
			return errors.New("invalid arguments")
		}
		payload := []byte("HEALTH/1\n")
		if args[0] == "request" {
			var err error
			payload, err = hex.DecodeString(args[1])
			if err != nil || len(payload) > 1024 {
				return errors.New("invalid test input")
			}
		}
		reply, err := call(args[0], payload)
		// A fixed refusal can close while malformed request bytes remain unread.
		// Linux reports that close as a reset; zero bytes still proves that no
		// health token or raw Tor reply crossed the CP-facing socket.
		if args[0] != "health" && len(reply) == 0 &&
			(errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)) {
			fmt.Println("REFUSED")
			return nil
		}
		if err != nil {
			return err
		}
		if args[0] == "health" {
			switch string(reply) {
			case "READY/1\n", "NOT_READY/1\n", "UNAVAILABLE/1\n":
				fmt.Print(strings.TrimSpace(string(reply)))
				return nil
			}
			return errors.New("non-finite health reply")
		}
		if len(reply) != 0 {
			return errors.New("invalid input received data")
		}
		fmt.Println("REFUSED")
		return nil
	default:
		return errors.New("unknown mode")
	}
}

// wire-auth §2.4 applies to the test peer too. A window is shorter than the
// production transport lifetime and never reconnects or conceals lost events.
func eventTLS(keys string) (*tls.Config, error) {
	private, err := readPrivate(filepath.Join(keys, "dp.priv"))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(0),
		SignatureAlgorithm: x509.PureEd25519,
		Subject:            pkix.Name{CommonName: "stargate-dp"},
		NotBefore:          now.Add(-5 * time.Minute), NotAfter: now.Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{{Scheme: "spiffe", Host: "stargate.local", Path: "/dp"}},
		BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}},
		InsecureSkipVerify: true, // UDS identity is the fresh Ed25519 pin, not a DNS name.
		VerifyConnection: func(state tls.ConnectionState) error {
			pin, err := readPublic(filepath.Join(keys, "cp.pub"))
			if err != nil || len(state.PeerCertificates) != 1 {
				return errors.New("invalid CP identity")
			}
			cert := state.PeerCertificates[0]
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			now := time.Now()
			if !ok || !pub.Equal(pin) || now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("invalid CP identity")
			}
			return nil
		},
	}, nil
}

func eventToken(event *grpcpb.SidecarEvent) (string, error) {
	if event.GetSidecar() == "tor" {
		switch {
		case event.GetKind() == grpcpb.EventKind_EVENT_KIND_STARTED && event.GetDetail() == "container_start":
			return "STARTED", nil
		case event.GetKind() == grpcpb.EventKind_EVENT_KIND_HEALTHY && event.GetDetail() == "healthcheck_pass":
			return "HEALTHY", nil
		case event.GetKind() == grpcpb.EventKind_EVENT_KIND_UNHEALTHY && event.GetDetail() == "healthcheck_fail":
			return "UNHEALTHY", nil
		}
	}
	return "", errors.New("unexpected event")
}

func watchEvents(ctx context.Context, socket, keys string, output io.Writer) error {
	cfg, err := eventTLS(keys)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient("passthrough:///stargate-cp",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}), grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024)))
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-stargate-proto-major", "1",
		"x-stargate-proto-minor", "0", "x-stargate-capabilities", "watch-events")
	stream, err := grpcpb.NewEventsClient(conn).WatchEvents(ctx, &grpcpb.WatchEventsRequest{}, grpc.WaitForReady(true))
	if err != nil {
		return err
	}
	// This announces a sent subscription, not proof of server registration.
	// The matrix's STARTED/HEALTHY positive controls supply that evidence.
	if _, err := fmt.Fprintln(output, "SUBSCRIBED"); err != nil {
		return err
	}
	for count := 0; count < 16; count++ {
		event, err := stream.Recv()
		if err != nil {
			return err
		}
		token, err := eventToken(event)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(output, token); err != nil {
			return err
		}
	}
	return errors.New("event bound exceeded")
}

func call(mode string, payload []byte) ([]byte, error) {
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(7 * time.Second))
	var hello [6 + 32]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil {
		return nil, err
	}
	if string(hello[:6]) != "OBS/1\n" {
		return nil, errors.New("observer hello invalid")
	}
	if mode == "absent-auth" {
		_, _ = conn.Write(payload)
		return io.ReadAll(io.LimitReader(conn, 65))
	}
	private, err := readPrivate(cpKeyPath)
	if err != nil {
		return nil, err
	}
	if mode == "wrong-auth" {
		_, private, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	transcript := append(append([]byte{}, hello[6:]...), nonce[:]...)
	signature := ed25519.Sign(private, append([]byte("stargate-observer/1 client\n"), transcript...))
	frame := append(append([]byte("CP/1\n"), nonce[:]...), signature...)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	if mode == "wrong-auth" {
		return io.ReadAll(io.LimitReader(conn, 65))
	}
	var proof [5 + 64]byte
	if _, err := io.ReadFull(conn, proof[:]); err != nil {
		return nil, err
	}
	public, err := readPublic(peerPath)
	if err != nil || string(proof[:5]) != "OK/1\n" ||
		!ed25519.Verify(public, append([]byte("stargate-observer/1 server\n"), transcript...), proof[5:]) {
		return nil, errors.New("observer proof invalid")
	}
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	if mode != "no-eof" {
		if err := conn.(*net.UnixConn).CloseWrite(); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(conn, 65))
}

func readPrivate(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("wrong private key type")
	}
	return private, nil
}

func readPublic(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("wrong public key type")
	}
	return public, nil
}
