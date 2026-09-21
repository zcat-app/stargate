// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0

// observer_probe is copied into the disposable CP container. It executes as
// UID 5101 in the CP's actual mount and network namespaces; it never prints
// a key, Tor reply, destination, or arbitrary peer text.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
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
